//! Logique d'état de l'interface, SANS affichage (testable) : options de méthode, code de
//! confirmation, activation des boutons, client, durées, fermeture pendant un effacement.

use std::collections::BTreeMap;

use crate::config::Customer;
use crate::detect::DiskInfo;
use crate::erase_hdd::{Phase, Plan, Progress, VerifyMode};
use crate::erase_ssd::{Decision, MethodOpt, Probe};
use crate::job::{self, Analysis};
use crate::report::{self, EraseRecord, Status};
use crate::safety;

/// Une méthode proposée à l'écran Configuration.
#[derive(Debug, Clone)]
pub struct MethodOption {
    pub analysis: Analysis,
    pub label: String,
    pub level: &'static str,
    pub reason: String,
    pub eta: String,
    /// Méthode choisie automatiquement (`--method auto`).
    pub recommended: bool,
}

impl MethodOption {
    /// Effacement possible avec cette option.
    pub fn runnable(&self) -> bool {
        !matches!(
            self.analysis.decision,
            Decision::Refuse(_) | Decision::Frozen(_)
        )
    }
    /// Équivalent en ligne de commande.
    pub fn cli_flags(&self) -> String {
        let m = match self.analysis.method {
            MethodOpt::Auto => "--method auto",
            MethodOpt::Firmware => "--method firmware",
            MethodOpt::Overwrite => "--method overwrite",
        };
        if self.analysis.allow_fallback {
            format!("{m} --allow-fallback")
        } else {
            m.to_string()
        }
    }
}

/// Options réellement possibles : mêmes combinaisons que `--method` / `--allow-fallback`,
/// sans doublon. La première est celle de `--method auto` (recommandée) ; un refus n'est
/// jamais proposé ; un disque gelé est montré (bloquant) s'il s'agit du choix automatique.
pub fn method_options(disk: &DiskInfo, probe: &Probe, plan: &Plan) -> Vec<MethodOption> {
    let combos = [
        (MethodOpt::Auto, false),
        (MethodOpt::Auto, true),
        (MethodOpt::Firmware, false),
        (MethodOpt::Firmware, true),
        (MethodOpt::Overwrite, false),
    ];
    let mut out: Vec<MethodOption> = Vec::new();
    for (i, (m, fb)) in combos.into_iter().enumerate() {
        let Ok(a) = job::analyse(disk, probe, m, false, fb) else {
            continue;
        };
        let refuse = matches!(a.decision, Decision::Refuse(_));
        let frozen = matches!(a.decision, Decision::Frozen(_));
        if refuse || (frozen && i != 0) {
            continue;
        }
        // Le repli n'a de sens que pour une commande firmware (sinon doublon).
        let fb_matters = matches!(a.decision, Decision::Firmware(_));
        if fb && !fb_matters && !matches!(a.decision, Decision::Fallback) {
            continue;
        }
        let dup = out.iter().any(|o| {
            o.analysis.decision == a.decision
                && (!fb_matters || o.analysis.allow_fallback == a.allow_fallback)
        });
        if dup {
            continue;
        }
        let eta = job::duration_text(job::estimate_secs(
            &a.decision,
            disk.size_bytes,
            plan,
            probe,
        ));
        out.push(MethodOption {
            label: job::decision_label(&a.decision, plan, fb && fb_matters),
            level: job::decision_level(&a.decision),
            reason: job::decision_reason(&a, probe),
            eta,
            recommended: i == 0,
            analysis: a,
        });
    }
    out
}

/// Avertissements de l'écran Configuration.
pub fn config_warnings(opt: &MethodOption, probe: &Probe) -> Vec<String> {
    let mut w: Vec<String> = blocked_warning(probe).into_iter().collect();
    match &opt.analysis.decision {
        Decision::Frozen(guide) => w.push(guide.clone()),
        Decision::Overwrite { ssd, note } => {
            if *ssd {
                w.push(format!("{} — statut au mieux PARTIAL.", report::NOTE_SSD));
            }
            if let Some(n) = note {
                w.push(n.clone());
                w.push(crate::erase_ssd::FROZEN_GUIDE.to_string());
            }
        }
        _ => {}
    }
    let overwrite = matches!(
        opt.analysis.decision,
        Decision::Overwrite { .. } | Decision::Fallback
    );
    match probe.hidden.hidden_sectors() {
        Some(n) if n > 0 => w.push(format!(
            "Zone cachée : {} — {}",
            probe.hidden.label(),
            if overwrite {
                "l'écrasement ne l'atteint pas, statut au mieux PARTIAL"
            } else {
                "voir le certificat"
            }
        )),
        None if overwrite => w.push(report::NOTE_HIDDEN_UNKNOWN.to_string()),
        _ => {}
    }
    for e in &probe.errors {
        w.push(format!("Lecture : {e}"));
    }
    w
}

/// Option « Effacer par écrasement (NIST Clear) » proposée par l'écran Résultat : seulement
/// si toutes les méthodes firmware ont été bloquées par le transport (rien n'a atteint le
/// disque). Préfère le repli Clear (TRIM + 1 passe vérifiée), sinon l'écrasement forcé.
pub fn clear_option(firmware_blocked: bool, options: &[MethodOption]) -> Option<usize> {
    if !firmware_blocked {
        return None;
    }
    let fallback = |o: &MethodOption| {
        o.runnable()
            && match o.analysis.decision {
                Decision::Fallback => true,
                Decision::Firmware(_) => o.analysis.allow_fallback,
                _ => false,
            }
    };
    options.iter().position(fallback).or_else(|| {
        options
            .iter()
            .position(|o| o.runnable() && matches!(o.analysis.decision, Decision::Overwrite { .. }))
    })
}

/// Bandeau de l'écran Configuration quand on y revient par « Effacer par écrasement ».
pub const CLEAR_HINT: &str = "Tentative précédente : commandes firmware bloquées par le pilote ou l'adaptateur. \
     Méthode de repli présélectionnée : si les commandes sont de nouveau bloquées, le disque est effacé par écrasement \
     (TRIM + 1 passe aléatoire vérifiée, NIST Clear, statut au mieux PARTIAL). La confirmation par code reste obligatoire.";

/// Avertissement « Sanitize bloqué » pour l'écran Configuration (raison du choix).
pub fn blocked_warning(probe: &Probe) -> Option<String> {
    probe.caps.ata_sanitize_blocked.map(|c| {
        format!(
            "{} : SANITIZE STATUS EXT refusé avant d'atteindre le disque, la méthode suivante est retenue.",
            crate::erase_ssd::blocked_note(crate::erase_ssd::FwMethod::AtaSanitizeCrypto, c)
        )
    })
}

/// « Continuer » de l'écran Configuration.
pub fn can_continue_config(options: &[MethodOption], selected: Option<usize>) -> bool {
    selected
        .and_then(|i| options.get(i))
        .is_some_and(MethodOption::runnable)
}

/// N° de série découpé : (début, partie à saisir mise en évidence).
pub fn serial_parts(disk: &DiskInfo) -> (String, String) {
    let serial = disk.serial.trim();
    if serial.is_empty() {
        return (String::new(), String::new());
    }
    let code = safety::confirmation_code(disk);
    let chars: Vec<char> = serial.chars().collect();
    if code.chars().count() >= chars.len() {
        return (String::new(), serial.to_string());
    }
    let cut = chars.len() - code.chars().count();
    (chars[..cut].iter().collect(), chars[cut..].iter().collect())
}

/// Consigne de saisie, selon la forme du code attendu.
pub fn confirm_prompt(disk: &DiskInfo) -> String {
    let code = safety::confirmation_code(disk);
    if disk.serial.trim().is_empty() {
        format!("Pour confirmer, saisissez le code {code} (disque sans n° de série)")
    } else if code.chars().count() > 4 {
        "Pour confirmer, saisissez le n° de série COMPLET (ses 4 derniers caractères sont identiques)".into()
    } else {
        "Pour confirmer, saisissez les 4 derniers caractères du n° de série".into()
    }
}

/// « Effacer définitivement » : code identique (MÊME fonction que la CLI) ET étiquette vérifiée.
pub fn can_erase(disk: &DiskInfo, typed: &str, label_checked: bool) -> bool {
    safety::confirmation_matches(disk, typed) && label_checked
}

/// Client choisi dans le carnet : ses 4 champs (modifiables ensuite).
pub fn customer_from_book(book: &BTreeMap<String, Customer>, id: Option<&str>) -> Customer {
    id.and_then(|id| book.get(id).cloned()).unwrap_or_default()
}

/// Avancement global (0..1) : passes d'écriture + vérifications, dans l'ordre du moteur.
pub fn global_fraction(p: &Progress, verify: VerifyMode) -> f64 {
    let verifies = |i: usize| match verify {
        VerifyMode::None => false,
        VerifyMode::Last => i + 1 == p.pass_total,
        VerifyMode::All => true,
    };
    let units: usize = (0..p.pass_total).map(|i| 1 + verifies(i) as usize).sum();
    if units == 0 {
        return 0.0;
    }
    let before: usize = (0..p.pass_index)
        .map(|i| 1 + verifies(i) as usize)
        .sum::<usize>()
        + usize::from(p.phase == Phase::Verify);
    let cur = p.done as f64 / p.total.max(1) as f64;
    ((before as f64 + cur) / units as f64).clamp(0.0, 1.0)
}

/// Temps restant estimé d'après l'avancement réel (None tant que c'est trop tôt).
pub fn remaining_secs(fraction: f64, elapsed_secs: f64) -> Option<u64> {
    ((0.01..1.0).contains(&fraction) && elapsed_secs > 2.0)
        .then(|| (elapsed_secs * (1.0 - fraction) / fraction).round() as u64)
}

/// « 3 h 28 min », « 12 min 05 s », « 42 s ».
pub fn hms_text(secs: u64) -> String {
    if secs >= 3600 {
        format!("{} h {:02} min", secs / 3600, (secs / 60) % 60)
    } else if secs >= 60 {
        format!("{} min {:02} s", secs / 60, secs % 60)
    } else {
        format!("{secs} s")
    }
}

/// Que faire quand l'opérateur ferme la fenêtre ?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAction {
    /// Rien en cours : fermer.
    Quit,
    /// Effacement en cours : demander confirmation (puis annulation propre).
    Ask,
}

pub fn on_close(job_running: bool) -> CloseAction {
    if job_running {
        CloseAction::Ask
    } else {
        CloseAction::Quit
    }
}

/// Un disque est sélectionnable : contexte de protection connu ET fiable, disque présent
/// et non protégé. Protection non fiable : AUCUN disque n'est sélectionnable.
pub fn selectable(ctx: Option<&crate::safety::ProtectContext>, protected: Option<bool>) -> bool {
    ctx.is_some_and(|c| c.reliable) && protected == Some(false)
}

/// Raison d'un refus (aucune méthode proposée).
pub fn refusal(disk: &DiskInfo, probe: &Probe) -> Option<String> {
    match job::analyse(disk, probe, MethodOpt::Auto, false, false).map(|a| a.decision) {
        Ok(Decision::Refuse(e)) => Some(e),
        Err(e) => Some(e),
        _ => None,
    }
}

/// Badge « SMART à vérifier » : santé lue et différente de PASSED.
pub fn smart_warning(probe: &Probe) -> Option<String> {
    let s = probe.smart.as_ref()?;
    (s.health != "PASSED" && s.health != "Non lu").then(|| s.health.clone())
}

/// Filtre de l'historique.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryFilter {
    All,
    Erased,
    Partial,
    Failed,
}

pub fn history_matches(r: &EraseRecord, f: HistoryFilter, search: &str) -> bool {
    let status_ok = match f {
        HistoryFilter::All => true,
        HistoryFilter::Erased => r.status == Status::Erased,
        HistoryFilter::Partial => r.status == Status::Partial,
        HistoryFilter::Failed => matches!(r.status, Status::Failed | Status::Aborted),
    };
    let q = search.trim().to_lowercase();
    status_ok
        && (q.is_empty()
            || [
                &r.disk.model,
                &r.disk.serial,
                &r.customer.name,
                &r.tag,
                &r.id,
                &r.technician.name,
            ]
            .iter()
            .any(|s| s.to_lowercase().contains(&q)))
}

/// Sous-titre de l'historique : « 9 disques · 7 effacés · 1 partiel · 1 échec ».
pub fn history_summary(all: &[EraseRecord]) -> String {
    let n = |s: &[Status]| all.iter().filter(|r| s.contains(&r.status)).count();
    format!(
        "{} effacement(s) · {} effacé(s) · {} partiel(s) · {} échec(s) ou interruption(s)",
        all.len(),
        n(&[Status::Erased]),
        n(&[Status::Partial]),
        n(&[Status::Failed, Status::Aborted])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::{demo_disks, demo_probe};
    use crate::erase_hdd::{ErrorCounts, Fill};

    #[test]
    fn confirmation_code_and_buttons() {
        let disks = demo_disks();
        let hdd = &disks[2]; // n° de série DEMO0HDD02
        assert_eq!(
            serial_parts(hdd),
            ("DEMO0H".to_string(), "DD02".to_string())
        );
        assert!(!can_erase(hdd, "DD02", false), "case non cochée");
        assert!(!can_erase(hdd, "DD03", true), "mauvais code");
        assert!(!can_erase(hdd, "", true));
        assert!(
            can_erase(hdd, " dd02 ", true),
            "même règle que la CLI (casse, espaces)"
        );
        // N° de série terminé par 4 caractères identiques : n° complet exigé.
        let mut d = hdd.clone();
        d.serial = "AB0000".into();
        assert_eq!(serial_parts(&d), (String::new(), "AB0000".to_string()));
        assert!(confirm_prompt(&d).contains("COMPLET"));
        assert!(!can_erase(&d, "0000", true));
        assert!(can_erase(&d, "AB0000", true));
        // Sans n° de série : code D<n>-<taille>.
        d.serial.clear();
        assert!(confirm_prompt(&d).contains(&safety::confirmation_code(&d)));
    }

    #[test]
    fn method_options_for_each_demo_disk() {
        let disks = demo_disks();
        let plan = Plan::dod_default(1);
        // HDD : écrasement recommandé, rien d'autre de distinct.
        let o = method_options(&disks[2], &demo_probe(&disks[2]), &plan);
        assert!(o[0].recommended && o[0].runnable());
        assert!(matches!(
            o[0].analysis.decision,
            Decision::Overwrite { ssd: false, .. }
        ));
        assert_eq!(o[0].eta, "≈ 3 h 34 min"); // 320 Go / 100 MB/s × 4
                                              // SSD : Sanitize recommandé + repli + écrasement forcé.
        let o = method_options(&disks[3], &demo_probe(&disks[3]), &plan);
        assert!(o[0].recommended);
        assert!(o
            .iter()
            .any(|x| x.analysis.allow_fallback && x.cli_flags().contains("--allow-fallback")));
        assert!(o
            .iter()
            .any(|x| matches!(x.analysis.decision, Decision::Overwrite { ssd: true, .. })));
        assert_eq!(
            o[0].eta, "inconnue",
            "aucune durée inventée pour un Sanitize ATA"
        );
        assert!(can_continue_config(&o, Some(0)));
        assert!(!can_continue_config(&o, None));
        // NVMe : durée annoncée par le disque (20 s).
        let o = method_options(&disks[4], &demo_probe(&disks[4]), &plan);
        assert_eq!(o[0].eta, "< 1 min");
    }

    #[test]
    fn frozen_ssd_blocks_continue_and_shows_the_guide() {
        let disks = demo_disks();
        let mut p = demo_probe(&disks[3]);
        if let Some(st) = p.caps.ata_sanitize.as_mut() {
            st.frozen = true;
        }
        if let Some(id) = p.caps.ata.as_mut() {
            id.security.frozen = true;
        }
        let o = method_options(&disks[3], &p, &Plan::dod_default(1));
        assert!(matches!(o[0].analysis.decision, Decision::Frozen(_)));
        assert!(!can_continue_config(&o, Some(0)));
        assert!(config_warnings(&o[0], &p)[0].contains("GELÉ"));
        // Seule issue : l'écrasement, proposé à part.
        assert!(o.iter().skip(1).all(MethodOption::runnable));
        assert!(o.len() >= 2);
    }

    #[test]
    fn ssd_without_firmware_is_never_offered_a_refusal() {
        let disks = demo_disks();
        let mut p = demo_probe(&disks[3]);
        p.caps.ata = None;
        p.caps.ata_sanitize = None;
        let o = method_options(&disks[3], &p, &Plan::dod_default(1));
        assert!(o.iter().all(MethodOption::runnable));
        assert!(o.iter().any(|x| x.analysis.decision == Decision::Fallback));
        assert!(!o[0].recommended || o[0].runnable());
    }

    #[test]
    fn blocked_sanitize_is_explained_and_next_method_recommended() {
        let disks = demo_disks();
        let mut p = demo_probe(&disks[3]);
        p.caps.ata_sanitize = None;
        p.caps.ata_sanitize_blocked = Some(50);
        let o = method_options(&disks[3], &p, &Plan::dod_default(1));
        assert!(o[0].recommended);
        match &o[0].analysis.decision {
            Decision::Firmware(m) => assert_ne!(m.family(), "ATA Sanitize"),
            Decision::Fallback => {}
            other => panic!("{other:?}"),
        }
        let w = config_warnings(&o[0], &p);
        assert!(
            w[0].contains("ATA Sanitize bloqué par le pilote ou l'adaptateur (erreur Windows 50)"),
            "{w:?}"
        );
        assert!(o[0].reason.contains("bloqué"), "{}", o[0].reason);
    }

    #[test]
    fn clear_button_only_when_all_firmware_was_blocked() {
        let disks = demo_disks();
        let plan = Plan::dod_default(1);
        let o = method_options(&disks[3], &demo_probe(&disks[3]), &plan);
        // Échec ordinaire (ou succès) : aucun bouton.
        assert_eq!(clear_option(false, &o), None);
        // Tout bloqué : l'option de repli est présélectionnée.
        let i = clear_option(true, &o).expect("option de repli");
        assert!(o[i].runnable());
        assert!(o[i].analysis.allow_fallback || o[i].analysis.decision == Decision::Fallback);
        // Sans option de repli : l'écrasement forcé.
        let only: Vec<MethodOption> = o
            .iter()
            .filter(|x| matches!(x.analysis.decision, Decision::Overwrite { .. }))
            .cloned()
            .collect();
        assert_eq!(clear_option(true, &only), Some(0));
        assert_eq!(clear_option(true, &[]), None);
    }

    #[test]
    fn client_selection_fills_the_four_fields() {
        let book = crate::config::parse_clients(
            "[clients.a]\nname = \"A\"\naddress = \"1 rue\"\ncontact_name = \"C\"\nphone = \"01\"",
        )
        .unwrap();
        let c = customer_from_book(&book, Some("a"));
        assert_eq!(
            (
                c.name.as_str(),
                c.address.as_str(),
                c.contact_name.as_str(),
                c.phone.as_str()
            ),
            ("A", "1 rue", "C", "01")
        );
        assert_eq!(customer_from_book(&book, None), Customer::default());
        assert_eq!(
            customer_from_book(&book, Some("inconnu")),
            Customer::default()
        );
    }

    fn prog(phase: Phase, pass: usize, done: u64) -> Progress {
        Progress {
            phase,
            pass_index: pass,
            pass_total: 3,
            done,
            total: 100,
            speed_mb_s: 1.0,
            errors: ErrorCounts::default(),
        }
    }

    #[test]
    fn global_progress_and_remaining_time() {
        // DoD : 3 passes + vérification de la dernière = 4 unités.
        assert_eq!(
            global_fraction(&prog(Phase::Write, 0, 0), VerifyMode::Last),
            0.0
        );
        assert_eq!(
            global_fraction(&prog(Phase::Write, 1, 50), VerifyMode::Last),
            0.375
        );
        assert_eq!(
            global_fraction(&prog(Phase::Verify, 2, 100), VerifyMode::Last),
            1.0
        );
        assert_eq!(
            global_fraction(&prog(Phase::Write, 2, 0), VerifyMode::None),
            2.0 / 3.0
        );
        assert_eq!(remaining_secs(0.25, 100.0), Some(300));
        assert_eq!(remaining_secs(0.0, 100.0), None);
        assert_eq!(remaining_secs(0.5, 1.0), None);
        assert_eq!(hms_text(12_480), "3 h 28 min");
        assert_eq!(hms_text(65), "1 min 05 s");
        assert_eq!(Fill::Random.label(), "random");
    }

    #[test]
    fn closing_during_an_erase_is_refused_without_confirmation() {
        assert_eq!(on_close(true), CloseAction::Ask);
        assert_eq!(on_close(false), CloseAction::Quit);
    }

    #[test]
    fn nothing_is_selectable_when_protection_is_unreliable() {
        let mut ctx = crate::demo::demo_protect_context();
        assert!(selectable(Some(&ctx), Some(false)));
        assert!(!selectable(Some(&ctx), Some(true)), "disque protégé");
        assert!(!selectable(Some(&ctx), None), "disque absent");
        assert!(!selectable(None, Some(false)), "contexte inconnu");
        ctx.reliable = false;
        assert!(!selectable(Some(&ctx), Some(false)));
    }

    #[test]
    fn refusal_text_is_shown() {
        let disks = demo_disks();
        let mut p = demo_probe(&disks[3]);
        p.caps.ata = None;
        p.caps.ata_sanitize = None;
        let r = refusal(&disks[3], &p).unwrap();
        assert!(r.contains("aucune commande firmware"), "{r}");
        assert!(refusal(&disks[2], &demo_probe(&disks[2])).is_none());
    }

    #[test]
    fn smart_badge_only_when_not_passed() {
        let disks = demo_disks();
        assert!(smart_warning(&demo_probe(&disks[5])).is_some());
        assert!(smart_warning(&demo_probe(&disks[2])).is_none());
        assert!(smart_warning(&Probe::default()).is_none());
    }

    #[test]
    fn history_filter_and_search() {
        let cfg = crate::config::Config::default();
        let mut r = crate::demo::demo_history(&cfg)
            .into_iter()
            .find(|r| r.status == Status::Erased && r.disk.serial == "DEMO0HDD02")
            .unwrap();
        assert!(history_matches(&r, HistoryFilter::All, ""));
        assert!(history_matches(&r, HistoryFilter::Erased, "demo0h"));
        assert!(!history_matches(&r, HistoryFilter::Failed, ""));
        r.status = Status::Aborted;
        assert!(history_matches(&r, HistoryFilter::Failed, ""));
        assert!(!history_matches(&r, HistoryFilter::All, "introuvable"));
        assert!(history_summary(&[r]).starts_with("1 effacement"));
    }
}
