//! Résultat d'un effacement, statut calculé, historique JSON et export CSV.
//!
//! Le statut et le niveau NIST sont CALCULÉS à partir des résultats réels du moteur :
//! aucune API ne permet de les saisir à la main.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::app::{APP_NAME, VERSION};
use crate::clock::{self, DateTime};
pub use crate::config::Customer;
use crate::config::{Company, Technician};
use crate::detect::DiskInfo;
use crate::erase_hdd::{ErrorCounts, Fill, Outcome, Plan, VerifyMode, VerifyResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    Erased,
    /// Terminé, mais avec une méthode de repli moins forte que prévu.
    Partial,
    Failed,
    Aborted,
}

impl Status {
    pub fn code(&self) -> &'static str {
        match self {
            Status::Erased => "ERASED",
            Status::Partial => "PARTIAL",
            Status::Failed => "FAILED",
            Status::Aborted => "ABORTED",
        }
    }
    pub fn fr(&self) -> &'static str {
        match self {
            Status::Erased => "Effacé",
            Status::Partial => "Partiel",
            Status::Failed => "Échec",
            Status::Aborted => "Interrompu",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MethodKind {
    /// Écrasement logiciel (DoD, 1 passe…) → NIST « Clear ».
    Overwrite,
    /// Commande firmware réussie (Sanitize, Secure Erase…) → NIST « Purge ».
    Firmware,
}

impl MethodKind {
    pub fn level(&self) -> &'static str {
        match self {
            MethodKind::Overwrite => "Clear",
            MethodKind::Firmware => "Purge",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskSnapshot {
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub bus: String,
    pub media: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmartAttr {
    pub id: u32,
    pub name: String,
    pub flags: String,
    pub value: String,
    pub worst: String,
    pub thresh: String,
    pub raw: String,
    pub failing: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SmartInfo {
    pub info: Vec<(String, String)>,
    pub health: String,
    pub attrs: Vec<SmartAttr>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EraseRecord {
    pub id: String,
    pub app: String,
    pub app_version: String,
    pub disk: DiskSnapshot,
    pub method: String,
    pub level: String,
    pub passes: Vec<String>,
    pub final_pass: String,
    pub verify: String,
    pub verify_result: String,
    pub rounds_done: u32,
    pub rounds_requested: u32,
    pub start: String,
    pub end: String,
    pub duration_secs: u64,
    pub bytes_erased: u64,
    pub percent: f64,
    pub errors_pass: u64,
    pub errors_sync: u64,
    pub errors_verify: u64,
    pub errors_retries: u64,
    pub avg_mb_s: f64,
    pub min_mb_s: f64,
    pub max_mb_s: f64,
    pub status: Status,
    pub hpa_dco: String,
    pub org: Company,
    pub technician: Technician,
    pub customer: Customer,
    pub tag: String,
    pub notes: Vec<String>,
    pub speed_samples: Vec<(f32, f32)>,
    pub smart: Option<SmartInfo>,
    /// Vrai si la cible était un fichier de test et non un disque physique.
    pub test_target: bool,
    /// Écrasement forcé sur SSD/NVMe (--force-overwrite-ssd) : effacement non garanti.
    #[serde(default)]
    pub ssd_overwrite: bool,
}

/// Statut d'après les résultats réels. `degraded` = repli plus faible que la méthode prévue.
/// `confirmed_size` = taille du disque confirmée par l'opérateur : si la taille effacée
/// diffère, c'est un ÉCHEC. Sans vérification, le meilleur statut possible est PARTIAL.
pub fn compute_status(
    o: &Outcome,
    planned_passes: usize,
    degraded: bool,
    confirmed_size: u64,
) -> Status {
    if o.aborted {
        return Status::Aborted;
    }
    let complete = o.size == confirmed_size
        && o.bytes_erased == o.size
        && o.passes_completed == planned_passes;
    let clean = o.errors.pass == 0 && o.errors.sync == 0;
    let verify_ok = matches!(o.verify, VerifyResult::Passed | VerifyResult::NotRequested)
        && o.errors.verify == 0;
    if !(complete && clean && verify_ok) {
        Status::Failed
    } else if degraded || o.verify == VerifyResult::NotRequested {
        Status::Partial
    } else {
        Status::Erased
    }
}

/// Libellé de la méthode, TOUJOURS dérivé du plan réellement exécuté.
pub fn method_label(plan: &Plan) -> String {
    let base = if plan.passes == [Fill::Byte(0x00), Fill::Byte(0xFF), Fill::Random] {
        "DoD 5220.22-M".to_string()
    } else {
        let motifs: Vec<String> = plan.passes.iter().map(Fill::label).collect();
        format!(
            "Écrasement {} passe(s) (motifs {})",
            plan.passes.len(),
            motifs.join(", ")
        )
    };
    if plan.verify == VerifyMode::None {
        format!("{base}, sans vérification")
    } else {
        base
    }
}

/// Note affichée (et mise en évidence) pour un écrasement forcé sur SSD/NVMe.
pub const NOTE_SSD: &str = "Écrasement sur SSD/NVMe : non garanti (sur-provisionnement)";

/// Note affichée (et mise en évidence) quand aucune relecture n'a été faite.
pub const NOTE_UNVERIFIED: &str =
    "NON VÉRIFIÉ : aucune relecture n'a confirmé l'effacement (statut limité à PARTIAL)";

/// Préfixe d'ID dérivé de APP_NAME : capitales (DiskErase → DE), sinon 3 premières lettres.
pub fn id_prefix() -> String {
    let caps: String = APP_NAME
        .chars()
        .filter(|c| c.is_ascii_uppercase())
        .collect();
    if caps.len() >= 2 {
        caps
    } else {
        APP_NAME
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(3)
            .collect::<String>()
            .to_uppercase()
    }
}

fn fnv1a(s: &str) -> u32 {
    s.bytes().fold(0x811C_9DC5u32, |h, b| {
        (h ^ b as u32).wrapping_mul(0x0100_0193)
    })
}

/// ID unique : PREFIXE-AAAAMMJJ-HHMMSS-XXXXXX (empreinte du disque, du début et de la fin).
/// `salt` (graine aléatoire du plan) distingue deux effacements terminés dans la même seconde.
pub fn make_id(serial: &str, start: &DateTime, end: &DateTime, salt: u64) -> String {
    let h = fnv1a(&format!(
        "{serial}|{}|{}|{salt:016x}",
        start.compact(),
        end.compact()
    )) & 0xFF_FFFF;
    format!("{}-{}-{:06X}", id_prefix(), start.compact(), h)
}

pub struct RecordInput<'a> {
    pub disk: &'a DiskInfo,
    pub plan: &'a Plan,
    pub outcome: &'a Outcome,
    pub kind: MethodKind,
    pub degraded: bool,
    pub org: Company,
    pub technician: Technician,
    pub customer: Customer,
    pub tag: String,
    pub start: DateTime,
    pub end: DateTime,
    pub notes: Vec<String>,
    pub smart: Option<SmartInfo>,
    pub test_target: bool,
    /// Écrasement forcé sur SSD/NVMe : statut au mieux PARTIAL.
    pub ssd_overwrite: bool,
}

pub fn build_record(i: RecordInput) -> EraseRecord {
    let o = i.outcome;
    let size = o.size.max(1);
    // Notes critiques EN TÊTE, puis les notes de l'appelant.
    let mut notes = Vec::new();
    if o.size != i.disk.size_bytes {
        notes.push(format!(
            "ÉCHEC : taille effacée ({} octets) différente de la taille confirmée du disque ({} octets)",
            o.size, i.disk.size_bytes
        ));
    }
    if i.ssd_overwrite {
        notes.push(NOTE_SSD.to_string());
    }
    if o.verify == VerifyResult::NotRequested {
        notes.push(NOTE_UNVERIFIED.to_string());
    }
    notes.extend(i.notes);
    EraseRecord {
        id: make_id(&i.disk.serial, &i.start, &i.end, i.plan.seed),
        app: APP_NAME.to_string(),
        app_version: VERSION.to_string(),
        disk: DiskSnapshot {
            model: i.disk.display_model(),
            serial: i.disk.serial.clone(),
            firmware: i.disk.firmware.clone(),
            bus: i.disk.bus.to_string(),
            media: i.disk.media.to_string(),
            size_bytes: o.size,
        },
        method: method_label(i.plan),
        level: i.kind.level().to_string(),
        passes: i.plan.passes.iter().map(|p| p.label()).collect(),
        final_pass: i
            .plan
            .passes
            .last()
            .map(|p| p.final_label())
            .unwrap_or("—")
            .to_string(),
        verify: i.plan.verify.label().to_string(),
        verify_result: match o.verify {
            VerifyResult::NotRequested => "Non demandée",
            VerifyResult::Passed => "OK",
            VerifyResult::Failed => "ÉCHEC",
            VerifyResult::Incomplete => "Incomplète",
        }
        .to_string(),
        rounds_done: u32::from(o.passes_completed == i.plan.passes.len()),
        rounds_requested: 1,
        start: i.start.slash(),
        end: i.end.slash(),
        duration_secs: o.elapsed.as_secs(),
        bytes_erased: o.bytes_erased,
        percent: o.bytes_erased as f64 / size as f64 * 100.0,
        errors_pass: o.errors.pass,
        errors_sync: o.errors.sync,
        errors_verify: o.errors.verify,
        errors_retries: o.errors.retries,
        avg_mb_s: o.avg_mb_s,
        min_mb_s: o.min_mb_s,
        max_mb_s: o.max_mb_s,
        // SSD/NVMe écrasé : traité comme une méthode dégradée -> au mieux PARTIAL.
        status: compute_status(
            o,
            i.plan.passes.len(),
            i.degraded || i.ssd_overwrite,
            i.disk.size_bytes,
        ),
        hpa_dco: "Non vérifié".to_string(), // lecture ATA IDENTIFY : étape 3
        org: i.org,
        technician: i.technician,
        customer: i.customer,
        tag: i.tag,
        notes,
        speed_samples: o.speed_samples.clone(),
        smart: i.smart,
        test_target: i.test_target,
        ssd_overwrite: i.ssd_overwrite,
    }
}

impl EraseRecord {
    pub fn errors(&self) -> ErrorCounts {
        ErrorCounts {
            pass: self.errors_pass,
            sync: self.errors_sync,
            verify: self.errors_verify,
            retries: self.errors_retries,
        }
    }
    pub fn duration_hms(&self) -> String {
        clock::hms(self.duration_secs)
    }
}

// ---------- Historique ----------

const HISTORY_FILE: &str = "history.json";

pub fn load_history(dir: &Path) -> Result<Vec<EraseRecord>, String> {
    let path = dir.join(HISTORY_FILE);
    match fs::read_to_string(&path) {
        Ok(t) if t.trim().is_empty() => Ok(Vec::new()),
        Ok(t) => serde_json::from_str(&t)
            .map_err(|e| format!("historique illisible ({}): {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(format!("lecture de {} impossible : {e}", path.display())),
    }
}

/// Ajoute un enregistrement (écriture atomique : fichier temporaire synchronisé puis renommage).
/// - JSON invalide : l'ancien fichier est mis de côté (`.corrupt-<horodatage>`), jamais écrasé ;
///   si ce renommage échoue, on s'arrête.
/// - Erreur d'E/S à la lecture : on s'arrête sans rien écrire.
pub fn append_history(dir: &Path, rec: &EraseRecord) -> Result<(), String> {
    use std::io::Write;
    let path = dir.join(HISTORY_FILE);
    let mut all: Vec<EraseRecord> = match fs::read_to_string(&path) {
        Ok(t) if t.trim().is_empty() => Vec::new(),
        Ok(t) => match serde_json::from_str(&t) {
            Ok(v) => v,
            Err(_) => {
                let stamp = DateTime::now().compact();
                let mut bak = dir.join(format!("{HISTORY_FILE}.corrupt-{stamp}"));
                let mut k = 1;
                while bak.exists() {
                    bak = dir.join(format!("{HISTORY_FILE}.corrupt-{stamp}-{k}"));
                    k += 1;
                }
                fs::rename(&path, &bak).map_err(|e| {
                    format!("historique illisible et mise de côté impossible ({}) : {e} — rien n'a été écrit", path.display())
                })?;
                Vec::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            return Err(format!(
                "lecture de {} impossible : {e} — historique non modifié",
                path.display()
            ))
        }
    };
    all.push(rec.clone());
    let json = serde_json::to_string_pretty(&all).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!("{HISTORY_FILE}.tmp"));
    let write = || -> std::io::Result<()> {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(json.as_bytes())?;
        f.sync_all()
    };
    write().map_err(|e| format!("écriture de l'historique impossible : {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("écriture de l'historique impossible : {e}"))
}

fn csv_escape(s: &str) -> String {
    // Anti-injection de formules (Excel/LibreOffice) : un champ commençant par = + - @ est
    // préfixé d'une apostrophe pour être lu comme du texte.
    let s = if s.starts_with(['=', '+', '-', '@']) {
        format!("'{s}")
    } else {
        s.to_string()
    };
    if s.contains([';', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

/// CSV (séparateur « ; », ouvre directement dans Excel en français), avec BOM UTF-8.
pub fn export_csv(records: &[EraseRecord]) -> String {
    let mut out = String::from("\u{feff}");
    out.push_str(
        "ID;Fin;Modèle;N° de série;Taille (octets);Bus;Type;Méthode;Niveau NIST;Statut;Passes;Octets effacés;\
         Erreurs (passe);Erreurs (sync);Erreurs (vérif.);Reprises;Durée;Débit moyen (MB/s);Technicien;Client;Tag\n",
    );
    for r in records {
        let row = [
            r.id.clone(),
            r.end.clone(),
            r.disk.model.clone(),
            r.disk.serial.clone(),
            r.disk.size_bytes.to_string(),
            r.disk.bus.clone(),
            r.disk.media.clone(),
            r.method.clone(),
            r.level.clone(),
            r.status.code().to_string(),
            r.passes.join(" "),
            r.bytes_erased.to_string(),
            r.errors_pass.to_string(),
            r.errors_sync.to_string(),
            r.errors_verify.to_string(),
            r.errors_retries.to_string(),
            r.duration_hms(),
            format!("{:.1}", r.avg_mb_s),
            r.technician.name.clone(),
            r.customer.name.clone(),
            r.tag.clone(),
        ];
        out.push_str(
            &row.iter()
                .map(|c| csv_escape(c))
                .collect::<Vec<_>>()
                .join(";"),
        );
        out.push('\n');
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::detect::{Bus, MediaType};
    use crate::erase_hdd::Fill;
    use std::time::Duration;

    pub fn sample_disk() -> DiskInfo {
        DiskInfo {
            number: 2,
            path: String::new(),
            vendor: String::new(),
            model: "ST320LM010-1KJ15".into(),
            serial: "ZX9K4T17".into(),
            firmware: "0002LIM1".into(),
            size_bytes: 320_072_933_376,
            bus: Bus::Sata,
            media: MediaType::Hdd,
            removable: false,
            volumes: vec![],
        }
    }

    pub fn good_outcome() -> Outcome {
        Outcome {
            size: 320_072_933_376,
            bytes_erased: 320_072_933_376,
            passes_completed: 3,
            verify: VerifyResult::Passed,
            errors: ErrorCounts::default(),
            aborted: false,
            abort_reason: None,
            speed_samples: vec![(0.0, 120.0), (50.0, 100.0), (100.0, 60.0)],
            avg_mb_s: 96.0,
            min_mb_s: 33.6,
            max_mb_s: 127.1,
            elapsed: Duration::from_secs(29_832),
        }
    }

    pub fn sample_record() -> EraseRecord {
        let plan = Plan::dod_default(1);
        let d = DateTime {
            year: 2026,
            month: 11,
            day: 9,
            hour: 13,
            minute: 45,
            second: 48,
        };
        let e = DateTime {
            year: 2026,
            month: 11,
            day: 9,
            hour: 22,
            minute: 3,
            second: 0,
        };
        build_record(RecordInput {
            disk: &sample_disk(),
            plan: &plan,
            outcome: &good_outcome(),
            kind: MethodKind::Overwrite,
            degraded: false,
            org: Company {
                name: "Société Exemple; \"Services\"".into(),
                ..Default::default()
            },
            technician: Technician {
                name: "Technicien Test".into(),
            },
            customer: Customer::default(),
            tag: "INV-1".into(),
            start: d,
            end: e,
            notes: vec![],
            smart: None,
            test_target: false,
            ssd_overwrite: false,
        })
    }

    const SZ: u64 = 320_072_933_376;

    #[test]
    fn status_erased_when_everything_is_clean() {
        assert_eq!(
            compute_status(&good_outcome(), 3, false, SZ),
            Status::Erased
        );
    }

    #[test]
    fn status_partial_when_degraded() {
        assert_eq!(
            compute_status(&good_outcome(), 3, true, SZ),
            Status::Partial
        );
    }

    #[test]
    fn status_failed_on_any_error_or_missing_coverage() {
        let mut o = good_outcome();
        o.errors.pass = 1;
        assert_eq!(compute_status(&o, 3, false, SZ), Status::Failed);
        let mut o = good_outcome();
        o.errors.verify = 2;
        o.verify = VerifyResult::Failed;
        assert_eq!(compute_status(&o, 3, false, SZ), Status::Failed);
        let mut o = good_outcome();
        o.bytes_erased -= 512;
        assert_eq!(compute_status(&o, 3, false, SZ), Status::Failed);
        let mut o = good_outcome();
        o.passes_completed = 2;
        assert_eq!(compute_status(&o, 3, false, SZ), Status::Failed);
        let mut o = good_outcome();
        o.verify = VerifyResult::Incomplete;
        assert_eq!(compute_status(&o, 3, false, SZ), Status::Failed);
    }

    #[test]
    fn status_aborted_wins() {
        let mut o = good_outcome();
        o.aborted = true;
        assert_eq!(compute_status(&o, 3, false, SZ), Status::Aborted);
    }

    #[test]
    fn size_differing_from_confirmed_size_is_failed_with_note() {
        assert_eq!(
            compute_status(&good_outcome(), 3, false, SZ + 512),
            Status::Failed
        );
        let mut disk = sample_disk();
        disk.size_bytes = SZ + 4096;
        let r = build_record(RecordInput {
            disk: &disk,
            plan: &Plan::dod_default(1),
            outcome: &good_outcome(),
            kind: MethodKind::Overwrite,
            degraded: false,
            org: Company::default(),
            technician: Technician::default(),
            customer: Customer::default(),
            tag: String::new(),
            start: DateTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
            end: DateTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 1,
                minute: 0,
                second: 0,
            },
            notes: vec![],
            smart: None,
            test_target: false,
            ssd_overwrite: false,
        });
        assert_eq!(r.status, Status::Failed);
        assert!(
            r.notes.iter().any(|n| n.contains("taille confirmée")),
            "{:?}",
            r.notes
        );
    }

    #[test]
    fn unverified_erase_is_at_best_partial_with_note() {
        let mut o = good_outcome();
        o.verify = VerifyResult::NotRequested;
        assert_eq!(compute_status(&o, 3, false, SZ), Status::Partial);
        let mut plan = Plan::dod_default(1);
        plan.verify = VerifyMode::None;
        let r = build_record(RecordInput {
            disk: &sample_disk(),
            plan: &plan,
            outcome: &o,
            kind: MethodKind::Overwrite,
            degraded: false,
            org: Company::default(),
            technician: Technician::default(),
            customer: Customer::default(),
            tag: String::new(),
            start: DateTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
            end: DateTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 1,
                minute: 0,
                second: 0,
            },
            notes: vec![],
            smart: None,
            test_target: false,
            ssd_overwrite: false,
        });
        assert_eq!(r.status, Status::Partial);
        assert!(r.notes.iter().any(|n| n == NOTE_UNVERIFIED));
        assert_eq!(r.method, "DoD 5220.22-M, sans vérification");
    }

    #[test]
    fn two_erasures_in_the_same_second_get_different_ids() {
        let t = DateTime {
            year: 2026,
            month: 11,
            day: 12,
            hour: 19,
            minute: 6,
            second: 10,
        };
        assert_ne!(
            make_id("TESTFILE", &t, &t, 1),
            make_id("TESTFILE", &t, &t, 2)
        );
        assert_eq!(
            make_id("TESTFILE", &t, &t, 7),
            make_id("TESTFILE", &t, &t, 7)
        );
    }

    fn record_with(o: &Outcome, plan: &Plan, ssd: bool, notes: Vec<String>) -> EraseRecord {
        build_record(RecordInput {
            disk: &sample_disk(),
            plan,
            outcome: o,
            kind: MethodKind::Overwrite,
            degraded: false,
            org: Company::default(),
            technician: Technician::default(),
            customer: Customer::default(),
            tag: String::new(),
            start: DateTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
            },
            end: DateTime {
                year: 2026,
                month: 1,
                day: 1,
                hour: 1,
                minute: 0,
                second: 0,
            },
            notes,
            smart: None,
            test_target: false,
            ssd_overwrite: ssd,
        })
    }

    #[test]
    fn forced_ssd_overwrite_is_at_best_partial_with_note_first() {
        let r = record_with(
            &good_outcome(),
            &Plan::dod_default(1),
            true,
            vec!["Cible : disque 2".into()],
        );
        assert_eq!(r.status, Status::Partial);
        assert!(r.ssd_overwrite);
        assert_eq!(r.notes[0], NOTE_SSD);
        assert_eq!(r.notes.last().unwrap(), "Cible : disque 2");
        // Un échec reste un échec.
        let mut o = good_outcome();
        o.errors.pass = 1;
        assert_eq!(
            record_with(&o, &Plan::dod_default(1), true, vec![]).status,
            Status::Failed
        );
        // Sans SSD : ERASED.
        assert_eq!(
            record_with(&good_outcome(), &Plan::dod_default(1), false, vec![]).status,
            Status::Erased
        );
    }

    #[test]
    fn critical_notes_come_first_in_order() {
        let mut o = good_outcome();
        o.verify = VerifyResult::NotRequested;
        o.size -= 512;
        o.bytes_erased = o.size;
        let r = record_with(
            &o,
            &Plan::dod_default(1),
            true,
            vec!["note appelant".into()],
        );
        assert!(r.notes[0].starts_with("ÉCHEC : taille"));
        assert_eq!(r.notes[1], NOTE_SSD);
        assert_eq!(r.notes[2], NOTE_UNVERIFIED);
        assert_eq!(r.notes[3], "note appelant");
        assert_eq!(r.status, Status::Failed);
    }

    #[test]
    fn old_history_without_ssd_field_still_loads() {
        let mut v = serde_json::to_value(sample_record()).unwrap();
        v.as_object_mut().unwrap().remove("ssd_overwrite");
        let r: EraseRecord = serde_json::from_value(v).unwrap();
        assert!(!r.ssd_overwrite);
    }

    #[test]
    fn csv_neutralises_formula_injection() {
        let mut r = sample_record();
        r.customer.name = "=HYPERLINK(\"http://x\")".into();
        r.tag = "+33 1 00".into();
        r.technician.name = "@SUM(A1)".into();
        let csv = export_csv(&[r]);
        let row = csv.lines().nth(1).unwrap();
        assert!(row.contains("\"'=HYPERLINK(\"\"http://x\"\")\""), "{row}");
        assert!(row.contains(";'+33 1 00"));
        assert!(row.contains(";'@SUM(A1);"));
        assert_eq!(csv_escape("-12"), "'-12");
        assert_eq!(csv_escape("DE-1"), "DE-1");
    }

    #[test]
    fn method_label_is_derived_from_plan() {
        let mut p = Plan::dod_default(1);
        assert_eq!(method_label(&p), "DoD 5220.22-M");
        p.passes = vec![Fill::Byte(0xFF), Fill::Byte(0x00), Fill::Random];
        assert_eq!(
            method_label(&p),
            "Écrasement 3 passe(s) (motifs 0xFF, 0x00, random)"
        );
        p.passes = vec![Fill::Byte(0)];
        assert_eq!(method_label(&p), "Écrasement 1 passe(s) (motifs 0x00)");
    }

    #[test]
    fn overwrite_can_never_be_purge() {
        let r = sample_record();
        assert_eq!(r.level, "Clear");
        assert_eq!(MethodKind::Firmware.level(), "Purge");
    }

    #[test]
    fn id_is_stable_and_prefixed() {
        let r = sample_record();
        assert!(r.id.starts_with("DE-20261109-134548-"), "{}", r.id);
        assert_eq!(r.id, sample_record().id);
        assert_eq!(r.id.len(), "DE-20261109-134548-".len() + 6);
        assert_eq!(r.passes, vec!["0x00", "0xFF", "random"]);
        assert_eq!(r.final_pass, "Aléatoire");
        assert_eq!(r.duration_hms(), "08:17:12");
        assert!((r.percent - 100.0).abs() < 1e-9);
        assert_eq!(Fill::Random.label(), "random");
    }

    #[test]
    fn csv_has_bom_header_and_escaping() {
        let mut r = sample_record();
        r.customer.name = "Client; \"Exemple\" SA".into();
        let csv = export_csv(&[r]);
        assert!(csv.starts_with('\u{feff}'));
        assert_eq!(csv.lines().count(), 2);
        assert!(csv.contains("\"Client; \"\"Exemple\"\" SA\""));
        assert!(csv.contains("ZX9K4T17"));
    }

    #[test]
    fn history_append_and_reload_and_corruption_is_kept() {
        let dir = std::env::temp_dir().join(format!("diskerase-hist-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(load_history(&dir).unwrap().is_empty());
        append_history(&dir, &sample_record()).unwrap();
        append_history(&dir, &sample_record()).unwrap();
        let all = load_history(&dir).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].disk.serial, "ZX9K4T17");
        fs::write(dir.join("history.json"), "{ pas du json").unwrap();
        append_history(&dir, &sample_record()).unwrap();
        assert_eq!(load_history(&dir).unwrap().len(), 1);
        let corrupt: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("history.json.corrupt-")
            })
            .collect();
        assert_eq!(corrupt.len(), 1);
        assert_eq!(
            fs::read_to_string(corrupt[0].path()).unwrap(),
            "{ pas du json"
        );
        // Une 2e corruption dans la même seconde ne remplace pas la première sauvegarde.
        fs::write(dir.join("history.json"), "encore cassé").unwrap();
        append_history(&dir, &sample_record()).unwrap();
        let n = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with("history.json.corrupt-")
            })
            .count();
        assert_eq!(n, 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_io_error_stops_without_writing() {
        let dir = std::env::temp_dir().join(format!("diskerase-hist-io-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // « history.json » est un DOSSIER : la lecture échoue (E/S), rien ne doit être écrasé.
        fs::create_dir_all(dir.join("history.json")).unwrap();
        assert!(append_history(&dir, &sample_record()).is_err());
        assert!(dir.join("history.json").is_dir());
        assert!(!dir.join("history.json.tmp").exists());
        let _ = fs::remove_dir_all(&dir);
    }
}
