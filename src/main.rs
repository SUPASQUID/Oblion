//! Point d'entrée. Mode console (l'interface graphique arrive à l'étape 4).
mod app;
mod ata;
mod certificate;
mod clock;
mod config;
mod detect;
mod erase_hdd;
mod erase_ssd;
mod hpa;
mod nvme;
mod pdf;
mod rawdisk;
mod report;
mod safety;
mod smart;
mod ui;
mod verify;
mod winio;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use app::{APP_NAME, VERSION};
use clock::DateTime;
use config::{Config, Customer, CustomerOverride, Paths, Technician};
use detect::{Bus, DiskInfo, MediaType};
use erase_hdd::{BlockDevice, Fill, Phase, Plan, Progress, VerifyMode};
use erase_ssd::{Decision, FwMethod, MethodOpt, Probe};
use hpa::Hidden;
use report::{EraseRecord, FirmwareKind, FirmwareReport, MethodKind, RecordInput, Status};
use safety::ProtectContext;

const USAGE: &str = "\
Usage :
  {APP} --list                              Liste les disques détectés
  {APP} --info N                            LECTURE SEULE : IDENTIFY ATA ou Identify NVMe, sécurité
                                            (gel…), capacités Sanitize, TRIM, HPA/DCO, SMART, et la
                                            méthode qui serait choisie (droits administrateur requis)
  {APP} --prepare N --confirm XXXX [--dry-run]
                                            TEST de préparation : vérifie les règles puis
                                            verrouille et démonte les volumes du disque N ;
                                            les verrous sont relâchés à la fin de la commande
                                            (rien n'est effacé, le disque n'est pas mis hors ligne)
                                            (XXXX = 4 derniers caractères du n° de série ;
                                             n° COMPLET s'ils sont identiques, ex. « 0000 » ;
                                             sans n° de série : D<n°>-<taille>, ex. D2-268M
                                             sous 1 Go, D3-320G au-delà)
  {APP} --erase N --confirm XXXX [options] [--dry-run]
                                            Efface le disque N et produit un certificat PDF
                                            (--dry-run : lit les capacités en lecture seule,
                                             affiche la méthode choisie et pourquoi, n'écrit rien)
  {APP} --erase-file <fichier> [options]    Même chaîne (écrasement) sur un fichier de test
                                            (certificat marqué « TEST SUR FICHIER »)
  {APP} --history                           Liste les effacements enregistrés
  {APP} --export-csv <fichier.csv>          Exporte l'historique en CSV (Excel)
  {APP} --clients                           Liste le carnet de clients (data/clients.toml)
  {APP} --version | --help

Options d'effacement :
  --method auto|firmware|overwrite
                                auto (défaut) : commande firmware si possible (NIST Purge),
                                  sinon écrasement DoD pour un HDD ;
                                  SSD SATA : Sanitize Crypto > Sanitize Block > Security Erase
                                  Enhanced > Normal ; NVMe : Sanitize Crypto > Block > Format
                                  NVM SES=2 > SES=1 ; HDD : Sanitize Crypto/Overwrite > Security
                                  Erase > DoD.
                                firmware : commande firmware uniquement.
                                overwrite : écrasement (SSD/NVMe : statut au mieux PARTIAL).
                                Purge n'est accordé que si la commande réussit ET que les
                                marqueurs posés avant (~1000 secteurs) sont tous effacés.
                                Disque gelé (frozen) : rien n'est tenté, un guide s'affiche.
  --allow-fallback              Si la commande firmware échoue ou est refusée (ou s'il n'y en
                                a aucune) : TRIM complet + écrasement 1 passe aléatoire +
                                vérification complète (NIST Clear, statut au mieux PARTIAL).
                                Sans cette option : arrêt et certificat FAILED.
  --passes 0x00,0xFF,random     Motifs des passes (défaut : config.toml, DoD 5220.22-M)
  --verify last|all|none        Vérification (défaut : config.toml)
  --client <id>                 Client du carnet data/clients.toml
  --customer \"Nom\"              Nom du client
  --customer-address \"…\"        Adresse du client
  --customer-contact \"…\"        Contact chez le client
  --customer-phone \"…\"          Téléphone du client
                                (les --customer-* remplacent champ par champ ceux de --client)
  --tag \"…\"                     Étiquette libre (n° d'inventaire…)
  --technician \"…\"              Technicien (défaut : config.toml)
  --force-overwrite-ssd         Alias de --method overwrite pour un SSD/NVMe (ou type inconnu) :
                                l'écrasement ne garantit pas l'effacement d'un SSD
                                (sur-provisionnement). Statut au mieux PARTIAL.

Le certificat contient le SMART lu AVANT l'effacement et l'état HPA/DCO (détection seule :
les zones cachées ne sont jamais modifiées ; si elles existent, un écrasement ou un Security
Erase donne au mieux PARTIAL, Sanitize couvre tout le support).

Ce programme est DESTRUCTIF. --dry-run et --info n'écrivent et ne modifient rien.
Ctrl+C (ou fermeture de la fenêtre) interrompt proprement un écrasement : un certificat
« ABORTED » est quand même produit. Une commande firmware déjà lancée se termine dans le disque.";

// ---------- Arguments ----------

fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Valeur d'une option ; une option présente sans valeur est une erreur.
fn opt(args: &[String], name: &str) -> Result<Option<String>, String> {
    match args.iter().position(|a| a == name) {
        None => Ok(None),
        Some(i) => match args.get(i + 1) {
            Some(v) if !v.starts_with("--") => Ok(Some(v.clone())),
            _ => Err(format!("valeur manquante après {name}")),
        },
    }
}

struct EraseOpts {
    plan: Plan,
    customer: Customer,
    technician: Technician,
    tag: String,
    dry_run: bool,
    force_ssd: bool,
    method: MethodOpt,
    allow_fallback: bool,
}

/// Cible de l'effacement, pour le certificat.
struct Target {
    notes: Vec<String>,
    test_target: bool,
    ssd_overwrite: bool,
    smart: Option<report::SmartInfo>,
    hidden: Hidden,
    real_size: Option<u64>,
}

/// Méthode effective : --force-overwrite-ssd = --method overwrite pour un support non magnétique.
fn method_opt(method: MethodOpt, force_ssd: bool, media: MediaType) -> Result<MethodOpt, String> {
    if force_ssd {
        if method == MethodOpt::Firmware {
            return Err("--force-overwrite-ssd et --method firmware sont incompatibles".into());
        }
        if media != MediaType::Hdd {
            return Ok(MethodOpt::Overwrite);
        }
    }
    Ok(method)
}

fn seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ ((std::process::id() as u64) << 32)
}

fn parse_passes(list: &[String]) -> Result<Vec<Fill>, String> {
    let passes = list
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| Fill::parse(s))
        .collect::<Result<Vec<_>, _>>()?;
    if passes.is_empty() {
        return Err("au moins une passe est nécessaire".into());
    }
    Ok(passes)
}

fn erase_opts(args: &[String], cfg: &Config, paths: &Paths) -> Result<EraseOpts, String> {
    let passes = match opt(args, "--passes")? {
        Some(s) => parse_passes(&s.split(',').map(str::to_string).collect::<Vec<_>>())?,
        None => parse_passes(&cfg.erase.hdd_passes)?,
    };
    let verify =
        VerifyMode::parse(&opt(args, "--verify")?.unwrap_or_else(|| cfg.erase.verify.clone()))?;
    let mut plan = Plan::dod_default(seed());
    plan.passes = passes;
    plan.verify = verify;

    let base = match opt(args, "--client")? {
        Some(id) => config::find_client(&config::load_clients(&paths.clients_file())?, &id)?,
        None => Customer::default(),
    };
    let over = CustomerOverride {
        name: opt(args, "--customer")?,
        address: opt(args, "--customer-address")?,
        contact_name: opt(args, "--customer-contact")?,
        phone: opt(args, "--customer-phone")?,
    };
    let technician = match opt(args, "--technician")? {
        Some(name) => Technician { name },
        None => cfg.technician.clone(),
    };
    let method = match opt(args, "--method")? {
        Some(m) => MethodOpt::parse(&m)?,
        None => MethodOpt::Auto,
    };
    let force_ssd = has(args, "--force-overwrite-ssd");
    if force_ssd && method == MethodOpt::Firmware {
        return Err("--force-overwrite-ssd et --method firmware sont incompatibles".into());
    }
    Ok(EraseOpts {
        plan,
        customer: base.merged(&over),
        technician,
        tag: opt(args, "--tag")?.unwrap_or_default(),
        dry_run: has(args, "--dry-run"),
        force_ssd,
        method,
        allow_fallback: has(args, "--allow-fallback"),
    })
}

fn describe_people(o: &EraseOpts) {
    let dash = |s: &str| {
        if s.is_empty() {
            "—".to_string()
        } else {
            s.to_string()
        }
    };
    println!("Client        : {}", dash(&o.customer.name));
    println!("Technicien    : {}", dash(&o.technician.name));
    if !o.tag.is_empty() {
        println!("Tag           : {}", o.tag);
    }
}

fn describe_plan(plan: &Plan) {
    println!(
        "Méthode       : {} (NIST 800-88 : {})",
        report::method_label(plan),
        MethodKind::Overwrite.level()
    );
    if plan.verify == VerifyMode::None {
        println!("ATTENTION     : sans vérification, le statut sera au mieux PARTIAL");
    }
    println!(
        "Passes        : {}",
        plan.passes
            .iter()
            .map(Fill::label)
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Vérification  : {}", plan.verify.label());
}

// ---------- Ctrl+C ----------

/// Arrêt demandé (Ctrl+C, Ctrl+Pause, fermeture de la fenêtre…).
static CANCEL: AtomicBool = AtomicBool::new(false);
/// Vrai pendant une opération à terminer proprement (préparation, effacement, certificat).
static BUSY: AtomicBool = AtomicBool::new(false);

/// Délai d'attente maximal après une fermeture : Windows tue le processus ~5 s après CTRL_CLOSE_EVENT.
const CLOSE_WAIT: Duration = Duration::from_millis(4500);

/// Événements après lesquels Windows termine le processus dès le retour du gestionnaire :
/// CTRL_CLOSE_EVENT (2), CTRL_LOGOFF_EVENT (5), CTRL_SHUTDOWN_EVENT (6).
fn must_wait(ctrl_type: u32) -> bool {
    matches!(ctrl_type, 2 | 5 | 6)
}

/// Attend (au plus `max`) que `busy` repasse à faux. Renvoie vrai si c'est terminé.
fn wait_until_idle(busy: &AtomicBool, max: Duration) -> bool {
    let start = Instant::now();
    while busy.load(Ordering::SeqCst) {
        if start.elapsed() >= max {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

unsafe extern "system" fn on_ctrl(ctrl_type: u32) -> windows_sys::core::BOOL {
    CANCEL.store(true, Ordering::SeqCst);
    if must_wait(ctrl_type) {
        // Laisse le moteur s'arrêter et le certificat ABORTED s'écrire avant la fin du processus.
        wait_until_idle(&BUSY, CLOSE_WAIT);
    }
    1 // géré : le moteur s'arrête proprement et le certificat est produit
}

/// Marque une opération en cours ; libérée automatiquement (même sur erreur).
struct BusyGuard;

impl BusyGuard {
    fn new() -> BusyGuard {
        BUSY.store(true, Ordering::SeqCst);
        BusyGuard
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::SeqCst);
    }
}

fn install_ctrl_handler() {
    // SAFETY: on enregistre une fonction `extern "system"` statique qui ne fait qu'écrire un atomique.
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1);
    }
}

// ---------- Effacement + certificat ----------

fn print_progress(p: &Progress) {
    let phase = match p.phase {
        Phase::Write => "Écriture",
        Phase::Verify => "Vérification",
    };
    let pct = p.done as f64 / p.total.max(1) as f64 * 100.0;
    let e = p.errors;
    print!(
        "\r{phase:<12} passe {}/{}  {pct:6.2} %  {:8.1} MB/s  erreurs {}/{}/{} (reprises {})   ",
        p.pass_index + 1,
        p.pass_total,
        p.speed_mb_s,
        e.pass,
        e.sync,
        e.verify,
        e.retries
    );
    let _ = std::io::stdout().flush();
}

/// Progression limitée à 5 affichages par seconde.
fn throttled_progress() -> impl FnMut(&Progress) {
    let mut last = Instant::now() - Duration::from_secs(1);
    move |p: &Progress| {
        if last.elapsed() >= Duration::from_millis(200) || p.done == p.total {
            print_progress(p);
            last = Instant::now();
        }
    }
}

fn print_status(s: &str) {
    print!("\r{s:<70}");
    let _ = std::io::stdout().flush();
}

fn load_logo(paths: &Paths) -> Option<pdf::Image> {
    let path = paths.assets.join("logo.png");
    let bytes = std::fs::read(&path).ok()?;
    match pdf::Image::from_png(&bytes) {
        Ok(img) => Some(img),
        Err(e) => {
            eprintln!("ATTENTION : logo {} ignoré ({e})", path.display());
            None
        }
    }
}

/// Champs communs d'un RecordInput.
#[allow(clippy::too_many_arguments)]
fn record_input<'a>(
    disk: &'a DiskInfo,
    plan: &'a Plan,
    outcome: &'a erase_hdd::Outcome,
    kind: MethodKind,
    o: &EraseOpts,
    cfg: &Config,
    start: DateTime,
    notes: Vec<String>,
    target: &Target,
) -> RecordInput<'a> {
    RecordInput {
        disk,
        plan,
        outcome,
        kind,
        degraded: false,
        org: cfg.company.clone(),
        technician: o.technician.clone(),
        customer: o.customer.clone(),
        tag: o.tag.clone(),
        start,
        end: DateTime::now(),
        notes,
        smart: target.smart.clone(),
        test_target: target.test_target,
        ssd_overwrite: target.ssd_overwrite,
        hidden: target.hidden.clone(),
        real_size: target.real_size,
        firmware: None,
    }
}

/// Écrit le certificat (jamais d'écrasement d'un fichier existant), l'historique et le
/// journal, affiche le résumé. Renvoie le code de sortie.
fn finish(rec: &EraseRecord, paths: &Paths) -> Result<i32, String> {
    let pdf_bytes = certificate::render(rec, load_logo(paths));
    let mut pdf_path: PathBuf = paths.certificates.join(format!("{}.pdf", rec.id));
    let mut k = 2;
    let mut file = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pdf_path)
        {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && k < 100 => {
                pdf_path = paths.certificates.join(format!("{}-{k}.pdf", rec.id));
                k += 1;
            }
            Err(e) => {
                return Err(format!(
                    "écriture du certificat {} impossible : {e}",
                    pdf_path.display()
                ))
            }
        }
    };
    file.write_all(&pdf_bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| {
            format!(
                "écriture du certificat {} impossible : {e}",
                pdf_path.display()
            )
        })?;
    report::append_history(&paths.history, rec)?;
    // Journal texte (une ligne par effacement + notes critiques) ; non bloquant.
    let mut line = format!(
        "{} {} {} {} {} {}\n",
        rec.end,
        rec.id,
        rec.status.code(),
        detect::serial_or_none(&rec.disk.serial),
        rec.method,
        pdf_path.display()
    );
    for n in rec
        .notes
        .iter()
        .filter(|n| n.starts_with("DISQUE VERROUILLÉ") || n.starts_with("REPLI"))
    {
        line.push_str(&format!("    {n}\n"));
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.logs.join("effacements.log"));
    if let Err(e) = log.and_then(|mut f| f.write_all(line.as_bytes())) {
        eprintln!("ATTENTION : journal non écrit ({e})");
    }

    for n in rec
        .notes
        .iter()
        .filter(|n| n.starts_with("DISQUE VERROUILLÉ"))
    {
        eprintln!("ATTENTION : {n}");
    }
    println!(
        "Statut        : {} ({}) — NIST 800-88 : {}",
        rec.status.code(),
        rec.status.fr(),
        rec.level
    );
    println!("Méthode       : {}", rec.method);
    println!("Vérification  : {} ({})", rec.verify, rec.verify_result);
    println!("HPA/DCO       : {}", rec.hpa_dco);
    println!(
        "Octets effacés: {} / {} ({:.2} %)",
        rec.bytes_erased, rec.disk.size_bytes, rec.percent
    );
    let e = rec.errors();
    println!(
        "Erreurs       : passe {} · sync {} · vérif. {} · reprises {}",
        e.pass, e.sync, e.verify, e.retries
    );
    println!("Certificat    : {}", pdf_path.display());
    Ok(if rec.status == Status::Erased { 0 } else { 2 })
}

/// Écrasement (moteur HDD), certificat et historique.
fn run_erase(
    dev: &mut dyn BlockDevice,
    disk: &DiskInfo,
    o: &EraseOpts,
    cfg: &Config,
    paths: &Paths,
    target: Target,
) -> Result<i32, String> {
    // Arrêt demandé pendant la préparation : on n'a encore rien écrit, pas de certificat.
    if CANCEL.load(Ordering::SeqCst) {
        return Err("interrompu avant le début de l'effacement : rien n'a été écrit".into());
    }
    let mut notes = target.notes.clone();
    println!("Taille effacée : {} octets", dev.size());
    let start = DateTime::now();
    let outcome = erase_hdd::erase(dev, &o.plan, &CANCEL, &mut throttled_progress());
    println!();
    if let Some(r) = &outcome.abort_reason {
        notes.push(format!("Arrêt : {r}"));
    } else if outcome.aborted {
        notes.push("Effacement interrompu par l'opérateur (Ctrl+C)".to_string());
    }
    let rec = report::build_record(record_input(
        disk,
        &o.plan,
        &outcome,
        MethodKind::Overwrite,
        o,
        cfg,
        start,
        notes,
        &target,
    ));
    finish(&rec, paths)
}

/// Repli Clear (TRIM + 1 passe aléatoire + vérification) puis certificat.
#[allow(clippy::too_many_arguments)]
fn run_fallback_erase(
    dev: &mut rawdisk::RawDisk,
    disk: &DiskInfo,
    mut report: FirmwareReport,
    trim: bool,
    o: &EraseOpts,
    cfg: &Config,
    paths: &Paths,
    target: &Target,
    mut notes: Vec<String>,
    start: DateTime,
) -> Result<i32, String> {
    println!(
        "Repli Clear : {}écrasement 1 passe aléatoire + vérification complète",
        if trim { "TRIM complet + " } else { "" }
    );
    let plan = erase_ssd::fallback_plan(o.plan.seed);
    let (fb, outcome) =
        erase_ssd::run_fallback(dev, trim, &plan, &CANCEL, &mut throttled_progress());
    println!();
    match &fb.trim {
        Some(Ok(())) => notes.push("TRIM complet : OK".into()),
        Some(Err(e)) => notes.push(format!("TRIM refusé : {e}")),
        None => notes.push("TRIM non supporté ou non signalé : non effectué".into()),
    }
    if let Some(r) = &outcome.abort_reason {
        notes.push(format!("Arrêt : {r}"));
    } else if outcome.aborted {
        notes.push("Effacement interrompu par l'opérateur (Ctrl+C)".to_string());
    }
    report.fallback = Some(fb);
    let mut input = record_input(
        disk,
        &plan,
        &outcome,
        MethodKind::Overwrite,
        o,
        cfg,
        start,
        notes,
        target,
    );
    input.ssd_overwrite = false;
    input.firmware = Some(report);
    finish(&report::build_record(input), paths)
}

/// Commande firmware avec vérification par marqueurs ; repli si demandé.
#[allow(clippy::too_many_arguments)]
fn run_firmware_erase(
    dev: &mut rawdisk::RawDisk,
    disk: &DiskInfo,
    m: FwMethod,
    probe: &Probe,
    media: MediaType,
    o: &EraseOpts,
    cfg: &Config,
    paths: &Paths,
    target: Target,
) -> Result<i32, String> {
    if CANCEL.load(Ordering::SeqCst) {
        return Err("interrompu avant le début de l'effacement : rien n'a été écrit".into());
    }
    let start = DateTime::now();
    let t0 = Instant::now();
    println!("Méthode firmware : {m}");
    println!(
        "(Ctrl+C n'arrête pas une commande firmware déjà lancée : le disque la termine seul.)"
    );
    let ctx = erase_ssd::FwContext {
        method: m,
        media,
        caps: &probe.caps,
        seed: o.plan.seed,
        markers: erase_ssd::MARKER_COUNT,
        poll: Duration::from_secs(5),
        cancel: &CANCEL,
    };
    let run = erase_ssd::run_firmware(dev, &ctx, &mut std::thread::sleep, &mut print_status);
    println!();
    for l in &run.log {
        println!("  {l}");
    }
    for c in &run.report.critical {
        eprintln!("ATTENTION : {c}");
    }
    let mut notes = target.notes.clone();
    notes.extend(run.notes.iter().cloned());
    let cancelled = CANCEL.load(Ordering::SeqCst);

    if run.failed() && run.attempted && run.maybe_busy {
        eprintln!("ATTENTION : {}", erase_ssd::NOTE_NO_FALLBACK_BUSY);
        notes.insert(0, erase_ssd::NOTE_NO_FALLBACK_BUSY.to_string());
    } else if run.failed() && !o.allow_fallback {
        notes.push("Repli non autorisé (option --allow-fallback absente)".into());
    }
    if run.fallback_allowed(o.allow_fallback) && !cancelled {
        return run_fallback_erase(
            dev,
            disk,
            run.report.clone(),
            probe.caps.trim(),
            o,
            cfg,
            paths,
            &target,
            notes,
            start,
        );
    }
    let mut outcome = erase_ssd::firmware_outcome(dev.size(), &run, t0.elapsed());
    if cancelled && !run.attempted {
        outcome.aborted = true;
        notes.push("Interrompu par l'opérateur avant la commande firmware (marqueurs éventuellement écrits)".into());
    }
    let mut input = record_input(
        disk,
        &o.plan,
        &outcome,
        MethodKind::Firmware,
        o,
        cfg,
        start,
        notes,
        &target,
    );
    input.ssd_overwrite = false;
    input.firmware = Some(run.report.clone());
    finish(&report::build_record(input), paths)
}

// ---------- Lecture des capacités (lecture seule) ----------

fn probe_disk(disk: &DiskInfo) -> Probe {
    let mut p = if disk.bus == Bus::Nvme {
        match nvme::ReadOnlyNvme::open(disk.number) {
            Ok(mut port) => erase_ssd::probe_nvme(&mut port),
            Err(e) => Probe {
                hidden: Hidden::NotApplicable("NVMe : pas de HPA/DCO".into()),
                errors: vec![e],
                ..Default::default()
            },
        }
    } else {
        match ata::ReadOnlyAta::open(disk.number) {
            Ok(mut port) => erase_ssd::probe_ata(&mut port),
            Err(e) => Probe {
                hidden: Hidden::Unreadable(e.clone()),
                errors: vec![e],
                ..Default::default()
            },
        }
    };
    p.caps.trim_property = detect::trim_enabled(disk.number);
    p
}

fn print_probe(p: &Probe, media: MediaType, smart_table: bool) {
    if let Some(id) = &p.caps.ata {
        println!("--- ATA IDENTIFY ---");
        println!("Modèle        : {}", id.model);
        println!("N° de série   : {}", id.serial);
        println!("Firmware      : {}", id.firmware);
        println!(
            "Capacité      : {} secteurs × {} octets = {} ({}48 bits)",
            id.sectors,
            id.logical_sector,
            detect::human_size(id.sectors * id.logical_sector as u64),
            if id.lba48 { "" } else { "pas de " }
        );
        println!(
            "Rotation      : {}",
            match id.rotation {
                ata::Rotation::NonRotating => "aucune (SSD)".to_string(),
                ata::Rotation::Rpm(r) => format!("{r} tr/min"),
                _ => "non rapportée".to_string(),
            }
        );
        println!(
            "TRIM          : {} (lecture déterministe après TRIM {}, zéros {})",
            if id.trim { "oui" } else { "non" },
            if id.drat { "oui" } else { "non" },
            if id.rzat { "oui" } else { "non" }
        );
    }
    if let Some(c) = &p.caps.nvme {
        println!("--- NVMe Identify ---");
        println!("Modèle        : {}", c.model);
        println!("N° de série   : {}", c.serial);
        println!("Firmware      : {}", c.firmware);
        if c.tnvmcap > 0 {
            println!("Capacité NVM  : {}", smart::human_bytes(c.tnvmcap));
        }
        println!("Espaces noms  : {}", c.namespaces);
        println!("DSM (TRIM)    : {}", if c.dsm { "oui" } else { "non" });
    }
    if let Some(ns) = &p.caps.nvme_ns {
        println!(
            "Namespace 1   : {} blocs × {} octets = {} (format LBA {})",
            ns.nsze,
            ns.lba_size,
            detect::human_size(ns.size_bytes()),
            ns.lbaf_index
        );
    }
    if let Some(l) = &p.nvme_sanitize {
        println!(
            "Sanitize (81h): état {:?}, progression {}",
            l.state,
            l.progress_text()
        );
    }
    println!("HPA/DCO       : {}", p.hidden.label());
    if let Some(r) = p.real_size {
        println!("Taille réelle : {} ({r} octets)", detect::human_size(r));
    }
    if let Some(s) = &p.smart {
        println!("--- SMART (santé : {}) ---", s.health);
        for (k, v) in &s.info {
            println!("  {k:<26}: {v}");
        }
        if smart_table && !s.attrs.is_empty() {
            println!(
                "  {:>3} {:<26} {:>6} {:>5} {:>5} {:>6}  Brut",
                "ID", "Nom", "Flags", "Val", "Pire", "Seuil"
            );
            for a in &s.attrs {
                println!(
                    "  {:>3} {:<26} {:>6} {:>5} {:>5} {:>6}  {}{}",
                    a.id,
                    a.name,
                    a.flags,
                    a.value,
                    a.worst,
                    a.thresh,
                    a.raw,
                    if a.failing { "  <-- EN DÉFAUT" } else { "" }
                );
            }
        }
    }
    if !p.errors.is_empty() {
        println!("--- Lectures en échec ---");
        for e in &p.errors {
            println!("  {e}");
        }
    }
    let choice = erase_ssd::choose(&p.caps, media, p.caps.frozen());
    println!("--- Capacités d'effacement ({media}) ---");
    for l in erase_ssd::explain(&p.caps, media, &choice) {
        println!("  {l}");
    }
}

fn info_disk(n: &str) -> Result<i32, String> {
    let n: u32 = n
        .parse()
        .map_err(|_| "numéro de disque invalide".to_string())?;
    let disks = list_disks()?;
    let disk = disks
        .iter()
        .find(|d| d.number == n)
        .ok_or("disque introuvable")?;
    println!(
        "Disque {} : {} — n° de série {} — {} — bus {} — type {}",
        disk.number,
        disk.display_model(),
        detect::serial_or_none(&disk.serial),
        detect::human_size(disk.size_bytes),
        disk.bus,
        disk.media
    );
    println!("(lecture seule : aucune commande d'écriture ni d'effacement n'est envoyée)");
    let p = probe_disk(disk);
    let media = erase_ssd::effective_media(disk.media, p.caps.ata.as_ref());
    print_probe(&p, media, true);
    Ok(0)
}

fn erase_disk(args: &[String], n: &str, cfg: &Config, paths: &Paths) -> Result<i32, String> {
    // Gestionnaire Ctrl+C/fermeture installé AVANT toute préparation ou ouverture du disque.
    install_ctrl_handler();
    let _busy = BusyGuard::new();
    let n: u32 = n
        .parse()
        .map_err(|_| "numéro de disque invalide".to_string())?;
    let o = erase_opts(args, cfg, paths)?;
    let disks = list_disks()?;
    let disk = disks
        .iter()
        .find(|d| d.number == n)
        .ok_or("disque introuvable")?;
    let ctx = ProtectContext::detect();
    let code = opt(args, "--confirm")?.unwrap_or_default();

    for w in &ctx.warnings {
        eprintln!("ATTENTION : {w}");
    }
    safety::check_allowed(disk, &ctx, &code).map_err(|e| e.to_string())?;
    println!(
        "Disque {} : {} — n° de série {} — {}",
        disk.number,
        disk.display_model(),
        detect::serial_or_none(&disk.serial),
        detect::human_size(disk.size_bytes)
    );

    // Capacités, SMART et HPA/DCO : lus AVANT l'effacement, en lecture seule.
    let probe = probe_disk(disk);
    let media = erase_ssd::effective_media(disk.media, probe.caps.ata.as_ref());
    print_probe(&probe, media, false);
    let mopt = method_opt(o.method, o.force_ssd, media)?;
    let choice = erase_ssd::choose(&probe.caps, media, probe.caps.frozen());
    let decision = erase_ssd::decide(mopt, o.allow_fallback, media, &choice);
    println!("--- Décision ---");
    match &decision {
        Decision::Refuse(e) => return Err(e.clone()),
        Decision::Frozen(guide) => {
            eprintln!("{guide}");
            return Err("disque gelé : rien n'a été tenté".into());
        }
        Decision::Firmware(m) => println!(
            "Méthode       : {m} (NIST 800-88 : Purge si la commande réussit ET que tous les marqueurs sont effacés)\n\
             Vérification  : {} marqueurs (début, fin, positions aléatoires) écrits avant, relus après{}",
            erase_ssd::MARKER_COUNT + 2,
            if o.allow_fallback {
                "\nRepli         : autorisé (TRIM + 1 passe aléatoire + vérification, statut au mieux PARTIAL)"
            } else {
                "\nRepli         : non autorisé (échec = certificat FAILED)"
            }
        ),
        Decision::Fallback => println!(
            "Méthode       : Repli Clear — TRIM {}+ écrasement 1 passe aléatoire + vérification complète (statut au mieux PARTIAL)",
            if probe.caps.trim() { "" } else { "(non supporté) " }
        ),
        Decision::Overwrite { ssd, note } => {
            describe_plan(&o.plan);
            if *ssd {
                eprintln!(
                    "ATTENTION : {} — écrasement forcé, statut au mieux PARTIAL",
                    report::NOTE_SSD
                );
            }
            if let Some(n) = note {
                eprintln!("ATTENTION : {n}");
                eprintln!("{}", erase_ssd::FROZEN_GUIDE);
            }
            match probe.hidden.hidden_sectors() {
                Some(n) if n > 0 => eprintln!(
                    "ATTENTION : {} — l'écrasement ne les atteint pas, statut au mieux PARTIAL",
                    probe.hidden.label()
                ),
                None => eprintln!("ATTENTION : {}", report::NOTE_HIDDEN_UNKNOWN),
                _ => {}
            }
        }
    }
    describe_people(&o);

    // Autorisation + verrous des volumes : `prepared` vit jusqu'à la fin de la fonction,
    // donc pendant tout l'effacement ET la vérification.
    let prepared = safety::prepare_disk(disk, &ctx, &code, o.dry_run).map_err(|e| e.to_string())?;
    for l in &prepared.log {
        println!("{l}");
    }
    if o.dry_run {
        println!("[dry-run] aucune écriture, aucune commande firmware, aucun certificat.");
        return Ok(0);
    }

    // Revérifie protection + identité, ouvre le disque, puis le met hors ligne
    // (remis en ligne automatiquement quand `dev` est détruit).
    let firmware_follows = matches!(decision, Decision::Firmware(_) | Decision::Fallback);
    let mut dev = rawdisk::RawDisk::open_for(&prepared, firmware_follows)?;
    let mut notes = vec![format!("Cible : disque {} ({})", disk.number, disk.path)];
    notes.extend(prepared.warnings.iter().cloned());
    notes.extend(dev.notes.iter().cloned());
    for e in &probe.errors {
        notes.push(format!("Lecture avant effacement : {e}"));
    }
    let mut disk_rec = disk.clone();
    disk_rec.media = media;
    let mut target = Target {
        notes,
        test_target: false,
        ssd_overwrite: false,
        smart: probe.smart.clone(),
        hidden: probe.hidden.clone(),
        real_size: probe.real_size,
    };
    let result = match decision {
        Decision::Overwrite { ssd, note } => {
            target.ssd_overwrite = ssd;
            if let Some(n) = note {
                target.notes.insert(0, n);
            }
            run_erase(&mut dev, &disk_rec, &o, cfg, paths, target)
        }
        Decision::Firmware(m) => run_firmware_erase(
            &mut dev, &disk_rec, m, &probe, media, &o, cfg, paths, target,
        ),
        Decision::Fallback => {
            let report = FirmwareReport {
                label: report::NO_FIRMWARE_LABEL.into(),
                kind: FirmwareKind::Sanitize,
                command_ok: false,
                markers: None,
                fallback: None,
                critical: Vec::new(),
            };
            let notes = target.notes.clone();
            run_fallback_erase(
                &mut dev,
                &disk_rec,
                report,
                probe.caps.trim(),
                &o,
                cfg,
                paths,
                &target,
                notes,
                DateTime::now(),
            )
        }
        Decision::Refuse(_) | Decision::Frozen(_) => unreachable!("traités avant la préparation"),
    };
    // Ordre explicite : poignée fermée et disque remis en ligne, PUIS volumes déverrouillés.
    drop(dev);
    drop(prepared);
    result
}

fn erase_file(args: &[String], file: &str, cfg: &Config, paths: &Paths) -> Result<i32, String> {
    install_ctrl_handler();
    let _busy = BusyGuard::new();
    // Garde-fou : --erase-file ne doit jamais servir à contourner les sécurités disque.
    let lower = file.to_ascii_lowercase();
    if lower.starts_with(r"\\.\") || lower.starts_with(r"\\?\") || lower.starts_with("//./") {
        return Err(
            "--erase-file n'accepte qu'un fichier ordinaire (utiliser --erase pour un disque)"
                .into(),
        );
    }
    let path = Path::new(file);
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("fichier {} inaccessible : {e}", path.display()))?;
    if !meta.is_file() {
        return Err(format!("{} n'est pas un fichier ordinaire", path.display()));
    }
    let o = erase_opts(args, cfg, paths)?;
    if o.method == MethodOpt::Firmware {
        return Err(
            "--method firmware : impossible sur un fichier de test (écrasement uniquement)".into(),
        );
    }
    let mut dev = erase_hdd::FileDevice::open(path)
        .map_err(|e| format!("ouverture de {} impossible : {e}", path.display()))?;
    if dev.size() == 0 {
        return Err("fichier de test trop petit (moins de 512 octets)".into());
    }
    let disk = DiskInfo {
        number: 0,
        path: path.display().to_string(),
        vendor: String::new(),
        model: "Fichier de test".into(),
        serial: "TESTFILE".into(),
        firmware: String::new(),
        size_bytes: dev.size(),
        bus: Bus::Virtual,
        media: MediaType::Unknown,
        removable: false,
        volumes: vec![],
    };
    println!("Fichier de test : {}", path.display());
    describe_plan(&o.plan);
    describe_people(&o);
    if o.dry_run {
        println!("[dry-run] aucune écriture, aucun certificat.");
        return Ok(0);
    }
    let target = Target {
        notes: vec![format!("Cible : fichier de test {}", path.display())],
        test_target: true,
        ssd_overwrite: false,
        smart: None,
        hidden: Hidden::NotApplicable("fichier de test".into()),
        real_size: Some(dev.size()),
    };
    run_erase(&mut dev, &disk, &o, cfg, paths, target)
}

// ---------- Autres commandes ----------

fn list_disks() -> Result<Vec<DiskInfo>, String> {
    detect::list_disks().map_err(|e| match e {
        detect::DetectError::NeedAdmin => {
            "droits administrateur requis (clic droit → Exécuter en tant qu'administrateur, ou Lancer.bat)".to_string()
        }
        other => other.to_string(),
    })
}

fn print_disks(disks: &[DiskInfo], ctx: &ProtectContext) {
    println!(
        "{:<3} {:<28} {:<18} {:>8} {:<6} {:<5} État",
        "N°", "Modèle", "N° de série", "Taille", "Bus", "Type"
    );
    for d in disks {
        let state = match ctx.reason(d) {
            Some(p) => format!("PROTÉGÉ — {p}"),
            None => "Effaçable".to_string(),
        };
        let vols = if d.volumes.is_empty() {
            String::new()
        } else {
            format!(
                "  [{}]",
                d.volumes
                    .iter()
                    .map(|c| format!("{c}:"))
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        println!(
            "{:<3} {:<28} {:<18} {:>8} {:<6} {:<5} {}{}",
            d.number,
            d.display_model(),
            detect::serial_or_none(&d.serial),
            detect::human_size(d.size_bytes),
            d.bus.to_string(),
            d.media.to_string(),
            if d.removable {
                format!("{state} (amovible)")
            } else {
                state
            },
            vols
        );
    }
}

fn print_history(paths: &Paths) -> Result<(), String> {
    let all = report::load_history(&paths.history)?;
    if all.is_empty() {
        println!("Historique vide.");
        return Ok(());
    }
    println!(
        "{:<27} {:<20} {:<8} {:<24} {:<16} Client",
        "ID", "Fin", "Statut", "Modèle", "N° de série"
    );
    for r in &all {
        println!(
            "{:<27} {:<20} {:<8} {:<24} {:<16} {}",
            r.id,
            r.end,
            r.status.code(),
            pdf::fit(&r.disk.model, pdf::Font::Mono, 10.0, 24.0 * 6.0),
            detect::serial_or_none(&r.disk.serial),
            r.customer.name
        );
    }
    println!("{} effacement(s).", all.len());
    Ok(())
}

fn run(args: &[String]) -> Result<i32, String> {
    if has(args, "--version") {
        println!("{APP_NAME} {VERSION}");
        return Ok(0);
    }
    if args.is_empty() || has(args, "--help") || has(args, "-h") {
        println!("{}", USAGE.replace("{APP}", APP_NAME));
        return Ok(0);
    }

    let paths = Paths::from_exe();
    if let Some(w) = &paths.warning {
        eprintln!("ATTENTION : {w}");
    }
    let cfg = Config::load(&paths.config_file())?;

    if has(args, "--history") {
        print_history(&paths)?;
        return Ok(0);
    }
    if let Some(out) = opt(args, "--export-csv")? {
        let all = report::load_history(&paths.history)?;
        std::fs::write(&out, report::export_csv(&all))
            .map_err(|e| format!("écriture de {out} impossible : {e}"))?;
        println!("{} effacement(s) exporté(s) vers {out}", all.len());
        return Ok(0);
    }
    if has(args, "--clients") {
        let book = config::load_clients(&paths.clients_file())?;
        if book.is_empty() {
            println!(
                "Carnet de clients vide ({}).",
                paths.clients_file().display()
            );
        }
        for (id, c) in &book {
            println!("{id:<20} {}", c.name);
        }
        return Ok(0);
    }
    if let Some(file) = opt(args, "--erase-file")? {
        return erase_file(args, &file, &cfg, &paths);
    }
    if let Some(n) = opt(args, "--erase")? {
        return erase_disk(args, &n, &cfg, &paths);
    }
    if let Some(n) = opt(args, "--info")? {
        return info_disk(&n);
    }
    if has(args, "--list") {
        let ctx = ProtectContext::detect();
        print_disks(&list_disks()?, &ctx);
        for w in &ctx.warnings {
            println!("ATTENTION : {w}");
        }
        if !ctx.reliable {
            println!("Protection non fiable : tout effacement sera refusé.");
        }
        return Ok(0);
    }
    if let Some(n) = opt(args, "--prepare")? {
        let n: u32 = n
            .parse()
            .map_err(|_| "numéro de disque invalide".to_string())?;
        let disks = list_disks()?;
        let disk = disks
            .iter()
            .find(|d| d.number == n)
            .ok_or("disque introuvable")?;
        let code = opt(args, "--confirm")?.unwrap_or_default();
        let prepared = safety::prepare_disk(
            disk,
            &ProtectContext::detect(),
            &code,
            has(args, "--dry-run"),
        )
        .map_err(|e| e.to_string())?;
        for l in &prepared.log {
            println!("{l}");
        }
        return Ok(0);
    }

    Err("commande inconnue (voir --help)".into())
}

/// Console en UTF-8 (sinon cp850 et accents cassés). Échec ignoré : l'outil continue.
fn set_console_utf8() {
    use windows_sys::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};
    const CP_UTF8: u32 = 65001;
    // SAFETY: simples appels sans pointeur ; un échec (pas de console) est sans conséquence.
    unsafe {
        let _ = SetConsoleOutputCP(CP_UTF8);
        let _ = SetConsoleCP(CP_UTF8);
    }
}

fn main() {
    set_console_utf8();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("Erreur : {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn option_values() {
        let args = a(&["--erase-file", "x.img", "--tag", "INV-1", "--customer"]);
        assert_eq!(opt(&args, "--tag").unwrap(), Some("INV-1".into()));
        assert_eq!(opt(&args, "--nope").unwrap(), None);
        assert!(opt(&args, "--customer").is_err());
        assert!(opt(&a(&["--tag", "--dry-run"]), "--tag").is_err());
    }

    #[test]
    fn force_overwrite_ssd_is_an_alias_of_method_overwrite_for_ssd() {
        for m in [MediaType::Ssd, MediaType::Nvme, MediaType::Unknown] {
            assert_eq!(
                method_opt(MethodOpt::Auto, true, m),
                Ok(MethodOpt::Overwrite)
            );
            assert_eq!(method_opt(MethodOpt::Auto, false, m), Ok(MethodOpt::Auto));
        }
        // HDD : sans effet (auto garde Purge d'abord).
        assert_eq!(
            method_opt(MethodOpt::Auto, true, MediaType::Hdd),
            Ok(MethodOpt::Auto)
        );
        assert!(method_opt(MethodOpt::Firmware, true, MediaType::Ssd).is_err());
        assert!(USAGE.contains("--force-overwrite-ssd"));
        let o = erase_opts(
            &a(&["--force-overwrite-ssd"]),
            &Config::default(),
            &test_paths(),
        )
        .unwrap();
        assert!(o.force_ssd);
        assert_eq!(o.method, MethodOpt::Auto);
        assert!(erase_opts(
            &a(&["--force-overwrite-ssd", "--method", "firmware"]),
            &Config::default(),
            &test_paths()
        )
        .is_err());
    }

    #[test]
    fn method_and_fallback_options() {
        let o = erase_opts(
            &a(&["--method", "firmware", "--allow-fallback"]),
            &Config::default(),
            &test_paths(),
        )
        .unwrap();
        assert_eq!(o.method, MethodOpt::Firmware);
        assert!(o.allow_fallback);
        let o = erase_opts(&a(&[]), &Config::default(), &test_paths()).unwrap();
        assert_eq!(o.method, MethodOpt::Auto);
        assert!(!o.allow_fallback);
        assert!(erase_opts(
            &a(&["--method", "magie"]),
            &Config::default(),
            &test_paths()
        )
        .is_err());
        for s in [
            "--info N",
            "--method auto|firmware|overwrite",
            "--allow-fallback",
            "LECTURE SEULE",
        ] {
            assert!(USAGE.contains(s), "{s}");
        }
    }

    fn test_paths() -> Paths {
        let root = std::env::temp_dir().join(format!("diskerase-main-{}", std::process::id()));
        Paths::resolve(&root, &std::env::temp_dir())
    }

    #[test]
    fn close_events_wait_for_a_clean_stop_with_a_bound() {
        assert!(!must_wait(0)); // Ctrl+C
        assert!(!must_wait(1)); // Ctrl+Pause
        assert!(must_wait(2) && must_wait(5) && must_wait(6)); // fermeture, déconnexion, arrêt
                                                               // Opération terminée pendant l'attente.
        let busy = std::sync::Arc::new(AtomicBool::new(true));
        let b = busy.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            b.store(false, Ordering::SeqCst);
        });
        assert!(wait_until_idle(&busy, Duration::from_secs(5)));
        t.join().unwrap();
        // Opération bloquée : l'attente est bornée.
        let stuck = AtomicBool::new(true);
        let start = Instant::now();
        assert!(!wait_until_idle(&stuck, Duration::from_millis(200)));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn prepare_help_says_it_is_a_test_and_locks_are_released() {
        assert!(USAGE.contains("TEST de préparation"));
        assert!(USAGE.contains("relâchés à la fin de la commande"));
    }

    #[test]
    fn passes_parsing() {
        assert_eq!(
            parse_passes(&a(&["0x00", " random "])).unwrap(),
            vec![Fill::Byte(0), Fill::Random]
        );
        assert!(parse_passes(&a(&[""])).is_err());
        assert!(parse_passes(&a(&["0xZZ"])).is_err());
    }
}
