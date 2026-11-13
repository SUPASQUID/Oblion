//! Ligne de commande (mode de secours), partagée par `oblion.exe` et `oblion-cli.exe`.
//! Toute la logique d'effacement passe par `job` (même code que l'interface).

use crate::{ata, config, erase_hdd, erase_ssd, job, pdf, report, smart};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::app::{APP_NAME, VERSION};
use crate::config::{Config, Customer, CustomerOverride, Paths, Technician};
use crate::detect::{self, Bus, DiskInfo, MediaType};
use crate::erase_hdd::{BlockDevice, Phase, Plan, Progress, VerifyMode};
use crate::erase_ssd::{MethodOpt, Probe};
use crate::hpa::Hidden;
use crate::job::{DiskBackend, EraseOpts, Event, JobError, RealBackend};
use crate::safety::ProtectContext;

pub const USAGE: &str = "\
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

pub fn has(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Valeur d'une option ; une option présente sans valeur est une erreur.
pub fn opt(args: &[String], name: &str) -> Result<Option<String>, String> {
    match args.iter().position(|a| a == name) {
        None => Ok(None),
        Some(i) => match args.get(i + 1) {
            Some(v) if !v.starts_with("--") => Ok(Some(v.clone())),
            _ => Err(format!("valeur manquante après {name}")),
        },
    }
}

fn erase_opts(args: &[String], cfg: &Config, paths: &Paths) -> Result<EraseOpts, String> {
    let passes = match opt(args, "--passes")? {
        Some(s) => job::parse_passes(&s.split(',').map(str::to_string).collect::<Vec<_>>())?,
        None => job::parse_passes(&cfg.erase.hdd_passes)?,
    };
    let verify =
        VerifyMode::parse(&opt(args, "--verify")?.unwrap_or_else(|| cfg.erase.verify.clone()))?;
    let mut plan = Plan::dod_default(job::seed());
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

// ---------- Affichage console ----------

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

/// Puits d'événements de la CLI : mêmes sorties qu'avant l'extraction dans `job`.
fn cli_sink() -> impl FnMut(Event) {
    let mut throttle = throttled_progress();
    move |e| match e {
        Event::Line(s) => println!("{s}"),
        Event::Warn(s) => eprintln!("{s}"),
        Event::Progress(p) => throttle(&p),
        Event::Status(s) => print_status(&s),
        Event::EndProgress => println!(),
    }
}

// ---------- Lecture des capacités (lecture seule) ----------

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
    let p = RealBackend.probe(disk);
    let media = erase_ssd::effective_media(disk.media, p.caps.ata.as_ref());
    print_probe(&p, media, true);
    Ok(0)
}

fn erase_disk(args: &[String], n: &str, cfg: &Config, paths: &Paths) -> Result<i32, JobError> {
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
    let backend = RealBackend;
    let code = opt(args, "--confirm")?.unwrap_or_default();
    let mut sink = cli_sink();
    let mut c = job::Ctx {
        cfg,
        paths,
        cancel: &CANCEL,
        interrupted_by: "Ctrl+C",
        sink: &mut sink,
        write_started: None,
    };
    // Contexte de protection frais et relecture du disque : dans job::erase_disk.
    let done = job::erase_disk(
        &mut c,
        &backend,
        disk,
        &code,
        &o,
        &mut |_, p: &Probe, media| print_probe(p, media, false),
        None,
    )?;
    Ok(done.exit_code())
}

fn erase_file(args: &[String], file: &str, cfg: &Config, paths: &Paths) -> Result<i32, JobError> {
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
        return Err(format!("{} n'est pas un fichier ordinaire", path.display()).into());
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
    let mut sink = cli_sink();
    let mut c = job::Ctx {
        cfg,
        paths,
        cancel: &CANCEL,
        interrupted_by: "Ctrl+C",
        sink: &mut sink,
        write_started: None,
    };
    println!("Fichier de test : {}", path.display());
    job::describe_plan(&mut c, &o.plan);
    job::describe_people(&mut c, &o);
    if o.dry_run {
        println!("[dry-run] aucune écriture, aucun certificat.");
        return Ok(0);
    }
    let target = job::Target {
        notes: vec![format!("Cible : fichier de test {}", path.display())],
        test_target: true,
        ssd_overwrite: false,
        smart: None,
        hidden: Hidden::NotApplicable("fichier de test".into()),
        real_size: Some(dev.size()),
        demo: false,
    };
    job::run_erase(&mut c, &mut dev, &disk, &o, target).map(|f| f.code)
}

// ---------- Autres commandes ----------

fn list_disks() -> Result<Vec<DiskInfo>, String> {
    RealBackend.list_disks().map_err(|e| e.to_string())
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

pub fn run(args: &[String]) -> Result<i32, JobError> {
    if has(args, "--version") {
        println!("{APP_NAME} {VERSION}");
        return Ok(0);
    }
    if args.is_empty() || has(args, "--help") || has(args, "-h") {
        println!("{}", USAGE.replace("{APP}", &exe_name()));
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
        return Ok(info_disk(&n)?);
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
        let backend = RealBackend;
        let prepared = backend.prepare(
            disk,
            &backend.protect_context(),
            &code,
            has(args, "--dry-run"),
        )?;
        for l in prepared.log() {
            println!("{l}");
        }
        return Ok(0);
    }

    Err("commande inconnue (voir --help)".into())
}

/// Console en UTF-8 (sinon cp850 et accents cassés). Échec ignoré : l'outil continue.
/// Nom de l'exécutable lancé (oblion, oblion-cli…), pour l'aide.
fn exe_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_stem().map(|s| s.to_string_lossy().into_owned()))
        .unwrap_or_else(|| APP_NAME.to_lowercase())
}

/// Point d'entrée commun de la ligne de commande. `extra_help` : texte ajouté à l'aide.
/// Codes de sortie : 0 ERASED, 2 autre statut, 1 erreur sans écriture, 3 erreur APRÈS le
/// début de l'écriture (disque modifié, certificat non écrit).
pub fn main_cli(args: &[String], extra_help: Option<&str>) -> i32 {
    set_console_utf8();
    if let Some(h) = extra_help {
        if args.is_empty() || has(args, "--help") || has(args, "-h") {
            println!(
                "{h}
"
            );
        }
    }
    let code = match run(args) {
        Ok(code) => code,
        Err(JobError::NotStarted(e)) => {
            eprintln!("Erreur : {e}");
            1
        }
        Err(e @ JobError::AfterWrite(_)) => {
            eprintln!("ERREUR : {e}");
            eprintln!(
                "Le disque a été au moins partiellement écrit : il n'est plus intact. Détails dans data/logs/effacements.log."
            );
            3
        }
    };
    let _ = std::io::stdout().flush();
    code
}

pub fn set_console_utf8() {
    use windows_sys::Win32::System::Console::{SetConsoleCP, SetConsoleOutputCP};
    const CP_UTF8: u32 = 65001;
    // SAFETY: simples appels sans pointeur ; un échec (pas de console) est sans conséquence.
    unsafe {
        let _ = SetConsoleOutputCP(CP_UTF8);
        let _ = SetConsoleCP(CP_UTF8);
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
    fn force_overwrite_ssd_option() {
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
        let root = std::env::temp_dir().join(format!("oblion-main-{}", std::process::id()));
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

    /// La CLI et l'interface passent par le même module : la CLI n'appelle plus RawDisk
    /// ni prepare_disk directement.
    #[test]
    fn cli_uses_the_shared_job_module() {
        let src = include_str!("cli.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(body.contains("job::erase_disk("));
        assert!(body.contains("job::run_erase("));
        for forbidden in ["RawDisk::open_for", "prepare_disk(", "run_firmware("] {
            assert!(!body.contains(forbidden), "{forbidden}");
        }
    }
}
