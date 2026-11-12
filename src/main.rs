//! Point d'entrée. Mode console (l'interface graphique arrive à l'étape 4).
mod app;
mod certificate;
mod clock;
mod config;
mod detect;
mod erase_hdd;
mod erase_ssd;
mod pdf;
mod rawdisk;
mod report;
mod safety;
mod ui;
mod verify;
mod winio;

use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use app::{APP_NAME, VERSION};
use clock::DateTime;
use config::{Config, Customer, CustomerOverride, Paths, Technician};
use detect::{Bus, DiskInfo, MediaType};
use erase_hdd::{BlockDevice, Fill, Phase, Plan, Progress, VerifyMode};
use report::{MethodKind, RecordInput, Status};
use safety::ProtectContext;

const USAGE: &str = "\
Usage :
  {APP} --list                              Liste les disques détectés
  {APP} --prepare N --confirm XXXX [--dry-run]
                                            TEST de préparation : vérifie les règles puis
                                            verrouille et démonte les volumes du disque N ;
                                            les verrous sont relâchés à la fin de la commande
                                            (rien n'est effacé, le disque n'est pas mis hors ligne)
                                            (XXXX = 4 derniers caractères du n° de série ;
                                             n° COMPLET s'ils sont identiques, ex. « 0000 » ;
                                             D<n°>-<taille en Go> sans n° de série)
  {APP} --erase N --confirm XXXX [options] [--dry-run]
                                            Efface le disque N et produit un certificat PDF
                                            (--dry-run : affiche le plan, n'écrit rien)
  {APP} --erase-file <fichier> [options]    Même chaîne sur un fichier de test
                                            (certificat marqué « TEST SUR FICHIER »)
  {APP} --history                           Liste les effacements enregistrés
  {APP} --export-csv <fichier.csv>          Exporte l'historique en CSV (Excel)
  {APP} --clients                           Liste le carnet de clients (data/clients.toml)
  {APP} --version | --help

Options d'effacement :
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
  --force-overwrite-ssd         Autorise l'écrasement d'un SSD/NVMe (ou type inconnu).
                                Refusé par défaut : l'écrasement ne garantit pas l'effacement
                                d'un SSD (sur-provisionnement). Statut au mieux PARTIAL.

Ce programme est DESTRUCTIF. --dry-run n'écrit et ne modifie rien.
Ctrl+C (ou fermeture de la fenêtre) interrompt proprement : un certificat « ABORTED »
est quand même produit.";

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
}

/// Cible de l'effacement, pour le certificat.
struct Target {
    notes: Vec<String>,
    test_target: bool,
    ssd_overwrite: bool,
}

const SSD_REFUSED: &str = "l'écrasement ne garantit pas l'effacement d'un SSD ; Sanitize/Secure Erase arrive à l'étape 3 \
     (option --force-overwrite-ssd pour écraser quand même, statut au mieux PARTIAL)";

/// Écrasement autorisé ? Ok(true) = écrasement forcé sur SSD/NVMe/inconnu.
fn ssd_policy(media: MediaType, force: bool) -> Result<bool, String> {
    match media {
        MediaType::Hdd => Ok(false),
        _ if force => Ok(true),
        other => Err(format!("disque de type {other} : {SSD_REFUSED}")),
    }
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
    Ok(EraseOpts {
        plan,
        customer: base.merged(&over),
        technician,
        tag: opt(args, "--tag")?.unwrap_or_default(),
        dry_run: has(args, "--dry-run"),
        force_ssd: has(args, "--force-overwrite-ssd"),
    })
}

fn describe_plan(o: &EraseOpts) {
    println!(
        "Méthode       : {} (NIST 800-88 : {})",
        report::method_label(&o.plan),
        MethodKind::Overwrite.level()
    );
    if o.plan.verify == VerifyMode::None {
        println!("ATTENTION     : sans vérification, le statut sera au mieux PARTIAL");
    }
    println!(
        "Passes        : {}",
        o.plan
            .passes
            .iter()
            .map(Fill::label)
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("Vérification  : {}", o.plan.verify.label());
    println!(
        "Client        : {}",
        if o.customer.name.is_empty() {
            "—"
        } else {
            &o.customer.name
        }
    );
    println!(
        "Technicien    : {}",
        if o.technician.name.is_empty() {
            "—"
        } else {
            &o.technician.name
        }
    );
    if !o.tag.is_empty() {
        println!("Tag           : {}", o.tag);
    }
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

/// Lance l'effacement, écrit le certificat et l'historique. Renvoie le code de sortie.
fn run_erase(
    dev: &mut dyn BlockDevice,
    disk: &DiskInfo,
    o: EraseOpts,
    cfg: &Config,
    paths: &Paths,
    target: Target,
) -> Result<i32, String> {
    // Arrêt demandé pendant la préparation : on n'a encore rien écrit, pas de certificat.
    if CANCEL.load(Ordering::SeqCst) {
        return Err("interrompu avant le début de l'effacement : rien n'a été écrit".into());
    }
    let mut notes = target.notes;
    println!("Taille effacée : {} octets", dev.size());
    let start = DateTime::now();
    let mut last = Instant::now() - Duration::from_secs(1);
    let outcome = erase_hdd::erase(dev, &o.plan, &CANCEL, &mut |p| {
        if last.elapsed() >= Duration::from_millis(200) || p.done == p.total {
            print_progress(p);
            last = Instant::now();
        }
    });
    let end = DateTime::now();
    println!();

    if let Some(r) = &outcome.abort_reason {
        notes.push(format!("Arrêt : {r}"));
    } else if outcome.aborted {
        notes.push("Effacement interrompu par l'opérateur (Ctrl+C)".to_string());
    }

    let rec = report::build_record(RecordInput {
        disk,
        plan: &o.plan,
        outcome: &outcome,
        kind: MethodKind::Overwrite,
        degraded: false,
        org: cfg.company.clone(),
        technician: o.technician,
        customer: o.customer,
        tag: o.tag,
        start,
        end,
        notes,
        smart: None,
        test_target: target.test_target,
        ssd_overwrite: target.ssd_overwrite,
    });

    let pdf_bytes = certificate::render(&rec, load_logo(paths));
    // Jamais d'écrasement d'un certificat existant : suffixe -2, -3… si le nom est pris.
    let mut pdf_path = paths.certificates.join(format!("{}.pdf", rec.id));
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
    report::append_history(&paths.history, &rec)?;
    // Journal texte (une ligne par effacement) ; non bloquant.
    let line = format!(
        "{} {} {} {} {}\n",
        rec.end,
        rec.id,
        rec.status.code(),
        rec.disk.serial,
        pdf_path.display()
    );
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.logs.join("effacements.log"));
    if let Err(e) = log.and_then(|mut f| f.write_all(line.as_bytes())) {
        eprintln!("ATTENTION : journal non écrit ({e})");
    }

    println!(
        "Statut        : {} ({}) — NIST 800-88 : {}",
        rec.status.code(),
        rec.status.fr(),
        rec.level
    );
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
    let ssd_overwrite = ssd_policy(disk.media, o.force_ssd)?;
    if ssd_overwrite {
        eprintln!(
            "ATTENTION : {} — écrasement forcé, statut au mieux PARTIAL",
            report::NOTE_SSD
        );
    }
    println!(
        "Disque {} : {} — n° de série {} — {}",
        disk.number,
        disk.display_model(),
        disk.serial,
        detect::human_size(disk.size_bytes)
    );
    // Autorisation + verrous des volumes : `prepared` vit jusqu'à la fin de la fonction,
    // donc pendant tout l'effacement ET la vérification.
    let prepared = safety::prepare_disk(disk, &ctx, &code, o.dry_run).map_err(|e| e.to_string())?;
    for l in &prepared.log {
        println!("{l}");
    }
    describe_plan(&o);
    if o.dry_run {
        println!("[dry-run] aucune écriture, aucun certificat.");
        return Ok(0);
    }

    // Revérifie protection + identité, ouvre le disque, puis le met hors ligne
    // (remis en ligne automatiquement quand `dev` est détruit).
    let mut dev = rawdisk::RawDisk::open(&prepared)?;
    let mut notes = vec![format!("Cible : disque {} ({})", disk.number, disk.path)];
    notes.extend(prepared.warnings.iter().cloned());
    notes.extend(dev.notes.iter().cloned());
    let target = Target {
        notes,
        test_target: false,
        ssd_overwrite,
    };
    let result = run_erase(&mut dev, disk, o, cfg, paths, target);
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
    describe_plan(&o);
    if o.dry_run {
        println!("[dry-run] aucune écriture, aucun certificat.");
        return Ok(0);
    }
    let target = Target {
        notes: vec![format!("Cible : fichier de test {}", path.display())],
        test_target: true,
        ssd_overwrite: false,
    };
    run_erase(&mut dev, &disk, o, cfg, paths, target)
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
            d.serial,
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
            r.disk.serial,
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

fn main() {
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
    fn ssd_overwrite_is_refused_unless_forced() {
        assert_eq!(ssd_policy(MediaType::Hdd, false), Ok(false));
        assert_eq!(ssd_policy(MediaType::Hdd, true), Ok(false));
        for m in [MediaType::Ssd, MediaType::Nvme, MediaType::Unknown] {
            let e = ssd_policy(m, false).unwrap_err();
            assert!(e.contains("ne garantit pas l'effacement d'un SSD"), "{e}");
            assert!(e.contains("étape 3"));
            assert_eq!(ssd_policy(m, true), Ok(true));
        }
        assert!(USAGE.contains("--force-overwrite-ssd"));
        let o = erase_opts(
            &a(&["--force-overwrite-ssd"]),
            &Config::default(),
            &test_paths(),
        )
        .unwrap();
        assert!(o.force_ssd);
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
