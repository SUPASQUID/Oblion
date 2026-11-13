//! Logique d'effacement PARTAGÉE par la ligne de commande et l'interface graphique.
//!
//! Les deux modes appellent exactement les mêmes fonctions : lecture des capacités (lecture
//! seule), décision, barrière `safety::check_allowed`, préparation (verrous des volumes),
//! ouverture du disque, effacement, certificat, historique et journal.
//!
//! Les messages ne sont jamais écrits directement : ils passent par un « puits » d'événements
//! (`Event`). La CLI les affiche à l'identique (stdout / stderr), l'interface les reçoit par
//! un canal depuis le thread d'effacement.
//!
//! L'accès au matériel passe par un `DiskBackend` : `RealBackend` (disques Windows) ou
//! `demo::DemoBackend` (disques simulés en mémoire, aucun accès matériel).

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::certificate;
use crate::clock::DateTime;
use crate::config::{Config, Customer, Paths, Technician};
use crate::detect::{self, Bus, DiskInfo, MediaType};
use crate::erase_hdd::{self, BlockDevice, Fill, Plan, Progress, VerifyMode};
use crate::erase_ssd::{self, Choice, Decision, FirmwareDisk, FwMethod, MethodOpt, Probe};
use crate::hpa::Hidden;
use crate::pdf;
use crate::report::{
    self, EraseRecord, FirmwareKind, FirmwareReport, MethodKind, RecordInput, Status,
};
use crate::safety::{self, ProtectContext};

// ---------- Événements ----------

/// Ce que le moteur veut montrer à l'opérateur.
#[derive(Debug, Clone)]
pub enum Event {
    /// Ligne d'information (stdout en CLI).
    Line(String),
    /// Avertissement ou erreur (stderr en CLI).
    Warn(String),
    /// Avancement d'un écrasement (phase, passe, %, débit, erreurs).
    Progress(Progress),
    /// État d'une commande firmware (ligne réécrite en CLI).
    Status(String),
    /// Fin d'une série de progressions (retour à la ligne en CLI).
    EndProgress,
}

/// Contexte d'exécution commun.
pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub paths: &'a Paths,
    /// Arrêt demandé (Ctrl+C en CLI, bouton Annuler dans l'interface).
    pub cancel: &'a AtomicBool,
    /// Qui a interrompu, pour la note du certificat : « Ctrl+C » ou « bouton Annuler ».
    pub interrupted_by: &'a str,
    pub sink: &'a mut dyn FnMut(Event),
    /// Mis à vrai dès que le disque est ouvert en écriture (pour qualifier une erreur
    /// ou une panique survenue ensuite).
    pub write_started: Option<&'a AtomicBool>,
}

impl Ctx<'_> {
    fn line(&mut self, s: impl Into<String>) {
        (self.sink)(Event::Line(s.into()));
    }
    fn warn(&mut self, s: impl Into<String>) {
        (self.sink)(Event::Warn(s.into()));
    }
}

// ---------- Options ----------

pub struct EraseOpts {
    pub plan: Plan,
    pub customer: Customer,
    pub technician: Technician,
    pub tag: String,
    pub dry_run: bool,
    pub force_ssd: bool,
    pub method: MethodOpt,
    pub allow_fallback: bool,
}

pub fn seed() -> u64 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    nanos ^ ((std::process::id() as u64) << 32)
}

pub fn parse_passes(list: &[String]) -> Result<Vec<Fill>, String> {
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

/// Plan d'écrasement par défaut : passes et vérification de config.toml.
pub fn plan_from_config(cfg: &Config) -> Result<Plan, String> {
    let mut plan = Plan::dod_default(seed());
    plan.passes = parse_passes(&cfg.erase.hdd_passes)?;
    plan.verify = VerifyMode::parse(&cfg.erase.verify)?;
    Ok(plan)
}

/// Méthode effective : --force-overwrite-ssd = --method overwrite pour un support non magnétique.
pub fn method_opt(
    method: MethodOpt,
    force_ssd: bool,
    media: MediaType,
) -> Result<MethodOpt, String> {
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

// ---------- Accès aux disques ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    /// Droits administrateur requis.
    NeedAdmin,
    Other(String),
}

impl std::fmt::Display for ListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ListError::NeedAdmin => f.write_str(
                "droits administrateur requis (clic droit → Exécuter en tant qu'administrateur, ou Lancer.bat)",
            ),
            ListError::Other(e) => f.write_str(e),
        }
    }
}

/// Autorisation d'effacer UN disque, volumes verrouillés tant qu'elle vit.
pub trait Authorization {
    fn log(&self) -> &[String];
    fn warnings(&self) -> &[String];
    /// Ouvre le disque en écriture. Renvoie le disque et les remarques pour le certificat.
    fn open(&self, firmware: bool) -> Result<(Box<dyn FirmwareDisk>, Vec<String>), String>;
}

/// Accès au matériel. Implémentations : `RealBackend` (Windows) et `demo::DemoBackend`.
pub trait DiskBackend: Send + Sync {
    /// Vrai pour le mode démonstration (aucun disque réel).
    fn is_demo(&self) -> bool;
    fn list_disks(&self) -> Result<Vec<DiskInfo>, ListError>;
    fn protect_context(&self) -> ProtectContext;
    /// Capacités, SMART, HPA/DCO : LECTURE SEULE.
    fn probe(&self, disk: &DiskInfo) -> Probe;
    /// Relit l'identité d'un disque juste avant l'effacement (LECTURE SEULE).
    fn reread(&self, number: u32) -> Result<DiskInfo, String>;
    /// Barrière de sécurité puis verrouillage des volumes (rien en `dry_run`).
    fn prepare(
        &self,
        disk: &DiskInfo,
        ctx: &ProtectContext,
        code: &str,
        dry_run: bool,
    ) -> Result<Box<dyn Authorization>, String>;
    /// Intervalle d'interrogation des commandes firmware.
    fn firmware_poll(&self) -> Duration;
}

/// Disques réels de Windows.
pub struct RealBackend;

struct RealAuthorization(safety::PreparedDisk);

impl Authorization for RealAuthorization {
    fn log(&self) -> &[String] {
        &self.0.log
    }
    fn warnings(&self) -> &[String] {
        &self.0.warnings
    }
    fn open(&self, firmware: bool) -> Result<(Box<dyn FirmwareDisk>, Vec<String>), String> {
        // Seule porte d'écriture : revérifie protection et identité juste avant l'ouverture.
        let dev = crate::rawdisk::RawDisk::open_for(&self.0, firmware)?;
        let notes = dev.notes.clone();
        Ok((Box::new(dev), notes))
    }
}

impl DiskBackend for RealBackend {
    fn is_demo(&self) -> bool {
        false
    }
    fn list_disks(&self) -> Result<Vec<DiskInfo>, ListError> {
        detect::list_disks().map_err(|e| match e {
            detect::DetectError::NeedAdmin => ListError::NeedAdmin,
            other => ListError::Other(other.to_string()),
        })
    }
    fn protect_context(&self) -> ProtectContext {
        ProtectContext::detect()
    }
    fn reread(&self, number: u32) -> Result<DiskInfo, String> {
        detect::reread_disk(number)
    }
    fn probe(&self, disk: &DiskInfo) -> Probe {
        let mut p = if disk.bus == Bus::Nvme {
            match crate::nvme::ReadOnlyNvme::open(disk.number) {
                Ok(mut port) => erase_ssd::probe_nvme(&mut port),
                Err(e) => Probe {
                    hidden: Hidden::NotApplicable("NVMe : pas de HPA/DCO".into()),
                    errors: vec![e],
                    ..Default::default()
                },
            }
        } else {
            match crate::ata::ReadOnlyAta::open(disk.number) {
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
    fn prepare(
        &self,
        disk: &DiskInfo,
        ctx: &ProtectContext,
        code: &str,
        dry_run: bool,
    ) -> Result<Box<dyn Authorization>, String> {
        let p = safety::prepare_disk(disk, ctx, code, dry_run).map_err(|e| e.to_string())?;
        Ok(Box::new(RealAuthorization(p)))
    }
    fn firmware_poll(&self) -> Duration {
        Duration::from_secs(5)
    }
}

// ---------- Préparation (lecture seule) ----------

/// Résultat de la préparation : méthode choisie et pourquoi. Aucune écriture.
#[derive(Debug, Clone)]
pub struct Analysis {
    pub media: MediaType,
    pub choice: Choice,
    pub method: MethodOpt,
    pub allow_fallback: bool,
    pub decision: Decision,
}

/// Décision PURE (même fonction pour la CLI, le dry-run et l'écran Configuration).
pub fn analyse(
    disk: &DiskInfo,
    probe: &Probe,
    method: MethodOpt,
    force_ssd: bool,
    allow_fallback: bool,
) -> Result<Analysis, String> {
    let media = erase_ssd::effective_media(disk.media, probe.caps.ata.as_ref());
    let mopt = method_opt(method, force_ssd, media)?;
    let choice = erase_ssd::choose(&probe.caps, media, probe.caps.frozen());
    let decision = erase_ssd::decide(mopt, allow_fallback, media, &choice);
    Ok(Analysis {
        media,
        choice,
        method: mopt,
        allow_fallback,
        decision,
    })
}

/// Niveau NIST visé par une décision (texte court).
pub fn decision_level(d: &Decision) -> &'static str {
    match d {
        Decision::Firmware(_) => "NIST 800-88 Purge",
        Decision::Overwrite { ssd: false, .. } => "NIST 800-88 Clear",
        Decision::Overwrite { ssd: true, .. } | Decision::Fallback => {
            "NIST 800-88 Clear · au mieux PARTIAL"
        }
        Decision::Refuse(_) | Decision::Frozen(_) => "—",
    }
}

/// Libellé d'une décision.
pub fn decision_label(d: &Decision, plan: &Plan, allow_fallback: bool) -> String {
    match d {
        Decision::Firmware(m) => {
            if allow_fallback {
                format!("{m} (repli autorisé)")
            } else {
                m.label().to_string()
            }
        }
        Decision::Overwrite { ssd: true, .. } => {
            format!("{} (écrasement forcé)", report::method_label(plan))
        }
        Decision::Overwrite { .. } => {
            let mut s = report::method_label(plan);
            if plan.verify != VerifyMode::None {
                s.push_str(" + vérification");
            }
            s
        }
        Decision::Fallback => "Repli Clear : TRIM + écrasement 1 passe + vérification".into(),
        Decision::Refuse(e) => format!("Aucune méthode possible : {e}"),
        Decision::Frozen(_) => "Disque gelé".into(),
    }
}

/// Raison lisible de la décision.
pub fn decision_reason(a: &Analysis, probe: &Probe) -> String {
    match &a.decision {
        Decision::Firmware(_) => {
            let ex = erase_ssd::explain(&probe.caps, a.media, &a.choice);
            format!(
                "{}. Purge seulement si la commande réussit ET que les {} marqueurs posés avant sont tous effacés.",
                ex.last().cloned().unwrap_or_default(),
                erase_ssd::MARKER_COUNT + 2
            )
        }
        Decision::Overwrite { ssd: true, .. } => format!("{} — statut au mieux PARTIAL.", report::NOTE_SSD),
        Decision::Overwrite { note: Some(n), .. } => format!("{n}."),
        Decision::Overwrite { .. } => "Écrase chaque secteur selon les passes configurées puis relit pour contrôler. Méthode adaptée aux disques magnétiques (NIST Clear).".into(),
        Decision::Fallback => "Aucune commande firmware utilisable : TRIM complet (si supporté) puis une passe aléatoire vérifiée. L'écrasement ne garantit pas l'effacement d'un SSD : statut au mieux PARTIAL.".into(),
        Decision::Refuse(e) => e.clone(),
        Decision::Frozen(g) => g.clone(),
    }
}

/// Débit supposé pour l'estimation d'un écrasement (hypothèse affichée comme telle).
pub const ESTIMATE_MB_S: u64 = 100;

/// Durée estimée : écrasement = taille / 100 MB/s × (passes + passes vérifiées) ;
/// firmware = durée annoncée par le disque, sinon None (« inconnue »).
pub fn estimate_secs(d: &Decision, size: u64, plan: &Plan, probe: &Probe) -> Option<u64> {
    let per_pass = size / (ESTIMATE_MB_S * 1_000_000);
    match d {
        Decision::Overwrite { .. } => {
            let verified = (0..plan.passes.len()).filter(|&i| plan.verifies(i)).count();
            Some(per_pass * (plan.passes.len() + verified) as u64)
        }
        Decision::Fallback => Some(per_pass * 2),
        Decision::Firmware(m) => match m {
            FwMethod::AtaSecurityEraseEnhanced => probe
                .caps
                .ata
                .as_ref()
                .and_then(|i| i.erase_enhanced.minutes())
                .map(|m| m as u64 * 60),
            FwMethod::AtaSecurityEraseNormal => probe
                .caps
                .ata
                .as_ref()
                .and_then(|i| i.erase_normal.minutes())
                .map(|m| m as u64 * 60),
            FwMethod::NvmeSanitizeCrypto => announced(probe.nvme_sanitize.map(|l| l.est_crypto)),
            FwMethod::NvmeSanitizeBlock => announced(probe.nvme_sanitize.map(|l| l.est_block)),
            _ => None,
        },
        Decision::Refuse(_) | Decision::Frozen(_) => None,
    }
}

fn announced(v: Option<u32>) -> Option<u64> {
    v.filter(|&s| s != u32::MAX && s != 0).map(|s| s as u64)
}

/// « ≈ 2 h 50 min », « ≈ 12 min », « < 1 min » ou « inconnue ».
pub fn duration_text(secs: Option<u64>) -> String {
    match secs {
        None => "inconnue".into(),
        Some(s) if s < 60 => "< 1 min".into(),
        Some(s) if s < 3600 => format!("≈ {} min", s.div_ceil(60)),
        Some(s) => {
            let m = s.div_ceil(60);
            format!("≈ {} h {:02} min", m / 60, m % 60)
        }
    }
}

// ---------- Effacement ----------

/// Cible de l'effacement, pour le certificat.
pub struct Target {
    pub notes: Vec<String>,
    pub test_target: bool,
    pub ssd_overwrite: bool,
    pub smart: Option<report::SmartInfo>,
    pub hidden: Hidden,
    pub real_size: Option<u64>,
    /// Mode démonstration : certificat « TEST / DÉMO — aucun disque réel ».
    pub demo: bool,
}

/// Résultat d'un effacement terminé (certificat écrit).
#[derive(Debug, Clone)]
pub struct Finished {
    pub record: EraseRecord,
    pub pdf: PathBuf,
    /// Code de sortie CLI : 0 si ERASED, 2 sinon.
    pub code: i32,
    /// Remarques connues APRÈS l'écriture du PDF (ex. remise en ligne impossible) :
    /// journal + écran Résultat.
    pub late_notes: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Done {
    DryRun,
    Finished(Box<Finished>),
}

impl Done {
    pub fn exit_code(&self) -> i32 {
        match self {
            Done::DryRun => 0,
            Done::Finished(f) => f.code,
        }
    }
}

pub fn describe_plan(c: &mut Ctx, plan: &Plan) {
    c.line(format!(
        "Méthode       : {} (NIST 800-88 : {})",
        report::method_label(plan),
        MethodKind::Overwrite.level()
    ));
    if plan.verify == VerifyMode::None {
        c.line("ATTENTION     : sans vérification, le statut sera au mieux PARTIAL");
    }
    c.line(format!(
        "Passes        : {}",
        plan.passes
            .iter()
            .map(Fill::label)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    c.line(format!("Vérification  : {}", plan.verify.label()));
}

pub fn describe_people(c: &mut Ctx, o: &EraseOpts) {
    let dash = |s: &str| {
        if s.is_empty() {
            "—".to_string()
        } else {
            s.to_string()
        }
    };
    c.line(format!("Client        : {}", dash(&o.customer.name)));
    c.line(format!("Technicien    : {}", dash(&o.technician.name)));
    if !o.tag.is_empty() {
        c.line(format!("Tag           : {}", o.tag));
    }
}

fn load_logo(c: &mut Ctx) -> Option<pdf::Image> {
    let path = c.paths.assets.join("logo.png");
    let bytes = std::fs::read(&path).ok()?;
    match pdf::Image::from_png(&bytes) {
        Ok(img) => Some(img),
        Err(e) => {
            c.warn(format!("ATTENTION : logo {} ignoré ({e})", path.display()));
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

fn build(input: RecordInput, target: &Target) -> EraseRecord {
    let mut rec = report::build_record(input);
    rec.demo = target.demo;
    if rec.demo {
        rec.id = demo_id(&rec.id);
    }
    rec
}

/// ID d'un certificat de démonstration : « OBL-… » devient « OBL-DEMO-… ».
pub fn demo_id(id: &str) -> String {
    match id.split_once('-') {
        Some((prefix, rest)) if !rest.starts_with("DEMO-") => format!("{prefix}-DEMO-{rest}"),
        _ => id.to_string(),
    }
}

/// Chemin du certificat d'un enregistrement (premier nom libre utilisé par `finish`).
pub fn certificate_path(paths: &Paths, id: &str) -> Option<PathBuf> {
    std::iter::once(paths.certificates.join(format!("{id}.pdf")))
        .chain((2..100).map(|k| paths.certificates.join(format!("{id}-{k}.pdf"))))
        .take_while(|p| p.exists())
        .last()
}

/// Erreur d'un effacement : AVANT toute écriture (disque intact) ou APRÈS le début de
/// l'écriture (disque modifié, certificat éventuellement non écrit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobError {
    /// Rien n'a été écrit sur le disque.
    NotStarted(String),
    /// Le disque a été (au moins partiellement) modifié, mais le certificat ou l'historique
    /// n'a pas pu être écrit (ou erreur interne après l'ouverture du disque).
    AfterWrite(String),
}

impl JobError {
    pub fn message(&self) -> &str {
        match self {
            JobError::NotStarted(e) | JobError::AfterWrite(e) => e,
        }
    }
}

impl std::fmt::Display for JobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobError::NotStarted(e) => f.write_str(e),
            JobError::AfterWrite(e) => write!(f, "{AFTER_WRITE_TITLE} : {e}"),
        }
    }
}

impl From<String> for JobError {
    fn from(e: String) -> Self {
        JobError::NotStarted(e)
    }
}

impl From<&str> for JobError {
    fn from(e: &str) -> Self {
        JobError::NotStarted(e.to_string())
    }
}

/// Titre commun (CLI et interface) d'une erreur survenue après le début de l'écriture.
pub const AFTER_WRITE_TITLE: &str = "Disque modifié — certificat non écrit";

/// Ajoute une ligne d'erreur au journal `effacements.log` (non bloquant).
pub fn log_line(paths: &Paths, text: &str) -> Result<(), String> {
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.logs.join("effacements.log"))
        .and_then(|mut f| {
            f.write_all(
                format!(
                    "{} {text}
",
                    DateTime::now().slash()
                )
                .as_bytes(),
            )
        })
        .map_err(|e| e.to_string())
}

/// Erreur APRÈS le début de l'écriture : journal + erreur distincte.
pub fn after_write_error(paths: &Paths, disk: &str, cause: &str) -> JobError {
    let _ = log_line(
        paths,
        &format!(
            "ERREUR {} ({disk}) : {cause}",
            AFTER_WRITE_TITLE.to_uppercase()
        ),
    );
    JobError::AfterWrite(cause.to_string())
}

/// Écrit le certificat, l'historique et le journal. Toute erreur ici survient APRÈS
/// l'effacement : elle est journalisée et signalée comme « disque modifié ».
pub fn finish(c: &mut Ctx, rec: &EraseRecord) -> Result<Finished, JobError> {
    write_outputs(c, rec).map_err(|e| {
        let disk = format!(
            "{} {}",
            rec.disk.model,
            detect::serial_or_none(&rec.disk.serial)
        );
        let err = after_write_error(c.paths, &disk, &e);
        c.warn(format!("ERREUR : {err}"));
        err
    })
}

/// Écrit le certificat (jamais d'écrasement d'un fichier existant), l'historique et le
/// journal, affiche le résumé.
fn write_outputs(c: &mut Ctx, rec: &EraseRecord) -> Result<Finished, String> {
    let logo = load_logo(c);
    let pdf_bytes = certificate::render(rec, logo);
    let mut pdf_path: PathBuf = c.paths.certificates.join(format!("{}.pdf", rec.id));
    let mut k = 2;
    let mut file = loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pdf_path)
        {
            Ok(f) => break f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && k < 100 => {
                pdf_path = c.paths.certificates.join(format!("{}-{k}.pdf", rec.id));
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
    report::append_history(&c.paths.history, rec)?;
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
        .open(c.paths.logs.join("effacements.log"));
    if let Err(e) = log.and_then(|mut f| f.write_all(line.as_bytes())) {
        c.warn(format!("ATTENTION : journal non écrit ({e})"));
    }

    for n in rec
        .notes
        .iter()
        .filter(|n| n.starts_with("DISQUE VERROUILLÉ"))
    {
        c.warn(format!("ATTENTION : {n}"));
    }
    c.line(format!(
        "Statut        : {} ({}) — NIST 800-88 : {}",
        rec.status.code(),
        rec.status.fr(),
        rec.level
    ));
    c.line(format!("Méthode       : {}", rec.method));
    c.line(format!(
        "Vérification  : {} ({})",
        rec.verify, rec.verify_result
    ));
    c.line(format!("HPA/DCO       : {}", rec.hpa_dco));
    c.line(format!(
        "Octets effacés: {} / {} ({:.2} %)",
        rec.bytes_erased, rec.disk.size_bytes, rec.percent
    ));
    let e = rec.errors();
    c.line(format!(
        "Erreurs       : passe {} · sync {} · vérif. {} · reprises {}",
        e.pass, e.sync, e.verify, e.retries
    ));
    c.line(format!("Certificat    : {}", pdf_path.display()));
    Ok(Finished {
        record: rec.clone(),
        pdf: pdf_path,
        code: if rec.status == Status::Erased { 0 } else { 2 },
        late_notes: Vec::new(),
    })
}

fn interrupted_note(c: &Ctx) -> String {
    format!(
        "Effacement interrompu par l'opérateur ({})",
        c.interrupted_by
    )
}

/// Écrasement (moteur HDD), certificat et historique.
pub fn run_erase(
    c: &mut Ctx,
    dev: &mut dyn BlockDevice,
    disk: &DiskInfo,
    o: &EraseOpts,
    target: Target,
) -> Result<Finished, JobError> {
    // Arrêt demandé pendant la préparation : on n'a encore rien écrit, pas de certificat.
    if c.cancel.load(Ordering::SeqCst) {
        return Err(JobError::NotStarted(
            "interrompu avant le début de l'effacement : rien n'a été écrit".into(),
        ));
    }
    let mut notes = target.notes.clone();
    c.line(format!("Taille effacée : {} octets", dev.size()));
    let start = DateTime::now();
    let outcome = {
        let sink = &mut *c.sink;
        erase_hdd::erase(dev, &o.plan, c.cancel, &mut |p: &Progress| {
            sink(Event::Progress(p.clone()))
        })
    };
    (c.sink)(Event::EndProgress);
    if let Some(r) = &outcome.abort_reason {
        notes.push(format!("Arrêt : {r}"));
    } else if outcome.aborted {
        notes.push(interrupted_note(c));
    }
    let rec = build(
        record_input(
            disk,
            &o.plan,
            &outcome,
            MethodKind::Overwrite,
            o,
            c.cfg,
            start,
            notes,
            &target,
        ),
        &target,
    );
    finish(c, &rec)
}

/// Repli Clear (TRIM + 1 passe aléatoire + vérification) puis certificat.
#[allow(clippy::too_many_arguments)]
fn run_fallback_erase(
    c: &mut Ctx,
    dev: &mut dyn FirmwareDisk,
    disk: &DiskInfo,
    mut report: FirmwareReport,
    trim: bool,
    o: &EraseOpts,
    target: &Target,
    mut notes: Vec<String>,
    start: DateTime,
) -> Result<Finished, JobError> {
    c.line(format!(
        "Repli Clear : {}écrasement 1 passe aléatoire + vérification complète",
        if trim { "TRIM complet + " } else { "" }
    ));
    let plan = erase_ssd::fallback_plan(o.plan.seed);
    let (fb, outcome) = {
        let sink = &mut *c.sink;
        erase_ssd::run_fallback(dev, trim, &plan, c.cancel, &mut |p: &Progress| {
            sink(Event::Progress(p.clone()))
        })
    };
    (c.sink)(Event::EndProgress);
    match &fb.trim {
        Some(Ok(())) => notes.push("TRIM complet : OK".into()),
        Some(Err(e)) => notes.push(format!("TRIM refusé : {e}")),
        None => notes.push("TRIM non supporté ou non signalé : non effectué".into()),
    }
    if let Some(r) = &outcome.abort_reason {
        notes.push(format!("Arrêt : {r}"));
    } else if outcome.aborted {
        notes.push(interrupted_note(c));
    }
    report.fallback = Some(fb);
    let mut input = record_input(
        disk,
        &plan,
        &outcome,
        MethodKind::Overwrite,
        o,
        c.cfg,
        start,
        notes,
        target,
    );
    input.ssd_overwrite = false;
    input.firmware = Some(report);
    let rec = build(input, target);
    finish(c, &rec)
}

/// Commande firmware avec vérification par marqueurs ; repli si demandé.
#[allow(clippy::too_many_arguments)]
fn run_firmware_erase(
    c: &mut Ctx,
    dev: &mut dyn FirmwareDisk,
    disk: &DiskInfo,
    m: FwMethod,
    probe: &Probe,
    media: MediaType,
    o: &EraseOpts,
    target: Target,
    poll: Duration,
) -> Result<Finished, JobError> {
    if c.cancel.load(Ordering::SeqCst) {
        return Err(JobError::NotStarted(
            "interrompu avant le début de l'effacement : rien n'a été écrit".into(),
        ));
    }
    let start = DateTime::now();
    let t0 = Instant::now();
    c.line(format!("Méthode firmware : {m}"));
    c.line(format!(
        "({} n'arrête pas une commande firmware déjà lancée : le disque la termine seul.)",
        c.interrupted_by
    ));
    let ctx = erase_ssd::FwContext {
        method: m,
        media,
        caps: &probe.caps,
        seed: o.plan.seed,
        markers: erase_ssd::MARKER_COUNT,
        poll,
        cancel: c.cancel,
    };
    let run = {
        let sink = &mut *c.sink;
        erase_ssd::run_firmware(dev, &ctx, &mut std::thread::sleep, &mut |s: &str| {
            sink(Event::Status(s.to_string()))
        })
    };
    (c.sink)(Event::EndProgress);
    for l in &run.log {
        c.line(format!("  {l}"));
    }
    for crit in &run.report.critical {
        c.warn(format!("ATTENTION : {crit}"));
    }
    let mut notes = target.notes.clone();
    notes.extend(run.notes.iter().cloned());
    let cancelled = c.cancel.load(Ordering::SeqCst);

    if run.failed() && run.attempted && run.maybe_busy {
        c.warn(format!("ATTENTION : {}", erase_ssd::NOTE_NO_FALLBACK_BUSY));
        notes.insert(0, erase_ssd::NOTE_NO_FALLBACK_BUSY.to_string());
    } else if run.failed() && !o.allow_fallback {
        notes.push("Repli non autorisé (option --allow-fallback absente)".into());
    }
    if run.fallback_allowed(o.allow_fallback) && !cancelled {
        return run_fallback_erase(
            c,
            dev,
            disk,
            run.report.clone(),
            probe.caps.trim(),
            o,
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
        c.cfg,
        start,
        notes,
        &target,
    );
    input.ssd_overwrite = false;
    input.firmware = Some(run.report.clone());
    let rec = build(input, &target);
    finish(c, &rec)
}

/// Effacement complet d'un disque : barrière, capacités (lecture seule), décision,
/// préparation, ouverture, effacement, certificat. MÊME code pour la CLI et l'interface.
///
/// - `on_probe` : affichage des capacités lues (CLI) ;
/// - `expected` : décision montrée à l'opérateur (interface) ; si la décision recalculée
///   diffère, rien n'est fait.
#[allow(clippy::too_many_arguments)]
pub fn erase_disk(
    c: &mut Ctx,
    backend: &dyn DiskBackend,
    disk: &DiskInfo,
    code: &str,
    o: &EraseOpts,
    on_probe: &mut dyn FnMut(&mut Ctx, &Probe, MediaType),
    expected: Option<&Decision>,
) -> Result<Done, JobError> {
    // Contexte de protection FRAIS et relecture de l'identité du disque juste avant tout :
    // le disque confirmé par l'opérateur (liste, écran Confirmation) doit être le même.
    let ctx = &backend.protect_context();
    let now = backend.reread(disk.number)?;
    safety::same_disk(disk, &now)?;
    for w in &ctx.warnings {
        c.warn(format!("ATTENTION : {w}"));
    }
    safety::check_allowed(disk, ctx, code).map_err(|e| e.to_string())?;
    c.line(format!(
        "Disque {} : {} — n° de série {} — {}",
        disk.number,
        disk.display_model(),
        detect::serial_or_none(&disk.serial),
        detect::human_size(disk.size_bytes)
    ));

    // Capacités, SMART et HPA/DCO : lus AVANT l'effacement, en lecture seule.
    let probe = backend.probe(disk);
    let media = erase_ssd::effective_media(disk.media, probe.caps.ata.as_ref());
    on_probe(c, &probe, media);
    let a = analyse(disk, &probe, o.method, o.force_ssd, o.allow_fallback)?;
    let decision = a.decision.clone();
    c.line("--- Décision ---");
    match &decision {
        Decision::Refuse(e) => return Err(e.clone().into()),
        Decision::Frozen(guide) => {
            c.warn(guide.clone());
            return Err("disque gelé : rien n'a été tenté".into());
        }
        Decision::Firmware(m) => c.line(format!(
            "Méthode       : {m} (NIST 800-88 : Purge si la commande réussit ET que tous les marqueurs sont effacés)\n\
             Vérification  : {} marqueurs (début, fin, positions aléatoires) écrits avant, relus après{}",
            erase_ssd::MARKER_COUNT + 2,
            if o.allow_fallback {
                "\nRepli         : autorisé (TRIM + 1 passe aléatoire + vérification, statut au mieux PARTIAL)"
            } else {
                "\nRepli         : non autorisé (échec = certificat FAILED)"
            }
        )),
        Decision::Fallback => c.line(format!(
            "Méthode       : Repli Clear — TRIM {}+ écrasement 1 passe aléatoire + vérification complète (statut au mieux PARTIAL)",
            if probe.caps.trim() { "" } else { "(non supporté) " }
        )),
        Decision::Overwrite { ssd, note } => {
            describe_plan(c, &o.plan);
            if *ssd {
                c.warn(format!(
                    "ATTENTION : {} — écrasement forcé, statut au mieux PARTIAL",
                    report::NOTE_SSD
                ));
            }
            if let Some(n) = note {
                c.warn(format!("ATTENTION : {n}"));
                c.warn(erase_ssd::FROZEN_GUIDE);
            }
            match probe.hidden.hidden_sectors() {
                Some(n) if n > 0 => c.warn(format!(
                    "ATTENTION : {} — l'écrasement ne les atteint pas, statut au mieux PARTIAL",
                    probe.hidden.label()
                )),
                None => c.warn(format!("ATTENTION : {}", report::NOTE_HIDDEN_UNKNOWN)),
                _ => {}
            }
        }
    }
    if let Some(exp) = expected {
        if *exp != decision {
            return Err(
                "la méthode recalculée diffère de celle affichée (état du disque modifié ?) : rien n'a été fait, revenez à l'écran Configuration"
                    .into(),
            );
        }
    }
    describe_people(c, o);

    // Autorisation + verrous des volumes : `auth` vit jusqu'à la fin de la fonction,
    // donc pendant tout l'effacement ET la vérification.
    let auth = backend.prepare(disk, ctx, code, o.dry_run)?;
    for l in auth.log() {
        c.line(l.clone());
    }
    if o.dry_run {
        c.line("[dry-run] aucune écriture, aucune commande firmware, aucun certificat.");
        return Ok(Done::DryRun);
    }

    // Revérifie protection + identité, ouvre le disque, puis le met hors ligne
    // (remis en ligne automatiquement quand `dev` est détruit).
    let firmware_follows = matches!(decision, Decision::Firmware(_) | Decision::Fallback);
    let (mut dev, dev_notes) = auth.open(firmware_follows)?;
    if let Some(flag) = c.write_started {
        flag.store(true, Ordering::SeqCst);
    }
    let demo = backend.is_demo();
    let mut notes = Vec::new();
    if demo {
        notes.push(report::NOTE_DEMO.to_string());
    }
    notes.push(format!("Cible : disque {} ({})", disk.number, disk.path));
    notes.extend(auth.warnings().iter().cloned());
    notes.extend(dev_notes);
    for e in &probe.errors {
        notes.push(format!("Lecture avant effacement : {e}"));
    }
    // Remise en ligne déjà échouée (sonde firmware à l'ouverture) : sur le certificat.
    for n in safety::take_online_failures() {
        c.warn(format!("ATTENTION : {n}"));
        notes.push(n);
    }
    let mut disk_rec = disk.clone();
    disk_rec.media = media;
    if demo {
        // Disque simulé : la taille effacée est celle de la mémoire de démonstration.
        disk_rec.size_bytes = dev.size();
    }
    let mut target = Target {
        notes,
        test_target: demo,
        ssd_overwrite: false,
        smart: probe.smart.clone(),
        hidden: probe.hidden.clone(),
        real_size: if demo {
            Some(dev.size())
        } else {
            probe.real_size
        },
        demo,
    };
    let poll = backend.firmware_poll();
    let result = match decision {
        Decision::Overwrite { ssd, note } => {
            target.ssd_overwrite = ssd;
            if let Some(n) = note {
                target.notes.insert(0, n);
            }
            let block: &mut dyn BlockDevice = &mut *dev;
            run_erase(c, block, &disk_rec, o, target)
        }
        Decision::Firmware(m) => {
            run_firmware_erase(c, &mut *dev, &disk_rec, m, &probe, media, o, target, poll)
        }
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
                c,
                &mut *dev,
                &disk_rec,
                report,
                probe.caps.trim(),
                o,
                &target,
                notes,
                DateTime::now(),
            )
        }
        Decision::Refuse(_) | Decision::Frozen(_) => unreachable!("traités avant la préparation"),
    };
    // Ordre explicite : poignée fermée et disque remis en ligne, PUIS volumes déverrouillés.
    drop(dev);
    drop(auth);
    // Remise en ligne impossible à la fermeture : trop tard pour le PDF → journal + écran.
    let late = safety::take_online_failures();
    for n in &late {
        c.warn(format!("ATTENTION : {n}"));
        let _ = log_line(c.paths, &format!("ATTENTION disque {} : {n}", disk.number));
    }
    result.map(|mut f| {
        f.late_notes.extend(late);
        Done::Finished(Box::new(f))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn force_overwrite_ssd_is_an_alias_of_method_overwrite_for_ssd() {
        for m in [MediaType::Ssd, MediaType::Nvme, MediaType::Unknown] {
            assert_eq!(
                method_opt(MethodOpt::Auto, true, m),
                Ok(MethodOpt::Overwrite)
            );
            assert_eq!(method_opt(MethodOpt::Auto, false, m), Ok(MethodOpt::Auto));
        }
        assert_eq!(
            method_opt(MethodOpt::Auto, true, MediaType::Hdd),
            Ok(MethodOpt::Auto)
        );
        assert!(method_opt(MethodOpt::Firmware, true, MediaType::Ssd).is_err());
    }

    #[test]
    fn passes_parsing() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            parse_passes(&a(&["0x00", " random "])).unwrap(),
            vec![Fill::Byte(0), Fill::Random]
        );
        assert!(parse_passes(&a(&[""])).is_err());
        assert!(parse_passes(&a(&["0xZZ"])).is_err());
    }

    #[test]
    fn estimate_overwrite_uses_100_mb_s_times_passes_and_verifications() {
        let plan = Plan::dod_default(1); // 3 passes + vérification de la dernière
        let size = 320_000_000_000u64;
        let p = Probe::default();
        let d = Decision::Overwrite {
            ssd: false,
            note: None,
        };
        // 320 Go / 100 MB/s = 3200 s par passe, × (3 + 1)
        assert_eq!(estimate_secs(&d, size, &plan, &p), Some(3200 * 4));
        assert_eq!(
            estimate_secs(&Decision::Fallback, size, &plan, &p),
            Some(6400)
        );
        assert_eq!(duration_text(Some(3200 * 4)), "≈ 3 h 34 min");
        assert_eq!(duration_text(Some(30)), "< 1 min");
        assert_eq!(duration_text(Some(600)), "≈ 10 min");
    }

    #[test]
    fn firmware_estimate_is_announced_or_unknown() {
        let plan = Plan::dod_default(1);
        let p = Probe::default();
        let d = Decision::Firmware(FwMethod::AtaSanitizeCrypto);
        assert_eq!(estimate_secs(&d, 1 << 40, &plan, &p), None);
        assert_eq!(duration_text(None), "inconnue");
        // Durée NVMe annoncée (journal 81h) ; FFFFFFFFh = non rapportée.
        let p = Probe {
            nvme_sanitize: Some(crate::nvme::SanitizeLog {
                sprog: 0xFFFF,
                state: crate::nvme::SanitizeState::Never,
                overwrite_passes: 0,
                global_data_erased: false,
                scdw10: 0,
                est_overwrite: u32::MAX,
                est_block: u32::MAX,
                est_crypto: 42,
            }),
            ..Default::default()
        };
        assert_eq!(
            estimate_secs(
                &Decision::Firmware(FwMethod::NvmeSanitizeCrypto),
                0,
                &plan,
                &p
            ),
            Some(42)
        );
        assert_eq!(
            estimate_secs(
                &Decision::Firmware(FwMethod::NvmeSanitizeBlock),
                0,
                &plan,
                &p
            ),
            None
        );
    }
}
