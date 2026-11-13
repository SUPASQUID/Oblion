//! Interface graphique (iced, rendu LOGICIEL tiny-skia : aucun GPU, ni OpenGL, ni Direct3D).
//!
//! Écrans (maquette `design-src/v2/Oblion.dc.html`) : 01 Disques, 02 Configuration,
//! 03 Confirmation, 04 Effacement, 05 Certificat, 06 Historique, 07 Paramètres, plus l'écran
//! « Relancez en administrateur ».
//!
//! L'effacement tourne dans un thread séparé et appelle le MÊME code que la CLI
//! (`job::erase_disk`) ; ses événements arrivent par un canal : l'interface ne gèle jamais.

mod fonts;
mod logo;
mod state;
mod style;
mod view;
mod win;

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use iced::futures::channel::mpsc;
use iced::{window, Subscription, Task};

use crate::app::{APP_NAME, VERSION};
use crate::clock::DateTime;
use crate::config::{self, Company, Config, Customer, Paths, Technician};
use crate::detect::DiskInfo;
use crate::erase_hdd::{Plan, Progress, VerifyMode};
use crate::erase_ssd::{Decision, Probe};
use crate::job::{self, DiskBackend, Done, EraseOpts, Event, ListError};
use crate::report::{self, EraseRecord};
use crate::safety::ProtectContext;

use state::{HistoryFilter, MethodOption};
use style::Pal;

/// Écrans.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Disks,
    Config,
    Confirm,
    Erase,
    Result,
    History,
    Settings,
    NeedAdmin,
}

impl Screen {
    /// Étape 1 à 5 du parcours d'effacement.
    pub fn step(self) -> Option<u8> {
        match self {
            Screen::Disks => Some(1),
            Screen::Config => Some(2),
            Screen::Confirm => Some(3),
            Screen::Erase => Some(4),
            Screen::Result => Some(5),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Address,
    Contact,
    Phone,
}

#[derive(Debug, Clone)]
pub enum Message {
    Nav(Screen),
    Refresh,
    Listed(Result<(Vec<DiskInfo>, ProtectContext), ListError>),
    Probed(ProbeKey, Arc<Probe>),
    SelectDisk(u32),
    ToConfig,
    PickMethod(usize),
    PickClient(ClientItem),
    Customer(Field, String),
    Technician(String),
    Tag(String),
    ToConfirm,
    Code(String),
    LabelChecked(bool),
    StartErase,
    Job(JobMsg),
    Tick,
    AskCancel,
    ConfirmCancel(bool),
    CloseRequested(window::Id),
    ConfirmQuit(bool),
    OpenPdf(PathBuf),
    OpenFolder(PathBuf, Option<PathBuf>),
    NewErase,
    HistoryFilter(HistoryFilter),
    HistorySearch(String),
    ExportCsv,
    SettingsCompany(Field, String),
    SettingsTechnician(String),
    SetDark(bool),
    SaveSettings,
    RelaunchAdmin,
}

/// Entrée de la liste déroulante des clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientItem {
    pub id: Option<String>,
    pub label: String,
}

impl std::fmt::Display for ClientItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

/// Messages du thread d'effacement.
#[derive(Debug, Clone)]
pub enum JobMsg {
    Event(Event),
    Done(Result<Done, job::JobError>),
}

/// Ligne de la liste des disques.
pub struct DiskRow {
    pub info: DiskInfo,
    pub protection: Option<String>,
    pub probe: Option<Arc<Probe>>,
}

/// Formulaire de l'écran Configuration.
pub struct ConfigForm {
    pub disk: DiskInfo,
    pub probe: Arc<Probe>,
    pub plan: Plan,
    pub options: Vec<MethodOption>,
    pub selected: Option<usize>,
    pub client: Option<ClientItem>,
    pub customer: Customer,
    pub technician: String,
    pub tag: String,
}

impl ConfigForm {
    pub fn option(&self) -> Option<&MethodOption> {
        self.selected.and_then(|i| self.options.get(i))
    }
}

/// Effacement en cours.
pub struct Running {
    pub disk: DiskInfo,
    pub method: String,
    pub decision: Decision,
    pub verify: VerifyMode,
    pub pass_labels: Vec<String>,
    pub started: Instant,
    pub started_at: DateTime,
    /// Début de la phase d'écrasement (premier événement de progression).
    pub overwrite_started: Option<Instant>,
    pub progress: Option<Progress>,
    pub status: Option<String>,
    pub notes: Vec<String>,
    /// (secondes écoulées, MB/s) pour le graphique.
    pub speeds: Vec<(f32, f32)>,
    pub cancel: Arc<AtomicBool>,
    pub cancel_asked: bool,
    pub cancel_requested: bool,
    pub now: Instant,
}

pub enum Outcome {
    Finished(Box<job::Finished>),
    /// Rien n'a été écrit sur le disque.
    NotStarted(String),
    /// Erreur APRÈS le début de l'écriture : disque modifié, certificat non écrit.
    AfterWrite(String),
}

/// Effacement en cours, connu du gestionnaire de panique du fil principal.
struct ActiveJob {
    cancel: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
}

static ACTIVE_JOB: std::sync::Mutex<Option<ActiveJob>> = std::sync::Mutex::new(None);

/// Panique du fil principal pendant un effacement : arrêt propre demandé, puis attente
/// (bornée) de la fin du thread pour que le certificat ABORTED soit écrit.
fn stop_active_job(max: Duration) -> bool {
    let job = ACTIVE_JOB
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|j| (j.cancel.clone(), j.done.clone())));
    let Some((cancel, done)) = job else {
        return true;
    };
    cancel.store(true, Ordering::SeqCst);
    let start = Instant::now();
    while !done.load(Ordering::SeqCst) {
        if start.elapsed() >= max {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

pub use win::offer_console as offer_cli;

pub struct SettingsForm {
    pub company: Company,
    pub technician: String,
    pub message: Option<(bool, String)>,
}

/// Clé du cache des sondes.
pub type ProbeKey = (u32, String, String, u64);

pub fn probe_key(d: &DiskInfo) -> ProbeKey {
    (d.number, d.serial.clone(), d.display_model(), d.size_bytes)
}

pub struct App {
    pub backend: Arc<dyn DiskBackend>,
    pub demo: bool,
    pub paths: Paths,
    pub cfg: Config,
    pub cfg_error: Option<String>,
    pub fonts: view::Fonts,
    pub font_source: String,
    pub dark: bool,
    pub screen: Screen,
    pub loading: bool,
    pub list_error: Option<String>,
    pub ctx: Option<ProtectContext>,
    pub disks: Vec<DiskRow>,
    pub selected: Option<u32>,
    /// Sondes par (numéro, n° de série, modèle, taille) ; vidé à chaque actualisation.
    pub probes: HashMap<ProbeKey, Arc<Probe>>,
    /// Erreur d'une action (ouvrir un PDF, un dossier…).
    pub notice: Option<String>,
    pub book: BTreeMap<String, Customer>,
    pub book_error: Option<String>,
    pub form: Option<ConfigForm>,
    pub code: String,
    pub label_checked: bool,
    pub running: Option<Running>,
    pub outcome: Option<Outcome>,
    pub history: Vec<EraseRecord>,
    pub history_error: Option<String>,
    pub history_filter: HistoryFilter,
    pub history_search: String,
    pub export_msg: Option<(bool, String)>,
    pub settings: SettingsForm,
    pub quit_asked: bool,
    pub quit_after_job: bool,
    pub exe_dir: String,
    pub winpe: bool,
    /// Écran à atteindre automatiquement (démo uniquement, captures d'écran).
    pub auto_screen: Option<u8>,
}

impl App {
    pub fn pal(&self) -> Pal {
        Pal::get(self.dark)
    }

    /// Chemin affiché. En démonstration, les préfixes personnels sont masqués
    /// (%TEMP%, %USERPROFILE%, dossier de l'exécutable) pour les captures d'écran.
    pub fn shown(&self, p: &std::path::Path) -> String {
        let s = p.display().to_string();
        if !self.demo {
            return s;
        }
        let exe = std::path::Path::new(&self.exe_dir);
        let exe_name = exe
            .file_name()
            .map(|n| format!("…\\{}", n.to_string_lossy()))
            .unwrap_or_default();
        let prefixes = [
            (
                std::env::temp_dir().display().to_string(),
                "%TEMP%".to_string(),
            ),
            (self.exe_dir.clone(), exe_name),
            (
                std::env::var("USERPROFILE").unwrap_or_default(),
                "%USERPROFILE%".to_string(),
            ),
        ];
        for (prefix, repl) in prefixes {
            let prefix = prefix.trim_end_matches('\\');
            if !prefix.is_empty()
                && s.len() >= prefix.len()
                && s.is_char_boundary(prefix.len())
                && s[..prefix.len()].eq_ignore_ascii_case(prefix)
            {
                return format!("{repl}{}", &s[prefix.len()..]);
            }
        }
        s
    }

    pub fn job_running(&self) -> bool {
        self.running.is_some()
    }

    fn load_history(&mut self) {
        match report::load_history(&self.paths.history) {
            Ok(mut h) => {
                h.reverse();
                self.history = h;
                self.history_error = None;
            }
            Err(e) => self.history_error = Some(e),
        }
    }

    fn refresh(&mut self) -> Task<Message> {
        self.loading = true;
        // Nouvelle lecture : sondes et sélection repartent de zéro.
        self.probes.clear();
        self.selected = None;
        self.list_error = None;
        let b = self.backend.clone();
        Task::perform(
            async move { b.list_disks().map(|d| (d, b.protect_context())) },
            Message::Listed,
        )
    }

    fn probe_for(&self, d: &DiskInfo) -> Option<Arc<Probe>> {
        self.probes.get(&probe_key(d)).cloned()
    }

    fn open_config(&mut self) {
        let Some(row) = self
            .selected
            .and_then(|n| self.disks.iter().find(|r| r.info.number == n))
        else {
            return;
        };
        let Some(probe) = row.probe.clone() else {
            return;
        };
        let plan = match job::plan_from_config(&self.cfg) {
            Ok(p) => p,
            Err(e) => {
                self.list_error = Some(format!("config.toml : {e}"));
                return;
            }
        };
        let options = state::method_options(&row.info, &probe, &plan);
        let selected = (!options.is_empty()).then_some(0);
        self.form = Some(ConfigForm {
            disk: row.info.clone(),
            probe,
            plan,
            options,
            selected,
            client: None,
            customer: Customer::default(),
            technician: self.cfg.technician.name.clone(),
            tag: String::new(),
        });
        self.code.clear();
        self.label_checked = false;
        self.screen = Screen::Config;
    }

    fn start_erase(&mut self) -> Task<Message> {
        let Some(form) = &self.form else {
            return Task::none();
        };
        let Some(opt) = form.option() else {
            return Task::none();
        };
        if !opt.runnable() || !state::can_erase(&form.disk, &self.code, self.label_checked) {
            return Task::none();
        }
        if self.cfg_error.is_some() || !self.ctx.as_ref().is_some_and(|c| c.reliable) {
            return Task::none();
        }
        let a = &opt.analysis;
        let mut plan = form.plan.clone();
        plan.seed = job::seed();
        let o = EraseOpts {
            plan: plan.clone(),
            customer: form.customer.clone(),
            technician: Technician {
                name: form.technician.trim().to_string(),
            },
            tag: form.tag.trim().to_string(),
            dry_run: false,
            force_ssd: false,
            method: a.method,
            allow_fallback: a.allow_fallback,
        };
        let firmware_like = matches!(a.decision, Decision::Firmware(_) | Decision::Fallback);
        let verify = if firmware_like {
            VerifyMode::Last
        } else {
            plan.verify
        };
        let pass_labels = if firmware_like {
            vec!["Aléatoire".to_string()]
        } else {
            plan.passes
                .iter()
                .map(|f| f.final_label().to_string())
                .collect()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let done_flag = Arc::new(AtomicBool::new(false));
        if let Ok(mut g) = ACTIVE_JOB.lock() {
            *g = Some(ActiveJob {
                cancel: cancel.clone(),
                done: done_flag.clone(),
            });
        }
        let now = Instant::now();
        self.running = Some(Running {
            disk: form.disk.clone(),
            method: opt.label.clone(),
            decision: a.decision.clone(),
            verify,
            pass_labels,
            started: now,
            started_at: DateTime::now(),
            overwrite_started: None,
            progress: None,
            status: None,
            notes: Vec::new(),
            speeds: Vec::new(),
            cancel: cancel.clone(),
            cancel_asked: false,
            cancel_requested: false,
            now,
        });
        self.outcome = None;
        self.screen = Screen::Erase;

        let (tx, rx) = mpsc::unbounded::<JobMsg>();
        let backend = self.backend.clone();
        let cfg = self.cfg.clone();
        let paths = self.paths.clone();
        let disk = form.disk.clone();
        let code = self.code.trim().to_string();
        let expected = a.decision.clone();
        let spawned = std::thread::Builder::new()
            .name("effacement".into())
            .spawn(move || {
                let started = AtomicBool::new(false);
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut last = Instant::now() - Duration::from_secs(1);
                    let mut last_key = None;
                    let txe = tx.clone();
                    let mut sink = move |e: Event| {
                        if let Event::Progress(p) = &e {
                            // Au plus ~4 rafraîchissements par seconde (sauf changement de passe).
                            let key = (p.phase, p.pass_index);
                            if last.elapsed() < Duration::from_millis(250)
                                && Some(key) == last_key
                                && p.done < p.total
                            {
                                return;
                            }
                            last = Instant::now();
                            last_key = Some(key);
                        }
                        let _ = txe.unbounded_send(JobMsg::Event(e));
                    };
                    let mut c = job::Ctx {
                        cfg: &cfg,
                        paths: &paths,
                        cancel: &cancel,
                        interrupted_by: "bouton Annuler",
                        sink: &mut sink,
                        write_started: Some(&started),
                    };
                    job::erase_disk(
                        &mut c,
                        backend.as_ref(),
                        &disk,
                        &code,
                        &o,
                        &mut |_, _, _| {},
                        Some(&expected),
                    )
                }));
                let msg = match result {
                    Ok(r) => r,
                    Err(p) => {
                        let cause = format!(
                            "erreur interne pendant l'effacement : {}",
                            p.downcast_ref::<String>()
                                .cloned()
                                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                                .unwrap_or_default()
                        );
                        if started.load(Ordering::SeqCst) {
                            // Panique APRÈS l'ouverture du disque : disque modifié.
                            Err(job::after_write_error(
                                &paths,
                                &format!("disque {} {}", disk.number, disk.serial),
                                &cause,
                            ))
                        } else {
                            Err(job::JobError::NotStarted(cause))
                        }
                    }
                };
                done_flag.store(true, Ordering::SeqCst);
                let _ = tx.unbounded_send(JobMsg::Done(msg));
            });
        if let Err(e) = spawned {
            self.running = None;
            self.outcome = Some(Outcome::NotStarted(format!(
                "thread d'effacement impossible : {e}"
            )));
            self.screen = Screen::Result;
            return Task::none();
        }
        Task::run(rx, Message::Job)
    }

    fn on_job(&mut self, m: JobMsg) -> Task<Message> {
        match m {
            JobMsg::Event(e) => {
                if let Some(r) = self.running.as_mut() {
                    r.now = Instant::now();
                    match e {
                        Event::Progress(p) => {
                            let t0 = *r.overwrite_started.get_or_insert(r.now);
                            let t = r.now.duration_since(r.started).as_secs_f32();
                            if p.speed_mb_s.is_finite() && p.speed_mb_s > 0.0 && r.now > t0 {
                                r.speeds.push((t, p.speed_mb_s as f32));
                                if r.speeds.len() > 600 {
                                    r.speeds.remove(0);
                                }
                            }
                            r.status = None;
                            r.progress = Some(p);
                        }
                        Event::Status(s) => r.status = Some(s),
                        Event::Warn(s) => r.notes.push(s),
                        Event::Line(s) => {
                            if s.starts_with("ATTENTION") || s.starts_with("Repli") {
                                r.notes.push(s);
                            }
                        }
                        Event::EndProgress => {}
                    }
                }
                Task::none()
            }
            JobMsg::Done(result) => {
                self.running = None;
                if let Ok(mut g) = ACTIVE_JOB.lock() {
                    *g = None;
                }
                self.outcome = Some(match result {
                    Ok(Done::Finished(f)) => Outcome::Finished(f),
                    Ok(Done::DryRun) => Outcome::NotStarted("dry-run : rien n'a été écrit".into()),
                    Err(job::JobError::NotStarted(e)) => Outcome::NotStarted(e),
                    Err(job::JobError::AfterWrite(e)) => Outcome::AfterWrite(e),
                });
                self.screen = Screen::Result;
                self.load_history();
                if self.quit_after_job {
                    return iced::exit();
                }
                Task::none()
            }
        }
    }

    /// Démo uniquement : avance automatiquement jusqu'à l'écran demandé (captures).
    fn auto_advance(&mut self) -> Task<Message> {
        let Some(target) = self.auto_screen else {
            return Task::none();
        };
        if !self.backend.is_demo() {
            self.auto_screen = None;
            return Task::none();
        }
        match target {
            6 => {
                self.auto_screen = None;
                self.load_history();
                self.screen = Screen::History;
            }
            7 => {
                self.auto_screen = None;
                self.screen = Screen::Settings;
            }
            _ => {
                let ready = self
                    .disks
                    .iter()
                    .find(|r| r.info.number == 2)
                    .is_some_and(|r| r.probe.is_some());
                if !ready {
                    return Task::none();
                }
                self.auto_screen = None;
                self.selected = Some(2);
                if target >= 2 {
                    self.open_config();
                    if let Some(f) = self.form.as_mut() {
                        if let Some((id, c)) = self.book.iter().next() {
                            f.client = Some(ClientItem {
                                id: Some(id.clone()),
                                label: format!("{} — {}", c.name, id),
                            });
                            f.customer = c.clone();
                        }
                        f.tag = "INV-DEMO-0412".into();
                    }
                }
                if target >= 3 {
                    self.screen = Screen::Confirm;
                    if let Some(f) = &self.form {
                        self.code = crate::safety::confirmation_code(&f.disk);
                        self.label_checked = true;
                    }
                }
                if target >= 4 {
                    return self.start_erase();
                }
            }
        }
        Task::none()
    }

    pub fn client_items(&self) -> Vec<ClientItem> {
        std::iter::once(ClientItem {
            id: None,
            label: "— Saisie libre —".into(),
        })
        .chain(self.book.iter().map(|(id, c)| ClientItem {
            id: Some(id.clone()),
            label: if c.name.is_empty() {
                id.clone()
            } else {
                format!("{} — {id}", c.name)
            },
        }))
        .collect()
    }
}

fn update(app: &mut App, msg: Message) -> Task<Message> {
    match msg {
        Message::Nav(s) => {
            if app.job_running() {
                return Task::none();
            }
            if s == Screen::History {
                app.load_history();
                app.export_msg = None;
            }
            if s == Screen::Disks && app.screen == Screen::Result {
                app.form = None;
            }
            if s == Screen::Disks && matches!(app.screen, Screen::Config | Screen::Confirm) {
                // Retour depuis le parcours : on garde la sélection.
            }
            if s == Screen::Settings {
                app.settings.message = None;
            }
            app.screen = s;
            Task::none()
        }
        Message::Refresh => {
            if app.job_running() {
                return Task::none();
            }
            app.refresh()
        }
        Message::Listed(r) => {
            app.loading = false;
            match r {
                Err(ListError::NeedAdmin) => {
                    app.screen = Screen::NeedAdmin;
                    Task::none()
                }
                Err(ListError::Other(e)) => {
                    app.list_error = Some(e);
                    Task::none()
                }
                Ok((disks, ctx)) => {
                    let mut tasks = Vec::new();
                    app.disks = disks
                        .into_iter()
                        .map(|info| {
                            let protection = ctx.reason(&info).map(|p| p.to_string());
                            let probe = app.probe_for(&info);
                            // Lecture SMART/capacités en arrière-plan (lecture seule), JAMAIS
                            // sur un disque protégé (système, clé de démarrage).
                            if probe.is_none() && protection.is_none() {
                                let b = app.backend.clone();
                                let d = info.clone();
                                tasks.push(Task::perform(
                                    async move {
                                        let p = b.probe(&d);
                                        (probe_key(&d), Arc::new(p))
                                    },
                                    |(k, p)| Message::Probed(k, p),
                                ));
                            }
                            DiskRow {
                                info,
                                protection,
                                probe,
                            }
                        })
                        .collect();
                    // La sélection ne survit pas à une actualisation.
                    app.selected = None;
                    app.ctx = Some(ctx);
                    if app.screen == Screen::NeedAdmin {
                        app.screen = Screen::Disks;
                    }
                    tasks.push(app.auto_advance());
                    Task::batch(tasks)
                }
            }
        }
        Message::Probed(key, p) => {
            if let Some(r) = app.disks.iter_mut().find(|r| probe_key(&r.info) == key) {
                app.probes.insert(key, p.clone());
                r.probe = Some(p);
            }
            app.auto_advance()
        }
        Message::SelectDisk(n) => {
            if state::selectable(
                app.ctx.as_ref(),
                app.disks
                    .iter()
                    .find(|r| r.info.number == n)
                    .map(|r| r.protection.is_some()),
            ) {
                app.selected = Some(n);
            }
            Task::none()
        }
        Message::ToConfig => {
            if app.cfg_error.is_some() {
                return Task::none();
            }
            app.open_config();
            Task::none()
        }
        Message::PickMethod(i) => {
            if let Some(f) = app.form.as_mut() {
                if i < f.options.len() {
                    f.selected = Some(i);
                }
            }
            Task::none()
        }
        Message::PickClient(item) => {
            if let Some(f) = app.form.as_mut() {
                f.customer = state::customer_from_book(&app.book, item.id.as_deref());
                f.client = Some(item);
            }
            Task::none()
        }
        Message::Customer(field, v) => {
            if let Some(f) = app.form.as_mut() {
                let c = &mut f.customer;
                match field {
                    Field::Name => c.name = v,
                    Field::Address => c.address = v,
                    Field::Contact => c.contact_name = v,
                    Field::Phone => c.phone = v,
                }
            }
            Task::none()
        }
        Message::Technician(v) => {
            if let Some(f) = app.form.as_mut() {
                f.technician = v;
            }
            Task::none()
        }
        Message::Tag(v) => {
            if let Some(f) = app.form.as_mut() {
                f.tag = v;
            }
            Task::none()
        }
        Message::ToConfirm => {
            if let Some(f) = &app.form {
                if state::can_continue_config(&f.options, f.selected) {
                    app.code.clear();
                    app.label_checked = false;
                    app.screen = Screen::Confirm;
                }
            }
            Task::none()
        }
        Message::Code(v) => {
            app.code = v.chars().take(40).collect();
            Task::none()
        }
        Message::LabelChecked(b) => {
            app.label_checked = b;
            Task::none()
        }
        Message::StartErase => {
            if app.job_running() {
                return Task::none();
            }
            app.start_erase()
        }
        Message::Job(m) => app.on_job(m),
        Message::Tick => {
            if let Some(r) = app.running.as_mut() {
                r.now = Instant::now();
            }
            Task::none()
        }
        Message::AskCancel => {
            if let Some(r) = app.running.as_mut() {
                r.cancel_asked = true;
            }
            Task::none()
        }
        Message::ConfirmCancel(yes) => {
            if let Some(r) = app.running.as_mut() {
                r.cancel_asked = false;
                if yes {
                    // Arrêt propre : le moteur s'arrête et produit un certificat ABORTED.
                    r.cancel.store(true, Ordering::SeqCst);
                    r.cancel_requested = true;
                }
            }
            Task::none()
        }
        Message::CloseRequested(id) => match state::on_close(app.job_running()) {
            state::CloseAction::Quit => window::close(id),
            state::CloseAction::Ask => {
                app.quit_asked = true;
                Task::none()
            }
        },
        Message::ConfirmQuit(yes) => {
            app.quit_asked = false;
            if yes {
                if let Some(r) = app.running.as_mut() {
                    r.cancel.store(true, Ordering::SeqCst);
                    r.cancel_requested = true;
                    // La fenêtre se ferme quand le certificat ABORTED est écrit.
                    app.quit_after_job = true;
                } else {
                    return iced::exit();
                }
            }
            Task::none()
        }
        Message::OpenPdf(p) => {
            app.notice = win::open_file(&p).err();
            Task::none()
        }
        Message::OpenFolder(dir, sel) => {
            app.notice = win::open_folder(&dir, sel.as_deref()).err();
            Task::none()
        }
        Message::NewErase => {
            app.probes.clear();
            app.notice = None;
            app.form = None;
            app.outcome = None;
            app.selected = None;
            app.code.clear();
            app.label_checked = false;
            app.screen = Screen::Disks;
            app.refresh()
        }
        Message::HistoryFilter(f) => {
            app.history_filter = f;
            Task::none()
        }
        Message::HistorySearch(s) => {
            app.history_search = s;
            Task::none()
        }
        Message::ExportCsv => {
            app.export_msg = Some(export_csv(app));
            Task::none()
        }
        Message::SettingsCompany(field, v) => {
            let c = &mut app.settings.company;
            match field {
                Field::Name => c.name = v,
                Field::Address => c.address = v,
                Field::Contact => c.contact_name = v,
                Field::Phone => c.phone = v,
            }
            Task::none()
        }
        Message::SettingsTechnician(v) => {
            app.settings.technician = v;
            Task::none()
        }
        Message::SetDark(d) => {
            app.dark = d;
            Task::none()
        }
        Message::SaveSettings => {
            let tech = Technician {
                name: app.settings.technician.trim().to_string(),
            };
            let theme = if app.dark { "dark" } else { "light" };
            app.settings.message = Some(
                match config::save_settings(
                    &app.paths.config_file(),
                    &app.settings.company,
                    &tech,
                    theme,
                ) {
                    Ok(()) => {
                        app.cfg.company = app.settings.company.clone();
                        app.cfg.technician = tech;
                        app.cfg.ui.theme = theme.into();
                        (
                            true,
                            format!("Enregistré dans {}", app.shown(&app.paths.config_file())),
                        )
                    }
                    Err(e) => (false, e),
                },
            );
            Task::none()
        }
        Message::RelaunchAdmin => {
            match win::relaunch_as_admin("") {
                Ok(()) => return iced::exit(),
                Err(e) => app.list_error = Some(e),
            }
            Task::none()
        }
    }
}

/// Export CSV dans le dossier data (repli : dossier de l'historique si data est en lecture seule).
fn export_csv(app: &App) -> (bool, String) {
    let all = match report::load_history(&app.paths.history) {
        Ok(a) => a,
        Err(e) => return (false, e),
    };
    let name = format!("historique-{}.csv", DateTime::now().compact());
    let csv = report::export_csv(&all);
    let mut last_err = String::new();
    for dir in [app.paths.data.clone(), app.paths.history.clone()] {
        let p = dir.join(&name);
        match std::fs::write(&p, csv.as_bytes()) {
            Ok(()) => {
                return (
                    true,
                    format!(
                        "{} effacement(s) exporté(s) vers {}",
                        all.len(),
                        app.shown(&p)
                    ),
                )
            }
            Err(e) => last_err = format!("écriture de {} impossible : {e}", app.shown(&p)),
        }
    }
    (false, last_err)
}

fn subscription(app: &App) -> Subscription<Message> {
    let close = window::close_requests().map(Message::CloseRequested);
    if app.job_running() {
        Subscription::batch([close, Subscription::run(ticker)])
    } else {
        close
    }
}

/// Horloge (2 fois par seconde) pendant un effacement : temps écoulé à jour.
fn ticker() -> impl iced::futures::Stream<Item = Message> {
    let (tx, rx) = mpsc::unbounded();
    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(500));
        if tx.unbounded_send(Message::Tick).is_err() {
            break;
        }
    });
    rx
}

fn title(app: &App) -> String {
    let base = format!("{APP_NAME} — Certification d'effacement · portable");
    let demo = if app.demo {
        " — DÉMO (aucun disque réel)"
    } else {
        ""
    };
    match &app.running {
        Some(r) => format!(
            "{APP_NAME} — Effacement en cours — {:.0} %{demo}",
            r.progress
                .as_ref()
                .map(|p| state::global_fraction(p, r.verify) * 100.0)
                .unwrap_or(0.0)
        ),
        None => format!("{base}{demo}"),
    }
}

/// Journal d'erreur de l'interface (data/logs/interface.log).
fn log_gui_error(paths: &Paths, e: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(paths.logs.join("interface.log"))
    {
        let _ = writeln!(f, "{} {APP_NAME} {VERSION} : {e}", DateTime::now().french());
    }
}

/// Lance l'interface. Renvoie le code de sortie du processus.
pub fn run(demo: bool, auto_screen: Option<u8>) -> i32 {
    let (backend, paths): (Arc<dyn DiskBackend>, Paths) = if demo {
        let p = crate::demo::demo_paths();
        if let Err(e) = crate::demo::seed(&p) {
            win::warn_box(&e, APP_NAME);
        }
        (Arc::new(crate::demo::DemoBackend), p)
    } else {
        (Arc::new(job::RealBackend), Paths::from_exe())
    };

    // Panique du fil principal (rendu, fenêtre) : journal + proposition du mode console.
    let hook_paths = paths.clone();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info.to_string();
        log_gui_error(&hook_paths, &format!("panique : {msg}"));
        if std::thread::current().name() == Some("main") {
            // Effacement en cours : arrêt propre (certificat ABORTED) avant de quitter.
            if !stop_active_job(Duration::from_millis(4500)) {
                log_gui_error(
                    &hook_paths,
                    "effacement toujours en cours après 4,5 s (commande firmware ?) : fermeture",
                );
            }
            win::offer_console(&msg);
        }
    }));

    let fonts = match fonts::find(&paths.assets.join("fonts")) {
        Ok(f) => f,
        Err(e) => {
            log_gui_error(&paths, &e);
            win::offer_console(&e);
            return 1;
        }
    };
    let (cfg, cfg_error) = match Config::load(&paths.config_file()) {
        Ok(c) => (c, None),
        Err(e) => (Config::default(), Some(e)),
    };
    let (book, book_error) = match config::load_clients(&paths.clients_file()) {
        Ok(b) => (b, None),
        Err(e) => (BTreeMap::new(), Some(e)),
    };
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.display().to_string()))
        .unwrap_or_default();
    let view_fonts = view::Fonts {
        regular: fonts.regular,
        strong: fonts.strong,
        bold: fonts.bold,
        mono: fonts.mono,
    };
    let font_source = fonts.source.clone();
    let winpe = win::is_winpe();

    let boot = move || {
        let mut app = App {
            backend: backend.clone(),
            demo,
            paths: paths.clone(),
            dark: cfg.ui.theme.eq_ignore_ascii_case("dark"),
            settings: SettingsForm {
                company: cfg.company.clone(),
                technician: cfg.technician.name.clone(),
                message: None,
            },
            cfg: cfg.clone(),
            cfg_error: cfg_error.clone(),
            fonts: view_fonts,
            font_source: font_source.clone(),
            screen: Screen::Disks,
            loading: true,
            list_error: None,
            ctx: None,
            disks: Vec::new(),
            selected: None,
            probes: HashMap::new(),
            notice: None,
            book: book.clone(),
            book_error: book_error.clone(),
            form: None,
            code: String::new(),
            label_checked: false,
            running: None,
            outcome: None,
            history: Vec::new(),
            history_error: None,
            history_filter: HistoryFilter::All,
            history_search: String::new(),
            export_msg: None,
            quit_asked: false,
            quit_after_job: false,
            exe_dir: exe_dir.clone(),
            winpe,
            auto_screen,
        };
        app.load_history();
        let t = app.refresh();
        (app, t)
    };

    let icon = window::icon::from_rgba(logo::icon_rgba(64), 64, 64).ok();
    let mut builder = iced::application(boot, update, view::view)
        .title(title)
        .theme(|app: &App| app.pal().theme(app.dark))
        .subscription(subscription)
        .window(window::Settings {
            size: iced::Size::new(1024.0, 768.0),
            min_size: Some(iced::Size::new(900.0, 640.0)),
            position: window::Position::Centered,
            exit_on_close_request: false,
            icon,
            ..Default::default()
        })
        .default_font(fonts.regular)
        .antialiasing(true);
    for f in fonts.data {
        builder = builder.font(f);
    }
    match builder.run() {
        Ok(()) => 0,
        Err(e) => {
            let paths = if demo {
                crate::demo::demo_paths()
            } else {
                Paths::from_exe()
            };
            let msg = format!("erreur de l'interface (iced / rendu logiciel) : {e}");
            log_gui_error(&paths, &msg);
            win::offer_console(&msg);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_follow_the_erase_path() {
        assert_eq!(Screen::Disks.step(), Some(1));
        assert_eq!(Screen::Result.step(), Some(5));
        assert_eq!(Screen::History.step(), None);
    }
}
