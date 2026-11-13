//! Mode démonstration (`--gui-demo`) : six disques FICTIFS, capacités simulées et
//! effacement simulé sur un disque EN MÉMOIRE, ralenti pour voir la progression.
//!
//! GARANTIE : ce module n'ouvre aucun disque et n'envoie aucune commande ATA/NVMe réelle.
//! Il n'utilise ni l'accès brut ni les ports en lecture seule ni la préparation des volumes
//! (vérifié par un test sur le texte de ce fichier). Les certificats produits portent la
//! mention « TEST / DÉMO — aucun disque réel ».

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::ata::{self, AtaCmd, AtaError, AtaPort, AtaResult, EraseTime, Identify, Rotation};
use crate::clock::DateTime;
#[cfg(test)]
use crate::config::Technician;
use crate::config::{Config, Customer, Paths};
use crate::detect::{Bus, DiskInfo, MediaType};
use crate::erase_hdd::{BlockDevice, ErrorCounts, Fill, Outcome, Plan, VerifyResult};
use crate::erase_ssd::{Caps, FirmwareDisk, Probe};
use crate::hpa::Hidden;
use crate::job::{Authorization, DiskBackend, ListError};
use crate::nvme::{
    Fna, NvmeController, NvmeNamespace, NvmePort, Sanicap, SanitizeLog, SanitizeState,
};
use crate::report::{self, EraseRecord, MethodKind, RecordInput, SmartAttr, SmartInfo};
use crate::safety::{self, ProtectContext};

/// Taille du disque simulé en mémoire.
pub const DEMO_DISK_BYTES: usize = 24 << 20;
/// Débit simulé (octets par seconde) : la démonstration dure quelques dizaines de secondes.
const DEMO_RATE: f64 = 5.0e6;

/// Disques fictifs (modèles de la maquette, n° de série inventés).
pub fn demo_disks() -> Vec<DiskInfo> {
    let d = |number: u32,
             model: &str,
             serial: &str,
             size: u64,
             bus: Bus,
             media: MediaType,
             removable: bool,
             volumes: Vec<char>| DiskInfo {
        number,
        path: format!("DEMO:{number}"),
        vendor: String::new(),
        model: model.into(),
        serial: serial.into(),
        firmware: "DEMO".into(),
        size_bytes: size,
        bus,
        media,
        removable,
        volumes,
    };
    vec![
        d(
            0,
            "Samsung SSD 870 EVO 500GB",
            "S6PXNF0R123456",
            500_107_862_016,
            Bus::Sata,
            MediaType::Ssd,
            false,
            vec!['C'],
        ),
        d(
            1,
            "SanDisk Ultra USB 3.0",
            "4C530001230817",
            30_752_000_000,
            Bus::Usb,
            MediaType::Unknown,
            true,
            vec!['E'],
        ),
        d(
            2,
            "ST320LM010-1KJ15",
            "DEMO0HDD02",
            320_072_933_376,
            Bus::Sata,
            MediaType::Hdd,
            false,
            vec![],
        ),
        d(
            3,
            "CT1000MX500SSD1",
            "2049E4C1A2B7",
            1_000_204_886_016,
            Bus::Sata,
            MediaType::Ssd,
            false,
            vec!['F'],
        ),
        d(
            4,
            "Samsung SSD 980 PRO 1TB",
            "S5GXNX0T612345K",
            1_000_204_886_016,
            Bus::Nvme,
            MediaType::Nvme,
            false,
            vec![],
        ),
        d(
            5,
            "WDC WD10EZEX-08WN4A0",
            "WD-DEMO6Y3KL9A21",
            1_000_204_886_016,
            Bus::Sata,
            MediaType::Hdd,
            false,
            vec![],
        ),
    ]
}

/// Contexte de protection simulé : disque 0 = système, disque 1 = clé de démarrage.
pub fn demo_protect_context() -> ProtectContext {
    ProtectContext {
        system_disks: vec![0],
        media_disks: vec![1],
        protect_usb: false,
        reliable: true,
        warnings: Vec::new(),
    }
}

fn identify(d: &DiskInfo, rotation: Rotation) -> Identify {
    let ssd = rotation == Rotation::NonRotating;
    Identify {
        model: d.model.clone(),
        serial: d.serial.clone(),
        firmware: "DEMO".into(),
        lba48: true,
        sectors: d.size_bytes / 512,
        logical_sector: 512,
        rotation,
        trim: ssd,
        drat: ssd,
        rzat: ssd,
        security: ata::SecurityState {
            supported: ssd,
            enhanced_supported: ssd,
            ..Default::default()
        },
        erase_normal: if ssd {
            EraseTime::Minutes(2)
        } else {
            EraseTime::NotReported
        },
        erase_enhanced: if ssd {
            EraseTime::Minutes(2)
        } else {
            EraseTime::NotReported
        },
        sanitize: ata::SanitizeCaps {
            supported: ssd,
            crypto: ssd,
            block: ssd,
            overwrite: false,
            antifreeze: false,
        },
        smart_supported: true,
        smart_enabled: true,
        hpa_supported: true,
        dco_supported: true,
    }
}

fn smart(d: &DiskInfo, healthy: bool) -> SmartInfo {
    let attr =
        |id: u32, name: &str, value: &str, thresh: &str, raw: &str, failing: bool| SmartAttr {
            id,
            name: name.into(),
            flags: "0x0033".into(),
            value: value.into(),
            worst: value.into(),
            thresh: thresh.into(),
            raw: raw.into(),
            failing,
        };
    SmartInfo {
        info: vec![
            ("Source".into(), "DÉMO (valeurs simulées)".into()),
            ("Modèle (IDENTIFY)".into(), d.model.clone()),
            ("N° de série (IDENTIFY)".into(), d.serial.clone()),
            (
                "Secteurs réalloués".into(),
                if healthy { "0" } else { "1 872" }.into(),
            ),
        ],
        health: if healthy {
            "PASSED".into()
        } else {
            "FAILED (seuil dépassé)".into()
        },
        attrs: vec![
            attr(
                5,
                "Reallocated_Sector_Ct",
                if healthy { "100" } else { "003" },
                "005",
                if healthy { "0" } else { "1872" },
                !healthy,
            ),
            attr(9, "Power_On_Hours", "091", "000", "8012", false),
            attr(194, "Temperature_Celsius", "041", "000", "41", false),
        ],
    }
}

/// Capacités simulées (aucune commande envoyée).
pub fn demo_probe(d: &DiskInfo) -> Probe {
    let no_hidden = Hidden::Checked {
        visible: d.size_bytes / 512,
        native: d.size_bytes / 512,
        dco: Some(d.size_bytes / 512),
        dco_error: None,
        sector: 512,
    };
    match d.number {
        // Clé USB : pont USB, rien de lisible.
        1 => Probe {
            hidden: Hidden::Unreadable("DÉMO : pont USB, commandes ATA non transmises".into()),
            errors: vec!["DÉMO : IDENTIFY DEVICE non transmis par le pont USB".into()],
            ..Default::default()
        },
        4 => {
            let c = NvmeController {
                model: d.model.clone(),
                serial: d.serial.clone(),
                firmware: "DEMO".into(),
                format_supported: true,
                sanicap: Sanicap {
                    crypto: true,
                    block: true,
                    overwrite: false,
                },
                fna: Fna {
                    format_all: false,
                    secure_erase_all: false,
                    crypto_erase: true,
                },
                dsm: true,
                tnvmcap: d.size_bytes as u128,
                namespaces: 1,
            };
            Probe {
                caps: Caps {
                    nvme: Some(c),
                    nvme_ns: Some(NvmeNamespace {
                        nsze: d.size_bytes / 512,
                        ncap: d.size_bytes / 512,
                        nuse: d.size_bytes / 1024,
                        lba_size: 512,
                        lbaf_index: 0,
                        pi_type: 0,
                        extended_metadata: false,
                    }),
                    trim_property: Some(true),
                    ..Default::default()
                },
                smart: Some(smart(d, true)),
                hidden: Hidden::NotApplicable("NVMe : pas de HPA/DCO".into()),
                real_size: Some(d.size_bytes),
                nvme_sanitize: Some(SanitizeLog {
                    sprog: 0xFFFF,
                    state: SanitizeState::Never,
                    overwrite_passes: 0,
                    global_data_erased: false,
                    scdw10: 0,
                    est_overwrite: u32::MAX,
                    est_block: 60,
                    est_crypto: 20,
                }),
                ..Default::default()
            }
        }
        _ => {
            let rotation = if d.media == MediaType::Hdd {
                Rotation::Rpm(5400)
            } else {
                Rotation::NonRotating
            };
            let id = identify(d, rotation);
            Probe {
                caps: Caps {
                    ata_sanitize: id
                        .sanitize
                        .supported
                        .then_some(ata::SanitizeStatus::default()),
                    ata: Some(id),
                    trim_property: Some(d.media != MediaType::Hdd),
                    ..Default::default()
                },
                smart: Some(smart(d, d.number != 5)),
                hidden: no_hidden,
                real_size: Some(d.size_bytes),
                ..Default::default()
            }
        }
    }
}

/// Accès « matériel » de démonstration.
pub struct DemoBackend;

struct DemoAuthorization {
    armed: bool,
    nvme: bool,
    log: Vec<String>,
}

impl Authorization for DemoAuthorization {
    fn log(&self) -> &[String] {
        &self.log
    }
    fn warnings(&self) -> &[String] {
        &[]
    }
    fn open(&self, _firmware: bool) -> Result<(Box<dyn FirmwareDisk>, Vec<String>), String> {
        if !self.armed {
            return Err(
                "autorisation non armée (--dry-run) : ouverture en écriture refusée".into(),
            );
        }
        Ok((
            Box::new(DemoDisk::new(DEMO_DISK_BYTES, self.nvme)),
            vec![format!(
                "DÉMO : disque simulé de {} Mo en mémoire, débit ralenti artificiellement",
                DEMO_DISK_BYTES >> 20
            )],
        ))
    }
}

impl DiskBackend for DemoBackend {
    fn is_demo(&self) -> bool {
        true
    }
    fn list_disks(&self) -> Result<Vec<DiskInfo>, ListError> {
        Ok(demo_disks())
    }
    fn reread(&self, number: u32) -> Result<DiskInfo, String> {
        demo_disks()
            .into_iter()
            .find(|d| d.number == number)
            .ok_or_else(|| format!("DÉMO : disque {number} introuvable"))
    }
    fn protect_context(&self) -> ProtectContext {
        demo_protect_context()
    }
    fn probe(&self, disk: &DiskInfo) -> Probe {
        // Lecture « lente » pour montrer le chargement en arrière-plan.
        std::thread::sleep(Duration::from_millis(400 + 150 * disk.number as u64));
        demo_probe(disk)
    }
    fn prepare(
        &self,
        disk: &DiskInfo,
        ctx: &ProtectContext,
        code: &str,
        dry_run: bool,
    ) -> Result<Box<dyn Authorization>, String> {
        // Même barrière que pour un vrai disque (protection + code de confirmation).
        safety::check_allowed(disk, ctx, code).map_err(|e| e.to_string())?;
        Ok(Box::new(DemoAuthorization {
            armed: !dry_run,
            nvme: disk.bus == Bus::Nvme,
            log: vec![format!(
                "{}DÉMO : aucun volume à verrouiller (disque simulé)",
                if dry_run { "[dry-run] " } else { "" }
            )],
        }))
    }
    fn firmware_poll(&self) -> Duration {
        Duration::from_millis(700)
    }
}

// ---------- Disque simulé ----------

/// Disque en mémoire ralenti. Les commandes firmware simulées l'effacent (zéros).
pub struct DemoDisk {
    data: Vec<u8>,
    nvme: bool,
    ata: DemoAta,
    port_nvme: DemoNvme,
    moved: u64,
}

impl DemoDisk {
    pub fn new(size: usize, nvme: bool) -> DemoDisk {
        DemoDisk {
            data: (0..size).map(|i| (i % 251) as u8 ^ 0x5A).collect(),
            nvme,
            ata: DemoAta::default(),
            port_nvme: DemoNvme::default(),
            moved: 0,
        }
    }

    /// Applique un effacement firmware terminé.
    fn apply(&mut self) {
        if std::mem::take(&mut self.ata.wipe) | std::mem::take(&mut self.port_nvme.wipe) {
            self.data.fill(0);
        }
    }

    /// Ralentissement artificiel avec un débit qui varie (graphique plus parlant).
    fn throttle(&mut self, len: usize) {
        self.moved += len as u64;
        let wave = 1.0 + 0.25 * ((self.moved as f64 / 3.0e6).sin());
        let secs = len as f64 / (DEMO_RATE * wave);
        if secs > 0.0005 {
            std::thread::sleep(Duration::from_secs_f64(secs));
        }
    }

    fn range(&self, off: u64, len: usize) -> io::Result<std::ops::Range<usize>> {
        let s = off as usize;
        if s + len > self.data.len() {
            return Err(io::Error::other("hors du disque simulé"));
        }
        Ok(s..s + len)
    }
}

impl BlockDevice for DemoDisk {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    fn sector_size(&self) -> u32 {
        512
    }
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        self.apply();
        let r = self.range(off, buf.len())?;
        self.data[r].copy_from_slice(buf);
        self.throttle(buf.len());
        Ok(())
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.apply();
        let r = self.range(off, buf.len())?;
        buf.copy_from_slice(&self.data[r]);
        self.throttle(buf.len());
        Ok(())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl FirmwareDisk for DemoDisk {
    fn ata(&mut self) -> Option<&mut dyn AtaPort> {
        (!self.nvme).then_some(&mut self.ata as &mut dyn AtaPort)
    }
    fn nvme(&mut self) -> Option<&mut dyn NvmePort> {
        self.nvme
            .then_some(&mut self.port_nvme as &mut dyn NvmePort)
    }
    fn trim_all(&mut self) -> Result<(), String> {
        std::thread::sleep(Duration::from_millis(500));
        Ok(())
    }
}

/// Étapes simulées d'un Sanitize (interrogations « en cours » avant la fin).
const DEMO_SANITIZE_POLLS: u32 = 8;

#[derive(Default)]
struct DemoAta {
    left: Option<u32>,
    password: bool,
    prepared: bool,
    wipe: bool,
}

const ABRT: AtaError = AtaError::Device {
    status: 0x51,
    error: 0x04,
};

impl AtaPort for DemoAta {
    fn exec(&mut self, c: &AtaCmd) -> Result<AtaResult, AtaError> {
        let ok = Ok(AtaResult {
            status: 0x50,
            ..Default::default()
        });
        match c.command {
            ata::CMD_SANITIZE if c.features == ata::SAN_STATUS => {
                let mut r = AtaResult::default();
                match self.left {
                    Some(n) if n > 0 => {
                        self.left = Some(n - 1);
                        r.count = 1 << 14;
                        r.lba = ((DEMO_SANITIZE_POLLS - n + 1) as u64 * 65535)
                            / DEMO_SANITIZE_POLLS as u64;
                    }
                    Some(_) => {
                        self.left = None;
                        self.wipe = true;
                        r.count = 1 << 15;
                    }
                    None => r.count = 1 << 15,
                }
                Ok(r)
            }
            ata::CMD_SANITIZE => {
                self.left = Some(DEMO_SANITIZE_POLLS);
                ok
            }
            ata::CMD_SEC_SET_PASSWORD => {
                self.password = true;
                ok
            }
            ata::CMD_SEC_ERASE_PREPARE if self.password => {
                self.prepared = true;
                ok
            }
            ata::CMD_SEC_ERASE_UNIT if self.prepared => {
                std::thread::sleep(Duration::from_secs(3));
                (self.prepared, self.password, self.wipe) = (false, false, true);
                ok
            }
            ata::CMD_SEC_DISABLE_PASSWORD | ata::CMD_SEC_UNLOCK => {
                self.password = false;
                ok
            }
            _ => Err(ABRT),
        }
    }
}

#[derive(Default)]
struct DemoNvme {
    left: Option<u32>,
    sanact: u32,
    wipe: bool,
}

impl NvmePort for DemoNvme {
    fn identify_controller(&mut self) -> Result<Vec<u8>, String> {
        Err("DÉMO : non simulé".into())
    }
    fn identify_namespace(&mut self, _: u32) -> Result<Vec<u8>, String> {
        Err("DÉMO : non simulé".into())
    }
    fn log_page(&mut self, id: u8, _: u32) -> Result<Vec<u8>, String> {
        let mut d = vec![0u8; 512];
        if id == crate::nvme::LOG_SANITIZE {
            let (state, sprog): (u16, u16) = match self.left {
                None => (0, 0xFFFF),
                Some(n) if n > 0 => {
                    self.left = Some(n - 1);
                    (
                        2,
                        ((DEMO_SANITIZE_POLLS - n + 1) * 65535 / DEMO_SANITIZE_POLLS) as u16,
                    )
                }
                Some(_) => {
                    self.wipe = true;
                    (1, 0xFFFF)
                }
            };
            d[0..2].copy_from_slice(&sprog.to_le_bytes());
            d[2..4].copy_from_slice(&state.to_le_bytes());
            d[4..8].copy_from_slice(&self.sanact.to_le_bytes());
        }
        Ok(d)
    }
    fn sanitize(&mut self, m: crate::nvme::SanitizeMethod, _: u32) -> Result<(), String> {
        self.sanact = match m {
            crate::nvme::SanitizeMethod::BlockErase => 2,
            crate::nvme::SanitizeMethod::CryptoErase => 4,
        };
        self.left = Some(DEMO_SANITIZE_POLLS);
        Ok(())
    }
    fn format(&mut self, _: u8, _: u8, _: u32) -> Result<(), String> {
        std::thread::sleep(Duration::from_secs(2));
        self.wipe = true;
        Ok(())
    }
}

// ---------- Dossier de données de démonstration ----------

/// Dossier data de la démo, séparé du vrai (rien n'est mélangé avec l'historique réel).
pub fn demo_paths() -> Paths {
    let temp = std::env::temp_dir();
    Paths::resolve(&temp.join(format!("{}-demo", crate::app::APP_NAME)), &temp)
}

const DEMO_CONFIG: &str = "# Données FICTIVES du mode démonstration\n\
[company]\nname = \"Exemple Informatique SARL\"\naddress = \"1 rue Exemple, 00000 Exempleville\"\n\
contact_name = \"Service atelier\"\nphone = \"01 00 00 00 00\"\n\n[technician]\nname = \"Technicien Démo\"\n";

const DEMO_CLIENTS: &str = "# Carnet FICTIF du mode démonstration\n\
[clients.lycee-demo]\nname = \"Lycée Exemple\"\naddress = \"2 avenue Exemple, 00000 Exempleville\"\n\
contact_name = \"Service informatique\"\nphone = \"01 00 00 00 01\"\n\n\
[clients.mairie-demo]\nname = \"Mairie Exemple\"\naddress = \"Place Exemple, 00000 Exempleville\"\n\
contact_name = \"Accueil\"\nphone = \"01 00 00 00 02\"\n";

/// Crée (si absents) config, carnet de clients et un historique fictif avec ses PDF.
pub fn seed(paths: &Paths) -> Result<(), String> {
    let write_new = |p: PathBuf, text: &str| -> Result<(), String> {
        if !p.exists() {
            std::fs::create_dir_all(p.parent().unwrap_or(Path::new(".")))
                .and_then(|_| std::fs::write(&p, text))
                .map_err(|e| format!("démo : écriture de {} impossible : {e}", p.display()))?;
        }
        Ok(())
    };
    write_new(paths.config_file(), DEMO_CONFIG)?;
    write_new(paths.clients_file(), DEMO_CLIENTS)?;
    if report::load_history(&paths.history)?.is_empty() {
        let cfg = Config::load(&paths.config_file())?;
        for rec in demo_history(&cfg) {
            report::append_history(&paths.history, &rec)?;
            let pdf = crate::certificate::render(&rec, None);
            let _ = std::fs::write(paths.certificates.join(format!("{}.pdf", rec.id)), pdf);
        }
    }
    Ok(())
}

/// Historique fictif (tous marqués démo / test).
pub fn demo_history(cfg: &Config) -> Vec<EraseRecord> {
    let disks = demo_disks();
    let at = |day: u8, hour: u8, minute: u8| DateTime {
        year: 2026,
        month: 11,
        day,
        hour,
        minute,
        second: 0,
    };
    // (disque, jour, heure, minute, durée s, fin anticipée, erreurs)
    let rows: [(usize, u8, u8, u8, u64, bool, u64); 5] = [
        (2, 9, 13, 45, 29_832, false, 0),
        (5, 9, 9, 12, 18_540, true, 37),
        (3, 8, 16, 2, 4_210, false, 0),
        (4, 8, 10, 58, 2_400, false, 0),
        (2, 7, 8, 20, 30_100, false, 0),
    ];
    let mut rows = rows;
    rows.sort_by_key(|r| (r.1, r.2, r.3));
    rows.iter()
        .map(|&(n, day, h, m, secs, fail, errors)| {
            let disk = &disks[n];
            let mut plan = Plan::dod_default(n as u64 + day as u64);
            if disk.media != MediaType::Hdd {
                plan.passes = vec![Fill::Random];
            }
            let size = disk.size_bytes;
            let outcome = Outcome {
                size,
                bytes_erased: if fail { size / 100 * 61 } else { size },
                passes_completed: if fail { 1 } else { plan.passes.len() },
                verify: if fail {
                    VerifyResult::Incomplete
                } else {
                    VerifyResult::Passed
                },
                errors: ErrorCounts {
                    pass: errors,
                    retries: errors / 3,
                    ..Default::default()
                },
                aborted: fail,
                abort_reason: fail
                    .then(|| "trop d'erreurs d'écriture consécutives (DÉMO)".to_string()),
                speed_samples: vec![(25.0, 92.0), (50.0, 96.0), (75.0, 101.0), (100.0, 95.0)],
                avg_mb_s: 96.0,
                min_mb_s: 92.0,
                max_mb_s: 101.0,
                elapsed: Duration::from_secs(secs),
            };
            let start = at(day, h, m);
            let end_s = h as u64 * 3600 + m as u64 * 60 + secs;
            let end = DateTime {
                hour: ((end_s / 3600) % 24) as u8,
                minute: ((end_s / 60) % 60) as u8,
                second: (end_s % 60) as u8,
                ..start
            };
            let mut rec = report::build_record(RecordInput {
                disk,
                plan: &plan,
                outcome: &outcome,
                kind: MethodKind::Overwrite,
                degraded: disk.media != MediaType::Hdd,
                org: cfg.company.clone(),
                technician: cfg.technician.clone(),
                customer: Customer {
                    name: "Lycée Exemple".into(),
                    ..Default::default()
                },
                tag: format!("DEMO-{:04}", 400 + n),
                start,
                end,
                notes: vec![report::NOTE_DEMO.to_string()],
                smart: Some(smart(disk, n != 5)),
                test_target: true,
                ssd_overwrite: false,
                hidden: Hidden::NotApplicable("démo".into()),
                real_size: Some(size),
                firmware: None,
            });
            rec.demo = true;
            rec.id = crate::job::demo_id(&rec.id);
            rec
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::{self, Ctx, Done, EraseOpts, Event};
    use std::sync::atomic::AtomicBool;

    /// Garantie structurelle : le code de la démo ne référence aucun accès matériel.
    #[test]
    fn demo_module_never_touches_real_hardware() {
        let src = include_str!("demo.rs");
        let body = &src[..src.find("#[cfg(test)]").unwrap()];
        for forbidden in [
            "rawdisk",
            "RawDisk",
            "ReadOnlyAta",
            "ReadOnlyNvme",
            "prepare_disk",
            "winio",
            "PhysicalDrive",
            "OfflineGuard",
            "detect::list_disks",
            "RealBackend",
        ] {
            assert!(!body.contains(forbidden), "la démo référence {forbidden}");
        }
        assert!(DemoBackend.is_demo());
        assert!(!job::RealBackend.is_demo());
    }

    #[test]
    fn demo_disks_match_the_mockup_and_protection() {
        let disks = demo_disks();
        assert_eq!(disks.len(), 6);
        let ctx = demo_protect_context();
        let protected: Vec<u32> = disks
            .iter()
            .filter(|d| ctx.reason(d).is_some())
            .map(|d| d.number)
            .collect();
        assert_eq!(protected, vec![0, 1]);
        // Disque 5 : SMART douteux.
        assert_ne!(demo_probe(&disks[5]).smart.unwrap().health, "PASSED");
        assert_eq!(demo_probe(&disks[2]).smart.unwrap().health, "PASSED");
        // Aucune « vraie » donnée : les chemins sont des chemins de démo.
        assert!(disks.iter().all(|d| d.path.starts_with("DEMO:")));
    }

    #[test]
    fn demo_decisions_cover_hdd_ssd_and_nvme() {
        use crate::erase_ssd::{Decision, FwMethod, MethodOpt};
        let disks = demo_disks();
        let dec = |n: usize| {
            job::analyse(
                &disks[n],
                &demo_probe(&disks[n]),
                MethodOpt::Auto,
                false,
                false,
            )
            .unwrap()
            .decision
        };
        assert!(matches!(dec(2), Decision::Overwrite { ssd: false, .. }));
        assert_eq!(dec(3), Decision::Firmware(FwMethod::AtaSanitizeCrypto));
        assert_eq!(dec(4), Decision::Firmware(FwMethod::NvmeSanitizeCrypto));
    }

    fn run_demo(n: usize, cancel_after: Option<usize>) -> (Done, Vec<Event>) {
        let disks = demo_disks();
        let disk = &disks[n];
        let paths = Paths::resolve(
            &std::env::temp_dir().join(format!("oblion-demo-test-{n}-{}", std::process::id())),
            &std::env::temp_dir(),
        );
        let cfg = Config::default();
        let cancel = AtomicBool::new(false);
        let mut events = Vec::new();
        let mut count = 0usize;
        let mut sink = |e: Event| {
            if matches!(e, Event::Progress(_)) {
                count += 1;
                if cancel_after.is_some_and(|k| count >= k) {
                    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                }
            }
            events.push(e);
        };
        let mut plan = Plan::dod_default(7);
        plan.passes = vec![Fill::Byte(0)];
        plan.chunk_bytes = 1 << 20;
        let o = EraseOpts {
            plan,
            customer: Customer::default(),
            technician: Technician::default(),
            tag: String::new(),
            dry_run: false,
            force_ssd: false,
            method: crate::erase_ssd::MethodOpt::Auto,
            allow_fallback: false,
        };
        let code = safety::confirmation_code(disk);
        let mut c = Ctx {
            cfg: &cfg,
            paths: &paths,
            cancel: &cancel,
            interrupted_by: "bouton Annuler",
            sink: &mut sink,
            write_started: None,
        };
        let done = job::erase_disk(
            &mut c,
            &DemoBackend,
            disk,
            &code,
            &o,
            &mut |_, _, _| {},
            None,
        )
        .unwrap();
        let _ = std::fs::remove_dir_all(paths.certificates.parent().unwrap());
        (done, events)
    }

    /// Effacement de démonstration complet via le module partagé `job` : certificat DÉMO.
    #[test]
    fn demo_erase_runs_through_the_shared_job_and_marks_the_certificate() {
        let (done, events) = run_demo(2, None);
        let Done::Finished(f) = done else {
            panic!("pas de certificat")
        };
        assert!(f.record.demo && f.record.test_target);
        assert_eq!(f.record.notes[0], report::NOTE_DEMO);
        assert!(f.record.id.contains("-DEMO-"), "{}", f.record.id);
        assert_eq!(f.record.status, report::Status::Erased);
        assert!(events.iter().any(|e| matches!(e, Event::Progress(_))));
    }

    #[test]
    fn demo_cancel_gives_an_aborted_certificate() {
        let (done, _) = run_demo(5, Some(3));
        let Done::Finished(f) = done else {
            panic!("pas de certificat")
        };
        assert_eq!(f.record.status, report::Status::Aborted);
        assert!(f
            .record
            .notes
            .iter()
            .any(|n| n.contains("interrompu par l'opérateur (bouton Annuler)")));
    }

    /// Demo dont la relecture ou la protection a changé depuis l'affichage de la liste.
    struct Changed {
        serial: Option<&'static str>,
        protect: Option<u32>,
    }

    impl DiskBackend for Changed {
        fn is_demo(&self) -> bool {
            true
        }
        fn list_disks(&self) -> Result<Vec<DiskInfo>, ListError> {
            DemoBackend.list_disks()
        }
        fn protect_context(&self) -> ProtectContext {
            let mut c = demo_protect_context();
            c.system_disks.extend(self.protect);
            c
        }
        fn probe(&self, disk: &DiskInfo) -> Probe {
            demo_probe(disk)
        }
        fn reread(&self, number: u32) -> Result<DiskInfo, String> {
            let mut d = DemoBackend.reread(number)?;
            if let Some(s) = self.serial {
                d.serial = s.into();
            }
            Ok(d)
        }
        fn prepare(
            &self,
            disk: &DiskInfo,
            ctx: &ProtectContext,
            code: &str,
            dry_run: bool,
        ) -> Result<Box<dyn Authorization>, String> {
            DemoBackend.prepare(disk, ctx, code, dry_run)
        }
        fn firmware_poll(&self) -> Duration {
            Duration::from_millis(1)
        }
    }

    fn attempt(b: &dyn DiskBackend) -> Result<Done, job::JobError> {
        let disk = demo_disks().remove(2);
        let paths = Paths::resolve(
            &std::env::temp_dir().join(format!("oblion-demo-changed-{}", std::process::id())),
            &std::env::temp_dir(),
        );
        let cancel = AtomicBool::new(false);
        let mut sink = |_: Event| {};
        let mut c = Ctx {
            cfg: &Config::default(),
            paths: &paths,
            cancel: &cancel,
            interrupted_by: "test",
            sink: &mut sink,
            write_started: None,
        };
        let o = EraseOpts {
            plan: Plan::dod_default(1),
            customer: Customer::default(),
            technician: Technician::default(),
            tag: String::new(),
            dry_run: true,
            force_ssd: false,
            method: crate::erase_ssd::MethodOpt::Auto,
            allow_fallback: false,
        };
        let code = safety::confirmation_code(&disk);
        job::erase_disk(&mut c, b, &disk, &code, &o, &mut |_, _, _| {}, None)
    }

    /// Le disque est relu et la protection recalculée au début de `erase_disk`.
    #[test]
    fn erase_rereads_the_disk_and_uses_a_fresh_protection_context() {
        assert!(matches!(
            attempt(&Changed {
                serial: None,
                protect: None
            }),
            Ok(Done::DryRun)
        ));
        let e = attempt(&Changed {
            serial: Some("AUTRE0001"),
            protect: None,
        })
        .unwrap_err();
        assert!(
            matches!(&e, job::JobError::NotStarted(m) if m.contains("a changé")),
            "{e}"
        );
        let e = attempt(&Changed {
            serial: None,
            protect: Some(2),
        })
        .unwrap_err();
        assert!(e.message().contains("protégé"), "{e}");
    }

    #[test]
    fn demo_protected_disk_and_wrong_code_are_refused() {
        let disks = demo_disks();
        let ctx = demo_protect_context();
        assert!(DemoBackend
            .prepare(
                &disks[0],
                &ctx,
                &safety::confirmation_code(&disks[0]),
                false
            )
            .is_err());
        assert!(DemoBackend.prepare(&disks[2], &ctx, "XXXX", false).is_err());
        assert!(DemoBackend
            .prepare(
                &disks[2],
                &ctx,
                &safety::confirmation_code(&disks[2]),
                false
            )
            .is_ok());
    }
}
