//! Effacement firmware : choix de la méthode, ATA Sanitize / Security Erase, NVMe Sanitize /
//! Format NVM, vérification par marqueurs, repli Clear (TRIM + écrasement).
//!
//! Tout ce qui décide est PUR et testé (choix, décision, délais, séquences sur ports simulés).
//! Les commandes destructives passent par un `FirmwareDisk` : en production, uniquement
//! `RawDisk`, qui n'existe qu'avec une autorisation `PreparedDisk` armée.
//!
//! Niveau NIST « Purge » UNIQUEMENT si la commande a réussi ET que la relecture des marqueurs
//! posés avant la commande montre qu'aucun n'a survécu (voir report::firmware_verdict).

use std::collections::BTreeSet;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::ata::{self, AtaError, AtaPort, Identify, Rotation, SanitizeStatus};
use crate::detect::MediaType;
use crate::erase_hdd::{self, AlignedBuf, BlockDevice, ErrorCounts, Fill, Outcome, Plan};
use crate::hpa::{self, DcoReading, Hidden};
use crate::nvme::{
    self, HealthLog, NvmeController, NvmeNamespace, NvmePort, SanitizeLog, SanitizeState,
};
use crate::report::{Fallback, FirmwareKind, FirmwareReport, MarkerCheck, SmartInfo};
use crate::smart;

// ---------- Capacités ----------

#[derive(Debug, Clone, Default)]
pub struct Caps {
    pub ata: Option<Identify>,
    /// SANITIZE STATUS EXT lu avant l'effacement (détecte le Sanitize Freeze Lock).
    pub ata_sanitize: Option<SanitizeStatus>,
    pub nvme: Option<NvmeController>,
    pub nvme_ns: Option<NvmeNamespace>,
    /// StorageDeviceTrimProperty (Windows) : TRIM activé.
    pub trim_property: Option<bool>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Frozen {
    /// Sécurité ATA gelée (mot 128 bit 3).
    pub security: bool,
    /// Sanitize Freeze Lock (SANITIZE STATUS EXT, bit 13).
    pub sanitize: bool,
}

impl Caps {
    pub fn frozen(&self) -> Frozen {
        Frozen {
            security: self.ata.as_ref().is_some_and(|i| i.security.frozen),
            sanitize: self.ata_sanitize.is_some_and(|s| s.frozen),
        }
    }

    /// TRIM utilisable pour le repli.
    pub fn trim(&self) -> bool {
        self.trim_property
            .or_else(|| self.ata.as_ref().map(|i| i.trim))
            .or_else(|| self.nvme.as_ref().map(|c| c.dsm))
            .unwrap_or(false)
    }
}

/// Type de support d'après IDENTIFY (mot 217) quand il est connu, sinon la détection Windows.
pub fn effective_media(detected: MediaType, id: Option<&Identify>) -> MediaType {
    if detected == MediaType::Nvme {
        return detected;
    }
    match id.map(|i| i.rotation) {
        Some(Rotation::NonRotating) => MediaType::Ssd,
        Some(Rotation::Rpm(_)) => MediaType::Hdd,
        _ => detected,
    }
}

// ---------- Méthodes firmware ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FwMethod {
    AtaSanitizeCrypto,
    AtaSanitizeBlock,
    AtaSanitizeOverwrite,
    AtaSecurityEraseEnhanced,
    AtaSecurityEraseNormal,
    NvmeSanitizeCrypto,
    NvmeSanitizeBlock,
    /// FORMAT NVM, SES = 2 (effacement cryptographique).
    NvmeFormatCrypto,
    /// FORMAT NVM, SES = 1 (effacement des données utilisateur).
    NvmeFormatUserData,
}

impl FwMethod {
    /// Libellé du certificat : TOUJOURS celui de la commande exécutée.
    pub fn label(&self) -> &'static str {
        match self {
            FwMethod::AtaSanitizeCrypto => "ATA Sanitize Crypto Scramble",
            FwMethod::AtaSanitizeBlock => "ATA Sanitize Block Erase",
            FwMethod::AtaSanitizeOverwrite => "ATA Sanitize Overwrite (1 passe)",
            FwMethod::AtaSecurityEraseEnhanced => "ATA Security Erase Enhanced",
            FwMethod::AtaSecurityEraseNormal => "ATA Security Erase Normal",
            FwMethod::NvmeSanitizeCrypto => "NVMe Sanitize (Crypto Erase)",
            FwMethod::NvmeSanitizeBlock => "NVMe Sanitize (Block Erase)",
            FwMethod::NvmeFormatCrypto => "NVMe Format NVM (SES=2, effacement cryptographique)",
            FwMethod::NvmeFormatUserData => "NVMe Format NVM (SES=1, effacement des données)",
        }
    }

    pub fn kind(&self) -> FirmwareKind {
        match self {
            FwMethod::AtaSecurityEraseEnhanced | FwMethod::AtaSecurityEraseNormal => {
                FirmwareKind::SecurityErase
            }
            FwMethod::NvmeFormatCrypto | FwMethod::NvmeFormatUserData => FirmwareKind::Format,
            _ => FirmwareKind::Sanitize,
        }
    }

    pub fn blocked_by(&self, f: Frozen) -> bool {
        match self {
            FwMethod::AtaSanitizeCrypto
            | FwMethod::AtaSanitizeBlock
            | FwMethod::AtaSanitizeOverwrite => f.sanitize,
            FwMethod::AtaSecurityEraseEnhanced | FwMethod::AtaSecurityEraseNormal => f.security,
            _ => false,
        }
    }
}

impl fmt::Display for FwMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// NVMe : méthodes firmware seulement si le contrôleur a EXACTEMENT un espace de noms (NN = 1).
/// - Sanitize agit sur tout le sous-système NVMe, donc sur tous les espaces de noms ;
/// - Format avec FNA « s'applique à tous » toucherait aussi les autres ;
/// - les NSID valides vont de 1 à NN : avec NN = 1, le NSID du disque est forcément 1, ce qui
///   confirme Identify Namespace 1 et le Format. Sans cette certitude, on refuse (plus sûr que
///   de deviner le NSID à partir de l'adresse SCSI, non documentée pour stornvme).
pub fn nvme_multi_ns_refusal(c: &NvmeController) -> Option<String> {
    (c.namespaces != 1).then(|| {
        format!(
            "contrôleur NVMe à {} espace(s) de noms : méthodes firmware NVMe refusées (Sanitize agit sur tout le \
             sous-système, Format peut toucher tous les espaces de noms, et le NSID du disque n'est pas confirmé). \
             Repli possible : --allow-fallback (TRIM + écrasement) ou --method overwrite",
            c.namespaces
        )
    })
}

/// Format NVM refusé si l'espace de noms est inconnu ou si son format ne serait pas conservé.
pub fn nvme_format_refusal(caps: &Caps) -> Option<String> {
    match &caps.nvme_ns {
        None => Some("format LBA courant inconnu (Identify Namespace illisible)".into()),
        Some(ns) => ns.format_refusal(),
    }
}

/// Méthodes supportées, dans l'ordre de préférence (sans tenir compte du gel).
pub fn candidates(caps: &Caps, media: MediaType) -> Vec<FwMethod> {
    let mut v = Vec::new();
    if let Some(c) = &caps.nvme {
        if nvme_multi_ns_refusal(c).is_some() {
            return v;
        }
        if c.sanicap.crypto {
            v.push(FwMethod::NvmeSanitizeCrypto);
        }
        if c.sanicap.block {
            v.push(FwMethod::NvmeSanitizeBlock);
        }
        if c.format_supported && nvme_format_refusal(caps).is_none() {
            if c.fna.crypto_erase {
                v.push(FwMethod::NvmeFormatCrypto);
            }
            v.push(FwMethod::NvmeFormatUserData);
        }
        return v;
    }
    if let Some(id) = &caps.ata {
        let s = id.sanitize;
        if s.supported && s.crypto {
            v.push(FwMethod::AtaSanitizeCrypto);
        }
        if media == MediaType::Hdd {
            if s.supported && s.overwrite {
                v.push(FwMethod::AtaSanitizeOverwrite);
            }
        } else if s.supported && s.block {
            v.push(FwMethod::AtaSanitizeBlock);
        }
        let sec = id.security;
        // Un mot de passe déjà présent (enabled/locked) ou un compteur épuisé interdit la séquence.
        if sec.supported && !sec.enabled && !sec.locked && !sec.count_expired {
            if sec.enhanced_supported {
                v.push(FwMethod::AtaSecurityEraseEnhanced);
            }
            v.push(FwMethod::AtaSecurityEraseNormal);
        }
    }
    v
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Choice {
    Firmware(FwMethod),
    /// HDD sans commande firmware utilisable : écrasement DoD (Clear). `frozen` = les
    /// commandes existent mais sont gelées.
    Overwrite {
        frozen: bool,
    },
    /// SSD/NVMe/inconnu : commandes présentes mais toutes gelées → rien n'est tenté.
    Frozen {
        blocked: Vec<FwMethod>,
    },
    /// SSD/NVMe/inconnu sans commande firmware utilisable.
    Unavailable,
}

/// Choix PUR de la méthode.
/// SSD SATA : Sanitize Crypto > Sanitize Block > Security Erase Enhanced > Normal.
/// NVMe : Sanitize Crypto > Sanitize Block > Format SES=2 > Format SES=1.
/// HDD SATA : Sanitize Crypto > Sanitize Overwrite > Security Erase (Enhanced > Normal) > DoD.
pub fn choose(caps: &Caps, media: MediaType, frozen: Frozen) -> Choice {
    let all = candidates(caps, media);
    if let Some(m) = all.iter().find(|m| !m.blocked_by(frozen)) {
        return Choice::Firmware(*m);
    }
    match (all.is_empty(), media == MediaType::Hdd) {
        (false, true) => Choice::Overwrite { frozen: true },
        (false, false) => Choice::Frozen { blocked: all },
        (true, true) => Choice::Overwrite { frozen: false },
        (true, false) => Choice::Unavailable,
    }
}

pub const FROZEN_GUIDE: &str = "\
Disque GELÉ (sécurité « frozen » et/ou Sanitize Freeze Lock) : aucune commande firmware n'a été tentée.
Pour le dégeler :
  1) mettre le PC en veille puis le réveiller (le BIOS ne regèle en général pas au réveil), puis relancer ;
  2) ou débrancher puis rebrancher à chaud l'ALIMENTATION SATA du disque (contrôleur en mode AHCI) ;
  3) sous WinPE (pas de mise en veille) : branchement à chaud, ou effacer ce disque depuis un autre PC
     / une station d'accueil.
Un écrasement (NIST Clear, statut au mieux PARTIAL pour un SSD) reste possible avec --method overwrite.";

/// Explication lisible (dry-run, --info) : capacités lues, gel, méthode retenue et pourquoi.
pub fn explain(caps: &Caps, media: MediaType, choice: &Choice) -> Vec<String> {
    let mut out = Vec::new();
    let fz = caps.frozen();
    if let Some(id) = &caps.ata {
        let s = id.sanitize;
        out.push(format!(
            "ATA Sanitize : {}",
            if s.supported {
                format!(
                    "supporté (crypto {}, block {}, overwrite {}){}",
                    yn(s.crypto),
                    yn(s.block),
                    yn(s.overwrite),
                    match caps.ata_sanitize {
                        Some(st) if st.frozen => " — GELÉ (Sanitize Freeze Lock)".to_string(),
                        Some(_) => " — non gelé".to_string(),
                        None => " — état non lu".to_string(),
                    }
                )
            } else {
                "non supporté".into()
            }
        ));
        let sec = id.security;
        out.push(format!(
            "ATA Security : {}",
            if sec.supported {
                format!(
                    "supporté (enhanced {}), activé {}, verrouillé {}, GELÉ {}, compteur épuisé {} ; durées : normal {}, enhanced {}",
                    yn(sec.enhanced_supported),
                    yn(sec.enabled),
                    yn(sec.locked),
                    yn(sec.frozen),
                    yn(sec.count_expired),
                    id.erase_normal.label(),
                    id.erase_enhanced.label()
                )
            } else {
                "non supporté".into()
            }
        ));
        if sec.enabled || sec.locked {
            out.push(
                "Un mot de passe ATA est déjà présent : Security Erase écarté (déverrouiller/désactiver d'abord)."
                    .into(),
            );
        }
    }
    if let Some(c) = &caps.nvme {
        out.push(format!(
            "NVMe Sanitize : crypto {}, block {}, overwrite {}",
            yn(c.sanicap.crypto),
            yn(c.sanicap.block),
            yn(c.sanicap.overwrite)
        ));
        out.push(format!(
            "NVMe Format NVM : {} (effacement crypto SES=2 {}, s'applique à tous les espaces de noms {})",
            if c.format_supported { "supporté" } else { "non supporté" },
            yn(c.fna.crypto_erase),
            yn(c.fna.format_all || c.fna.secure_erase_all)
        ));
        if let Some(r) = nvme_multi_ns_refusal(c) {
            out.push(format!("REFUS : {r}"));
        } else if c.format_supported {
            if let Some(r) = nvme_format_refusal(caps) {
                out.push(format!("Format NVM écarté : {r}"));
            }
        }
    }
    if caps.ata.is_none() && caps.nvme.is_none() {
        out.push("Capacités firmware non lues (voir les erreurs de lecture ci-dessus).".into());
    }
    out.push(format!(
        "TRIM : {}",
        if caps.trim() { "oui" } else { "non / inconnu" }
    ));
    out.push(format!(
        "Gel : sécurité {}, sanitize {}",
        yn(fz.security),
        yn(fz.sanitize)
    ));
    out.push(match choice {
        Choice::Firmware(m) => format!("Méthode firmware retenue : {m} (première disponible dans l'ordre de préférence pour un {media})"),
        Choice::Overwrite { frozen: true } => format!(
            "Commandes firmware gelées sur ce {media} : écrasement DoD 5220.22-M (NIST Clear)"
        ),
        Choice::Overwrite { frozen: false } => format!(
            "Aucune commande firmware utilisable sur ce {media} : écrasement DoD 5220.22-M (NIST Clear)"
        ),
        Choice::Frozen { blocked } => format!(
            "GELÉ : {} bloquée(s) par le gel, rien ne sera tenté",
            blocked.iter().map(|m| m.label()).collect::<Vec<_>>().join(", ")
        ),
        Choice::Unavailable => format!("Aucune commande firmware d'effacement utilisable sur ce disque ({media})"),
    });
    out
}

fn yn(b: bool) -> &'static str {
    if b {
        "oui"
    } else {
        "non"
    }
}

// ---------- Décision (option --method) ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodOpt {
    Auto,
    Firmware,
    Overwrite,
}

impl MethodOpt {
    pub fn parse(s: &str) -> Result<MethodOpt, String> {
        match s.trim().to_lowercase().as_str() {
            "auto" => Ok(MethodOpt::Auto),
            "firmware" => Ok(MethodOpt::Firmware),
            "overwrite" | "ecrasement" | "écrasement" => Ok(MethodOpt::Overwrite),
            _ => Err(format!(
                "méthode invalide « {s} » (auto | firmware | overwrite)"
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Écrasement (moteur HDD). `ssd` = support non magnétique : statut au mieux PARTIAL.
    Overwrite {
        ssd: bool,
        note: Option<String>,
    },
    Firmware(FwMethod),
    /// Repli direct (aucune commande firmware) : TRIM + 1 passe aléatoire + vérification.
    Fallback,
    Refuse(String),
    Frozen(String),
}

pub const SSD_NO_FIRMWARE: &str = "aucune commande firmware d'effacement utilisable ; l'écrasement ne garantit pas l'effacement d'un SSD (sur-provisionnement). \
     Options : --allow-fallback (TRIM + écrasement 1 passe, statut au mieux PARTIAL) ou --method overwrite (alias --force-overwrite-ssd)";

/// Décision PURE à partir de l'option, du repli autorisé, du support et du choix.
pub fn decide(opt: MethodOpt, allow_fallback: bool, media: MediaType, choice: &Choice) -> Decision {
    if opt == MethodOpt::Overwrite {
        return Decision::Overwrite {
            ssd: media != MediaType::Hdd,
            note: None,
        };
    }
    match choice {
        Choice::Firmware(m) => Decision::Firmware(*m),
        Choice::Overwrite { frozen } => match (opt, frozen) {
            (MethodOpt::Auto, true) => Decision::Overwrite {
                ssd: false,
                note: Some(
                    "Commandes firmware gelées (frozen) : écrasement DoD au lieu de Purge — dégeler le disque pour un effacement firmware"
                        .into(),
                ),
            },
            (MethodOpt::Auto, false) => Decision::Overwrite {
                ssd: false,
                note: None,
            },
            (_, true) => Decision::Frozen(FROZEN_GUIDE.into()),
            (_, false) => Decision::Refuse(
                "--method firmware : aucune commande firmware d'effacement utilisable sur ce disque (utiliser --method auto ou overwrite)"
                    .into(),
            ),
        },
        Choice::Frozen { .. } => Decision::Frozen(FROZEN_GUIDE.into()),
        Choice::Unavailable if allow_fallback => Decision::Fallback,
        Choice::Unavailable => Decision::Refuse(format!("disque de type {media} : {SSD_NO_FIRMWARE}")),
    }
}

// ---------- Délais ----------

const HOUR: u64 = 3600;

/// Délai d'ERASE UNIT : 2 × durée annoncée, au minimum 2 h (HDD) ou 10 min (SSD). Durée non
/// annoncée sur HDD : estimation à 100 Mo/s, doublée.
pub fn security_timeout_secs(announced_min: Option<u32>, media: MediaType, size: u64) -> u32 {
    let floor = if media == MediaType::Hdd {
        2 * HOUR
    } else {
        600
    };
    let wanted = match announced_min {
        Some(m) => 2 * m as u64 * 60,
        None if media == MediaType::Hdd => 2 * size / 100_000_000,
        None => 0,
    };
    floor.max(wanted).min(u32::MAX as u64) as u32
}

/// Attente maximale de la fin d'un Sanitize (puis échec « délai dépassé »).
pub fn sanitize_max_wait(m: FwMethod, size: u64) -> Duration {
    let secs = match m {
        FwMethod::AtaSanitizeCrypto | FwMethod::NvmeSanitizeCrypto => HOUR,
        FwMethod::AtaSanitizeBlock | FwMethod::NvmeSanitizeBlock => 4 * HOUR,
        // 50 Mo/s au pire, ×3, au moins 4 h.
        _ => (3 * size / 50_000_000).max(4 * HOUR),
    };
    Duration::from_secs(secs)
}

// ---------- Marqueurs ----------

pub const MARKER_COUNT: usize = 1000;
const MARKER_SALT: u64 = 0x4D41_524B_4552_5321; // « MARKERS! »

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Positions (octets) des secteurs échantillons : premier, dernier, et `random` positions
/// pseudo-aléatoires alignées sur 4096 octets (ou sur le secteur s'il est plus grand).
pub fn plan_markers(size: u64, sector: u32, seed: u64, random: usize) -> Vec<u64> {
    let ss = (sector as u64).max(512);
    let total = size / ss;
    if total == 0 {
        return Vec::new();
    }
    let step = (4096 / ss).max(1); // en secteurs
    let slots = total.div_ceil(step);
    let mut set = BTreeSet::new();
    set.insert(0u64);
    set.insert((total - 1) * ss);
    let want = (random as u64 + 2).min(total) as usize;
    let mut x = seed ^ MARKER_SALT;
    let mut tries = 0;
    while set.len() < want && tries < random * 20 + 100 {
        x = mix(x);
        let lba = (x % slots) * step;
        if lba < total {
            set.insert(lba * ss);
        }
        tries += 1;
    }
    set.into_iter().collect()
}

fn marker_fill(seed: u64, off: u64, buf: &mut [u8]) {
    erase_hdd::fill_buf(Fill::Random, seed ^ MARKER_SALT, off, buf);
}

/// Écrit les marqueurs, synchronise, puis les relit. Toute anomalie = échec (pas de firmware).
pub fn plant_markers(
    dev: &mut dyn BlockDevice,
    positions: &[u64],
    seed: u64,
    cancel: &AtomicBool,
) -> Result<(), String> {
    if positions.is_empty() {
        return Err("aucun secteur échantillon".into());
    }
    let ss = dev.sector_size() as usize;
    let mut w = AlignedBuf::new(ss);
    let mut r = AlignedBuf::new(ss);
    for &p in positions {
        if cancel.load(Ordering::Relaxed) {
            return Err("interrompu par l'opérateur".into());
        }
        marker_fill(seed, p, w.as_mut_slice());
        dev.write_at(p, w.as_slice())
            .map_err(|e| format!("écriture du marqueur à l'octet {p} impossible ({e})"))?;
    }
    dev.flush()
        .map_err(|e| format!("synchronisation des marqueurs impossible ({e})"))?;
    for &p in positions {
        marker_fill(seed, p, w.as_mut_slice());
        dev.read_at(p, r.as_mut_slice())
            .map_err(|e| format!("relecture du marqueur à l'octet {p} impossible ({e})"))?;
        if r.as_slice() != w.as_slice() {
            return Err(format!(
                "marqueur à l'octet {p} non retrouvé à la relecture"
            ));
        }
    }
    Ok(())
}

/// Relit les marqueurs après la commande. Un marqueur « subsiste » si un seul bloc de
/// 16 octets du motif est retrouvé intact (probabilité de faux positif négligeable).
pub fn check_markers(dev: &mut dyn BlockDevice, positions: &[u64], seed: u64) -> MarkerCheck {
    let ss = dev.sector_size() as usize;
    let mut expect = vec![0u8; ss];
    let mut r = AlignedBuf::new(ss);
    let mut c = MarkerCheck {
        planted: positions.len(),
        ..Default::default()
    };
    for &p in positions {
        marker_fill(seed, p, &mut expect);
        let ok =
            dev.read_at(p, r.as_mut_slice()).is_ok() || dev.read_at(p, r.as_mut_slice()).is_ok();
        if !ok {
            c.unreadable += 1;
        } else if r
            .as_slice()
            .chunks(16)
            .zip(expect.chunks(16))
            .any(|(a, b)| a == b)
        {
            c.survivors += 1;
        } else {
            c.erased += 1;
        }
    }
    c
}

// ---------- Disque cible ----------

/// Disque sur lequel on peut lancer des commandes firmware. En production : `RawDisk`
/// (autorisation armée exigée) ; dans les tests : disque simulé.
pub trait FirmwareDisk: BlockDevice {
    fn ata(&mut self) -> Option<&mut dyn AtaPort>;
    fn nvme(&mut self) -> Option<&mut dyn NvmePort>;
    /// TRIM de tout le disque (repli). DESTRUCTIF.
    fn trim_all(&mut self) -> Result<(), String>;
}

/// Résultat d'une étape firmware.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Step {
    pub ok: bool,
    /// Commande en échec et code (pour les notes du certificat).
    pub error: Option<String>,
    /// Notes critiques (mot de passe resté actif…).
    pub critical: Vec<String>,
    /// Notes non critiques pour le certificat (ex. relance sans FAILURE MODE).
    pub notes: Vec<String>,
    /// La commande a peut-être encore cours dans le disque (délai dépassé) : aucun repli.
    pub maybe_busy: bool,
    pub log: Vec<String>,
}

impl Step {
    fn fail(mut self, e: String) -> Step {
        self.log.push(format!("ÉCHEC : {e}"));
        self.error = Some(e);
        self.ok = false;
        self
    }
}

pub fn locked_note() -> String {
    format!(
        "DISQUE VERROUILLÉ par le mot de passe utilisateur ATA \"{pw}\" : le déverrouiller avec SECURITY UNLOCK puis SECURITY DISABLE PASSWORD \
         (mot de passe utilisateur \"{pw}\"), par exemple sous Linux : hdparm --user-master u --security-unlock {pw} /dev/sdX \
         puis hdparm --user-master u --security-disable {pw} /dev/sdX",
        pw = ata::PASSWORD
    )
}

/// Erreur de transport (délai…) pendant ERASE UNIT et nettoyage impossible.
pub fn erase_timeout_note() -> String {
    format!(
        "ERASE UNIT sans réponse : le disque peut encore être en cours d'effacement : attendre, relire --info ; \
         s'il reste verrouillé, déverrouiller avec le mot de passe \"{pw}\" (commande SECURITY UNLOCK puis \
         SECURITY DISABLE PASSWORD, ex. sous Linux : hdparm --user-master u --security-unlock {pw} /dev/sdX \
         puis hdparm --user-master u --security-disable {pw} /dev/sdX)",
        pw = ata::PASSWORD
    )
}

/// Erreur de transport sur SET PASSWORD et DISABLE de précaution sans réponse.
pub fn uncertain_password_note() -> String {
    format!(
        "ÉTAT DU MOT DE PASSE INCERTAIN après une erreur de transport sur SECURITY SET PASSWORD : vérifier avec --info ; \
         si la sécurité est activée ou le disque verrouillé, utiliser le mot de passe utilisateur \"{pw}\" \
         (SECURITY UNLOCK puis SECURITY DISABLE PASSWORD)",
        pw = ata::PASSWORD
    )
}

/// Retire le mot de passe : DISABLE PASSWORD, puis UNLOCK + DISABLE si le disque est verrouillé.
fn remove_password(p: &mut dyn AtaPort, log: &mut Vec<String>) -> Result<(), String> {
    match p.exec(&ata::security_disable_password(ata::PASSWORD)) {
        Ok(_) => {
            log.push("SECURITY DISABLE PASSWORD : OK".into());
            return Ok(());
        }
        Err(e) => log.push(format!("SECURITY DISABLE PASSWORD : {e}")),
    }
    let unlock = p.exec(&ata::security_unlock(ata::PASSWORD));
    log.push(format!(
        "SECURITY UNLOCK : {}",
        unlock
            .as_ref()
            .map(|_| "OK".to_string())
            .unwrap_or_else(|e| e.to_string())
    ));
    p.exec(&ata::security_disable_password(ata::PASSWORD))
        .map(|_| log.push("SECURITY DISABLE PASSWORD (après UNLOCK) : OK".into()))
        .map_err(|e| format!("SECURITY DISABLE PASSWORD : {e}"))
}

/// Séquence ATA Security Erase : SET PASSWORD → ERASE PREPARE → ERASE UNIT. En cas d'échec
/// après SET PASSWORD, DISABLE PASSWORD est TOUJOURS tenté ; s'il échoue, note critique.
pub fn security_erase(p: &mut dyn AtaPort, enhanced: bool, timeout_secs: u32) -> Step {
    let mut s = Step::default();
    match p.exec(&ata::security_set_password(ata::PASSWORD)) {
        Ok(_) => {}
        // Refus du disque : aucun mot de passe n'a été posé, rien à nettoyer.
        Err(e @ AtaError::Device { .. }) | Err(e @ AtaError::ReadOnly) => {
            return s.fail(format!("SECURITY SET PASSWORD : {e}"))
        }
        // Erreur de transport : la commande a peut-être abouti → DISABLE de précaution.
        Err(e) => {
            s = s.fail(format!("SECURITY SET PASSWORD : {e}"));
            match p.exec(&ata::security_disable_password(ata::PASSWORD)) {
                Ok(_) => s.log.push(
                    "SECURITY DISABLE PASSWORD de précaution : OK (un mot de passe avait été posé)"
                        .into(),
                ),
                Err(e2 @ AtaError::Device { .. }) => s.log.push(format!(
                    "SECURITY DISABLE PASSWORD de précaution refusé ({e2}) : aucun mot de passe posé"
                )),
                Err(e2) => {
                    s.log.push(format!(
                        "SECURITY DISABLE PASSWORD de précaution sans réponse : {e2}"
                    ));
                    s.critical.push(uncertain_password_note());
                }
            }
            return s;
        }
    }
    s.log.push(format!(
        "SECURITY SET PASSWORD (utilisateur \"{}\") : OK",
        ata::PASSWORD
    ));
    let mode = if enhanced { "enhanced" } else { "normal" };
    let step = match p.exec(&ata::security_erase_prepare()) {
        Err(e) => Err((format!("SECURITY ERASE PREPARE : {e}"), false)),
        Ok(_) => p
            .exec(&ata::security_erase_unit(
                ata::PASSWORD,
                enhanced,
                timeout_secs,
            ))
            .map_err(|e| {
                (
                    format!("SECURITY ERASE UNIT ({mode}, délai {timeout_secs} s) : {e}"),
                    matches!(e, AtaError::Windows(_)),
                )
            }),
    };
    match step {
        Err((e, transport)) => {
            s = s.fail(e);
            if let Err(e2) = remove_password(p, &mut s.log) {
                s.log
                    .push(format!("Nettoyage du mot de passe impossible : {e2}"));
                if transport {
                    // Délai/erreur de transport : l'effacement peut encore tourner dans le disque.
                    s.maybe_busy = true;
                    s.critical.push(erase_timeout_note());
                } else {
                    s.critical.push(locked_note());
                }
            }
            s
        }
        Ok(_) => {
            s.log.push("SECURITY ERASE UNIT : OK".into());
            s.ok = true;
            // Après un ERASE UNIT réussi, la sécurité doit être désactivée : on le vérifie.
            match ata::read_identify(p) {
                Ok(id) if !id.security.enabled => s
                    .log
                    .push("Mot de passe retiré par le disque (sécurité désactivée)".into()),
                Ok(_) => {
                    if let Err(e) = remove_password(p, &mut s.log) {
                        s.log
                            .push(format!("Nettoyage du mot de passe impossible : {e}"));
                        s.critical.push(locked_note());
                    }
                }
                Err(e) => {
                    s.log.push(format!("État de sécurité non relu ({e})"));
                    if remove_password(p, &mut s.log).is_err() {
                        s.log.push(
                            "DISABLE PASSWORD refusé (sans doute déjà désactivé) : état du mot de passe non vérifiable".into(),
                        );
                    }
                }
            }
            s
        }
    }
}

/// Sanitize ATA : lancement puis interrogation (SANITIZE STATUS EXT) jusqu'à la fin, l'échec
/// ou `max_wait`.
pub fn ata_sanitize(
    p: &mut dyn AtaPort,
    m: FwMethod,
    max_wait: Duration,
    poll: Duration,
    sleep: &mut dyn FnMut(Duration),
    progress: &mut dyn FnMut(&str),
) -> Step {
    let mut s = Step::default();
    let cmd = match m {
        FwMethod::AtaSanitizeCrypto => ata::sanitize_crypto_scramble(),
        FwMethod::AtaSanitizeBlock => ata::sanitize_block_erase(),
        FwMethod::AtaSanitizeOverwrite => ata::sanitize_overwrite(0, 1),
        other => return s.fail(format!("{other} n'est pas une commande Sanitize ATA")),
    };
    match p.exec(&cmd) {
        Ok(_) => {}
        // ABRT avec FAILURE MODE = 1 : certains disques refusent ce bit → une relance sans.
        Err(AtaError::Device { error, .. }) if error & 0x04 != 0 => {
            let mut retry = cmd.clone();
            retry.count &= !ata::SAN_FAILURE_MODE;
            let note = format!(
                "{} refusée avec FAILURE MODE = 1 (ABRT) : relancée une fois sans ce bit \
                 (en cas d'échec, sortie de l'état d'échec restreinte)",
                cmd.name()
            );
            s.log.push(note.clone());
            if let Err(e) = p.exec(&retry) {
                return s.fail(format!("{} (relance sans FAILURE MODE) : {e}", cmd.name()));
            }
            s.notes.push(note);
        }
        Err(e) => return s.fail(format!("{} : {e}", cmd.name())),
    }
    s.log.push(format!("{} : lancée", cmd.name()));
    let mut waited = Duration::ZERO;
    let (mut odd, mut io_errors) = (0, 0);
    loop {
        if waited >= max_wait {
            s.maybe_busy = true;
            return s.fail(format!(
                "{} : délai dépassé ({} min) — l'opération peut encore être en cours dans le disque",
                cmd.name(),
                max_wait.as_secs() / 60
            ));
        }
        sleep(poll);
        waited += poll;
        match ata::read_sanitize_status(p) {
            Ok(st) if st.in_progress => {
                (odd, io_errors) = (0, 0);
                progress(&format!("Sanitize en cours : {:.1} %", st.percent()));
            }
            Ok(st) if st.completed_ok => {
                s.log.push(format!("{} : terminée sans erreur", cmd.name()));
                s.ok = true;
                return s;
            }
            Ok(_) => {
                io_errors = 0;
                odd += 1;
                if odd >= 3 {
                    return s.fail(format!(
                        "SANITIZE STATUS EXT : ni en cours ni réussie après {} — Sanitize non effectuée",
                        cmd.name()
                    ));
                }
            }
            Err(e @ AtaError::Device { .. }) => {
                return s.fail(format!(
                    "{} en échec (SANITIZE STATUS EXT : {e})",
                    cmd.name()
                ))
            }
            Err(e) => {
                io_errors += 1;
                if io_errors >= 3 {
                    return s.fail(format!("SANITIZE STATUS EXT illisible : {e}"));
                }
            }
        }
    }
}

/// Sanitize NVMe (IOCTL_STORAGE_REINITIALIZE_MEDIA) puis suivi par le journal 81h.
pub fn nvme_sanitize(
    p: &mut dyn NvmePort,
    m: FwMethod,
    max_wait: Duration,
    poll: Duration,
    sleep: &mut dyn FnMut(Duration),
    progress: &mut dyn FnMut(&str),
) -> Step {
    let mut s = Step::default();
    let method = match m {
        FwMethod::NvmeSanitizeCrypto => nvme::SanitizeMethod::CryptoErase,
        FwMethod::NvmeSanitizeBlock => nvme::SanitizeMethod::BlockErase,
        other => return s.fail(format!("{other} n'est pas une commande Sanitize NVMe")),
    };
    let timeout = max_wait.as_secs().min(u32::MAX as u64) as u32;
    if let Err(e) = p.sanitize(method, timeout) {
        return s.fail(e);
    }
    s.log.push(format!("{m} : commande acceptée par le pilote"));
    // SANACT attendu dans SCDW10 (bits 2:0) : 2 = Block Erase, 4 = Crypto Erase.
    let sanact = match method {
        nvme::SanitizeMethod::BlockErase => 2,
        nvme::SanitizeMethod::CryptoErase => 4,
    };
    let mut waited = Duration::ZERO;
    let (mut never, mut io_errors, mut seen_progress) = (0, 0, false);
    loop {
        if waited >= max_wait {
            s.maybe_busy = true;
            return s.fail(format!(
                "{m} : délai dépassé ({} min) — l'opération peut encore être en cours",
                max_wait.as_secs() / 60
            ));
        }
        match p
            .log_page(nvme::LOG_SANITIZE, 512)
            .and_then(|d| nvme::decode_sanitize_log(&d))
        {
            Ok(
                l @ SanitizeLog {
                    state: SanitizeState::InProgress,
                    ..
                },
            ) => {
                (never, io_errors, seen_progress) = (0, 0, true);
                progress(&format!("Sanitize en cours : {:.1} %", l.percent()))
            }
            // Un succès n'est retenu que s'il est bien celui de NOTRE commande : opération vue
            // en cours, ou SCDW10 cohérent avec l'action envoyée (sinon : succès antérieur).
            Ok(
                l @ SanitizeLog {
                    state: SanitizeState::Succeeded | SanitizeState::SucceededForcedDeallocation,
                    ..
                },
            ) if seen_progress || l.scdw10 & 0x7 == sanact => {
                s.log
                    .push(format!("{m} : terminée (journal 81h, état {:?})", l.state));
                s.ok = true;
                return s;
            }
            Ok(SanitizeLog {
                state: SanitizeState::Failed,
                ..
            }) => {
                return s.fail(format!(
                    "{m} en échec selon le journal Sanitize Status (81h)"
                ))
            }
            Ok(l) => {
                io_errors = 0;
                never += 1;
                if never >= 3 {
                    return s.fail(format!(
                        "{m} non démarrée selon le journal 81h (état {:?}, SCDW10 {:#x} : succès éventuel antérieur, pas celui de cette commande)",
                        l.state, l.scdw10
                    ));
                }
            }
            Err(e) => {
                io_errors += 1;
                if io_errors >= 3 {
                    return s.fail(format!("journal Sanitize Status (81h) illisible : {e}"));
                }
            }
        }
        sleep(poll);
        waited += poll;
    }
}

// ---------- Orchestration ----------

pub struct FwContext<'a> {
    pub method: FwMethod,
    pub media: MediaType,
    pub caps: &'a Caps,
    pub seed: u64,
    pub markers: usize,
    pub poll: Duration,
    pub cancel: &'a AtomicBool,
}

#[derive(Debug)]
pub struct FwRun {
    pub report: FirmwareReport,
    /// Notes détaillées (commande en échec et code, nombre de marqueurs…).
    pub notes: Vec<String>,
    pub log: Vec<String>,
    /// Vrai si la commande firmware a été envoyée.
    pub attempted: bool,
    /// Délai dépassé sur une commande lancée : le disque est peut-être encore occupé,
    /// donc AUCUN repli automatique.
    pub maybe_busy: bool,
}

impl FwRun {
    /// Repli automatique permis ? Jamais si la commande a peut-être encore cours.
    pub fn fallback_allowed(&self, allow_fallback: bool) -> bool {
        self.failed() && allow_fallback && !(self.attempted && self.maybe_busy)
    }
}

pub const NOTE_NO_FALLBACK_BUSY: &str = "Pas de repli automatique : la commande firmware lancée n'a pas répondu à temps et peut encore être en cours dans le disque (statut FAILED) — attendre, puis relancer --info";

impl FwRun {
    pub fn failed(&self) -> bool {
        !self.report.command_ok
    }
}

/// Marqueurs → commande firmware → relecture des marqueurs.
pub fn run_firmware(
    d: &mut dyn FirmwareDisk,
    ctx: &FwContext,
    sleep: &mut dyn FnMut(Duration),
    progress: &mut dyn FnMut(&str),
) -> FwRun {
    let m = ctx.method;
    let mut run = FwRun {
        report: FirmwareReport {
            label: m.label().to_string(),
            kind: m.kind(),
            command_ok: false,
            markers: None,
            fallback: None,
            critical: Vec::new(),
        },
        notes: Vec::new(),
        log: Vec::new(),
        attempted: false,
        maybe_busy: false,
    };
    let size = d.size();
    let positions = plan_markers(size, d.sector_size(), ctx.seed, ctx.markers);
    progress(&format!("Écriture de {} marqueurs…", positions.len()));
    if let Err(e) = plant_markers(d, &positions, ctx.seed, ctx.cancel) {
        run.notes.push(format!(
            "Marqueurs non posés ({e}) : {m} NON lancée (vérification impossible)"
        ));
        run.log.push(format!("Marqueurs : {e}"));
        return run;
    }
    run.log.push(format!(
        "{} marqueurs écrits, synchronisés et relus",
        positions.len()
    ));

    run.attempted = true;
    progress(&format!("Lancement de {m}…"));
    let step = match m {
        FwMethod::AtaSanitizeCrypto
        | FwMethod::AtaSanitizeBlock
        | FwMethod::AtaSanitizeOverwrite => match d.ata() {
            Some(p) => ata_sanitize(p, m, sanitize_max_wait(m, size), ctx.poll, sleep, progress),
            None => Step::default().fail("port ATA indisponible".into()),
        },
        FwMethod::AtaSecurityEraseEnhanced | FwMethod::AtaSecurityEraseNormal => {
            let enhanced = m == FwMethod::AtaSecurityEraseEnhanced;
            let announced = ctx.caps.ata.as_ref().and_then(|i| {
                if enhanced {
                    i.erase_enhanced.minutes()
                } else {
                    i.erase_normal.minutes()
                }
            });
            let t = security_timeout_secs(announced, ctx.media, size);
            match d.ata() {
                Some(p) => security_erase(p, enhanced, t),
                None => Step::default().fail("port ATA indisponible".into()),
            }
        }
        FwMethod::NvmeSanitizeCrypto | FwMethod::NvmeSanitizeBlock => match d.nvme() {
            Some(p) => nvme_sanitize(p, m, sanitize_max_wait(m, size), ctx.poll, sleep, progress),
            None => Step::default().fail("port NVMe indisponible".into()),
        },
        FwMethod::NvmeFormatCrypto | FwMethod::NvmeFormatUserData => {
            let ses = if m == FwMethod::NvmeFormatCrypto {
                2
            } else {
                1
            };
            let refusal = ctx
                .caps
                .nvme
                .as_ref()
                .and_then(nvme_multi_ns_refusal)
                .or_else(|| nvme_format_refusal(ctx.caps));
            match (ctx.caps.nvme_ns.as_ref(), d.nvme()) {
                (_, _) if refusal.is_some() => Step::default().fail(format!(
                    "Format NVM refusé : {}",
                    refusal.unwrap_or_default()
                )),
                // Le format LBA courant est conservé (sinon la taille du disque changerait).
                (Some(ns), Some(p)) => match p.format(ses, ns.lbaf_index, 3600) {
                    Ok(()) => Step {
                        ok: true,
                        log: vec![format!("{m} : OK")],
                        ..Default::default()
                    },
                    Err(e) => Step::default().fail(e),
                },
                (None, _) => Step::default().fail(
                    "Format NVM refusé : format LBA courant inconnu (Identify Namespace illisible)"
                        .into(),
                ),
                (_, None) => Step::default().fail("port NVMe indisponible".into()),
            }
        }
    };
    run.log.extend(step.log.iter().cloned());
    run.report.critical = step.critical.clone();
    run.maybe_busy = step.maybe_busy;
    run.notes.extend(step.notes.iter().cloned());
    if let Some(e) = &step.error {
        run.notes.push(format!("Commande firmware en échec : {e}"));
    }
    if !step.ok {
        return run;
    }
    run.report.command_ok = true;
    progress("Relecture des marqueurs…");
    let check = check_markers(d, &positions, ctx.seed);
    run.notes.push(format!("Vérification : {}", check.label()));
    run.report.markers = Some(check);
    run
}

/// Outcome synthétique d'un effacement firmware (aucune passe logicielle).
pub fn firmware_outcome(size: u64, run: &FwRun, elapsed: Duration) -> Outcome {
    let m = run.report.markers.as_ref();
    Outcome {
        size,
        bytes_erased: if run.report.command_ok { size } else { 0 },
        passes_completed: 0,
        verify: match m {
            Some(c) if c.ok() => erase_hdd::VerifyResult::Passed,
            Some(c) if c.survivors > 0 => erase_hdd::VerifyResult::Failed,
            _ => erase_hdd::VerifyResult::Incomplete,
        },
        errors: ErrorCounts {
            verify: m.map(|c| (c.survivors + c.unreadable) as u64).unwrap_or(0),
            ..Default::default()
        },
        aborted: false,
        abort_reason: None,
        speed_samples: Vec::new(),
        avg_mb_s: 0.0,
        min_mb_s: 0.0,
        max_mb_s: 0.0,
        elapsed,
    }
}

/// Plan du repli : 1 passe aléatoire + vérification complète.
pub fn fallback_plan(seed: u64) -> Plan {
    Plan {
        passes: vec![Fill::Random],
        verify: erase_hdd::VerifyMode::Last,
        ..Plan::dod_default(seed)
    }
}

/// Repli Clear : TRIM complet (si supporté) puis 1 passe aléatoire vérifiée.
pub fn run_fallback(
    d: &mut dyn FirmwareDisk,
    trim_supported: bool,
    plan: &Plan,
    cancel: &AtomicBool,
    progress: &mut dyn FnMut(&erase_hdd::Progress),
) -> (Fallback, Outcome) {
    let trim = trim_supported.then(|| d.trim_all());
    let dev: &mut dyn BlockDevice = d;
    let o = erase_hdd::erase(dev, plan, cancel, progress);
    (Fallback { trim }, o)
}

// ---------- Lecture des capacités (lecture seule) ----------

#[derive(Debug, Default)]
pub struct Probe {
    pub caps: Caps,
    pub smart: Option<SmartInfo>,
    pub hidden: Hidden,
    pub real_size: Option<u64>,
    pub nvme_health: Option<HealthLog>,
    pub nvme_sanitize: Option<SanitizeLog>,
    /// Lectures en échec, avec la commande et le code.
    pub errors: Vec<String>,
}

/// IDENTIFY, SANITIZE STATUS, SMART, READ NATIVE MAX, DCO IDENTIFY : uniquement des lectures.
pub fn probe_ata(p: &mut dyn AtaPort) -> Probe {
    let mut pr = Probe::default();
    let id = match ata::read_identify(p) {
        Ok(id) => id,
        Err(e) => {
            pr.hidden = Hidden::Unreadable(e.clone());
            pr.errors.push(e);
            return pr;
        }
    };
    if id.sanitize.supported {
        match ata::read_sanitize_status(p) {
            Ok(s) => pr.caps.ata_sanitize = Some(s),
            Err(e) => pr.errors.push(format!("SANITIZE STATUS EXT : {e}")),
        }
    }
    let (mut data, mut thr, mut health) = (None, None, None);
    if id.smart_supported {
        match p.exec(&ata::smart_read_data()) {
            Ok(r) => data = Some(r.data),
            Err(e) => pr.errors.push(format!("SMART READ DATA : {e}")),
        }
        match p.exec(&ata::smart_read_thresholds()) {
            Ok(r) => thr = Some(r.data),
            Err(e) => pr.errors.push(format!("SMART READ THRESHOLDS : {e}")),
        }
        match ata::read_smart_health(p) {
            Ok(h) => health = Some(h),
            Err(e) => pr.errors.push(e),
        }
    }
    pr.smart = Some(smart::from_ata(
        &id,
        data.as_deref(),
        thr.as_deref(),
        health,
    ));
    // HPA : sans le jeu de fonctions HPA, l'adresse native est celle d'IDENTIFY.
    let native = if id.hpa_supported {
        ata::read_native_max_lba(p, id.lba48)
    } else {
        Ok(id.sectors.saturating_sub(1))
    };
    if let Err(e) = &native {
        pr.errors.push(e.clone());
    }
    let dco = if id.dco_supported {
        match ata::read_dco_max_lba(p) {
            Ok(l) => DcoReading::MaxLba(l),
            Err(e) => {
                pr.errors.push(e.clone());
                DcoReading::Error(e)
            }
        }
    } else {
        DcoReading::Unsupported
    };
    pr.hidden = hpa::compare(id.sectors, id.logical_sector, native, dco);
    pr.real_size = pr.hidden.real_size_bytes();
    pr.caps.ata = Some(id);
    pr
}

/// Identify Controller/Namespace, journaux 02h et 81h : uniquement des lectures.
pub fn probe_nvme(p: &mut dyn NvmePort) -> Probe {
    let mut pr = Probe {
        hidden: Hidden::NotApplicable("NVMe : pas de HPA/DCO".into()),
        ..Default::default()
    };
    match p
        .identify_controller()
        .and_then(|d| nvme::decode_controller(&d))
    {
        Ok(c) => pr.caps.nvme = Some(c),
        Err(e) => pr.errors.push(e),
    }
    // Identify Namespace 1 seulement si NN = 1 : c'est alors forcément le NSID du disque.
    match pr.caps.nvme.as_ref().map(nvme_multi_ns_refusal) {
        Some(None) => match p
            .identify_namespace(1)
            .and_then(|d| nvme::decode_namespace(&d))
        {
            Ok(ns) => {
                pr.real_size = Some(ns.size_bytes());
                pr.caps.nvme_ns = Some(ns);
            }
            Err(e) => pr.errors.push(e),
        },
        Some(Some(r)) => pr.errors.push(format!("Identify Namespace non lu : {r}")),
        None => {}
    }
    match p
        .log_page(nvme::LOG_HEALTH, 512)
        .and_then(|d| nvme::decode_health(&d))
    {
        Ok(h) => {
            pr.smart = Some(smart::from_nvme(pr.caps.nvme.as_ref(), &h));
            pr.nvme_health = Some(h);
        }
        Err(e) => pr.errors.push(e),
    }
    let sanitize = pr
        .caps
        .nvme
        .as_ref()
        .is_some_and(|c| c.sanicap.crypto || c.sanicap.block || c.sanicap.overwrite);
    if sanitize {
        match p
            .log_page(nvme::LOG_SANITIZE, 512)
            .and_then(|d| nvme::decode_sanitize_log(&d))
        {
            Ok(l) => pr.nvme_sanitize = Some(l),
            Err(e) => pr.errors.push(e),
        }
    }
    pr
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ata::tests::{put_word, sample_identify, seal};
    use crate::ata::{AtaCmd, AtaResult, SanitizeCaps, SecurityState};
    use crate::erase_hdd::tests::MemDisk;
    use crate::nvme::{Fna, Sanicap};
    use std::io;

    // ----- Faux port ATA (machine à états minimale) -----

    pub struct FakeAta {
        pub identify: Vec<u8>,
        pub enabled: bool,
        pub locked: bool,
        pub frozen: bool,
        pub password: Option<Vec<u8>>,
        pub prepared: bool,
        /// Commandes qui échouent (ABRT).
        pub fail: Vec<u8>,
        /// ERASE UNIT en échec laisse le disque verrouillé.
        pub lock_on_erase_fail: bool,
        /// Commandes exécutées puis signalées en erreur de transport (délai Windows 121).
        pub transport: Vec<u8>,
        /// Sanitize refusée (ABRT) si le bit FAILURE MODE est présent.
        pub abort_failure_mode: bool,
        pub san_frozen: bool,
        /// Interrogations « en cours » restantes ; None = pas de Sanitize lancée.
        pub san_left: Option<u32>,
        pub san_fail: bool,
        pub san_done: bool,
        pub wipe: bool,
        pub log: Vec<String>,
    }

    impl FakeAta {
        pub fn new() -> FakeAta {
            let mut d = sample_identify();
            put_word(&mut d, 128, 1 | (1 << 5)); // supporté, amélioré, NON gelé
            seal(&mut d);
            FakeAta {
                identify: d,
                enabled: false,
                locked: false,
                frozen: false,
                password: None,
                prepared: false,
                fail: vec![],
                lock_on_erase_fail: false,
                transport: vec![],
                abort_failure_mode: false,
                san_frozen: false,
                san_left: None,
                san_fail: false,
                san_done: false,
                wipe: false,
                log: vec![],
            }
        }
        fn pw(c: &AtaCmd) -> Vec<u8> {
            match &c.data {
                ata::DataDir::Out(v) => v[2..34].to_vec(),
                _ => vec![],
            }
        }
        pub fn sent(&self, name: &str) -> bool {
            self.log.iter().any(|l| l == name)
        }
    }

    const ABRT: AtaError = AtaError::Device {
        status: 0x51,
        error: 0x04,
    };

    impl AtaPort for FakeAta {
        fn exec(&mut self, c: &AtaCmd) -> Result<AtaResult, AtaError> {
            self.log.push(c.name());
            let r = self.inner(c);
            if self.transport.contains(&c.command) {
                return Err(AtaError::Windows(121));
            }
            r
        }
    }

    impl FakeAta {
        fn inner(&mut self, c: &AtaCmd) -> Result<AtaResult, AtaError> {
            let status_query = c.command == ata::CMD_SANITIZE && c.features == ata::SAN_STATUS;
            if self.fail.contains(&c.command) && !status_query {
                if c.command == ata::CMD_SEC_ERASE_UNIT && self.lock_on_erase_fail {
                    self.locked = true;
                }
                return Err(ABRT);
            }
            let ok = Ok(AtaResult {
                status: 0x50,
                ..Default::default()
            });
            match c.command {
                ata::CMD_IDENTIFY => {
                    let mut d = self.identify.clone();
                    let mut w = ata::word(&d, 128) & !0b1_1110;
                    w |= (self.enabled as u16) << 1
                        | (self.locked as u16) << 2
                        | (self.frozen as u16) << 3;
                    put_word(&mut d, 128, w);
                    seal(&mut d);
                    Ok(AtaResult {
                        data: d,
                        ..Default::default()
                    })
                }
                ata::CMD_SEC_SET_PASSWORD => {
                    if self.frozen || self.locked {
                        return Err(ABRT);
                    }
                    self.password = Some(Self::pw(c));
                    self.enabled = true;
                    ok
                }
                ata::CMD_SEC_ERASE_PREPARE => {
                    if !self.enabled || self.frozen {
                        return Err(ABRT);
                    }
                    self.prepared = true;
                    ok
                }
                ata::CMD_SEC_ERASE_UNIT => {
                    if !self.prepared || self.password.as_deref() != Some(&Self::pw(c)[..]) {
                        return Err(ABRT);
                    }
                    self.prepared = false;
                    self.wipe = true;
                    self.enabled = false;
                    self.locked = false;
                    self.password = None;
                    ok
                }
                ata::CMD_SEC_UNLOCK => {
                    if self.password.as_deref() != Some(&Self::pw(c)[..]) {
                        return Err(ABRT);
                    }
                    self.locked = false;
                    ok
                }
                ata::CMD_SEC_DISABLE_PASSWORD => {
                    if self.locked || self.password.as_deref() != Some(&Self::pw(c)[..]) {
                        return Err(ABRT);
                    }
                    self.enabled = false;
                    self.password = None;
                    ok
                }
                ata::CMD_SANITIZE if status_query => {
                    let mut count = (self.san_frozen as u16) << 13;
                    match self.san_left {
                        Some(n) if n > 0 => {
                            self.san_left = Some(n - 1);
                            count |= 1 << 14;
                        }
                        Some(_) => {
                            if self.san_fail {
                                return Err(ABRT);
                            }
                            self.san_done = true;
                            self.wipe = true;
                            count |= 1 << 15;
                        }
                        None => {}
                    }
                    Ok(AtaResult {
                        count,
                        lba: 0x4000,
                        ..Default::default()
                    })
                }
                ata::CMD_SANITIZE => {
                    if self.san_frozen
                        || (self.abort_failure_mode && c.count & ata::SAN_FAILURE_MODE != 0)
                    {
                        return Err(ABRT);
                    }
                    self.san_left = Some(2);
                    ok
                }
                _ => Err(ABRT),
            }
        }
    }

    // ----- Faux port NVMe -----

    pub struct FakeNvme {
        pub ctrl: Vec<u8>,
        pub ns: Vec<u8>,
        pub sanitize_refusal: Option<String>,
        pub format_refusal: Option<String>,
        pub san_left: Option<u32>,
        pub san_fail: bool,
        pub wipe: bool,
        pub formats: Vec<(u8, u8)>,
    }

    impl FakeNvme {
        pub fn new() -> FakeNvme {
            let mut ns = vec![0u8; 4096];
            ns[0..8].copy_from_slice(&16384u64.to_le_bytes());
            ns[128 + 2] = 9;
            FakeNvme {
                ctrl: crate::nvme::tests::sample_controller(),
                ns,
                sanitize_refusal: None,
                format_refusal: None,
                san_left: None,
                san_fail: false,
                wipe: false,
                formats: vec![],
            }
        }
    }

    impl NvmePort for FakeNvme {
        fn identify_controller(&mut self) -> Result<Vec<u8>, String> {
            Ok(self.ctrl.clone())
        }
        fn identify_namespace(&mut self, _: u32) -> Result<Vec<u8>, String> {
            Ok(self.ns.clone())
        }
        fn log_page(&mut self, id: u8, _: u32) -> Result<Vec<u8>, String> {
            let mut d = vec![0u8; 512];
            if id == nvme::LOG_SANITIZE {
                let state: u16 = match self.san_left {
                    None => 0,
                    Some(n) if n > 0 => {
                        self.san_left = Some(n - 1);
                        2
                    }
                    Some(_) if self.san_fail => 3,
                    Some(_) => {
                        self.wipe = true;
                        1
                    }
                };
                d[2..4].copy_from_slice(&state.to_le_bytes());
            } else {
                d[1..3].copy_from_slice(&310u16.to_le_bytes());
            }
            Ok(d)
        }
        fn sanitize(&mut self, _: nvme::SanitizeMethod, _: u32) -> Result<(), String> {
            if let Some(e) = &self.sanitize_refusal {
                return Err(e.clone());
            }
            self.san_left = Some(2);
            Ok(())
        }
        fn format(&mut self, ses: u8, lbaf: u8, _: u32) -> Result<(), String> {
            if let Some(e) = &self.format_refusal {
                return Err(e.clone());
            }
            self.formats.push((ses, lbaf));
            self.wipe = true;
            Ok(())
        }
    }

    // ----- Disque simulé -----

    pub struct FakeDrive {
        pub mem: MemDisk,
        pub ata: Option<FakeAta>,
        pub nvme: Option<FakeNvme>,
        /// La commande firmware efface-t-elle vraiment ?
        pub effective: bool,
        /// Ne vide que la première moitié (effacement partiel).
        pub half: bool,
        pub unreadable_after: Vec<u64>,
        pub trim_ok: bool,
        pub trimmed: bool,
    }

    impl FakeDrive {
        pub fn ata(size: usize) -> FakeDrive {
            FakeDrive {
                mem: MemDisk::new(size),
                ata: Some(FakeAta::new()),
                nvme: None,
                effective: true,
                half: false,
                unreadable_after: vec![],
                trim_ok: true,
                trimmed: false,
            }
        }
        pub fn nvme(size: usize) -> FakeDrive {
            FakeDrive {
                ata: None,
                nvme: Some(FakeNvme::new()),
                ..FakeDrive::ata(size)
            }
        }
        fn apply(&mut self) {
            let a = self
                .ata
                .as_mut()
                .map(|a| std::mem::take(&mut a.wipe))
                .unwrap_or(false);
            let n = self
                .nvme
                .as_mut()
                .map(|n| std::mem::take(&mut n.wipe))
                .unwrap_or(false);
            if (a || n) && self.effective {
                let end = if self.half {
                    self.mem.data.len() / 2
                } else {
                    self.mem.data.len()
                };
                self.mem.data[..end].fill(0);
                self.mem
                    .bad_read
                    .extend(self.unreadable_after.iter().copied());
            }
        }
    }

    impl BlockDevice for FakeDrive {
        fn size(&self) -> u64 {
            self.mem.size()
        }
        fn sector_size(&self) -> u32 {
            512
        }
        fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
            self.apply();
            self.mem.write_at(off, buf)
        }
        fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
            self.apply();
            self.mem.read_at(off, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl FirmwareDisk for FakeDrive {
        fn ata(&mut self) -> Option<&mut dyn AtaPort> {
            self.ata.as_mut().map(|a| a as &mut dyn AtaPort)
        }
        fn nvme(&mut self) -> Option<&mut dyn NvmePort> {
            self.nvme.as_mut().map(|n| n as &mut dyn NvmePort)
        }
        fn trim_all(&mut self) -> Result<(), String> {
            if self.trim_ok {
                self.trimmed = true;
                Ok(())
            } else {
                Err("IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES (TRIM) : erreur Windows 1".into())
            }
        }
    }

    const MB8: usize = 8 << 20;

    fn ctx<'a>(m: FwMethod, caps: &'a Caps, cancel: &'a AtomicBool) -> FwContext<'a> {
        FwContext {
            method: m,
            media: MediaType::Ssd,
            caps,
            seed: 7,
            markers: 200,
            poll: Duration::from_secs(5),
            cancel,
        }
    }

    fn run(d: &mut FakeDrive, m: FwMethod, caps: &Caps) -> FwRun {
        let cancel = AtomicBool::new(false);
        run_firmware(d, &ctx(m, caps, &cancel), &mut |_| {}, &mut |_| {})
    }

    // ----- Choix de la méthode -----

    fn ata_caps(san: SanitizeCaps, sec: SecurityState) -> Caps {
        let mut id = ata::decode_identify(&sample_identify()).unwrap();
        id.sanitize = san;
        id.security = sec;
        Caps {
            ata: Some(id),
            ..Default::default()
        }
    }

    fn nvme_caps(crypto: bool, block: bool, format: bool, fna_crypto: bool) -> Caps {
        let mut c = nvme::decode_controller(&crate::nvme::tests::sample_controller()).unwrap();
        c.sanicap = Sanicap {
            crypto,
            block,
            overwrite: false,
        };
        c.format_supported = format;
        c.fna = Fna {
            crypto_erase: fna_crypto,
            ..Default::default()
        };
        Caps {
            nvme: Some(c),
            nvme_ns: Some(good_ns()),
            ..Default::default()
        }
    }

    fn good_ns() -> NvmeNamespace {
        NvmeNamespace {
            nsze: 16384,
            ncap: 16384,
            nuse: 0,
            lba_size: 512,
            lbaf_index: 0,
            pi_type: 0,
            extended_metadata: false,
        }
    }

    #[test]
    fn nvme_multi_namespace_refuses_firmware_and_allows_fallback() {
        let mut caps = nvme_caps(true, true, true, true);
        caps.nvme.as_mut().unwrap().namespaces = 2;
        assert!(candidates(&caps, MediaType::Nvme).is_empty());
        let c = choose(&caps, MediaType::Nvme, Frozen::default());
        assert_eq!(c, Choice::Unavailable);
        assert_eq!(
            decide(MethodOpt::Auto, true, MediaType::Nvme, &c),
            Decision::Fallback
        );
        assert!(matches!(
            decide(MethodOpt::Auto, false, MediaType::Nvme, &c),
            Decision::Refuse(_)
        ));
        let txt = explain(&caps, MediaType::Nvme, &c).join("\n");
        assert!(txt.contains("2 espace(s) de noms"), "{txt}");
        assert!(txt.contains("--allow-fallback"));
        // NN = 0 (invalide) : refusé aussi.
        caps.nvme.as_mut().unwrap().namespaces = 0;
        assert!(candidates(&caps, MediaType::Nvme).is_empty());
    }

    #[test]
    fn nvme_format_refused_without_namespace_or_with_pi() {
        let mut caps = nvme_caps(false, false, true, true);
        assert_eq!(
            candidates(&caps, MediaType::Nvme),
            vec![FwMethod::NvmeFormatCrypto, FwMethod::NvmeFormatUserData]
        );
        caps.nvme_ns.as_mut().unwrap().pi_type = 2;
        assert!(candidates(&caps, MediaType::Nvme).is_empty());
        let txt = explain(&caps, MediaType::Nvme, &Choice::Unavailable).join("\n");
        assert!(txt.contains("Format NVM écarté"), "{txt}");
        caps.nvme_ns = None;
        assert!(candidates(&caps, MediaType::Nvme).is_empty());
        // Défense en profondeur : même si la méthode est imposée, run_firmware refuse.
        let mut d = FakeDrive::nvme(MB8);
        let r = run(&mut d, FwMethod::NvmeFormatUserData, &caps);
        assert!(r.failed());
        assert!(d.nvme.as_ref().unwrap().formats.is_empty());
    }

    fn bits(n: u32, k: u32) -> bool {
        n & (1 << k) != 0
    }

    #[test]
    fn choose_exhaustive_ata() {
        // 4 bits sanitize × 6 bits sécurité × 2 gels × 3 supports.
        for media in [MediaType::Ssd, MediaType::Hdd, MediaType::Unknown] {
            for s in 0..16u32 {
                for sec in 0..64u32 {
                    for fz in 0..4u32 {
                        let san = SanitizeCaps {
                            supported: bits(s, 0),
                            crypto: bits(s, 1),
                            block: bits(s, 2),
                            overwrite: bits(s, 3),
                            antifreeze: false,
                        };
                        let st = SecurityState {
                            supported: bits(sec, 0),
                            enabled: bits(sec, 1),
                            locked: bits(sec, 2),
                            frozen: false,
                            count_expired: bits(sec, 3),
                            enhanced_supported: bits(sec, 4),
                        };
                        let frozen = Frozen {
                            security: bits(fz, 0),
                            sanitize: bits(fz, 1),
                        };
                        let caps = ata_caps(san, st);
                        let c = choose(&caps, media, frozen);
                        // Ordre de préférence attendu, écrit indépendamment.
                        let mut pref = Vec::new();
                        if san.supported && san.crypto && !frozen.sanitize {
                            pref.push(FwMethod::AtaSanitizeCrypto);
                        }
                        let second = if media == MediaType::Hdd {
                            san.overwrite
                        } else {
                            san.block
                        };
                        if san.supported && second && !frozen.sanitize {
                            pref.push(if media == MediaType::Hdd {
                                FwMethod::AtaSanitizeOverwrite
                            } else {
                                FwMethod::AtaSanitizeBlock
                            });
                        }
                        let sec_ok = st.supported && !st.enabled && !st.locked && !st.count_expired;
                        if sec_ok && !frozen.security {
                            if st.enhanced_supported {
                                pref.push(FwMethod::AtaSecurityEraseEnhanced);
                            }
                            pref.push(FwMethod::AtaSecurityEraseNormal);
                        }
                        let any = (san.supported && (san.crypto || second)) || sec_ok;
                        let expected = match (pref.first(), any, media == MediaType::Hdd) {
                            (Some(m), _, _) => Choice::Firmware(*m),
                            (None, true, true) => Choice::Overwrite { frozen: true },
                            (None, true, false) => Choice::Frozen {
                                blocked: candidates(&caps, media),
                            },
                            (None, false, true) => Choice::Overwrite { frozen: false },
                            (None, false, false) => Choice::Unavailable,
                        };
                        assert_eq!(c, expected, "{media:?} {san:?} {st:?} {frozen:?}");
                        if let Choice::Firmware(m) = c {
                            assert!(!m.blocked_by(frozen));
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn choose_exhaustive_nvme() {
        for n in 0..16u32 {
            let caps = nvme_caps(bits(n, 0), bits(n, 1), bits(n, 2), bits(n, 3));
            let c = choose(
                &caps,
                MediaType::Nvme,
                Frozen {
                    security: true,
                    sanitize: true,
                },
            );
            let expected = if bits(n, 0) {
                Choice::Firmware(FwMethod::NvmeSanitizeCrypto)
            } else if bits(n, 1) {
                Choice::Firmware(FwMethod::NvmeSanitizeBlock)
            } else if bits(n, 2) && bits(n, 3) {
                Choice::Firmware(FwMethod::NvmeFormatCrypto)
            } else if bits(n, 2) {
                Choice::Firmware(FwMethod::NvmeFormatUserData)
            } else {
                Choice::Unavailable
            };
            assert_eq!(c, expected, "{n:04b}");
        }
    }

    #[test]
    fn choose_typical_cases() {
        let all = SanitizeCaps {
            supported: true,
            crypto: true,
            block: true,
            overwrite: true,
            antifreeze: false,
        };
        let sec = SecurityState {
            supported: true,
            enhanced_supported: true,
            ..Default::default()
        };
        let none = Frozen::default();
        assert_eq!(
            choose(&ata_caps(all, sec), MediaType::Ssd, none),
            Choice::Firmware(FwMethod::AtaSanitizeCrypto)
        );
        // SSD : sécurité gelée mais sanitize libre → Sanitize.
        let caps = ata_caps(
            SanitizeCaps {
                crypto: false,
                ..all
            },
            sec,
        );
        assert_eq!(
            choose(
                &caps,
                MediaType::Ssd,
                Frozen {
                    security: true,
                    sanitize: false
                }
            ),
            Choice::Firmware(FwMethod::AtaSanitizeBlock)
        );
        // SSD sans sanitize, sécurité gelée → GELÉ.
        let caps = ata_caps(SanitizeCaps::default(), sec);
        assert!(matches!(
            choose(
                &caps,
                MediaType::Ssd,
                Frozen {
                    security: true,
                    sanitize: false
                }
            ),
            Choice::Frozen { .. }
        ));
        // HDD : sécurité gelée → DoD, signalé gelé.
        assert_eq!(
            choose(
                &caps,
                MediaType::Hdd,
                Frozen {
                    security: true,
                    sanitize: false
                }
            ),
            Choice::Overwrite { frozen: true }
        );
        // HDD avec sanitize overwrite → Purge d'abord.
        let caps = ata_caps(
            SanitizeCaps {
                crypto: false,
                ..all
            },
            sec,
        );
        assert_eq!(
            choose(&caps, MediaType::Hdd, none),
            Choice::Firmware(FwMethod::AtaSanitizeOverwrite)
        );
        // Sans capacités lues.
        assert_eq!(
            choose(&Caps::default(), MediaType::Hdd, none),
            Choice::Overwrite { frozen: false }
        );
        assert_eq!(
            choose(&Caps::default(), MediaType::Unknown, none),
            Choice::Unavailable
        );
    }

    #[test]
    fn decide_maps_options() {
        let fw = Choice::Firmware(FwMethod::AtaSanitizeCrypto);
        assert_eq!(
            decide(MethodOpt::Auto, false, MediaType::Ssd, &fw),
            Decision::Firmware(FwMethod::AtaSanitizeCrypto)
        );
        assert_eq!(
            decide(MethodOpt::Overwrite, false, MediaType::Ssd, &fw),
            Decision::Overwrite {
                ssd: true,
                note: None
            }
        );
        assert_eq!(
            decide(MethodOpt::Overwrite, false, MediaType::Hdd, &fw),
            Decision::Overwrite {
                ssd: false,
                note: None
            }
        );
        let hdd = Choice::Overwrite { frozen: false };
        assert_eq!(
            decide(MethodOpt::Auto, false, MediaType::Hdd, &hdd),
            Decision::Overwrite {
                ssd: false,
                note: None
            }
        );
        assert!(matches!(
            decide(MethodOpt::Firmware, false, MediaType::Hdd, &hdd),
            Decision::Refuse(_)
        ));
        let hdd_frozen = Choice::Overwrite { frozen: true };
        assert!(matches!(
            decide(MethodOpt::Auto, false, MediaType::Hdd, &hdd_frozen),
            Decision::Overwrite {
                ssd: false,
                note: Some(_)
            }
        ));
        assert!(matches!(
            decide(MethodOpt::Firmware, true, MediaType::Hdd, &hdd_frozen),
            Decision::Frozen(_)
        ));
        let frozen = Choice::Frozen {
            blocked: vec![FwMethod::AtaSecurityEraseNormal],
        };
        for fb in [false, true] {
            match decide(MethodOpt::Auto, fb, MediaType::Ssd, &frozen) {
                Decision::Frozen(g) => {
                    assert!(g.contains("veille") && g.contains("à chaud") && g.contains("WinPE"))
                }
                d => panic!("{d:?}"),
            }
        }
        match decide(MethodOpt::Auto, false, MediaType::Ssd, &Choice::Unavailable) {
            Decision::Refuse(e) => assert!(e.contains("ne garantit pas l'effacement d'un SSD")),
            d => panic!("{d:?}"),
        }
        assert_eq!(
            decide(MethodOpt::Auto, true, MediaType::Nvme, &Choice::Unavailable),
            Decision::Fallback
        );
        assert_eq!(MethodOpt::parse("Firmware").unwrap(), MethodOpt::Firmware);
        assert!(MethodOpt::parse("x").is_err());
    }

    #[test]
    fn timeouts() {
        // 2 × durée annoncée, minimum 2 h (HDD) / 10 min (SSD).
        assert_eq!(security_timeout_secs(Some(2), MediaType::Ssd, 0), 600);
        assert_eq!(security_timeout_secs(Some(60), MediaType::Ssd, 0), 7200);
        assert_eq!(security_timeout_secs(Some(30), MediaType::Hdd, 0), 7200);
        assert_eq!(security_timeout_secs(Some(300), MediaType::Hdd, 0), 36_000);
        assert_eq!(security_timeout_secs(None, MediaType::Ssd, 1 << 40), 600);
        // HDD de 4 To sans durée : 2 × 4e12 / 1e8 = 80 000 s.
        assert_eq!(
            security_timeout_secs(None, MediaType::Hdd, 4_000_000_000_000),
            80_000
        );
        assert_eq!(
            sanitize_max_wait(FwMethod::AtaSanitizeCrypto, 0),
            Duration::from_secs(3600)
        );
        assert_eq!(
            sanitize_max_wait(FwMethod::AtaSanitizeOverwrite, 4_000_000_000_000),
            Duration::from_secs(240_000)
        );
    }

    #[test]
    fn labels_are_those_of_the_command() {
        assert_eq!(
            FwMethod::AtaSanitizeCrypto.label(),
            "ATA Sanitize Crypto Scramble"
        );
        assert_eq!(
            FwMethod::NvmeSanitizeBlock.label(),
            "NVMe Sanitize (Block Erase)"
        );
        assert_eq!(
            FwMethod::AtaSecurityEraseEnhanced.label(),
            "ATA Security Erase Enhanced"
        );
        assert_eq!(
            FwMethod::AtaSecurityEraseNormal.kind(),
            FirmwareKind::SecurityErase
        );
        assert_eq!(FwMethod::NvmeFormatCrypto.kind(), FirmwareKind::Format);
    }

    // ----- Marqueurs -----

    #[test]
    fn markers_cover_first_last_and_aligned_random() {
        let size = 64u64 << 20;
        let p = plan_markers(size, 512, 1, 1000);
        assert_eq!(p.len(), 1002);
        assert_eq!(p[0], 0);
        assert_eq!(*p.last().unwrap(), size - 512);
        assert!(p[1..p.len() - 1].iter().all(|o| o % 4096 == 0 && *o < size));
        assert_eq!(p, plan_markers(size, 512, 1, 1000), "reproductible");
        assert_ne!(p, plan_markers(size, 512, 2, 1000));
        // Petit disque : plafonné au nombre de positions alignées (+ le dernier secteur).
        assert_eq!(plan_markers(4096, 512, 1, 1000), vec![0, 3584]);
        let small = plan_markers(65536, 512, 1, 1000);
        assert!(small.len() <= 17 && small.len() > 10, "{}", small.len());
        assert!(plan_markers(100, 512, 1, 10).is_empty());
    }

    #[test]
    fn markers_planted_then_checked() {
        let mut d = MemDisk::new(MB8);
        let pos = plan_markers(MB8 as u64, 512, 3, 100);
        plant_markers(&mut d, &pos, 3, &AtomicBool::new(false)).unwrap();
        let c = check_markers(&mut d, &pos, 3);
        assert_eq!(c.survivors, pos.len(), "rien n'a été effacé");
        d.data.fill(0);
        let c = check_markers(&mut d, &pos, 3);
        assert!(c.ok(), "{c:?}");
        // Un seul bloc de 16 octets restant suffit à compter un survivant.
        plant_markers(&mut d, &pos, 3, &AtomicBool::new(false)).unwrap();
        d.data.fill(0);
        let p = pos[5] as usize;
        let mut buf = vec![0u8; 512];
        marker_fill(3, pos[5], &mut buf);
        d.data[p + 64..p + 80].copy_from_slice(&buf[64..80]);
        let c = check_markers(&mut d, &pos, 3);
        assert_eq!(c.survivors, 1);
        assert!(!c.ok());
    }

    #[test]
    fn marker_write_failure_prevents_firmware() {
        let mut d = FakeDrive::ata(MB8);
        d.mem.bad_write.insert(0);
        let caps = ata_caps(
            ata::decode_identify(&sample_identify()).unwrap().sanitize,
            SecurityState::default(),
        );
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &caps);
        assert!(!r.attempted);
        assert!(!r.report.command_ok);
        assert!(r.notes[0].contains("NON lancée"));
        assert!(!d.ata.unwrap().sent("SANITIZE CRYPTO SCRAMBLE EXT"));
    }

    #[test]
    fn marker_not_read_back_prevents_firmware() {
        let mut d = FakeDrive::ata(MB8);
        d.mem.silent_corrupt.insert(0); // l'écriture du secteur 0 est corrompue en silence
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &Caps::default());
        assert!(!r.attempted);
        assert!(r.notes[0].contains("non retrouvé"), "{:?}", r.notes);
    }

    // ----- Sanitize ATA -----

    #[test]
    fn ata_sanitize_success_is_verified_by_markers() {
        let mut d = FakeDrive::ata(MB8);
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &Caps::default());
        assert!(r.attempted && r.report.command_ok, "{:?}", r.log);
        assert!(r.report.markers.as_ref().unwrap().ok());
        assert_eq!(r.report.label, "ATA Sanitize Crypto Scramble");
        let a = d.ata.as_ref().unwrap();
        assert!(a.sent("SANITIZE CRYPTO SCRAMBLE EXT"));
        assert!(a.log.iter().filter(|l| *l == "SANITIZE STATUS EXT").count() >= 3);
        let (status, level) = crate::report::firmware_verdict(&r.report, 0, false);
        assert_eq!((status, level), (crate::report::Status::Erased, "Purge"));
    }

    #[test]
    fn ineffective_firmware_leaves_markers_and_fails() {
        let mut d = FakeDrive::ata(MB8);
        d.effective = false;
        let r = run(&mut d, FwMethod::AtaSanitizeBlock, &Caps::default());
        assert!(r.report.command_ok);
        let m = r.report.markers.clone().unwrap();
        assert_eq!(m.survivors, m.planted);
        assert_eq!(
            crate::report::firmware_verdict(&r.report, 0, false).0,
            crate::report::Status::Failed
        );
        // Effacement partiel : FAILED aussi.
        let mut d = FakeDrive::ata(MB8);
        d.half = true;
        let r = run(&mut d, FwMethod::AtaSanitizeBlock, &Caps::default());
        let m = r.report.markers.clone().unwrap();
        assert!(m.survivors > 0 && m.erased > 0);
        assert_ne!(
            crate::report::firmware_verdict(&r.report, 0, false).1,
            "Purge"
        );
    }

    #[test]
    fn unreadable_markers_mean_incomplete_no_purge() {
        let mut d = FakeDrive::ata(MB8);
        d.unreadable_after = vec![0];
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &Caps::default());
        let m = r.report.markers.clone().unwrap();
        assert_eq!(m.unreadable, 1);
        assert!(m.label().starts_with("Incomplète"));
        assert_eq!(
            crate::report::firmware_verdict(&r.report, 0, false),
            (crate::report::Status::Failed, "Aucun")
        );
    }

    #[test]
    fn ata_sanitize_refused_or_failed_is_reported_with_code() {
        let mut d = FakeDrive::ata(MB8);
        d.ata.as_mut().unwrap().fail = vec![ata::CMD_SANITIZE];
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &Caps::default());
        assert!(r.attempted && r.failed());
        assert!(r.report.markers.is_none());
        assert!(
            r.notes
                .iter()
                .any(|n| n.contains("SANITIZE CRYPTO SCRAMBLE EXT") && n.contains("0x04")),
            "{:?}",
            r.notes
        );
        let mut d = FakeDrive::ata(MB8);
        d.ata.as_mut().unwrap().san_fail = true;
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &Caps::default());
        assert!(r.failed());
        assert!(
            r.notes.iter().any(|n| n.contains("en échec")),
            "{:?}",
            r.notes
        );
    }

    /// Port qui accepte le lancement puis répond toujours « en cours ».
    struct Stuck;
    impl AtaPort for Stuck {
        fn exec(&mut self, c: &AtaCmd) -> Result<AtaResult, AtaError> {
            Ok(AtaResult {
                count: if c.features == ata::SAN_STATUS {
                    1 << 14
                } else {
                    0
                },
                ..Default::default()
            })
        }
    }

    #[test]
    fn ata_sanitize_times_out() {
        let mut slept = Duration::ZERO;
        let mut msgs = 0;
        let s = ata_sanitize(
            &mut Stuck,
            FwMethod::AtaSanitizeCrypto,
            Duration::from_secs(60),
            Duration::from_secs(5),
            &mut |d| slept += d,
            &mut |_| msgs += 1,
        );
        assert!(!s.ok);
        assert!(s.error.unwrap().contains("délai dépassé"));
        assert_eq!(slept, Duration::from_secs(60));
        assert_eq!(msgs, 12, "progression affichée à chaque interrogation");
    }

    // ----- Security Erase -----

    #[test]
    fn security_erase_success_sequence() {
        let mut d = FakeDrive::ata(MB8);
        let r = run(&mut d, FwMethod::AtaSecurityEraseEnhanced, &Caps::default());
        assert!(r.report.command_ok, "{:?}", r.log);
        assert!(r.report.markers.as_ref().unwrap().ok());
        let a = d.ata.as_ref().unwrap();
        let seq: Vec<&str> = a
            .log
            .iter()
            .map(|s| s.as_str())
            .filter(|s| s.starts_with("SECURITY"))
            .collect();
        assert_eq!(
            seq,
            [
                "SECURITY SET PASSWORD",
                "SECURITY ERASE PREPARE",
                "SECURITY ERASE UNIT"
            ]
        );
        assert!(!a.enabled && a.password.is_none());
        assert!(r.report.critical.is_empty());
    }

    #[test]
    fn security_erase_failure_always_disables_password() {
        let mut a = FakeAta::new();
        a.fail = vec![ata::CMD_SEC_ERASE_UNIT];
        let s = security_erase(&mut a, false, 600);
        assert!(!s.ok);
        assert!(s.error.as_ref().unwrap().contains("SECURITY ERASE UNIT"));
        assert!(a.sent("SECURITY DISABLE PASSWORD"));
        assert!(!a.enabled, "mot de passe retiré");
        assert!(s.critical.is_empty());

        // ERASE PREPARE refusé : nettoyage aussi.
        let mut a = FakeAta::new();
        a.fail = vec![ata::CMD_SEC_ERASE_PREPARE];
        let s = security_erase(&mut a, true, 600);
        assert!(!s.ok && !a.enabled);
        assert!(!a.sent("SECURITY ERASE UNIT"));

        // Disque verrouillé après l'échec : UNLOCK puis DISABLE.
        let mut a = FakeAta::new();
        a.fail = vec![ata::CMD_SEC_ERASE_UNIT];
        a.lock_on_erase_fail = true;
        let s = security_erase(&mut a, false, 600);
        assert!(a.sent("SECURITY UNLOCK"));
        assert!(!a.enabled && !a.locked);
        assert!(s.critical.is_empty(), "{:?}", s.log);
    }

    #[test]
    fn security_erase_cleanup_failure_gives_locked_note_first() {
        let mut d = FakeDrive::ata(MB8);
        {
            let a = d.ata.as_mut().unwrap();
            a.fail = vec![ata::CMD_SEC_ERASE_UNIT, ata::CMD_SEC_DISABLE_PASSWORD];
        }
        let r = run(&mut d, FwMethod::AtaSecurityEraseNormal, &Caps::default());
        assert!(r.failed());
        assert_eq!(r.report.critical.len(), 1);
        assert!(r.report.critical[0].contains("DISQUE VERROUILLÉ"));
        assert!(r.report.critical[0].contains("\"DiskErase\""));
        // Note en tête du certificat.
        let disk = crate::report::tests::sample_disk();
        let o = firmware_outcome(disk.size_bytes, &r, Duration::from_secs(1));
        let plan = Plan::dod_default(1);
        let rec = crate::report::build_record(crate::report::RecordInput {
            disk: &disk,
            plan: &plan,
            outcome: &o,
            kind: crate::report::MethodKind::Firmware,
            degraded: false,
            org: Default::default(),
            technician: Default::default(),
            customer: Default::default(),
            tag: String::new(),
            start: crate::clock::DateTime::now(),
            end: crate::clock::DateTime::now(),
            notes: r.notes.clone(),
            smart: None,
            test_target: false,
            ssd_overwrite: false,
            hidden: Hidden::NotChecked,
            real_size: None,
            firmware: Some(r.report.clone()),
        });
        assert!(rec.notes[0].starts_with("DISQUE VERROUILLÉ"));
        assert_eq!(rec.status, crate::report::Status::Failed);
        assert!(rec.notes.iter().any(|n| n.contains("SECURITY ERASE UNIT")));
    }

    #[test]
    fn set_password_refused_needs_no_cleanup() {
        let mut a = FakeAta::new();
        a.frozen = true;
        let s = security_erase(&mut a, false, 600);
        assert!(!s.ok);
        assert!(!a.sent("SECURITY DISABLE PASSWORD"));
        assert!(s.critical.is_empty());
    }

    #[test]
    fn set_password_transport_error_triggers_precautionary_disable() {
        // Le mot de passe a été posé mais Windows signale une erreur : DISABLE de précaution.
        let mut a = FakeAta::new();
        a.transport = vec![ata::CMD_SEC_SET_PASSWORD];
        let s = security_erase(&mut a, false, 600);
        assert!(!s.ok);
        assert!(a.sent("SECURITY DISABLE PASSWORD"));
        assert!(!a.enabled && a.password.is_none());
        assert!(s.critical.is_empty());
        assert!(!a.sent("SECURITY ERASE PREPARE"));
        // DISABLE de précaution aussi sans réponse : note critique « incertain ».
        let mut a = FakeAta::new();
        a.transport = vec![ata::CMD_SEC_SET_PASSWORD, ata::CMD_SEC_DISABLE_PASSWORD];
        let s = security_erase(&mut a, false, 600);
        assert!(s.critical[0].starts_with("ÉTAT DU MOT DE PASSE INCERTAIN"));
        // Refus du disque (ABRT) : aucun DISABLE.
        let mut a = FakeAta::new();
        a.fail = vec![ata::CMD_SEC_SET_PASSWORD];
        security_erase(&mut a, false, 600);
        assert!(!a.sent("SECURITY DISABLE PASSWORD"));
    }

    #[test]
    fn erase_unit_timeout_note_and_no_automatic_fallback() {
        let mut d = FakeDrive::ata(MB8);
        d.ata.as_mut().unwrap().transport = vec![ata::CMD_SEC_ERASE_UNIT];
        d.ata.as_mut().unwrap().fail = vec![ata::CMD_SEC_DISABLE_PASSWORD];
        let r = run(&mut d, FwMethod::AtaSecurityEraseNormal, &Caps::default());
        assert!(r.failed() && r.attempted && r.maybe_busy);
        let c = &r.report.critical[0];
        assert!(c.contains("peut encore être en cours d'effacement"), "{c}");
        assert!(c.contains("relire --info") && c.contains("\"DiskErase\""));
        assert!(
            !r.fallback_allowed(true),
            "pas de repli sur un disque peut-être occupé"
        );
        // Échec franc (ABRT) : repli permis.
        let mut d = FakeDrive::ata(MB8);
        d.ata.as_mut().unwrap().fail = vec![ata::CMD_SANITIZE];
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &Caps::default());
        assert!(r.fallback_allowed(true) && !r.fallback_allowed(false));
    }

    #[test]
    fn sanitize_timeout_forbids_fallback() {
        let s = ata_sanitize(
            &mut Stuck,
            FwMethod::AtaSanitizeBlock,
            Duration::from_secs(10),
            Duration::from_secs(5),
            &mut |_| {},
            &mut |_| {},
        );
        assert!(s.maybe_busy);
    }

    #[test]
    fn failure_mode_abort_is_retried_once_without_the_bit() {
        let mut d = FakeDrive::ata(MB8);
        d.ata.as_mut().unwrap().abort_failure_mode = true;
        let r = run(&mut d, FwMethod::AtaSanitizeCrypto, &Caps::default());
        assert!(r.report.command_ok, "{:?}", r.log);
        assert!(
            r.notes.iter().any(|n| n.contains("sans ce bit")),
            "{:?}",
            r.notes
        );
        let n = d
            .ata
            .as_ref()
            .unwrap()
            .log
            .iter()
            .filter(|l| *l == "SANITIZE CRYPTO SCRAMBLE EXT")
            .count();
        assert_eq!(n, 2);
    }

    /// Alterne erreurs de transport et « en cours », puis termine.
    struct Flaky(u32);
    impl AtaPort for Flaky {
        fn exec(&mut self, c: &AtaCmd) -> Result<AtaResult, AtaError> {
            if c.features != ata::SAN_STATUS {
                return Ok(AtaResult::default());
            }
            self.0 += 1;
            match self.0 {
                n if n >= 20 => Ok(AtaResult {
                    count: 1 << 15,
                    ..Default::default()
                }),
                n if n % 3 == 0 => Ok(AtaResult {
                    count: 1 << 14,
                    ..Default::default()
                }),
                _ => Err(AtaError::Windows(1167)),
            }
        }
    }

    #[test]
    fn sanitize_poll_counters_reset_on_valid_status() {
        // 2 erreurs, 1 « en cours », 2 erreurs… : jamais 3 erreurs d'affilée → succès.
        let s = ata_sanitize(
            &mut Flaky(0),
            FwMethod::AtaSanitizeBlock,
            Duration::from_secs(3600),
            Duration::from_secs(1),
            &mut |_| {},
            &mut |_| {},
        );
        assert!(s.ok, "{:?}", s.log);
    }

    /// Journal 81h figé sur « réussi » (opération antérieure), SCDW10 configurable.
    struct StaleNvme(u32);
    impl NvmePort for StaleNvme {
        fn identify_controller(&mut self) -> Result<Vec<u8>, String> {
            Err("n/a".into())
        }
        fn identify_namespace(&mut self, _: u32) -> Result<Vec<u8>, String> {
            Err("n/a".into())
        }
        fn log_page(&mut self, _: u8, _: u32) -> Result<Vec<u8>, String> {
            let mut d = vec![0u8; 512];
            d[2] = 1; // Succeeded
            d[4..8].copy_from_slice(&self.0.to_le_bytes());
            Ok(d)
        }
        fn sanitize(&mut self, _: nvme::SanitizeMethod, _: u32) -> Result<(), String> {
            Ok(())
        }
        fn format(&mut self, _: u8, _: u8, _: u32) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn nvme_success_must_belong_to_this_command() {
        let go = |scdw10: u32, m: FwMethod| {
            nvme_sanitize(
                &mut StaleNvme(scdw10),
                m,
                Duration::from_secs(600),
                Duration::from_secs(5),
                &mut |_| {},
                &mut |_| {},
            )
        };
        // Succès antérieur d'un Block Erase (SANACT 2) alors qu'on a lancé un Crypto Erase.
        let s = go(2, FwMethod::NvmeSanitizeCrypto);
        assert!(!s.ok);
        assert!(s.error.unwrap().contains("antérieur"));
        // SCDW10 cohérent (SANACT 4 = Crypto Erase) : accepté.
        assert!(go(4, FwMethod::NvmeSanitizeCrypto).ok);
        assert!(go(2, FwMethod::NvmeSanitizeBlock).ok);
    }

    // ----- NVMe -----

    #[test]
    fn nvme_sanitize_success_and_refusal() {
        let mut d = FakeDrive::nvme(MB8);
        let caps = Caps::default();
        let r = run(&mut d, FwMethod::NvmeSanitizeCrypto, &caps);
        assert!(
            r.report.command_ok && r.report.markers.as_ref().unwrap().ok(),
            "{:?}",
            r.log
        );

        let mut d = FakeDrive::nvme(MB8);
        d.nvme.as_mut().unwrap().sanitize_refusal = Some(
            "IOCTL_STORAGE_REINITIALIZE_MEDIA (CryptoErase) refusé : erreur Windows 50".into(),
        );
        let r = run(&mut d, FwMethod::NvmeSanitizeCrypto, &caps);
        assert!(r.failed());
        assert!(
            r.notes.iter().any(|n| n.contains("erreur Windows 50")),
            "{:?}",
            r.notes
        );

        let mut d = FakeDrive::nvme(MB8);
        d.nvme.as_mut().unwrap().san_fail = true;
        let r = run(&mut d, FwMethod::NvmeSanitizeBlock, &caps);
        assert!(r.failed());
        assert!(r.notes.iter().any(|n| n.contains("81h")));
    }

    #[test]
    fn nvme_format_keeps_current_lba_format_and_reports_refusal() {
        let mut fake = FakeNvme::new();
        let mut caps = probe_nvme(&mut fake).caps;
        caps.nvme_ns.as_mut().unwrap().lbaf_index = 1;
        let mut d = FakeDrive::nvme(MB8);
        let r = run(&mut d, FwMethod::NvmeFormatCrypto, &caps);
        assert!(r.report.command_ok);
        assert_eq!(d.nvme.as_ref().unwrap().formats, vec![(2, 1)]);
        // Sans Identify Namespace : refus (le format LBA ne doit pas changer).
        let mut d = FakeDrive::nvme(MB8);
        let r = run(&mut d, FwMethod::NvmeFormatUserData, &Caps::default());
        assert!(r.failed());
        assert!(d.nvme.as_ref().unwrap().formats.is_empty());
        let mut d = FakeDrive::nvme(MB8);
        d.nvme.as_mut().unwrap().format_refusal =
            Some("NVMe FORMAT NVM (SES=1) refusé : erreur Windows 1".into());
        let r = run(&mut d, FwMethod::NvmeFormatUserData, &caps);
        assert!(r.notes.iter().any(|n| n.contains("erreur Windows 1")));
    }

    // ----- Repli -----

    #[test]
    fn refusal_then_fallback_is_clear_partial() {
        let mut d = FakeDrive::nvme(MB8);
        d.nvme.as_mut().unwrap().sanitize_refusal = Some("refusé : erreur Windows 50".into());
        let caps = Caps::default();
        let r = run(&mut d, FwMethod::NvmeSanitizeCrypto, &caps);
        assert!(r.failed());
        let plan = Plan {
            chunk_bytes: 1 << 16,
            ..fallback_plan(9)
        };
        let (fb, o) = run_fallback(&mut d, true, &plan, &AtomicBool::new(false), &mut |_| {});
        assert!(d.trimmed);
        assert_eq!(fb.trim, Some(Ok(())));
        assert_eq!(o.verify, erase_hdd::VerifyResult::Passed);
        let mut report = r.report.clone();
        report.fallback = Some(fb);
        let mut disk = crate::report::tests::sample_disk();
        disk.size_bytes = MB8 as u64;
        disk.media = MediaType::Nvme;
        let rec = crate::report::build_record(crate::report::RecordInput {
            disk: &disk,
            plan: &plan,
            outcome: &o,
            kind: crate::report::MethodKind::Overwrite,
            degraded: false,
            org: Default::default(),
            technician: Default::default(),
            customer: Default::default(),
            tag: String::new(),
            start: crate::clock::DateTime::now(),
            end: crate::clock::DateTime::now(),
            notes: r.notes.clone(),
            smart: None,
            test_target: false,
            ssd_overwrite: false,
            hidden: Hidden::NotApplicable("NVMe".into()),
            real_size: None,
            firmware: Some(report),
        });
        assert_eq!(rec.status, crate::report::Status::Partial);
        assert_eq!(rec.level, "Clear");
        assert!(rec.method.starts_with("Repli Clear : TRIM complet"));
        assert!(rec.notes.iter().any(|n| n.contains("erreur Windows 50")));
        // TRIM refusé : le repli continue, sans « TRIM » dans le libellé.
        let mut d = FakeDrive::nvme(MB8);
        d.trim_ok = false;
        let (fb, _) = run_fallback(&mut d, true, &plan, &AtomicBool::new(false), &mut |_| {});
        assert!(matches!(fb.trim, Some(Err(_))));
        let (fb, _) = run_fallback(&mut d, false, &plan, &AtomicBool::new(false), &mut |_| {});
        assert_eq!(fb.trim, None);
    }

    // ----- Lecture des capacités -----

    #[test]
    fn probe_ata_reads_everything_and_detects_hpa() {
        let mut a = FakeAta::new();
        // READ NATIVE MAX et DCO ne sont pas simulés : erreurs rapportées, pas de panique.
        let p = probe_ata(&mut a);
        let id = p.caps.ata.as_ref().unwrap();
        assert_eq!(id.model, "Samsung SSD 860 EVO 500GB");
        assert!(p.smart.is_some());
        assert!(p.errors.iter().any(|e| e.contains("READ NATIVE MAX")));
        assert!(p.hidden.label().starts_with("Non lisible"));
        assert!(!a
            .log
            .iter()
            .any(|l| l.starts_with("SECURITY") || l.contains("SCRAMBLE")));

        struct Hpa(FakeAta);
        impl AtaPort for Hpa {
            fn exec(&mut self, c: &AtaCmd) -> Result<AtaResult, AtaError> {
                match c.command {
                    ata::CMD_READ_NATIVE_MAX_EXT => Ok(AtaResult {
                        lba: 976_773_168 + 999,
                        ..Default::default()
                    }),
                    ata::CMD_DCO => Err(ABRT),
                    ata::CMD_SMART => Ok(AtaResult {
                        data: vec![0u8; 512],
                        ..Default::default()
                    }),
                    _ => self.0.exec(c),
                }
            }
        }
        let mut h = Hpa(FakeAta::new());
        let p = probe_ata(&mut h);
        assert_eq!(p.hidden.hpa_sectors(), 1000);
        assert!(p.hidden.label().starts_with("HPA : 1000 secteurs cachés"));
        assert!(p.hidden.label().contains("DCO non lisible"));
    }

    #[test]
    fn probe_nvme_reads_identify_health_and_sanitize_log() {
        let mut n = FakeNvme::new();
        let p = probe_nvme(&mut n);
        assert!(p.errors.is_empty(), "{:?}", p.errors);
        assert_eq!(p.real_size, Some(16384 * 512));
        assert_eq!(p.smart.as_ref().unwrap().health, "PASSED");
        assert!(p.nvme_sanitize.is_some());
        assert_eq!(p.hidden.label(), "Non applicable (NVMe : pas de HPA/DCO)");
        assert_eq!(
            choose(&p.caps, MediaType::Nvme, p.caps.frozen()),
            Choice::Firmware(FwMethod::NvmeSanitizeCrypto)
        );
    }

    #[test]
    fn effective_media_uses_rotation() {
        let id = ata::decode_identify(&sample_identify()).unwrap();
        assert_eq!(
            effective_media(MediaType::Unknown, Some(&id)),
            MediaType::Ssd
        );
        let mut d = sample_identify();
        put_word(&mut d, 217, 5400);
        seal(&mut d);
        let id = ata::decode_identify(&d).unwrap();
        assert_eq!(effective_media(MediaType::Ssd, Some(&id)), MediaType::Hdd);
        assert_eq!(effective_media(MediaType::Nvme, Some(&id)), MediaType::Nvme);
        assert_eq!(
            effective_media(MediaType::Unknown, None),
            MediaType::Unknown
        );
    }

    #[test]
    fn explain_mentions_frozen_and_choice() {
        let mut caps = ata_caps(
            SanitizeCaps::default(),
            SecurityState {
                supported: true,
                frozen: true,
                ..Default::default()
            },
        );
        caps.trim_property = Some(true);
        let c = choose(&caps, MediaType::Ssd, caps.frozen());
        let lines = explain(&caps, MediaType::Ssd, &c).join("\n");
        assert!(lines.contains("GELÉ oui"), "{lines}");
        assert!(lines.contains("TRIM : oui"));
        assert!(lines.contains("rien ne sera tenté"));
    }
}
