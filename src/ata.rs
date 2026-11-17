//! Commandes ATA via IOCTL_ATA_PASS_THROUGH (disques SATA/PATA).
//!
//! Réimplémenté d'après :
//! - les en-têtes du Windows SDK 10.0.26100.0 (`shared/ntddscsi.h`) pour ATA_PASS_THROUGH_EX,
//!   IOCTL_ATA_PASS_THROUGH et les ATA_FLAGS_* (taille/offsets vérifiés par les tests) ;
//! - la documentation Microsoft d'ATA_PASS_THROUGH_EX pour l'ordre des registres dans
//!   CurrentTaskFile/PreviousTaskFile (non décrit dans l'en-tête) ;
//! - les normes ATA (ACS-2/ACS-3) pour les commandes, les mots d'IDENTIFY et les clés Sanitize.
//!
//! Sécurité : `exec_on_handle` envoie N'IMPORTE QUELLE commande. Il n'est appelé que par
//! `ReadOnlyAta` (qui filtre : seules les commandes de lecture passent) et par `RawDisk`, qui
//! n'existe qu'avec une autorisation `PreparedDisk` armée (voir rawdisk.rs).

use std::fmt;
use std::mem::{offset_of, size_of};

use crate::erase_hdd::AlignedBuf;
use crate::winio::{self, Handle};

// ---------- Constantes (ntddscsi.h) ----------

/// CTL_CODE(IOCTL_SCSI_BASE = FILE_DEVICE_CONTROLLER (4), 0x040b, METHOD_BUFFERED,
/// FILE_READ_ACCESS | FILE_WRITE_ACCESS).
pub const IOCTL_ATA_PASS_THROUGH: u32 = winio::ctl_code(0x4, 0x040b, 0, 1 | 2);

pub const ATA_FLAGS_DRDY_REQUIRED: u16 = 1 << 0;
pub const ATA_FLAGS_DATA_IN: u16 = 1 << 1;
pub const ATA_FLAGS_DATA_OUT: u16 = 1 << 2;
pub const ATA_FLAGS_48BIT_COMMAND: u16 = 1 << 3;

/// Miroir de ATA_PASS_THROUGH_EX (ntddscsi.h, x64 : ULONG_PTR = 8 octets).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct AtaPassThroughEx {
    pub length: u16,
    pub ata_flags: u16,
    pub path_id: u8,
    pub target_id: u8,
    pub lun: u8,
    pub reserved_as_uchar: u8,
    pub data_transfer_length: u32,
    pub time_out_value: u32,
    pub reserved_as_ulong: u32,
    pub data_buffer_offset: usize,
    pub previous_task_file: [u8; 8],
    pub current_task_file: [u8; 8],
}

pub const APT_SIZE: usize = size_of::<AtaPassThroughEx>();
/// Données juste après la structure (offset multiple de 8 : aligné sur un pointeur).
pub const DATA_OFFSET: usize = APT_SIZE;
const OFF_LEN: usize = offset_of!(AtaPassThroughEx, length);
const OFF_FLAGS: usize = offset_of!(AtaPassThroughEx, ata_flags);
const OFF_DTL: usize = offset_of!(AtaPassThroughEx, data_transfer_length);
const OFF_TIMEOUT: usize = offset_of!(AtaPassThroughEx, time_out_value);
const OFF_DBO: usize = offset_of!(AtaPassThroughEx, data_buffer_offset);
const OFF_PREV: usize = offset_of!(AtaPassThroughEx, previous_task_file);
const OFF_CUR: usize = offset_of!(AtaPassThroughEx, current_task_file);

// ---------- Codes de commande (ACS) ----------

pub const CMD_IDENTIFY: u8 = 0xEC;
pub const CMD_SMART: u8 = 0xB0;
pub const SMART_READ_DATA: u16 = 0xD0;
pub const SMART_READ_THRESHOLDS: u16 = 0xD1;
pub const SMART_RETURN_STATUS: u16 = 0xDA;
/// LBA mid = 4Fh, LBA high = C2h : signature exigée par les commandes SMART.
const SMART_LBA: u64 = (0xC2 << 16) | (0x4F << 8);
pub const CMD_READ_NATIVE_MAX_EXT: u8 = 0x27;
pub const CMD_READ_NATIVE_MAX: u8 = 0xF8;
pub const CMD_DCO: u8 = 0xB1;
pub const DCO_IDENTIFY: u16 = 0xC2;
pub const CMD_SEC_SET_PASSWORD: u8 = 0xF1;
pub const CMD_SEC_UNLOCK: u8 = 0xF2;
pub const CMD_SEC_ERASE_PREPARE: u8 = 0xF3;
pub const CMD_SEC_ERASE_UNIT: u8 = 0xF4;
pub const CMD_SEC_DISABLE_PASSWORD: u8 = 0xF6;
pub const CMD_SANITIZE: u8 = 0xB4;
pub const SAN_STATUS: u16 = 0x0000;
pub const SAN_CRYPTO_SCRAMBLE: u16 = 0x0011;
pub const SAN_BLOCK_ERASE: u16 = 0x0012;
pub const SAN_OVERWRITE: u16 = 0x0014;
/// Clés exigées dans le champ LBA (ACS-3) : « Cryp », « BkEr », « OW » (bits 47:32).
const KEY_CRYPTO: u64 = 0x4372_7970;
const KEY_BLOCK: u64 = 0x426B_4572;
const KEY_OVERWRITE: u64 = 0x4F57 << 32;
/// Count bit 4 = FAILURE MODE à 1 : en cas d'échec, l'état « Sanitize failed » peut être
/// quitté (comme le mode NVMe par défaut de Windows, sortie non restreinte).
pub const SAN_FAILURE_MODE: u16 = 1 << 4;
const DEV_LBA: u8 = 0x40;

/// Mot de passe utilisateur temporaire de Security Erase (connu, affiché en cas de souci).
///
/// Volontairement resté « DiskErase » malgré le changement de nom en Oblion (pas APP_NAME) :
/// c'est une valeur de protocole, pas un nom affiché. Un disque resté verrouillé par une
/// version précédente (Security Erase interrompu) doit toujours pouvoir être déverrouillé
/// par `remove_password` et par les instructions des notes (hdparm … DiskErase).
pub const PASSWORD: &str = "DiskErase";

// ---------- Commande / résultat ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDir {
    None,
    In(usize),
    Out(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AtaCmd {
    pub command: u8,
    pub features: u16,
    pub count: u16,
    pub lba: u64,
    pub device: u8,
    /// Commande 48 bits (registres « previous » utilisés).
    pub ext: bool,
    pub data: DataDir,
    pub timeout_secs: u32,
}

impl AtaCmd {
    fn new(command: u8) -> AtaCmd {
        AtaCmd {
            command,
            features: 0,
            count: 0,
            lba: 0,
            device: 0,
            ext: false,
            data: DataDir::None,
            timeout_secs: 30,
        }
    }

    /// Nom lisible pour les journaux et les notes du certificat.
    pub fn name(&self) -> String {
        match (self.command, self.features) {
            (CMD_IDENTIFY, _) => "IDENTIFY DEVICE".into(),
            (CMD_SMART, SMART_READ_DATA) => "SMART READ DATA".into(),
            (CMD_SMART, SMART_READ_THRESHOLDS) => "SMART READ THRESHOLDS".into(),
            (CMD_SMART, SMART_RETURN_STATUS) => "SMART RETURN STATUS".into(),
            (CMD_READ_NATIVE_MAX_EXT, _) => "READ NATIVE MAX ADDRESS EXT".into(),
            (CMD_READ_NATIVE_MAX, _) => "READ NATIVE MAX ADDRESS".into(),
            (CMD_DCO, DCO_IDENTIFY) => "DEVICE CONFIGURATION IDENTIFY".into(),
            (CMD_SEC_SET_PASSWORD, _) => "SECURITY SET PASSWORD".into(),
            (CMD_SEC_UNLOCK, _) => "SECURITY UNLOCK".into(),
            (CMD_SEC_ERASE_PREPARE, _) => "SECURITY ERASE PREPARE".into(),
            (CMD_SEC_ERASE_UNIT, _) => "SECURITY ERASE UNIT".into(),
            (CMD_SEC_DISABLE_PASSWORD, _) => "SECURITY DISABLE PASSWORD".into(),
            (CMD_SANITIZE, SAN_STATUS) => "SANITIZE STATUS EXT".into(),
            (CMD_SANITIZE, SAN_CRYPTO_SCRAMBLE) => "SANITIZE CRYPTO SCRAMBLE EXT".into(),
            (CMD_SANITIZE, SAN_BLOCK_ERASE) => "SANITIZE BLOCK ERASE EXT".into(),
            (CMD_SANITIZE, SAN_OVERWRITE) => "SANITIZE OVERWRITE EXT".into(),
            (c, f) => format!("commande ATA {c:#04X}/{f:#06X}"),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AtaResult {
    pub error: u8,
    pub status: u8,
    pub count: u16,
    pub lba: u64,
    pub device: u8,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtaError {
    /// DeviceIoControl a échoué (code GetLastError).
    Windows(u32),
    /// Le disque a rejeté la commande (bit ERR du registre d'état).
    Device { status: u8, error: u8 },
    /// Commande destructive refusée par l'accès en lecture seule.
    ReadOnly,
    /// Réponse illisible.
    Invalid(String),
}

impl fmt::Display for AtaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtaError::Windows(5) => f.write_str("erreur Windows 5 (accès refusé : droits administrateur ?)"),
            AtaError::Windows(1) => f.write_str(
                "erreur Windows 1 (fonction non prise en charge : pont USB, pilote RAID/RST ou NVMe ?)",
            ),
            AtaError::Windows(c) => write!(f, "erreur Windows {c}"),
            AtaError::Device { status, error } => write!(
                f,
                "refusée par le disque (status {status:#04X}, error {error:#04X}{})",
                if error & 0x04 != 0 { " : ABRT" } else { "" }
            ),
            AtaError::ReadOnly => {
                f.write_str("commande destructive refusée (accès en lecture seule)")
            }
            AtaError::Invalid(s) => write!(f, "réponse invalide : {s}"),
        }
    }
}

/// Codes Windows renvoyés par DeviceIoControl LUI-MÊME quand le pilote ou le pont USB refuse
/// la requête ATA : 1 (ERROR_INVALID_FUNCTION), 50 (ERROR_NOT_SUPPORTED),
/// 87 (ERROR_INVALID_PARAMETER).
pub const TRANSPORT_REFUSALS: [u32; 3] = [1, 50, 87];

impl AtaError {
    /// Code Windows si la commande a été refusée par Windows, le pilote ou l'adaptateur AVANT
    /// d'atteindre le disque (méthode « indisponible ») ; None si elle a pu atteindre le disque
    /// (ABRT, délai, autre erreur de transport) ou n'a pas été envoyée pour une autre raison.
    pub fn transport_refusal(&self) -> Option<u32> {
        match self {
            AtaError::Windows(c) if TRANSPORT_REFUSALS.contains(c) => Some(*c),
            _ => None,
        }
    }
}

/// Port ATA : envoi d'une commande, retour des registres de sortie et des données.
pub trait AtaPort {
    fn exec(&mut self, cmd: &AtaCmd) -> Result<AtaResult, AtaError>;
}

// ---------- Construction / décodage du tampon (pur) ----------

fn put_u16(b: &mut [u8], off: usize, v: u16) {
    b[off..off + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn data_len(cmd: &AtaCmd) -> usize {
    match &cmd.data {
        DataDir::None => 0,
        DataDir::In(n) => *n,
        DataDir::Out(v) => v.len(),
    }
}

/// Tampon d'entrée : ATA_PASS_THROUGH_EX suivi des données (même allocation).
/// Registres (doc. Microsoft) : [0] Features, [1] Count, [2] LBA 7:0, [3] LBA 15:8,
/// [4] LBA 23:16, [5] Device, [6] Command ; « previous » = octets hauts (48 bits).
pub fn encode(cmd: &AtaCmd) -> Vec<u8> {
    let n = data_len(cmd);
    let mut b = vec![0u8; DATA_OFFSET + n];
    put_u16(&mut b, OFF_LEN, APT_SIZE as u16);
    let mut flags = ATA_FLAGS_DRDY_REQUIRED;
    match &cmd.data {
        DataDir::None => {}
        DataDir::In(_) => flags |= ATA_FLAGS_DATA_IN,
        DataDir::Out(v) => {
            flags |= ATA_FLAGS_DATA_OUT;
            b[DATA_OFFSET..].copy_from_slice(v);
        }
    }
    if cmd.ext {
        flags |= ATA_FLAGS_48BIT_COMMAND;
    }
    put_u16(&mut b, OFF_FLAGS, flags);
    put_u32(&mut b, OFF_DTL, n as u32);
    put_u32(&mut b, OFF_TIMEOUT, cmd.timeout_secs.max(1));
    put_u64(&mut b, OFF_DBO, if n > 0 { DATA_OFFSET as u64 } else { 0 });
    let l = cmd.lba.to_le_bytes();
    let cur = [
        cmd.features as u8,
        cmd.count as u8,
        l[0],
        l[1],
        l[2],
        if cmd.ext {
            cmd.device
        } else {
            // 28 bits : LBA 27:24 dans les 4 bits bas du registre Device.
            cmd.device | (l[3] & 0x0F)
        },
        cmd.command,
        0,
    ];
    b[OFF_CUR..OFF_CUR + 8].copy_from_slice(&cur);
    if cmd.ext {
        let prev = [
            (cmd.features >> 8) as u8,
            (cmd.count >> 8) as u8,
            l[3],
            l[4],
            l[5],
            0,
            0,
            0,
        ];
        b[OFF_PREV..OFF_PREV + 8].copy_from_slice(&prev);
    }
    b
}

/// Décode le tampon de sortie : registres (Error = [0], Status = [6]) et données reçues.
pub fn decode(out: &[u8], cmd: &AtaCmd) -> Result<AtaResult, AtaError> {
    if out.len() < APT_SIZE {
        return Err(AtaError::Invalid("tampon de sortie trop court".into()));
    }
    let cur = &out[OFF_CUR..OFF_CUR + 8];
    let prev = &out[OFF_PREV..OFF_PREV + 8];
    let (error, status) = (cur[0], cur[6]);
    let mut lba = cur[2] as u64 | (cur[3] as u64) << 8 | (cur[4] as u64) << 16;
    let mut count = cur[1] as u16;
    if cmd.ext {
        lba |= (prev[2] as u64) << 24 | (prev[3] as u64) << 32 | (prev[4] as u64) << 40;
        count |= (prev[1] as u16) << 8;
    } else {
        lba |= ((cur[5] & 0x0F) as u64) << 24;
    }
    // ERR (bit 0) ou DF « Device Fault » (bit 5) : échec.
    if status & (0x01 | 0x20) != 0 {
        return Err(AtaError::Device { status, error });
    }
    let data = match cmd.data {
        DataDir::In(n) => out
            .get(DATA_OFFSET..DATA_OFFSET + n)
            .ok_or_else(|| AtaError::Invalid("données manquantes".into()))?
            .to_vec(),
        _ => Vec::new(),
    };
    Ok(AtaResult {
        error,
        status,
        count,
        lba,
        device: cur[5],
        data,
    })
}

// ---------- Seconde voie : SCSI ATA PASS-THROUGH (16) (traduction SAT) ----------
//
// Réimplémenté d'après ntddscsi.h (SCSI_PASS_THROUGH, IOCTL_SCSI_PASS_THROUGH) et la norme
// T10 SAT (commande 85h, descripteur de sense « ATA Status Return » 09h, format fixe 00h/1Dh).
// Certains pilotes (Intel RST, certains pilotes AHCI) refusent IOCTL_ATA_PASS_THROUGH mais
// acceptent la commande SCSI 85h, que leur couche de traduction transmet au disque.

/// CTL_CODE(IOCTL_SCSI_BASE, 0x0401, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS).
pub const IOCTL_SCSI_PASS_THROUGH: u32 = winio::ctl_code(0x4, 0x0401, 0, 1 | 2);

/// Miroir de SCSI_PASS_THROUGH (ntddscsi.h, x64).
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ScsiPassThrough {
    pub length: u16,
    pub scsi_status: u8,
    pub path_id: u8,
    pub target_id: u8,
    pub lun: u8,
    pub cdb_length: u8,
    pub sense_info_length: u8,
    pub data_in: u8,
    pub data_transfer_length: u32,
    pub time_out_value: u32,
    pub data_buffer_offset: usize,
    pub sense_info_offset: u32,
    pub cdb: [u8; 16],
}

pub const SPT_SIZE: usize = size_of::<ScsiPassThrough>();
const SENSE_LEN: usize = 32;
const SPT_SENSE_OFFSET: usize = SPT_SIZE;
/// Données après le sense (multiple de 8).
pub const SPT_DATA_OFFSET: usize = SPT_SIZE + SENSE_LEN;
const SPT_OFF_STATUS: usize = offset_of!(ScsiPassThrough, scsi_status);
const SPT_OFF_CDBLEN: usize = offset_of!(ScsiPassThrough, cdb_length);
const SPT_OFF_SENSELEN: usize = offset_of!(ScsiPassThrough, sense_info_length);
const SPT_OFF_DATAIN: usize = offset_of!(ScsiPassThrough, data_in);
const SPT_OFF_DTL: usize = offset_of!(ScsiPassThrough, data_transfer_length);
const SPT_OFF_TIMEOUT: usize = offset_of!(ScsiPassThrough, time_out_value);
const SPT_OFF_DBO: usize = offset_of!(ScsiPassThrough, data_buffer_offset);
const SPT_OFF_SIO: usize = offset_of!(ScsiPassThrough, sense_info_offset);
const SPT_OFF_CDB: usize = offset_of!(ScsiPassThrough, cdb);

const SCSI_IOCTL_DATA_OUT: u8 = 0;
const SCSI_IOCTL_DATA_IN: u8 = 1;
const SCSI_IOCTL_DATA_UNSPECIFIED: u8 = 2;
const SAT_ATA_PASS_THROUGH_16: u8 = 0x85;
const SCSI_STATUS_GOOD: u8 = 0x00;
const SCSI_STATUS_CHECK_CONDITION: u8 = 0x02;
const SENSE_NO_SENSE: u8 = 0x0;
const SENSE_RECOVERED_ERROR: u8 = 0x1;
const SENSE_ILLEGAL_REQUEST: u8 = 0x5;

/// Commandes dont on DOIT lire les registres de sortie (adresse max, état Sanitize, seuil
/// SMART dépassé) : sans eux, le résultat est inexploitable.
fn needs_registers(c: &AtaCmd) -> bool {
    match c.command {
        CMD_READ_NATIVE_MAX_EXT | CMD_READ_NATIVE_MAX => true,
        CMD_SANITIZE => c.features == SAN_STATUS,
        CMD_SMART => c.features == SMART_RETURN_STATUS,
        _ => false,
    }
}

/// CDB ATA PASS-THROUGH (16). Transfert PIO compté en blocs de 512 octets dans le champ
/// COUNT (T_LENGTH = 2, BYTE_BLOCK = 1) ; CK_COND = 1 pour les commandes sans données afin
/// d'obtenir les registres de sortie.
pub fn sat_cdb(cmd: &AtaCmd) -> [u8; 16] {
    let n = data_len(cmd);
    let (protocol, byte2, count) = match &cmd.data {
        DataDir::None => (3u8, 1u8 << 5, cmd.count),
        DataDir::In(_) => (4, (1 << 3) | (1 << 2) | 2, sat_count(cmd, n)),
        DataDir::Out(_) => (5, (1 << 2) | 2, sat_count(cmd, n)),
    };
    let l = cmd.lba.to_le_bytes();
    let device = if cmd.ext {
        cmd.device
    } else {
        cmd.device | (l[3] & 0x0F)
    };
    let (f, c) = (cmd.features.to_be_bytes(), count.to_be_bytes());
    let (hi_lba_lo, hi_lba_mid, hi_lba_hi) = if cmd.ext {
        (l[3], l[4], l[5])
    } else {
        (0, 0, 0)
    };
    [
        SAT_ATA_PASS_THROUGH_16,
        (protocol << 1) | cmd.ext as u8,
        byte2,
        if cmd.ext { f[0] } else { 0 },
        f[1],
        if cmd.ext { c[0] } else { 0 },
        c[1],
        hi_lba_lo,
        l[0],
        hi_lba_mid,
        l[1],
        hi_lba_hi,
        l[2],
        device,
        cmd.command,
        0,
    ]
}

/// COUNT d'une commande avec données : nombre de blocs de 512 octets si la commande ne
/// l'utilise pas elle-même (IDENTIFY, SMART READ, SECURITY…).
fn sat_count(cmd: &AtaCmd, n: usize) -> u16 {
    if cmd.count == 0 {
        n.div_ceil(512) as u16
    } else {
        cmd.count
    }
}

/// Tampon d'entrée : SCSI_PASS_THROUGH, zone de sense, puis les données.
pub fn sat_encode(cmd: &AtaCmd) -> Vec<u8> {
    let n = data_len(cmd);
    let mut b = vec![0u8; SPT_DATA_OFFSET + n];
    put_u16(&mut b, 0, SPT_SIZE as u16);
    b[SPT_OFF_CDBLEN] = 16;
    b[SPT_OFF_SENSELEN] = SENSE_LEN as u8;
    b[SPT_OFF_DATAIN] = match &cmd.data {
        DataDir::None => SCSI_IOCTL_DATA_UNSPECIFIED,
        DataDir::In(_) => SCSI_IOCTL_DATA_IN,
        DataDir::Out(v) => {
            b[SPT_DATA_OFFSET..].copy_from_slice(v);
            SCSI_IOCTL_DATA_OUT
        }
    };
    put_u32(&mut b, SPT_OFF_DTL, n as u32);
    put_u32(&mut b, SPT_OFF_TIMEOUT, cmd.timeout_secs.max(1));
    put_u64(&mut b, SPT_OFF_DBO, SPT_DATA_OFFSET as u64);
    put_u32(&mut b, SPT_OFF_SIO, SPT_SENSE_OFFSET as u32);
    b[SPT_OFF_CDB..SPT_OFF_CDB + 16].copy_from_slice(&sat_cdb(cmd));
    b
}

/// Registres renvoyés dans le sense : (error, status, count, lba, device, complets ?).
/// « complets » = faux si la commande est 48 bits et que les octets hauts manquent.
type SatRegs = (u8, u8, u16, u64, u8, bool);

/// Sense : (clé, registres ATA s'ils sont présents).
fn parse_sense(sense: &[u8], cmd: &AtaCmd) -> Option<(u8, Option<SatRegs>)> {
    match sense.first()? & 0x7F {
        // Format descripteur : on cherche le descripteur ATA Status Return (09h).
        0x72 | 0x73 => {
            let key = sense.get(1)? & 0x0F;
            let end = (8 + *sense.get(7)? as usize).min(sense.len());
            let mut i = 8;
            while i + 2 <= end {
                let (kind, len) = (sense[i], sense[i + 1] as usize);
                if kind == 0x09 && len >= 12 && i + 14 <= sense.len() {
                    let d = &sense[i..i + 14];
                    let ext = d[2] & 1 != 0;
                    let mut count = d[5] as u16;
                    let mut lba = d[7] as u64 | (d[9] as u64) << 8 | (d[11] as u64) << 16;
                    if ext {
                        count |= (d[4] as u16) << 8;
                        lba |= (d[6] as u64) << 24 | (d[8] as u64) << 32 | (d[10] as u64) << 40;
                    } else if !cmd.ext {
                        lba |= ((d[12] & 0x0F) as u64) << 24;
                    }
                    return Some((key, Some((d[3], d[13], count, lba, d[12], ext || !cmd.ext))));
                }
                i += 2 + len;
            }
            Some((key, None))
        }
        // Format fixe : registres présents si ASC/ASCQ = 00h/1Dh (ATA PASS THROUGH
        // INFORMATION AVAILABLE).
        0x70 | 0x71 => {
            let key = sense.get(2)? & 0x0F;
            if sense.len() < 14 || (sense[12], sense[13]) != (0x00, 0x1D) {
                return Some((key, None));
            }
            let upper = sense[8] & 0x60 != 0;
            let mut lba = sense[9] as u64 | (sense[10] as u64) << 8 | (sense[11] as u64) << 16;
            if !cmd.ext {
                lba |= ((sense[5] & 0x0F) as u64) << 24;
            }
            let complete = !cmd.ext || !upper;
            Some((
                key,
                Some((sense[3], sense[4], sense[6] as u16, lba, sense[5], complete)),
            ))
        }
        _ => None,
    }
}

/// Résultat de la seconde voie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SatOutcome {
    /// La couche de traduction a traité la commande (succès ou erreur du disque).
    Done(Result<AtaResult, AtaError>),
    /// Refusée par le pilote ou sa couche SAT : la commande n'a pas atteint le disque.
    Refused,
}

/// Décode le tampon de sortie de la seconde voie (pur, testable).
pub fn sat_decode(out: &[u8], cmd: &AtaCmd) -> SatOutcome {
    use SatOutcome::*;
    if out.len() < SPT_DATA_OFFSET {
        return Done(Err(AtaError::Invalid("tampon SCSI trop court".into())));
    }
    let n = data_len(cmd);
    let data = || -> Result<Vec<u8>, AtaError> {
        if !matches!(cmd.data, DataDir::In(_)) {
            return Ok(Vec::new());
        }
        let got = u32::from_le_bytes(out[SPT_OFF_DTL..SPT_OFF_DTL + 4].try_into().unwrap());
        if (got as usize) < n {
            return Err(AtaError::Invalid(format!(
                "données incomplètes par la voie SCSI ({got}/{n} octets)"
            )));
        }
        out.get(SPT_DATA_OFFSET..SPT_DATA_OFFSET + n)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| AtaError::Invalid("données manquantes".into()))
    };
    let sense = &out[SPT_SENSE_OFFSET..SPT_SENSE_OFFSET + SENSE_LEN];
    match out[SPT_OFF_STATUS] {
        SCSI_STATUS_GOOD => {
            if needs_registers(cmd) {
                return Done(Err(AtaError::Invalid(
                    "registres de sortie non renvoyés par la voie SCSI".into(),
                )));
            }
            Done(data().map(|data| AtaResult {
                status: 0x50,
                data,
                ..AtaResult::default()
            }))
        }
        SCSI_STATUS_CHECK_CONDITION => match parse_sense(sense, cmd) {
            // La couche SAT refuse la commande 85h ou ses champs : rien n'a atteint le disque.
            Some((SENSE_ILLEGAL_REQUEST, None)) => Refused,
            Some((key, Some((error, status, count, lba, device, complete)))) => {
                let failed = status & (0x01 | 0x20) != 0
                    || !matches!(key, SENSE_NO_SENSE | SENSE_RECOVERED_ERROR);
                if failed {
                    // Erreur signalée sans bit ERR : on la force (jamais de faux succès).
                    let status = if status & 0x21 == 0 {
                        status | 0x01
                    } else {
                        status
                    };
                    let error = if error == 0 { 0x04 } else { error };
                    return Done(Err(AtaError::Device { status, error }));
                }
                if needs_registers(cmd) && !complete {
                    return Done(Err(AtaError::Invalid(
                        "registres 48 bits incomplets par la voie SCSI".into(),
                    )));
                }
                Done(data().map(|data| AtaResult {
                    error,
                    status,
                    count,
                    lba,
                    device,
                    data,
                }))
            }
            Some((key, None)) => Done(Err(AtaError::Invalid(format!(
                "voie SCSI : sense {key:#04X} sans registres ATA"
            )))),
            None => Done(Err(AtaError::Invalid("voie SCSI : sense illisible".into()))),
        },
        s => Done(Err(AtaError::Invalid(format!(
            "voie SCSI : état SCSI {s:#04X}"
        )))),
    }
}

fn exec_apt(h: &Handle, cmd: &AtaCmd) -> Result<AtaResult, AtaError> {
    let input = encode(cmd);
    let mut out = AlignedBuf::new(input.len());
    winio::ioctl(h, IOCTL_ATA_PASS_THROUGH, &input, out.as_mut_slice())
        .map_err(AtaError::Windows)?;
    decode(out.as_slice(), cmd)
}

fn exec_sat(h: &Handle, cmd: &AtaCmd) -> SatOutcome {
    let input = sat_encode(cmd);
    let mut out = AlignedBuf::new(input.len());
    match winio::ioctl(h, IOCTL_SCSI_PASS_THROUGH, &input, out.as_mut_slice()) {
        Ok(_) => sat_decode(out.as_slice(), cmd),
        Err(c) if TRANSPORT_REFUSALS.contains(&c) => SatOutcome::Refused,
        Err(c) => SatOutcome::Done(Err(AtaError::Windows(c))),
    }
}

/// Choix entre les deux voies à partir de leurs résultats (pur, testable) : la seconde
/// n'est tentée que si la première a été refusée avant le disque ; si elle est refusée
/// aussi, l'erreur d'origine est conservée.
pub fn combine(
    first: Result<AtaResult, AtaError>,
    second: impl FnOnce() -> SatOutcome,
) -> Result<AtaResult, AtaError> {
    match first {
        Err(e) if e.transport_refusal().is_some() => match second() {
            SatOutcome::Done(r) => r,
            SatOutcome::Refused => Err(e),
        },
        r => r,
    }
}

/// Envoie la commande sur la poignée : IOCTL_ATA_PASS_THROUGH, puis la commande SCSI 85h si
/// le pilote a refusé la première voie. N'EST PAS filtré : réservé à `ReadOnlyAta`
/// (qui filtre) et à `RawDisk` (autorisation armée).
pub(crate) fn exec_on_handle(h: &Handle, cmd: &AtaCmd) -> Result<AtaResult, AtaError> {
    combine(exec_apt(h, cmd), || exec_sat(h, cmd))
}

/// Commandes autorisées en lecture seule : IDENTIFY, SMART (lecture/état), READ NATIVE MAX,
/// DCO IDENTIFY, SANITIZE STATUS EXT (sans le bit CLEAR). Tout le reste est refusé.
pub fn is_read_only(c: &AtaCmd) -> bool {
    if matches!(c.data, DataDir::Out(_)) {
        return false;
    }
    match c.command {
        CMD_IDENTIFY => true,
        CMD_SMART => matches!(
            c.features,
            SMART_READ_DATA | SMART_READ_THRESHOLDS | SMART_RETURN_STATUS
        ),
        CMD_READ_NATIVE_MAX_EXT | CMD_READ_NATIVE_MAX => matches!(c.data, DataDir::None),
        CMD_DCO => c.features == DCO_IDENTIFY,
        CMD_SANITIZE => c.features == SAN_STATUS && c.count & 1 == 0,
        _ => false,
    }
}

/// Accès en LECTURE SEULE pour --info et le dry-run. IOCTL_ATA_PASS_THROUGH exige une poignée
/// ouverte en lecture+écriture ; c'est le filtre `is_read_only` qui garantit qu'aucune
/// commande destructive ne part par ici.
pub struct ReadOnlyAta {
    h: Handle,
}

impl ReadOnlyAta {
    pub fn open(number: u32) -> Result<ReadOnlyAta, String> {
        let path = format!(r"\\.\PhysicalDrive{number}");
        Handle::open(&path, winio::GENERIC_READ | winio::GENERIC_WRITE)
            .map(|h| ReadOnlyAta { h })
            .map_err(|e| format!("ouverture de {path} impossible ({})", AtaError::Windows(e)))
    }
}

impl AtaPort for ReadOnlyAta {
    fn exec(&mut self, cmd: &AtaCmd) -> Result<AtaResult, AtaError> {
        if !is_read_only(cmd) {
            return Err(AtaError::ReadOnly);
        }
        exec_on_handle(&self.h, cmd)
    }
}

// ---------- Fabrication des commandes ----------

pub fn identify() -> AtaCmd {
    AtaCmd {
        data: DataDir::In(512),
        ..AtaCmd::new(CMD_IDENTIFY)
    }
}

fn smart(feature: u16, data: bool) -> AtaCmd {
    AtaCmd {
        features: feature,
        lba: SMART_LBA,
        device: DEV_LBA,
        data: if data {
            DataDir::In(512)
        } else {
            DataDir::None
        },
        ..AtaCmd::new(CMD_SMART)
    }
}
pub fn smart_read_data() -> AtaCmd {
    smart(SMART_READ_DATA, true)
}
pub fn smart_read_thresholds() -> AtaCmd {
    smart(SMART_READ_THRESHOLDS, true)
}
pub fn smart_return_status() -> AtaCmd {
    smart(SMART_RETURN_STATUS, false)
}

pub fn read_native_max_ext() -> AtaCmd {
    AtaCmd {
        device: DEV_LBA,
        ext: true,
        ..AtaCmd::new(CMD_READ_NATIVE_MAX_EXT)
    }
}
pub fn read_native_max() -> AtaCmd {
    AtaCmd {
        device: DEV_LBA,
        ..AtaCmd::new(CMD_READ_NATIVE_MAX)
    }
}

pub fn dco_identify() -> AtaCmd {
    AtaCmd {
        features: DCO_IDENTIFY,
        data: DataDir::In(512),
        ..AtaCmd::new(CMD_DCO)
    }
}

/// Bloc de 512 octets des commandes SECURITY : mot 0 (bit 0 = mot de passe maître,
/// bit 1 = effacement amélioré pour ERASE UNIT, bit 8 = niveau maximum pour SET PASSWORD),
/// mots 1 à 16 = mot de passe (32 octets, complété par des zéros, dans l'ordre des caractères).
pub fn password_block(enhanced: bool, pw: &str) -> Vec<u8> {
    let mut b = vec![0u8; 512];
    let mut w0: u16 = 0; // bit 0 = 0 : mot de passe UTILISATEUR ; bit 8 = 0 : niveau « High »
    if enhanced {
        w0 |= 1 << 1;
    }
    b[0..2].copy_from_slice(&w0.to_le_bytes());
    let p = pw.as_bytes();
    let n = p.len().min(32);
    b[2..2 + n].copy_from_slice(&p[..n]);
    b
}

fn sec_out(command: u8, block: Vec<u8>, timeout_secs: u32) -> AtaCmd {
    AtaCmd {
        data: DataDir::Out(block),
        timeout_secs,
        ..AtaCmd::new(command)
    }
}
pub fn security_set_password(pw: &str) -> AtaCmd {
    sec_out(CMD_SEC_SET_PASSWORD, password_block(false, pw), 30)
}
pub fn security_unlock(pw: &str) -> AtaCmd {
    sec_out(CMD_SEC_UNLOCK, password_block(false, pw), 30)
}
pub fn security_erase_prepare() -> AtaCmd {
    AtaCmd::new(CMD_SEC_ERASE_PREPARE)
}
pub fn security_erase_unit(pw: &str, enhanced: bool, timeout_secs: u32) -> AtaCmd {
    sec_out(
        CMD_SEC_ERASE_UNIT,
        password_block(enhanced, pw),
        timeout_secs,
    )
}
pub fn security_disable_password(pw: &str) -> AtaCmd {
    sec_out(CMD_SEC_DISABLE_PASSWORD, password_block(false, pw), 30)
}

fn sanitize(feature: u16, count: u16, lba: u64) -> AtaCmd {
    AtaCmd {
        features: feature,
        count,
        lba,
        device: DEV_LBA,
        ext: true,
        ..AtaCmd::new(CMD_SANITIZE)
    }
}
pub fn sanitize_crypto_scramble() -> AtaCmd {
    sanitize(SAN_CRYPTO_SCRAMBLE, SAN_FAILURE_MODE, KEY_CRYPTO)
}
pub fn sanitize_block_erase() -> AtaCmd {
    sanitize(SAN_BLOCK_ERASE, SAN_FAILURE_MODE, KEY_BLOCK)
}
/// `passes` de 1 à 16 (16 codé 0), motif 32 bits, sans inversion.
pub fn sanitize_overwrite(pattern: u32, passes: u8) -> AtaCmd {
    let n = (passes.clamp(1, 16) & 0x0F) as u16;
    sanitize(
        SAN_OVERWRITE,
        n | SAN_FAILURE_MODE,
        KEY_OVERWRITE | pattern as u64,
    )
}
pub fn sanitize_status() -> AtaCmd {
    sanitize(SAN_STATUS, 0, 0)
}

// ---------- IDENTIFY DEVICE (décodage pur) ----------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SecurityState {
    pub supported: bool,
    pub enabled: bool,
    pub locked: bool,
    pub frozen: bool,
    pub count_expired: bool,
    pub enhanced_supported: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SanitizeCaps {
    pub supported: bool,
    pub crypto: bool,
    pub block: bool,
    pub overwrite: bool,
    pub antifreeze: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    NotReported,
    /// Mot 217 = 1 : support sans rotation (SSD).
    NonRotating,
    Rpm(u16),
    Reserved(u16),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EraseTime {
    NotReported,
    Minutes(u32),
    /// Durée annoncée « supérieure à » (valeur maximale du champ).
    MoreThan(u32),
}

impl EraseTime {
    pub fn minutes(&self) -> Option<u32> {
        match self {
            EraseTime::NotReported => None,
            EraseTime::Minutes(m) | EraseTime::MoreThan(m) => Some(*m),
        }
    }
    pub fn label(&self) -> String {
        match self {
            EraseTime::NotReported => "non annoncée".into(),
            EraseTime::Minutes(m) => format!("{m} min"),
            EraseTime::MoreThan(m) => format!("> {m} min"),
        }
    }
}

/// Mots 89/90 (ACS-3) : bit 15 = 1 → format étendu, bits 14:0 en unités de 2 min ;
/// bit 15 = 0 → bits 7:0 en unités de 2 min, 255 = plus de 508 min ; 0 = non annoncé.
pub fn decode_erase_time(w: u16) -> EraseTime {
    if w & 0x8000 != 0 {
        match w & 0x7FFF {
            0 => EraseTime::NotReported,
            0x7FFF => EraseTime::MoreThan(0x7FFE * 2),
            v => EraseTime::Minutes(v as u32 * 2),
        }
    } else {
        match w & 0xFF {
            0 => EraseTime::NotReported,
            255 => EraseTime::MoreThan(508),
            v => EraseTime::Minutes(v as u32 * 2),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identify {
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub lba48: bool,
    /// Nombre de secteurs adressables par l'hôte (mots 100-103, sinon 60-61).
    pub sectors: u64,
    pub logical_sector: u32,
    pub rotation: Rotation,
    /// Mot 169 bit 0 : DATA SET MANAGEMENT (TRIM).
    pub trim: bool,
    /// Mot 69 bit 14 / bit 5 : lecture déterministe / zéros après TRIM.
    pub drat: bool,
    pub rzat: bool,
    pub security: SecurityState,
    pub erase_normal: EraseTime,
    pub erase_enhanced: EraseTime,
    pub sanitize: SanitizeCaps,
    pub smart_supported: bool,
    pub smart_enabled: bool,
    pub hpa_supported: bool,
    pub dco_supported: bool,
}

pub fn word(d: &[u8], i: usize) -> u16 {
    d.get(2 * i..2 * i + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

/// Chaîne ATA : dans chaque mot, l'octet de poids fort est le premier caractère.
pub fn ata_string(d: &[u8], first: usize, words: usize) -> String {
    let mut s = Vec::with_capacity(words * 2);
    for i in first..first + words {
        let w = word(d, i);
        s.push((w >> 8) as u8);
        s.push(w as u8);
    }
    String::from_utf8_lossy(&s)
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string()
}

/// Mot 255 : si l'octet bas vaut A5h, la somme des 512 octets doit être nulle (mod 256).
pub fn checksum_ok(d: &[u8]) -> bool {
    if d.len() < 512 || d[510] != 0xA5 {
        return true;
    }
    d[..512].iter().fold(0u8, |a, &b| a.wrapping_add(b)) == 0
}

/// Mot « valide » des groupes 83/84/87/106 : bit 14 = 1 et bit 15 = 0.
fn valid(w: u16) -> bool {
    w & 0xC000 == 0x4000
}

pub fn decode_identify(d: &[u8]) -> Result<Identify, String> {
    if d.len() < 512 {
        return Err(format!(
            "IDENTIFY : {} octets reçus au lieu de 512",
            d.len()
        ));
    }
    if d[..512].iter().all(|&b| b == 0) || word(d, 0) == 0xFFFF {
        return Err("IDENTIFY : données vides".into());
    }
    if !checksum_ok(d) {
        return Err("IDENTIFY : somme de contrôle (mot 255) incorrecte".into());
    }
    let w = |i| word(d, i);
    let w83_ok = valid(w(83));
    let lba48 = w83_ok && w(83) & (1 << 10) != 0;
    let s48 = w(100) as u64 | (w(101) as u64) << 16 | (w(102) as u64) << 32 | (w(103) as u64) << 48;
    let s28 = w(60) as u64 | (w(61) as u64) << 16;
    let sectors = if lba48 && s48 > 0 { s48 } else { s28 };
    let w106 = w(106);
    let logical_sector = if valid(w106) && w106 & (1 << 12) != 0 {
        let words = w(117) as u32 | (w(118) as u32) << 16;
        (words * 2).max(512)
    } else {
        512
    };
    let rotation = match w(217) {
        0 => Rotation::NotReported,
        1 => Rotation::NonRotating,
        v @ 0x0401..=0xFFFE => Rotation::Rpm(v),
        v => Rotation::Reserved(v),
    };
    let w128 = w(128);
    let security = SecurityState {
        supported: w128 & 1 != 0,
        enabled: w128 & (1 << 1) != 0,
        locked: w128 & (1 << 2) != 0,
        frozen: w128 & (1 << 3) != 0,
        count_expired: w128 & (1 << 4) != 0,
        enhanced_supported: w128 & (1 << 5) != 0,
    };
    let w59 = w(59);
    let sanitize = SanitizeCaps {
        supported: w59 & (1 << 12) != 0,
        crypto: w59 & (1 << 13) != 0,
        overwrite: w59 & (1 << 14) != 0,
        block: w59 & (1 << 15) != 0,
        antifreeze: w59 & (1 << 10) != 0,
    };
    let w82 = w(82);
    let w82_ok = w82 != 0xFFFF;
    let w85 = w(85);
    Ok(Identify {
        serial: ata_string(d, 10, 10),
        firmware: ata_string(d, 23, 4),
        model: ata_string(d, 27, 20),
        lba48,
        sectors,
        logical_sector,
        rotation,
        trim: w(169) & 1 != 0,
        drat: w(69) & (1 << 14) != 0,
        rzat: w(69) & (1 << 5) != 0,
        security,
        erase_normal: decode_erase_time(w(89)),
        erase_enhanced: decode_erase_time(w(90)),
        sanitize,
        smart_supported: w82_ok && w82 & 1 != 0,
        smart_enabled: w85 != 0xFFFF && w85 & 1 != 0,
        hpa_supported: w82_ok && w82 & (1 << 10) != 0,
        dco_supported: w83_ok && w(83) & (1 << 11) != 0,
    })
}

// ---------- Lectures de haut niveau ----------

pub fn read_identify(p: &mut dyn AtaPort) -> Result<Identify, String> {
    let r = p
        .exec(&identify())
        .map_err(|e| format!("IDENTIFY DEVICE : {e}"))?;
    decode_identify(&r.data)
}

/// Adresse native maximale (dernier LBA, HPA comprise).
pub fn read_native_max_lba(p: &mut dyn AtaPort, lba48: bool) -> Result<u64, String> {
    let c = if lba48 {
        read_native_max_ext()
    } else {
        read_native_max()
    };
    p.exec(&c)
        .map(|r| r.lba)
        .map_err(|e| format!("{} : {e}", c.name()))
}

/// Dernier LBA selon DEVICE CONFIGURATION IDENTIFY (mots 3 à 6, DCO).
pub fn read_dco_max_lba(p: &mut dyn AtaPort) -> Result<u64, String> {
    let r = p
        .exec(&dco_identify())
        .map_err(|e| format!("DEVICE CONFIGURATION IDENTIFY : {e}"))?;
    decode_dco_max(&r.data)
}

pub fn decode_dco_max(d: &[u8]) -> Result<u64, String> {
    if d.len() < 512 || !checksum_ok(d) {
        return Err("DEVICE CONFIGURATION IDENTIFY : données invalides".into());
    }
    let max = (word(d, 3) as u64)
        | (word(d, 4) as u64) << 16
        | (word(d, 5) as u64) << 32
        | (word(d, 6) as u64) << 48;
    if max == 0 {
        return Err("DEVICE CONFIGURATION IDENTIFY : LBA maximal nul".into());
    }
    Ok(max & 0xFFFF_FFFF_FFFF)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmartHealth {
    Passed,
    /// Un seuil est dépassé (LBA mid/high = F4h/2Ch).
    Failed,
    Unknown,
}

pub fn decode_smart_status(r: &AtaResult) -> SmartHealth {
    match ((r.lba >> 8) as u8, (r.lba >> 16) as u8) {
        (0x4F, 0xC2) => SmartHealth::Passed,
        (0xF4, 0x2C) => SmartHealth::Failed,
        _ => SmartHealth::Unknown,
    }
}

pub fn read_smart_health(p: &mut dyn AtaPort) -> Result<SmartHealth, String> {
    p.exec(&smart_return_status())
        .map(|r| decode_smart_status(&r))
        .map_err(|e| format!("SMART RETURN STATUS : {e}"))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SanitizeStatus {
    /// Count bit 15 : dernière opération terminée sans erreur.
    pub completed_ok: bool,
    /// Count bit 14 : opération en cours.
    pub in_progress: bool,
    /// Count bit 13 : Sanitize Freeze Lock actif.
    pub frozen: bool,
    pub antifreeze: bool,
    /// LBA 15:0 : progression sur 65536.
    pub progress: u16,
}

impl SanitizeStatus {
    pub fn percent(&self) -> f64 {
        self.progress as f64 / 65536.0 * 100.0
    }
}

pub fn decode_sanitize_status(r: &AtaResult) -> SanitizeStatus {
    SanitizeStatus {
        completed_ok: r.count & (1 << 15) != 0,
        in_progress: r.count & (1 << 14) != 0,
        frozen: r.count & (1 << 13) != 0,
        antifreeze: r.count & (1 << 12) != 0,
        progress: r.lba as u16,
    }
}

pub fn read_sanitize_status(p: &mut dyn AtaPort) -> Result<SanitizeStatus, AtaError> {
    p.exec(&sanitize_status())
        .map(|r| decode_sanitize_status(&r))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Écrit une chaîne ATA (octet fort = premier caractère) dans les mots [first, first+words).
    pub fn put_string(d: &mut [u8], first: usize, words: usize, s: &str) {
        let mut bytes = s.as_bytes().to_vec();
        bytes.resize(words * 2, b' ');
        for i in 0..words {
            d[2 * (first + i)] = bytes[2 * i + 1];
            d[2 * (first + i) + 1] = bytes[2 * i];
        }
    }

    pub fn put_word(d: &mut [u8], i: usize, v: u16) {
        d[2 * i..2 * i + 2].copy_from_slice(&v.to_le_bytes());
    }

    /// Met à jour la somme de contrôle du mot 255.
    pub fn seal(d: &mut [u8]) {
        d[510] = 0xA5;
        let s = d[..511].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        d[511] = 0u8.wrapping_sub(s);
    }

    /// IDENTIFY fabriqué : SSD SATA de 500 Go, sanitize crypto+block, sécurité supportée.
    pub fn sample_identify() -> Vec<u8> {
        let mut d = vec![0u8; 512];
        put_word(&mut d, 0, 0x0040);
        put_string(&mut d, 10, 10, "S3Z9NB0K123456X");
        put_string(&mut d, 23, 4, "RVT04B6Q");
        put_string(&mut d, 27, 20, "Samsung SSD 860 EVO 500GB");
        put_word(&mut d, 59, (1 << 12) | (1 << 13) | (1 << 15));
        put_word(&mut d, 60, 0xFFFF);
        put_word(&mut d, 61, 0x0FFF);
        put_word(&mut d, 69, (1 << 14) | (1 << 5));
        put_word(&mut d, 82, (1 << 0) | (1 << 1) | (1 << 10));
        put_word(&mut d, 83, 0x4000 | (1 << 10) | (1 << 11));
        put_word(&mut d, 85, 1);
        put_word(&mut d, 89, 1); // 2 min
        put_word(&mut d, 90, 0x8000 | 30); // étendu : 60 min
        let sectors: u64 = 976_773_168;
        for k in 0..4 {
            put_word(&mut d, 100 + k, (sectors >> (16 * k)) as u16);
        }
        put_word(&mut d, 128, (1 << 0) | (1 << 3) | (1 << 5)); // supporté, gelé, amélioré
        put_word(&mut d, 169, 1);
        put_word(&mut d, 217, 1);
        seal(&mut d);
        d
    }

    #[test]
    fn ioctl_code_matches_header() {
        // CTL_CODE(4, 0x40b, 0, 3)
        assert_eq!(IOCTL_ATA_PASS_THROUGH, 0x0004_D02C);
    }

    #[test]
    fn ata_pass_through_ex_layout_matches_ntddscsi_h() {
        assert_eq!(APT_SIZE, 48);
        assert_eq!(OFF_LEN, 0);
        assert_eq!(OFF_FLAGS, 2);
        assert_eq!(offset_of!(AtaPassThroughEx, path_id), 4);
        assert_eq!(offset_of!(AtaPassThroughEx, reserved_as_uchar), 7);
        assert_eq!(OFF_DTL, 8);
        assert_eq!(OFF_TIMEOUT, 12);
        assert_eq!(offset_of!(AtaPassThroughEx, reserved_as_ulong), 16);
        assert_eq!(OFF_DBO, 24); // ULONG_PTR aligné sur 8
        assert_eq!(OFF_PREV, 32);
        assert_eq!(OFF_CUR, 40);
        assert_eq!(DATA_OFFSET % 8, 0);
    }

    #[test]
    fn encodes_identify() {
        let b = encode(&identify());
        assert_eq!(b.len(), 48 + 512);
        assert_eq!(u16::from_le_bytes([b[0], b[1]]), 48);
        let flags = u16::from_le_bytes([b[2], b[3]]);
        assert_eq!(flags, ATA_FLAGS_DRDY_REQUIRED | ATA_FLAGS_DATA_IN);
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 512);
        assert_eq!(u64::from_le_bytes(b[24..32].try_into().unwrap()), 48);
        assert_eq!(b[40 + 6], 0xEC);
    }

    #[test]
    fn encodes_48bit_sanitize_with_key() {
        let b = encode(&sanitize_crypto_scramble());
        let flags = u16::from_le_bytes([b[2], b[3]]);
        assert_ne!(flags & ATA_FLAGS_48BIT_COMMAND, 0);
        assert_eq!(flags & (ATA_FLAGS_DATA_IN | ATA_FLAGS_DATA_OUT), 0);
        let cur = &b[40..48];
        let prev = &b[32..40];
        assert_eq!(cur[0], 0x11); // feature 7:0
        assert_eq!(cur[1], 0x10); // FAILURE MODE
        assert_eq!(&cur[2..5], &[0x70, 0x79, 0x72]); // « Cryp » en LBA 23:0
        assert_eq!(prev[2], 0x43); // LBA 31:24
        assert_eq!(cur[6], 0xB4);
        let ow = encode(&sanitize_overwrite(0xDEAD_BEEF, 1));
        assert_eq!(ow[32 + 3], 0x57); // LBA 39:32 = 57h
        assert_eq!(ow[32 + 4], 0x4F); // LBA 47:40 = 4Fh
        assert_eq!(ow[40 + 1], 0x11); // 1 passe + FAILURE MODE
        assert_eq!(&ow[42..45], &[0xEF, 0xBE, 0xAD]);
    }

    #[test]
    fn encodes_data_out_password() {
        let b = encode(&security_erase_unit(PASSWORD, true, 7200));
        let flags = u16::from_le_bytes([b[2], b[3]]);
        assert_ne!(flags & ATA_FLAGS_DATA_OUT, 0);
        assert_eq!(u32::from_le_bytes(b[12..16].try_into().unwrap()), 7200);
        assert_eq!(b[48], 0x02); // mode amélioré, mot de passe utilisateur
        assert_eq!(&b[50..59], b"DiskErase");
        assert!(b[59..82].iter().all(|&x| x == 0));
    }

    #[test]
    fn decodes_registers_and_errors() {
        let cmd = read_native_max_ext();
        let mut out = vec![0u8; 48];
        out[40 + 2] = 0xAF;
        out[40 + 3] = 0x02;
        out[40 + 4] = 0x30;
        out[32 + 2] = 0x3A;
        out[40 + 6] = 0x50;
        let r = decode(&out, &cmd).unwrap();
        assert_eq!(r.lba, 0x3A_3002AF);
        out[40 + 6] = 0x51;
        out[40] = 0x04;
        assert_eq!(
            decode(&out, &cmd).unwrap_err(),
            AtaError::Device {
                status: 0x51,
                error: 0x04
            }
        );
        // DF (Device Fault, bit 5) sans ERR : échec aussi.
        out[40 + 6] = 0x70;
        out[40] = 0;
        assert_eq!(
            decode(&out, &cmd).unwrap_err(),
            AtaError::Device {
                status: 0x70,
                error: 0
            }
        );
        assert_eq!(encode(&smart_return_status())[40 + 5], 0x40);
        assert!(AtaError::Device {
            status: 0x51,
            error: 4
        }
        .to_string()
        .contains("ABRT"));
    }

    #[test]
    fn read_only_filter_lets_only_reads_through() {
        for c in [
            identify(),
            smart_read_data(),
            smart_read_thresholds(),
            smart_return_status(),
            read_native_max_ext(),
            read_native_max(),
            dco_identify(),
            sanitize_status(),
        ] {
            assert!(is_read_only(&c), "{}", c.name());
        }
        for c in [
            security_set_password(PASSWORD),
            security_unlock(PASSWORD),
            security_erase_prepare(),
            security_erase_unit(PASSWORD, false, 60),
            security_disable_password(PASSWORD),
            sanitize_crypto_scramble(),
            sanitize_block_erase(),
            sanitize_overwrite(0, 1),
        ] {
            assert!(!is_read_only(&c), "{}", c.name());
        }
        // SANITIZE STATUS avec le bit CLEAR, DCO SET (C3h), SMART autre que lecture : refusés.
        let mut c = sanitize_status();
        c.count = 1;
        assert!(!is_read_only(&c));
        let mut c = dco_identify();
        c.features = 0xC3;
        assert!(!is_read_only(&c));
        let mut c = smart_read_data();
        c.features = 0xD6; // SMART WRITE LOG
        assert!(!is_read_only(&c));
        // SET MAX ADDRESS (F9h), TRIM (06h) : refusés.
        assert!(!is_read_only(&AtaCmd::new(0xF9)));
        assert!(!is_read_only(&AtaCmd::new(0x06)));
    }

    #[test]
    fn decodes_identify_fields() {
        let id = decode_identify(&sample_identify()).unwrap();
        assert_eq!(id.model, "Samsung SSD 860 EVO 500GB");
        assert_eq!(id.serial, "S3Z9NB0K123456X");
        assert_eq!(id.firmware, "RVT04B6Q");
        assert!(id.lba48);
        assert_eq!(id.sectors, 976_773_168);
        assert_eq!(id.logical_sector, 512);
        assert_eq!(id.rotation, Rotation::NonRotating);
        assert!(id.trim && id.drat && id.rzat);
        assert_eq!(
            id.security,
            SecurityState {
                supported: true,
                enabled: false,
                locked: false,
                frozen: true,
                count_expired: false,
                enhanced_supported: true
            }
        );
        assert_eq!(id.erase_normal, EraseTime::Minutes(2));
        assert_eq!(id.erase_enhanced, EraseTime::Minutes(60));
        assert_eq!(
            id.sanitize,
            SanitizeCaps {
                supported: true,
                crypto: true,
                block: true,
                overwrite: false,
                antifreeze: false
            }
        );
        assert!(id.smart_supported && id.smart_enabled);
        assert!(id.hpa_supported && id.dco_supported);
    }

    #[test]
    fn identify_rotation_hdd_and_28bit_fallback() {
        let mut d = sample_identify();
        put_word(&mut d, 217, 7200);
        put_word(&mut d, 83, 0x4000); // pas de 48 bits
        seal(&mut d);
        let id = decode_identify(&d).unwrap();
        assert_eq!(id.rotation, Rotation::Rpm(7200));
        assert!(!id.lba48);
        assert_eq!(id.sectors, 0x0FFF_FFFF);
        put_word(&mut d, 217, 0);
        seal(&mut d);
        assert_eq!(decode_identify(&d).unwrap().rotation, Rotation::NotReported);
    }

    #[test]
    fn identify_checksum_and_empty_are_rejected() {
        let mut d = sample_identify();
        d[100] ^= 1;
        assert!(decode_identify(&d).unwrap_err().contains("somme"));
        assert!(decode_identify(&[0u8; 512]).is_err());
        assert!(decode_identify(&[0u8; 100]).is_err());
        // Sans signature A5h, pas de contrôle.
        let mut d = sample_identify();
        d[510] = 0;
        d[100] ^= 1;
        assert!(decode_identify(&d).is_ok());
    }

    #[test]
    fn security_bits_each_decoded() {
        for (bit, check) in [
            (
                1,
                (|s: SecurityState| s.enabled) as fn(SecurityState) -> bool,
            ),
            (2, |s| s.locked),
            (3, |s| s.frozen),
            (4, |s| s.count_expired),
            (5, |s| s.enhanced_supported),
        ] {
            let mut d = sample_identify();
            put_word(&mut d, 128, 1 | (1 << bit));
            seal(&mut d);
            let s = decode_identify(&d).unwrap().security;
            assert!(check(s), "bit {bit}");
            assert_eq!(
                [
                    s.enabled,
                    s.locked,
                    s.frozen,
                    s.count_expired,
                    s.enhanced_supported
                ]
                .iter()
                .filter(|&&b| b)
                .count(),
                1
            );
        }
    }

    #[test]
    fn erase_time_formats() {
        assert_eq!(decode_erase_time(0), EraseTime::NotReported);
        assert_eq!(decode_erase_time(60), EraseTime::Minutes(120));
        assert_eq!(decode_erase_time(255), EraseTime::MoreThan(508));
        assert_eq!(decode_erase_time(0x8000 | 300), EraseTime::Minutes(600));
        assert_eq!(decode_erase_time(0x8000), EraseTime::NotReported);
        assert_eq!(EraseTime::Minutes(4).minutes(), Some(4));
    }

    #[test]
    fn logical_sector_size_from_words_117_118() {
        let mut d = sample_identify();
        put_word(&mut d, 106, 0x4000 | (1 << 12));
        put_word(&mut d, 117, 2048); // 2048 mots = 4096 octets
        seal(&mut d);
        assert_eq!(decode_identify(&d).unwrap().logical_sector, 4096);
    }

    #[test]
    fn smart_status_and_sanitize_status_decoding() {
        let r = AtaResult {
            lba: SMART_LBA,
            ..Default::default()
        };
        assert_eq!(decode_smart_status(&r), SmartHealth::Passed);
        let r = AtaResult {
            lba: (0x2C << 16) | (0xF4 << 8),
            ..Default::default()
        };
        assert_eq!(decode_smart_status(&r), SmartHealth::Failed);
        assert_eq!(
            decode_smart_status(&AtaResult::default()),
            SmartHealth::Unknown
        );
        let s = decode_sanitize_status(&AtaResult {
            count: (1 << 14) | (1 << 13),
            lba: 0x8000,
            ..Default::default()
        });
        assert!(s.in_progress && s.frozen && !s.completed_ok);
        assert!((s.percent() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn dco_max_is_words_3_to_6() {
        let mut d = vec![0u8; 512];
        put_word(&mut d, 0, 2);
        put_word(&mut d, 3, 0x2FAF);
        put_word(&mut d, 4, 0x3A38);
        seal(&mut d);
        assert_eq!(decode_dco_max(&d).unwrap(), 0x3A38_2FAF);
        assert!(decode_dco_max(&[0u8; 512]).is_err());
    }

    #[test]
    fn password_block_layout() {
        let b = password_block(false, PASSWORD);
        assert_eq!(b.len(), 512);
        assert_eq!(&b[0..2], &[0, 0]);
        assert_eq!(&b[2..11], b"DiskErase");
    }

    // ---------- Seconde voie SAT ----------

    #[test]
    fn spt_layout_matches_ntddscsi_x64() {
        assert_eq!(SPT_SIZE, 56);
        assert_eq!(SPT_OFF_DTL, 12);
        assert_eq!(SPT_OFF_DBO, 24);
        assert_eq!(SPT_OFF_SIO, 32);
        assert_eq!(SPT_OFF_CDB, 36);
        assert_eq!(SPT_DATA_OFFSET % 8, 0);
        assert_eq!(IOCTL_SCSI_PASS_THROUGH, 0x0004_D004);
    }

    #[test]
    fn sat_cdb_identify_pio_in_one_block() {
        let c = sat_cdb(&identify());
        assert_eq!(c[0], 0x85);
        assert_eq!(c[1], 4 << 1); // PIO Data-In, 28 bits
        assert_eq!(c[2], 0x0E); // T_DIR | BYTE_BLOCK | T_LENGTH=2, pas de CK_COND
        assert_eq!(c[6], 1); // 1 bloc de 512
        assert_eq!(c[14], CMD_IDENTIFY);
    }

    #[test]
    fn sat_cdb_sanitize_block_erase_48bit() {
        let c = sat_cdb(&sanitize_block_erase());
        assert_eq!(c[1], (3 << 1) | 1); // non-data, EXTEND
        assert_eq!(c[2], 0x20); // CK_COND
        assert_eq!((c[3], c[4]), (0x00, 0x12));
        assert_eq!((c[5], c[6]), (0x00, 0x10)); // FAILURE MODE
                                                // Clé 0x426B4572 : LBA 47:0 = 00 00 42 6B 45 72
        assert_eq!([c[8], c[10], c[12]], [0x72, 0x45, 0x6B]);
        assert_eq!([c[7], c[9], c[11]], [0x42, 0x00, 0x00]);
        assert_eq!(c[13], DEV_LBA);
        assert_eq!(c[14], CMD_SANITIZE);
    }

    #[test]
    fn sat_cdb_security_out_and_smart_28bit() {
        let c = sat_cdb(&security_set_password("x"));
        assert_eq!(c[1], 5 << 1);
        assert_eq!(c[2], 0x06); // T_DIR = 0 (sortie)
        assert_eq!(c[6], 1);
        let s = sat_cdb(&smart_return_status());
        assert_eq!(s[2], 0x20);
        assert_eq!((s[10], s[12]), (0x4F, 0xC2));
        assert_eq!(s[4], 0xDA);
        let e = sat_encode(&security_set_password("x"));
        assert_eq!(e.len(), SPT_DATA_OFFSET + 512);
        assert_eq!(e[SPT_OFF_DATAIN], SCSI_IOCTL_DATA_OUT);
        assert_eq!(&e[SPT_DATA_OFFSET + 2..SPT_DATA_OFFSET + 3], b"x");
    }

    fn sat_out(cmd: &AtaCmd, status: u8, sense: &[u8], dtl: u32) -> Vec<u8> {
        let mut o = sat_encode(cmd);
        o[SPT_OFF_STATUS] = status;
        o[SPT_SENSE_OFFSET..SPT_SENSE_OFFSET + sense.len()].copy_from_slice(sense);
        put_u32(&mut o, SPT_OFF_DTL, dtl);
        o
    }

    /// Sense descripteur avec ATA Status Return.
    fn desc_sense(key: u8, ext: bool, error: u8, status: u8, lba: u64, count: u16) -> Vec<u8> {
        let l = lba.to_le_bytes();
        let c = count.to_le_bytes();
        let mut s = vec![0x72, key, 0x00, 0x1D, 0, 0, 0, 14];
        s.extend_from_slice(&[
            0x09, 0x0C, ext as u8, error, c[1], c[0], l[3], l[0], l[4], l[1], l[5], l[2], 0x40,
            status,
        ]);
        s
    }

    #[test]
    fn sat_identify_good_returns_data() {
        let cmd = identify();
        let mut o = sat_out(&cmd, 0, &[], 512);
        o[SPT_DATA_OFFSET] = 0xAB;
        match sat_decode(&o, &cmd) {
            SatOutcome::Done(Ok(r)) => {
                assert_eq!((r.status, r.data[0], r.data.len()), (0x50, 0xAB, 512))
            }
            x => panic!("{x:?}"),
        }
        let short = sat_out(&cmd, 0, &[], 0);
        assert!(matches!(
            sat_decode(&short, &cmd),
            SatOutcome::Done(Err(AtaError::Invalid(_)))
        ));
    }

    #[test]
    fn sat_registers_from_descriptor_48bit() {
        let cmd = read_native_max_ext();
        let o = sat_out(
            &cmd,
            2,
            &desc_sense(1, true, 0, 0x50, 0x0000_3A38_6030, 0),
            0,
        );
        match sat_decode(&o, &cmd) {
            SatOutcome::Done(Ok(r)) => assert_eq!(r.lba, 0x0000_3A38_6030),
            x => panic!("{x:?}"),
        }
        // Sans EXTEND : octets hauts manquants -> inexploitable, jamais un faux résultat.
        let o = sat_out(&cmd, 2, &desc_sense(1, false, 0, 0x50, 0x6030, 0), 0);
        assert!(matches!(
            sat_decode(&o, &cmd),
            SatOutcome::Done(Err(AtaError::Invalid(_)))
        ));
        // GOOD sans registres pour une commande qui en a besoin -> inexploitable.
        let o = sat_out(&cmd, 0, &[], 0);
        assert!(matches!(
            sat_decode(&o, &cmd),
            SatOutcome::Done(Err(AtaError::Invalid(_)))
        ));
    }

    #[test]
    fn sat_abort_is_device_error_never_success() {
        let cmd = sanitize_block_erase();
        let o = sat_out(&cmd, 2, &desc_sense(0x0B, true, 0x04, 0x51, 0, 0), 0);
        assert_eq!(
            sat_decode(&o, &cmd),
            SatOutcome::Done(Err(AtaError::Device {
                status: 0x51,
                error: 0x04
            }))
        );
        // Clé ABORTED COMMAND avec un registre d'état « propre » : échec forcé.
        let o = sat_out(&cmd, 2, &desc_sense(0x0B, true, 0, 0x50, 0, 0), 0);
        assert!(matches!(
            sat_decode(&o, &cmd),
            SatOutcome::Done(Err(AtaError::Device { .. }))
        ));
        // Sense ABORTED sans registres : inexploitable (pas un refus du transport).
        let o = sat_out(
            &cmd,
            2,
            &[0x70, 0, 0x0B, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0],
            0,
        );
        assert!(matches!(
            sat_decode(&o, &cmd),
            SatOutcome::Done(Err(AtaError::Invalid(_)))
        ));
    }

    #[test]
    fn sat_illegal_request_without_registers_is_refusal() {
        let cmd = sanitize_block_erase();
        // INVALID COMMAND OPERATION CODE, format fixe.
        let o = sat_out(
            &cmd,
            2,
            &[0x70, 0, 0x05, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0x20, 0x00],
            0,
        );
        assert_eq!(sat_decode(&o, &cmd), SatOutcome::Refused);
        // INVALID FIELD IN CDB, format descripteur.
        let o = sat_out(&cmd, 2, &[0x72, 0x05, 0x24, 0x00, 0, 0, 0, 0], 0);
        assert_eq!(sat_decode(&o, &cmd), SatOutcome::Refused);
    }

    #[test]
    fn sat_fixed_format_registers_28bit() {
        let cmd = smart_return_status();
        // error 0, status 0x50, device 0x40, count 0, LBA mid/high = 2C F4 (seuil dépassé)
        let s = [
            0x70, 0, 0x01, 0x00, 0x50, 0x40, 0x00, 10, 0, 0x00, 0xF4, 0x2C, 0x00, 0x1D,
        ];
        match sat_decode(&sat_out(&cmd, 2, &s, 0), &cmd) {
            SatOutcome::Done(Ok(r)) => assert_eq!(r.lba & 0xFF_FF00, 0x2C_F400),
            x => panic!("{x:?}"),
        }
    }

    #[test]
    fn combine_tries_second_route_only_after_transport_refusal() {
        let ok = || {
            SatOutcome::Done(Ok(AtaResult {
                status: 0x50,
                ..Default::default()
            }))
        };
        let abrt = AtaError::Device {
            status: 0x51,
            error: 4,
        };
        // Première voie OK ou refus du disque : la seconde n'est jamais appelée.
        assert!(combine(Ok(AtaResult::default()), || panic!("appel inattendu")).is_ok());
        assert_eq!(
            combine(Err(abrt.clone()), || panic!("appel inattendu")),
            Err(abrt.clone())
        );
        assert_eq!(
            combine(Err(AtaError::Windows(121)), || panic!("appel inattendu")),
            Err(AtaError::Windows(121))
        );
        // Refus du pilote : seconde voie.
        assert!(combine(Err(AtaError::Windows(50)), ok).is_ok());
        assert_eq!(
            combine(Err(AtaError::Windows(50)), || SatOutcome::Done(Err(
                abrt.clone()
            ))),
            Err(abrt)
        );
        // Les deux refusées : erreur d'origine (toujours un refus du transport).
        let r = combine(Err(AtaError::Windows(50)), || SatOutcome::Refused);
        assert_eq!(r, Err(AtaError::Windows(50)));
        assert_eq!(r.unwrap_err().transport_refusal(), Some(50));
    }
}
