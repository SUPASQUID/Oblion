//! NVMe sous Windows (pilote Microsoft stornvme).
//!
//! - Lecture seule : IOCTL_STORAGE_QUERY_PROPERTY avec StorageAdapterProtocolSpecificProperty /
//!   StorageDeviceProtocolSpecificProperty et STORAGE_PROTOCOL_SPECIFIC_DATA (Identify
//!   Controller, Identify Namespace, journaux SMART/Health 02h et Sanitize Status 81h).
//! - Effacement : IOCTL_STORAGE_REINITIALIZE_MEDIA (Sanitize NVMe) ; repli Format NVM par
//!   IOCTL_STORAGE_PROTOCOL_COMMAND. Le pilote Microsoft peut refuser ces commandes : chaque
//!   refus remonte avec son code (jamais en silence).
//!
//! Structures vérifiées contre le Windows SDK 10.0.26100.0 (`um/winioctl.h`, `shared/nvme.h`) ;
//! décodage d'après ces en-têtes et la norme NVMe (réimplémentation, aucun code repris).

use std::mem::{offset_of, size_of};

use crate::winio::{self, Handle};

// ---------- Constantes (winioctl.h) ----------

const IOCTL_STORAGE_BASE: u32 = 0x2d; // FILE_DEVICE_MASS_STORAGE
/// CTL_CODE(IOCTL_STORAGE_BASE, 0x0590, METHOD_BUFFERED, FILE_WRITE_ACCESS)
pub const IOCTL_STORAGE_REINITIALIZE_MEDIA: u32 = winio::ctl_code(IOCTL_STORAGE_BASE, 0x590, 0, 2);
/// CTL_CODE(IOCTL_STORAGE_BASE, 0x04F0, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
pub const IOCTL_STORAGE_PROTOCOL_COMMAND: u32 =
    winio::ctl_code(IOCTL_STORAGE_BASE, 0x4F0, 0, 1 | 2);

/// STORAGE_PROPERTY_ID (énumération de winioctl.h).
pub const STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY: u32 = 49;
pub const STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY: u32 = 50;
/// STORAGE_PROTOCOL_TYPE::ProtocolTypeNvme
pub const PROTOCOL_TYPE_NVME: u32 = 3;
/// STORAGE_PROTOCOL_NVME_DATA_TYPE
pub const NVME_DATA_TYPE_IDENTIFY: u32 = 1;
pub const NVME_DATA_TYPE_LOG_PAGE: u32 = 2;
/// NVME_IDENTIFY_CNS_CODES (nvme.h)
pub const CNS_NAMESPACE: u32 = 0;
pub const CNS_CONTROLLER: u32 = 1;
/// NVME_LOG_PAGES (nvme.h)
pub const LOG_HEALTH: u8 = 0x02;
pub const LOG_SANITIZE: u8 = 0x81;
/// NVME_ADMIN_COMMANDS::NVME_ADMIN_COMMAND_FORMAT_NVM
pub const ADMIN_FORMAT_NVM: u8 = 0x80;
pub const STORAGE_PROTOCOL_STRUCTURE_VERSION: u32 = 1;
pub const STORAGE_PROTOCOL_COMMAND_LENGTH_NVME: u32 = 0x40;
pub const STORAGE_PROTOCOL_SPECIFIC_NVME_ADMIN_COMMAND: u32 = 1;
pub const STORAGE_PROTOCOL_STATUS_SUCCESS: u32 = 1;

/// Miroir de STORAGE_PROPERTY_QUERY (AdditionalParameters[1]).
#[repr(C)]
pub struct StoragePropertyQuery {
    pub property_id: u32,
    pub query_type: u32,
    pub additional_parameters: [u8; 1],
}

/// Miroir de STORAGE_PROTOCOL_SPECIFIC_DATA.
#[repr(C)]
pub struct StorageProtocolSpecificData {
    pub protocol_type: u32,
    pub data_type: u32,
    pub protocol_data_request_value: u32,
    pub protocol_data_request_sub_value: u32,
    pub protocol_data_offset: u32,
    pub protocol_data_length: u32,
    pub fixed_protocol_return_data: u32,
    pub protocol_data_request_sub_value2: u32,
    pub protocol_data_request_sub_value3: u32,
    pub protocol_data_request_sub_value4: u32,
}

/// Miroir de STORAGE_PROTOCOL_DATA_DESCRIPTOR.
#[repr(C)]
pub struct StorageProtocolDataDescriptor {
    pub version: u32,
    pub size: u32,
    pub protocol_specific_data: StorageProtocolSpecificData,
}

/// Miroir de STORAGE_REINITIALIZE_MEDIA (SanitizeOption : champ de bits sur un DWORD).
#[repr(C)]
pub struct StorageReinitializeMedia {
    pub version: u32,
    pub size: u32,
    pub timeout_in_seconds: u32,
    /// bits 3:0 SanitizeMethod, bit 4 DisallowUnrestrictedSanitizeExit.
    pub sanitize_option: u32,
}

/// Miroir de STORAGE_PROTOCOL_COMMAND (Command[ANYSIZE_ARRAY]).
#[repr(C)]
pub struct StorageProtocolCommand {
    pub version: u32,
    pub length: u32,
    pub protocol_type: u32,
    pub flags: u32,
    pub return_status: u32,
    pub error_code: u32,
    pub command_length: u32,
    pub error_info_length: u32,
    pub data_to_device_transfer_length: u32,
    pub data_from_device_transfer_length: u32,
    pub time_out_value: u32,
    pub error_info_offset: u32,
    pub data_to_device_buffer_offset: u32,
    pub data_from_device_buffer_offset: u32,
    pub command_specific: u32,
    pub reserved0: u32,
    pub fixed_protocol_return_data: u32,
    pub fixed_protocol_return_data2: u32,
    pub reserved1: [u32; 2],
    pub command: [u8; 1],
}

const QUERY_PARAMS: usize = offset_of!(StoragePropertyQuery, additional_parameters);
const SPD_SIZE: usize = size_of::<StorageProtocolSpecificData>();
const DESC_DATA: usize = offset_of!(StorageProtocolDataDescriptor, protocol_specific_data);
const CMD_OFFSET: usize = offset_of!(StorageProtocolCommand, command);

/// STORAGE_SANITIZE_METHOD (winioctl.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeMethod {
    BlockErase = 1,
    CryptoErase = 2,
}

fn put(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

// ---------- Tampons (purs, testés) ----------

/// Tampon d'entrée/sortie d'IOCTL_STORAGE_QUERY_PROPERTY protocol-specific :
/// STORAGE_PROPERTY_QUERY + STORAGE_PROTOCOL_SPECIFIC_DATA + `len` octets de données.
pub fn protocol_query(property: u32, data_type: u32, value: u32, sub: u32, len: u32) -> Vec<u8> {
    let mut b = vec![0u8; QUERY_PARAMS + SPD_SIZE + len as usize];
    put(
        &mut b,
        offset_of!(StoragePropertyQuery, property_id),
        property,
    );
    put(&mut b, offset_of!(StoragePropertyQuery, query_type), 0); // PropertyStandardQuery
    let p = QUERY_PARAMS;
    put(
        &mut b,
        p + offset_of!(StorageProtocolSpecificData, protocol_type),
        PROTOCOL_TYPE_NVME,
    );
    put(
        &mut b,
        p + offset_of!(StorageProtocolSpecificData, data_type),
        data_type,
    );
    put(
        &mut b,
        p + offset_of!(StorageProtocolSpecificData, protocol_data_request_value),
        value,
    );
    put(
        &mut b,
        p + offset_of!(StorageProtocolSpecificData, protocol_data_request_sub_value),
        sub,
    );
    put(
        &mut b,
        p + offset_of!(StorageProtocolSpecificData, protocol_data_offset),
        SPD_SIZE as u32,
    );
    put(
        &mut b,
        p + offset_of!(StorageProtocolSpecificData, protocol_data_length),
        len,
    );
    b
}

/// Extrait les données d'un STORAGE_PROTOCOL_DATA_DESCRIPTOR rendu par le pilote.
pub fn protocol_reply(out: &[u8], expected: u32) -> Result<Vec<u8>, String> {
    let desc = size_of::<StorageProtocolDataDescriptor>() as u32;
    if out.len() < desc as usize {
        return Err("réponse trop courte".into());
    }
    if winio::u32_at(out, 0) != desc || winio::u32_at(out, 4) != desc {
        return Err(format!(
            "descripteur inattendu (Version {}, Size {})",
            winio::u32_at(out, 0),
            winio::u32_at(out, 4)
        ));
    }
    let off = winio::u32_at(
        out,
        DESC_DATA + offset_of!(StorageProtocolSpecificData, protocol_data_offset),
    ) as usize;
    let len = winio::u32_at(
        out,
        DESC_DATA + offset_of!(StorageProtocolSpecificData, protocol_data_length),
    );
    if off < SPD_SIZE || len < expected {
        return Err(format!("données incomplètes ({len} octets)"));
    }
    let start = DESC_DATA + off;
    out.get(start..start + expected as usize)
        .map(|s| s.to_vec())
        .ok_or_else(|| "données hors du tampon".into())
}

pub fn reinitialize_media_buffer(method: SanitizeMethod, timeout_secs: u32) -> Vec<u8> {
    let size = size_of::<StorageReinitializeMedia>();
    let mut b = vec![0u8; size];
    put(
        &mut b,
        offset_of!(StorageReinitializeMedia, version),
        size as u32,
    );
    put(
        &mut b,
        offset_of!(StorageReinitializeMedia, size),
        size as u32,
    );
    put(
        &mut b,
        offset_of!(StorageReinitializeMedia, timeout_in_seconds),
        timeout_secs,
    );
    // DisallowUnrestrictedSanitizeExit = 0 : valeur par défaut documentée.
    put(
        &mut b,
        offset_of!(StorageReinitializeMedia, sanitize_option),
        method as u32 & 0xF,
    );
    b
}

/// STORAGE_PROTOCOL_COMMAND + commande NVMe FORMAT NVM de 64 octets (CDW10 : LBAF 3:0, SES 11:9).
pub fn format_command_buffer(ses: u8, lbaf: u8, nsid: u32, timeout_secs: u32) -> Vec<u8> {
    let mut b = vec![0u8; CMD_OFFSET + STORAGE_PROTOCOL_COMMAND_LENGTH_NVME as usize];
    let fields = [
        (
            offset_of!(StorageProtocolCommand, version),
            STORAGE_PROTOCOL_STRUCTURE_VERSION,
        ),
        (
            offset_of!(StorageProtocolCommand, length),
            size_of::<StorageProtocolCommand>() as u32,
        ),
        (
            offset_of!(StorageProtocolCommand, protocol_type),
            PROTOCOL_TYPE_NVME,
        ),
        (
            offset_of!(StorageProtocolCommand, command_length),
            STORAGE_PROTOCOL_COMMAND_LENGTH_NVME,
        ),
        (
            offset_of!(StorageProtocolCommand, time_out_value),
            timeout_secs,
        ),
        (
            offset_of!(StorageProtocolCommand, command_specific),
            STORAGE_PROTOCOL_SPECIFIC_NVME_ADMIN_COMMAND,
        ),
    ];
    for (off, v) in fields {
        put(&mut b, off, v);
    }
    // NVME_COMMAND : CDW0 (opcode 7:0) @0, NSID @4, CDW10 @40.
    let c = CMD_OFFSET;
    b[c] = ADMIN_FORMAT_NVM;
    put(&mut b, c + 4, nsid);
    let cdw10 = (lbaf as u32 & 0xF) | ((ses as u32 & 0x7) << 9);
    put(&mut b, c + 40, cdw10);
    b
}

/// (ReturnStatus, ErrorCode) d'un STORAGE_PROTOCOL_COMMAND rendu.
pub fn protocol_command_status(out: &[u8]) -> (u32, u32) {
    (
        winio::u32_at(out, offset_of!(StorageProtocolCommand, return_status)),
        winio::u32_at(out, offset_of!(StorageProtocolCommand, error_code)),
    )
}

// ---------- Décodage (pur) ----------

fn ascii(d: &[u8], off: usize, len: usize) -> String {
    d.get(off..off + len)
        .map(|s| {
            String::from_utf8_lossy(s)
                .trim_matches(|c: char| c == '\0' || c.is_whitespace())
                .to_string()
        })
        .unwrap_or_default()
}

fn u128_at(d: &[u8], off: usize) -> u128 {
    d.get(off..off + 16)
        .map(|b| u128::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}

fn u16_at(d: &[u8], off: usize) -> u16 {
    d.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .unwrap_or(0)
}

fn u64_at(d: &[u8], off: usize) -> u64 {
    d.get(off..off + 8)
        .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sanicap {
    pub crypto: bool,
    pub block: bool,
    pub overwrite: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Fna {
    /// Le formatage s'applique à tous les espaces de noms.
    pub format_all: bool,
    /// L'effacement sécurisé (SES) s'applique à tous les espaces de noms.
    pub secure_erase_all: bool,
    /// Effacement cryptographique (SES = 2) supporté.
    pub crypto_erase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvmeController {
    pub model: String,
    pub serial: String,
    pub firmware: String,
    /// OACS bit 1 : FORMAT NVM supportée.
    pub format_supported: bool,
    pub sanicap: Sanicap,
    pub fna: Fna,
    /// ONCS bit 2 : Dataset Management (TRIM/Deallocate).
    pub dsm: bool,
    pub tnvmcap: u128,
    pub namespaces: u32,
}

/// Identify Controller (4096 octets) : SN 4..24, MN 24..64, FR 64..72, OACS 256,
/// TNVMCAP 280, SANICAP 328, NN 516, ONCS 520, FNA 524.
pub fn decode_controller(d: &[u8]) -> Result<NvmeController, String> {
    if d.len() < 4096 {
        return Err(format!("Identify Controller : {} octets", d.len()));
    }
    if d[..1024].iter().all(|&b| b == 0) {
        return Err("Identify Controller : données vides".into());
    }
    let oacs = u16_at(d, 256);
    let sanicap = winio::u32_at(d, 328);
    let fna = d[524];
    Ok(NvmeController {
        serial: ascii(d, 4, 20),
        model: ascii(d, 24, 40),
        firmware: ascii(d, 64, 8),
        format_supported: oacs & (1 << 1) != 0,
        sanicap: Sanicap {
            crypto: sanicap & 1 != 0,
            block: sanicap & (1 << 1) != 0,
            overwrite: sanicap & (1 << 2) != 0,
        },
        fna: Fna {
            format_all: fna & 1 != 0,
            secure_erase_all: fna & (1 << 1) != 0,
            crypto_erase: fna & (1 << 2) != 0,
        },
        dsm: u16_at(d, 520) & (1 << 2) != 0,
        tnvmcap: u128_at(d, 280),
        namespaces: winio::u32_at(d, 516),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvmeNamespace {
    pub nsze: u64,
    pub ncap: u64,
    pub nuse: u64,
    pub lba_size: u32,
    pub lbaf_index: u8,
    /// DPS bits 2:0 (octet 29) : type de protection d'information actif (0 = aucune).
    pub pi_type: u8,
    /// FLBAS bit 4 : métadonnées en fin de bloc LBA étendu.
    pub extended_metadata: bool,
}

impl NvmeNamespace {
    pub fn size_bytes(&self) -> u64 {
        self.nsze.saturating_mul(self.lba_size as u64)
    }

    /// FORMAT NVM sans risque de changer le format : notre CDW10 ne code que LBAF 3:0,
    /// MSET = 0 et PI = 0. Renvoie la raison du refus sinon.
    pub fn format_refusal(&self) -> Option<String> {
        if self.lbaf_index > 15 {
            Some(format!(
                "format LBA {} > 15 (bits LBAFU non gérés)",
                self.lbaf_index
            ))
        } else if self.pi_type != 0 {
            Some(format!(
                "protection d'information de type {} active (non conservée par le formatage)",
                self.pi_type
            ))
        } else if self.extended_metadata {
            Some("métadonnées en LBA étendu (non conservées par le formatage)".into())
        } else {
            None
        }
    }
}

/// Identify Namespace : NSZE 0, NCAP 8, NUSE 16, NLBAF 25, FLBAS 26, LBAF[] 128 (4 octets).
pub fn decode_namespace(d: &[u8]) -> Result<NvmeNamespace, String> {
    if d.len() < 4096 {
        return Err(format!("Identify Namespace : {} octets", d.len()));
    }
    let flbas = d[26];
    let idx = (flbas & 0x0F) | (((flbas >> 5) & 0x03) << 4);
    let lbads = d[128 + 4 * idx as usize + 2];
    if !(9..=16).contains(&lbads) {
        return Err(format!("Identify Namespace : LBADS {lbads} invalide"));
    }
    Ok(NvmeNamespace {
        nsze: u64_at(d, 0),
        ncap: u64_at(d, 8),
        nuse: u64_at(d, 16),
        lba_size: 1u32 << lbads,
        lbaf_index: idx,
        pi_type: d[29] & 0x07,
        extended_metadata: flbas & (1 << 4) != 0,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HealthLog {
    pub critical_warning: u8,
    pub temperature_k: u16,
    pub available_spare: u8,
    pub spare_threshold: u8,
    pub percent_used: u8,
    pub data_units_read: u128,
    pub data_units_written: u128,
    pub power_cycles: u128,
    pub power_on_hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
    pub error_log_entries: u128,
}

impl HealthLog {
    /// Température en °C (0 K = non rapportée).
    pub fn celsius(&self) -> Option<i32> {
        (self.temperature_k > 0).then(|| self.temperature_k as i32 - 273)
    }
    /// Une unité de données = 1000 × 512 octets.
    pub fn bytes(units: u128) -> u128 {
        units.saturating_mul(512_000)
    }
}

/// Journal SMART / Health (02h, 512 octets) : NVME_HEALTH_INFO_LOG de nvme.h.
pub fn decode_health(d: &[u8]) -> Result<HealthLog, String> {
    if d.len() < 512 {
        return Err(format!("journal SMART/Health : {} octets", d.len()));
    }
    Ok(HealthLog {
        critical_warning: d[0],
        temperature_k: u16_at(d, 1),
        available_spare: d[3],
        spare_threshold: d[4],
        percent_used: d[5],
        data_units_read: u128_at(d, 32),
        data_units_written: u128_at(d, 48),
        power_cycles: u128_at(d, 112),
        power_on_hours: u128_at(d, 128),
        unsafe_shutdowns: u128_at(d, 144),
        media_errors: u128_at(d, 160),
        error_log_entries: u128_at(d, 176),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SanitizeState {
    Never,
    Succeeded,
    InProgress,
    Failed,
    SucceededForcedDeallocation,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SanitizeLog {
    pub sprog: u16,
    pub state: SanitizeState,
    pub overwrite_passes: u8,
    pub global_data_erased: bool,
    pub scdw10: u32,
    pub est_overwrite: u32,
    pub est_block: u32,
    pub est_crypto: u32,
}

impl SanitizeLog {
    pub fn percent(&self) -> f64 {
        self.sprog as f64 / 65536.0 * 100.0
    }

    /// Progression lisible : « — » hors opération en cours (SPROG vaut alors FFFFh).
    pub fn progress_text(&self) -> String {
        if self.state == SanitizeState::InProgress {
            format!("{:.1} %", self.percent())
        } else {
            "—".into()
        }
    }
}

/// Journal Sanitize Status (81h) : SPROG 0, SSTAT 2 (bits 2:0 état, 6:3 passes, 8 GDE),
/// SCDW10 4, estimations 8/12/16 (secondes, FFFFFFFFh = non rapportée).
pub fn decode_sanitize_log(d: &[u8]) -> Result<SanitizeLog, String> {
    if d.len() < 20 {
        return Err(format!("journal Sanitize Status : {} octets", d.len()));
    }
    let sstat = u16_at(d, 2);
    let state = match sstat & 0x7 {
        0 => SanitizeState::Never,
        1 => SanitizeState::Succeeded,
        2 => SanitizeState::InProgress,
        3 => SanitizeState::Failed,
        4 => SanitizeState::SucceededForcedDeallocation,
        n => SanitizeState::Other(n as u8),
    };
    Ok(SanitizeLog {
        sprog: u16_at(d, 0),
        state,
        overwrite_passes: ((sstat >> 3) & 0xF) as u8,
        global_data_erased: sstat & (1 << 8) != 0,
        scdw10: winio::u32_at(d, 4),
        est_overwrite: winio::u32_at(d, 8),
        est_block: winio::u32_at(d, 12),
        est_crypto: winio::u32_at(d, 16),
    })
}

// ---------- Port NVMe ----------

/// Accès NVMe. `sanitize` et `format` sont DESTRUCTIFS : seule l'implémentation de `RawDisk`
/// (autorisation armée) les exécute ; l'accès en lecture seule les refuse.
pub trait NvmePort {
    fn identify_controller(&mut self) -> Result<Vec<u8>, String>;
    fn identify_namespace(&mut self, nsid: u32) -> Result<Vec<u8>, String>;
    fn log_page(&mut self, id: u8, len: u32) -> Result<Vec<u8>, String>;
    fn sanitize(&mut self, method: SanitizeMethod, timeout_secs: u32) -> Result<(), String>;
    fn format(&mut self, ses: u8, lbaf: u8, timeout_secs: u32) -> Result<(), String>;
}

fn win_err(e: u32) -> String {
    match e {
        1 => "erreur Windows 1 (fonction non prise en charge par le pilote)".into(),
        5 => "erreur Windows 5 (accès refusé : droits administrateur ?)".into(),
        50 => "erreur Windows 50 (requête non prise en charge par le pilote/le disque)".into(),
        87 => "erreur Windows 87 (paramètre refusé par le pilote)".into(),
        c => format!("erreur Windows {c}"),
    }
}

fn query_once(
    h: &Handle,
    property: u32,
    dt: u32,
    v: u32,
    sub: u32,
    len: u32,
) -> Result<Vec<u8>, String> {
    let input = protocol_query(property, dt, v, sub, len);
    let mut out = vec![0u8; input.len()];
    winio::ioctl(h, winio::IOCTL_STORAGE_QUERY_PROPERTY, &input, &mut out).map_err(win_err)?;
    protocol_reply(&out, len)
}

/// Essaie la propriété « disque » puis « adaptateur » (ou l'inverse) ; les deux erreurs
/// sont rapportées si aucune ne répond.
pub(crate) fn query(
    h: &Handle,
    adapter_first: bool,
    dt: u32,
    v: u32,
    sub: u32,
    len: u32,
) -> Result<Vec<u8>, String> {
    let (a, b) = if adapter_first {
        (
            STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY,
            STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY,
        )
    } else {
        (
            STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY,
            STORAGE_ADAPTER_PROTOCOL_SPECIFIC_PROPERTY,
        )
    };
    query_once(h, a, dt, v, sub, len)
        .or_else(|e1| query_once(h, b, dt, v, sub, len).map_err(|e2| format!("{e1} ; puis {e2}")))
}

pub(crate) fn read_identify_controller(h: &Handle) -> Result<Vec<u8>, String> {
    query(h, true, NVME_DATA_TYPE_IDENTIFY, CNS_CONTROLLER, 0, 4096)
        .map_err(|e| format!("NVMe Identify Controller : {e}"))
}
pub(crate) fn read_identify_namespace(h: &Handle, nsid: u32) -> Result<Vec<u8>, String> {
    query(h, false, NVME_DATA_TYPE_IDENTIFY, CNS_NAMESPACE, nsid, 4096)
        .map_err(|e| format!("NVMe Identify Namespace {nsid} : {e}"))
}
pub(crate) fn read_log_page(h: &Handle, id: u8, len: u32) -> Result<Vec<u8>, String> {
    query(h, false, NVME_DATA_TYPE_LOG_PAGE, id as u32, 0, len)
        .map_err(|e| format!("NVMe journal {id:02X}h : {e}"))
}

/// IOCTL_STORAGE_REINITIALIZE_MEDIA (Sanitize NVMe par stornvme). DESTRUCTIF.
pub(crate) fn reinitialize_media(
    h: &Handle,
    method: SanitizeMethod,
    timeout_secs: u32,
) -> Result<(), String> {
    let input = reinitialize_media_buffer(method, timeout_secs);
    winio::ioctl(h, IOCTL_STORAGE_REINITIALIZE_MEDIA, &input, &mut [])
        .map(|_| ())
        .map_err(|e| {
            format!(
                "IOCTL_STORAGE_REINITIALIZE_MEDIA ({method:?}) refusé : {}",
                win_err(e)
            )
        })
}

/// FORMAT NVM par IOCTL_STORAGE_PROTOCOL_COMMAND. DESTRUCTIF. Le pilote Microsoft peut la
/// bloquer : le refus est rapporté avec ses codes.
pub(crate) fn protocol_format(
    h: &Handle,
    ses: u8,
    lbaf: u8,
    nsid: u32,
    timeout_secs: u32,
) -> Result<(), String> {
    let input = format_command_buffer(ses, lbaf, nsid, timeout_secs);
    let mut out = vec![0u8; input.len()];
    let what = format!("NVMe FORMAT NVM (SES={ses}) par IOCTL_STORAGE_PROTOCOL_COMMAND");
    winio::ioctl(h, IOCTL_STORAGE_PROTOCOL_COMMAND, &input, &mut out)
        .map_err(|e| format!("{what} refusé : {}", win_err(e)))?;
    match protocol_command_status(&out) {
        (STORAGE_PROTOCOL_STATUS_SUCCESS, _) => Ok(()),
        (status, code) => Err(format!(
            "{what} en échec : ReturnStatus {status:#X}, statut NVMe {code:#06X}"
        )),
    }
}

/// Accès NVMe en LECTURE SEULE (--info, dry-run) : les commandes destructives sont refusées.
pub struct ReadOnlyNvme {
    h: Handle,
}

impl ReadOnlyNvme {
    pub fn open(number: u32) -> Result<ReadOnlyNvme, String> {
        let path = format!(r"\\.\PhysicalDrive{number}");
        Handle::open(&path, winio::GENERIC_READ)
            .or_else(|_| Handle::open(&path, 0))
            .map(|h| ReadOnlyNvme { h })
            .map_err(|e| format!("ouverture de {path} impossible ({})", win_err(e)))
    }
}

pub const READ_ONLY_REFUSAL: &str = "commande destructive refusée (accès en lecture seule)";

impl NvmePort for ReadOnlyNvme {
    fn identify_controller(&mut self) -> Result<Vec<u8>, String> {
        read_identify_controller(&self.h)
    }
    fn identify_namespace(&mut self, nsid: u32) -> Result<Vec<u8>, String> {
        read_identify_namespace(&self.h, nsid)
    }
    fn log_page(&mut self, id: u8, len: u32) -> Result<Vec<u8>, String> {
        read_log_page(&self.h, id, len)
    }
    fn sanitize(&mut self, _: SanitizeMethod, _: u32) -> Result<(), String> {
        Err(READ_ONLY_REFUSAL.into())
    }
    fn format(&mut self, _: u8, _: u8, _: u32) -> Result<(), String> {
        Err(READ_ONLY_REFUSAL.into())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn sample_controller() -> Vec<u8> {
        let mut d = vec![0u8; 4096];
        d[0..2].copy_from_slice(&0x144Du16.to_le_bytes());
        d[4..24].copy_from_slice(b"S4EWNX0R123456      ");
        let mut mn = b"Samsung SSD 970 EVO Plus 500GB".to_vec();
        mn.resize(40, b' ');
        d[24..64].copy_from_slice(&mn);
        d[64..72].copy_from_slice(b"2B2QEXM7");
        d[256..258].copy_from_slice(&0x0017u16.to_le_bytes()); // dont FORMAT (bit 1)
        d[280..296].copy_from_slice(&500_107_862_016u128.to_le_bytes());
        d[328..332].copy_from_slice(&0b011u32.to_le_bytes()); // crypto + block
        d[516..520].copy_from_slice(&1u32.to_le_bytes());
        d[520..522].copy_from_slice(&(1u16 << 2).to_le_bytes());
        d[524] = 0b101; // format tous NS + crypto erase
        d
    }

    #[test]
    fn ioctl_codes_match_winioctl_h() {
        assert_eq!(IOCTL_STORAGE_REINITIALIZE_MEDIA, 0x002D_9640);
        assert_eq!(IOCTL_STORAGE_PROTOCOL_COMMAND, 0x002D_D3C0);
    }

    #[test]
    fn storage_property_query_layout() {
        assert_eq!(offset_of!(StoragePropertyQuery, property_id), 0);
        assert_eq!(offset_of!(StoragePropertyQuery, query_type), 4);
        assert_eq!(QUERY_PARAMS, 8);
        assert_eq!(size_of::<StoragePropertyQuery>(), 12);
    }

    #[test]
    fn storage_protocol_specific_data_layout() {
        assert_eq!(SPD_SIZE, 40);
        assert_eq!(offset_of!(StorageProtocolSpecificData, data_type), 4);
        assert_eq!(
            offset_of!(StorageProtocolSpecificData, protocol_data_request_value),
            8
        );
        assert_eq!(
            offset_of!(StorageProtocolSpecificData, protocol_data_request_sub_value),
            12
        );
        assert_eq!(
            offset_of!(StorageProtocolSpecificData, protocol_data_offset),
            16
        );
        assert_eq!(
            offset_of!(StorageProtocolSpecificData, protocol_data_length),
            20
        );
        assert_eq!(
            offset_of!(StorageProtocolSpecificData, fixed_protocol_return_data),
            24
        );
        assert_eq!(
            offset_of!(
                StorageProtocolSpecificData,
                protocol_data_request_sub_value4
            ),
            36
        );
    }

    #[test]
    fn storage_protocol_data_descriptor_layout() {
        assert_eq!(size_of::<StorageProtocolDataDescriptor>(), 48);
        assert_eq!(DESC_DATA, 8);
    }

    #[test]
    fn storage_reinitialize_media_layout() {
        assert_eq!(size_of::<StorageReinitializeMedia>(), 16);
        assert_eq!(offset_of!(StorageReinitializeMedia, timeout_in_seconds), 8);
        assert_eq!(offset_of!(StorageReinitializeMedia, sanitize_option), 12);
        let b = reinitialize_media_buffer(SanitizeMethod::CryptoErase, 600);
        assert_eq!(winio::u32_at(&b, 0), 16);
        assert_eq!(winio::u32_at(&b, 4), 16);
        assert_eq!(winio::u32_at(&b, 8), 600);
        assert_eq!(winio::u32_at(&b, 12), 2);
        assert_eq!(
            winio::u32_at(
                &reinitialize_media_buffer(SanitizeMethod::BlockErase, 1),
                12
            ),
            1
        );
    }

    #[test]
    fn storage_protocol_command_layout_and_format_buffer() {
        assert_eq!(offset_of!(StorageProtocolCommand, return_status), 16);
        assert_eq!(offset_of!(StorageProtocolCommand, error_code), 20);
        assert_eq!(offset_of!(StorageProtocolCommand, time_out_value), 40);
        assert_eq!(offset_of!(StorageProtocolCommand, command_specific), 56);
        assert_eq!(
            offset_of!(StorageProtocolCommand, fixed_protocol_return_data),
            64
        );
        assert_eq!(CMD_OFFSET, 80);
        assert_eq!(size_of::<StorageProtocolCommand>(), 84);
        let b = format_command_buffer(2, 0, 1, 3600);
        assert_eq!(b.len(), 144);
        assert_eq!(winio::u32_at(&b, 0), 1);
        assert_eq!(winio::u32_at(&b, 4), 84);
        assert_eq!(winio::u32_at(&b, 8), 3);
        assert_eq!(winio::u32_at(&b, 24), 64);
        assert_eq!(winio::u32_at(&b, 56), 1);
        assert_eq!(b[80], 0x80);
        assert_eq!(winio::u32_at(&b, 84), 1);
        assert_eq!(winio::u32_at(&b, 120), 2 << 9);
        let mut out = b.clone();
        out[16..20].copy_from_slice(&2u32.to_le_bytes());
        out[20..24].copy_from_slice(&0x4002u32.to_le_bytes());
        assert_eq!(protocol_command_status(&out), (2, 0x4002));
    }

    #[test]
    fn protocol_query_buffer_and_reply() {
        let b = protocol_query(
            STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY,
            NVME_DATA_TYPE_LOG_PAGE,
            0x02,
            0,
            512,
        );
        assert_eq!(b.len(), 8 + 40 + 512);
        assert_eq!(winio::u32_at(&b, 0), 50);
        assert_eq!(winio::u32_at(&b, 8), 3);
        assert_eq!(winio::u32_at(&b, 12), 2);
        assert_eq!(winio::u32_at(&b, 16), 2);
        assert_eq!(winio::u32_at(&b, 24), 40);
        assert_eq!(winio::u32_at(&b, 28), 512);
        // Réponse : descripteur (Version = Size = 48) puis données à 8 + 40.
        let mut out = vec![0u8; 8 + 40 + 512];
        out[0..4].copy_from_slice(&48u32.to_le_bytes());
        out[4..8].copy_from_slice(&48u32.to_le_bytes());
        out[8 + 16..8 + 20].copy_from_slice(&40u32.to_le_bytes());
        out[8 + 20..8 + 24].copy_from_slice(&512u32.to_le_bytes());
        out[48] = 0x42;
        let data = protocol_reply(&out, 512).unwrap();
        assert_eq!(data.len(), 512);
        assert_eq!(data[0], 0x42);
        out[0] = 0;
        assert!(protocol_reply(&out, 512).is_err());
    }

    #[test]
    fn decodes_identify_controller() {
        let c = decode_controller(&sample_controller()).unwrap();
        assert_eq!(c.model, "Samsung SSD 970 EVO Plus 500GB");
        assert_eq!(c.serial, "S4EWNX0R123456");
        assert_eq!(c.firmware, "2B2QEXM7");
        assert!(c.format_supported);
        assert_eq!(
            c.sanicap,
            Sanicap {
                crypto: true,
                block: true,
                overwrite: false
            }
        );
        assert_eq!(
            c.fna,
            Fna {
                format_all: true,
                secure_erase_all: false,
                crypto_erase: true
            }
        );
        assert!(c.dsm);
        assert_eq!(c.tnvmcap, 500_107_862_016);
        assert!(decode_controller(&[0u8; 4096]).is_err());
    }

    #[test]
    fn decodes_identify_namespace() {
        let mut d = vec![0u8; 4096];
        d[0..8].copy_from_slice(&976_773_168u64.to_le_bytes());
        d[8..16].copy_from_slice(&976_773_168u64.to_le_bytes());
        d[25] = 1;
        d[26] = 1; // format 1
        d[128 + 2] = 9; // LBAF0 : 512
        d[132 + 2] = 12; // LBAF1 : 4096
        let n = decode_namespace(&d).unwrap();
        assert_eq!(n.lba_size, 4096);
        assert_eq!(n.lbaf_index, 1);
        assert_eq!(n.size_bytes(), 976_773_168 * 4096);
        assert_eq!(n.format_refusal(), None);
        d[26] = 0;
        assert_eq!(decode_namespace(&d).unwrap().lba_size, 512);
        // PI active (DPS octet 29) et métadonnées étendues (FLBAS bit 4) : Format refusé.
        d[29] = 1;
        let n = decode_namespace(&d).unwrap();
        assert_eq!(n.pi_type, 1);
        assert!(n.format_refusal().unwrap().contains("protection"));
        d[29] = 0;
        d[26] = 0x10;
        assert!(decode_namespace(&d)
            .unwrap()
            .format_refusal()
            .unwrap()
            .contains("étendu"));
        // Index de format > 15 (bits FLBAS 6:5).
        d[26] = 0x20;
        d[128 + 4 * 16 + 2] = 9;
        let n = decode_namespace(&d).unwrap();
        assert_eq!(n.lbaf_index, 16);
        assert!(n.format_refusal().unwrap().contains("> 15"));
        d[26] = 0;
        d[130] = 0;
        assert!(decode_namespace(&d).is_err());
    }

    #[test]
    fn decodes_health_log() {
        let mut d = vec![0u8; 512];
        d[0] = 0x04;
        d[1..3].copy_from_slice(&310u16.to_le_bytes());
        d[3] = 100;
        d[4] = 10;
        d[5] = 3;
        d[48..64].copy_from_slice(&20_000u128.to_le_bytes());
        d[112..128].copy_from_slice(&1500u128.to_le_bytes());
        d[128..144].copy_from_slice(&4321u128.to_le_bytes());
        d[144..160].copy_from_slice(&12u128.to_le_bytes());
        d[160..176].copy_from_slice(&1u128.to_le_bytes());
        let h = decode_health(&d).unwrap();
        assert_eq!(h.critical_warning, 4);
        assert_eq!(h.celsius(), Some(37));
        assert_eq!(h.percent_used, 3);
        assert_eq!(h.power_cycles, 1500);
        assert_eq!(h.power_on_hours, 4321);
        assert_eq!(h.unsafe_shutdowns, 12);
        assert_eq!(h.media_errors, 1);
        assert_eq!(HealthLog::bytes(h.data_units_written), 10_240_000_000);
        assert!(decode_health(&d[..100]).is_err());
    }

    #[test]
    fn decodes_sanitize_log() {
        let mut d = vec![0u8; 512];
        d[0..2].copy_from_slice(&0x4000u16.to_le_bytes());
        d[2..4].copy_from_slice(&(2u16 | (1 << 8)).to_le_bytes());
        d[4..8].copy_from_slice(&4u32.to_le_bytes());
        d[16..20].copy_from_slice(&30u32.to_le_bytes());
        let s = decode_sanitize_log(&d).unwrap();
        assert_eq!(s.state, SanitizeState::InProgress);
        assert!(s.global_data_erased);
        assert_eq!(s.scdw10, 4);
        assert_eq!(s.est_crypto, 30);
        assert!((s.percent() - 25.0).abs() < 1e-9);
        assert_eq!(s.progress_text(), "25.0 %");
        let mut never = d.clone();
        never[0..2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        never[2] = 0;
        assert_eq!(decode_sanitize_log(&never).unwrap().progress_text(), "—");
        d[2] = 3;
        assert_eq!(
            decode_sanitize_log(&d).unwrap().state,
            SanitizeState::Failed
        );
        d[2] = 4;
        assert_eq!(
            decode_sanitize_log(&d).unwrap().state,
            SanitizeState::SucceededForcedDeallocation
        );
    }
}
