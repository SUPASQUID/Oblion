//! Détection des disques physiques (\\.\PhysicalDriveN).
//!
//! Lecture seule : on ouvre chaque disque avec un accès 0 (requêtes de propriétés uniquement),
//! jamais en écriture. SMART, HPA/DCO et capacités firmware : voir ata.rs / nvme.rs.

use std::fmt;

use crate::winio::{self, Handle};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    Scsi,
    Ata,
    Usb,
    Raid,
    Sas,
    Sata,
    Sd,
    Virtual,
    Nvme,
    Other(u32),
}

impl Bus {
    pub fn from_code(c: u32) -> Bus {
        match c {
            1 => Bus::Scsi,
            3 => Bus::Ata,
            7 => Bus::Usb,
            8 => Bus::Raid,
            10 => Bus::Sas,
            11 => Bus::Sata,
            12 | 13 => Bus::Sd,
            14 | 15 => Bus::Virtual,
            17 => Bus::Nvme,
            n => Bus::Other(n),
        }
    }
}

impl fmt::Display for Bus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bus::Scsi => f.write_str("SCSI"),
            Bus::Ata => f.write_str("ATA"),
            Bus::Usb => f.write_str("USB"),
            Bus::Raid => f.write_str("RAID"),
            Bus::Sas => f.write_str("SAS"),
            Bus::Sata => f.write_str("SATA"),
            Bus::Sd => f.write_str("SD"),
            Bus::Virtual => f.write_str("Virtuel"),
            Bus::Nvme => f.write_str("NVMe"),
            Bus::Other(n) => write!(f, "Autre({n})"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Hdd,
    Ssd,
    Nvme,
    Unknown,
}

impl MediaType {
    /// HDD/SSD d'après le bus et la « pénalité de seek » rapportée par le disque.
    /// Attention : certains ponts USB mentent ; on affiche alors Unknown plutôt que de deviner.
    pub fn classify(bus: Bus, incurs_seek_penalty: Option<bool>) -> MediaType {
        if bus == Bus::Nvme {
            return MediaType::Nvme;
        }
        match incurs_seek_penalty {
            Some(true) => MediaType::Hdd,
            Some(false) => MediaType::Ssd,
            None => MediaType::Unknown,
        }
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MediaType::Hdd => "HDD",
            MediaType::Ssd => "SSD",
            MediaType::Nvme => "NVMe",
            MediaType::Unknown => "?",
        })
    }
}

#[derive(Debug, Clone)]
pub struct DiskInfo {
    pub number: u32,
    pub path: String,
    pub vendor: String,
    pub model: String,
    pub serial: String,
    pub firmware: String,
    pub size_bytes: u64,
    pub bus: Bus,
    pub media: MediaType,
    /// RemovableMedia du STORAGE_DEVICE_DESCRIPTOR (affiché par --list).
    pub removable: bool,
    /// Lettres de volumes (C, D…) situées sur ce disque.
    pub volumes: Vec<char>,
}

impl DiskInfo {
    pub fn display_model(&self) -> String {
        if self.vendor.is_empty() || self.model.starts_with(&self.vendor) {
            self.model.clone()
        } else {
            format!("{} {}", self.vendor, self.model)
        }
    }
}

#[derive(Debug)]
pub enum DetectError {
    NeedAdmin,
    Io(u32),
}

impl fmt::Display for DetectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DetectError::NeedAdmin => f.write_str("droits administrateur requis"),
            DetectError::Io(c) => write!(f, "erreur Windows {c}"),
        }
    }
}

// ---------- Analyse pure des tampons Windows (testable sans disque) ----------

#[derive(Debug, PartialEq, Eq)]
pub struct Descriptor {
    pub removable: bool,
    pub vendor: String,
    pub model: String,
    pub firmware: String,
    pub serial: String,
    pub bus_code: u32,
}

/// Décode un STORAGE_DEVICE_DESCRIPTOR.
pub fn parse_device_descriptor(buf: &[u8]) -> Option<Descriptor> {
    if buf.len() < 32 {
        return None;
    }
    // Disposition : Version(4) Size(4) DeviceType(1) DeviceTypeModifier(1) RemovableMedia(1) à l'octet 10.
    Some(Descriptor {
        removable: buf[10] != 0,
        vendor: winio::cstr_at(buf, winio::u32_at(buf, 12) as usize),
        model: winio::cstr_at(buf, winio::u32_at(buf, 16) as usize),
        firmware: winio::cstr_at(buf, winio::u32_at(buf, 20) as usize),
        // Les n° de série NVMe se terminent par un « . » de remplissage (norme NVMe) : on l'enlève.
        serial: winio::cstr_at(buf, winio::u32_at(buf, 24) as usize)
            .trim_end_matches('.')
            .to_string(),
        bus_code: winio::u32_at(buf, 28),
    })
}

/// Numéros de disques d'un VOLUME_DISK_EXTENTS (un volume peut s'étendre sur plusieurs disques).
pub fn parse_disk_extents(buf: &[u8]) -> Vec<u32> {
    let count = winio::u32_at(buf, 0) as usize;
    let mut out = Vec::new();
    for i in 0..count {
        let off = 8 + i * 24;
        if off + 4 > buf.len() {
            break;
        }
        let n = winio::u32_at(buf, off);
        if !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

// ---------- Accès Windows ----------

fn query_property(h: &Handle, property_id: u32, out: &mut [u8]) -> bool {
    // STORAGE_PROPERTY_QUERY : PropertyId, QueryType (0 = standard), 1 octet de paramètres.
    let mut q = [0u8; 12];
    q[0..4].copy_from_slice(&property_id.to_le_bytes());
    winio::ioctl(h, winio::IOCTL_STORAGE_QUERY_PROPERTY, &q, out).is_ok()
}

/// DEVICE_TRIM_DESCRIPTOR (Version, Size, TrimEnabled à l'octet 8) → TRIM activé ?
pub fn parse_trim_descriptor(buf: &[u8]) -> Option<bool> {
    (buf.len() >= 9 && winio::u32_at(buf, 4) >= 9).then(|| buf[8] != 0)
}

/// StorageDeviceTrimProperty (8), en lecture seule. None si la propriété n'est pas lisible.
pub fn trim_enabled(number: u32) -> Option<bool> {
    let path = format!(r"\\.\PhysicalDrive{number}");
    let h = Handle::open(&path, winio::GENERIC_READ)
        .or_else(|_| Handle::open(&path, 0))
        .ok()?;
    let mut buf = [0u8; 16];
    query_property(&h, 8, &mut buf)
        .then_some(())
        .and_then(|_| parse_trim_descriptor(&buf))
}

/// Relit un seul disque (descripteur + taille) juste avant de l'ouvrir en écriture,
/// pour vérifier qu'il n'a pas changé depuis la confirmation.
pub fn reread_disk(number: u32) -> Result<DiskInfo, String> {
    read_disk(number)
        .map_err(|e| format!("relecture du disque {number} impossible (erreur Windows {e})"))
}

fn read_disk(number: u32) -> Result<DiskInfo, u32> {
    let path = format!(r"\\.\PhysicalDrive{number}");
    // Lecture seule : IOCTL_DISK_GET_LENGTH_INFO exige FILE_READ_ACCESS (jamais d'écriture ici).
    let h = Handle::open(&path, winio::GENERIC_READ).or_else(|_| Handle::open(&path, 0))?;

    let mut desc_buf = vec![0u8; 1024];
    if !query_property(&h, 0, &mut desc_buf) {
        return Err(winio::ERROR_FILE_NOT_FOUND);
    }
    let d = parse_device_descriptor(&desc_buf).ok_or(winio::ERROR_FILE_NOT_FOUND)?;
    let bus = Bus::from_code(d.bus_code);

    // 7 = StorageDeviceSeekPenaltyProperty ; IncursSeekPenalty à l'octet 8.
    let mut sp = [0u8; 16];
    let penalty = if query_property(&h, 7, &mut sp) {
        Some(sp[8] != 0)
    } else {
        None
    };

    let mut len = [0u8; 8];
    let mut size_bytes = match winio::ioctl(&h, winio::IOCTL_DISK_GET_LENGTH_INFO, &[], &mut len) {
        Ok(_) => i64::from_le_bytes(len).max(0) as u64,
        Err(_) => 0,
    };
    if size_bytes == 0 {
        let mut geo = [0u8; 64];
        if winio::ioctl(&h, winio::IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut geo).is_ok() {
            size_bytes = i64::from_le_bytes(geo[24..32].try_into().unwrap()).max(0) as u64;
        }
    }

    Ok(DiskInfo {
        number,
        path,
        vendor: d.vendor,
        model: d.model,
        serial: d.serial,
        firmware: d.firmware,
        size_bytes,
        bus,
        media: MediaType::classify(bus, penalty),
        removable: d.removable,
        volumes: Vec::new(),
    })
}

/// Un volume du système, avec ou sans lettre.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeInfo {
    /// `\\?\Volume{GUID}` SANS « \ » final (forme attendue par CreateFile pour le volume).
    pub path: String,
    pub letters: Vec<char>,
    /// Disques physiques portant au moins un extent du volume (vide si inconnu).
    pub disks: Vec<u32>,
}

impl VolumeInfo {
    /// Nom lisible : « E: » ou le chemin GUID pour un volume sans lettre (EFI, MSR…).
    pub fn label(&self) -> String {
        match self.letters.first() {
            Some(c) => format!("{c}:"),
            None => self.path.clone(),
        }
    }
}

/// Tous les volumes (FindFirstVolumeW/FindNextVolumeW), y compris sans lettre.
/// Le tampon des extents est agrandi si nécessaire (ERROR_MORE_DATA) : aucun extent perdu.
pub fn volumes() -> Vec<VolumeInfo> {
    winio::list_volume_guids()
        .into_iter()
        .map(|guid| {
            let path = guid.trim_end_matches('\\').to_string();
            let disks = Handle::open(&path, 0)
                .ok()
                .and_then(|h| {
                    winio::ioctl_dynamic(&h, winio::IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 256).ok()
                })
                .map(|b| parse_disk_extents(&b))
                .unwrap_or_default();
            VolumeInfo {
                letters: winio::volume_letters(&guid),
                path,
                disks,
            }
        })
        .collect()
}

/// Table pure lettre → disques à partir de la liste des volumes.
pub fn letter_map(vols: &[VolumeInfo]) -> Vec<(char, Vec<u32>)> {
    let mut out: Vec<(char, Vec<u32>)> = Vec::new();
    for v in vols.iter().filter(|v| !v.disks.is_empty()) {
        for &l in &v.letters {
            out.push((l, v.disks.clone()));
        }
    }
    out
}

/// Pour chaque lettre de volume existante : (lettre, disques physiques concernés).
pub fn volume_map() -> Vec<(char, Vec<u32>)> {
    letter_map(&volumes())
}

/// Liste tous les disques physiques (0..63) avec leurs volumes.
pub fn list_disks() -> Result<Vec<DiskInfo>, DetectError> {
    let mut disks = Vec::new();
    let mut denied = false;
    let mut last_err = 0;
    for n in 0..64 {
        match read_disk(n) {
            Ok(d) => disks.push(d),
            Err(winio::ERROR_ACCESS_DENIED) => denied = true,
            Err(winio::ERROR_FILE_NOT_FOUND) | Err(winio::ERROR_PATH_NOT_FOUND) => {}
            Err(e) => last_err = e,
        }
    }
    if disks.is_empty() {
        if denied {
            return Err(DetectError::NeedAdmin);
        }
        if last_err != 0 {
            return Err(DetectError::Io(last_err));
        }
    }
    for (letter, nums) in volume_map() {
        for n in nums {
            if let Some(d) = disks.iter_mut().find(|d| d.number == n) {
                d.volumes.push(letter);
            }
        }
    }
    Ok(disks)
}

/// Formate une taille en Mo/Go/To (décimal, comme les fabricants).
pub fn human_size(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1e12 {
        format!("{:.1} To", b / 1e12)
    } else if b >= 1e9 {
        format!("{:.0} Go", b / 1e9)
    } else {
        format!("{:.0} Mo", b / 1e6)
    }
}

/// Taille courte pour le code de confirmation : « 268M » sous 1 Go, sinon « 320G »
/// (mêmes arrondis que `human_size` en Mo/Go).
pub fn size_tag(bytes: u64) -> String {
    let b = bytes as f64;
    if b >= 1e9 {
        format!("{:.0}G", b / 1e9)
    } else {
        format!("{:.0}M", b / 1e6)
    }
}

/// N° de série pour la console : « (aucun) » s'il est vide.
pub fn serial_or_none(serial: &str) -> &str {
    if serial.trim().is_empty() {
        "(aucun)"
    } else {
        serial
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_descriptor() -> Vec<u8> {
        let mut b = vec![0u8; 128];
        b[5] = 1; // octet sans rapport (piège de l'ancien décodage)
        b[10] = 0; // RemovableMedia : non amovible
        b[12..16].copy_from_slice(&40u32.to_le_bytes());
        b[16..20].copy_from_slice(&48u32.to_le_bytes());
        b[20..24].copy_from_slice(&72u32.to_le_bytes());
        b[24..28].copy_from_slice(&80u32.to_le_bytes());
        b[28..32].copy_from_slice(&11u32.to_le_bytes()); // SATA
        b[40..44].copy_from_slice(b"ATA\0");
        b[48..66].copy_from_slice(b"ST320LM010-1KJ15\0\0");
        b[72..77].copy_from_slice(b"0002\0");
        b[80..89].copy_from_slice(b"ZX9K4T17\0");
        b
    }

    #[test]
    fn parses_descriptor() {
        let d = parse_device_descriptor(&fake_descriptor()).unwrap();
        assert_eq!(d.vendor, "ATA");
        assert_eq!(d.model, "ST320LM010-1KJ15");
        assert_eq!(d.serial, "ZX9K4T17");
        assert_eq!(d.firmware, "0002");
        assert_eq!(Bus::from_code(d.bus_code), Bus::Sata);
        assert!(!d.removable);
        let mut b = fake_descriptor();
        b[10] = 1;
        assert!(parse_device_descriptor(&b).unwrap().removable);
    }

    #[test]
    fn letter_map_keeps_multi_disk_volumes_and_skips_unknown() {
        let vols = vec![
            VolumeInfo {
                path: r"\\?\Volume{a}".into(),
                letters: vec!['C'],
                disks: vec![0],
            },
            VolumeInfo {
                path: r"\\?\Volume{b}".into(),
                letters: vec![],
                disks: vec![0],
            }, // EFI
            VolumeInfo {
                path: r"\\?\Volume{c}".into(),
                letters: vec!['E', 'F'],
                disks: vec![1, 2],
            },
            VolumeInfo {
                path: r"\\?\Volume{d}".into(),
                letters: vec!['Z'],
                disks: vec![],
            },
        ];
        assert_eq!(
            letter_map(&vols),
            vec![('C', vec![0]), ('E', vec![1, 2]), ('F', vec![1, 2])]
        );
        assert_eq!(vols[1].label(), r"\\?\Volume{b}");
        assert_eq!(vols[2].label(), "E:");
    }

    #[test]
    fn strips_nvme_serial_padding_dot() {
        let mut b = fake_descriptor();
        b[80..91].copy_from_slice(b"0025_D120.\0");
        let d = parse_device_descriptor(&b).unwrap();
        assert_eq!(d.serial, "0025_D120");
    }

    #[test]
    fn parses_trim_descriptor() {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&12u32.to_le_bytes());
        b[4..8].copy_from_slice(&12u32.to_le_bytes());
        b[8] = 1;
        assert_eq!(parse_trim_descriptor(&b), Some(true));
        b[8] = 0;
        assert_eq!(parse_trim_descriptor(&b), Some(false));
        assert_eq!(parse_trim_descriptor(&[0u8; 16]), None);
    }

    #[test]
    fn rejects_short_descriptor() {
        assert!(parse_device_descriptor(&[0u8; 10]).is_none());
    }

    #[test]
    fn parses_extents_without_duplicates() {
        let mut b = vec![0u8; 8 + 48];
        b[0..4].copy_from_slice(&2u32.to_le_bytes());
        b[8..12].copy_from_slice(&3u32.to_le_bytes());
        b[32..36].copy_from_slice(&3u32.to_le_bytes());
        assert_eq!(parse_disk_extents(&b), vec![3]);
        assert!(parse_disk_extents(&[]).is_empty());
    }

    #[test]
    fn classifies_media() {
        assert_eq!(MediaType::classify(Bus::Nvme, Some(false)), MediaType::Nvme);
        assert_eq!(MediaType::classify(Bus::Sata, Some(true)), MediaType::Hdd);
        assert_eq!(MediaType::classify(Bus::Sata, Some(false)), MediaType::Ssd);
        assert_eq!(MediaType::classify(Bus::Usb, None), MediaType::Unknown);
    }

    #[test]
    fn formats_sizes() {
        assert_eq!(human_size(320_072_933_376), "320 Go");
        assert_eq!(human_size(1_000_204_886_016), "1.0 To");
        assert_eq!(human_size(268_435_456), "268 Mo");
        assert_eq!(size_tag(268_435_456), "268M");
        assert_eq!(size_tag(320_072_933_376), "320G");
        assert_eq!(serial_or_none("  "), "(aucun)");
        assert_eq!(serial_or_none("ZX9K4T17"), "ZX9K4T17");
    }
}
