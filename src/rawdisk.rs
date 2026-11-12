//! Disque physique brut (\\.\PhysicalDriveN) comme `BlockDevice`.
//! Ouverture en FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH : pas de cache Windows,
//! chaque écriture va jusqu'au disque. Tampons alignés fournis par le moteur.
//!
//! Seule porte d'entrée en écriture : `RawDisk::open_for(&PreparedDisk, firmware)`. Elle revérifie juste
//! avant l'ouverture la protection et l'identité du disque.

use std::io;
use std::mem::{offset_of, size_of};

use crate::ata::{self, AtaCmd, AtaError, AtaPort, AtaResult};
use crate::detect::Bus;
use crate::erase_hdd::BlockDevice;
use crate::erase_ssd::FirmwareDisk;
use crate::nvme::{self, NvmePort, SanitizeMethod};
use crate::safety::{OfflineGuard, PreparedDisk, ProtectContext};
use crate::winio::{self, Handle, GENERIC_READ, GENERIC_WRITE};

pub struct RawDisk {
    // Ordre de destruction : la poignée est fermée AVANT la remise en ligne.
    h: Handle,
    _offline: Option<OfflineGuard>,
    size: u64,
    sector: u32,
    /// Disque NVMe (sinon : commandes ATA).
    nvme: bool,
    /// Remarques à reporter sur le certificat (mise hors ligne impossible…).
    pub notes: Vec<String>,
}

// ---------- TRIM (winioctl.h) ----------

/// CTL_CODE(IOCTL_STORAGE_BASE (0x2d), 0x0501, METHOD_BUFFERED, FILE_WRITE_ACCESS)
pub const IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES: u32 = winio::ctl_code(0x2d, 0x501, 0, 2);
/// DeviceDsmAction_Trim
pub const DEVICE_DSM_ACTION_TRIM: u32 = 1;

/// Miroir de DEVICE_MANAGE_DATA_SET_ATTRIBUTES.
#[repr(C)]
pub struct DeviceManageDataSetAttributes {
    pub size: u32,
    pub action: u32,
    pub flags: u32,
    pub parameter_block_offset: u32,
    pub parameter_block_length: u32,
    pub data_set_ranges_offset: u32,
    pub data_set_ranges_length: u32,
}

/// Miroir de DEVICE_DATA_SET_RANGE / DEVICE_DSM_RANGE.
#[repr(C)]
pub struct DeviceDsmRange {
    pub starting_offset: i64,
    pub length_in_bytes: u64,
}

const DSM_HEADER: usize = size_of::<DeviceManageDataSetAttributes>();
/// Plages alignées sur __alignof(DEVICE_DSM_RANGE) = 8.
const DSM_RANGES_OFFSET: usize = DSM_HEADER.next_multiple_of(8);
const TRIM_RANGE_BYTES: u64 = 1 << 30;
const TRIM_RANGES_PER_CALL: usize = 64;

/// Découpe le disque en plages de TRIM (≤ 1 Gio, multiples du secteur), par lots.
pub fn trim_batches(size: u64, sector: u32) -> Vec<Vec<(u64, u64)>> {
    let ss = (sector as u64).max(512);
    let step = TRIM_RANGE_BYTES / ss * ss;
    let mut ranges = Vec::new();
    let mut off = 0;
    let end = size / ss * ss;
    while off < end {
        let n = step.min(end - off);
        ranges.push((off, n));
        off += n;
    }
    ranges
        .chunks(TRIM_RANGES_PER_CALL)
        .map(|c| c.to_vec())
        .collect()
}

/// Tampon d'entrée d'IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES (action TRIM).
pub fn trim_buffer(ranges: &[(u64, u64)]) -> Vec<u8> {
    let rsz = size_of::<DeviceDsmRange>();
    let mut b = vec![0u8; DSM_RANGES_OFFSET + rsz * ranges.len()];
    let put = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());
    put(
        &mut b,
        offset_of!(DeviceManageDataSetAttributes, size),
        DSM_HEADER as u32,
    );
    put(
        &mut b,
        offset_of!(DeviceManageDataSetAttributes, action),
        DEVICE_DSM_ACTION_TRIM,
    );
    put(
        &mut b,
        offset_of!(DeviceManageDataSetAttributes, data_set_ranges_offset),
        DSM_RANGES_OFFSET as u32,
    );
    put(
        &mut b,
        offset_of!(DeviceManageDataSetAttributes, data_set_ranges_length),
        (rsz * ranges.len()) as u32,
    );
    for (i, (start, len)) in ranges.iter().enumerate() {
        let o = DSM_RANGES_OFFSET + i * rsz;
        b[o..o + 8].copy_from_slice(&(*start as i64).to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&len.to_le_bytes());
    }
    b
}

/// (taille totale, octets par secteur) d'un DISK_GEOMETRY_EX.
pub fn parse_geometry(buf: &[u8]) -> Option<(u64, u32)> {
    if buf.len() < 32 {
        return None;
    }
    let sector = winio::u32_at(buf, 20);
    let size = i64::from_le_bytes(buf[24..32].try_into().ok()?);
    (sector > 0 && size > 0).then_some((size as u64, sector))
}

/// Taille exploitable : non nulle et multiple de la taille de secteur.
pub fn validate_size(size: u64, sector: u32) -> Result<(), String> {
    if size == 0 || sector == 0 {
        return Err("taille du disque nulle ou secteur inconnu".into());
    }
    if !size.is_multiple_of(sector as u64) {
        return Err(format!(
            "taille du disque ({size} octets) non multiple du secteur ({sector} octets)"
        ));
    }
    Ok(())
}

impl RawDisk {
    /// Ouvre le disque autorisé par `prep` en écriture (seule porte d'écriture).
    /// `firmware` : des commandes firmware suivront ; une sonde vérifie qu'elles passent
    /// disque hors ligne (sinon remise en ligne, volumes verrouillés, note au certificat).
    pub fn open_for(prep: &PreparedDisk, firmware: bool) -> Result<RawDisk, String> {
        if !prep.armed() {
            return Err(
                "autorisation non armée (--dry-run) : ouverture en écriture refusée".into(),
            );
        }
        let number = prep.number;

        // Revérification juste avant l'ouverture : protection et identité.
        let ctx = ProtectContext::detect();
        let now = crate::detect::reread_disk(number)?;
        if !ctx.reliable {
            return Err(format!(
                "protection des disques non fiable : {}",
                ctx.warnings.join(" ")
            ));
        }
        if let Some(p) = ctx.reason(&now) {
            return Err(format!("le disque {number} est désormais protégé : {p}"));
        }
        prep.check_same_disk(&now)?;

        let path = format!(r"\\.\PhysicalDrive{number}");
        let h = Handle::open_flags(
            &path,
            GENERIC_READ | GENERIC_WRITE,
            winio::FILE_FLAG_NO_BUFFERING | winio::FILE_FLAG_WRITE_THROUGH,
        )
        .map_err(|e| {
            format!("ouverture de {path} impossible (erreur Windows {e}) — droits administrateur ?")
        })?;

        let mut geo = [0u8; 64];
        winio::ioctl(&h, winio::IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut geo)
            .map_err(|e| format!("lecture de la géométrie impossible (erreur {e})"))?;
        let (geo_size, sector) = parse_geometry(&geo).ok_or("géométrie du disque invalide")?;
        // Taille exacte : IOCTL_DISK_GET_LENGTH_INFO, repli sur la géométrie.
        let mut len = [0u8; 8];
        let size = match winio::ioctl(&h, winio::IOCTL_DISK_GET_LENGTH_INFO, &[], &mut len) {
            Ok(_) if i64::from_le_bytes(len) > 0 => i64::from_le_bytes(len) as u64,
            _ => geo_size,
        };
        validate_size(size, sector)?;

        // Autorise l'écriture sur des zones couvertes par des volumes (déjà verrouillés).
        let _ = winio::ioctl(&h, winio::FSCTL_ALLOW_EXTENDED_DASD_IO, &[], &mut []);

        // Hors ligne APRÈS l'ouverture du handle brut ; remis en ligne par le garde.
        let mut notes = Vec::new();
        let offline = match OfflineGuard::take(number) {
            Ok(g) => Some(g),
            Err(e) => {
                if !prep.unlocked.is_empty() {
                    return Err(format!(
                        "mise hors ligne impossible (erreur {e}) et volumes non verrouillés ({}) : effacement refusé",
                        prep.unlocked.join(", ")
                    ));
                }
                notes.push(format!("Mise hors ligne du disque impossible (erreur Windows {e}) ; volumes verrouillés"));
                None
            }
        };
        let nvme = now.bus == Bus::Nvme;
        // Commandes firmware sur un disque hors ligne : non garanti par Windows. Sonde en
        // LECTURE SEULE sur la même poignée ; en cas d'échec, retour en ligne (volumes verrouillés).
        let offline = match (offline, firmware) {
            (Some(g), true) => {
                match offline_policy(probe_offline(&h, nvme, sector), &prep.unlocked) {
                    OfflinePolicy::KeepOffline => Some(g),
                    OfflinePolicy::GoOnline(note) => {
                        drop(g); // remise en ligne
                        notes.push(note);
                        None
                    }
                    OfflinePolicy::Refuse(e) => return Err(e),
                }
            }
            (g, _) => g,
        };
        Ok(RawDisk {
            h,
            _offline: offline,
            size,
            sector,
            nvme,
            notes,
        })
    }
}

/// Sonde en lecture seule après la mise hors ligne : IDENTIFY (ATA) ou journal SMART/Health
/// (NVMe), puis lecture du secteur 0 dans un tampon aligné.
fn probe_offline(h: &Handle, nvme: bool, sector: u32) -> Result<(), String> {
    if nvme {
        nvme::read_log_page(h, nvme::LOG_HEALTH, 512)?;
    } else {
        let r = ata::exec_on_handle(h, &ata::identify())
            .map_err(|e| format!("IDENTIFY DEVICE : {e}"))?;
        ata::decode_identify(&r.data)?;
    }
    let mut buf = crate::erase_hdd::AlignedBuf::new(sector as usize);
    winio::read_at(h, 0, buf.as_mut_slice())
        .map_err(|e| format!("lecture du secteur 0 : erreur Windows {e}"))
}

pub const NOTE_FIRMWARE_ONLINE: &str =
    "Commandes firmware envoyées disque en ligne (sonde hors ligne en échec)";

#[derive(Debug, PartialEq, Eq)]
pub enum OfflinePolicy {
    KeepOffline,
    /// Remise en ligne, volumes restant verrouillés.
    GoOnline(String),
    /// Volumes non verrouillés : impossible de repasser en ligne sans risque.
    Refuse(String),
}

/// Décision pure après la sonde hors ligne.
pub fn offline_policy(probe: Result<(), String>, unlocked: &[String]) -> OfflinePolicy {
    match probe {
        Ok(()) => OfflinePolicy::KeepOffline,
        Err(e) if unlocked.is_empty() => {
            OfflinePolicy::GoOnline(format!("{NOTE_FIRMWARE_ONLINE} : {e}"))
        }
        Err(e) => OfflinePolicy::Refuse(format!(
            "sonde du disque hors ligne en échec ({e}) et volumes non verrouillés ({}) : \
             remise en ligne impossible sans risque, effacement refusé",
            unlocked.join(", ")
        )),
    }
}

// Commandes firmware : uniquement via un RawDisk, donc avec une autorisation ARMÉE et les
// mêmes revérifications (protection, identité) que pour l'écriture.

impl AtaPort for RawDisk {
    fn exec(&mut self, cmd: &AtaCmd) -> Result<AtaResult, AtaError> {
        ata::exec_on_handle(&self.h, cmd)
    }
}

impl NvmePort for RawDisk {
    fn identify_controller(&mut self) -> Result<Vec<u8>, String> {
        nvme::read_identify_controller(&self.h)
    }
    fn identify_namespace(&mut self, nsid: u32) -> Result<Vec<u8>, String> {
        nvme::read_identify_namespace(&self.h, nsid)
    }
    fn log_page(&mut self, id: u8, len: u32) -> Result<Vec<u8>, String> {
        nvme::read_log_page(&self.h, id, len)
    }
    fn sanitize(&mut self, method: SanitizeMethod, timeout_secs: u32) -> Result<(), String> {
        nvme::reinitialize_media(&self.h, method, timeout_secs)
    }
    fn format(&mut self, ses: u8, lbaf: u8, timeout_secs: u32) -> Result<(), String> {
        // NSID ignoré hors requête adaptateur : le pilote utilise celui du disque ouvert.
        nvme::protocol_format(&self.h, ses, lbaf, 1, timeout_secs)
    }
}

impl FirmwareDisk for RawDisk {
    fn ata(&mut self) -> Option<&mut dyn AtaPort> {
        if self.nvme {
            None
        } else {
            Some(self)
        }
    }
    fn nvme(&mut self) -> Option<&mut dyn NvmePort> {
        if self.nvme {
            Some(self)
        } else {
            None
        }
    }
    fn trim_all(&mut self) -> Result<(), String> {
        for batch in trim_batches(self.size, self.sector) {
            let buf = trim_buffer(&batch);
            winio::ioctl(&self.h, IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES, &buf, &mut []).map_err(
                |e| {
                    format!(
                        "IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES (TRIM) refusé à l'octet {} : erreur Windows {e}",
                        batch[0].0
                    )
                },
            )?;
        }
        Ok(())
    }
}

fn io_err(code: u32) -> io::Error {
    io::Error::other(format!("erreur Windows {code}"))
}

impl BlockDevice for RawDisk {
    fn size(&self) -> u64 {
        self.size
    }
    fn sector_size(&self) -> u32 {
        self.sector
    }
    fn write_at(&mut self, off: u64, buf: &[u8]) -> io::Result<()> {
        winio::write_at(&self.h, off, buf).map_err(io_err)
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        winio::read_at(&self.h, off, buf).map_err(io_err)
    }
    fn flush(&mut self) -> io::Result<()> {
        winio::flush(&self.h).map_err(io_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_geometry() {
        let mut b = vec![0u8; 64];
        b[20..24].copy_from_slice(&512u32.to_le_bytes());
        b[24..32].copy_from_slice(&320_072_933_376i64.to_le_bytes());
        assert_eq!(parse_geometry(&b), Some((320_072_933_376, 512)));
        assert_eq!(parse_geometry(&[0u8; 64]), None);
        assert_eq!(parse_geometry(&[0u8; 8]), None);
    }

    #[test]
    fn size_must_be_whole_sectors() {
        assert!(validate_size(320_072_933_376, 512).is_ok());
        assert!(validate_size(0, 512).is_err());
        assert!(validate_size(1000, 512).is_err());
        assert!(validate_size(8192, 4096).is_ok());
    }

    #[test]
    fn dsm_structures_match_winioctl_h() {
        assert_eq!(IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES, 0x002D_9404);
        assert_eq!(DSM_HEADER, 28);
        assert_eq!(offset_of!(DeviceManageDataSetAttributes, action), 4);
        assert_eq!(offset_of!(DeviceManageDataSetAttributes, flags), 8);
        assert_eq!(
            offset_of!(DeviceManageDataSetAttributes, data_set_ranges_offset),
            20
        );
        assert_eq!(
            offset_of!(DeviceManageDataSetAttributes, data_set_ranges_length),
            24
        );
        assert_eq!(size_of::<DeviceDsmRange>(), 16);
        assert_eq!(offset_of!(DeviceDsmRange, length_in_bytes), 8);
        assert_eq!(DSM_RANGES_OFFSET, 32);
    }

    #[test]
    fn trim_buffer_and_batches() {
        let b = trim_buffer(&[(0, 4096), (1 << 30, 512)]);
        assert_eq!(b.len(), 32 + 32);
        assert_eq!(winio::u32_at(&b, 0), 28);
        assert_eq!(winio::u32_at(&b, 4), 1);
        assert_eq!(winio::u32_at(&b, 20), 32);
        assert_eq!(winio::u32_at(&b, 24), 32);
        assert_eq!(u64::from_le_bytes(b[40..48].try_into().unwrap()), 4096);
        assert_eq!(u64::from_le_bytes(b[48..56].try_into().unwrap()), 1 << 30);
        // 320 Go : 299 plages de 1 Gio (+ reste), lots de 64, couverture exacte.
        let size = 320_072_933_376u64;
        let batches = trim_batches(size, 512);
        let all: Vec<_> = batches.iter().flatten().copied().collect();
        assert!(batches.iter().all(|b| b.len() <= 64));
        assert_eq!(all.iter().map(|r| r.1).sum::<u64>(), size);
        assert!(all.windows(2).all(|w| w[0].0 + w[0].1 == w[1].0));
        assert!(all.iter().all(|r| r.0 % 512 == 0 && r.1 % 512 == 0));
        assert!(trim_batches(0, 512).is_empty());
    }

    #[test]
    fn offline_probe_policy() {
        assert_eq!(offline_policy(Ok(()), &[]), OfflinePolicy::KeepOffline);
        match offline_policy(Err("IDENTIFY DEVICE : erreur Windows 1".into()), &[]) {
            OfflinePolicy::GoOnline(n) => {
                assert!(n.starts_with(NOTE_FIRMWARE_ONLINE));
                assert!(n.contains("erreur Windows 1"));
            }
            p => panic!("{p:?}"),
        }
        assert!(matches!(
            offline_policy(Err("x".into()), &["E:".into()]),
            OfflinePolicy::Refuse(_)
        ));
    }

    #[test]
    fn dry_run_authorisation_cannot_open_a_disk() {
        use crate::safety::tests::{disk, ok_ctx};
        let p =
            crate::safety::prepare_disk(&disk(99, "ZX9K4T17"), &ok_ctx(), "4T17", true).unwrap();
        for fw in [false, true] {
            let e = RawDisk::open_for(&p, fw).err().unwrap();
            assert!(e.contains("non armée"), "{e}");
        }
        let e = RawDisk::open_for(&p, false).err().unwrap();
        assert!(e.contains("non armée"), "{e}");
    }
}
