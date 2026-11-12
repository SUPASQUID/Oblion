//! Disque physique brut (\\.\PhysicalDriveN) comme `BlockDevice`.
//! Ouverture en FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH : pas de cache Windows,
//! chaque écriture va jusqu'au disque. Tampons alignés fournis par le moteur.
//!
//! Seule porte d'entrée en écriture : `RawDisk::open(&PreparedDisk)`. Elle revérifie juste
//! avant l'ouverture la protection et l'identité du disque.

use std::io;

use crate::erase_hdd::BlockDevice;
use crate::safety::{OfflineGuard, PreparedDisk, ProtectContext};
use crate::winio::{self, Handle, GENERIC_READ, GENERIC_WRITE};

pub struct RawDisk {
    // Ordre de destruction : la poignée est fermée AVANT la remise en ligne.
    h: Handle,
    _offline: Option<OfflineGuard>,
    size: u64,
    sector: u32,
    /// Remarques à reporter sur le certificat (mise hors ligne impossible…).
    pub notes: Vec<String>,
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
    /// Ouvre le disque autorisé par `prep` en écriture.
    pub fn open(prep: &PreparedDisk) -> Result<RawDisk, String> {
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
        Ok(RawDisk {
            h,
            _offline: offline,
            size,
            sector,
            notes,
        })
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
    fn dry_run_authorisation_cannot_open_a_disk() {
        use crate::safety::tests::{disk, ok_ctx};
        let p =
            crate::safety::prepare_disk(&disk(99, "ZX9K4T17"), &ok_ctx(), "4T17", true).unwrap();
        let e = RawDisk::open(&p).err().unwrap();
        assert!(e.contains("non armée"), "{e}");
    }
}
