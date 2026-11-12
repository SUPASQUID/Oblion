//! Sécurités avant tout effacement : disques protégés, confirmation par n° de série,
//! verrouillage/démontage des volumes (y compris sans lettre), mise hors ligne, mode --dry-run.
//!
//! Règle : un disque qui a contenu Windows (même supprimé) reste effaçable ; seuls sont
//! bloqués le disque qui héberge le Windows en cours et celui qui héberge l'outil (clé USB).
//! Protection FERMÉE PAR DÉFAUT : si on ne sait pas identifier ces disques, on refuse tout.

use std::fmt;
use std::path::Path;

use crate::detect::{Bus, DiskInfo, VolumeInfo};
use crate::winio::{self, Handle, GENERIC_READ, GENERIC_WRITE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Héberge le système en cours d'exécution.
    RunningSystem,
    /// Héberge l'outil lui-même (clé USB de démarrage).
    BootMedia,
    /// WinPE chargé en RAM (outil sur X:) : la clé d'origine est inconnue, tout disque USB est protégé.
    UsbUnderWinPeRam,
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protection::RunningSystem => "Disque système en cours d'utilisation",
            Protection::BootMedia => "Clé de démarrage (contient l'outil)",
            Protection::UsbUnderWinPeRam => {
                "Disque USB (WinPE en RAM : clé de démarrage non identifiable)"
            }
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProtectContext {
    pub system_disks: Vec<u32>,
    pub media_disks: Vec<u32>,
    /// WinPE en RAM avec l'outil sur X: : tous les disques USB sont protégés.
    pub protect_usb: bool,
    /// Faux = impossible d'identifier les disques à protéger : tout effacement est refusé.
    pub reliable: bool,
    pub warnings: Vec<String>,
}

/// Lettre de lecteur d'un chemin (`E:\x`, `\\?\E:\x`), en majuscule. UNC → None.
pub fn drive_letter_of(path: &Path) -> Option<char> {
    let s = path.to_string_lossy();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    let mut it = s.chars();
    let c = it.next()?;
    (c.is_ascii_alphabetic() && it.next() == Some(':')).then(|| c.to_ascii_uppercase())
}

impl ProtectContext {
    /// Logique pure (testable sans Windows) : table lettre → disques, WinPE ou non,
    /// lettre du système et lettre de l'exécutable (None = UNC ou inconnue).
    pub fn evaluate(
        is_winpe: bool,
        system_letter: Option<char>,
        exe_letter: Option<char>,
        map: &[(char, Vec<u32>)],
    ) -> ProtectContext {
        let find = |l: Option<char>| {
            l.and_then(|l| map.iter().find(|(c, _)| *c == l.to_ascii_uppercase()))
                .map(|(_, d)| d.clone())
                .unwrap_or_default()
        };
        let system_letter = system_letter.map(|c| c.to_ascii_uppercase());
        let exe_letter = exe_letter.map(|c| c.to_ascii_uppercase());
        let mut ctx = ProtectContext {
            system_disks: find(system_letter),
            media_disks: find(exe_letter),
            protect_usb: false,
            reliable: true,
            warnings: Vec::new(),
        };
        // Sous WinPE, l'exe est « en RAM » s'il est sur le lecteur système (X: en général,
        // mais la lettre n'est pas codée en dur).
        let exe_on_ram = is_winpe && exe_letter.is_some() && exe_letter == system_letter;

        if !is_winpe && ctx.system_disks.is_empty() {
            ctx.reliable = false;
            ctx.warnings.push(format!(
                "Disque du Windows en cours introuvable (lecteur système {}) : protection non fiable, effacement refusé.",
                system_letter.map(|c| format!("{c}:")).unwrap_or_else(|| "inconnu".into())
            ));
        }
        if ctx.media_disks.is_empty() && !exe_on_ram {
            ctx.reliable = false;
            ctx.warnings.push(match exe_letter {
                Some(l) => format!(
                    "Disque contenant l'outil ({l}:) introuvable (lecteur réseau, subst… ?) : protection non fiable, effacement refusé."
                ),
                None => "L'outil est lancé depuis un chemin réseau (UNC) : disque de l'outil inconnu, effacement refusé."
                    .to_string(),
            });
        }
        if exe_on_ram {
            ctx.protect_usb = true;
            ctx.warnings.push(format!(
                "WinPE chargé en RAM (outil sur le lecteur système {}:) : la clé de démarrage n'est pas identifiable, TOUS les disques USB sont protégés.",
                exe_letter.unwrap_or('?')
            ));
        }
        ctx
    }

    /// Contexte réel : WinPE (SystemDrive = X: ou clé MiniNT), dossier Windows via
    /// GetSystemWindowsDirectoryW, lecteur de l'exécutable.
    pub fn detect() -> ProtectContext {
        let map = crate::detect::volume_map();
        let env_x = std::env::var("SystemDrive")
            .map(|s| s.trim().eq_ignore_ascii_case("X:"))
            .unwrap_or(false);
        let is_winpe = env_x || winio::hklm_key_exists(r"SYSTEM\CurrentControlSet\Control\MiniNT");
        let sys = winio::system_windows_dir().and_then(|d| drive_letter_of(Path::new(&d)));
        let exe = std::env::current_exe()
            .ok()
            .and_then(|p| drive_letter_of(&p));
        ProtectContext::evaluate(is_winpe, sys, exe, &map)
    }

    pub fn reason(&self, disk: &DiskInfo) -> Option<Protection> {
        if self.system_disks.contains(&disk.number) {
            Some(Protection::RunningSystem)
        } else if self.media_disks.contains(&disk.number) {
            Some(Protection::BootMedia)
        } else if self.protect_usb && disk.bus == Bus::Usb {
            Some(Protection::UsbUnderWinPeRam)
        } else {
            None
        }
    }
}

// ---------- Confirmation ----------

/// Code à saisir : 4 derniers caractères du n° de série (en majuscules).
/// Si ces 4 caractères sont identiques (ex. « 0000 »), le n° de série COMPLET est exigé.
/// Sans n° de série : « D<numéro>-<taille> », taille en Mo sous 1 Go (« D2-268M »),
/// sinon en Go (« D3-320G ») — mêmes arrondis que l'affichage de `--list`.
pub fn confirmation_code(disk: &DiskInfo) -> String {
    let s: Vec<char> = disk.serial.trim().chars().collect();
    if s.is_empty() {
        return format!(
            "D{}-{}",
            disk.number,
            crate::detect::size_tag(disk.size_bytes)
        );
    }
    let last: String = s[s.len().saturating_sub(4)..]
        .iter()
        .collect::<String>()
        .to_uppercase();
    let first = last.chars().next();
    if last.chars().all(|c| Some(c) == first) {
        disk.serial.trim().to_uppercase()
    } else {
        last
    }
}

pub fn confirmation_matches(disk: &DiskInfo, typed: &str) -> bool {
    let t = typed.trim().to_uppercase();
    !t.is_empty() && t == confirmation_code(disk)
}

// ---------- Préparation du disque ----------

/// Autorisation d'effacer UN disque précis. Seul `prepare_disk` la fabrique ; `RawDisk::open`
/// l'exige. Les volumes restent verrouillés tant que cette valeur vit.
pub struct PreparedDisk {
    pub number: u32,
    pub serial: String,
    pub model: String,
    pub size_bytes: u64,
    armed: bool,
    pub log: Vec<String>,
    /// Volumes du disque qui n'ont pas pu être verrouillés/démontés.
    pub unlocked: Vec<String>,
    /// Avertissements à reporter sur le certificat.
    pub warnings: Vec<String>,
    _locked: Vec<Handle>,
}

impl PreparedDisk {
    /// Faux en --dry-run : l'ouverture en écriture est alors refusée.
    pub fn armed(&self) -> bool {
        self.armed
    }

    /// Le disque relu maintenant est-il bien celui qui a été confirmé ?
    pub fn check_same_disk(&self, now: &DiskInfo) -> Result<(), String> {
        if now.number != self.number
            || now.serial != self.serial
            || now.display_model() != self.model
            || now.size_bytes != self.size_bytes
        {
            return Err(format!(
                "le disque {} a changé depuis la confirmation",
                self.number
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct PrepareError(pub String);

impl fmt::Display for PrepareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Barrière unique avant toute action destructive. À appeler par tous les modes d'effacement.
pub fn check_allowed(
    disk: &DiskInfo,
    ctx: &ProtectContext,
    typed_code: &str,
) -> Result<(), PrepareError> {
    if !ctx.reliable {
        return Err(PrepareError(format!(
            "Protection des disques non fiable, effacement refusé : {}",
            ctx.warnings.join(" ")
        )));
    }
    if let Some(p) = ctx.reason(disk) {
        return Err(PrepareError(format!(
            "Disque {} protégé : {p}",
            disk.number
        )));
    }
    if !confirmation_matches(disk, typed_code) {
        return Err(PrepareError(format!(
            "Confirmation incorrecte : saisir {} ({}).",
            if disk.serial.trim().is_empty() {
                "le code D<n°>-<taille> (taille en Mo « M » sous 1 Go, sinon en Go « G »)"
            } else {
                "le code demandé du n° de série"
            },
            confirmation_code(disk)
        )));
    }
    Ok(())
}

/// Verrouille et démonte chaque volume du disque (avec ou sans lettre).
/// La mise hors ligne se fait à l'ouverture (`RawDisk::open`), après l'ouverture du handle brut.
/// En `dry_run`, ne fait rien et décrit seulement ce qui serait fait (autorisation non armée).
pub fn prepare_disk(
    disk: &DiskInfo,
    ctx: &ProtectContext,
    typed_code: &str,
    dry_run: bool,
) -> Result<PreparedDisk, PrepareError> {
    check_allowed(disk, ctx, typed_code)?;
    prepare_with(disk, ctx, typed_code, dry_run, &crate::detect::volumes())
}

/// `all_vols` = tous les volumes du système : on verrouille ceux qui ont un extent sur le
/// disque et on signale ceux dont les disques sont inconnus (ils pourraient être dessus).
fn prepare_with(
    disk: &DiskInfo,
    ctx: &ProtectContext,
    typed_code: &str,
    dry_run: bool,
    all_vols: &[VolumeInfo],
) -> Result<PreparedDisk, PrepareError> {
    check_allowed(disk, ctx, typed_code)?;
    let vols: Vec<&VolumeInfo> = all_vols
        .iter()
        .filter(|v| v.disks.contains(&disk.number))
        .collect();
    let mut p = PreparedDisk {
        number: disk.number,
        serial: disk.serial.clone(),
        model: disk.display_model(),
        size_bytes: disk.size_bytes,
        armed: !dry_run,
        log: Vec::new(),
        unlocked: Vec::new(),
        warnings: Vec::new(),
        _locked: Vec::new(),
    };

    for v in &vols {
        let name = v.label();
        if dry_run {
            p.log
                .push(format!("[dry-run] verrouiller et démonter {name}"));
            continue;
        }
        match lock_and_dismount(&v.path) {
            Ok(h) => {
                p.log.push(format!("Volume {name} verrouillé et démonté"));
                p._locked.push(h);
            }
            Err(e) => {
                // Pas d'abandon immédiat (BitLocker verrouillé, RAW…) : la mise hors ligne sert de filet.
                let msg = format!("Volume {name} non verrouillé : {e}");
                p.log.push(format!("ATTENTION : {msg}"));
                p.warnings.push(msg);
                p.unlocked.push(name);
            }
        }
    }
    if vols.is_empty() {
        p.log.push(format!(
            "{}Aucun volume sur ce disque",
            if dry_run { "[dry-run] " } else { "" }
        ));
    }
    for v in all_vols.iter().filter(|v| v.disks.is_empty()) {
        let msg = format!(
            "Volume {} : disques inconnus (extents illisibles), il pourrait se trouver sur ce disque et n'est pas verrouillé",
            v.label()
        );
        p.log.push(format!("ATTENTION : {msg}"));
        p.warnings.push(msg);
    }
    if dry_run {
        p.log.push(format!(
            "[dry-run] mettre le disque {} hors ligne pendant l'effacement",
            disk.number
        ));
    }
    Ok(p)
}

fn lock_and_dismount(path: &str) -> Result<Handle, String> {
    let h = Handle::open(path, GENERIC_READ | GENERIC_WRITE)
        .map_err(|e| format!("ouverture impossible (erreur {e})"))?;
    // Le verrou échoue si un fichier est ouvert : quelques tentatives avant d'abandonner.
    let mut locked = false;
    for _ in 0..5 {
        if winio::ioctl(&h, winio::FSCTL_LOCK_VOLUME, &[], &mut []).is_ok() {
            locked = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if !locked {
        return Err("verrouillage refusé (fichiers ouverts ?)".into());
    }
    winio::ioctl(&h, winio::FSCTL_DISMOUNT_VOLUME, &[], &mut [])
        .map_err(|e| format!("démontage refusé (erreur {e})"))?;
    Ok(h)
}

// ---------- Hors ligne ----------

/// Octets d'un SET_DISK_ATTRIBUTES (Version, Persist, Attributes, AttributesMask).
pub fn offline_attributes_buffer(offline: bool) -> [u8; 40] {
    let mut b = [0u8; 40];
    b[0..4].copy_from_slice(&40u32.to_le_bytes()); // Version = sizeof
    b[4] = 0; // Persist = FALSE : l'état ne survit pas au redémarrage
    let attrs: u64 = if offline { 1 } else { 0 }; // DISK_ATTRIBUTE_OFFLINE
    b[8..16].copy_from_slice(&attrs.to_le_bytes());
    b[16..24].copy_from_slice(&1u64.to_le_bytes());
    b
}

fn set_offline(disk_number: u32, offline: bool) -> Result<(), u32> {
    let h = Handle::open(
        &format!(r"\\.\PhysicalDrive{disk_number}"),
        GENERIC_READ | GENERIC_WRITE,
    )?;
    winio::ioctl(
        &h,
        winio::IOCTL_DISK_SET_DISK_ATTRIBUTES,
        &offline_attributes_buffer(offline),
        &mut [],
    )
    .map(|_| ())
}

/// Disque mis hors ligne ; remis en ligne automatiquement à la destruction (fin d'effacement,
/// erreur ou Ctrl+C), quel que soit le chemin de sortie.
pub struct OfflineGuard(u32);

impl OfflineGuard {
    pub(crate) fn take(disk_number: u32) -> Result<OfflineGuard, u32> {
        set_offline(disk_number, true).map(|_| OfflineGuard(disk_number))
    }
}

impl Drop for OfflineGuard {
    fn drop(&mut self) {
        if let Err(e) = set_offline(self.0, false) {
            eprintln!("ATTENTION : remise en ligne du disque {} impossible (erreur {e}) ; elle se fera au redémarrage.", self.0);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::detect::MediaType;
    use std::path::PathBuf;

    pub fn disk(n: u32, serial: &str) -> DiskInfo {
        DiskInfo {
            number: n,
            path: format!(r"\\.\PhysicalDrive{n}"),
            vendor: String::new(),
            model: "TEST".into(),
            serial: serial.into(),
            firmware: String::new(),
            size_bytes: 320_000_000_000,
            bus: Bus::Sata,
            media: MediaType::Hdd,
            removable: false,
            volumes: vec![],
        }
    }

    /// Contexte fiable sans aucun disque protégé.
    pub fn ok_ctx() -> ProtectContext {
        ProtectContext {
            reliable: true,
            ..Default::default()
        }
    }

    fn vol(letter: Option<char>, d: u32) -> VolumeInfo {
        VolumeInfo {
            path: format!(r"\\?\Volume{{{d}-{letter:?}}}"),
            letters: letter.into_iter().collect(),
            disks: vec![d],
        }
    }

    #[test]
    fn drive_letters() {
        assert_eq!(
            drive_letter_of(&PathBuf::from(r"E:\DiskErase\x.exe")),
            Some('E')
        );
        assert_eq!(
            drive_letter_of(&PathBuf::from(r"\\?\e:\a\b.exe")),
            Some('E')
        );
        assert_eq!(
            drive_letter_of(&PathBuf::from(r"\\server\share\a.exe")),
            None
        );
    }

    #[test]
    fn context_protects_system_and_usb_only() {
        let map = vec![('C', vec![0]), ('E', vec![1]), ('D', vec![2])];
        let ctx = ProtectContext::evaluate(false, Some('C'), Some('e'), &map);
        assert!(ctx.reliable && ctx.warnings.is_empty());
        assert_eq!(ctx.reason(&disk(0, "A")), Some(Protection::RunningSystem));
        assert_eq!(ctx.reason(&disk(1, "B")), Some(Protection::BootMedia));
        // Disque 2 : ancien Windows ou données -> effaçable.
        assert_eq!(ctx.reason(&disk(2, "C")), None);
    }

    #[test]
    fn unknown_system_disk_outside_winpe_is_unreliable() {
        let map = vec![('E', vec![1])];
        let ctx = ProtectContext::evaluate(false, Some('C'), Some('E'), &map);
        assert!(!ctx.reliable);
        assert_eq!(ctx.warnings.len(), 1);
        assert!(check_allowed(&disk(3, "ZX9K4T17"), &ctx, "4T17")
            .unwrap_err()
            .0
            .contains("non fiable"));
    }

    #[test]
    fn exe_on_unc_or_subst_is_unreliable() {
        let map = vec![('C', vec![0])];
        // UNC : pas de lettre.
        assert!(!ProtectContext::evaluate(false, Some('C'), None, &map).reliable);
        // subst / lecteur réseau : lettre sans disque physique.
        assert!(!ProtectContext::evaluate(false, Some('C'), Some('S'), &map).reliable);
        // Même sous WinPE, une lettre autre que X: sans disque est refusée.
        assert!(!ProtectContext::evaluate(true, Some('X'), Some('S'), &map).reliable);
    }

    #[test]
    fn winpe_from_usb_key_protects_the_key() {
        // X: (RAM) n'a pas de disque physique ; l'outil est lancé depuis la clé E:.
        let map = vec![('E', vec![1])];
        let ctx = ProtectContext::evaluate(true, Some('X'), Some('E'), &map);
        assert!(ctx.reliable);
        assert!(ctx.system_disks.is_empty());
        assert_eq!(ctx.media_disks, vec![1]);
        assert!(!ctx.protect_usb);
    }

    #[test]
    fn winpe_in_ram_protects_every_usb_disk() {
        let map = vec![('D', vec![0])];
        let ctx = ProtectContext::evaluate(true, Some('X'), Some('X'), &map);
        assert!(ctx.reliable && ctx.protect_usb);
        assert_eq!(ctx.warnings.len(), 1);
        let mut usb = disk(4, "USB1234");
        usb.bus = Bus::Usb;
        assert_eq!(ctx.reason(&usb), Some(Protection::UsbUnderWinPeRam));
        assert_eq!(ctx.reason(&disk(0, "SATA1234")), None);
        assert!(check_allowed(&usb, &ctx, "1234").is_err());
    }

    #[test]
    fn winpe_ram_drive_is_the_system_letter_not_hardcoded_x() {
        let map = vec![('D', vec![0])];
        // WinPE monté en Y: : exe sur Y: = en RAM.
        let ctx = ProtectContext::evaluate(true, Some('Y'), Some('y'), &map);
        assert!(ctx.reliable && ctx.protect_usb);
        assert!(ctx.warnings[0].contains("Y:"));
        // Exe sur X: alors que le système est sur Y: : X: n'est pas la RAM -> disque inconnu -> refus.
        let ctx = ProtectContext::evaluate(true, Some('Y'), Some('X'), &map);
        assert!(!ctx.reliable && !ctx.protect_usb);
        // Hors WinPE, même lettre que le système : jamais considéré « en RAM ».
        let ctx = ProtectContext::evaluate(false, Some('C'), Some('C'), &[('C', vec![0])]);
        assert!(!ctx.protect_usb);
    }

    #[test]
    fn volumes_with_unknown_disks_are_warned() {
        let d = disk(2, "ZX9K4T17");
        let mut unknown = vol(Some('K'), 9);
        unknown.disks.clear();
        let vols = vec![vol(Some('F'), 2), vol(None, 5), unknown];
        let p = prepare_with(&d, &ok_ctx(), "4T17", true, &vols).unwrap();
        assert_eq!(p.warnings.len(), 1);
        assert!(p.warnings[0].contains("K:") && p.warnings[0].contains("inconnus"));
        assert!(p.log.iter().any(|l| l.starts_with("ATTENTION")));
        // Le volume du disque 5 n'est pas concerné.
        assert!(!p.log.iter().any(|l| l.contains("Volume{5")));
    }

    #[test]
    fn default_context_refuses_everything() {
        assert!(check_allowed(&disk(2, "ZX9K4T17"), &ProtectContext::default(), "4T17").is_err());
    }

    #[test]
    fn confirmation_uses_last_four_chars() {
        let d = disk(2, "ZX9K4T17");
        assert_eq!(confirmation_code(&d), "4T17");
        assert!(confirmation_matches(&d, " 4t17 "));
        assert!(!confirmation_matches(&d, "CP9"));
        assert!(!confirmation_matches(&d, ""));
    }

    #[test]
    fn confirmation_requires_full_serial_when_last_four_are_identical() {
        let d = disk(2, "ab120000");
        assert_eq!(confirmation_code(&d), "AB120000");
        assert!(!confirmation_matches(&d, "0000"));
        assert!(confirmation_matches(&d, "ab120000"));
    }

    #[test]
    fn confirmation_without_serial_uses_number_and_size() {
        let d = disk(5, "  ");
        assert_eq!(confirmation_code(&d), "D5-320G");
        assert!(confirmation_matches(&d, "d5-320g"));
        assert!(!confirmation_matches(&d, "D5"));
        assert!(!confirmation_matches(&d, "D5-320"));
        assert_eq!(confirmation_code(&disk(1, "AB")), "AB");
        // VHD de 256 Mio : taille en Mo, cohérente avec l'affichage « 268 Mo ».
        let mut vhd = disk(2, "");
        vhd.size_bytes = 268_435_456;
        assert_eq!(confirmation_code(&vhd), "D2-268M");
        assert_eq!(crate::detect::human_size(vhd.size_bytes), "268 Mo");
    }

    #[test]
    fn protected_disk_is_refused_even_with_right_code() {
        let ctx = ProtectContext {
            system_disks: vec![0],
            ..ok_ctx()
        };
        let d = disk(0, "FAKE0000SN1234");
        assert!(check_allowed(&d, &ctx, "1234").is_err());
    }

    #[test]
    fn wrong_code_is_refused_right_code_accepted() {
        let d = disk(2, "ZX9K4T17");
        assert!(check_allowed(&d, &ok_ctx(), "0000").is_err());
        assert!(check_allowed(&d, &ok_ctx(), "4t17").is_ok());
    }

    #[test]
    fn dry_run_touches_nothing_and_is_not_armed() {
        let d = disk(2, "ZX9K4T17");
        let vols = vec![vol(Some('F'), 2), vol(None, 2)];
        let p = prepare_with(&d, &ok_ctx(), "4T17", true, &vols).unwrap();
        assert!(!p.armed());
        assert!(
            p.log.iter().all(|l| l.starts_with("[dry-run]")),
            "{:?}",
            p.log
        );
        assert_eq!(p.log.len(), 3);
        assert!(
            p.log[1].contains(r"\\?\Volume"),
            "volume sans lettre listé : {:?}",
            p.log
        );
        assert_eq!(
            (p.number, p.serial.as_str(), p.size_bytes),
            (2, "ZX9K4T17", 320_000_000_000)
        );
    }

    #[test]
    fn dry_run_still_checks_the_rules() {
        let ctx = ProtectContext {
            system_disks: vec![2],
            ..ok_ctx()
        };
        assert!(prepare_with(&disk(2, "ZX9K4T17"), &ctx, "4T17", true, &[]).is_err());
        assert!(prepare_with(&disk(3, "ZX9K4T17"), &ok_ctx(), "XXXX", true, &[]).is_err());
    }

    #[test]
    fn changed_disk_is_detected() {
        let d = disk(2, "ZX9K4T17");
        let p = prepare_with(&d, &ok_ctx(), "4T17", true, &[]).unwrap();
        assert!(p.check_same_disk(&d).is_ok());
        let mut other = d.clone();
        other.serial = "XXXX4T17".into();
        assert_eq!(
            p.check_same_disk(&other).unwrap_err(),
            "le disque 2 a changé depuis la confirmation"
        );
        let mut other = d.clone();
        other.size_bytes += 512;
        assert!(p.check_same_disk(&other).is_err());
        let mut other = d.clone();
        other.model = "AUTRE".into();
        assert!(p.check_same_disk(&other).is_err());
    }

    #[test]
    fn offline_buffer_layout() {
        let b = offline_attributes_buffer(true);
        assert_eq!(&b[0..4], &40u32.to_le_bytes());
        assert_eq!(&b[8..16], &1u64.to_le_bytes());
        assert_eq!(&b[16..24], &1u64.to_le_bytes());
        assert_eq!(
            &offline_attributes_buffer(false)[8..16],
            &0u64.to_le_bytes()
        );
    }
}
