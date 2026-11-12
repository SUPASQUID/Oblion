//! Petite couche Win32 : poignées RAII et DeviceIoControl.
//! Tout le code `unsafe` d'accès aux disques passe par ici.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::CreateFileW;
use windows_sys::Win32::System::IO::DeviceIoControl;

pub const GENERIC_READ: u32 = 0x8000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
const FILE_SHARE_READ: u32 = 1;
const FILE_SHARE_WRITE: u32 = 2;
const OPEN_EXISTING: u32 = 3;

pub const ERROR_FILE_NOT_FOUND: u32 = 2;
pub const ERROR_PATH_NOT_FOUND: u32 = 3;
pub const ERROR_ACCESS_DENIED: u32 = 5;

/// Équivalent de la macro CTL_CODE de Windows.
pub const fn ctl_code(device: u32, function: u32, method: u32, access: u32) -> u32 {
    (device << 16) | (access << 14) | (function << 2) | method
}

const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;
const FILE_READ_ACCESS: u32 = 1;
const FILE_WRITE_ACCESS: u32 = 2;
const FILE_DEVICE_DISK: u32 = 7;
const FILE_DEVICE_FILE_SYSTEM: u32 = 9;
const IOCTL_STORAGE_BASE: u32 = 0x2d;
const IOCTL_VOLUME_BASE: u32 = 0x56;

pub const IOCTL_STORAGE_QUERY_PROPERTY: u32 =
    ctl_code(IOCTL_STORAGE_BASE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_DISK_GET_LENGTH_INFO: u32 =
    ctl_code(FILE_DEVICE_DISK, 0x17, METHOD_BUFFERED, FILE_READ_ACCESS);
/// Géométrie étendue : accessible sans droit de lecture, contient la taille totale à l'octet 24.
pub const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 =
    ctl_code(FILE_DEVICE_DISK, 0x28, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const IOCTL_DISK_SET_DISK_ATTRIBUTES: u32 = ctl_code(
    FILE_DEVICE_DISK,
    0x3d,
    METHOD_BUFFERED,
    FILE_READ_ACCESS | FILE_WRITE_ACCESS,
);
pub const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 =
    ctl_code(IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const FSCTL_LOCK_VOLUME: u32 =
    ctl_code(FILE_DEVICE_FILE_SYSTEM, 6, METHOD_BUFFERED, FILE_ANY_ACCESS);
pub const FSCTL_DISMOUNT_VOLUME: u32 =
    ctl_code(FILE_DEVICE_FILE_SYSTEM, 8, METHOD_BUFFERED, FILE_ANY_ACCESS);

/// Poignée Windows fermée automatiquement.
pub struct Handle(HANDLE);

// Une poignée de fichier peut passer d'un thread à l'autre.
unsafe impl Send for Handle {}

impl Handle {
    /// Ouvre un périphérique (`\\.\PhysicalDrive0`, `\\.\C:`…). Erreur = code GetLastError.
    pub fn open(path: &str, access: u32) -> Result<Handle, u32> {
        Handle::open_flags(path, access, 0)
    }

    /// Comme `open` avec des FILE_FLAG_* (NO_BUFFERING, WRITE_THROUGH…).
    pub fn open_flags(path: &str, access: u32, flags: u32) -> Result<Handle, u32> {
        let wide: Vec<u16> = OsStr::new(path).encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` est terminé par un zéro et vit pendant l'appel.
        let h = unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                flags,
                ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE || h.is_null() {
            // SAFETY: simple lecture du dernier code d'erreur du thread.
            Err(unsafe { GetLastError() })
        } else {
            Ok(Handle(h))
        }
    }

    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: la poignée est valide et n'est fermée qu'ici.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// DeviceIoControl avec tampons d'octets. Renvoie le nombre d'octets écrits en sortie.
pub fn ioctl(h: &Handle, code: u32, input: &[u8], output: &mut [u8]) -> Result<u32, u32> {
    let mut returned: u32 = 0;
    let (in_ptr, in_len) = if input.is_empty() {
        (ptr::null(), 0)
    } else {
        (input.as_ptr().cast(), input.len() as u32)
    };
    let (out_ptr, out_len) = if output.is_empty() {
        (ptr::null_mut(), 0)
    } else {
        (output.as_mut_ptr().cast(), output.len() as u32)
    };
    // SAFETY: les pointeurs et longueurs proviennent de tranches valides pendant l'appel.
    let ok = unsafe {
        DeviceIoControl(
            h.raw(),
            code,
            in_ptr,
            in_len,
            out_ptr,
            out_len,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok != 0 {
        Ok(returned)
    } else {
        // SAFETY: lecture du code d'erreur.
        Err(unsafe { GetLastError() })
    }
}

pub const FILE_FLAG_WRITE_THROUGH: u32 = 0x8000_0000;
pub const FILE_FLAG_NO_BUFFERING: u32 = 0x2000_0000;
/// Autorise l'écriture sur des zones couvertes par des volumes (volumes verrouillés).
pub const FSCTL_ALLOW_EXTENDED_DASD_IO: u32 = 0x0009_0083;

fn seek(h: &Handle, off: u64) -> Result<(), u32> {
    use windows_sys::Win32::Storage::FileSystem::SetFilePointerEx;
    // SAFETY: poignée valide, pointeur de sortie nul autorisé.
    if unsafe { SetFilePointerEx(h.raw(), off as i64, ptr::null_mut(), 0) } != 0 {
        Ok(())
    } else {
        Err(unsafe { GetLastError() })
    }
}

/// Écrit tout `buf` à la position `off` (tampon aligné requis avec NO_BUFFERING).
pub fn write_at(h: &Handle, off: u64, buf: &[u8]) -> Result<(), u32> {
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    seek(h, off)?;
    let mut written: u32 = 0;
    // SAFETY: `buf` valide pendant l'appel, appel synchrone (pas d'OVERLAPPED).
    let ok = unsafe {
        WriteFile(
            h.raw(),
            buf.as_ptr().cast(),
            buf.len() as u32,
            &mut written,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(unsafe { GetLastError() })
    } else if written as usize != buf.len() {
        Err(0xFFFF_FFFF)
    } else {
        Ok(())
    }
}

pub fn read_at(h: &Handle, off: u64, buf: &mut [u8]) -> Result<(), u32> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    seek(h, off)?;
    let mut read: u32 = 0;
    // SAFETY: `buf` valide en écriture pendant l'appel, appel synchrone.
    let ok = unsafe {
        ReadFile(
            h.raw(),
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
            &mut read,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(unsafe { GetLastError() })
    } else if read as usize != buf.len() {
        Err(0xFFFF_FFFF)
    } else {
        Ok(())
    }
}

pub fn flush(h: &Handle) -> Result<(), u32> {
    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
    // SAFETY: poignée valide.
    if unsafe { FlushFileBuffers(h.raw()) } != 0 {
        Ok(())
    } else {
        Err(unsafe { GetLastError() })
    }
}

pub const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
pub const ERROR_MORE_DATA: u32 = 234;

/// DeviceIoControl dont la sortie est de taille variable : agrandit le tampon tant que
/// Windows répond ERROR_MORE_DATA / ERROR_INSUFFICIENT_BUFFER (plafond 1 Mio).
pub fn ioctl_dynamic(h: &Handle, code: u32, initial: usize) -> Result<Vec<u8>, u32> {
    let mut size = initial.max(64);
    loop {
        let mut buf = vec![0u8; size];
        match ioctl(h, code, &[], &mut buf) {
            // Tampon entier rendu : la structure porte elle-même son nombre d'éléments.
            Ok(_) => return Ok(buf),
            Err(ERROR_MORE_DATA) | Err(ERROR_INSUFFICIENT_BUFFER) if size < (1 << 20) => size *= 4,
            Err(e) => return Err(e),
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Tous les volumes du système (`\\?\Volume{GUID}\`), avec ou sans lettre (EFI, MSR, récupération…).
pub fn list_volume_guids() -> Vec<String> {
    use windows_sys::Win32::Storage::FileSystem::{
        FindFirstVolumeW, FindNextVolumeW, FindVolumeClose,
    };
    let mut out = Vec::new();
    let mut buf = [0u16; 512];
    // SAFETY: tampon local de 512 caractères, taille passée correctement.
    let h = unsafe { FindFirstVolumeW(buf.as_mut_ptr(), buf.len() as u32) };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return out;
    }
    loop {
        out.push(from_wide(&buf));
        buf.fill(0);
        // SAFETY: même tampon, poignée de recherche valide.
        if unsafe { FindNextVolumeW(h, buf.as_mut_ptr(), buf.len() as u32) } == 0 {
            break;
        }
    }
    // SAFETY: poignée de recherche ouverte par FindFirstVolumeW.
    unsafe { FindVolumeClose(h) };
    out
}

/// Lettres de lecteur d'un volume (`\\?\Volume{GUID}\`).
pub fn volume_letters(guid_path: &str) -> Vec<char> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumePathNamesForVolumeNameW;
    let name = wide(guid_path);
    let mut buf = vec![0u16; 1024];
    let mut needed = 0u32;
    // SAFETY: chaînes terminées par zéro, tailles exactes.
    let ok = unsafe {
        GetVolumePathNamesForVolumeNameW(
            name.as_ptr(),
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut needed,
        )
    };
    if ok == 0 {
        return Vec::new();
    }
    // Liste de chaînes séparées par des zéros, terminée par un double zéro.
    String::from_utf16_lossy(&buf)
        .split('\0')
        .filter_map(|p| {
            let mut it = p.chars();
            let c = it.next()?;
            (c.is_ascii_alphabetic() && it.next() == Some(':') && p.len() <= 3)
                .then(|| c.to_ascii_uppercase())
        })
        .collect()
}

/// Dossier Windows réel (GetSystemWindowsDirectoryW), indépendant des variables d'environnement.
pub fn system_windows_dir() -> Option<String> {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    let mut buf = [0u16; 512];
    // SAFETY: tampon local, taille correcte.
    let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) } as usize;
    (n > 0 && n < buf.len()).then(|| from_wide(&buf[..n]))
}

/// La clé HKLM\<subkey> existe-t-elle ? Ouverture en LECTURE SEULE, aucune écriture.
pub fn hklm_key_exists(subkey: &str) -> bool {
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    };
    let name = wide(subkey);
    let mut key: HKEY = ptr::null_mut();
    // SAFETY: nom terminé par zéro, pointeur de sortie local.
    let rc = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, name.as_ptr(), 0, KEY_READ, &mut key) };
    if rc == 0 {
        // SAFETY: clé ouverte juste au-dessus.
        unsafe { RegCloseKey(key) };
        true
    } else {
        false
    }
}

/// Lit un u32 little-endian à `off` (0 si hors limites).
pub fn u32_at(buf: &[u8], off: usize) -> u32 {
    buf.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .unwrap_or(0)
}

/// Lit une chaîne ASCII terminée par 0 à `off` (vide si off == 0 ou hors limites).
pub fn cstr_at(buf: &[u8], off: usize) -> String {
    if off == 0 || off >= buf.len() {
        return String::new();
    }
    let end = buf[off..]
        .iter()
        .position(|&b| b == 0)
        .map_or(buf.len(), |p| off + p);
    String::from_utf8_lossy(&buf[off..end]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctl_codes_match_windows_headers() {
        assert_eq!(IOCTL_STORAGE_QUERY_PROPERTY, 0x002D_1400);
        assert_eq!(IOCTL_DISK_GET_LENGTH_INFO, 0x0007_405C);
        assert_eq!(IOCTL_DISK_SET_DISK_ATTRIBUTES, 0x0007_C0F4);
        assert_eq!(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, 0x0007_00A0);
        assert_eq!(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, 0x0056_0000);
        assert_eq!(FSCTL_LOCK_VOLUME, 0x0009_0018);
        assert_eq!(FSCTL_DISMOUNT_VOLUME, 0x0009_0020);
    }

    #[test]
    fn cstr_and_u32_helpers() {
        let buf = b"\0\0ABC  \0xyz";
        assert_eq!(cstr_at(buf, 2), "ABC");
        assert_eq!(cstr_at(buf, 0), "");
        assert_eq!(cstr_at(buf, 999), "");
        assert_eq!(u32_at(&[1, 0, 0, 0, 9], 0), 1);
        assert_eq!(u32_at(&[1, 0], 0), 0);
    }
}
