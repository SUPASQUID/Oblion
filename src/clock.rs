//! Heure locale (sans dépendance) et formats d'affichage.

use windows_sys::Win32::Foundation::SYSTEMTIME;
use windows_sys::Win32::System::SystemInformation::GetLocalTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl DateTime {
    pub fn now() -> DateTime {
        // SAFETY: SYSTEMTIME est une structure de nombres ; GetLocalTime la remplit.
        let mut st: SYSTEMTIME = unsafe { std::mem::zeroed() };
        unsafe { GetLocalTime(&mut st) };
        DateTime {
            year: st.wYear,
            month: st.wMonth as u8,
            day: st.wDay as u8,
            hour: st.wHour as u8,
            minute: st.wMinute as u8,
            second: st.wSecond as u8,
        }
    }

    /// Format du rapport nwipe : 2026/11/09 22:03:00
    pub fn slash(&self) -> String {
        format!(
            "{:04}/{:02}/{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }

    /// Format français : 09/11/2026 22:03:00
    pub fn french(&self) -> String {
        format!(
            "{:02}/{:02}/{:04} {:02}:{:02}:{:02}",
            self.day, self.month, self.year, self.hour, self.minute, self.second
        )
    }

    /// 20261109-220300 (pour les n° de certificat et noms de fichiers)
    pub fn compact(&self) -> String {
        format!(
            "{:04}{:02}{:02}-{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

/// 29832 s -> "08:17:12"
pub fn hms(total_secs: u64) -> String {
    format!(
        "{:02}:{:02}:{:02}",
        total_secs / 3600,
        (total_secs / 60) % 60,
        total_secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let d = DateTime {
            year: 2026,
            month: 11,
            day: 9,
            hour: 22,
            minute: 3,
            second: 0,
        };
        assert_eq!(d.slash(), "2026/11/09 22:03:00");
        assert_eq!(d.french(), "09/11/2026 22:03:00");
        assert_eq!(d.compact(), "20261109-220300");
        assert_eq!(hms(29_832), "08:17:12");
        assert_eq!(hms(59), "00:00:59");
    }

    #[test]
    fn now_is_plausible() {
        assert!(DateTime::now().year >= 2025);
    }
}
