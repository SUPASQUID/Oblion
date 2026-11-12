//! Conversion des données SMART (ATA et NVMe) vers `report::SmartInfo` pour le certificat.
//!
//! ATA : table des attributs de SMART READ DATA (30 entrées de 12 octets à partir de l'octet 2 :
//! ID, drapeaux sur 2 octets, valeur, pire valeur, brut sur 6 octets) et seuils de
//! SMART READ THRESHOLDS (même disposition : ID puis seuil). Santé d'après RETURN STATUS.
//! NVMe : journal SMART/Health 02h ; santé PASSED si l'avertissement critique vaut 0.

use crate::ata::{Identify, Rotation, SmartHealth};
use crate::nvme::{HealthLog, NvmeController};
use crate::report::{SmartAttr, SmartInfo};

/// Noms usuels des attributs ATA (la signification exacte varie selon les constructeurs).
pub fn attr_name(id: u8) -> &'static str {
    match id {
        1 => "Raw_Read_Error_Rate",
        2 => "Throughput_Performance",
        3 => "Spin_Up_Time",
        4 => "Start_Stop_Count",
        5 => "Reallocated_Sector_Ct",
        7 => "Seek_Error_Rate",
        8 => "Seek_Time_Performance",
        9 => "Power_On_Hours",
        10 => "Spin_Retry_Count",
        11 => "Calibration_Retry_Count",
        12 => "Power_Cycle_Count",
        13 => "Read_Soft_Error_Rate",
        170 => "Available_Reservd_Space",
        171 => "Program_Fail_Count",
        172 => "Erase_Fail_Count",
        173 => "Wear_Leveling_Count",
        174 => "Unexpect_Power_Loss_Ct",
        177 => "Wear_Leveling_Count",
        179 => "Used_Rsvd_Blk_Cnt_Tot",
        180 => "Unused_Rsvd_Blk_Cnt_Tot",
        181 => "Program_Fail_Cnt_Total",
        182 => "Erase_Fail_Count_Total",
        183 => "Runtime_Bad_Block",
        184 => "End-to-End_Error",
        187 => "Reported_Uncorrect",
        188 => "Command_Timeout",
        189 => "High_Fly_Writes",
        190 => "Airflow_Temperature_Cel",
        191 => "G-Sense_Error_Rate",
        192 => "Power-Off_Retract_Count",
        193 => "Load_Cycle_Count",
        194 => "Temperature_Celsius",
        195 => "Hardware_ECC_Recovered",
        196 => "Reallocated_Event_Count",
        197 => "Current_Pending_Sector",
        198 => "Offline_Uncorrectable",
        199 => "UDMA_CRC_Error_Count",
        200 => "Multi_Zone_Error_Rate",
        202 => "Data_Address_Mark_Errs",
        220 => "Disk_Shift",
        222 => "Loaded_Hours",
        223 => "Load_Retry_Count",
        224 => "Load_Friction",
        225 => "Load_Cycle_Count",
        226 => "Load-in_Time",
        231 => "SSD_Life_Left",
        232 => "Available_Reservd_Space",
        233 => "Media_Wearout_Indicator",
        235 => "POR_Recovery_Count",
        240 => "Head_Flying_Hours",
        241 => "Total_LBAs_Written",
        242 => "Total_LBAs_Read",
        254 => "Free_Fall_Sensor",
        _ => "Inconnu",
    }
}

/// Attribut brut décodé (avant mise en forme).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawAttr {
    pub id: u8,
    pub flags: u16,
    pub value: u8,
    pub worst: u8,
    pub raw: u64,
    pub thresh: Option<u8>,
}

impl RawAttr {
    /// En défaut : valeur ≤ seuil avec un seuil non nul.
    pub fn failing(&self) -> bool {
        matches!(self.thresh, Some(t) if t > 0 && self.value <= t)
    }
}

/// Décode SMART READ DATA et, si disponibles, les seuils.
pub fn decode_ata_attrs(data: &[u8], thresholds: Option<&[u8]>) -> Vec<RawAttr> {
    let mut out = Vec::new();
    if data.len() < 362 {
        return out;
    }
    for i in 0..30 {
        let o = 2 + i * 12;
        let id = data[o];
        if id == 0 {
            continue;
        }
        let mut raw = [0u8; 8];
        raw[..6].copy_from_slice(&data[o + 5..o + 11]);
        let thresh = thresholds.and_then(|t| {
            (0..30)
                .map(|k| 2 + k * 12)
                .find(|&p| t.get(p) == Some(&id))
                .and_then(|p| t.get(p + 1).copied())
        });
        out.push(RawAttr {
            id,
            flags: u16::from_le_bytes([data[o + 1], data[o + 2]]),
            value: data[o + 3],
            worst: data[o + 4],
            raw: u64::from_le_bytes(raw),
            thresh,
        });
    }
    out
}

fn raw_text(a: &RawAttr) -> String {
    match a.id {
        // Température : l'octet bas porte la valeur courante (°C).
        190 | 194 => format!("{} °C", a.raw & 0xFF),
        // Heures : certains disques mettent des minutes/secondes dans les octets hauts.
        9 => (a.raw & 0xFFFF_FFFF).to_string(),
        _ => a.raw.to_string(),
    }
}

fn attr(attrs: &[RawAttr], id: u8) -> Option<&RawAttr> {
    attrs.iter().find(|a| a.id == id)
}

pub fn health_text(h: Option<SmartHealth>) -> String {
    match h {
        Some(SmartHealth::Passed) => "PASSED".into(),
        Some(SmartHealth::Failed) => "FAILED (seuil dépassé)".into(),
        Some(SmartHealth::Unknown) => "Indéterminé".into(),
        None => "Non lu".into(),
    }
}

/// SMART ATA → SmartInfo. `health` = résultat de SMART RETURN STATUS (None si non lu).
pub fn from_ata(
    id: &Identify,
    data: Option<&[u8]>,
    thresholds: Option<&[u8]>,
    health: Option<SmartHealth>,
) -> SmartInfo {
    let attrs = data
        .map(|d| decode_ata_attrs(d, thresholds))
        .unwrap_or_default();
    let mut info = vec![
        ("Source".to_string(), "ATA SMART".to_string()),
        ("Modèle (IDENTIFY)".to_string(), id.model.clone()),
        ("N° de série (IDENTIFY)".to_string(), id.serial.clone()),
        ("Firmware".to_string(), id.firmware.clone()),
        (
            "Rotation".to_string(),
            match id.rotation {
                Rotation::NonRotating => "Aucune (SSD)".to_string(),
                Rotation::Rpm(r) => format!("{r} tr/min"),
                _ => "Non rapportée".to_string(),
            },
        ),
        (
            "SMART".to_string(),
            match (id.smart_supported, id.smart_enabled) {
                (true, true) => "Supporté, activé",
                (true, false) => "Supporté, désactivé",
                _ => "Non supporté",
            }
            .to_string(),
        ),
    ];
    for (label, n) in [
        ("Heures de fonctionnement", 9u8),
        ("Cycles d'alimentation", 12),
        ("Secteurs réalloués", 5),
        ("Secteurs en attente", 197),
        ("Température", 194),
    ] {
        if let Some(a) = attr(&attrs, n) {
            info.push((label.to_string(), raw_text(a)));
        }
    }
    SmartInfo {
        info,
        health: health_text(health),
        attrs: attrs
            .iter()
            .map(|a| SmartAttr {
                id: a.id as u32,
                name: attr_name(a.id).to_string(),
                flags: format!("0x{:04X}", a.flags),
                value: format!("{:03}", a.value),
                worst: format!("{:03}", a.worst),
                thresh: a
                    .thresh
                    .map(|t| format!("{t:03}"))
                    .unwrap_or_else(|| "—".into()),
                raw: raw_text(a),
                failing: a.failing(),
            })
            .collect(),
    }
}

/// Octets lisibles (décimal, comme les fabricants).
pub fn human_bytes(b: u128) -> String {
    let f = b as f64;
    if f >= 1e12 {
        format!("{:.2} To", f / 1e12)
    } else if f >= 1e9 {
        format!("{:.1} Go", f / 1e9)
    } else {
        format!("{:.0} Mo", f / 1e6)
    }
}

/// SMART NVMe (journal 02h) → SmartInfo. Santé : PASSED si avertissement critique = 0.
pub fn from_nvme(ctrl: Option<&NvmeController>, h: &HealthLog) -> SmartInfo {
    let mut info = vec![("Source".to_string(), "NVMe SMART/Health (02h)".to_string())];
    if let Some(c) = ctrl {
        info.push(("Modèle (Identify)".into(), c.model.clone()));
        info.push(("N° de série (Identify)".into(), c.serial.clone()));
        info.push(("Firmware".into(), c.firmware.clone()));
    }
    info.extend([
        (
            "Avertissement critique".to_string(),
            format!("0x{:02X}", h.critical_warning),
        ),
        (
            "Température".to_string(),
            h.celsius()
                .map(|c| format!("{c} °C"))
                .unwrap_or_else(|| "—".into()),
        ),
        (
            "Réserve disponible".to_string(),
            format!("{} %", h.available_spare),
        ),
        (
            "Seuil de réserve".to_string(),
            format!("{} %", h.spare_threshold),
        ),
        (
            "Pourcentage utilisé".to_string(),
            format!("{} %", h.percent_used),
        ),
        (
            "Heures de fonctionnement".to_string(),
            h.power_on_hours.to_string(),
        ),
        (
            "Cycles d'alimentation".to_string(),
            h.power_cycles.to_string(),
        ),
        ("Arrêts brutaux".to_string(), h.unsafe_shutdowns.to_string()),
        ("Erreurs média".to_string(), h.media_errors.to_string()),
        (
            "Entrées journal d'erreurs".to_string(),
            h.error_log_entries.to_string(),
        ),
        (
            "Données écrites".to_string(),
            human_bytes(HealthLog::bytes(h.data_units_written)),
        ),
        (
            "Données lues".to_string(),
            human_bytes(HealthLog::bytes(h.data_units_read)),
        ),
    ]);
    SmartInfo {
        info,
        health: if h.critical_warning == 0 {
            "PASSED".into()
        } else {
            format!(
                "FAILED (avertissement critique 0x{:02X})",
                h.critical_warning
            )
        },
        attrs: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ata::decode_identify;

    fn entry(buf: &mut [u8], i: usize, id: u8, flags: u16, value: u8, worst: u8, raw: u64) {
        let o = 2 + i * 12;
        buf[o] = id;
        buf[o + 1..o + 3].copy_from_slice(&flags.to_le_bytes());
        buf[o + 3] = value;
        buf[o + 4] = worst;
        buf[o + 5..o + 11].copy_from_slice(&raw.to_le_bytes()[..6]);
    }

    fn thresh(buf: &mut [u8], i: usize, id: u8, t: u8) {
        let o = 2 + i * 12;
        buf[o] = id;
        buf[o + 1] = t;
    }

    #[test]
    fn decodes_attributes_with_thresholds_and_failing() {
        let mut d = vec![0u8; 512];
        let mut t = vec![0u8; 512];
        entry(&mut d, 0, 5, 0x0033, 1, 1, 4096);
        entry(&mut d, 1, 9, 0x0032, 90, 90, 12345 | (7u64 << 32));
        entry(&mut d, 2, 194, 0x0022, 64, 50, 36 | (50 << 16));
        entry(&mut d, 3, 199, 0x003E, 200, 200, 0);
        thresh(&mut t, 0, 9, 0);
        thresh(&mut t, 1, 5, 36);
        thresh(&mut t, 2, 194, 0);
        let a = decode_ata_attrs(&d, Some(&t));
        assert_eq!(a.len(), 4);
        assert_eq!(a[0].thresh, Some(36));
        assert!(a[0].failing(), "valeur 1 ≤ seuil 36");
        assert!(!a[1].failing(), "seuil nul : jamais en défaut");
        assert_eq!(a[3].thresh, None);
        assert!(!a[3].failing());

        let id = decode_identify(&crate::ata::tests::sample_identify()).unwrap();
        let s = from_ata(&id, Some(&d), Some(&t), Some(SmartHealth::Passed));
        assert_eq!(s.health, "PASSED");
        assert_eq!(s.attrs[0].name, "Reallocated_Sector_Ct");
        assert_eq!(s.attrs[0].thresh, "036");
        assert!(s.attrs[0].failing);
        assert_eq!(s.attrs[1].raw, "12345");
        assert_eq!(s.attrs[2].raw, "36 °C");
        assert_eq!(s.attrs[3].thresh, "—");
        assert!(s
            .info
            .iter()
            .any(|(k, v)| k == "Heures de fonctionnement" && v == "12345"));
        assert!(s
            .info
            .iter()
            .any(|(k, v)| k == "Rotation" && v == "Aucune (SSD)"));
    }

    #[test]
    fn ata_health_texts() {
        assert_eq!(
            health_text(Some(SmartHealth::Failed)),
            "FAILED (seuil dépassé)"
        );
        assert_eq!(health_text(None), "Non lu");
        assert_eq!(attr_name(197), "Current_Pending_Sector");
        assert_eq!(attr_name(250), "Inconnu");
        assert!(decode_ata_attrs(&[0u8; 10], None).is_empty());
    }

    #[test]
    fn nvme_health_passed_only_without_critical_warning() {
        let mut h = HealthLog {
            temperature_k: 300,
            power_on_hours: 1234,
            data_units_written: 2_000_000,
            ..Default::default()
        };
        let s = from_nvme(None, &h);
        assert_eq!(s.health, "PASSED");
        assert!(s
            .info
            .iter()
            .any(|(k, v)| k == "Température" && v == "27 °C"));
        assert!(s
            .info
            .iter()
            .any(|(k, v)| k == "Données écrites" && v == "1.02 To"));
        assert!(s.attrs.is_empty());
        h.critical_warning = 0x02;
        assert!(from_nvme(None, &h).health.starts_with("FAILED"));
    }
}
