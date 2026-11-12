//! Zones cachées ATA : HPA (Host Protected Area) et DCO (Device Configuration Overlay).
//!
//! DÉTECTION SEULEMENT : on compare IDENTIFY (secteurs visibles), READ NATIVE MAX ADDRESS
//! (fin de la HPA) et DEVICE CONFIGURATION IDENTIFY (fin réelle avant DCO). Aucune commande
//! SET MAX / DCO SET / DCO RESTORE n'est jamais envoyée.

/// Lecture DCO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DcoReading {
    /// Le disque ne déclare pas DCO (mot 83 bit 11) : rien ne peut être caché par DCO.
    Unsupported,
    /// Dernier LBA selon DCO IDENTIFY.
    MaxLba(u64),
    Error(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Hidden {
    /// Ancien comportement (historique) : pas de lecture.
    #[default]
    NotChecked,
    /// NVMe, fichier de test… : la notion ne s'applique pas.
    NotApplicable(String),
    /// Lecture impossible (pont USB, droits, commande refusée…).
    Unreadable(String),
    Checked {
        /// Secteurs visibles (IDENTIFY).
        visible: u64,
        /// Secteurs jusqu'à l'adresse native maximale (HPA comprise).
        native: u64,
        /// Secteurs selon DCO (None = DCO non supporté).
        dco: Option<u64>,
        /// DCO supporté mais illisible.
        dco_error: Option<String>,
        sector: u32,
    },
}

/// Comparaison pure. `native_max_lba` et le DCO sont des DERNIERS LBA (nombre = LBA + 1).
pub fn compare(
    visible: u64,
    sector: u32,
    native_max_lba: Result<u64, String>,
    dco: DcoReading,
) -> Hidden {
    let native = match native_max_lba {
        Ok(lba) => lba + 1,
        Err(e) => return Hidden::Unreadable(e),
    };
    let (dco, dco_error) = match dco {
        DcoReading::Unsupported => (None, None),
        DcoReading::MaxLba(l) => (Some(l + 1), None),
        DcoReading::Error(e) => (None, Some(e)),
    };
    Hidden::Checked {
        visible,
        native,
        dco,
        dco_error,
        sector,
    }
}

impl Hidden {
    /// Secteurs cachés par HPA (adresse native au-delà des secteurs visibles).
    pub fn hpa_sectors(&self) -> u64 {
        match self {
            Hidden::Checked {
                visible, native, ..
            } => native.saturating_sub(*visible),
            _ => 0,
        }
    }

    /// Secteurs cachés par DCO (au-delà de l'adresse native).
    pub fn dco_sectors(&self) -> u64 {
        match self {
            Hidden::Checked {
                native,
                dco: Some(d),
                ..
            } => d.saturating_sub(*native),
            _ => 0,
        }
    }

    /// Secteurs cachés : Some(n) si l'état est CONNU (0 = rien de caché ou notion non
    /// applicable), None si la zone cachée est inconnue (non lue, illisible, DCO illisible).
    pub fn hidden_sectors(&self) -> Option<u64> {
        match self {
            Hidden::NotApplicable(_) => Some(0),
            Hidden::Checked {
                dco_error: None, ..
            } => Some(self.hpa_sectors() + self.dco_sectors()),
            _ => None,
        }
    }

    /// Zone cachée inconnue : effacement complet non garanti hors Sanitize.
    pub fn unknown(&self) -> bool {
        self.hidden_sectors().is_none()
    }

    /// Texte du champ HPA/DCO du certificat.
    pub fn label(&self) -> String {
        match self {
            Hidden::NotChecked => "Non vérifié".into(),
            Hidden::NotApplicable(r) => format!("Non applicable ({r})"),
            Hidden::Unreadable(r) => format!("Non lisible ({r})"),
            Hidden::Checked { dco_error, .. } => {
                let mut parts = Vec::new();
                let (h, d) = (self.hpa_sectors(), self.dco_sectors());
                if h > 0 {
                    parts.push(format!("HPA : {h} secteurs cachés"));
                }
                if d > 0 {
                    parts.push(format!("DCO : {d} secteurs cachés"));
                }
                if parts.is_empty() {
                    parts.push("Aucun secteur caché".into());
                }
                if let Some(e) = dco_error {
                    parts.push(format!("DCO non lisible ({e})"));
                }
                parts.join(" ; ")
            }
        }
    }

    /// Taille physique réelle, si elle est entièrement connue.
    pub fn real_size_bytes(&self) -> Option<u64> {
        match self {
            Hidden::Checked {
                native,
                dco,
                dco_error: None,
                sector,
                ..
            } => Some(dco.unwrap_or(*native).max(*native) * *sector as u64),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VIS: u64 = 625_142_448;

    #[test]
    fn nothing_hidden() {
        let h = compare(VIS, 512, Ok(VIS - 1), DcoReading::MaxLba(VIS - 1));
        assert_eq!(h.hidden_sectors(), Some(0));
        assert_eq!(h.label(), "Aucun secteur caché");
        assert_eq!(h.real_size_bytes(), Some(VIS * 512));
        let h = compare(VIS, 512, Ok(VIS - 1), DcoReading::Unsupported);
        assert_eq!(h.label(), "Aucun secteur caché");
        assert_eq!(h.real_size_bytes(), Some(VIS * 512));
    }

    #[test]
    fn hpa_is_detected() {
        let h = compare(VIS - 1000, 512, Ok(VIS - 1), DcoReading::MaxLba(VIS - 1));
        assert_eq!(h.hpa_sectors(), 1000);
        assert_eq!(h.dco_sectors(), 0);
        assert_eq!(h.label(), "HPA : 1000 secteurs cachés");
        assert_eq!(h.real_size_bytes(), Some(VIS * 512));
    }

    #[test]
    fn dco_is_detected_and_combined_with_hpa() {
        let h = compare(VIS, 512, Ok(VIS - 1), DcoReading::MaxLba(VIS + 4095));
        assert_eq!(h.label(), "DCO : 4096 secteurs cachés");
        let h = compare(VIS - 10, 512, Ok(VIS - 1), DcoReading::MaxLba(VIS + 9));
        assert_eq!(h.hidden_sectors(), Some(20));
        assert_eq!(
            h.label(),
            "HPA : 10 secteurs cachés ; DCO : 10 secteurs cachés"
        );
        assert_eq!(h.real_size_bytes(), Some((VIS + 10) * 512));
    }

    #[test]
    fn unreadable_cases() {
        let h = compare(
            VIS,
            512,
            Err("READ NATIVE MAX : refusée".into()),
            DcoReading::Unsupported,
        );
        assert!(h.label().starts_with("Non lisible"));
        assert_eq!(h.hidden_sectors(), None);
        assert!(h.unknown());
        assert_eq!(h.real_size_bytes(), None);
        let h = compare(VIS, 512, Ok(VIS - 1), DcoReading::Error("ABRT".into()));
        assert_eq!(h.label(), "Aucun secteur caché ; DCO non lisible (ABRT)");
        assert_eq!(h.real_size_bytes(), None, "taille réelle inconnue sans DCO");
        assert_eq!(
            h.hidden_sectors(),
            None,
            "DCO illisible : zone cachée inconnue"
        );
        assert!(Hidden::NotChecked.unknown());
        assert_eq!(
            Hidden::NotApplicable("NVMe".into()).hidden_sectors(),
            Some(0)
        );
        assert_eq!(
            Hidden::NotApplicable("NVMe".into()).label(),
            "Non applicable (NVMe)"
        );
        assert_eq!(Hidden::NotChecked.label(), "Non vérifié");
    }
}
