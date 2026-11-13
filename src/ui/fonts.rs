//! Polices : AUCUNE police n'est embarquée dans l'exécutable.
//!
//! Ordre de recherche, à l'exécution :
//! 1. une police `.ttf` / `.otf` déposée dans `data/assets/fonts/` ;
//! 2. polices système de `%WINDIR%\Fonts` : Segoe UI, sinon Arial, sinon Tahoma.
//!
//! Chasse fixe (n° de série) : Consolas, sinon Courier New, sinon Lucida Console, sinon la
//! police principale.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use iced::font::{Family, Weight};
use iced::Font;

pub struct FontSet {
    /// Fichiers à charger (octets lus au démarrage).
    pub data: Vec<Cow<'static, [u8]>>,
    pub regular: Font,
    /// Graisse des titres (Semibold si disponible, sinon Bold).
    pub strong: Font,
    pub bold: Font,
    pub mono: Font,
    /// Description pour l'écran Paramètres.
    pub source: String,
}

fn fonts_dir() -> PathBuf {
    let win = std::env::var_os("WINDIR")
        .or_else(|| std::env::var_os("SystemRoot"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    win.join("Fonts")
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn read(dir: &Path, name: &str) -> Option<Vec<u8>> {
    std::fs::read(dir.join(name)).ok().filter(|b| b.len() > 12)
}

/// Familles système : (nom, normal, semi-gras, gras).
const SYSTEM: [(&str, &str, Option<&str>, &str); 3] = [
    (
        "Segoe UI",
        "segoeui.ttf",
        Some("seguisb.ttf"),
        "segoeuib.ttf",
    ),
    ("Arial", "arial.ttf", None, "arialbd.ttf"),
    ("Tahoma", "tahoma.ttf", None, "tahomabd.ttf"),
];

const MONO: [(&str, &str); 3] = [
    ("Consolas", "consola.ttf"),
    ("Courier New", "cour.ttf"),
    ("Lucida Console", "lucon.ttf"),
];

/// Cherche les polices. Erreur claire si aucune n'est trouvée.
pub fn find(custom_dir: &Path) -> Result<FontSet, String> {
    find_in(custom_dir, &fonts_dir())
}

pub fn find_in(custom_dir: &Path, system_dir: &Path) -> Result<FontSet, String> {
    let mut data: Vec<Cow<'static, [u8]>> = Vec::new();
    let mut chosen: Option<(String, bool, String)> = None; // (famille, semi-gras, source)

    // 1. Police fournie par l'utilisateur.
    let mut custom: Vec<PathBuf> = std::fs::read_dir(custom_dir)
        .map(|it| {
            it.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| {
                    p.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                        e.eq_ignore_ascii_case("ttf") || e.eq_ignore_ascii_case("otf")
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    custom.sort();
    for p in &custom {
        if let Ok(bytes) = std::fs::read(p) {
            if let Some(family) = family_name(&bytes) {
                if chosen.is_none() {
                    chosen = Some((
                        family,
                        false,
                        format!("{} (data/assets/fonts)", p.display()),
                    ));
                }
                data.push(Cow::Owned(bytes));
            }
        }
    }

    // 2. Polices système.
    if chosen.is_none() {
        for (family, regular, semi, bold) in SYSTEM {
            if let Some(r) = read(system_dir, regular) {
                data.push(Cow::Owned(r));
                let mut has_semi = false;
                if let Some(s) = semi.and_then(|s| read(system_dir, s)) {
                    data.push(Cow::Owned(s));
                    has_semi = true;
                }
                if let Some(b) = read(system_dir, bold) {
                    data.push(Cow::Owned(b));
                }
                chosen = Some((
                    family.to_string(),
                    has_semi,
                    format!("{family} ({})", system_dir.join(regular).display()),
                ));
                break;
            }
        }
    }
    let Some((family, has_semi, source)) = chosen else {
        return Err(format!(
            "Aucune police trouvée : ni police dans data/assets/fonts, ni Segoe UI, Arial ou Tahoma dans {}.",
            system_dir.display()
        ));
    };
    let name = leak(family);
    let regular = Font {
        family: Family::Name(name),
        ..Font::DEFAULT
    };
    let mono = MONO
        .iter()
        .find_map(|(fam, file)| {
            read(system_dir, file).map(|b| {
                data.push(Cow::Owned(b));
                Font {
                    family: Family::Name(fam),
                    ..Font::DEFAULT
                }
            })
        })
        .unwrap_or(regular);
    Ok(FontSet {
        data,
        regular,
        strong: Font {
            weight: if has_semi {
                Weight::Semibold
            } else {
                Weight::Bold
            },
            ..regular
        },
        bold: Font {
            weight: Weight::Bold,
            ..regular
        },
        mono,
        source,
    })
}

fn be16(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}
fn be32(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Nom de famille d'une police TrueType/OpenType (table `name`, id 16 sinon 1).
pub fn family_name(d: &[u8]) -> Option<String> {
    let tables = be16(d, 4)? as usize;
    let name_off = (0..tables).find_map(|i| {
        let rec = 12 + 16 * i;
        (d.get(rec..rec + 4)? == b"name").then(|| be32(d, rec + 8))?
    })? as usize;
    let count = be16(d, name_off + 2)? as usize;
    let strings = name_off + be16(d, name_off + 4)? as usize;
    let mut best: Option<(u16, String)> = None;
    for i in 0..count {
        let r = name_off + 6 + 12 * i;
        let (platform, encoding, id) = (be16(d, r)?, be16(d, r + 2)?, be16(d, r + 6)?);
        let (len, off) = (be16(d, r + 8)? as usize, be16(d, r + 10)? as usize);
        if !(id == 1 || id == 16) {
            continue;
        }
        let raw = d.get(strings + off..strings + off + len)?;
        let s = if platform == 3 || platform == 0 {
            let u: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            String::from_utf16(&u).ok()?
        } else if platform == 1 && encoding == 0 {
            raw.iter().map(|&b| b as char).collect()
        } else {
            continue;
        };
        let rank = if id == 16 { 2 } else { 1 };
        if !s.is_empty() && best.as_ref().is_none_or(|(r, _)| rank > *r) {
            best = Some((rank, s));
        }
    }
    best.map(|(_, s)| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Police minimale : en-tête + table `name` avec une famille (id 1, Windows UTF-16).
    fn tiny_font(family: &str) -> Vec<u8> {
        let utf16: Vec<u8> = family
            .encode_utf16()
            .flat_map(|c| c.to_be_bytes())
            .collect();
        let mut d = vec![0u8; 12 + 16];
        d[4..6].copy_from_slice(&1u16.to_be_bytes());
        d[12..16].copy_from_slice(b"name");
        let name_off = d.len() as u32;
        d[20..24].copy_from_slice(&name_off.to_be_bytes());
        let mut name = vec![0u8; 6 + 12];
        name[2..4].copy_from_slice(&1u16.to_be_bytes());
        name[4..6].copy_from_slice(&18u16.to_be_bytes());
        name[6..8].copy_from_slice(&3u16.to_be_bytes());
        name[8..10].copy_from_slice(&1u16.to_be_bytes());
        name[12..14].copy_from_slice(&1u16.to_be_bytes());
        name[14..16].copy_from_slice(&(utf16.len() as u16).to_be_bytes());
        name.extend(utf16);
        d.extend(name);
        d
    }

    #[test]
    fn family_name_is_read_from_the_name_table() {
        assert_eq!(
            family_name(&tiny_font("Ma Police")).as_deref(),
            Some("Ma Police")
        );
        assert_eq!(family_name(b"pas une police"), None);
    }

    #[test]
    fn custom_font_first_then_system_then_clear_error() {
        let base = std::env::temp_dir().join(format!("oblion-fonts-{}", std::process::id()));
        let custom = base.join("custom");
        let system = base.join("system");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&custom).unwrap();
        std::fs::create_dir_all(&system).unwrap();
        // Rien : erreur claire.
        let e = find_in(&custom, &system).err().unwrap();
        assert!(e.contains("Aucune police"), "{e}");
        // Tahoma seulement (« système ») : choisie, gras en repli.
        std::fs::write(system.join("tahoma.ttf"), tiny_font("Tahoma")).unwrap();
        let f = find_in(&custom, &system).unwrap();
        assert_eq!(f.regular.family, Family::Name("Tahoma"));
        assert_eq!(f.strong.weight, Weight::Bold);
        // Arial passe avant Tahoma.
        std::fs::write(system.join("arial.ttf"), tiny_font("Arial")).unwrap();
        assert_eq!(
            find_in(&custom, &system).unwrap().regular.family,
            Family::Name("Arial")
        );
        // Police de l'utilisateur : prioritaire.
        std::fs::write(custom.join("perso.ttf"), tiny_font("Perso Sans")).unwrap();
        let f = find_in(&custom, &system).unwrap();
        assert_eq!(f.regular.family, Family::Name("Perso Sans"));
        assert!(f.source.contains("data/assets/fonts"));
        let _ = std::fs::remove_dir_all(&base);
    }
}
