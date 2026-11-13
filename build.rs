//! Script de compilation.
//!
//! 1. Chargement différé des DLL graphiques de `oblion.exe` (interface iced/winit).
//!    Si l'une manque (WinPE minimal), l'exe démarre quand même : il le détecte avec
//!    LoadLibraryW avant de lancer l'interface et propose `oblion-cli.exe`.
//!    `oblion-cli.exe` n'importe aucune de ces DLL (pas d'iced ni de winit).
//! 2. Icône et informations de version (VERSIONINFO) des deux exe.
//!    L'icône `.ico` (16 à 256 px) est calculée ici à partir de `assets/oblion-logo.svg` :
//!    le logo n'est fait que de rectangles, on les rastérise nous-mêmes (anticrénelage par
//!    surface couverte), sans moteur SVG. Même géométrie que l'icône de la fenêtre
//!    (`src/ui/logo.rs`). Les ressources sont compilées par rc.exe (Windows SDK) via winresource.

use std::path::{Path, PathBuf};

const DELAY: [&str; 4] = ["dwmapi.dll", "uxtheme.dll", "imm32.dll", "ole32.dll"];
const SVG_PATH: &str = "assets/oblion-logo.svg";
const SIZES: [u32; 7] = [16, 24, 32, 48, 64, 128, 256];
/// Couleur « encre » du SVG ; toute autre couleur est l'accent bleu.
const INK: &str = "#14171b";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={SVG_PATH}");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() != Ok("msvc") {
        return;
    }
    for dll in DELAY {
        println!("cargo:rustc-link-arg-bin=oblion=/DELAYLOAD:{dll}");
    }
    println!("cargo:rustc-link-arg-bin=oblion=delayimp.lib");

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let svg = std::fs::read_to_string(SVG_PATH).expect("lecture de assets/oblion-logo.svg");
    let ico = out.join("oblion.ico");
    std::fs::write(&ico, ico_bytes(&rects(&svg))).expect("écriture de oblion.ico");

    resources(
        &ico,
        "oblion",
        "Oblion - effacement sécurisé de disques (interface)",
    );
    resources(
        &ico,
        "oblion-cli",
        "Oblion - effacement sécurisé de disques (console)",
    );
}

/// Icône + VERSIONINFO pour un exe (version tirée de CARGO_PKG_VERSION par winresource).
fn resources(ico: &Path, bin: &str, description: &str) {
    let mut res = winresource::WindowsResource::new();
    res.set_language(0x040C) // français (France)
        .set_icon(ico.to_str().expect("chemin de l'icône"))
        .set("ProductName", "Oblion")
        .set("FileDescription", description)
        .set("CompanyName", "SUPASQUID")
        .set("LegalCopyright", "MIT")
        .set("OriginalFilename", &format!("{bin}.exe"))
        .set("InternalName", bin);
    if let Err(e) = res.compile_for(bin) {
        panic!(
            "compilation des ressources Windows de {bin}.exe impossible ({e}) : \
             rc.exe (Windows SDK) est-il installé ?"
        );
    }
}

/// Rectangle du SVG (viewBox 0 0 64 64) : x, y, largeur, hauteur, RVB, opacité.
struct Rect {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    rgb: [u8; 3],
    opacity: f32,
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let i = tag.find(&key)? + key.len();
    let j = tag[i..].find('"')? + i;
    Some(&tag[i..j])
}

fn hex(c: &str) -> Option<[u8; 3]> {
    let c = c.strip_prefix('#')?;
    let v = u32::from_str_radix(c, 16).ok()?;
    (c.len() == 6).then_some([(v >> 16) as u8, (v >> 8) as u8, v as u8])
}

fn rects(svg: &str) -> Vec<Rect> {
    let r: Vec<Rect> = svg
        .split("<rect")
        .skip(1)
        .filter_map(|t| {
            let t = &t[..t.find('>')?];
            let num = |n: &str| attr(t, n).and_then(|v| v.parse::<f32>().ok());
            let fill = attr(t, "fill").unwrap_or(INK);
            Some(Rect {
                x: num("x")?,
                y: num("y")?,
                w: num("width")?,
                h: num("height")?,
                rgb: hex(fill).unwrap_or([0x14, 0x17, 0x1b]),
                opacity: num("fill-opacity").unwrap_or(1.0),
            })
        })
        .collect();
    assert!(!r.is_empty(), "aucun rectangle dans {SVG_PATH}");
    r
}

/// Image RGBA non prémultipliée `n`×`n`, anticrénelée (surface de chaque pixel couverte).
fn raster(rects: &[Rect], n: u32) -> Vec<u8> {
    let k = n as f32 / 64.0;
    let mut px = vec![0u8; (n * n * 4) as usize];
    for py in 0..n {
        for pxx in 0..n {
            // Couleur prémultipliée, composée « par-dessus » rectangle après rectangle.
            let (mut r, mut g, mut b, mut a) = (0f32, 0f32, 0f32, 0f32);
            for s in rects {
                let ox = ((s.x + s.w) * k).min(pxx as f32 + 1.0) - (s.x * k).max(pxx as f32);
                let oy = ((s.y + s.h) * k).min(py as f32 + 1.0) - (s.y * k).max(py as f32);
                if ox <= 0.0 || oy <= 0.0 {
                    continue;
                }
                let ca = ox * oy * s.opacity;
                r = r * (1.0 - ca) + s.rgb[0] as f32 * ca;
                g = g * (1.0 - ca) + s.rgb[1] as f32 * ca;
                b = b * (1.0 - ca) + s.rgb[2] as f32 * ca;
                a = a * (1.0 - ca) + ca;
            }
            let i = ((py * n + pxx) * 4) as usize;
            if a > 0.0 {
                px[i] = (r / a).round() as u8;
                px[i + 1] = (g / a).round() as u8;
                px[i + 2] = (b / a).round() as u8;
                px[i + 3] = (a * 255.0) as u8;
            }
        }
    }
    px
}

/// Entrée BMP (DIB 32 bits BGRA + masque ET) : format classique des icônes < 256 px.
fn dib(rgba: &[u8], n: u32) -> Vec<u8> {
    let mask_row = n.div_ceil(32) * 4;
    let mut v = Vec::new();
    for x in [40u32, n, n * 2] {
        v.extend_from_slice(&x.to_le_bytes()); // taille de l'en-tête, largeur, hauteur ×2
    }
    v.extend_from_slice(&1u16.to_le_bytes()); // plans
    v.extend_from_slice(&32u16.to_le_bytes()); // bits par pixel
    for x in [0u32, n * n * 4 + mask_row * n, 0, 0, 0, 0] {
        v.extend_from_slice(&x.to_le_bytes());
    }
    for y in (0..n).rev() {
        for x in 0..n {
            let i = ((y * n + x) * 4) as usize;
            v.extend_from_slice(&[rgba[i + 2], rgba[i + 1], rgba[i], rgba[i + 3]]);
        }
    }
    // Masque ET à zéro : la transparence vient du canal alpha.
    v.resize(v.len() + (mask_row * n) as usize, 0);
    v
}

fn png_bytes(rgba: &[u8], n: u32) -> Vec<u8> {
    let mut v = Vec::new();
    let mut enc = png::Encoder::new(&mut v, n, n);
    enc.set_color(png::ColorType::Rgba);
    enc.set_depth(png::BitDepth::Eight);
    let mut w = enc.write_header().expect("en-tête PNG");
    w.write_image_data(rgba).expect("données PNG");
    w.finish().expect("fin PNG");
    v
}

/// Fichier .ico multi-tailles (256 px en PNG, les autres en BMP).
fn ico_bytes(rects: &[Rect]) -> Vec<u8> {
    let images: Vec<(u32, Vec<u8>)> = SIZES
        .iter()
        .map(|&n| {
            let rgba = raster(rects, n);
            let data = if n >= 256 {
                png_bytes(&rgba, n)
            } else {
                dib(&rgba, n)
            };
            (n, data)
        })
        .collect();
    let mut v = Vec::new();
    v.extend_from_slice(&[0, 0, 1, 0]); // réservé, type 1 = icône
    v.extend_from_slice(&(images.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * images.len() as u32;
    for (n, data) in &images {
        let side = if *n >= 256 { 0 } else { *n as u8 }; // 0 = 256
        v.extend_from_slice(&[side, side, 0, 0]);
        v.extend_from_slice(&1u16.to_le_bytes()); // plans
        v.extend_from_slice(&32u16.to_le_bytes()); // bits par pixel
        v.extend_from_slice(&(data.len() as u32).to_le_bytes());
        v.extend_from_slice(&offset.to_le_bytes());
        offset += data.len() as u32;
    }
    for (_, data) in &images {
        v.extend_from_slice(data);
    }
    v
}
