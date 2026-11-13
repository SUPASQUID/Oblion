//! Logo Oblion (piste « 1d — Grille de blocs »).
//!
//! Source unique : `assets/oblion-logo.svg`, lu à la compilation. Le dessin n'est fait que
//! de rectangles : on les relit ici et on les dessine sur un canvas (rendu CPU) avec les
//! couleurs du thème (encre = `--text`, blocs bleus = `--accent`), comme la maquette.
//! La même géométrie sert à l'icône de la fenêtre.

use iced::widget::canvas::{self, Frame, Geometry, Path};
use iced::{mouse, Color, Point, Rectangle, Renderer, Size, Theme};

/// SVG du dépôt (aussi source de l'icône .ico de l'étape 5).
pub const SVG: &str = include_str!("../../assets/oblion-logo.svg");

/// Couleur « encre » du SVG (remplacée par `--text`).
const INK: &str = "#14171b";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Block {
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    /// Vrai = bloc d'accent (bleu), faux = encre.
    pub accent: bool,
    pub opacity: f32,
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let key = format!(" {name}=\"");
    let i = tag.find(&key)? + key.len();
    let j = tag[i..].find('"')? + i;
    Some(tag[i..j].to_string())
}

/// Rectangles du SVG (viewBox 0 0 64 64).
pub fn blocks() -> Vec<Block> {
    SVG.split("<rect")
        .skip(1)
        .filter_map(|t| {
            let t = &t[..t.find('>')?];
            let num = |n: &str| attr(t, n).and_then(|v| v.parse::<f32>().ok());
            Some(Block {
                x: num("x")?,
                y: num("y")?,
                w: num("width")?,
                h: num("height")?,
                accent: attr(t, "fill").is_some_and(|f| !f.eq_ignore_ascii_case(INK)),
                opacity: num("fill-opacity").unwrap_or(1.0),
            })
        })
        .collect()
}

/// Logo dessiné à la taille du canvas.
pub struct Mark {
    pub ink: Color,
    pub accent: Color,
}

impl<Message> canvas::Program<Message> for Mark {
    type State = ();

    fn draw(
        &self,
        _state: &(),
        renderer: &Renderer,
        _theme: &Theme,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Vec<Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        let k = bounds.width.min(bounds.height) / 64.0;
        for b in blocks() {
            let c = if b.accent { self.accent } else { self.ink };
            frame.fill(
                &Path::rectangle(Point::new(b.x * k, b.y * k), Size::new(b.w * k, b.h * k)),
                Color {
                    a: c.a * b.opacity,
                    ..c
                },
            );
        }
        vec![frame.into_geometry()]
    }
}

/// Icône de fenêtre (RGBA `n`×`n`) aux couleurs du SVG.
pub fn icon_rgba(n: u32) -> Vec<u8> {
    let mut px = vec![0u8; (n * n * 4) as usize];
    let k = n as f32 / 64.0;
    for b in blocks() {
        let rgb = if b.accent {
            [0x1f, 0x5f, 0xbf]
        } else {
            [0x14, 0x17, 0x1b]
        };
        let a = (b.opacity * 255.0) as u8;
        let (x0, y0) = ((b.x * k) as u32, (b.y * k) as u32);
        let (x1, y1) = (
            (((b.x + b.w) * k).ceil() as u32).min(n),
            (((b.y + b.h) * k).ceil() as u32).min(n),
        );
        for y in y0..y1 {
            for x in x0..x1 {
                let i = ((y * n + x) * 4) as usize;
                px[i..i + 4].copy_from_slice(&[rgb[0], rgb[1], rgb[2], a]);
            }
        }
    }
    px
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn svg_is_only_the_drawing() {
        assert!(SVG.trim_start().starts_with("<svg"));
        assert!(SVG.trim_end().ends_with("</svg>"));
        // Aucun script, lien, texte ni métadonnée : uniquement des rectangles.
        for bad in [
            "<script",
            "href",
            "<text",
            "<metadata",
            "<!--",
            "<image",
            "<style",
        ] {
            assert!(!SVG.contains(bad), "{bad}");
        }
        assert_eq!(SVG.matches("<rect").count(), 14);
    }

    #[test]
    fn blocks_are_parsed_with_colors() {
        let b = blocks();
        assert_eq!(b.len(), 14);
        assert_eq!(b.iter().filter(|b| !b.accent).count(), 6);
        assert_eq!(b.iter().filter(|b| b.opacity < 1.0).count(), 4);
        assert!(b.iter().all(|b| b.x + b.w <= 64.0 && b.y + b.h <= 64.0));
        assert_eq!(icon_rgba(32).len(), 32 * 32 * 4);
    }
}
