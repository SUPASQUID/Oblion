//! Écrivain PDF minimal (texte, traits, rectangles, image) sans dépendance.
//! Polices standard du PDF (Helvetica, Courier) : rien à embarquer, lisible partout.
//! Les coordonnées `y` sont mesurées depuis le HAUT de la page (A4 = 595 × 842 pt).

use std::io::Cursor;

pub const W: f32 = 595.0;
pub const H: f32 = 842.0;

pub type Rgb = (f32, f32, f32);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Font {
    Sans,
    SansBold,
    Mono,
    MonoBold,
}

impl Font {
    fn res(&self) -> &'static str {
        match self {
            Font::Sans => "F1",
            Font::SansBold => "F2",
            Font::Mono => "F3",
            Font::MonoBold => "F4",
        }
    }
    /// Largeur moyenne d'un caractère (en « em ») pour estimer les troncatures.
    pub fn avg_em(&self) -> f32 {
        match self {
            Font::Sans => 0.52,
            Font::SansBold => 0.56,
            Font::Mono | Font::MonoBold => 0.6,
        }
    }
}

/// Texte tronqué (avec « … ») pour tenir dans `max_width` points.
pub fn fit(text: &str, font: Font, size: f32, max_width: f32) -> String {
    let max_chars = (max_width / (size * font.avg_em())).floor() as usize;
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= max_chars.max(1) {
        text.to_string()
    } else {
        let keep = max_chars.saturating_sub(1).max(1);
        format!("{}…", chars[..keep].iter().collect::<String>())
    }
}

fn cp1252(c: char) -> u8 {
    match c as u32 {
        0..=0x7F => c as u8,
        0xA0..=0xFF => c as u32 as u8,
        0x20AC => 0x80,
        0x2026 => 0x85,
        0x2022 => 0x95,
        0x2013 => 0x96,
        0x2014 => 0x97,
        0x2018 => 0x91,
        0x2019 => 0x92,
        0x201C => 0x93,
        0x201D => 0x94,
        0x0152 => 0x8C,
        0x0153 => 0x9C,
        0x2713 | 0x2714 => b'v',
        _ => b'?',
    }
}

/// Chaîne PDF littérale (octets WinAnsi, échappements).
fn pdf_string(s: &str) -> Vec<u8> {
    let mut out = vec![b'('];
    for c in s.chars() {
        let b = cp1252(c);
        match b {
            b'(' | b')' | b'\\' => {
                out.push(b'\\');
                out.push(b);
            }
            0x20..=0x7E => out.push(b),
            _ => out.extend_from_slice(format!("\\{:03o}", b).as_bytes()),
        }
    }
    out.push(b')');
    out
}

pub struct Image {
    pub w: u32,
    pub h: u32,
    pub rgb: Vec<u8>,
}

impl Image {
    /// Décode un PNG (alpha composité sur fond blanc).
    pub fn from_png(bytes: &[u8]) -> Result<Image, String> {
        let mut dec = png::Decoder::new(Cursor::new(bytes));
        dec.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
        let mut reader = dec.read_info().map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; reader.output_buffer_size().ok_or("PNG trop grand")?];
        let info = reader.next_frame(&mut buf).map_err(|e| e.to_string())?;
        let data = &buf[..info.buffer_size()];
        let blend = |c: u8, a: u8| ((c as u32 * a as u32 + 255 * (255 - a as u32)) / 255) as u8;
        let mut rgb = Vec::with_capacity((info.width * info.height * 3) as usize);
        match info.color_type {
            png::ColorType::Rgb => rgb.extend_from_slice(data),
            png::ColorType::Rgba => {
                for p in data.as_chunks::<4>().0 {
                    rgb.extend_from_slice(&[
                        blend(p[0], p[3]),
                        blend(p[1], p[3]),
                        blend(p[2], p[3]),
                    ]);
                }
            }
            png::ColorType::Grayscale => {
                data.iter().for_each(|&g| rgb.extend_from_slice(&[g, g, g]))
            }
            png::ColorType::GrayscaleAlpha => {
                for p in data.as_chunks::<2>().0 {
                    let g = blend(p[0], p[1]);
                    rgb.extend_from_slice(&[g, g, g]);
                }
            }
            png::ColorType::Indexed => return Err("PNG indexé non géré".into()),
        }
        Ok(Image {
            w: info.width,
            h: info.height,
            rgb,
        })
    }
}

#[derive(Default)]
pub struct Page {
    c: Vec<u8>,
}

impl Page {
    pub fn new() -> Page {
        Page::default()
    }
    fn put(&mut self, s: &str) {
        self.c.extend_from_slice(s.as_bytes());
    }
    pub fn fill(&mut self, c: Rgb) {
        self.put(&format!("{:.3} {:.3} {:.3} rg\n", c.0, c.1, c.2));
    }
    pub fn stroke(&mut self, c: Rgb) {
        self.put(&format!("{:.3} {:.3} {:.3} RG\n", c.0, c.1, c.2));
    }
    pub fn width(&mut self, w: f32) {
        self.put(&format!("{w:.2} w\n"));
    }
    pub fn rect(&mut self, x: f32, y: f32, w: f32, h: f32, fill: bool, stroke: bool) {
        let op = match (fill, stroke) {
            (true, true) => "B",
            (true, false) => "f",
            (false, true) => "S",
            _ => "n",
        };
        self.put(&format!("{x:.2} {:.2} {w:.2} {h:.2} re {op}\n", H - y - h));
    }
    pub fn line(&mut self, x1: f32, y1: f32, x2: f32, y2: f32) {
        self.put(&format!(
            "{x1:.2} {:.2} m {x2:.2} {:.2} l S\n",
            H - y1,
            H - y2
        ));
    }
    pub fn polyline(&mut self, pts: &[(f32, f32)]) {
        if pts.len() < 2 {
            return;
        }
        let mut s = String::new();
        for (i, (x, y)) in pts.iter().enumerate() {
            s.push_str(&format!(
                "{x:.2} {:.2} {}\n",
                H - y,
                if i == 0 { "m" } else { "l" }
            ));
        }
        s.push_str("S\n");
        self.put(&s);
    }
    /// `y` = ligne de base du texte.
    pub fn text(&mut self, x: f32, y: f32, size: f32, font: Font, s: &str) {
        self.put(&format!(
            "BT /{} {size:.2} Tf {x:.2} {:.2} Td ",
            font.res(),
            H - y
        ));
        let st = pdf_string(s);
        self.c.extend_from_slice(&st);
        self.put(" Tj ET\n");
    }
    pub fn image(&mut self, x: f32, y: f32, w: f32, h: f32) {
        self.put(&format!(
            "q {w:.2} 0 0 {h:.2} {x:.2} {:.2} cm /Logo Do Q\n",
            H - y - h
        ));
    }
}

#[derive(Default)]
pub struct Doc {
    pub title: String,
    pub pages: Vec<Page>,
    pub logo: Option<Image>,
}

impl Doc {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut objs: Vec<Vec<u8>> = Vec::new(); // objet n° i+1
        let fonts = ["Helvetica", "Helvetica-Bold", "Courier", "Courier-Bold"];
        let n_pages = self.pages.len();
        let first_page_obj = 3 + fonts.len() + 1 + usize::from(self.logo.is_some()); // après info + image

        // 1 Catalog, 2 Pages
        objs.push(b"<< /Type /Catalog /Pages 2 0 R >>".to_vec());
        let kids: String = (0..n_pages)
            .map(|i| format!("{} 0 R", first_page_obj + 1 + i * 2))
            .collect::<Vec<_>>()
            .join(" ");
        objs.push(format!("<< /Type /Pages /Kids [{kids}] /Count {n_pages} >>").into_bytes());
        // 3..6 polices
        for f in fonts {
            objs.push(
                format!(
                    "<< /Type /Font /Subtype /Type1 /BaseFont /{f} /Encoding /WinAnsiEncoding >>"
                )
                .into_bytes(),
            );
        }
        // 7 Info
        let mut info = b"<< /Title ".to_vec();
        info.extend(pdf_string(&self.title));
        info.extend_from_slice(b" /Producer ");
        info.extend(pdf_string(&self.title));
        info.extend_from_slice(b" >>");
        objs.push(info);
        // 8 image (optionnelle)
        let mut image_obj = None;
        if let Some(img) = &self.logo {
            let mut o = format!(
                "<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace /DeviceRGB /BitsPerComponent 8 /Length {} >>\nstream\n",
                img.w,
                img.h,
                img.rgb.len()
            )
            .into_bytes();
            o.extend_from_slice(&img.rgb);
            o.extend_from_slice(b"\nendstream");
            objs.push(o);
            image_obj = Some(objs.len());
        }
        let xobj = image_obj
            .map(|n| format!("/XObject << /Logo {n} 0 R >>"))
            .unwrap_or_default();
        let res = format!("<< /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R /F4 6 0 R >> {xobj} >>");
        for p in &self.pages {
            let content_no = objs.len() + 1;
            let mut c = format!("<< /Length {} >>\nstream\n", p.c.len()).into_bytes();
            c.extend_from_slice(&p.c);
            c.extend_from_slice(b"endstream");
            objs.push(c);
            objs.push(
                format!(
                    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {W} {H}] /Resources {res} /Contents {content_no} 0 R >>"
                )
                .into_bytes(),
            );
        }

        let mut out = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3\n".to_vec();
        let mut offsets = Vec::new();
        for (i, o) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes(),
        );
        for off in offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R /Info 7 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    #[test]
    fn encodes_french_accents_as_winansi() {
        assert_eq!(pdf_string("é"), b"(\\351)".to_vec());
        assert_eq!(pdf_string("a(b)\\"), b"(a\\(b\\)\\\\)".to_vec());
        assert_eq!(pdf_string("€"), b"(\\200)".to_vec());
        assert_eq!(pdf_string("日"), b"(?)".to_vec());
    }

    #[test]
    fn fit_truncates_with_ellipsis() {
        assert_eq!(fit("court", Font::Sans, 10.0, 200.0), "court");
        let t = fit("un texte vraiment très long", Font::Sans, 10.0, 50.0);
        assert!(t.ends_with('…') && t.chars().count() <= 10, "{t}");
    }

    #[test]
    fn document_has_valid_structure() {
        let mut p1 = Page::new();
        p1.text(40.0, 50.0, 12.0, Font::Sans, "Bonjour é");
        p1.rect(10.0, 10.0, 50.0, 20.0, true, true);
        let mut p2 = Page::new();
        p2.line(0.0, 0.0, 10.0, 10.0);
        let d = Doc {
            title: "T".into(),
            pages: vec![p1, p2],
            logo: None,
        };
        let b = d.to_bytes();
        assert!(b.starts_with(b"%PDF-1.4"));
        assert!(b.ends_with(b"%%EOF\n"));
        assert!(find(&b, b"/Count 2").is_some());
        // Les offsets de la table xref pointent bien sur « N 0 obj ».
        let sx = find(&b, b"startxref\n").unwrap() + 10;
        let xref_pos: usize = String::from_utf8_lossy(&b[sx..])
            .lines()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(b[xref_pos..].starts_with(b"xref"));
        let table = String::from_utf8_lossy(&b[xref_pos..]).to_string();
        let offs: Vec<usize> = table
            .lines()
            .skip(3)
            .take_while(|l| l.ends_with(" n "))
            .map(|l| l[..10].parse().unwrap())
            .collect();
        assert_eq!(offs.len(), 2 + 4 + 1 + 4);
        for (i, off) in offs.iter().enumerate() {
            assert!(
                b[*off..].starts_with(format!("{} 0 obj", i + 1).as_bytes()),
                "objet {}",
                i + 1
            );
        }
    }

    #[test]
    fn png_logo_is_decoded_and_embedded() {
        // PNG 1×1 rouge opaque généré à la main via l'encodeur.
        let mut png_bytes = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut png_bytes, 2, 1);
            enc.set_color(png::ColorType::Rgba);
            enc.set_depth(png::BitDepth::Eight);
            let mut w = enc.write_header().unwrap();
            w.write_image_data(&[255, 0, 0, 255, 0, 0, 255, 0]).unwrap(); // rouge opaque, bleu transparent
        }
        let img = Image::from_png(&png_bytes).unwrap();
        assert_eq!((img.w, img.h), (2, 1));
        assert_eq!(&img.rgb[..3], &[255, 0, 0]);
        assert_eq!(&img.rgb[3..], &[255, 255, 255]); // transparent -> blanc
        let mut p = Page::new();
        p.image(10.0, 10.0, 20.0, 10.0);
        let b = Doc {
            title: "T".into(),
            pages: vec![p],
            logo: Some(img),
        }
        .to_bytes();
        assert!(find(&b, b"/Subtype /Image").is_some());
        assert!(find(&b, b"/Logo 8 0 R").is_some());
    }
}
