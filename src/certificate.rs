//! Certificat d'effacement PDF (2 pages), inspiré du rapport nwipe, libellés en français.
//!
//! Page 1 : statut, organisation/client, disque, technicien, détails de l'effacement.
//! Page 2 : données SMART (si disponibles) et profil de débit.
//! Toutes les valeurs viennent de l'`EraseRecord` : rien n'est saisi ici.

use barcoders::sym::code128::Code128;
use qrcode::{Color, QrCode};

use crate::clock::DateTime;
use crate::pdf::{self, fit, Doc, Font, Image, Page, Rgb};
use crate::report::{EraseRecord, Status};

const M: f32 = 36.0; // marge gauche/droite
const CW: f32 = pdf::W - 2.0 * M; // largeur utile
const ROW: f32 = 13.0;

const BLACK: Rgb = (0.0, 0.0, 0.0);
const WHITE: Rgb = (1.0, 1.0, 1.0);
const GREY: Rgb = (0.40, 0.40, 0.40);
const LIGHT: Rgb = (0.90, 0.92, 0.95);
const BORDER: Rgb = (0.70, 0.72, 0.76);
const GREEN: Rgb = (0.13, 0.55, 0.20);
const ORANGE: Rgb = (0.93, 0.55, 0.05);
const RED: Rgb = (0.80, 0.10, 0.10);
const BLUE: Rgb = (0.12, 0.35, 0.70);
const PALE_RED: Rgb = (1.0, 0.85, 0.85);

// ---------- Formatage ----------

/// 320072933376 -> "320 072 933 376"
fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

/// Décimale à la française : 320,07
fn dec(v: f64, digits: usize) -> String {
    if !v.is_finite() {
        return "—".to_string(); // jamais de NaN/inf dans le PDF
    }
    format!("{v:.digits$}").replace('.', ",")
}

/// Taille lisible + octets exacts : « 268 Mo (268 435 456 octets) » sous 1 Go,
/// « 320,07 Go (320 072 933 376 octets) » au-delà (même seuil que la console).
fn size_text(n: u64) -> String {
    if n < 1_000_000_000 {
        format!("{} Mo ({} octets)", dec(n as f64 / 1e6, 0), thousands(n))
    } else {
        format!("{} Go ({} octets)", dec(n as f64 / 1e9, 2), thousands(n))
    }
}

fn or_dash(s: &str) -> String {
    if s.trim().is_empty() {
        "—".to_string()
    } else {
        s.to_string()
    }
}

fn status_color(s: Status) -> Rgb {
    match s {
        Status::Erased => GREEN,
        Status::Partial => ORANGE,
        Status::Failed | Status::Aborted => RED,
    }
}

/// Graduation « ronde » au-dessus de `v` (1, 2, 2,5, 5 × 10^n).
fn nice_max(v: f32) -> f32 {
    if v <= 0.0 || !v.is_finite() {
        return 1.0;
    }
    let mag = 10f32.powf(v.log10().floor());
    for m in [1.0, 2.0, 2.5, 5.0, 10.0] {
        if m * mag >= v {
            return m * mag;
        }
    }
    10.0 * mag
}

// ---------- Briques de mise en page ----------

/// Bandeau de titre de section. Renvoie la ligne de base de la première ligne de contenu.
fn section(p: &mut Page, x: f32, y: f32, w: f32, title: &str) -> f32 {
    p.fill(LIGHT);
    p.rect(x, y, w, 15.0, true, false);
    p.fill(BLACK);
    p.text(
        x + 5.0,
        y + 10.5,
        9.0,
        Font::SansBold,
        &fit(title, Font::SansBold, 9.0, w - 10.0),
    );
    y + 15.0 + 11.0
}

/// Ligne « libellé : valeur » ; la valeur est tronquée pour tenir dans la colonne.
fn kv(p: &mut Page, x: f32, y: f32, w: f32, label_w: f32, label: &str, value: &str) {
    p.fill(GREY);
    p.text(
        x + 5.0,
        y,
        8.0,
        Font::Sans,
        &fit(label, Font::Sans, 8.0, label_w - 6.0),
    );
    p.fill(BLACK);
    p.text(
        x + label_w,
        y,
        9.0,
        Font::Sans,
        &fit(value, Font::Sans, 9.0, w - label_w - 6.0),
    );
}

fn frame(p: &mut Page, x: f32, y: f32, w: f32, h: f32) {
    p.stroke(BORDER);
    p.width(0.6);
    p.rect(x, y, w, h, false, true);
}

fn draw_qr(p: &mut Page, x: f32, y: f32, size: f32, data: &str) {
    let Ok(code) = QrCode::new(data.as_bytes()) else {
        return;
    };
    let n = code.width();
    let colors = code.to_colors();
    let quiet = 2.0;
    let m = size / (n as f32 + 2.0 * quiet);
    p.fill(BLACK);
    for row in 0..n {
        // Modules sombres consécutifs regroupés en un seul rectangle.
        let mut col = 0;
        while col < n {
            if colors[row * n + col] == Color::Dark {
                let start = col;
                while col < n && colors[row * n + col] == Color::Dark {
                    col += 1;
                }
                let rx = x + (quiet + start as f32) * m;
                let ry = y + (quiet + row as f32) * m;
                p.rect(
                    rx,
                    ry,
                    (col - start) as f32 * m + 0.05,
                    m + 0.05,
                    true,
                    false,
                );
            } else {
                col += 1;
            }
        }
    }
}

fn draw_barcode(p: &mut Page, x: f32, y: f32, w: f32, h: f32, id: &str) {
    // Préfixe « Ɓ » : jeu de caractères B (lettres, chiffres, tiret).
    let Ok(bc) = Code128::new(format!("Ɓ{id}")) else {
        return;
    };
    let bits = bc.encode();
    let m = w / bits.len() as f32;
    p.fill(BLACK);
    let mut i = 0;
    while i < bits.len() {
        if bits[i] == 1 {
            let start = i;
            while i < bits.len() && bits[i] == 1 {
                i += 1;
            }
            p.rect(
                x + start as f32 * m,
                y,
                (i - start) as f32 * m,
                h,
                true,
                false,
            );
        } else {
            i += 1;
        }
    }
    p.text(
        x,
        y + h + 10.0,
        8.0,
        Font::Mono,
        &fit(id, Font::Mono, 8.0, w),
    );
}

fn footer(p: &mut Page, rec: &EraseRecord, generated: &str, page: u32) {
    p.stroke(BORDER);
    p.width(0.6);
    p.line(M, 806.0, M + CW, 806.0);
    p.fill(GREY);
    let left = format!(
        "Généré le {generated} · {} version {} · Page {page} / 2",
        rec.app, rec.app_version
    );
    p.text(
        M,
        818.0,
        7.5,
        Font::Sans,
        &fit(&left, Font::Sans, 7.5, CW - 150.0),
    );
    let id_w = rec.id.chars().count() as f32 * 7.5 * 0.6;
    p.text(M + CW - id_w, 818.0, 7.5, Font::Mono, &rec.id);
}

// ---------- Page 1 ----------

fn page1(rec: &EraseRecord, logo: Option<(u32, u32)>, generated: &str) -> Page {
    let mut p = Page::new();

    // En-tête : logo (ou nom de l'outil), code-barres, QR code.
    match logo {
        Some((w, h)) => {
            let scale = (140.0 / w as f32).min(50.0 / h as f32);
            p.image(M, 26.0, w as f32 * scale, h as f32 * scale);
        }
        None => {
            p.fill(BLUE);
            p.text(
                M,
                56.0,
                18.0,
                Font::SansBold,
                &fit(&rec.app, Font::SansBold, 18.0, 200.0),
            );
        }
    }
    draw_barcode(&mut p, 250.0, 28.0, 215.0, 32.0, &rec.id);
    let qr = format!(
        "{}|{}|{}|{}|{}|{}",
        rec.app,
        rec.id,
        rec.disk.serial,
        rec.status.code(),
        rec.level,
        rec.end
    );
    draw_qr(&mut p, M + CW - 82.0, 20.0, 82.0, &qr);

    p.fill(BLACK);
    p.text(
        M,
        92.0,
        18.0,
        Font::SansBold,
        "Certificat d'effacement de disque",
    );
    p.fill(GREY);
    p.text(
        M,
        106.0,
        9.0,
        Font::Sans,
        &format!("{} {} — Statut d'effacement", rec.app, rec.app_version),
    );

    // Bandeau de statut.
    let mut y = 114.0;
    p.fill(status_color(rec.status));
    p.rect(M, y, CW, 30.0, true, false);
    p.fill(WHITE);
    p.text(
        M + 10.0,
        y + 20.0,
        15.0,
        Font::SansBold,
        &format!("{} — {}", rec.status.code(), rec.status.fr()),
    );
    let nist = format!("NIST 800-88 : {}", rec.level);
    let nist_w = nist.chars().count() as f32 * 12.0 * Font::SansBold.avg_em();
    p.text(
        M + CW - 10.0 - nist_w,
        y + 20.0,
        12.0,
        Font::SansBold,
        &nist,
    );
    y += 36.0;

    if rec.test_target {
        p.fill(RED);
        p.rect(M, y, CW, 20.0, true, false);
        p.fill(WHITE);
        p.text(
            M + 10.0,
            y + 14.0,
            10.0,
            Font::SansBold,
            "TEST SUR FICHIER — ce certificat ne concerne pas un disque physique",
        );
        y += 26.0;
    }
    if rec.ssd_overwrite {
        p.fill(ORANGE);
        p.rect(M, y, CW, 20.0, true, false);
        p.fill(WHITE);
        p.text(
            M + 10.0,
            y + 14.0,
            10.0,
            Font::SansBold,
            "ÉCRASEMENT SUR SSD/NVMe — effacement non garanti (sur-provisionnement)",
        );
        y += 26.0;
    }
    if rec.verify_result == "Non demandée" {
        p.fill(ORANGE);
        p.rect(M, y, CW, 20.0, true, false);
        p.fill(WHITE);
        p.text(
            M + 10.0,
            y + 14.0,
            10.0,
            Font::SansBold,
            "NON VÉRIFIÉ — aucune relecture n'a confirmé l'effacement",
        );
        y += 26.0;
    }

    // Organisation | Client
    let half = (CW - 12.0) / 2.0;
    let x2 = M + half + 12.0;
    let top = y;
    let mut ya = section(&mut p, M, y, half, "Organisation");
    let mut yb = section(&mut p, x2, y, half, "Client");
    let o = &rec.org;
    let c = &rec.customer;
    for (l, a, b) in [
        ("Nom", &o.name, &c.name),
        ("Adresse", &o.address, &c.address),
        ("Contact", &o.contact_name, &c.contact_name),
        ("Téléphone", &o.phone, &c.phone),
    ] {
        kv(&mut p, M, ya, half, 62.0, l, &or_dash(a));
        kv(&mut p, x2, yb, half, 62.0, l, &or_dash(b));
        ya += ROW;
        yb += ROW;
    }
    let h = ya - top - 6.0;
    frame(&mut p, M, top, half, h);
    frame(&mut p, x2, top, half, h);
    y = top + h + 10.0;

    // Disque
    let top = y;
    let d = &rec.disk;
    let mut yl = section(&mut p, M, y, CW, "Disque");
    let mut yr = yl;
    let real = match rec.real_size_bytes {
        Some(n) => size_text(n),
        None => "Non vérifiée (HPA/DCO non lu)".to_string(),
    };
    for (l, v) in [
        ("Modèle", d.model.clone()),
        ("N° de série", d.serial.clone()),
        ("Bus", d.bus.clone()),
        ("Type", d.media.clone()),
    ] {
        kv(&mut p, M, yl, half, 70.0, l, &or_dash(&v));
        yl += ROW;
    }
    for (l, v) in [
        ("Taille apparente", size_text(d.size_bytes)),
        ("Taille réelle", real),
        ("Firmware", d.firmware.clone()),
    ] {
        kv(&mut p, x2, yr, half, 80.0, l, &or_dash(&v));
        yr += ROW;
    }
    let h = yl.max(yr) - top - 6.0;
    frame(&mut p, M, top, CW, h);
    y = top + h + 10.0;

    // Technicien + signature
    let top = y;
    let yt = section(&mut p, M, y, CW, "Technicien");
    kv(
        &mut p,
        M,
        yt,
        half,
        62.0,
        "Nom",
        &or_dash(&rec.technician.name),
    );
    p.fill(GREY);
    p.text(x2, yt, 8.0, Font::Sans, "Signature");
    p.stroke(BORDER);
    p.rect(x2 + 50.0, yt - 8.0, half - 56.0, 36.0, false, true);
    let h = 15.0 + 44.0;
    frame(&mut p, M, top, CW, h);
    y = top + h + 10.0;

    // Détails de l'effacement (grille 2 colonnes)
    let top = y;
    let mut yl = section(&mut p, M, y, CW, "Détails de l'effacement");
    let mut yr = yl;
    let verif = format!("{} ({})", rec.verify, rec.verify_result);
    let left: [(&str, String); 9] = [
        ("Début", rec.start.clone()),
        ("Fin", rec.end.clone()),
        ("Durée", rec.duration_hms()),
        (
            "Statut",
            format!("{} ({})", rec.status.code(), rec.status.fr()),
        ),
        ("Méthode", rec.method.clone()),
        (
            "Algorithme PRNG",
            if rec.passes.iter().any(|p| p == "firmware") {
                "— (commande firmware)".to_string()
            } else {
                "SplitMix64".to_string()
            },
        ),
        ("Passes", rec.passes.join(", ")),
        ("Passe finale", rec.final_pass.clone()),
        ("Vérification", verif),
    ];
    let right: [(&str, String); 9] = [
        (
            "Tours (fait/demandé)",
            format!("{} / {}", rec.rounds_done, rec.rounds_requested),
        ),
        (
            "*Octets effacés",
            format!(
                "{} ({} %)",
                thousands(rec.bytes_erased),
                dec(rec.percent, 2)
            ),
        ),
        ("HPA/DCO", rec.hpa_dco.clone()),
        ("Débit moyen", format!("{} MB/s", dec(rec.avg_mb_s, 1))),
        ("Erreurs de passe", rec.errors_pass.to_string()),
        ("Erreurs de sync", rec.errors_sync.to_string()),
        ("Erreurs de vérif.", rec.errors_verify.to_string()),
        ("Reprises", rec.errors_retries.to_string()),
        ("Tag", rec.tag.clone()),
    ];
    for (l, v) in left {
        kv(&mut p, M, yl, half, 82.0, l, &or_dash(&v));
        yl += ROW;
    }
    for (l, v) in right {
        kv(&mut p, x2, yr, half, 95.0, l, &or_dash(&v));
        yr += ROW;
    }
    let h = yl.max(yr) - top - 6.0;
    frame(&mut p, M, top, CW, h);
    y = top + h + 10.0;

    // Informations (notes) : autant de lignes que la place le permet avant la note de bas de page.
    let top = y;
    let mut yi = section(&mut p, M, y, CW, "Informations");
    let max_y = 770.0;
    if rec.notes.is_empty() {
        kv(&mut p, M, yi, CW, 0.0, "", "—");
        yi += ROW;
    }
    for (i, n) in rec.notes.iter().enumerate() {
        if yi > max_y - ROW && i + 1 < rec.notes.len() {
            kv(
                &mut p,
                M,
                yi,
                CW,
                0.0,
                "",
                &format!("… {} note(s) supplémentaire(s)", rec.notes.len() - i),
            );
            yi += ROW;
            break;
        }
        kv(&mut p, M, yi, CW, 0.0, "", &format!("• {n}"));
        yi += ROW;
    }
    frame(&mut p, M, top, CW, yi - top - 6.0);

    p.fill(GREY);
    p.text(
        M,
        794.0,
        7.5,
        Font::Sans,
        "* octets effacés : partie du disque écrite au moins une fois",
    );
    footer(&mut p, rec, generated, 1);
    p
}

// ---------- Page 2 ----------

fn page2(rec: &EraseRecord, generated: &str) -> Page {
    let mut p = Page::new();
    p.fill(BLACK);
    p.text(
        M,
        50.0,
        16.0,
        Font::SansBold,
        "Données SMART et profil de débit",
    );
    p.fill(GREY);
    let recall = format!(
        "Modèle : {}    N° de série : {}    Certificat : {}",
        rec.disk.model, rec.disk.serial, rec.id
    );
    p.text(M, 66.0, 9.0, Font::Sans, &fit(&recall, Font::Sans, 9.0, CW));

    let mut y = 80.0;
    let graph_top_min = 540.0;
    match &rec.smart {
        Some(s) => {
            // Informations SMART en 2 colonnes.
            let top = y;
            let half = (CW - 12.0) / 2.0;
            let mut yy = section(&mut p, M, y, CW, "Informations SMART");
            let mut items: Vec<(String, String)> = s.info.clone();
            items.push(("État de santé".into(), or_dash(&s.health)));
            for pair in items.chunks(2) {
                for (k, (l, v)) in pair.iter().enumerate() {
                    let x = M + k as f32 * (half + 12.0);
                    kv(&mut p, x, yy, half, 95.0, l, &or_dash(v));
                }
                yy += ROW;
            }
            frame(&mut p, M, top, CW, yy - top - 6.0);
            y = yy + 4.0;

            // Tableau des attributs.
            let cols: [(&str, f32); 7] = [
                ("ID", 28.0),
                ("Nom", 168.0),
                ("Flags", 60.0),
                ("Value", 45.0),
                ("Worst", 45.0),
                ("Thresh", 45.0),
                ("Raw", 0.0),
            ];
            let raw_w = CW - cols.iter().map(|c| c.1).sum::<f32>();
            let width = |i: usize| if i == 6 { raw_w } else { cols[i].1 };
            p.fill(LIGHT);
            p.rect(M, y, CW, 14.0, true, false);
            p.fill(BLACK);
            let mut x = M;
            for (i, (name, _)) in cols.iter().enumerate() {
                p.text(x + 3.0, y + 10.0, 8.0, Font::SansBold, name);
                x += width(i);
            }
            y += 14.0;
            for (i, a) in s.attrs.iter().enumerate() {
                if y > graph_top_min - 30.0 {
                    p.fill(GREY);
                    p.text(
                        M + 3.0,
                        y + 9.0,
                        8.0,
                        Font::Sans,
                        &format!("… {} attribut(s) non affiché(s)", s.attrs.len() - i),
                    );
                    y += 12.0;
                    break;
                }
                if a.failing {
                    p.fill(PALE_RED);
                    p.rect(M, y, CW, 11.0, true, false);
                }
                p.fill(if a.failing { RED } else { BLACK });
                let id = a.id.to_string();
                let vals = [
                    &id, &a.name, &a.flags, &a.value, &a.worst, &a.thresh, &a.raw,
                ];
                let mut x = M;
                for (k, v) in vals.iter().enumerate() {
                    // Attribut en défaut : rouge et gras.
                    let f = if a.failing {
                        Font::MonoBold
                    } else {
                        Font::Mono
                    };
                    p.text(x + 3.0, y + 8.5, 7.5, f, &fit(v, f, 7.5, width(k) - 5.0));
                    x += width(k);
                }
                y += 11.0;
            }
            p.stroke(BORDER);
            p.width(0.6);
            p.line(M, y, M + CW, y);
        }
        None => {
            p.fill(LIGHT);
            p.stroke(BORDER);
            p.width(0.6);
            p.rect(M, y, CW, 40.0, true, true);
            p.fill(GREY);
            p.text(
                M + 12.0,
                y + 24.0,
                10.0,
                Font::Sans,
                "Données SMART non disponibles (non lues avant l'effacement ou non supportées)",
            );
            y += 40.0;
        }
    }

    speed_graph(&mut p, rec, y + 24.0);
    footer(&mut p, rec, generated, 2);
    p
}

fn speed_graph(p: &mut Page, rec: &EraseRecord, top: f32) {
    let top = top.min(560.0);
    let section_y = section(
        p,
        M,
        top,
        CW,
        "Profil de débit (MB/s) selon l'avancement (%)",
    );
    let (gx, gy) = (M + 46.0, section_y + 6.0);
    let (gw, gh) = (CW - 66.0, (770.0 - 40.0 - gy).clamp(80.0, 220.0));
    // Seules les mesures finies sont tracées (aucun NaN/inf dans le flux PDF).
    let samples: Vec<(f32, f32)> = rec
        .speed_samples
        .iter()
        .copied()
        .filter(|s| s.0.is_finite() && s.1.is_finite())
        .collect();
    let rec_max = if rec.max_mb_s.is_finite() {
        rec.max_mb_s as f32
    } else {
        0.0
    };
    let vmax = samples
        .iter()
        .map(|s| s.1)
        .fold(0.0f32, f32::max)
        .max(rec_max);
    let ymax = nice_max(vmax);

    // Grille et graduations
    p.width(0.4);
    for i in 0..=5 {
        let v = ymax * i as f32 / 5.0;
        let yy = gy + gh - gh * i as f32 / 5.0;
        p.stroke(LIGHT);
        p.line(gx, yy, gx + gw, yy);
        p.fill(GREY);
        let label = dec(v as f64, if ymax < 10.0 { 1 } else { 0 });
        let lw = label.chars().count() as f32 * 7.0 * 0.52;
        p.text(gx - 4.0 - lw, yy + 2.5, 7.0, Font::Sans, &label);
    }
    for i in 0..=10 {
        let xx = gx + gw * i as f32 / 10.0;
        p.stroke(BORDER);
        p.line(xx, gy + gh, xx, gy + gh + 3.0);
        p.fill(GREY);
        let label = format!("{}", i * 10);
        p.text(
            xx - label.len() as f32 * 1.8,
            gy + gh + 12.0,
            7.0,
            Font::Sans,
            &label,
        );
    }
    // Axes
    p.stroke(BLACK);
    p.width(0.8);
    p.line(gx, gy, gx, gy + gh);
    p.line(gx, gy + gh, gx + gw, gy + gh);
    p.fill(GREY);
    p.text(gx - 40.0, gy - 2.0, 7.0, Font::Sans, "MB/s");
    p.text(
        gx + gw - 50.0,
        gy + gh + 22.0,
        7.0,
        Font::Sans,
        "Avancement (%)",
    );

    if samples.is_empty() {
        p.text(
            gx + 10.0,
            gy + gh / 2.0,
            9.0,
            Font::Sans,
            "Aucune mesure de débit",
        );
    } else {
        let pts: Vec<(f32, f32)> = samples
            .iter()
            .map(|&(pct, v)| {
                (
                    gx + gw * pct.clamp(0.0, 100.0) / 100.0,
                    gy + gh - gh * (v.max(0.0) / ymax).min(1.0),
                )
            })
            .collect();
        p.stroke(BLUE);
        p.width(1.2);
        if pts.len() == 1 {
            p.fill(BLUE);
            p.rect(pts[0].0 - 1.5, pts[0].1 - 1.5, 3.0, 3.0, true, false);
        } else {
            p.polyline(&pts);
        }
        // Ligne de la moyenne
        if rec.avg_mb_s.is_finite() {
            let ya = gy + gh - gh * (rec.avg_mb_s as f32 / ymax).clamp(0.0, 1.0);
            p.stroke(ORANGE);
            p.width(0.6);
            p.line(gx, ya, gx + gw, ya);
        }
    }
    p.fill(BLACK);
    let stats = format!(
        "Min : {} MB/s    Moy : {} MB/s    Max : {} MB/s",
        dec(rec.min_mb_s, 1),
        dec(rec.avg_mb_s, 1),
        dec(rec.max_mb_s, 1)
    );
    p.text(gx, gy + gh + 36.0, 9.0, Font::SansBold, &stats);
}

// ---------- Point d'entrée ----------

/// PDF A4 de 2 pages pour un enregistrement d'effacement.
pub fn render(rec: &EraseRecord, logo: Option<Image>) -> Vec<u8> {
    let generated = DateTime::now().french();
    let dims = logo.as_ref().map(|l| (l.w, l.h));
    let pages = vec![page1(rec, dims, &generated), page2(rec, &generated)];
    // Titre en ASCII : le dictionnaire Info n'utilise pas l'encodage WinAnsi (« — » s'afficherait mal).
    Doc {
        title: format!("{} - Certificat {}", rec.app, rec.id),
        pages,
        logo,
    }
    .to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::tests::sample_record;
    use crate::report::{SmartAttr, SmartInfo};

    fn contains(hay: &[u8], needle: &str) -> bool {
        hay.windows(needle.len()).any(|w| w == needle.as_bytes())
    }

    #[test]
    fn two_pages_with_id_and_status() {
        let r = sample_record();
        let b = render(&r, None);
        assert!(b.starts_with(b"%PDF-1.4"));
        assert!(b.ends_with(b"%%EOF\n"));
        assert!(contains(&b, "/Count 2"));
        assert!(contains(&b, &r.id));
        assert!(contains(&b, "ERASED"));
        assert!(contains(&b, "NIST 800-88 : Clear"));
        assert!(contains(&b, "Page 1 / 2") && contains(&b, "Page 2 / 2"));
        assert!(contains(&b, "SplitMix64"));
        assert!(!contains(&b, "TEST SUR FICHIER"));
        // Pas de SMART : encadré explicite.
        assert!(contains(&b, "SMART non disponibles"));
    }

    #[test]
    fn test_target_shows_red_banner() {
        let mut r = sample_record();
        r.test_target = true;
        assert!(contains(&render(&r, None), "TEST SUR FICHIER"));
    }

    #[test]
    fn failed_status_is_printed() {
        let mut r = sample_record();
        r.status = Status::Failed;
        let b = render(&r, None);
        assert!(contains(&b, "FAILED"));
        assert!(!contains(&b, "ERASED"));
    }

    #[test]
    fn long_values_are_truncated() {
        let mut r = sample_record();
        r.customer.name = "X".repeat(300);
        let b = render(&r, None);
        assert!(!contains(&b, &"X".repeat(300)));
        assert!(contains(&b, &"X".repeat(20)));
    }

    #[test]
    fn smart_table_is_rendered_with_failing_rows() {
        let mut r = sample_record();
        r.smart = Some(SmartInfo {
            info: vec![("Heures de fonctionnement".into(), "12345".into())],
            health: "PASSED".into(),
            attrs: vec![SmartAttr {
                id: 5,
                name: "Reallocated_Sector_Ct".into(),
                flags: "PO--CK".into(),
                value: "001".into(),
                worst: "001".into(),
                thresh: "036".into(),
                raw: "4096".into(),
                failing: true,
            }],
        });
        let b = render(&r, None);
        assert!(contains(&b, "Reallocated_Sector_Ct"));
        assert!(!contains(&b, "SMART non disponibles"));
    }

    #[test]
    fn real_size_and_firmware_fields_are_printed() {
        let mut r = sample_record();
        assert!(contains(&render(&r, None), "\\(HPA/DCO non lu\\)"));
        r.real_size_bytes = Some(320_072_933_376 + 512_000);
        r.hpa_dco = "HPA : 1000 secteurs cachés".into();
        r.method = "ATA Sanitize Crypto Scramble".into();
        r.level = "Purge".into();
        r.passes = vec!["firmware".into()];
        r.verify_result = "Marqueurs : 1002/1002 effacés".into();
        let b = render(&r, None);
        assert!(contains(&b, "320,07 Go \\(320 073 445 376 octets\\)"));
        assert!(contains(&b, "NIST 800-88 : Purge"));
        assert!(contains(&b, "Marqueurs : 1002/1002"));
        assert!(contains(&b, "commande firmware"));
        assert!(!contains(&b, "SplitMix64"));
    }

    #[test]
    fn logo_is_embedded() {
        let img = Image {
            w: 2,
            h: 1,
            rgb: vec![255, 0, 0, 0, 0, 255],
        };
        let b = render(&sample_record(), Some(img));
        assert!(contains(&b, "/Logo Do"));
        assert!(contains(&b, "/Subtype /Image"));
    }

    #[test]
    fn no_nan_or_infinity_reaches_the_pdf() {
        let mut r = sample_record();
        r.avg_mb_s = f64::NAN;
        r.max_mb_s = f64::INFINITY;
        r.min_mb_s = f64::NEG_INFINITY;
        r.percent = f64::NAN;
        r.speed_samples = vec![
            (0.0, f32::NAN),
            (50.0, 80.0),
            (f32::INFINITY, 10.0),
            (100.0, 60.0),
        ];
        let b = render(&r, None);
        let text = String::from_utf8_lossy(&b);
        for bad in ["NaN", " inf", "-inf", "(inf"] {
            assert!(!text.contains(bad), "valeur non finie dans le PDF : {bad}");
        }
    }

    #[test]
    fn forced_ssd_overwrite_is_highlighted() {
        let mut r = sample_record();
        r.ssd_overwrite = true;
        assert!(contains(&render(&r, None), "SUR SSD/NVMe"));
        assert!(!contains(&render(&sample_record(), None), "SUR SSD/NVMe"));
    }

    #[test]
    fn unverified_erase_is_highlighted() {
        let mut r = sample_record();
        r.verify_result = "Non demandée".into();
        assert!(contains(&render(&r, None), "NON V"));
        assert!(!contains(&render(&sample_record(), None), "NON V"));
    }

    #[test]
    fn small_sizes_are_in_mo() {
        assert_eq!(size_text(268_435_456), "268 Mo (268 435 456 octets)");
        assert_eq!(
            size_text(320_072_933_376),
            "320,07 Go (320 072 933 376 octets)"
        );
        let mut r = sample_record();
        r.disk.size_bytes = 268_435_456;
        // Les parenthèses sont échappées dans les chaînes PDF.
        assert!(contains(
            &render(&r, None),
            "268 Mo \\(268 435 456 octets\\)"
        ));
    }

    /// (x, y PDF, texte brut) de chaque opération de texte du PDF.
    fn text_ops(pdf: &[u8]) -> Vec<(f32, f32, Vec<u8>)> {
        let s = String::from_utf8_lossy(pdf).to_string();
        let mut out = Vec::new();
        for chunk in s.split("BT /").skip(1) {
            let Some(td) = chunk.find(" Td (") else {
                continue;
            };
            let nums: Vec<f32> = chunk[..td]
                .split_whitespace()
                .filter_map(|t| t.parse().ok())
                .collect();
            let rest = &chunk[td + 5..];
            let Some(end) = rest.find(") Tj ET") else {
                continue;
            };
            if nums.len() >= 3 {
                let n = nums.len();
                out.push((nums[n - 2], nums[n - 1], rest.as_bytes()[..end].to_vec()));
            }
        }
        out
    }

    #[test]
    fn disk_block_labels_and_values_share_their_line_even_with_empty_serial() {
        let mut r = sample_record();
        r.disk.serial = String::new();
        r.disk.model = "Virtual Disk".into();
        let ops = text_ops(&render(&r, None));
        // Libellé « N° de série » (WinAnsi : \260 = °, \351 = é) et la valeur qui suit.
        let label = b"N\\260 de s\\351rie".to_vec();
        let i = ops
            .iter()
            .position(|o| o.2 == label)
            .expect("libellé présent");
        let (lx, ly, _) = &ops[i];
        let (vx, vy, v) = &ops[i + 1];
        assert_eq!(ly, vy, "valeur sur la même ligne que son libellé");
        assert!(vx > lx);
        assert_eq!(v, b"\\227", "n° de série vide affiché « — »");
        // Le modèle est sur la ligne au-dessus, à un pas de ROW.
        let m = ops
            .iter()
            .position(|o| o.2 == b"Mod\\350le".to_vec())
            .unwrap();
        assert_eq!(ops[m + 1].2, b"Virtual Disk".to_vec());
        assert!((ops[m].1 - ly - ROW).abs() < 0.01);
    }

    #[test]
    fn helpers() {
        assert_eq!(thousands(320_072_933_376), "320 072 933 376");
        assert_eq!(thousands(12), "12");
        assert_eq!(dec(96.04, 1), "96,0");
        assert_eq!(nice_max(127.1), 200.0);
        assert_eq!(nice_max(96.0), 100.0);
        assert_eq!(nice_max(0.0), 1.0);
        assert!(Code128::new("ƁDE-20261109-134548-ABCDEF").is_ok());
    }
}
