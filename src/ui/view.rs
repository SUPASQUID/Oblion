//! Affichage des écrans (fidèle à la maquette v2 : 1024×768, menu à gauche, étapes 1 à 5).

use iced::widget::canvas::{self, Frame, Geometry, Path, Stroke};
use iced::widget::text::Wrapping;
use iced::widget::{
    button, center, checkbox, column, container, opaque, pick_list, row, scrollable, space, stack,
    text, text_input, Canvas, Column, Row,
};
use iced::{
    mouse, Alignment, Color, Element, Fill, FillPortion, Font, Point, Rectangle, Renderer, Shrink,
    Theme,
};

use super::logo;
use super::state::{self, HistoryFilter};
use super::style::{self, Btn, Pal, Tone};
use super::{App, Field, Message, Outcome, Screen};
use crate::app::{APP_NAME, VERSION};
use crate::detect::{self, DiskInfo, MediaType};
use crate::erase_hdd::Phase;
use crate::erase_ssd::Decision;
use crate::report::{EraseRecord, Status};

type El<'a> = Element<'a, Message>;

#[derive(Debug, Clone, Copy)]
pub struct Fonts {
    pub regular: Font,
    pub strong: Font,
    pub bold: Font,
    pub mono: Font,
}

// ---------- Briques ----------

fn t<'a>(s: impl text::IntoFragment<'a>, size: f32, color: Color) -> text::Text<'a> {
    text(s).size(size).color(color)
}

fn btn<'a>(p: Pal, f: &Fonts, label: &'a str, kind: Btn, msg: Option<Message>) -> El<'a> {
    button(
        container(text(label).size(14).font(f.strong))
            .height(Fill)
            .align_y(Alignment::Center),
    )
    .height(44)
    .padding([0, 22])
    .on_press_maybe(msg)
    .style(move |_, s| style::button_style(p, kind, s))
    .into()
}

fn badge<'a>(p: Pal, f: &Fonts, label: String, tone: Tone) -> El<'a> {
    let (bg, ink) = tone.colors(&p);
    container(t(label, 12.0, ink).font(f.strong).wrapping(Wrapping::None))
        .padding([3, 9])
        .style(move |_| style::panel(bg, bg, 0.0, 10.0))
        .into()
}

fn outline_badge<'a>(p: Pal, f: &Fonts, label: String) -> El<'a> {
    container(
        t(label, 12.0, p.text)
            .font(f.strong)
            .wrapping(Wrapping::None),
    )
    .padding([2, 7])
    .style(move |_| style::panel(Color::TRANSPARENT, p.border_strong, 1.0, 4.0))
    .into()
}

fn radio_dot<'a>(p: Pal, on: bool, disabled: bool) -> El<'a> {
    let ring = if disabled {
        p.border
    } else if on {
        p.accent
    } else {
        p.border_strong
    };
    let dot = if on { p.accent } else { Color::TRANSPARENT };
    container(
        container(space())
            .width(8)
            .height(8)
            .style(move |_| style::panel(dot, dot, 0.0, 4.0)),
    )
    .width(16)
    .height(16)
    .center_x(16)
    .center_y(16)
    .style(move |_| style::panel(Color::TRANSPARENT, ring, 2.0, 8.0))
    .into()
}

fn hr<'a>(p: Pal) -> El<'a> {
    container(space())
        .width(Fill)
        .height(1)
        .style(move |_| style::fill(p.border))
        .into()
}

fn panel<'a>(p: Pal, content: impl Into<El<'a>>) -> container::Container<'a, Message> {
    container(content).style(move |_| style::panel(p.surface, p.border, 1.0, 8.0))
}

fn tone_panel<'a>(
    p: Pal,
    tone: Tone,
    content: impl Into<El<'a>>,
) -> container::Container<'a, Message> {
    let (bg, ink) = tone.colors(&p);
    container(content).style(move |_| style::panel(bg, ink, 1.0, 8.0))
}

fn labeled_input<'a>(
    p: Pal,
    f: &Fonts,
    label: &'a str,
    value: &str,
    on: Option<fn(String) -> Message>,
    mono: bool,
) -> El<'a> {
    let mut input = text_input("", value)
        .size(14)
        .padding([10, 10])
        .style(move |_, s| style::input_style(p, s, false));
    if mono {
        input = input.font(f.mono);
    }
    if let Some(on) = on {
        input = input.on_input(on);
    }
    column![t(label, 13.0, p.muted), input].spacing(4).into()
}

fn title_block<'a>(p: Pal, f: &Fonts, title: String, subtitle: El<'a>) -> El<'a> {
    column![t(title, 22.0, p.text).font(f.strong), subtitle]
        .spacing(4)
        .into()
}

fn footer<'a>(p: Pal, left: El<'a>, right: Vec<El<'a>>) -> El<'a> {
    column![
        hr(p),
        row![
            left,
            space().width(Fill),
            Row::with_children(right).spacing(12)
        ]
        .spacing(16)
        .align_y(Alignment::Center),
    ]
    .spacing(16)
    .into()
}

fn kv_grid<'a>(
    p: Pal,
    f: &Fonts,
    rows: Vec<(String, String)>,
    key_w: f32,
    mono_keys: &[&str],
) -> El<'a> {
    // Deux colonnes clé/valeur côte à côte (grille 4 colonnes de la maquette).
    let mut lines: Vec<El<'a>> = Vec::new();
    let n = rows.len();
    let mut it = rows.into_iter().peekable();
    let mut i = 0;
    while it.peek().is_some() {
        let mut cells: Vec<El<'a>> = Vec::new();
        for _ in 0..2 {
            if let Some((k, v)) = it.next() {
                let mono = mono_keys.contains(&k.as_str());
                let val = t(v, 14.0, p.text).font(if mono { f.mono } else { f.strong });
                cells.push(
                    container(t(k, 14.0, p.muted))
                        .width(key_w)
                        .padding([10, 16])
                        .into(),
                );
                cells.push(container(val).width(Fill).padding([10, 16]).into());
            } else {
                cells.push(space().width(key_w).into());
                cells.push(space().width(Fill).into());
            }
        }
        lines.push(Row::with_children(cells).into());
        i += 2;
        if i < n {
            lines.push(hr(p));
        }
    }
    panel(p, Column::with_children(lines)).width(Fill).into()
}

// ---------- Cadre : menu + étapes ----------

fn sidebar<'a>(app: &'a App) -> El<'a> {
    let p = app.pal();
    let f = &app.fonts;
    let nav = |label: &'a str, target: Screen| -> El<'a> {
        let sel = match target {
            Screen::Disks => app.screen.step().is_some(),
            s => app.screen == s,
        };
        button(
            container(t(label, 14.0, p.text).font(if sel { f.strong } else { f.regular }))
                .height(Fill)
                .align_y(Alignment::Center),
        )
        .width(Fill)
        .height(44)
        .padding([0, 14])
        .on_press_maybe((!app.job_running()).then_some(Message::Nav(target)))
        .style(move |_, s| style::button_style(p, Btn::Nav(sel), s))
        .into()
    };
    let env = if app.demo {
        "MODE DÉMO".to_string()
    } else if app.winpe {
        "WinPE".to_string()
    } else {
        "Windows".to_string()
    };
    let brand = row![
        Canvas::new(logo::Mark {
            ink: p.text,
            accent: p.accent
        })
        .width(22)
        .height(22),
        column![
            t(APP_NAME, 15.0, p.text).font(f.bold),
            t("Certification d'effacement", 11.0, p.muted),
        ]
        .spacing(0),
    ]
    .spacing(10)
    .align_y(Alignment::Center);
    container(
        column![
            container(brand).padding([6, 10]),
            space().height(8),
            nav("Disques", Screen::Disks),
            nav("Historique", Screen::History),
            nav("Paramètres", Screen::Settings),
            space().height(Fill),
            container(
                column![
                    t("Lancé depuis", 12.0, p.muted),
                    t(app.shown(std::path::Path::new(&app.exe_dir)), 12.0, p.muted).font(f.mono),
                    t(
                        format!("{env} · v{VERSION}"),
                        12.0,
                        if app.demo { p.warn } else { p.muted }
                    )
                    .font(if app.demo { f.strong } else { f.regular }),
                ]
                .spacing(2)
            )
            .padding([10, 14]),
        ]
        .spacing(2),
    )
    .width(188)
    .height(Fill)
    .padding([12, 8])
    .style(move |_| style::fill(p.side))
    .into()
}

fn steps<'a>(p: Pal, f: &Fonts, current: u8) -> El<'a> {
    let names = [
        "Disque",
        "Configuration",
        "Confirmation",
        "Effacement",
        "Certificat",
    ];
    let mut items: Vec<El<'a>> = Vec::new();
    for (i, name) in names.iter().enumerate() {
        let n = i as u8 + 1;
        let (circle, label): (El<'a>, El<'a>) = if n < current {
            (
                container(t("✓", 13.0, p.ok).font(f.bold))
                    .center_x(22)
                    .center_y(22)
                    .style(move |_| style::panel(p.ok_soft, p.ok_soft, 0.0, 11.0))
                    .into(),
                t(*name, 13.0, p.muted).into(),
            )
        } else if n == current {
            (
                container(t(n.to_string(), 13.0, p.on_accent).font(f.strong))
                    .center_x(22)
                    .center_y(22)
                    .style(move |_| style::panel(p.accent, p.accent, 0.0, 11.0))
                    .into(),
                t(*name, 13.0, p.text).font(f.strong).into(),
            )
        } else {
            (
                container(t(n.to_string(), 13.0, p.muted))
                    .center_x(20)
                    .center_y(20)
                    .style(move |_| style::panel(Color::TRANSPARENT, p.border_strong, 1.0, 10.0))
                    .into(),
                t(*name, 13.0, p.muted).into(),
            )
        };
        items.push(
            row![circle, label]
                .spacing(6)
                .align_y(Alignment::Center)
                .into(),
        );
        if n < 5 {
            items.push(
                container(space())
                    .width(Fill)
                    .height(1)
                    .style(move |_| style::fill(p.border_strong))
                    .into(),
            );
        }
    }
    Row::with_children(items)
        .spacing(10)
        .align_y(Alignment::Center)
        .into()
}

pub fn view(app: &App) -> El<'_> {
    let p = app.pal();
    let body: El<'_> = match app.screen {
        Screen::Disks => disks(app),
        Screen::Config => config(app),
        Screen::Confirm => confirm(app),
        Screen::Erase => erase(app),
        Screen::Result => result(app),
        Screen::History => history(app),
        Screen::Settings => settings(app),
        Screen::NeedAdmin => need_admin(app),
    };
    let top = if app.screen.step().is_some_and(|s| s > 1) {
        20
    } else {
        24
    };
    let main = container(body)
        .width(Fill)
        .height(Fill)
        .padding(iced::Padding {
            top: top as f32,
            right: 28.0,
            bottom: 24.0,
            left: 28.0,
        });
    let base: El<'_> = row![
        sidebar(app),
        container(space())
            .width(1)
            .height(Fill)
            .style(move |_| style::fill(p.border)),
        main
    ]
    .height(Fill)
    .into();
    let base = container(base)
        .width(Fill)
        .height(Fill)
        .style(move |_| style::fill(p.bg));
    if app.quit_asked {
        let dialog = confirm_dialog(
            app,
            "Un effacement est en cours",
            "Fermer la fenêtre ANNULE l'effacement : le moteur s'arrête proprement et un certificat ABORTED est produit, puis la fenêtre se ferme. Une commande firmware déjà lancée se termine d'abord dans le disque.",
            "Continuer l'effacement",
            Message::ConfirmQuit(false),
            "Annuler et fermer",
            Message::ConfirmQuit(true),
        );
        stack![base, dialog].into()
    } else {
        base.into()
    }
}

#[allow(clippy::too_many_arguments)]
fn confirm_dialog<'a>(
    app: &'a App,
    title: &'a str,
    body: &'a str,
    no: &'a str,
    no_msg: Message,
    yes: &'a str,
    yes_msg: Message,
) -> El<'a> {
    let p = app.pal();
    let f = &app.fonts;
    let card = container(
        column![
            t(title, 19.0, p.danger).font(f.bold),
            t(body, 14.0, p.text),
            row![
                space().width(Fill),
                btn(p, f, no, Btn::Secondary, Some(no_msg)),
                btn(p, f, yes, Btn::Danger, Some(yes_msg)),
            ]
            .spacing(12),
        ]
        .spacing(14),
    )
    .width(520)
    .padding(22)
    .style(move |_| style::panel(p.surface, p.danger, 1.0, 8.0));
    opaque(center(card).width(Fill).height(Fill).style(move |_| {
        style::fill(Color {
            a: 0.45,
            ..Color::BLACK
        })
    }))
}

// ---------- 01 Disques ----------

fn type_label(d: &DiskInfo) -> String {
    match (d.bus, d.media) {
        (detect::Bus::Usb, MediaType::Unknown) => "USB".into(),
        (_, m) => m.to_string(),
    }
}

fn disk_line(d: &DiskInfo) -> String {
    format!(
        "Disque {} — {} · {} · {}",
        d.number,
        d.display_model(),
        detect::human_size(d.size_bytes),
        type_label(d)
    )
}

const DISK_COLS: [f32; 7] = [40.0, 54.0, 158.0, 66.0, 58.0, 62.0, 122.0];

fn disks(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let protected = app.disks.iter().filter(|r| r.protection.is_some()).count();
    let subtitle = if app.loading {
        "Recherche des disques…".to_string()
    } else {
        format!(
            "{} disque(s) · {} protégé(s) · sélectionnez le disque à effacer",
            app.disks.len(),
            protected
        )
    };
    let head = row![
        title_block(
            p,
            f,
            "Disques détectés".into(),
            t(subtitle, 14.0, p.muted).into()
        ),
        space().width(Fill),
        btn(
            p,
            f,
            "↻ Actualiser",
            Btn::Secondary,
            (!app.loading).then_some(Message::Refresh)
        ),
    ]
    .align_y(Alignment::End);

    let hcell = |s: &'static str, w: Option<f32>| -> El<'_> {
        let c = container(t(s, 12.0, p.muted).font(f.strong)).padding([0, 4]);
        match w {
            Some(w) => c.width(w).into(),
            None => c.width(Fill).into(),
        }
    };
    let header = container(
        row![
            hcell("", Some(DISK_COLS[0])),
            hcell("Disque", Some(DISK_COLS[1])),
            hcell("Modèle", None),
            hcell("N° de série", Some(DISK_COLS[2])),
            hcell("Taille", Some(DISK_COLS[3])),
            hcell("Bus", Some(DISK_COLS[4])),
            hcell("Type", Some(DISK_COLS[5])),
            hcell("État", Some(DISK_COLS[6])),
        ]
        .align_y(Alignment::Center),
    )
    .height(40)
    .padding([0, 8])
    .align_y(Alignment::Center)
    .style(move |_| style::fill(p.surface2));

    let mut rows: Vec<El<'_>> = vec![header.into(), hr(p)];
    for (i, r) in app.disks.iter().enumerate() {
        let d = &r.info;
        let prot = r.protection.is_some();
        let sel = app.selected == Some(d.number);
        let ink = if prot { p.muted } else { p.text };
        let note = match &r.protection {
            Some(reason) => reason.clone(),
            None => {
                let mut parts = Vec::new();
                if !d.volumes.is_empty() {
                    parts.push(
                        d.volumes
                            .iter()
                            .map(|c| format!("{c}:"))
                            .collect::<Vec<_>>()
                            .join(" "),
                    );
                }
                if let Some(h) = r.probe.as_deref().and_then(state::smart_warning) {
                    parts.push(format!("SMART : {h}"));
                }
                if d.removable {
                    parts.push("amovible".into());
                }
                parts.join(" · ")
            }
        };
        let (state_label, tone) = if prot {
            ("Protégé".to_string(), Tone::Neutral)
        } else {
            match r.probe.as_deref() {
                None => ("Lecture…".to_string(), Tone::Neutral),
                Some(pr) if state::smart_warning(pr).is_some() => {
                    ("SMART à vérifier".to_string(), Tone::Warn)
                }
                Some(_) => ("Effaçable".to_string(), Tone::Accent),
            }
        };
        let cell = |e: El<'static>, w: f32| -> El<'static> {
            container(e).width(w).padding([0, 4]).into()
        };
        let line = row![
            container(radio_dot(p, sel, prot))
                .width(DISK_COLS[0])
                .center_x(DISK_COLS[0]),
            cell(
                t(d.number.to_string(), 14.0, ink).font(f.strong).into(),
                DISK_COLS[1]
            ),
            container(
                container(
                    column![
                        t(d.display_model(), 14.0, ink).wrapping(Wrapping::None),
                        t(note, 12.0, p.muted).wrapping(Wrapping::None),
                    ]
                    .spacing(1)
                )
                .width(Fill)
                .clip(true)
            )
            .width(Fill)
            .padding(iced::Padding {
                left: 4.0,
                right: 12.0,
                ..Default::default()
            }),
            cell(
                t(detect::serial_or_none(&d.serial).to_string(), 13.0, ink)
                    .font(f.mono)
                    .wrapping(Wrapping::None)
                    .into(),
                DISK_COLS[2]
            ),
            cell(
                t(detect::human_size(d.size_bytes), 14.0, ink).into(),
                DISK_COLS[3]
            ),
            cell(t(d.bus.to_string(), 14.0, ink).into(), DISK_COLS[4]),
            cell(outline_badge(p, f, type_label(d)), DISK_COLS[5]),
            cell(badge(p, f, state_label, tone), DISK_COLS[6]),
        ]
        .align_y(Alignment::Center);
        let reliable = app.ctx.as_ref().is_some_and(|c| c.reliable);
        let line: El<'_> = if prot || !reliable {
            container(line)
                .height(52)
                .padding([0, 8])
                .align_y(Alignment::Center)
                .style(move |_| style::fill(p.surface2))
                .into()
        } else {
            button(container(line).height(Fill).align_y(Alignment::Center))
                .width(Fill)
                .height(52)
                .padding([0, 8])
                .on_press(Message::SelectDisk(d.number))
                .style(move |_, s| style::button_style(p, Btn::Row(sel), s))
                .into()
        };
        rows.push(line);
        if i + 1 < app.disks.len() {
            rows.push(hr(p));
        }
    }
    let table = panel(p, scrollable(Column::with_children(rows)))
        .width(Fill)
        .clip(true);

    let mut notes: Vec<El<'_>> = vec![t(
        "Le disque système et la clé de démarrage sont protégés et ne peuvent pas être sélectionnés.",
        12.0,
        p.muted,
    )
    .into()];
    if let Some(ctx) = &app.ctx {
        for w in &ctx.warnings {
            notes.push(t(format!("ATTENTION : {w}"), 12.0, p.warn).into());
        }
        if !ctx.reliable {
            notes.push(
                t(
                    "Protection non fiable : tout effacement sera refusé.",
                    13.0,
                    p.danger,
                )
                .font(f.strong)
                .into(),
            );
        }
    }
    if let Some(e) = &app.list_error {
        notes.push(
            t(format!("Erreur : {e}"), 13.0, p.danger)
                .font(f.strong)
                .into(),
        );
    }
    if let Some(e) = &app.cfg_error {
        notes.push(
            t(
                format!(
                    "Configuration invalide, effacement bloqué (comme en ligne de commande) : {e}"
                ),
                13.0,
                p.danger,
            )
            .font(f.strong)
            .into(),
        );
    }

    let sel_row = app
        .selected
        .and_then(|n| app.disks.iter().find(|r| r.info.number == n));
    let left: El<'_> = match sel_row {
        Some(r) => row![
            t("Sélectionné : ", 14.0, p.muted),
            t(disk_line(&r.info), 14.0, p.text).font(f.strong),
        ]
        .into(),
        None => t("Aucun disque sélectionné", 14.0, p.muted).into(),
    };
    let ready = sel_row.is_some_and(|r| r.probe.is_some()) && app.cfg_error.is_none();
    let cont_label = if sel_row.is_some() && !ready {
        "Lecture des capacités…"
    } else {
        "Continuer"
    };
    column![
        head,
        table,
        Column::with_children(notes).spacing(4),
        space().height(Fill),
        footer(
            p,
            left,
            vec![btn(
                p,
                f,
                cont_label,
                Btn::Primary,
                ready.then_some(Message::ToConfig)
            )]
        ),
    ]
    .spacing(18)
    .into()
}

// ---------- 02 Configuration ----------

fn disk_subtitle<'a>(p: Pal, f: &Fonts, d: &DiskInfo, extra: Option<String>) -> El<'a> {
    let mut r = row![
        t(
            format!("Disque {} · {} · ", d.number, d.display_model()),
            14.0,
            p.muted
        ),
        t(detect::serial_or_none(&d.serial).to_string(), 14.0, p.muted).font(f.mono),
        t(
            format!(
                " · {} · {}",
                detect::human_size(d.size_bytes),
                type_label(d)
            ),
            14.0,
            p.muted
        ),
    ];
    if let Some(e) = extra {
        r = r.push(t(format!(" · {e}"), 14.0, p.muted));
    }
    r.into()
}

fn config(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let Some(form) = &app.form else {
        return t("Aucun disque sélectionné.", 14.0, p.muted).into();
    };
    let media = form
        .option()
        .map(|o| o.analysis.media)
        .unwrap_or(form.disk.media);

    // Méthodes.
    let mut methods: Vec<El<'_>> = vec![t("Méthode d'effacement", 14.0, p.text)
        .font(f.strong)
        .into()];
    if let Some(h) = &form.hint {
        let (_, ink) = Tone::Warn.colors(&p);
        methods.push(
            tone_panel(p, Tone::Warn, t(h.clone(), 12.0, ink).font(f.strong))
                .padding([8, 12])
                .width(Fill)
                .into(),
        );
    }
    if form.options.is_empty() {
        methods.push(
            t(
                format!(
                    "Aucune méthode possible : {}",
                    state::refusal(&form.disk, &form.probe)
                        .unwrap_or_else(|| "raison inconnue".into())
                ),
                14.0,
                p.danger,
            )
            .into(),
        );
    }
    for (i, o) in form.options.iter().enumerate() {
        let sel = form.selected == Some(i);
        let content: El<'_> = if sel {
            let mut head = row![
                radio_dot(p, true, false),
                t(o.label.clone(), 14.0, p.text).font(f.strong)
            ]
            .spacing(10)
            .align_y(Alignment::Center);
            head = head.push(space().width(Fill));
            if o.recommended {
                head = head.push(badge(p, f, format!("Recommandé · {media}"), Tone::Accent));
            }
            column![
                head,
                t(o.reason.clone(), 13.0, p.muted),
                t(
                    format!("{} · durée estimée {} · {}", o.level, o.eta, o.cli_flags()),
                    12.0,
                    p.muted
                ),
            ]
            .spacing(8)
            .into()
        } else {
            row![
                radio_dot(p, false, false),
                t(o.label.clone(), 14.0, p.text),
                space().width(Fill),
                t(format!("{} · {}", o.level, o.eta), 12.0, p.muted).wrapping(Wrapping::None),
            ]
            .spacing(10)
            .align_y(Alignment::Center)
            .into()
        };
        let border = if sel {
            (p.accent, 2.0)
        } else {
            (p.border, 1.0)
        };
        methods.push(
            button(content)
                .width(Fill)
                .padding(if sel { [14, 16] } else { [12, 16] })
                .on_press(Message::PickMethod(i))
                .style(move |_, s| {
                    let mut st = style::button_style(p, Btn::Secondary, s);
                    st.background = Some(iced::Background::Color(p.surface));
                    st.border = style::border(border.0, border.1, 8.0);
                    st
                })
                .into(),
        );
    }
    if let Some(o) = form.option() {
        for w in state::config_warnings(o, &form.probe) {
            let tone = if matches!(o.analysis.decision, Decision::Frozen(_)) {
                Tone::Danger
            } else {
                Tone::Warn
            };
            let (_, ink) = tone.colors(&p);
            methods.push(
                tone_panel(p, tone, t(w, 12.0, ink))
                    .padding([8, 12])
                    .width(Fill)
                    .into(),
            );
        }
    }

    // Informations du certificat.
    let pair = |a: El<'static>, b: El<'static>| -> El<'static> {
        row![
            container(a).width(FillPortion(1)),
            container(b).width(FillPortion(1))
        ]
        .spacing(12)
        .into()
    };
    let c = &form.customer;
    let client_pick = pick_list(app.client_items(), form.client.clone(), Message::PickClient)
        .placeholder("Choisir dans le carnet (clients.toml)…")
        .style(move |_, st| iced::widget::pick_list::Style {
            text_color: p.text,
            placeholder_color: p.disabled_ink,
            handle_color: p.muted,
            background: iced::Background::Color(p.surface),
            border: style::border(
                if matches!(st, iced::widget::pick_list::Status::Active) {
                    p.border_strong
                } else {
                    p.accent
                },
                1.0,
                6.0,
            ),
        })
        .width(Fill)
        .padding([10, 10])
        .text_size(14);
    let mut info: Vec<El<'_>> = vec![
        t("Informations du certificat", 14.0, p.text)
            .font(f.strong)
            .into(),
        labeled_input(p, f, "Société", &app.cfg.company.name, None, false),
        labeled_input(
            p,
            f,
            "Technicien",
            &form.technician,
            Some(Message::Technician),
            false,
        ),
        column![t("Client", 13.0, p.muted), client_pick]
            .spacing(4)
            .into(),
        pair(
            labeled_input(
                p,
                f,
                "Nom du client",
                &c.name,
                Some(|v| Message::Customer(Field::Name, v)),
                false,
            ),
            labeled_input(
                p,
                f,
                "Contact",
                &c.contact_name,
                Some(|v| Message::Customer(Field::Contact, v)),
                false,
            ),
        ),
        pair(
            labeled_input(
                p,
                f,
                "Adresse",
                &c.address,
                Some(|v| Message::Customer(Field::Address, v)),
                false,
            ),
            labeled_input(
                p,
                f,
                "Téléphone",
                &c.phone,
                Some(|v| Message::Customer(Field::Phone, v)),
                false,
            ),
        ),
        labeled_input(
            p,
            f,
            "Tag / n° d'inventaire",
            &form.tag,
            Some(Message::Tag),
            true,
        ),
        t(
            "Société et technicien sont préremplis depuis les Paramètres.",
            12.0,
            p.muted,
        )
        .into(),
    ];
    if let Some(e) = &app.book_error {
        info.push(t(format!("Carnet de clients : {e}"), 12.0, p.danger).into());
    }

    let grid = row![
        scrollable(
            Column::with_children(methods)
                .spacing(10)
                .padding(iced::Padding {
                    right: 10.0,
                    ..Default::default()
                })
        )
        .width(FillPortion(115))
        .height(Fill),
        scrollable(
            Column::with_children(info)
                .spacing(10)
                .padding(iced::Padding {
                    right: 10.0,
                    ..Default::default()
                })
        )
        .width(FillPortion(100))
        .height(Fill),
    ]
    .spacing(20)
    .height(Fill);

    let can = state::can_continue_config(&form.options, form.selected);
    column![
        steps(p, f, 2),
        title_block(
            p,
            f,
            "Configuration de l'effacement".into(),
            disk_subtitle(p, f, &form.disk, None)
        ),
        grid,
        footer(
            p,
            btn(
                p,
                f,
                "Retour",
                Btn::Secondary,
                Some(Message::Nav(Screen::Disks))
            ),
            vec![btn(
                p,
                f,
                "Continuer",
                Btn::Primary,
                can.then_some(Message::ToConfirm)
            )]
        ),
    ]
    .spacing(18)
    .into()
}

// ---------- 03 Confirmation ----------

fn confirm(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let Some(form) = &app.form else {
        return t("Aucun disque sélectionné.", 14.0, p.muted).into();
    };
    let d = &form.disk;
    let banner = tone_panel(
        p,
        Tone::Danger,
        row![
            container(t("!", 22.0, Color::WHITE).font(f.bold))
                .center_x(40)
                .center_y(40)
                .style(move |_| style::panel(p.danger_btn, p.danger_btn, 0.0, 20.0)),
            column![
                t(
                    format!("Toutes les données du disque {} vont être détruites définitivement", d.number),
                    19.0,
                    p.danger
                )
                .font(f.bold),
                t(
                    "Cette opération est irréversible. Vérifiez sur l'étiquette du disque que le numéro de série correspond avant de continuer.",
                    14.0,
                    p.text
                ),
            ]
            .spacing(6),
        ]
        .spacing(16),
    )
    .padding([20, 22])
    .width(Fill);

    let (head, hot) = state::serial_parts(d);
    let serial_view: El<'_> = if hot.is_empty() {
        t("(aucun n° de série)", 16.0, p.muted).into()
    } else {
        row![
            t(head, 16.0, p.text).font(f.mono),
            container(t(hot, 16.0, p.danger).font(Font {
                weight: iced::font::Weight::Bold,
                ..f.mono
            }))
            .padding([0, 3])
            .style(move |_| style::panel(p.danger_soft, p.danger_soft, 0.0, 3.0)),
        ]
        .into()
    };
    let method = form.option().map(|o| o.label.clone()).unwrap_or_default();
    let line = |k: &'static str, v: El<'static>| -> El<'static> {
        row![
            container(t(k, 14.0, p.muted)).width(180).padding([12, 16]),
            container(v).width(Fill).padding([12, 16]),
        ]
        .align_y(Alignment::Center)
        .into()
    };
    let summary = panel(
        p,
        column![
            line(
                "Disque",
                t(
                    format!(
                        "{} · {} · {}",
                        d.number,
                        d.display_model(),
                        detect::human_size(d.size_bytes)
                    ),
                    14.0,
                    p.text
                )
                .font(f.strong)
                .into()
            ),
            hr(p),
            line("N° de série", serial_view),
            hr(p),
            line("Méthode", t(method, 14.0, p.text).into()),
        ],
    )
    .width(Fill);

    let matches = crate::safety::confirmation_matches(d, &app.code);
    let feedback: El<'_> = if app.code.trim().is_empty() {
        t(
            "Recopiez les caractères surlignés en rouge, lus sur l'étiquette du disque.",
            13.0,
            p.muted,
        )
        .into()
    } else if matches {
        t("✓ Correspond", 14.0, p.ok).font(f.strong).into()
    } else {
        t("Ne correspond pas", 14.0, p.danger).font(f.strong).into()
    };
    let code_width = if safety_code_len(d) > 4 { 300 } else { 150 };
    let input = text_input("····", &app.code)
        .on_input(Message::Code)
        .on_submit_maybe(
            state::can_erase(d, &app.code, app.label_checked).then_some(Message::StartErase),
        )
        .font(f.mono)
        .size(26)
        .padding([8, 14])
        .width(code_width)
        .style(move |_, s| style::input_style(p, s, true));
    let check = checkbox(app.label_checked)
        .label("J'ai vérifié l'étiquette du disque (n° de série)")
        .on_toggle(Message::LabelChecked)
        .size(18)
        .text_size(14)
        .style(move |_, s| style::checkbox_style(p, s));

    let can = state::can_erase(d, &app.code, app.label_checked);
    column![
        steps(p, f, 3),
        banner,
        summary,
        column![
            t(state::confirm_prompt(d), 14.0, p.text).font(f.strong),
            row![input, feedback].spacing(14).align_y(Alignment::Center),
            check,
        ]
        .spacing(10),
        space().height(Fill),
        footer(
            p,
            btn(
                p,
                f,
                "Retour",
                Btn::Secondary,
                Some(Message::Nav(Screen::Config))
            ),
            vec![btn(
                p,
                f,
                "Effacer définitivement",
                Btn::Danger,
                can.then_some(Message::StartErase)
            )]
        ),
    ]
    .spacing(20)
    .into()
}

fn safety_code_len(d: &DiskInfo) -> usize {
    crate::safety::confirmation_code(d).chars().count()
}

// ---------- 04 Effacement ----------

/// Graphique du débit en direct.
struct SpeedChart {
    pts: Vec<(f32, f32)>,
    line: Color,
    fill: Color,
    grid: Color,
}

impl canvas::Program<Message> for SpeedChart {
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
        let (w, h) = (bounds.width, bounds.height);
        for k in 1..4 {
            let y = h * k as f32 / 4.0;
            frame.stroke(
                &Path::line(Point::new(0.0, y), Point::new(w, y)),
                Stroke::default().with_color(self.grid).with_width(1.0),
            );
        }
        if self.pts.len() >= 2 {
            let t0 = self.pts[0].0;
            let t1 = self.pts[self.pts.len() - 1].0.max(t0 + 1.0);
            let vmax = self.pts.iter().map(|p| p.1).fold(1.0f32, f32::max) * 1.2;
            let pt = |(x, v): (f32, f32)| Point::new((x - t0) / (t1 - t0) * w, h - v / vmax * h);
            let line = Path::new(|b| {
                b.move_to(pt(self.pts[0]));
                for &p in &self.pts[1..] {
                    b.line_to(pt(p));
                }
            });
            let area = Path::new(|b| {
                b.move_to(Point::new(0.0, h));
                for &p in &self.pts {
                    b.line_to(pt(p));
                }
                b.line_to(Point::new(w, h));
                b.close();
            });
            frame.fill(&area, self.fill);
            frame.stroke(
                &line,
                Stroke::default().with_color(self.line).with_width(2.0),
            );
        }
        vec![frame.into_geometry()]
    }
}

fn stat_card<'a>(p: Pal, f: &Fonts, label: &'a str, value: String, color: Color) -> El<'a> {
    panel(
        p,
        column![
            t(label, 12.0, p.muted),
            t(value, 24.0, color).font(f.strong)
        ]
        .spacing(4),
    )
    .padding([14, 16])
    .width(FillPortion(1))
    .into()
}

fn bar<'a>(p: Pal, frac: f64, height: f32, color: Color, track: Color, border: bool) -> El<'a> {
    let done = (frac.clamp(0.0, 1.0) * 1000.0).round() as u16;
    let mut r = Row::new();
    if done > 0 {
        r = r.push(
            container(space())
                .width(FillPortion(done))
                .height(Fill)
                .style(move |_| style::fill(color)),
        );
    }
    if done < 1000 {
        r = r.push(space().width(FillPortion(1000 - done)));
    }
    container(r)
        .width(Fill)
        .height(height)
        .clip(true)
        .style(move |_| {
            style::panel(
                track,
                if border { p.border } else { track },
                if border { 1.0 } else { 0.0 },
                height / 2.0,
            )
        })
        .into()
}

fn erase(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let Some(r) = &app.running else {
        return t("Aucun effacement en cours.", 14.0, p.muted).into();
    };
    let frac = r
        .progress
        .as_ref()
        .map(|pr| state::global_fraction(pr, r.verify))
        .unwrap_or(0.0);
    let elapsed = r.now.duration_since(r.started).as_secs();
    let over_elapsed = r
        .overwrite_started
        .map(|s| r.now.duration_since(s).as_secs_f64())
        .unwrap_or(0.0);
    let firmware = matches!(r.decision, Decision::Firmware(_));
    let in_overwrite = r.progress.is_some() && r.status.is_none();

    // Barres de passes.
    let mut segs: Vec<El<'_>> = Vec::new();
    if let Some(pr) = r.progress.as_ref().filter(|_| in_overwrite) {
        let n = pr.pass_total.max(1);
        let labels: Vec<String> = (0..n)
            .map(|i| {
                r.pass_labels
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| "Passe".into())
            })
            .collect();
        let cur = pr.done as f64 / pr.total.max(1) as f64;
        for (i, label) in labels.iter().enumerate() {
            let (fr, txt, strong) =
                if i < pr.pass_index || (i == pr.pass_index && pr.phase == Phase::Verify) {
                    (1.0, format!("Passe {} · {label} — terminée", i + 1), false)
                } else if i == pr.pass_index {
                    (
                        cur,
                        format!("Passe {} · {label} — {:.0} %", i + 1, cur * 100.0),
                        true,
                    )
                } else {
                    (0.0, format!("Passe {} · {label}", i + 1), false)
                };
            let color = if fr >= 1.0 { p.ok } else { p.accent };
            segs.push(seg(p, f, fr, color, txt, strong));
        }
        if r.verify != crate::erase_hdd::VerifyMode::None {
            let (fr, txt, strong) = if pr.phase == Phase::Verify {
                (cur, format!("Vérification — {:.0} %", cur * 100.0), true)
            } else {
                (0.0, "Vérification".to_string(), false)
            };
            segs.push(seg(p, f, fr, p.accent, txt, strong));
        }
    }
    let status_line: El<'_> = match (&r.status, r.progress.is_some()) {
        (Some(s), _) => t(s.clone(), 14.0, p.text).font(f.strong).into(),
        (None, false) => t(
            "Préparation : lecture des capacités, verrouillage des volumes, ouverture du disque…",
            14.0,
            p.muted,
        )
        .into(),
        _ => space().into(),
    };
    let big = if firmware && !in_overwrite {
        "Firmware".to_string()
    } else {
        format!("{:.0} %", frac * 100.0)
    };
    let main = panel(
        p,
        column![
            row![
                t(big, 40.0, p.text).font(f.strong),
                space().width(Fill),
                t("Progression globale", 14.0, p.muted)
            ]
            .align_y(Alignment::End),
            bar(
                p,
                if firmware && !in_overwrite { 0.0 } else { frac },
                14.0,
                p.accent,
                p.surface2,
                true
            ),
            status_line,
            Row::with_children(segs).spacing(8),
        ]
        .spacing(14),
    )
    .padding([20, 22])
    .width(Fill);

    let pr = r.progress.as_ref();
    let errs = pr
        .map(|p| p.errors.pass + p.errors.sync + p.errors.verify)
        .unwrap_or(0);
    let remaining = if in_overwrite {
        state::remaining_secs(frac, over_elapsed)
            .map(state::hms_text)
            .unwrap_or_else(|| "calcul…".into())
    } else {
        "inconnu".into()
    };
    let pass_txt = match pr {
        Some(pr) if in_overwrite => match pr.phase {
            Phase::Write => format!("{} / {}", pr.pass_index + 1, pr.pass_total),
            Phase::Verify => "Vérif.".into(),
        },
        _ => "—".into(),
    };
    let speed = pr
        .filter(|_| in_overwrite)
        .map(|pr| format!("{:.0} MB/s", pr.speed_mb_s))
        .unwrap_or_else(|| "—".into());
    let cards = row![
        stat_card(p, f, "Passe en cours", pass_txt, p.text),
        stat_card(p, f, "Débit", speed, p.text),
        stat_card(p, f, "Temps restant", remaining, p.text),
        stat_card(
            p,
            f,
            "Erreurs",
            errs.to_string(),
            if errs == 0 { p.ok } else { p.danger }
        ),
    ]
    .spacing(12);

    let written = pr
        .map(|pr| {
            format!(
                "{} / {}",
                detect::human_size(pr.done),
                detect::human_size(pr.total)
            )
        })
        .unwrap_or_else(|| "—".into());
    let retries = pr.map(|pr| pr.errors.retries).unwrap_or(0);
    let info = |k: &'static str, v: String| -> El<'static> {
        row![t(k, 13.0, p.muted), t(v, 13.0, p.text)]
            .spacing(4)
            .width(FillPortion(1))
            .into()
    };
    let infos = row![
        info(
            "Démarré",
            format!(
                "{:02}:{:02}:{:02}",
                r.started_at.hour, r.started_at.minute, r.started_at.second
            )
        ),
        info("Écoulé", state::hms_text(elapsed)),
        info("Écrit (passe)", written),
        info("Reprises", retries.to_string()),
    ]
    .spacing(12);

    let chart = panel(
        p,
        column![
            t("Débit en direct (MB/s)", 12.0, p.muted),
            Canvas::new(SpeedChart {
                pts: r.speeds.clone(),
                line: p.accent,
                fill: Color {
                    a: 0.15,
                    ..p.accent
                },
                grid: p.border,
            })
            .width(Fill)
            .height(70),
        ]
        .spacing(6),
    )
    .padding([10, 16])
    .width(Fill);

    let mut notes: Vec<El<'_>> = Vec::new();
    for n in r.notes.iter().rev().take(3) {
        notes.push(
            t(n.clone(), 12.0, p.warn)
                .wrapping(Wrapping::WordOrGlyph)
                .into(),
        );
    }

    let cancel_area: Vec<El<'_>> = if r.cancel_requested {
        vec![
            t("Annulation demandée : arrêt propre en cours…", 14.0, p.warn)
                .font(f.strong)
                .into(),
        ]
    } else {
        vec![btn(
            p,
            f,
            "Annuler",
            Btn::Secondary,
            Some(Message::AskCancel),
        )]
    };
    let mut col = column![
        steps(p, f, 4),
        title_block(
            p,
            f,
            if r.cancel_requested {
                "Annulation en cours".into()
            } else {
                "Effacement en cours".into()
            },
            disk_subtitle(p, f, &r.disk, Some(r.method.clone()))
        ),
        main,
        cards,
        infos,
        chart,
        Column::with_children(notes).spacing(2),
        space().height(Fill),
    ]
    .spacing(14);
    if r.cancel_asked {
        col = col.push(
            tone_panel(
                p,
                Tone::Danger,
                row![
                    t(
                        "Annuler l'effacement ? Le disque restera partiellement effacé ; un certificat ABORTED sera produit.",
                        14.0,
                        p.danger
                    )
                    .width(Fill),
                    btn(p, f, "Continuer", Btn::Secondary, Some(Message::ConfirmCancel(false))),
                    btn(p, f, "Oui, annuler", Btn::Danger, Some(Message::ConfirmCancel(true))),
                ]
                .spacing(12)
                .align_y(Alignment::Center),
            )
            .padding([10, 14])
            .width(Fill),
        );
    }
    col.push(footer(
        p,
        t(
            if firmware {
                "Ne débranchez pas le disque. Une commande firmware lancée ne peut pas être interrompue : le disque la termine seul."
            } else {
                "Ne débranchez pas le disque et désactivez la mise en veille. Annuler laisse le disque partiellement effacé."
            },
            13.0,
            p.muted,
        )
        .width(Fill)
        .into(),
        cancel_area,
    ))
    .into()
}

fn seg<'a>(p: Pal, f: &Fonts, frac: f64, color: Color, label: String, strong: bool) -> El<'a> {
    column![
        bar(p, frac, 6.0, color, p.surface2, false),
        t(label, 12.0, if strong { p.text } else { p.muted })
            .font(if strong { f.strong } else { f.regular })
            .wrapping(Wrapping::None),
    ]
    .spacing(6)
    .width(FillPortion(1))
    .clip(true)
    .into()
}

// ---------- 05 Certificat ----------

fn status_tone(s: Status) -> Tone {
    match s {
        Status::Erased => Tone::Ok,
        Status::Partial => Tone::Warn,
        Status::Failed | Status::Aborted => Tone::Danger,
    }
}

fn result(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let Some(outcome) = &app.outcome else {
        return t("Aucun résultat.", 14.0, p.muted).into();
    };
    match outcome {
        Outcome::NotStarted(_) | Outcome::AfterWrite(_) => {
            let (title, e, info) = match outcome {
                Outcome::AfterWrite(e) => (
                    crate::job::AFTER_WRITE_TITLE,
                    e,
                    "Le disque a été au moins partiellement écrit : il n'est plus intact et n'est pas certifié. L'erreur est inscrite dans data/logs/effacements.log.",
                ),
                Outcome::NotStarted(e) => (
                    "Effacement non effectué",
                    e,
                    "Rien n'a été écrit sur le disque et aucun certificat n'a été produit.",
                ),
                Outcome::Finished(_) => unreachable!(),
            };
            let banner = tone_panel(
                p,
                Tone::Danger,
                row![
                    circle_icon(p, f, "✕", p.danger_btn, Color::WHITE),
                    column![
                        t(title, 30.0, p.danger).font(f.bold),
                        t(e.clone(), 15.0, p.text),
                    ]
                    .spacing(4),
                ]
                .spacing(20)
                .align_y(Alignment::Center),
            )
            .padding([22, 24])
            .width(Fill);
            column![
                steps(p, f, 5),
                banner,
                t(info, 13.0, p.muted),
                space().height(Fill),
                footer(
                    p,
                    space().into(),
                    vec![
                        btn(
                            p,
                            f,
                            "Retour à la configuration",
                            Btn::Secondary,
                            app.form.as_ref().map(|_| Message::Nav(Screen::Config))
                        ),
                        btn(
                            p,
                            f,
                            "Effacer un autre disque",
                            Btn::Primary,
                            Some(Message::NewErase)
                        ),
                    ]
                ),
            ]
            .spacing(20)
            .into()
        }
        Outcome::Finished(fin) => {
            let rec = &fin.record;
            let tone = status_tone(rec.status);
            let (_, ink) = tone.colors(&p);
            let (icon, title, sub) = match rec.status {
                Status::Erased => ("✓", if rec.demo { "ERASED (DÉMO)".to_string() } else { "ERASED".to_string() }, "Effacement terminé et vérifié. Le certificat a été généré."),
                Status::Partial => ("!", format!("EFFACEMENT PARTIEL ({})", rec.level), "Le disque n'a pas pu être effacé au niveau prévu. Voir les remarques ci-dessous et le certificat."),
                Status::Failed => ("✕", "FAILED".to_string(), "L'effacement a échoué. Ce disque ne peut pas être certifié effacé."),
                Status::Aborted => ("!", "ABORTED".to_string(), "Effacement interrompu : le disque est partiellement effacé. Un certificat ABORTED a été généré."),
            };
            let icon_bg = match tone {
                Tone::Ok => p.ok,
                Tone::Warn => p.warn,
                _ => p.danger_btn,
            };
            let banner = tone_panel(
                p,
                tone,
                row![
                    circle_icon(
                        p,
                        f,
                        icon,
                        icon_bg,
                        if tone == Tone::Danger {
                            Color::WHITE
                        } else {
                            p.bg
                        }
                    ),
                    column![t(title, 38.0, ink).font(f.bold), t(sub, 16.0, p.text)].spacing(2),
                ]
                .spacing(20)
                .align_y(Alignment::Center),
            )
            .padding([22, 24])
            .width(Fill);
            let e = rec.errors();
            let rows = vec![
                ("Disque".to_string(), rec.disk.model.clone()),
                (
                    "N° de série".to_string(),
                    detect::serial_or_none(&rec.disk.serial).to_string(),
                ),
                ("Méthode".to_string(), rec.method.clone()),
                ("Niveau NIST".to_string(), rec.level.clone()),
                (
                    "Vérification".to_string(),
                    format!("{} — {}", rec.verify, rec.verify_result),
                ),
                ("Durée".to_string(), rec.duration_hms()),
                ("Début".to_string(), rec.start.clone()),
                ("Fin".to_string(), rec.end.clone()),
                (
                    "Octets effacés".to_string(),
                    format!("{} ({:.2} %)", group(rec.bytes_erased), rec.percent),
                ),
                (
                    "Débit moyen".to_string(),
                    if rec.avg_mb_s > 0.0 {
                        format!("{:.0} MB/s", rec.avg_mb_s)
                    } else {
                        "—".into()
                    },
                ),
                (
                    "Erreurs".to_string(),
                    format!("{} / {} / {} / {}", e.pass, e.sync, e.verify, e.retries),
                ),
                ("HPA/DCO".to_string(), rec.hpa_dco.clone()),
                ("Client".to_string(), dash(&rec.customer.name)),
                ("Tag".to_string(), dash(&rec.tag)),
            ];
            let mut notes: Vec<El<'_>> = Vec::new();
            for n in rec.notes.iter().filter(|n| !n.starts_with("Cible")).take(3) {
                notes.push(t(n.clone(), 13.0, p.text).font(f.strong).into());
            }
            // Remarques arrivées après l'écriture du PDF (ex. remise en ligne impossible).
            for n in &fin.late_notes {
                notes.push(
                    t(format!("ATTENTION : {n}"), 13.0, p.warn)
                        .font(f.strong)
                        .into(),
                );
            }
            if let Some(e) = &app.notice {
                notes.push(t(e.clone(), 13.0, p.danger).font(f.strong).into());
            }
            // Commandes firmware toutes bloquées par le transport : pas de cul-de-sac.
            let clear = app
                .form
                .as_ref()
                .and_then(|form| state::clear_option(fin.firmware_blocked, &form.options));
            if fin.firmware_blocked {
                let (_, ink) = Tone::Warn.colors(&p);
                notes.push(
                    tone_panel(
                        p,
                        Tone::Warn,
                        t(crate::erase_ssd::FIRMWARE_BLOCKED_MSG, 14.0, ink).font(f.strong),
                    )
                    .padding([10, 14])
                    .width(Fill)
                    .into(),
                );
            }
            let pdf = fin.pdf.clone();
            let dir = pdf.parent().map(|d| d.to_path_buf()).unwrap_or_default();
            let mut buttons = vec![
                btn(
                    p,
                    f,
                    "Ouvrir le dossier",
                    Btn::Secondary,
                    Some(Message::OpenFolder(dir, Some(pdf.clone()))),
                ),
                btn(
                    p,
                    f,
                    "Ouvrir le certificat PDF",
                    Btn::Secondary,
                    Some(Message::OpenPdf(pdf.clone())),
                ),
            ];
            if let Some(i) = clear {
                buttons.push(btn(
                    p,
                    f,
                    "Effacer par écrasement (NIST Clear)",
                    Btn::Primary,
                    Some(Message::RetryClear(i)),
                ));
            }
            buttons.push(btn(
                p,
                f,
                "Effacer un autre disque",
                if clear.is_some() {
                    Btn::Secondary
                } else {
                    Btn::Primary
                },
                Some(Message::NewErase),
            ));
            column![
                steps(p, f, 5),
                banner,
                kv_grid(p, f, rows, 150.0, &["N° de série"]),
                Column::with_children(notes).spacing(4),
                row![
                    t("Certificat enregistré : ", 13.0, p.muted),
                    t(app.shown(&pdf), 13.0, p.text).font(f.mono),
                ],
                space().height(Fill),
                footer(p, space().into(), buttons),
            ]
            .spacing(16)
            .into()
        }
    }
}

fn circle_icon<'a>(_p: Pal, f: &Fonts, icon: &'a str, bg: Color, ink: Color) -> El<'a> {
    container(t(icon, 32.0, ink).font(f.bold))
        .center_x(60)
        .center_y(60)
        .style(move |_| style::panel(bg, bg, 0.0, 30.0))
        .into()
}

fn dash(s: &str) -> String {
    if s.trim().is_empty() {
        "—".into()
    } else {
        s.to_string()
    }
}

/// 320072933376 → « 320 072 933 376 ».
fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('\u{202f}');
        }
        out.push(c);
    }
    out
}

/// « 2026/11/09 22:03:00 » → « 09/11/2026 22:03 ».
fn short_date(s: &str) -> String {
    let b = s.as_bytes();
    if b.len() >= 16 && b[4] == b'/' && b[7] == b'/' {
        format!("{}/{}/{} {}", &s[8..10], &s[5..7], &s[0..4], &s[11..16])
    } else {
        s.to_string()
    }
}

// ---------- 06 Historique ----------

fn history(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let head = row![
        title_block(
            p,
            f,
            "Historique".into(),
            t(state::history_summary(&app.history), 14.0, p.muted).into()
        ),
        space().width(Fill),
        btn(
            p,
            f,
            "Exporter CSV",
            Btn::Secondary,
            Some(Message::ExportCsv)
        ),
    ]
    .align_y(Alignment::End);
    let seg_btn = |label: &'static str, flt: HistoryFilter| -> El<'static> {
        let on = app.history_filter == flt;
        button(
            container(t(label, 14.0, p.text).font(if on { f.strong } else { f.regular }))
                .height(Fill)
                .align_y(Alignment::Center),
        )
        .height(Fill)
        .padding([0, 14])
        .on_press(Message::HistoryFilter(flt))
        .style(move |_, s| style::button_style(p, Btn::Segment(on), s))
        .into()
    };
    let vsep = || -> El<'static> {
        container(space())
            .width(1)
            .height(Fill)
            .style(move |_| style::fill(p.border_strong))
            .into()
    };
    let filters = container(
        row![
            seg_btn("Tous", HistoryFilter::All),
            vsep(),
            seg_btn("Effacés", HistoryFilter::Erased),
            vsep(),
            seg_btn("Partiels", HistoryFilter::Partial),
            vsep(),
            seg_btn("Échecs", HistoryFilter::Failed),
        ]
        .height(Fill),
    )
    .height(44)
    .padding(1)
    .clip(true)
    .style(move |_| style::panel(p.surface, p.border_strong, 1.0, 6.0));
    let search = text_input(
        "Rechercher un modèle, un n° de série, un client…",
        &app.history_search,
    )
    .on_input(Message::HistorySearch)
    .size(14)
    .padding([12, 12])
    .width(Fill)
    .style(move |_, s| style::input_style(p, s, false));

    let cols = [128.0, 150.0, 176.0, 104.0, 44.0];
    let hcell = |s: &'static str, w: Option<f32>| -> El<'static> {
        let c = container(t(s, 12.0, p.muted).font(f.strong));
        match w {
            Some(w) => c.width(w).into(),
            None => c.width(Fill).into(),
        }
    };
    let header = container(
        row![
            hcell("Date", Some(cols[0])),
            hcell("Modèle", None),
            hcell("N° de série", Some(cols[1])),
            hcell("Méthode", Some(cols[2])),
            hcell("Statut", Some(cols[3])),
            hcell("PDF", Some(cols[4])),
        ]
        .spacing(8)
        .align_y(Alignment::Center),
    )
    .height(40)
    .padding([0, 14])
    .align_y(Alignment::Center)
    .style(move |_| style::fill(p.surface2));

    let shown: Vec<&EraseRecord> = app
        .history
        .iter()
        .filter(|r| state::history_matches(r, app.history_filter, &app.history_search))
        .collect();
    let mut rows: Vec<El<'_>> = vec![header.into(), hr(p)];
    if shown.is_empty() {
        rows.push(
            container(t(
                if app.history.is_empty() {
                    "Aucun effacement enregistré."
                } else {
                    "Aucun résultat pour ce filtre."
                },
                13.0,
                p.muted,
            ))
            .padding([14, 14])
            .into(),
        );
    }
    for (i, r) in shown.iter().enumerate() {
        let pdf = crate::job::certificate_path(&app.paths, &r.id);
        let pdf_cell: El<'_> = match pdf {
            Some(path) => button(t("PDF", 13.0, p.accent).font(f.strong))
                .padding(0)
                .on_press(Message::OpenPdf(path))
                .style(move |_, s| style::button_style(p, Btn::Link, s))
                .into(),
            None => t("—", 13.0, p.muted).into(),
        };
        let label = r.status.fr().to_string();
        let line = row![
            container(t(short_date(&r.end), 13.0, p.text)).width(cols[0]),
            container(t(r.disk.model.clone(), 13.0, p.text).wrapping(Wrapping::None))
                .width(Fill)
                .clip(true),
            container(
                t(
                    detect::serial_or_none(&r.disk.serial).to_string(),
                    13.0,
                    p.text
                )
                .font(f.mono)
                .wrapping(Wrapping::None)
            )
            .width(cols[1])
            .clip(true),
            container(t(r.method.clone(), 13.0, p.muted).wrapping(Wrapping::None))
                .width(cols[2])
                .clip(true),
            container(badge(p, f, label, status_tone(r.status)))
                .width(cols[3])
                .clip(true),
            container(pdf_cell).width(cols[4]),
        ]
        .spacing(8)
        .align_y(Alignment::Center);
        rows.push(
            container(line)
                .height(46)
                .padding([0, 14])
                .align_y(Alignment::Center)
                .into(),
        );
        if i + 1 < shown.len() {
            rows.push(hr(p));
        }
    }
    let table = panel(p, scrollable(Column::with_children(rows)).height(Shrink))
        .width(Fill)
        .clip(true);
    let mut col = column![
        head,
        row![search, filters].spacing(12).align_y(Alignment::Center),
        table
    ]
    .spacing(16);
    if let Some(e) = &app.history_error {
        col = col.push(t(format!("Historique : {e}"), 13.0, p.danger));
    }
    if let Some((ok, m)) = &app.export_msg {
        col = col.push(t(m.clone(), 13.0, if *ok { p.ok } else { p.danger }).font(f.strong));
    }
    if let Some(e) = &app.notice {
        col = col.push(t(e.clone(), 13.0, p.danger).font(f.strong));
    }
    container(col).height(Fill).into()
}

// ---------- 07 Paramètres ----------

fn settings(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let s = &app.settings;
    let theme_btn = |label: &'static str, dark: bool| -> El<'static> {
        let on = app.dark == dark;
        button(
            container(t(label, 14.0, p.text).font(f.strong))
                .center_x(Fill)
                .height(Fill)
                .align_y(Alignment::Center),
        )
        .width(FillPortion(1))
        .height(Fill)
        .on_press(Message::SetDark(dark))
        .style(move |_, st| style::button_style(p, Btn::Segment(on), st))
        .into()
    };
    let theme = container(
        row![
            theme_btn("Clair", false),
            container(space())
                .width(1)
                .height(Fill)
                .style(move |_| style::fill(p.border_strong)),
            theme_btn("Sombre", true),
        ]
        .height(Fill),
    )
    .height(44)
    .padding(1)
    .clip(true)
    .style(move |_| style::panel(p.surface, p.border_strong, 1.0, 6.0));
    let half = |a: El<'static>, b: El<'static>| -> El<'static> {
        row![
            container(a).width(FillPortion(1)),
            container(b).width(FillPortion(1))
        ]
        .spacing(24)
        .into()
    };
    let c = &s.company;
    let logo_path = app.paths.assets.join("logo.png");
    let logo_state = if logo_path.exists() {
        "présent"
    } else {
        "absent (aucun logo sur le certificat)"
    };
    let data_path = app.shown(&app.paths.data);
    let mut col = column![
        title_block(
            p,
            f,
            "Paramètres".into(),
            row![
                t("Enregistrés dans ", 14.0, p.muted),
                t(app.shown(&app.paths.config_file()), 14.0, p.muted).font(f.mono),
                t(".", 14.0, p.muted),
            ]
            .into()
        ),
        half(
            column![
                t("Technicien par défaut", 14.0, p.text).font(f.strong),
                labeled_input(
                    p,
                    f,
                    "Nom / identifiant",
                    &s.technician,
                    Some(Message::SettingsTechnician),
                    false
                ),
            ]
            .spacing(10)
            .into(),
            column![t("Thème", 14.0, p.text).font(f.strong), theme]
                .spacing(10)
                .into(),
        ),
        column![
            t("Société par défaut", 14.0, p.text).font(f.strong),
            half(
                labeled_input(
                    p,
                    f,
                    "Raison sociale",
                    &c.name,
                    Some(|v| Message::SettingsCompany(Field::Name, v)),
                    false
                ),
                labeled_input(
                    p,
                    f,
                    "Adresse",
                    &c.address,
                    Some(|v| Message::SettingsCompany(Field::Address, v)),
                    false
                ),
            ),
            half(
                labeled_input(
                    p,
                    f,
                    "Contact",
                    &c.contact_name,
                    Some(|v| Message::SettingsCompany(Field::Contact, v)),
                    false
                ),
                labeled_input(
                    p,
                    f,
                    "Téléphone",
                    &c.phone,
                    Some(|v| Message::SettingsCompany(Field::Phone, v)),
                    false
                ),
            ),
        ]
        .spacing(10),
        column![
            t("Dossier des données", 14.0, p.text).font(f.strong),
            row![
                text_input("", &data_path)
                    .font(f.mono)
                    .size(14)
                    .padding([12, 10])
                    .width(Fill)
                    .style(move |_, st| style::input_style(p, st, false)),
                btn(
                    p,
                    f,
                    "Ouvrir",
                    Btn::Secondary,
                    Some(Message::OpenFolder(app.paths.data.clone(), None))
                ),
            ]
            .spacing(10)
            .align_y(Alignment::Center),
            t(
                format!("Certificats : {}", app.shown(&app.paths.certificates)),
                12.0,
                p.muted
            )
            .font(f.mono),
            t(
                format!(
                    "Logo du certificat : {} — {logo_state}",
                    app.shown(&logo_path)
                ),
                12.0,
                p.muted
            ),
            t(format!("Police : {}", app.font_source), 12.0, p.muted),
        ]
        .spacing(6),
    ]
    .spacing(18);
    if let Some(w) = &app.paths.warning {
        col = col.push(
            tone_panel(p, Tone::Warn, t(w.clone(), 13.0, p.warn))
                .padding([10, 14])
                .width(Fill),
        );
    }
    if let Some(e) = &app.notice {
        col = col.push(t(e.clone(), 13.0, p.danger).font(f.strong));
    }
    let msg: El<'_> = match &s.message {
        Some((ok, m)) => t(m.clone(), 13.0, if *ok { p.ok } else { p.danger })
            .font(f.strong)
            .into(),
        None => space().into(),
    };
    col.push(space().height(Fill))
        .push(footer(
            p,
            msg,
            vec![btn(
                p,
                f,
                "Enregistrer",
                Btn::Primary,
                Some(Message::SaveSettings),
            )],
        ))
        .into()
}

// ---------- Droits administrateur ----------

fn need_admin(app: &App) -> El<'_> {
    let p = app.pal();
    let f = &app.fonts;
    let card = panel(
        p,
        column![
            Canvas::new(logo::Mark { ink: p.text, accent: p.accent }).width(56).height(56),
            t("Droits administrateur requis", 22.0, p.text).font(f.strong),
            t(
                format!("{APP_NAME} doit lire les disques physiques : relancez-le en administrateur (Lancer.bat, ou clic droit → Exécuter en tant qu'administrateur)."),
                14.0,
                p.muted
            ),
            row![
                btn(p, f, "Relancer en administrateur", Btn::Primary, Some(Message::RelaunchAdmin)),
                btn(p, f, "Réessayer", Btn::Secondary, Some(Message::Refresh)),
            ]
            .spacing(12),
            match &app.list_error {
                Some(e) => El::from(t(e.clone(), 13.0, p.danger)),
                None => El::from(space()),
            },
        ]
        .spacing(16)
        .align_x(Alignment::Center),
    )
    .padding(32)
    .width(560);
    center(card).width(Fill).height(Fill).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(
            group(320_072_933_376),
            "320\u{202f}072\u{202f}933\u{202f}376"
        );
        assert_eq!(group(12), "12");
        assert_eq!(short_date("2026/11/09 22:03:00"), "09/11/2026 22:03");
        assert_eq!(short_date("x"), "x");
    }
}
