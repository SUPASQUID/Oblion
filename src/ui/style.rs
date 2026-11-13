//! Couleurs (variables CSS de la maquette, thèmes clair et sombre) et styles des widgets.

use iced::widget::{button, checkbox, container, text_input};
use iced::{Background, Border, Color, Shadow};

const fn hex(v: u32) -> Color {
    Color::from_rgb8((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

/// Palette de la maquette (`--bg`, `--surface`…).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Pal {
    pub bg: Color,
    pub surface: Color,
    pub surface2: Color,
    pub side: Color,
    pub title: Color,
    pub border: Color,
    pub border_strong: Color,
    pub text: Color,
    pub muted: Color,
    pub sel: Color,
    pub accent: Color,
    pub on_accent: Color,
    pub accent_soft: Color,
    pub danger: Color,
    pub danger_btn: Color,
    pub danger_soft: Color,
    pub ok: Color,
    pub ok_soft: Color,
    pub warn: Color,
    pub warn_soft: Color,
    pub disabled: Color,
    pub disabled_ink: Color,
}

impl Pal {
    pub const LIGHT: Pal = Pal {
        bg: hex(0xf7f8fa),
        surface: hex(0xffffff),
        surface2: hex(0xf0f2f5),
        side: hex(0xeef0f3),
        title: hex(0xe7eaee),
        border: hex(0xdde1e6),
        border_strong: hex(0xc3c9d0),
        text: hex(0x1c2025),
        muted: hex(0x5b646e),
        sel: hex(0xe1eafa),
        accent: hex(0x1f5fbf),
        on_accent: hex(0xffffff),
        accent_soft: hex(0xe3ecfa),
        danger: hex(0xc42b1c),
        danger_btn: hex(0xc42b1c),
        danger_soft: hex(0xfdecea),
        ok: hex(0x1d7a3b),
        ok_soft: hex(0xe5f3e9),
        warn: hex(0xa85600),
        warn_soft: hex(0xfff0dc),
        disabled: hex(0xe4e7eb),
        disabled_ink: hex(0x8a929b),
    };

    pub const DARK: Pal = Pal {
        bg: hex(0x1d2024),
        surface: hex(0x25292e),
        surface2: hex(0x2c3137),
        side: hex(0x181b1f),
        title: hex(0x141619),
        border: hex(0x353b42),
        border_strong: hex(0x4b535c),
        text: hex(0xe8eaed),
        muted: hex(0xa0a9b3),
        sel: hex(0x243552),
        accent: hex(0x5b9bef),
        on_accent: hex(0x0b1424),
        accent_soft: hex(0x1f2f48),
        danger: hex(0xf0675e),
        danger_btn: hex(0xc9372c),
        danger_soft: hex(0x3b1f1d),
        ok: hex(0x4cc07a),
        ok_soft: hex(0x163021),
        warn: hex(0xeda04f),
        warn_soft: hex(0x3a2a17),
        disabled: hex(0x2f343a),
        disabled_ink: hex(0x6f7780),
    };

    pub fn get(dark: bool) -> Pal {
        if dark {
            Pal::DARK
        } else {
            Pal::LIGHT
        }
    }

    /// Thème iced cohérent (barres de défilement, listes déroulantes).
    pub fn theme(&self, dark: bool) -> iced::Theme {
        iced::Theme::custom(
            if dark {
                "Oblion sombre"
            } else {
                "Oblion clair"
            },
            iced::theme::Palette {
                background: self.bg,
                text: self.text,
                primary: self.accent,
                success: self.ok,
                warning: self.warn,
                danger: self.danger,
            },
        )
    }
}

/// Couleurs (fond, encre) d'un badge de statut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Ok,
    Warn,
    Danger,
    Accent,
    Neutral,
}

impl Tone {
    pub fn colors(self, p: &Pal) -> (Color, Color) {
        match self {
            Tone::Ok => (p.ok_soft, p.ok),
            Tone::Warn => (p.warn_soft, p.warn),
            Tone::Danger => (p.danger_soft, p.danger),
            Tone::Accent => (p.accent_soft, p.accent),
            Tone::Neutral => (p.surface2, p.muted),
        }
    }
}

pub fn border(color: Color, width: f32, radius: f32) -> Border {
    Border {
        color,
        width,
        radius: radius.into(),
    }
}

pub fn panel(bg: Color, line: Color, width: f32, radius: f32) -> container::Style {
    container::Style {
        background: Some(Background::Color(bg)),
        border: border(line, width, radius),
        ..Default::default()
    }
}

pub fn fill(bg: Color) -> container::Style {
    container::Style {
        background: Some(Background::Color(bg)),
        ..Default::default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Btn {
    Primary,
    Secondary,
    Danger,
    /// Entrée du menu (sélectionnée ou non).
    Nav(bool),
    /// Ligne cliquable d'un tableau (sélectionnée ou non).
    Row(bool),
    /// Segment d'un sélecteur (actif ou non).
    Segment(bool),
    Link,
}

pub fn button_style(p: Pal, kind: Btn, status: button::Status) -> button::Style {
    let hovered = matches!(status, button::Status::Hovered | button::Status::Pressed);
    let disabled = status == button::Status::Disabled;
    let base = button::Style {
        background: None,
        text_color: p.text,
        border: border(Color::TRANSPARENT, 0.0, 6.0),
        shadow: Shadow::default(),
        snap: true,
    };
    let solid = |bg: Color, ink: Color| button::Style {
        background: Some(Background::Color(if disabled {
            p.disabled
        } else if hovered {
            mix(bg, Color::BLACK, 0.12)
        } else {
            bg
        })),
        text_color: if disabled { p.disabled_ink } else { ink },
        ..base
    };
    match kind {
        Btn::Primary => solid(p.accent, p.on_accent),
        Btn::Danger => solid(p.danger_btn, Color::WHITE),
        Btn::Secondary => button::Style {
            background: Some(Background::Color(if disabled {
                p.disabled
            } else if hovered {
                p.surface2
            } else {
                p.surface
            })),
            text_color: if disabled { p.disabled_ink } else { p.text },
            border: border(p.border_strong, 1.0, 6.0),
            ..base
        },
        Btn::Nav(sel) => button::Style {
            background: (sel || hovered).then(|| {
                Background::Color(if sel {
                    p.sel
                } else {
                    mix(p.side, p.text, 0.05)
                })
            }),
            text_color: if disabled { p.disabled_ink } else { p.text },
            ..base
        },
        Btn::Row(sel) => button::Style {
            background: Some(Background::Color(if sel {
                p.sel
            } else if disabled {
                p.surface2
            } else if hovered {
                mix(p.surface, p.accent, 0.05)
            } else {
                p.surface
            })),
            text_color: if disabled { p.muted } else { p.text },
            border: border(Color::TRANSPARENT, 0.0, 0.0),
            ..base
        },
        Btn::Segment(on) => button::Style {
            background: Some(Background::Color(if on {
                p.sel
            } else if hovered {
                p.surface2
            } else {
                p.surface
            })),
            text_color: p.text,
            border: border(Color::TRANSPARENT, 0.0, 0.0),
            ..base
        },
        Btn::Link => button::Style {
            text_color: if hovered { p.text } else { p.accent },
            ..base
        },
    }
}

pub fn input_style(p: Pal, status: text_input::Status, strong: bool) -> text_input::Style {
    let focused = matches!(status, text_input::Status::Focused { .. });
    text_input::Style {
        background: Background::Color(if status == text_input::Status::Disabled {
            p.surface2
        } else {
            p.surface
        }),
        border: border(
            if focused { p.accent } else { p.border_strong },
            if strong { 2.0 } else { 1.0 },
            6.0,
        ),
        icon: p.muted,
        placeholder: p.disabled_ink,
        value: p.text,
        selection: p.accent_soft,
    }
}

pub fn checkbox_style(p: Pal, status: checkbox::Status) -> checkbox::Style {
    let checked = match status {
        checkbox::Status::Active { is_checked }
        | checkbox::Status::Hovered { is_checked }
        | checkbox::Status::Disabled { is_checked } => is_checked,
    };
    checkbox::Style {
        background: Background::Color(if checked { p.accent } else { p.surface }),
        icon_color: p.on_accent,
        border: border(if checked { p.accent } else { p.border_strong }, 2.0, 4.0),
        text_color: Some(p.text),
    }
}

/// Mélange linéaire de deux couleurs.
pub fn mix(a: Color, b: Color, t: f32) -> Color {
    Color {
        r: a.r + (b.r - a.r) * t,
        g: a.g + (b.g - a.g) * t,
        b: a.b + (b.b - a.b) * t,
        a: a.a + (b.a - a.a) * t,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn palettes_use_the_mockup_values() {
        assert_eq!(Pal::LIGHT.accent, Color::from_rgb8(0x1f, 0x5f, 0xbf));
        assert_eq!(Pal::DARK.accent, Color::from_rgb8(0x5b, 0x9b, 0xef));
        assert_eq!(Pal::LIGHT.danger_btn, Color::from_rgb8(0xc4, 0x2b, 0x1c));
        assert_eq!(Pal::get(true), Pal::DARK);
    }
}
