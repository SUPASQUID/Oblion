//! `oblion.exe` : interface graphique (sous-système windows, pas de console au double-clic).
//! - sans argument : interface (rendu logiciel, sans GPU) ;
//! - avec des arguments : ligne de commande de secours, sorties dans la console parente
//!   (AttachConsole). Pour les scripts et les codes de retour : `oblion-cli.exe` ;
//! - `--console` : force la ligne de commande ;
//! - `--gui-demo` : interface de démonstration (disques simulés, aucun accès matériel).
//!
//! Les DLL graphiques (dwmapi, uxtheme, imm32, ole32) sont chargées en différé (build.rs) :
//! si l'une manque (WinPE minimal), l'exe démarre quand même, explique et propose
//! `oblion-cli.exe`.
#![cfg_attr(not(test), windows_subsystem = "windows")]

mod ui;

pub(crate) use oblion::{
    app, clock, config, demo, detect, erase_hdd, erase_ssd, job, report, safety, winio,
};
use oblion::{cli, console};

/// Ajouté à l'aide de `oblion.exe`.
const HELP_NOTE: &str = "NOTE : oblion.exe est l'interface graphique (lancée sans argument). \
Le terminal n'attend pas sa fin : pour les scripts et les codes de retour, utilisez oblion-cli.exe \
(mêmes commandes, sous-système console).";

/// DLL chargées en différé par l'interface : vérifiées avant de lancer iced.
const GUI_DLLS: [&str; 4] = ["dwmapi.dll", "uxtheme.dll", "imm32.dll", "ole32.dll"];

/// Mode de démarrage choisi d'après les arguments (logique pure, testée).
#[derive(Debug, PartialEq, Eq)]
enum Mode {
    /// Interface graphique ; `demo` = disques simulés ; `screen` = écran ouvert directement.
    Gui { demo: bool, screen: Option<u8> },
    /// Ligne de commande avec les arguments restants.
    Cli(Vec<String>),
}

fn startup_mode(args: &[String]) -> Mode {
    if args.is_empty() {
        return Mode::Gui {
            demo: false,
            screen: None,
        };
    }
    if cli::has(args, "--gui-demo") {
        let screen = cli::opt(args, "--gui-demo-screen")
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok());
        return Mode::Gui { demo: true, screen };
    }
    Mode::Cli(args.iter().filter(|a| *a != "--console").cloned().collect())
}

/// DLL graphiques absentes de ce Windows (WinPE minimal…).
fn missing_gui_dlls() -> Vec<&'static str> {
    use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;
    GUI_DLLS
        .iter()
        .copied()
        .filter(|name| {
            let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: nom UTF-16 terminé par zéro ; la DLL reste chargée (utilisée ensuite).
            unsafe { LoadLibraryW(w.as_ptr()) }.is_null()
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match startup_mode(&args) {
        Mode::Gui { demo, screen } => {
            let missing = missing_gui_dlls();
            if !missing.is_empty() {
                ui::offer_cli(&format!(
                    "DLL système absente(s) : {}. L'interface graphique ne peut pas démarrer sur ce Windows (WinPE minimal ?).",
                    missing.join(", ")
                ));
                std::process::exit(1);
            }
            std::process::exit(ui::run(demo, screen))
        }
        Mode::Cli(args) => {
            console::attach();
            let code = cli::main_cli(&args, Some(HELP_NOTE));
            console::detach();
            std::process::exit(code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn startup_mode_gui_without_args_cli_otherwise() {
        assert_eq!(
            startup_mode(&[]),
            Mode::Gui {
                demo: false,
                screen: None
            }
        );
        assert_eq!(startup_mode(&a(&["--list"])), Mode::Cli(a(&["--list"])));
        // --console force la CLI (sans autre argument : l'aide).
        assert_eq!(startup_mode(&a(&["--console"])), Mode::Cli(vec![]));
        assert_eq!(
            startup_mode(&a(&["--console", "--history"])),
            Mode::Cli(a(&["--history"]))
        );
        assert_eq!(
            startup_mode(&a(&["--gui-demo", "--gui-demo-screen", "4"])),
            Mode::Gui {
                demo: true,
                screen: Some(4)
            }
        );
    }

    #[test]
    fn gui_dlls_are_present_on_this_windows_and_help_points_to_the_cli() {
        assert!(missing_gui_dlls().is_empty());
        assert!(HELP_NOTE.contains("oblion-cli.exe"));
    }
}
