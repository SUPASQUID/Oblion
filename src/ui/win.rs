//! Fonctions Windows de l'interface : ouvrir un PDF ou un dossier, relancer en
//! administrateur, boîte de message, proposition du mode console.

use std::os::windows::process::CommandExt;
use std::path::Path;

use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    MessageBoxW, IDYES, MB_ICONERROR, MB_ICONWARNING, MB_OK, MB_YESNO, SW_SHOWNORMAL,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// ShellExecuteW ; vrai si Windows a accepté (code > 32).
fn shell(verb: &str, file: &str, params: Option<&str>) -> bool {
    let (v, f) = (wide(verb), wide(file));
    let p = params.map(wide);
    // SAFETY: chaînes UTF-16 terminées par zéro, valides pendant l'appel.
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            v.as_ptr(),
            f.as_ptr(),
            p.as_ref().map_or(std::ptr::null(), |p| p.as_ptr()),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    r as isize > 32
}

/// Ouvre un fichier (PDF) avec l'application associée ; repli sur l'explorateur.
pub fn open_file(path: &Path) -> Result<(), String> {
    let s = path.display().to_string();
    if shell("open", &s, None) {
        return Ok(());
    }
    std::process::Command::new("explorer.exe")
        .arg(&s)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("ouverture de {s} impossible : {e}"))
}

/// Ouvre l'explorateur sur un dossier (fichier sélectionné si `select`).
pub fn open_folder(dir: &Path, select: Option<&Path>) -> Result<(), String> {
    let mut cmd = std::process::Command::new("explorer.exe");
    match select {
        Some(f) => cmd.raw_arg(format!("/select,\"{}\"", f.display())),
        None => cmd.arg(dir),
    };
    if cmd.spawn().is_ok() {
        return Ok(());
    }
    if shell("open", &dir.display().to_string(), None) {
        Ok(())
    } else {
        Err(format!("ouverture du dossier {} impossible", dir.display()))
    }
}

/// Relance l'exécutable avec élévation (UAC « runas »).
pub fn relaunch_as_admin(args: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if shell(
        "runas",
        &exe.display().to_string(),
        (!args.is_empty()).then_some(args),
    ) {
        Ok(())
    } else {
        Err("élévation refusée ou impossible".into())
    }
}

fn message(text: &str, title: &str, flags: u32) -> i32 {
    let (t, c) = (wide(text), wide(title));
    // SAFETY: chaînes valides pendant l'appel, pas de fenêtre parente.
    unsafe { MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), flags) }
}

pub fn warn_box(text: &str, title: &str) {
    message(text, title, MB_OK | MB_ICONWARNING);
}

/// L'interface ne peut pas démarrer : message clair et proposition du mode console.
pub fn offer_console(error: &str) {
    let app = crate::app::APP_NAME;
    let text = format!(
        "L'interface graphique de {app} ne peut pas démarrer :

{error}

         La ligne de commande reste disponible (mêmes fonctions et mêmes sécurités) avec          oblion-cli.exe, par exemple :
  oblion-cli.exe --list

         Ouvrir une console avec l'aide d'oblion-cli.exe ?"
    );
    if message(&text, app, MB_YESNO | MB_ICONERROR) == IDYES {
        let _ = open_console_help();
    }
}

/// Nouvelle console qui affiche l'aide et reste ouverte (cmd /k). Utilise oblion-cli.exe
/// s'il est à côté, sinon oblion.exe --console.
fn open_console_help() -> std::io::Result<()> {
    const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;
    let exe = std::env::current_exe()?;
    let cli = exe.with_file_name("oblion-cli.exe");
    let cmd = if cli.is_file() {
        format!("/k \"\"{}\" --help\"", cli.display())
    } else {
        format!("/k \"\"{}\" --console --help\"", exe.display())
    };
    std::process::Command::new("cmd.exe")
        .raw_arg(cmd)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map(|_| ())
}

/// Environnement WinPE (même détection que la protection des disques).
pub fn is_winpe() -> bool {
    std::env::var("SystemDrive")
        .map(|s| s.trim().eq_ignore_ascii_case("X:"))
        .unwrap_or(false)
        || crate::winio::hklm_key_exists(r"SYSTEM\CurrentControlSet\Control\MiniNT")
}
