//! Console du mode ligne de commande.
//!
//! L'exécutable est du sous-système « windows » (pas de fenêtre noire au double-clic). En mode
//! CLI on se rattache à la console du parent (cmd, PowerShell) ; à défaut on en crée une.
//! Les sorties déjà redirigées (pipe, fichier) sont conservées telles quelles.

use std::sync::atomic::{AtomicBool, Ordering};

use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    AllocConsole, AttachConsole, GetStdHandle, SetStdHandle, ATTACH_PARENT_PROCESS,
    STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

/// Vrai si la console a été créée par nous (lancement sans console parente).
static ALLOCATED: AtomicBool = AtomicBool::new(false);

fn valid(h: HANDLE) -> bool {
    !h.is_null() && h != INVALID_HANDLE_VALUE
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Rattache (ou crée) la console et complète les flux standard non redirigés.
pub fn attach() {
    // SAFETY: appels Win32 sans pointeur conservé ; les poignées ouvertes restent valides
    // jusqu'à la fin du processus (flux standard).
    unsafe {
        let ids: [STD_HANDLE; 3] = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
        let redirected: Vec<bool> = ids.iter().map(|&i| valid(GetStdHandle(i))).collect();
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            if AllocConsole() == 0 {
                return;
            }
            ALLOCATED.store(true, Ordering::SeqCst);
        }
        for (k, &id) in ids.iter().enumerate() {
            if redirected[k] {
                continue; // pipe ou fichier fourni par le parent : on le garde
            }
            let (name, access) = if id == STD_INPUT_HANDLE {
                ("CONIN$", GENERIC_READ | GENERIC_WRITE)
            } else {
                ("CONOUT$", GENERIC_READ | GENERIC_WRITE)
            };
            let n = wide(name);
            let h = CreateFileW(
                n.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            );
            if valid(h) {
                SetStdHandle(id, h);
            }
        }
    }
}

/// Fin du mode CLI : si la console a été créée pour nous, on attend Entrée avant qu'elle
/// ne se ferme (sinon le texte disparaîtrait aussitôt).
pub fn detach() {
    if ALLOCATED.load(Ordering::SeqCst) {
        println!();
        println!("Appuyez sur Entrée pour fermer cette fenêtre…");
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
    }
}
