//! Chargement différé des DLL graphiques de `oblion.exe` (interface iced/winit).
//! Si l'une manque (WinPE minimal), l'exe démarre quand même : il le détecte avec
//! LoadLibraryW avant de lancer l'interface et propose `oblion-cli.exe`.
//! `oblion-cli.exe` n'importe aucune de ces DLL (pas d'iced ni de winit).

const DELAY: [&str; 4] = ["dwmapi.dll", "uxtheme.dll", "imm32.dll", "ole32.dll"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        for dll in DELAY {
            println!("cargo:rustc-link-arg-bin=oblion=/DELAYLOAD:{dll}");
        }
        println!("cargo:rustc-link-arg-bin=oblion=delayimp.lib");
    }
}
