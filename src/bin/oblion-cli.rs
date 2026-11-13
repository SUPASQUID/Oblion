//! `oblion-cli.exe` : ligne de commande seule (sous-système console).
//! Pour les scripts et les codes de retour : le terminal attend la fin, `$LASTEXITCODE` /
//! `%ERRORLEVEL%` sont fiables. Aucune dépendance graphique (ni iced, ni winit, ni DWM).

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(oblion::cli::main_cli(&args, None));
}
