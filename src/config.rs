//! Chemins relatifs à l'exécutable + lecture de data/config.toml.
//! Aucune écriture hors du dossier de l'outil (ni registre, ni AppData, ni C:\).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::app::APP_NAME;
use crate::erase_hdd::{Fill, VerifyMode};

#[derive(Debug, Clone)]
pub struct Paths {
    /// Dossier data/ d'origine (config.toml, assets) : lu seulement.
    pub data: PathBuf,
    pub assets: PathBuf,
    /// Dossiers où l'on écrit.
    pub certificates: PathBuf,
    pub history: PathBuf,
    pub logs: PathBuf,
    /// Message à afficher si data/ est en lecture seule et qu'on a basculé sur un dossier temporaire.
    pub warning: Option<String>,
}

fn is_writable_dir(dir: &Path) -> bool {
    if fs::create_dir_all(dir).is_err() {
        return false;
    }
    let probe = dir.join(format!(".write_test_{}", std::process::id()));
    match fs::write(&probe, b"x") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

impl Paths {
    /// Chemins réels : dossier de l'exécutable, repli sur le dossier temporaire.
    pub fn from_exe() -> Paths {
        let root = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        Paths::resolve(&root, &std::env::temp_dir())
    }

    /// Testable : `root` = dossier de l'exe, `temp` = dossier temporaire de repli.
    pub fn resolve(root: &Path, temp: &Path) -> Paths {
        let data = root.join("data");
        let assets = data.join("assets");
        let writable = ["certificates", "history", "logs"]
            .iter()
            .all(|d| is_writable_dir(&data.join(d)));
        let (base, warning) = if writable {
            (data.clone(), None)
        } else {
            let fb = temp.join(format!("{APP_NAME}-data"));
            let msg = format!(
                "Le dossier data est en lecture seule : certificats, historique et journaux sont écrits dans {} (temporaire, copiez-les avant de quitter).",
                fb.display()
            );
            (fb, Some(msg))
        };
        for d in ["certificates", "history", "logs"] {
            let _ = fs::create_dir_all(base.join(d));
        }
        Paths {
            data,
            assets,
            certificates: base.join("certificates"),
            history: base.join("history"),
            logs: base.join("logs"),
            warning,
        }
    }

    pub fn config_file(&self) -> PathBuf {
        self.data.join("config.toml")
    }

    pub fn clients_file(&self) -> PathBuf {
        self.data.join("clients.toml")
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Company {
    pub name: String,
    pub address: String,
    pub contact_name: String,
    pub phone: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Technician {
    pub name: String,
}

/// Client final (bloc « Client » du certificat). Vient du carnet `clients.toml`
/// et/ou des options `--customer-*`.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Customer {
    pub name: String,
    pub address: String,
    pub contact_name: String,
    pub phone: String,
}

/// Champs saisis en ligne de commande : chacun, s'il est présent, remplace celui du carnet.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CustomerOverride {
    pub name: Option<String>,
    pub address: Option<String>,
    pub contact_name: Option<String>,
    pub phone: Option<String>,
}

impl Customer {
    /// Fusion champ par champ : les options explicites l'emportent.
    pub fn merged(mut self, o: &CustomerOverride) -> Customer {
        if let Some(v) = &o.name {
            self.name = v.clone();
        }
        if let Some(v) = &o.address {
            self.address = v.clone();
        }
        if let Some(v) = &o.contact_name {
            self.contact_name = v.clone();
        }
        if let Some(v) = &o.phone {
            self.phone = v.clone();
        }
        self
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ClientsFile {
    clients: BTreeMap<String, Customer>,
}

/// Carnet de clients (`[clients.<id>]`), trié par identifiant.
pub fn parse_clients(text: &str) -> Result<BTreeMap<String, Customer>, String> {
    toml::from_str::<ClientsFile>(text)
        .map(|f| f.clients)
        .map_err(|e| format!("clients.toml invalide : {e}"))
}

/// Fichier absent = carnet vide ; fichier illisible ou invalide = erreur claire.
pub fn load_clients(path: &Path) -> Result<BTreeMap<String, Customer>, String> {
    match fs::read_to_string(path) {
        Ok(t) => parse_clients(&t),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(format!("lecture de {} impossible : {e}", path.display())),
    }
}

/// Client du carnet par identifiant ; un id inconnu liste les ids disponibles.
pub fn find_client(book: &BTreeMap<String, Customer>, id: &str) -> Result<Customer, String> {
    book.get(id.trim()).cloned().ok_or_else(|| {
        if book.is_empty() {
            format!("client « {id} » inconnu : le carnet clients.toml est vide ou absent")
        } else {
            let ids: Vec<&str> = book.keys().map(String::as_str).collect();
            format!("client « {id} » inconnu (disponibles : {})", ids.join(", "))
        }
    })
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct EraseCfg {
    pub hdd_passes: Vec<String>,
    pub verify: String,
}

impl Default for EraseCfg {
    fn default() -> Self {
        EraseCfg {
            hdd_passes: vec!["0x00".into(), "0xFF".into(), "random".into()],
            verify: "last".into(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub company: Company,
    pub technician: Technician,
    pub erase: EraseCfg,
}

impl Config {
    pub fn parse(text: &str) -> Result<Config, String> {
        // Champ inconnu (faute de frappe) = erreur : toml indique le champ et les noms attendus.
        let c: Config = toml::from_str(text).map_err(|e| format!("config.toml invalide : {e}"))?;
        c.validate()?;
        Ok(c)
    }

    /// Passes et vérification utilisables telles quelles par le moteur.
    fn validate(&self) -> Result<(), String> {
        if self.erase.hdd_passes.is_empty() {
            return Err("config.toml invalide : [erase] hdd_passes ne peut pas être vide".into());
        }
        for p in &self.erase.hdd_passes {
            Fill::parse(p)
                .map_err(|e| format!("config.toml invalide : [erase] hdd_passes : {e}"))?;
        }
        VerifyMode::parse(&self.erase.verify)
            .map_err(|e| format!("config.toml invalide : [erase] verify : {e}"))?;
        Ok(())
    }

    /// Fichier absent = valeurs par défaut ; fichier illisible ou invalide = erreur claire.
    pub fn load(path: &Path) -> Result<Config, String> {
        match fs::read_to_string(path) {
            Ok(t) => Config::parse(&t),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(format!("lecture de {} impossible : {e}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("diskerase-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn parses_config_with_defaults() {
        let c = Config::parse(
            "[company]\nname = \"Société Exemple\"\n[technician]\nname = \"Technicien Test\"",
        )
        .unwrap();
        assert_eq!(c.company.name, "Société Exemple");
        assert_eq!(c.technician.name, "Technicien Test");
        assert_eq!(c.erase.hdd_passes, vec!["0x00", "0xFF", "random"]);
        assert_eq!(c.erase.verify, "last");
    }

    #[test]
    fn invalid_config_is_an_error() {
        assert!(Config::parse("[company\nname=").is_err());
    }

    #[test]
    fn unknown_fields_are_rejected_with_their_name() {
        let e = Config::parse("[company]\nnmae = \"x\"").unwrap_err();
        assert!(
            e.contains("config.toml invalide") && e.contains("nmae"),
            "{e}"
        );
        assert!(Config::parse("[technicien]\nname = \"x\"").is_err());
        assert!(parse_clients("[clients.a]\nadress = \"x\"")
            .unwrap_err()
            .contains("adress"));
    }

    #[test]
    fn erase_section_is_validated() {
        assert!(Config::parse("[erase]\nhdd_passes = []")
            .unwrap_err()
            .contains("vide"));
        assert!(Config::parse("[erase]\nhdd_passes = [\"0x00\", \"zz\"]")
            .unwrap_err()
            .contains("zz"));
        assert!(Config::parse("[erase]\nverify = \"parfois\"").is_err());
        assert!(Config::parse("[erase]\nhdd_passes = [\"0xAA\"]\nverify = \"all\"").is_ok());
    }

    #[test]
    fn missing_config_gives_defaults() {
        let c = Config::load(Path::new(r"Z:\nexiste\pas\config.toml")).unwrap();
        assert_eq!(c, Config::default());
    }

    const BOOK: &str = r#"
[clients.lycee-jm]
name = "Client Exemple"
address = "1 rue Exemple, 00000 Exempleville"
contact_name = "Service informatique"
phone = "01 00 00 00 00"

[clients.autre]
name = "Autre Exemple"
"#;

    #[test]
    fn parses_client_book() {
        let b = parse_clients(BOOK).unwrap();
        assert_eq!(b.len(), 2);
        assert_eq!(b["lycee-jm"].phone, "01 00 00 00 00");
        // Champs manquants = vides.
        assert_eq!(b["autre"].address, "");
        assert!(parse_clients("").unwrap().is_empty());
        assert!(parse_clients("[clients.x\nname=").is_err());
    }

    #[test]
    fn missing_client_book_is_empty() {
        assert!(load_clients(Path::new(r"Z:\nexiste\pas\clients.toml"))
            .unwrap()
            .is_empty());
    }

    #[test]
    fn unknown_client_lists_available_ids() {
        let b = parse_clients(BOOK).unwrap();
        let e = find_client(&b, "inconnu").unwrap_err();
        assert!(e.contains("autre") && e.contains("lycee-jm"), "{e}");
        assert!(find_client(&BTreeMap::new(), "x")
            .unwrap_err()
            .contains("vide"));
        assert_eq!(find_client(&b, "autre").unwrap().name, "Autre Exemple");
    }

    #[test]
    fn explicit_options_override_field_by_field() {
        let b = parse_clients(BOOK).unwrap();
        let o = CustomerOverride {
            phone: Some("02 00 00 00 00".into()),
            ..Default::default()
        };
        let c = find_client(&b, "lycee-jm").unwrap().merged(&o);
        assert_eq!(c.name, "Client Exemple");
        assert_eq!(c.contact_name, "Service informatique");
        assert_eq!(c.phone, "02 00 00 00 00");
        // Sans carnet : seules les options.
        let o = CustomerOverride {
            name: Some("Seul".into()),
            ..Default::default()
        };
        assert_eq!(
            Customer::default().merged(&o),
            Customer {
                name: "Seul".into(),
                ..Default::default()
            }
        );
    }

    #[test]
    fn paths_are_relative_to_root_and_created() {
        let root = tmp("root");
        let p = Paths::resolve(&root, &tmp("temp"));
        assert!(p.warning.is_none());
        assert_eq!(p.certificates, root.join("data").join("certificates"));
        assert!(p.history.is_dir() && p.logs.is_dir());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn falls_back_to_temp_when_data_is_unwritable() {
        let root = tmp("ro");
        // Un fichier nommé « data » empêche de créer le dossier : simule un support en lecture seule.
        fs::write(root.join("data"), b"x").unwrap();
        let temp = tmp("fb");
        let p = Paths::resolve(&root, &temp);
        assert!(p.warning.is_some());
        assert!(p.certificates.starts_with(&temp));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&temp);
    }
}
