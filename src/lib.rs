//! Oblion : effacement certifié de disques (HDD/SSD/NVMe) avec certificat PDF.
//!
//! Bibliothèque commune aux deux exécutables :
//! - `oblion.exe` (sous-système windows) : interface graphique, CLI de secours ;
//! - `oblion-cli.exe` (sous-système console) : ligne de commande seule, SANS iced ni winit.
//!
//! L'interface (iced) vit dans le binaire `oblion` (src/ui), pas ici : la bibliothèque et
//! `oblion-cli.exe` ne dépendent d'aucune DLL graphique.

pub mod app;
pub mod ata;
pub mod certificate;
pub mod cli;
pub mod clock;
pub mod config;
pub mod console;
pub mod demo;
pub mod detect;
pub mod erase_hdd;
pub mod erase_ssd;
pub mod hpa;
pub mod job;
pub mod nvme;
pub mod pdf;
pub mod rawdisk;
pub mod report;
pub mod safety;
pub mod smart;
mod verify;
pub mod winio;
