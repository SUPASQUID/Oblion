# Journal des modifications

Toutes les évolutions notables d'Oblion sont notées ici.

Le format suit [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/) et le projet
utilise le [versionnage sémantique](https://semver.org/lang/fr/).

## [Non publié]

## [0.1.0] - 2026-11-13

Première version publique. Effacement validé sur disque virtuel (VHD) ; lecture NVMe
testée sur matériel réel ; commandes d'effacement firmware pas encore validées sur
du matériel physique.

### Ajouté

- **Détection et sécurités** : liste des disques physiques, protection du disque du
  Windows en cours et de la clé qui contient l'outil (fermée par défaut : refus si la
  protection ne peut pas être établie ; WinPE détecté), confirmation par les 4 derniers
  caractères du n° de série, mode `--dry-run`, verrouillage et démontage des volumes,
  mise hors ligne puis remise en ligne du disque.
- **Écrasement HDD** : DoD 5220.22-M (0x00, 0xFF, aléatoire) avec vérification,
  reprise sur erreur, E/S alignées sans cache ; niveau NIST 800-88 **Clear**.
- **Effacement firmware** :
  - ATA : Sanitize (Crypto Scramble, Block Erase, Overwrite) avec suivi, Security Erase
    (mot de passe temporaire retiré automatiquement, signalé sur le certificat sinon) ;
  - NVMe : Sanitize, Format NVM sécurisé en repli, refus si plusieurs namespaces ;
  - **Purge** accordé seulement si la commande réussit **et** si la vérification par
    marqueurs (environ 1000 secteurs) confirme leur disparition.
- Disque gelé (frozen) détecté : aucune commande tentée, l'opérateur est guidé.
- SMART (ATA et NVMe) et détection HPA/DCO (sans modification).
- **Certificat PDF** de 2 pages (QR code, code-barres, identifiant unique, SMART, profil
  de débit), statut calculé et non modifiable, historique JSON, export CSV, carnet de
  clients (`data/clients.toml`).
- **Commandes console** : `--list`, `--info`, `--prepare`, `--erase`, `--erase-file`,
  `--history`, `--export-csv`, `--clients`, `--method auto|firmware|overwrite`,
  `--allow-fallback`.
- **Interface graphique** iced en rendu logiciel (aucun GPU, compatible WinPE) : liste
  des disques, configuration, confirmation, effacement en direct, certificat,
  historique, paramètres, thèmes clair et sombre, mode `--gui-demo` (disques simulés).
- **Deux exécutables** : `oblion.exe` (interface, DLL graphiques chargées en différé) et
  `oblion-cli.exe` (console, sans dépendance graphique, pour WinPE minimal).
- Paramètres enregistrés dans `data/config.toml` sans perdre ses commentaires.
- **Distribution** :
  - icône (générée depuis `assets/oblion-logo.svg`) et informations de version dans
    les deux exécutables ;
  - paquet portable `Oblion-vX.Y.Z.zip` (lanceurs `Lancer.bat` et `Lancer-console.bat`
    avec élévation administrateur, `LISEZMOI.txt`, modèles `data/` vides,
    `THIRD-PARTY-LICENSES.txt`) et son empreinte `.sha256` ;
  - intégration continue GitHub Actions et publication automatique des releases sur tag ;
  - `SECURITY.md`, modèles d'issues, procédure Medicat (`docs/medicat.md`).

### Modifié

- Projet renommé de « DiskErase » en **Oblion**.

### Corrigé

- Console en UTF-8 (accents corrects sous cmd et WinPE).
- Tailles de moins de 1 Go affichées en Mo ; code de confirmation `D<n>-<taille>` pour
  un disque sans n° de série.
- Débit provisoire affiché pendant la progression au lieu de 0,0 MB/s.

[Non publié]: https://github.com/SUPASQUID/Oblion/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SUPASQUID/Oblion/releases/tag/v0.1.0
