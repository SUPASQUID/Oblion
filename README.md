# DiskErase

> ⚠️ **Outil DESTRUCTIF — version de développement (pré-alpha).**
> L'effacement d'un disque physique n'a **pas encore été validé sur du matériel réel**.
> N'utilisez pas cet outil sur un disque contenant des données à conserver.
> Utilisation à vos risques, sans aucune garantie (voir [LICENSE](LICENSE)).
>
> ⚠️ **DESTRUCTIVE tool — development version (pre-alpha).** Physical-disk erasure has **not yet
> been validated on real hardware**. Use at your own risk, without any warranty.

## Français

Outil Windows portable (sans installation, compatible WinPE / Medicat) pour effacer des disques
durs et SSD, puis générer un certificat PDF d'effacement inspiré du rapport nwipe.
Projet étudiant (BTS SIO). Nom provisoire.

### Avancement

| Étape | Contenu | État |
|---|---|---|
| 1 | Détection des disques + sécurités (disque système et clé protégés, confirmation par n° de série, `--dry-run`) | fait, testé en lecture seule |
| 2 | Effacement HDD par écrasement (DoD 5220.22-M, vérification, reprise sur erreur) + certificat PDF + historique JSON/CSV | fait, testé sur fichier uniquement |
| 3 | SSD SATA/NVMe (Sanitize, Secure Erase), SMART, HPA/DCO | à faire |
| 4 | Interface graphique (sans GPU) | à faire |
| 5 | Zip portable, CI GitHub Actions, releases signées SHA256 | à faire |

### Niveaux NIST 800-88

- Un **écrasement** (DoD, 1 passe…) vaut **Clear**, jamais Purge.
- **Purge** n'est indiqué que si une commande firmware (Sanitize / Secure Erase) a réellement réussi (étape 3).
- Le statut du certificat est **calculé** à partir des résultats ; il ne peut pas être saisi à la main.

### Utilisation (console, en administrateur)

```
DiskErase --list
DiskErase --erase N --confirm XXXX --dry-run
DiskErase --erase-file test.img --client exemple --tag INV-001
DiskErase --history
DiskErase --export-csv historique.csv
```

`XXXX` = 4 derniers caractères du n° de série du disque. `--erase-file` efface un **fichier** de test
(le certificat porte alors la mention « TEST SUR FICHIER »).

### Configuration

Tout est relatif au dossier de l'exécutable (`data/`), rien n'est écrit ailleurs :
- `data/config.toml` : votre société et le technicien par défaut ;
- `data/clients.toml` : carnet de clients ;
- `data/assets/logo.png` : logo affiché sur le certificat (optionnel).

### Compilation

```
cargo test
cargo build --release
```
Cible `x86_64-pc-windows-msvc`, CRT liée statiquement (aucun runtime Visual C++ requis).

Ce projet n'utilise pas le code de nwipe (GPLv2) : seule la structure du rapport sert de référence.

## English

Portable Windows tool (no install, WinPE / Medicat friendly) to wipe HDDs and SSDs and produce
a PDF erasure certificate. Student project, work in progress — see the warning above.
Overwrite methods are reported as NIST 800-88 **Clear**; **Purge** is only reported after a
successful firmware sanitize command (planned). MIT licensed.
