# Sécurité

## Signaler une faille

Merci de **ne pas** ouvrir d'issue publique pour une faille de sécurité.

Utilisez le signalement privé de GitHub : onglet **Security** du dépôt, puis
**Report a vulnerability** (GitHub Security Advisories). Le rapport n'est visible que
par le mainteneur jusqu'à sa publication.

Indiquez si possible :

- la version d'Oblion (`oblion-cli --version`) et l'environnement (Windows 10/11, WinPE) ;
- le type de disque et sa connexion (SATA direct, NVMe, adaptateur USB…) ;
- les étapes pour reproduire, ce qui était attendu et ce qui s'est passé ;
- l'impact estimé.

N'envoyez **aucune donnée personnelle** ni **n° de série complet** : masquez-les
(par exemple `XXXX…1234`).

Oblion est un projet étudiant maintenu sur le temps libre : aucun délai de réponse
n'est garanti, mais les signalements sont traités en priorité.

## Périmètre

Oblion est un **outil destructif** : il efface définitivement des disques. Il est fourni
tel quel, sans aucune garantie ; l'auteur décline toute responsabilité en cas de perte
de données (voir [LICENSE](LICENSE)).

Sont considérés comme des failles, par exemple :

- un effacement possible du disque système en cours d'utilisation ou de la clé qui
  contient l'outil, malgré la protection ;
- un effacement d'un autre disque que celui confirmé (n° de série) ;
- un certificat qui annonce un niveau (Clear / Purge) ou un statut non justifié par les
  résultats réels ;
- une écriture de fichiers hors du dossier de l'outil, ou une fuite de données
  (n° de série, informations clients) hors des fichiers prévus ;
- une exécution de code ou une élévation de privilèges via les fichiers lus
  (`data/config.toml`, `data/clients.toml`, `data/assets/`) ;
- un problème dans le paquet publié (zip modifié, empreinte SHA256 incorrecte).

Hors périmètre :

- l'effacement volontaire d'un disque choisi et confirmé par l'utilisateur ;
- le blocage par SmartScreen ou un antivirus (exécutables non signés) ;
- les limites connues documentées dans le README (adaptateurs USB ou pilotes RAID qui
  bloquent les commandes firmware, vérification par échantillonnage, etc.) ;
- les failles de Windows, du firmware des disques ou de Medicat / WinPE eux-mêmes.

## Versions prises en charge

Seule la dernière version publiée dans
[Releases](https://github.com/SUPASQUID/Oblion/releases) reçoit des correctifs.
