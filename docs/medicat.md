# Utiliser Oblion depuis une clé Medicat (WinPE)

Medicat est une clé USB de dépannage qui démarre notamment un
Windows PE (« Mini Windows »). Oblion est portable : il suffit de copier son dossier sur
la clé, aucune installation n'est nécessaire.

> Les menus, noms d'entrées et partitions peuvent varier selon la version de Medicat :
> les étapes ci-dessous restent volontairement génériques.

> ⚠️ **Outil destructif** : il efface définitivement les disques. Fourni tel quel, sans
> aucune garantie ; l'auteur décline toute responsabilité en cas de perte de données.

## 1. Préparer la clé (sur un PC Windows)

1. Téléchargez `Oblion-vX.Y.Z.zip` depuis la page
   [Releases](https://github.com/SUPASQUID/Oblion/releases) et vérifiez son empreinte :
   ```powershell
   Get-FileHash .\Oblion-vX.Y.Z.zip -Algorithm SHA256
   ```
   Le résultat doit être identique au contenu de `Oblion-vX.Y.Z.zip.sha256`.
2. Décompressez le zip.
3. Branchez la clé Medicat et ouvrez sa **partition de données** (la partition visible
   dans l'explorateur, celle où l'on dépose habituellement ses fichiers et outils).
4. Copiez le dossier décompressé à la racine de cette partition, par exemple dans un
   dossier `Oblion` :
   ```
   <partition de données>\Oblion\oblion.exe
   <partition de données>\Oblion\oblion-cli.exe
   <partition de données>\Oblion\Lancer.bat
   <partition de données>\Oblion\data\...
   ```
5. (Facultatif) Remplissez `data\config.toml` (société, technicien) et
   `data\clients.toml`, et déposez votre logo dans `data\assets\logo.png`.

Gardez tout le dossier ensemble : Oblion lit et écrit uniquement dans `data\` à côté de
l'exécutable (certificats, historique, journaux).

## 2. Démarrer et lancer Oblion

1. Branchez le disque à effacer **en direct** (SATA ou NVMe sur la carte mère) : les
   adaptateurs USB bloquent le plus souvent les commandes d'effacement firmware.
2. Démarrez le PC sur la clé Medicat et choisissez l'environnement Windows PE
   (« Mini Windows » ou équivalent selon la version).
3. Une fois le bureau WinPE affiché, ouvrez l'explorateur de fichiers et allez dans le
   dossier `Oblion` de la clé (la lettre de lecteur peut changer d'un démarrage à
   l'autre).
4. Double-cliquez sur **`Lancer.bat`**. Sous WinPE on est déjà administrateur : l'interface
   s'ouvre directement.
5. Si l'interface ne démarre pas (WinPE très minimal, DLL graphiques absentes), Oblion
   l'indique : utilisez alors **`Lancer-console.bat`** et `oblion-cli.exe`
   (`oblion-cli --list`, `oblion-cli --info N`, `oblion-cli --erase N --confirm XXXX`).

Les certificats PDF sont enregistrés dans `Oblion\data\certificates` **sur la clé** : ils
sont donc conservés après l'arrêt du PC.

## 3. Protection automatique de la clé

Oblion refuse d'effacer :

- le disque qui héberge le Windows en cours d'exécution ;
- **le disque qui contient Oblion lui-même**, c'est-à-dire la clé Medicat quand Oblion
  est lancé depuis la clé. Elle apparaît dans la liste marquée « Clé de démarrage
  (contient l'outil) » et ne peut pas être effacée.

Cas particulier : si Oblion est lancé depuis le lecteur système de WinPE (`X:`, chargé en
mémoire), la clé d'origine ne peut pas être identifiée. Par prudence, **tous les disques
USB sont alors protégés** et un avertissement s'affiche. Lancez Oblion depuis la clé
elle-même pour éviter ce cas.

La protection est **fermée par défaut** : si Oblion ne parvient pas à déterminer quels
disques protéger, il refuse tout effacement.

Les autres disques USB branchés (disque externe, autre clé) ne sont pas protégés :
débranchez tout ce qui ne doit pas être effacé avant de commencer.

## 4. Si le dossier est en lecture seule

Si la partition de la clé n'est pas accessible en écriture, Oblion écrit certificats,
historique et journaux dans un dossier temporaire de WinPE et l'indique à l'écran.
Ce dossier disparaît à l'arrêt : **copiez les certificats** sur un autre support avant
d'éteindre.
