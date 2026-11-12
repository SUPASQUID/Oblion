# Référence : rapport nwipe (v0.43.1) à reproduire

Source : un rapport nwipe réel (fichier non publié ; n° de série anonymisé dans ce dépôt)
(on ne copie pas le code de nwipe, GPLv2 : on reproduit seulement la structure du rapport.)

**Constat : le PDF de référence fait 7 pages, pas 2.** Pour tenir en 2 pages, on garde :
- Page 1 = « Erasure Status » (identique à nwipe)
- Page 2 = résumé SMART (attributs clés + health + température) + courbe vitesse/température
Le SMART brut complet (journaux, historique de température) va en annexe optionnelle ou dans `logs/`. À valider avec toi.

## Page 1 — Erasure Status (champs)
- En-tête : Disk Model, Disk S/N, Tag
- Organisation : Business Name / Address / Contact Name / Contact Phone  (← `config.toml`)
- Client : Name / Address / Contact Name / Contact Phone
- Disk Information : Serial, Make/Model, Bus (ATA…), Size (Apparent), Size (Real)
- Disk Erasure Details : Start time, End time, Duration, Status (ERASED), Method,
  PRNG algorithm, Verify pass (Last/All/None), Final pass (Zeros/Ones/None),
  Rounds (completed/requested), Bytes Erased (+ %), HPA/DCO, Throughput,
  Errors (pass/sync/verify/retries), Information
- Technicien : Name/ID, Signature
- Pied : « Disc Erasure by <APP_NAME> version X »

## Page 2+ — SMART
- smartctl : modèle, famille, S/N, WWN, firmware, capacité, secteurs, rotation, ATA/SATA, « ata security: Disabled, frozen »
- Health PASSED/FAILED, table des attributs (id, nom, flags, value, worst, thresh, raw)
- Journaux d'erreurs, auto-tests, historique SCT température

## Page finale — Speed Profile
- Graphe débit (min/max/avg) + température en fonction de % effacé

## Ajouts demandés (absents du nwipe)
Code-barres, ID unique du certificat, QR code, signature, méthode RÉELLE (Purge/Clear).

## Décision : niveau NIST 800-88 (validée)
- « Purge » uniquement si une commande firmware a réellement réussi (jamais déduit d'un simple écrasement).
- SSD SATA : ATA Sanitize (Block Erase / Crypto Scramble), sinon ATA Secure Erase. NVMe : Sanitize ou Format NVM (Secure/Crypto Erase).
- HDD : ATA Secure Erase (ou Sanitize Overwrite) en 1re option = Purge. DoD 5220.22-M = « Clear » (repli si non supporté).
- Commande refusée/bloquée (pont USB, frozen, driver) : toujours affiché, repli TRIM + écrasement, certificat « Clear ».
- Mode « Purge obligatoire » : si le Purge échoue, arrêt, aucun certificat Purge.
- Frozen : guider l'opérateur (veille/réveil ou rebranchement à chaud).

## Remarque utile pour la suite
Ce disque test affichait « ata security: Disabled, frozen » : bon cas réel pour tester la détection « frozen » (étape 3).
