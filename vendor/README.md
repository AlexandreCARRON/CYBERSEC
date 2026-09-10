---
id: vendor.index
kind: reference
status: active
last_reviewed: 2026-09-10
sensitivity: public
---

# Dépendances amont archivées

Ce dossier conserve des sources tierces exactes pour audit et comparaison. Elles ne font pas partie du chemin d'exécution de CYBERSEC.

- `sooryathejas-metatron/` : copie byte-for-byte de METATRON au commit `9dd2ee3daa33397453c76e9fcba446f117d22cb6`.
- `sooryathejas-metatron.manifest.sha256` : empreintes de tous les fichiers importés.
- `upstreams.json` : provenance et licence de la copie.

Ne pas corriger le code dans la copie. Importer un nouveau commit dans une branche dédiée, recalculer le manifeste, comparer les changements de sécurité, puis adapter séparément `metatron/`.
