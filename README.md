---
id: cybersec.index
kind: reference
status: active
last_reviewed: 2026-09-10
sensitivity: public
---

# CYBERSEC

CYBERSEC est un dépôt de cybersécurité défensive et de tests d'intrusion strictement autorisés. Son projet actif est [Metatron](metatron/README.md), un control plane déterministe inspiré du projet amont METATRON.

## Organisation

- `metatron/` : implémentation maintenue, contrats, évaluations et documentation.
- `vendor/sooryathejas-metatron/` : copie exacte et inactive de l'amont, épinglée par commit et manifeste SHA-256.
- `Analyse/`, `Decouverte/`, `Installs/` : ressources historiques, hors du chemin d'exécution Metatron.
- `scripts/` : contrôles de qualité du dépôt.

## Modèle opérationnel

Metatron sépare quatre phases : contrat d'autorisation, plan sans effet externe, approbation humaine liée au hash du plan, puis exécution bornée. Le modèle local n'intervient qu'après l'exécution pour structurer les preuves ; il ne choisit ni cible, ni outil, ni argument.

```text
contrat JSON -> plan immuable -> approbation exacte -> outils bornés -> preuves JSON -> synthèse locale optionnelle
```

Commencer par le [guide Metatron](metatron/README.md), puis consulter l'[architecture](metatron/docs/architecture.md) et l'[analyse de l'amont](metatron/docs/sources/upstream-metatron.md).

## Usage responsable

N'utiliser ce dépôt que sur un système pour lequel une autorisation explicite, datée et vérifiable a été obtenue. Toute exploitation autonome, persistance, évasion, destruction, saturation ou mouvement latéral est hors périmètre. Aucun secret, jeton, donnée personnelle ou export brut de cible ne doit être versionné.

Le code maintenu par ce dépôt est distribué sous GPL-3.0. La copie tierce conserve sa licence MIT originale dans son propre dossier.
