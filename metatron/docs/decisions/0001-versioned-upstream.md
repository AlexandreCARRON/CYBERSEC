---
id: metatron.decision.0001
kind: decision
status: accepted
last_reviewed: 2026-09-10
sensitivity: public
sources:
  - https://github.com/sooryathejas/METATRON/commit/9dd2ee3daa33397453c76e9fcba446f117d22cb6
---

# Archiver l'amont sans l'exécuter

## Contexte

Le projet tiers est utile comme référence fonctionnelle, mais son historique courant ne fournit ni release, ni tests, ni workflow CI. Plusieurs frontières de sécurité ne correspondent pas au modèle d'autorisation de CYBERSEC.

## Décision

Conserver une copie exacte sous `vendor/sooryathejas-metatron/`, avec commit, arbre Git, licence MIT et manifeste SHA-256. Cette copie est inactive et exclue du chemin d'import Python. Toute évolution se fait par nouvel import auditable, jamais par modification locale silencieuse.

## Conséquence

Le code maintenu sous `metatron/` peut évoluer sous GPL-3.0 sans masquer l'origine du travail tiers ni hériter automatiquement de ses choix opérationnels.
