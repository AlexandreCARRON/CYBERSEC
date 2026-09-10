---
id: metatron.decision.0002
kind: decision
status: accepted
last_reviewed: 2026-09-10
sensitivity: public
sources:
  - https://github.com/sooryathejas/METATRON/issues/32
  - https://github.com/sooryathejas/METATRON/issues/33
  - https://github.com/sooryathejas/METATRON/issues/36
  - https://github.com/AlexandreCARRON/ai-foundation-carron
---

# Retirer le LLM de la boucle d'exécution

## Contexte

L'amont interprète des balises textuelles du modèle pour lancer des outils. Les issues publiques documentent des pivots hors cible, des redirections vers des services internes et des déductions de vulnérabilités insuffisamment fondées.

## Décision

Le modèle ne dispose d'aucun outil. Le contrat, le plan, le hash d'approbation, les modèles `argv`, les budgets et les contrôles DNS sont du code déterministe. L'IA intervient uniquement sur un fichier de preuves déjà produit, via Ollama local et un schéma de sortie fermé.

## Conséquence

La surface d'attaque par prompt injection est réduite à la qualité du rapport : un texte hostile peut encore influencer une synthèse, mais ne peut ni changer la cible, ni choisir un outil, ni provoquer une requête réseau de pentest.
