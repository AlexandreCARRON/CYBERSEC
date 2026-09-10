# Instructions du dépôt CYBERSEC

- GitHub est la source de vérité. Avant une écriture partagée ou une publication, vérifier la branche, l'état local, le remote et l'écart avec `origin/main`.
- Séparer les faits et sources dans `metatron/docs/sources/`, les décisions dans `metatron/docs/decisions/`, les schémas dans `metatron/schemas/` et les évaluations dans `metatron/evals/`.
- Conserver `vendor/sooryathejas-metatron/` byte-for-byte conforme au commit épinglé. Ne jamais l'importer ou l'exécuter depuis le code maintenu.
- Ne jamais stocker de secret, jeton, clé privée, donnée personnelle, cible réelle ou export brut de cible dans le dépôt. Tous les exemples doivent être fictifs.
- Garder Metatron mono-agent tant qu'une séparation mesurable de contexte, d'outils, de permissions, de propriétaire, de risque ou d'évaluation ne justifie pas un agent supplémentaire.
- Une capacité réseau reste inactive par défaut. Elle doit être permise par un contrat actif, figurer dans un plan content-addressed et recevoir l'approbation exacte de l'opérateur.
- Le modèle ne choisit jamais une cible, un outil ou un argument. Les effets externes restent dans du code déterministe avec budget, timeout, journal et condition d'arrêt.
- Ne pas ajouter d'exploitation autonome, de persistance, d'évasion, de déni de service, de destruction ou de mouvement latéral.
- Tout répertoire durable maintenu possède un `README.md`. Tout document maintenu possède un frontmatter YAML, sauf les instructions moteur comme ce fichier.
- Placer avant chaque fonction ou méthode créée ou modifiée un commentaire bref décrivant son intention, sa contrainte ou son risque.
- Avant publication, exécuter `PYTHONPATH=metatron/src python3 -m unittest discover -s metatron/tests -v` puis `python3 scripts/validate_repository.py`.
