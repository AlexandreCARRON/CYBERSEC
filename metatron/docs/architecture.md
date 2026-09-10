---
id: metatron.architecture
kind: decision
status: draft
last_reviewed: 2026-09-10
sensitivity: public
sources: ["https://github.com/AlexandreCARRON/ai-foundation-carron", "https://developers.openai.com/api/docs/guides/structured-outputs"]
---

# Architecture initiale de Metatron

## Décision

Metatron démarre avec un agent unique et un flux déterministe : charger le contrat d'engagement, autoriser l'action, observer la cible sans suivre les redirections, puis produire au besoin une analyse structurée avec l'API Responses.

## Frontières

- Le contrat JSON porte le propriétaire, la période, les origines, les actions et les références de secrets autorisées.
- La politique locale contrôle l'origine et toutes les adresses issues de la résolution DNS. Une cible SaaS exige la politique `public_only`, qui refuse les adresses non publiques.
- Les secrets proviennent uniquement de variables d'environnement et restent hors des sorties, journaux et entrées du modèle.
- L'observateur utilise uniquement une requête `HEAD`, ne suit aucune redirection et ne conserve qu'une liste fermée d'en-têtes de sécurité.
- Le modèle reçoit des métadonnées structurées, jamais le corps de la page, et n'exécute aucun outil.
- Le journal contient l'origine et l'état de l'exécution, sans chemin, requête, en-tête ni contenu de cible.

## Conditions d'arrêt

L'exécution s'arrête si le contrat est invalide ou expiré, si la cible sort du périmètre, si une adresse viole la politique réseau, si l'opérateur ne confirme pas l'autorisation, si un secret référencé manque ou si la sortie du modèle ne respecte pas le schéma.

## Évolution

Une nouvelle capacité doit disposer d'une action de scope dédiée, d'un contrôle déterministe, de tests et d'une trace. Un second agent n'est justifié que par une séparation mesurable de contexte, d'outils, de permissions, de propriétaire ou d'évaluation.

L'authentification Basic et Bearer est disponible dans ce socle. Une authentification par formulaire, SSO ou MFA doit être ajoutée comme adaptateur spécifique après documentation du parcours de connexion de la cible ; les identifiants restent injectés à l'exécution.
