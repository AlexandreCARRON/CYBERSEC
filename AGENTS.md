# Instructions du dépôt CYBERSEC

- GitHub est la source de vérité. Vérifier la synchronisation avant toute écriture partagée et préserver les changements existants.
- Tous les tests de sécurité doivent viser un périmètre explicitement autorisé, daté et vérifiable.
- Ne jamais stocker de secret, jeton, clé privée, donnée personnelle ou export brut de cible dans le dépôt.
- Garder Metatron mono-agent tant qu'une séparation mesurable de contexte, d'outils, de permissions ou d'évaluation ne justifie pas un agent supplémentaire.
- Une capacité réseau reste inactive par défaut. Elle doit être permise par le contrat d'engagement et confirmée au moment de l'exécution.
- Ne pas ajouter d'exploitation autonome, de persistance, d'évasion, de déni de service ou de mouvement latéral.
- Échanger des entrées et sorties JSON structurées, tracer les frontières d'exécution et limiter les journaux aux métadonnées non sensibles.
- Pour valider Metatron, exécuter `python3 -m unittest discover -s metatron/tests -v` depuis la racine du dépôt.
