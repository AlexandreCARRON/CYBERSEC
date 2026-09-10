---
id: metatron.architecture
kind: reference
status: active
last_reviewed: 2026-09-10
sensitivity: public
sources:
  - https://github.com/sooryathejas/METATRON/tree/9dd2ee3daa33397453c76e9fcba446f117d22cb6
  - https://github.com/AlexandreCARRON/ai-foundation-carron
---

# Architecture Metatron v2

## Décision

Metatron reste mono-agent. Les étapes contrôlables sont un workflow déterministe ; l'IA locale est une capacité paresseuse de synthèse, sans outils et sans effet externe.

```text
Contrat v2
   │ validation temporelle, origine, DNS, budget
   ▼
Plan JSON ── hash du contenu ──► approbation humaine exacte
   │                                  │
   └──────────────────────────────────┘
                   │ nouveau contrôle DNS
                   ▼
        adaptateurs argv fermés / HEAD sans redirection
                   │
                   ▼
      preuves JSON + audit de métadonnées
                   │
                   ▼ option explicite
         Ollama local, sortie sous schéma
```

## Frontières de confiance

Le contrat est la source d'autorité. Un plan ne peut contenir que des outils énumérés, vise une origine unique, porte une durée courte et devient invalide au moindre changement. La revalidation DNS limite les pivots vers une adresse privée ou locale après planification.

Les adaptateurs reçoivent uniquement la cible extraite du contrat et des arguments constants. Les processus n'héritent pas des variables secrètes. `http_headers` effectue un unique `HEAD`, valide TLS, refuse les redirections et ne conserve qu'une liste fermée d'en-têtes sans cookies.

Les sorties d'outils et bannières sont des données non fiables. Elles peuvent être stockées localement sous `.metatron/`, mais ne deviennent jamais des instructions. Ollama n'est joignable qu'en boucle locale, n'a aucun registre d'outils et sa sortie doit respecter le schéma d'assessment.

## Risques et checkpoints

| Niveau | Outils | Checkpoint |
| --- | --- | --- |
| `passive` | `dns`, `http_headers`, `whois` | hash du plan |
| `active` | `nmap_service`, `whatweb` | hash du plan |
| `noisy` | `nikto` | hash du plan + `--approve-noisy` |

Tous les niveaux exigent un contrat actif. La classification ne remplace jamais l'autorisation du propriétaire.

## États et reprise

Le `plan_id` sert de clé d'idempotence : une réservation locale atomique est créée avant le premier outil et le plan ne peut ensuite pas être rejoué. Après un échec, l'opérateur doit créer, relire et approuver un nouveau plan. Une erreur journalise uniquement son type ; les preuves ne sont émises par la CLI que si le plan se termine entièrement.

## Hors périmètre

L'exploitation autonome, les commandes libres, les scripts générés par modèle, la persistance, l'évasion, le déni de service et le mouvement latéral sont interdits. Une connexion par formulaire, SSO ou MFA n'est pas simulée génériquement : elle nécessite un adaptateur limité et testé à partir du parcours réel de la cible.
