---
id: metatron.index
kind: reference
status: active
last_reviewed: 2026-09-10
sensitivity: public
---

# Metatron

Metatron est le projet actif de CYBERSEC pour conduire des observations et scans bornés sur un SaaS explicitement autorisé. Cette version reprend les idées utiles de l'amont — CLI locale, outils spécialisés, synthèse Ollama — derrière un control plane qui ne laisse jamais le modèle piloter les outils.

## Garanties principales

- une origine exacte, une période, un propriétaire et les outils permis sont signés dans le contrat ;
- la résolution DNS est vérifiée à la planification puis juste avant chaque action ;
- un plan est identifié par le hash de tout son contenu et expire en 15 minutes par défaut ;
- l'opérateur doit fournir cet identifiant exact, avec une seconde confirmation pour `nikto` ;
- les arguments d'outils proviennent de modèles `argv` fermés, jamais du LLM ou de la cible ;
- les redirections HTTP ne sont jamais suivies ;
- les secrets restent dans l'environnement et les sous-processus reçoivent un environnement nettoyé ;
- Ollama est limité à la boucle locale et reçoit des preuves JSON bornées après exécution.

## Installation

Le noyau n'a aucune dépendance Python externe :

```bash
cd metatron
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Les adaptateurs locaux nécessitent uniquement le binaire choisi : `whois`, `nmap`, `whatweb` ou `nikto`. `dns` et `http_headers` utilisent la bibliothèque standard Python. L'analyse IA optionnelle nécessite Ollama sur `127.0.0.1` et un modèle installé explicitement ; le `Modelfile` tiers archivé n'est pas activé.

## Préparer une mission SaaS

Copier `config/engagement.example.json` vers un fichier local ignoré, puis renseigner l'origine publique exacte, la fenêtre d'autorisation, le signataire et une liste minimale d'outils. Ne jamais mettre les identifiants dans ce fichier : seules les références de variables d'environnement y figurent.

Les modes génériques actuels sont `none`, `basic` et `bearer`. Une authentification par formulaire, SSO ou MFA exige un adaptateur de session spécifique au parcours réel ; il sera ajouté lorsque l'URL de test et le fonctionnement de connexion seront disponibles. Les comptes doivent être dédiés, non privilégiés et révocables.

```bash
export METATRON_TEST_USERNAME="..."
export METATRON_TEST_PASSWORD="..."
metatron validate config/engagement.example.json
```

Créer ensuite un plan sans effet réseau autre que la résolution nécessaire au contrôle de scope :

```bash
metatron plan config/engagement.example.json \
  --target https://saas.example.invalid \
  --tool dns \
  --tool http_headers \
  --output .metatron/plan.json
```

Relire le fichier et exécuter avec le `plan_id` affiché :

```bash
metatron execute config/engagement.example.json \
  --plan .metatron/plan.json \
  --approve PLAN_ID > .metatron/evidence.json
```

`nikto` est classé `noisy` et réclame aussi `--approve-noisy`. Aucun exemple ne l'active par défaut.

Pour une synthèse locale optionnelle :

```bash
export METATRON_MODEL="nom-du-modele-ollama-installe"
metatron assess \
  --evidence .metatron/evidence.json \
  --objective "Qualifier uniquement les constats démontrés"
```

## Validation

Depuis la racine du dépôt :

```bash
PYTHONPATH=metatron/src python3 -m unittest discover -s metatron/tests -v
python3 scripts/validate_repository.py
```

Les détails de conception sont dans [docs/architecture.md](docs/architecture.md). La copie et l'analyse du projet d'origine sont séparées dans [`vendor/`](../vendor/README.md) et [docs/sources/upstream-metatron.md](docs/sources/upstream-metatron.md).
