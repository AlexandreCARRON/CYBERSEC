# Metatron

Metatron est un assistant de test d'intrusion conçu pour des environnements explicitement autorisés. Ce premier incrément valide le périmètre, effectue une observation HTTP passive par `HEAD` et peut demander à un modèle OpenAI une analyse JSON structurée.

## Garde-fous du MVP

- contrat d'engagement daté et limité à des origines exactes ;
- confirmation d'autorisation obligatoire à chaque action réseau ;
- accès aux cibles publiques uniquement avec la politique `public_only`, qui refuse les adresses privées, locales ou réservées ;
- secrets chargés par variables d'environnement, jamais inscrits dans le contrat ou les journaux ;
- aucune redirection suivie et aucun corps de page transmis au modèle ;
- aucune capacité d'exploitation, de persistance, d'évasion, de déni de service ou de mouvement latéral ;
- sortie IA validée et journal local réduit aux métadonnées.

## Installation

Depuis ce dossier :

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[ai]'
```

La clé API et les futurs codes du compte de test Mouci restent dans l'environnement :

```bash
export OPENAI_API_KEY="..."
export METATRON_MOUCI_USERNAME="..."
export METATRON_MOUCI_PASSWORD="..."
```

## Contrat Mouci SaaS

Copier `config/engagement.mouci.example.json` hors du contrôle de version si des détails sensibles doivent y être ajoutés. Remplacer l'origine fictive, les dates, le responsable de l'autorisation et le mode d'authentification. Les modes actuels sont `none`, `basic` et `bearer` ; une connexion par formulaire, SSO ou MFA demandera un adaptateur lié au parcours réel de Mouci.

Valider le contrat :

```bash
metatron validate config/engagement.mouci.example.json
```

Observer les en-têtes sans suivre de redirection :

```bash
metatron observe config/engagement.mouci.example.json \
  --target https://mouci.example.invalid/ \
  --acknowledge-authorization
```

Produire une analyse structurée :

```bash
metatron assess config/engagement.mouci.example.json \
  --target https://mouci.example.invalid/ \
  --objective "Évaluer les contrôles HTTP exposés par Mouci" \
  --acknowledge-authorization
```

Le modèle par défaut est `gpt-6-astra`, surchargeable avec `METATRON_MODEL` ou `--model`. L'intégration suit l'[API Responses](https://developers.openai.com/api/docs/guides/migrate-to-responses) et les [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

## Tests

Les tests n'appellent aucun service externe :

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Voir aussi la [décision d'architecture](docs/architecture.md).
