---
id: metatron.source.upstream
kind: source
status: active
last_reviewed: 2026-09-10
sensitivity: public
sources:
  - https://github.com/sooryathejas/METATRON
  - https://github.com/sooryathejas/METATRON/tree/9dd2ee3daa33397453c76e9fcba446f117d22cb6
---

# Projet amont sooryathejas/METATRON

## Version étudiée

- dépôt : `https://github.com/sooryathejas/METATRON` ;
- branche : `main` ;
- commit : `9dd2ee3daa33397453c76e9fcba446f117d22cb6` ;
- arbre Git : `97a096dca555cfaf11e1e9ba454083b31cf599d4` ;
- licence : MIT ;
- aucune release publiée au moment de la revue du 10 septembre 2026.

## Fonctionnement observé

L'amont est une CLI Python locale pour Parrot OS. Il s'appuie sur Ollama et un modèle Qwen, MariaDB, DuckDuckGo et les binaires `nmap`, `whois`, `whatweb`, `curl`, `dig` et `nikto`. Le modèle produit des balises textuelles `[TOOL: ...]` et `[SEARCH: ...]` qui sont interprétées dans une boucle allant jusqu'à neuf appels.

Des améliorations récentes ajoutent une allowlist d'outils et des consignes de preuve. Elles n'attachent toutefois pas les arguments produits par le modèle à la cible autorisée. Le code archivé contient aussi un mot de passe MariaDB d'exemple en dur et suit les redirections de `curl` avec validation TLS désactivée.

## Risques publics pris en compte

- [#32](https://github.com/sooryathejas/METATRON/issues/32) : arguments d'outils non liés à la cible ;
- [#33](https://github.com/sooryathejas/METATRON/issues/33) : redirection `curl` vers localhost ou un service de métadonnées ;
- [#36](https://github.com/sooryathejas/METATRON/issues/36) : pivot vers d'autres hôtes et CVE supposées ;
- [#5](https://github.com/sooryathejas/METATRON/issues/5), [#14](https://github.com/sooryathejas/METATRON/issues/14) : exécution induite par prompt injection ;
- [#16](https://github.com/sooryathejas/METATRON/issues/16) : SSRF dans la récupération de pages ;
- [#19](https://github.com/sooryathejas/METATRON/issues/19), [#20](https://github.com/sooryathejas/METATRON/issues/20) : boucle/parser et faux positifs.

Ces éléments sont des faits et signalements amont, pas une affirmation que chaque issue reste ouverte ou reproductible sur toute version future. La décision locale correspondante est `../decisions/0002-deterministic-control-plane.md`.
