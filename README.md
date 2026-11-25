# PhishLens

[![tests](https://github.com/sssouheibsid/phishlens/actions/workflows/tests.yml/badge.svg)](https://github.com/sssouheibsid/phishlens/actions/workflows/tests.yml)
![python](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.13-blue)
[![licence](https://img.shields.io/badge/licence-MIT-green)](LICENSE)

**PhishLens** est un outil en ligne de commande destiné aux analystes SOC. Il analyse un e-mail
suspect au format `.eml` et rend un verdict **sain / suspect / malveillant** accompagné d'un
score sur 100, d'un rapport HTML autonome et d'un export JSON.

- 100 % hors ligne : aucune clé API, aucune requête réseau.
- Uniquement la bibliothèque standard Python (pytest seulement pour le développement).
- Code de sortie exploitable dans un pipeline SOAR ou un script de tri.

## Contrôles réalisés

| Catégorie | Contrôle | Points |
|---|---|---|
| Authentification | SPF en échec (`fail` / `permerror`) | +15 |
| Authentification | SPF `softfail` | +8 |
| Authentification | DKIM invalide | +10 |
| Authentification | DMARC en échec | +15 |
| Expéditeur | `Reply-To` vers un autre domaine que `From` | +10 |
| Expéditeur | `Return-Path` d'un autre domaine que `From` | +5 |
| Expéditeur | Adresse usurpée dans le nom affiché (`"service@paypal.com" <x@evil.com>`) | +15 |
| Typosquatting | Domaine imitant une marque (homoglyphes `0→o`, `1→l`, `rn→m`…, Levenshtein = 1, marque dans un domaine non officiel) | +25 |
| Liens | Texte affiché pointant vers un autre domaine que le `href` | +20 |
| Liens | URL vers une adresse IP brute | +10 |
| Pièces jointes | Extension dangereuse (`.exe .js .vbs .iso .lnk .docm .hta .ps1`…) | +30 |
| Pièces jointes | Double extension (`facture.pdf.exe`) | +15 |
| Contenu | Vocabulaire d'urgence (au moins deux expressions) | +10 |

Le score est plafonné à 100. **≥ 60 : malveillant**, **≥ 25 : suspect**, sinon **sain**.

IOC extraits : URLs, domaines, IPs publiques (corps et en-têtes `Received`), SHA-256 des pièces jointes.
SPF/DKIM/DMARC sont lus dans `Authentication-Results` (repli sur `Received-SPF` pour SPF).

Marques surveillées : PayPal, Microsoft / Office 365, Amazon, Netflix, Apple, Google, Ameli,
impots.gouv, La Poste, Colissimo, Chronopost, DocuSign et les principales banques françaises
(Crédit Agricole, Société Générale, BNP Paribas, Caisse d'Épargne, Crédit Mutuel, La Banque
Postale, Banque Populaire, Boursorama). Les domaines officiels et leurs sous-domaines ne sont
jamais signalés.

## Installation

```bash
git clone https://github.com/sssouheibsid/phishlens.git
cd phishlens
python -m pip install .
```

Pour le développement :

```bash
python -m pip install -e ".[dev]"
```

## Utilisation

```text
phishlens analyze FICHIER.eml [FICHIER.eml ...] [-o DOSSIER] [-f html|json|both] [-q]
```

| Option | Rôle | Défaut |
|---|---|---|
| `-o`, `--output` | dossier des rapports | `reports` |
| `-f`, `--format` | `html`, `json` ou `both` | `both` |
| `-q`, `--quiet` | une ligne par fichier | désactivé |

Codes de sortie : `0` sain, `1` suspect, `2` malveillant (pire verdict si plusieurs fichiers), `3` erreur.

### Exemple

```text
$ phishlens analyze samples/facture_phishing.eml
PhishLens v0.1.0 - samples/facture_phishing.eml
  Sujet    : Action requise : votre compte PayPal sera suspendu
  De       : "service@paypal.com" <service@paypa1-secure.com>
  Auth     : SPF=fail  DKIM=none  DMARC=fail
  Verdict  : MALVEILLANT (100/100)
  Signaux  :
    +15  SPF en échec  résultat : fail
    +15  DMARC en échec  résultat : fail
    +10  Reply-To vers un autre domaine  mail-securise.ru ≠ paypa1-secure.com
    +15  Adresse usurpée dans le nom affiché  service@paypal.com affiché, envoyé depuis paypa1-secure.com
    +25  Domaine imitant une marque  paypa1-secure.com imite paypal (homoglyphe)
    +20  Lien trompeur (texte ≠ destination)  « www.paypal.com » -> 185.234.72.19
    +30  Pièce jointe dangereuse  facture.pdf.exe
    +15  Double extension de fichier  facture.pdf.exe
    +10  URL pointant vers une adresse IP brute  http://185.234.72.19/paypal/login.php
    +10  Vocabulaire d'urgence  immediatement, sous 24 heures, action requise, sera suspendu, verifiez votre compte, activite inhabituelle, facture impayee
  IOC      : 2 URL(s), 1 domaine(s), 1 IP(s), 1 pièce(s) jointe(s)
             facture.pdf.exe  sha256=1b4b38fb7f8883b823b608cfe4536839358ddaf8d870b68eee1d263c51475023
  Rapports : reports/facture_phishing.json, reports/facture_phishing.html
```

```text
$ phishlens analyze samples/*.eml -q
MALVEILLANT (100/100)  samples/facture_phishing.eml
SAIN (0/100)  samples/newsletter_legit.eml
```

Un exemple de rapport HTML est disponible dans [`docs/rapport.html`](docs/rapport.html).

Utilisation depuis Python :

```python
from phishlens import analyze

result = analyze("samples/facture_phishing.eml")
print(result["verdict"], result["score"])
```

## Docker

```bash
docker build -t phishlens .
docker run --rm -v "$PWD:/data" phishlens analyze samples/facture_phishing.eml -o reports
```

L'image est basée sur `python:3.12-slim` et s'exécute avec un utilisateur non root (`analyst`).

## Structure

```text
phishlens/
  __init__.py     # analyze(path) : enchaîne toutes les étapes et renvoie un dict
  __main__.py     # python -m phishlens
  parser.py       # lecture du .eml (en-têtes, corps texte/HTML, pièces jointes + SHA-256)
  domains.py      # utilitaires de domaines (domaine enregistré, IP, comparaison)
  auth.py         # SPF, DKIM, DMARC, Reply-To / Return-Path, nom affiché usurpé
  ioc.py          # URLs, domaines, IPs, liens trompeurs, extensions dangereuses
  typosquat.py    # imitation de marques (homoglyphes, Levenshtein)
  scoring.py      # pondération des signaux, score et verdict
  report.py       # rapports JSON et HTML autonome
  cli.py          # interface en ligne de commande
samples/          # un e-mail de phishing fictif et une newsletter légitime
tests/            # tests pytest
docs/             # exemple de rapport HTML
```

## Tests

```bash
python -m pip install -e ".[dev]"
pytest -v
```

La CI GitHub Actions exécute les tests sur Python 3.10, 3.12 et 3.13.

## Feuille de route

- **V2 – enrichissement en ligne** : VirusTotal (hash, URLs), AbuseIPDB (IPs), URLhaus, WHOIS
  (âge des domaines).
- **V3 – intégration** : export MISP et STIX 2.1, interface web Flask pour le dépôt d'e-mails.

## Avertissement : données personnelles

Les e-mails analysés et les rapports générés contiennent des données personnelles (adresses,
noms, contenu des messages). Traitez-les conformément au RGPD et à la politique de votre
organisation : ne les versionnez pas (le dossier `reports/` est ignoré par git), limitez leur
conservation et ne les transmettez pas à des services tiers sans autorisation. Les échantillons
fournis dans `samples/` sont entièrement fictifs.

PhishLens est une aide au tri : son verdict ne remplace pas l'analyse d'un analyste.

## Licence

[MIT](LICENSE) © Souheib SID
