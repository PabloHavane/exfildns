# exfildns

Application de machine learning qui détecte les requêtes DNS servant à **exfiltrer des données**
(DNS tunneling). Elle lit une capture réseau, attribue à chaque requête DNS une probabilité
d'exfiltration avec un réseau de neurones TensorFlow, et liste les requêtes suspectes.

Projet ENSIBS — module IA pour la cybersécurité. Entraîné sur le dataset CIC-Bell-DNS-EXF-2021.

## Installation

Prérequis : Python 3.12 (installé automatiquement par uv) et [uv](https://docs.astral.sh/uv/).

```bash
pip install uv          # si uv n'est pas installé
git clone https://github.com/PabloHavane/exfildns.git
cd exfildns
uv sync                 # crée l'environnement et installe les dépendances
uv run exfildns --help
```

## Données

1. Télécharger [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html)
   (formulaire du CIC), partie **PCAP heavy**.
2. Placer les captures ainsi (le dossier `data/` n'est pas versionné) :

```
data/
  Attacks/  heavy_audio.pcap  heavy_compressed.pcap  heavy_exe.pcap
            heavy_image.pcap  heavy_text.pcap        heavy_video.pcap
  Benign/   benign_heavy_1.pcap  benign_heavy_2.pcap  benign_heavy_3.pcap
```

> Mahdavifar, S., et al. *Lightweight Hybrid Detection of Data Exfiltration using DNS based on
> Machine Learning*. ICCNS 2021.

## Utilisation

### Entraîner

```bash
uv run exfildns train          # data/ → models/exfildns.keras
```

```
Entraînement sur 220037 requêtes, test sur 70159.
Arrêt après 13 époques.
Modèle sauvegardé : models/exfildns.keras
Résultats sur le jeu de test :
  rappel (exfiltrations détectées) : 1.0000
  taux de faux positifs            : 0.000039
  ...
```

Le premier lancement lit les PCAP (~1 min 30) et garde les requêtes dans `data/requetes.csv` ;
les suivants prennent une dizaine de secondes. Supprimer ce fichier pour relire les PCAP.

Options : `-o` fichier du modèle, `--epochs` nombre maximal d'époques, `--captures-test`
captures mises de côté pour le test (par défaut `heavy_video benign_heavy_3`).

### Évaluer un modèle sauvegardé

```bash
uv run exfildns evaluate       # métriques de models/exfildns.keras sur le jeu de test
```

`train` et `evaluate` prennent en argument le dossier de données (`data` par défaut) ;
`evaluate` accepte `-m` pour choisir le modèle.

### Analyser une capture

```bash
uv run exfildns scan capture.pcap [--seuil 0.5] [--max 20] [-m models/exfildns.keras]
```

```
42081 requêtes DNS analysées, 41987 suspectes (seuil 0.5).

Serveurs DNS destinataires des requêtes suspectes :
  192.168.20.72                            41987

Domaines parents les plus touchés :
  (nom incomplet dans la capture)          41987

Requêtes suspectes (3 plus probables) :
  1.000  192.168.20.38 -> 192.168.20.72  18038.E_yl9iUnLNtXYEU7YNi-AOL_Q_0gRze-oSx
  ...
```

Code de sortie : **0** si rien n'est suspect, **1** si au moins une requête est suspecte,
**2** si le modèle est introuvable (une autre erreur, comme une capture introuvable, renvoie
aussi 1 avec un message d'erreur). Dans un script :

```bash
uv run exfildns scan capture.pcap > rapport.txt
[ $? -eq 1 ] && grep -q suspectes rapport.txt && echo "Exfiltration suspectée"
```

## Notebook de méthodologie

[notebooks/methodologie.ipynb](notebooks/methodologie.ipynb) déroule la démarche d'apprentissage
(données, features, découpage, modèles, métriques, explicabilité). Il est livré **exécuté** : il se
lit directement sur GitHub. Pour le relancer (dataset dans `data/`) :

```bash
uv sync --group notebook
uv run --group notebook jupyter lab notebooks/methodologie.ipynb   # puis « Run All »
```

Il réentraîne le réseau et réécrit `models/exfildns.keras`, le même modèle que `exfildns train`.

## Documentation

| Document | Contenu |
|---|---|
| [docs/algorithme.md](docs/algorithme.md) | Fonctionnement de bout en bout, à lire pour la soutenance |
| [docs/evaluation.md](docs/evaluation.md) | Protocole, métriques, résultats, importance des features, limites |
| [docs/donnees.md](docs/donnees.md) | Analyse du dataset et pièges rencontrés |
| [docs/decisions.md](docs/decisions.md) | Journal des décisions et de leurs justifications |

## Développement

```bash
uv run pytest                                      # ~15 s
uv run ruff check . && uv run ruff format --check .
```

Code dans `src/exfildns/` : `pcap.py` (lecture des captures), `features.py` (features d'un nom
de domaine), `dataset.py` (jeu étiqueté), `model.py` (modèles), `evaluation.py` (métriques et
explication), `cli.py` (commandes). Conventions (GitLab Flow, commits, branches) :
[CLAUDE.md](CLAUDE.md).

## Licence

Apache 2.0
