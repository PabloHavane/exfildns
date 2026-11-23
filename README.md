# exfildns

Application de machine learning qui détecte les requêtes DNS servant à **exfiltrer des données**
(DNS tunneling), entraînée sur le dataset CIC-Bell-DNS-EXF-2021.

## Installation

```bash
pip install uv      # si uv n'est pas installé
uv sync
uv run exfildns --help
```

## Données

Télécharger [CIC-Bell-DNS-EXF-2021](https://www.unb.ca/cic/datasets/dns-exf-2021.html) et
le placer dans `data/` (non versionné).

> Mahdavifar, S., et al. *Lightweight Hybrid Detection of Data Exfiltration using DNS based on
> Machine Learning*. ICCNS 2021.

## Développement

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

Conventions (GitLab Flow, commits, branches) : voir [CLAUDE.md](CLAUDE.md).

## Licence

Apache 2.0
