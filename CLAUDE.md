# exfildns — instructions pour les agents Claude

Projet ENSIBS CyberAI : application de machine learning qui détecte les requêtes DNS
servant à **exfiltrer des données** (DNS tunneling). Un humain (PabloHavane) et ses agents
Claude (elias-utf8 travaille désormais sur un autre projet). **L'humain n'écrit pas de code :
les agents codent, committent, poussent et ouvrent les PR.** Ce fichier est le contrat commun entre les agents.

## Principe directeur : KISS

Keep It Simple, Stupid. Avant d'ajouter quoi que ce soit, demande-toi si c'est nécessaire
pour l'issue en cours. Pas d'abstraction « pour plus tard », pas de framework en plus,
pas de configuration superflue. Un module = une responsabilité. Échéance : fin de semaine (27/11/2026).

## Langue

Tout en **français** : code commenté, docstrings, messages de commit, issues, PR, docs.
Les identifiants Python peuvent rester en anglais quand c'est l'usage (`train`, `predict`…).

## Stack et commandes

Python 3.12 (fixé par `.python-version`), gestion par **uv**.

- **TensorFlow / Keras** pour le modèle (choix de l'équipe, déjà pratiqué en TP) : un petit réseau
  dense (MLP). La normalisation se fait **dans le modèle** (couche `keras.layers.Normalization`
  adaptée sur le jeu d'entraînement uniquement), le modèle se sauvegarde en un seul fichier `.keras`.
- **scikit-learn** uniquement comme boîte à outils : découpage train/test, métriques, modèle de
  référence (régression logistique) pour comparaison.
- **pandas** pour les tableaux, **scapy** pour lire les PCAP et capturer en direct.
- **Jupyter** + **matplotlib** pour le notebook de méthodologie (groupe de dépendances `notebook`,
  hors application et hors CI).
- **Streamlit** pour le dashboard, **SQLite** (`sqlite3`, bibliothèque standard) entre la capture
  et le dashboard, **Docker** (compose) pour le déploiement.

```bash
uv sync                         # installer / mettre à jour l'environnement
uv run exfildns --help          # lancer l'application
uv run pytest                   # tests
uv run ruff check . --fix       # lint
uv run ruff format .            # formatage
uv add <paquet>                 # ajouter une dépendance (met à jour uv.lock, à committer)
uv sync --group notebook        # ajouter Jupyter et matplotlib
uv run --group notebook jupyter lab
```

La CI (`.github/workflows/ci.yml`) exécute lint + formatage + tests sur chaque PR.
**Une PR ne se merge que si la CI est verte.**

## Données

- Dataset : **CIC-Bell-DNS-EXF-2021** (UNB/CIC). Classes : bénin, attaque légère, attaque lourde ;
  6 types de fichiers exfiltrés ; 30 features (14 *stateless* calculées sur une seule requête,
  16 *stateful* calculées sur une fenêtre de 100 paquets). L'article de référence obtient ses
  meilleurs résultats avec une Random Forest.
- Citation obligatoire : Mahdavifar et al., *Lightweight Hybrid Detection of Data Exfiltration
  using DNS based on Machine Learning*, ICCNS 2021.
- Les fichiers vont dans `data/` (ignoré par git). Les modèles entraînés vont dans `models/`
  (ignoré). **Ne jamais committer de données, de PCAP ni de modèle.**
- Les tests utilisent de petites données synthétiques construites dans les tests, jamais le dataset.
- **Chaque nouvelle fonctionnalité arrive avec sa batterie de tests** (cas nominal, cas limites,
  erreurs), y compris le dashboard Streamlit (`streamlit.testing.v1.AppTest`).

## Architecture visée

```
src/exfildns/
  features.py   # features stateless calculées à partir d'un nom de domaine
  pcap.py       # lecture d'un PCAP -> requêtes DNS (scapy)
  dataset.py    # PCAP du dataset -> DataFrame étiqueté (capture, qname, label + features)
  model.py      # construction du MLP Keras, entraînement, évaluation, sauvegarde/chargement (.keras)
  evaluation.py # métriques, seuil, importance par permutation
  cli.py        # exfildns train | evaluate | scan | sniff | dashboard
  sniff.py      # capture DNS en direct -> scores -> base SQLite
  alertes.py    # agrégation des requêtes suspectes par domaine parent, liste blanche
  dashboard.py  # application Streamlit (lit la base SQLite, importe un PCAP)
notebooks/      # methodologie.ipynb : importe exfildns, livré exécuté avec ses sorties
tests/          # un fichier de test par module
Dockerfile, compose.yaml   # déploiement : service sniff (NET_RAW, réseau hôte) + dashboard
```

Le notebook **importe** le paquet au lieu de recopier du code. La capture en direct et l'analyse
d'un fichier PCAP partagent le même décodage de paquet.

Règle clé : **la même fonction de calcul des features sert à l'entraînement et à l'inférence**,
sinon le modèle verra en production des données différentes de celles d'entraînement.

## Explicabilité

Il faut pouvoir expliquer l'algorithme à l'oral. Un réseau de neurones est moins lisible
qu'un arbre, donc : garder le MLP **petit** (2 couches cachées suffisent), le comparer à une
régression logistique de référence, mesurer l'importance des features par **permutation**,
documenter chaque choix dans `docs/` et justifier la métrique retenue.
Fixer les graines aléatoires (`keras.utils.set_random_seed`) pour des résultats reproductibles.

## Workflow git : GitLab Flow

- `main` : branche d'intégration, **protégée** (merge uniquement par PR avec CI verte).
- `production` : version livrée, **protégée**. Seule `main` peut y être mergée (check CI
  `source-production`), par PR en **merge** ou **rebase**, jamais en squash (skill `livrer-production`).
- Titre d'issue préfixé par son numéro : `[#9] Extraire les requêtes DNS d'un fichier PCAP`.
  Le numéro n'est connu qu'après création : créer l'issue, puis
  `gh issue edit <n°> --title "[#<n°>] <titre>"`.
- Une branche par issue, créée depuis `main` à jour :
  `feat/<n°>-<description>`, `fix/<n°>-…`, `docs/<n°>-…`, `test/<n°>-…`, `chore/<n°>-…`, `refactor/<n°>-…`
  (en kebab-case, ex. `feat/4-features-stateless`).
- Commits **Conventional Commits** en français : `feat(features): ajoute le calcul de l'entropie`.
  Types : `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `perf`, `style`.
- **Petits commits** : un commit = un changement cohérent qui passe les tests (ex. la fonction,
  puis ses tests, puis son branchement dans la CLI). Cela permet de revenir en arrière finement
  pendant le travail sur la branche.
- PR vers `main` avec `Closes #<n°>`, mergée en **squash** (`gh pr merge --squash`) : une PR = un
  commit sur `main`. Le **titre de la PR devient le message du commit**, il doit donc suivre les
  Conventional Commits. Les autres méthodes sont refusées par GitHub sur `main`.
- **Branche supprimée après chaque PR** (automatique sur GitHub + `--delete-branch` en local).
- Pas de relecture humaine obligatoire : l'agent `relecteur` sert de relecteur avant le merge.
  Toute PR qui touche au Dockerfile, au compose ou à la CI Docker passe **aussi** par l'agent
  `relecteur-docker`.

Pour traiter une issue de bout en bout, utilise le skill **`traiter-issue`**.

## Coordination entre agents

- Avant de commencer une issue : vérifier qu'elle n'est **assignée à personne**, puis se l'assigner
  (`gh issue edit <n°> --add-assignee @me`). Une issue assignée à quelqu'un d'autre n'est pas à toi.
- Toujours partir d'un `main` à jour (`git pull --rebase`) et garder les PR petites pour éviter
  les conflits.
- Toute décision structurante (choix de features, de modèle, de métrique) est consignée dans
  `docs/decisions.md` (date, décision, justification en 2-3 lignes).

## Sécurité

Ne jamais écrire de secret, de token ni de donnée personnelle dans le dépôt, les issues ou les PR.
