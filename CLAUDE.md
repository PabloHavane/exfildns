# exfildns — instructions pour les agents Claude

Projet ENSIBS CyberAI : application de machine learning qui détecte les requêtes DNS
servant à **exfiltrer des données** (DNS tunneling). Deux humains (PabloHavane et elias-utf8),
chacun avec ses agents Claude. **Les humains n'écrivent pas de code : les agents codent,
committent, poussent et ouvrent les PR.** Ce fichier est le contrat commun entre les agents.

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
- **pandas** pour les tableaux, **scapy** pour lire les PCAP.

```bash
uv sync                         # installer / mettre à jour l'environnement
uv run exfildns --help          # lancer l'application
uv run pytest                   # tests
uv run ruff check . --fix       # lint
uv run ruff format .            # formatage
uv add <paquet>                 # ajouter une dépendance (met à jour uv.lock, à committer)
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

## Architecture visée

```
src/exfildns/
  features.py   # features stateless calculées à partir d'un nom de domaine
  pcap.py       # lecture d'un PCAP -> requêtes DNS (scapy)
  dataset.py    # chargement du dataset -> X, y
  model.py      # construction du MLP Keras, entraînement, évaluation, sauvegarde/chargement (.keras)
  cli.py        # exfildns train | evaluate | scan
tests/          # un fichier de test par module
```

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

Pour traiter une issue de bout en bout, utilise le skill **`traiter-issue`**.

## Coordination entre les deux équipes d'agents

- Avant de commencer une issue : vérifier qu'elle n'est **assignée à personne**, puis se l'assigner
  (`gh issue edit <n°> --add-assignee @me`). Une issue assignée à l'autre n'est pas à toi.
- Toujours partir d'un `main` à jour (`git pull --rebase`) et garder les PR petites pour éviter
  les conflits.
- Toute décision structurante (choix de features, de modèle, de métrique) est consignée dans
  `docs/decisions.md` (date, décision, justification en 2-3 lignes).

## Sécurité

Ne jamais écrire de secret, de token ni de donnée personnelle dans le dépôt, les issues ou les PR.
