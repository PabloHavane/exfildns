---
name: livrer-production
description: Promeut main vers la branche production selon le GitLab Flow (PR main -> production, CI verte, merge, tag de version). À utiliser quand on demande de "livrer", "déployer", "passer en production" ou "faire une release".
---

# Livrer en production

1. Vérifier que `main` est saine :
   ```bash
   git switch main && git pull --rebase
   uv sync && uv run ruff check . && uv run pytest -q
   ```
2. Ouvrir la PR de promotion (merge commit classique, pour garder l'historique) :
   ```bash
   gh pr create --base production --head main --title "release: vX.Y.Z" --body "<changements depuis la dernière livraison>"
   gh pr checks --watch
   gh pr merge --merge
   ```
3. Taguer la version livrée sur `production` :
   ```bash
   git fetch origin && git switch production && git pull
   git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z
   git switch main
   ```
4. Mettre à jour `version` dans `pyproject.toml` et `src/exfildns/__init__.py` pour la version
   suivante via une PR `chore/…` classique.

Numérotation : `0.MINEUR.CORRECTIF` jusqu'au rendu final ; le rendu final est `v1.0.0`.
On ne commite jamais directement sur `production`.
