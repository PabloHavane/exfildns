---
name: traiter-issue
description: Traite une issue GitHub de bout en bout selon le GitLab Flow du projet - s'assigner l'issue, créer la branche, implémenter avec des tests, vérifier lint et tests, committer, pousser, ouvrir la PR, attendre la CI puis merger. À utiliser quand on demande de "prendre", "faire" ou "traiter" une issue, ou de passer à l'issue suivante.
---

# Traiter une issue

Argument : le numéro de l'issue. Sans numéro, prendre la première issue ouverte, **non assignée**,
du milestone ouvert le plus ancien (`gh issue list --milestone "<titre>" --search "no:assignee"`).

## 1. Préparer

```bash
gh issue view <n°>                       # lire l'issue et ses critères d'acceptation
gh issue edit <n°> --add-assignee @me    # la réserver (si elle est assignée à l'autre : STOP, en choisir une autre)
git switch main && git pull --rebase
git switch -c <type>/<n°>-<description-courte>
```

`<type>` suit le label ou la nature de l'issue : `feat`, `fix`, `docs`, `test`, `chore`, `refactor`.

## 2. Implémenter (KISS)

- Faire **uniquement** ce que demande l'issue. Une idée en plus = une nouvelle issue (`gh issue create`).
- Écrire ou compléter les tests dans `tests/test_<module>.py`, avec des données synthétiques minuscules.
- Respecter `CLAUDE.md` : français, même fonction de features à l'entraînement et à l'inférence,
  aucune donnée ni modèle commité.

## 3. Vérifier en local (obligatoire avant de pousser)

```bash
uv run ruff check . --fix && uv run ruff format . && uv run pytest -q
```

Tout doit passer. Si une dépendance a été ajoutée, `uv.lock` fait partie du commit.

## 4. Relire

Lancer l'agent `relecteur` sur le diff (`git diff main...HEAD`) et corriger ce qu'il remonte
de bloquant.

## 5. Committer, pousser, ouvrir la PR

Committer **au fil de l'eau, par petits pas** (pas un seul gros commit à la fin) : chaque commit
contient un changement cohérent et laisse les tests verts.

```bash
git add <fichiers concernés>
git commit -m "<type>(<portée>): <description en français>"   # Conventional Commits
# ... répéter pour chaque étape ...
git push -u origin HEAD
gh pr create --base main --title "<type>(<portée>): <description>" --body "<résumé>

Closes #<n°>"
```

## 6. Merger

```bash
gh pr checks --watch            # attendre la CI
gh pr merge --squash --delete-branch   # squash obligatoire vers main ; supprime la branche
git switch main && git pull --rebase
```

Si la CI échoue : corriger sur la même branche, pousser, recommencer l'étape 6.
En cas de conflit avec `main` : `git merge origin/main` sur la branche, résoudre, relancer les
tests, committer et pousser normalement (le squash final efface ce commit de merge de
l'historique de `main`). **Jamais de push forcé** : il est interdit par `.claude/settings.json`.

Terminer par un résumé de 2-3 lignes à l'humain : ce qui a été fait, le lien de la PR, la suite logique.
