"""Liste blanche modifiable depuis le dashboard : domaines ajoutés par l'analyste.

Ils complètent la liste par défaut (`alertes.LISTE_BLANCHE`, CDN connus), qui reste toujours
appliquée. Comme les statuts d'alertes, ils vivent dans la base écrite par le dashboard seul
(`statuts.db`, table `liste_blanche`) : la base des détections reste en lecture seule pour lui.
"""

import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path

from exfildns.alertes import LISTE_BLANCHE

SCHEMA = """
CREATE TABLE IF NOT EXISTS liste_blanche (
    domaine TEXT PRIMARY KEY,  -- en minuscules, sans point final
    ajoute_le REAL NOT NULL
);
"""

# Labels de lettres, chiffres, tirets ou soulignés, séparés par des points (au moins deux labels)
FORME_DOMAINE = re.compile(r"[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})+")


def normaliser(domaine: str) -> str:
    """Domaine en minuscules sans espaces ni point final ; `ValueError` s'il est mal formé."""
    nom = domaine.strip().rstrip(".").lower()
    if len(nom) > 253 or not FORME_DOMAINE.fullmatch(nom):
        raise ValueError(f"domaine invalide : {domaine!r} (exemple attendu : exemple.com)")
    return nom


def lire(chemin: str | Path) -> list[str]:
    """Domaines ajoutés, par ordre alphabétique ; liste vide si la base n'existe pas encore."""
    if not Path(chemin).exists():
        return []
    with closing(sqlite3.connect(chemin)) as connexion:
        table = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'liste_blanche'"
        if connexion.execute(table).fetchone() is None:  # base des statuts sans liste blanche
            return []
        lignes = connexion.execute("SELECT domaine FROM liste_blanche ORDER BY domaine")
        return [domaine for (domaine,) in lignes]


def ajouter(chemin: str | Path, domaine: str, maintenant: float | None = None) -> str:
    """Ajoute `domaine` (normalisé, renvoyé) à la liste ; sans effet s'il y est déjà."""
    nom = normaliser(domaine)
    Path(chemin).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(chemin)) as connexion, connexion:
        connexion.executescript(SCHEMA)
        connexion.execute(
            "INSERT OR IGNORE INTO liste_blanche VALUES (?, ?)",
            (nom, time.time() if maintenant is None else maintenant),
        )
    return nom


def retirer(chemin: str | Path, domaine: str) -> None:
    """Retire `domaine` des domaines ajoutés (la liste par défaut, elle, ne change pas)."""
    if not Path(chemin).exists():
        return
    with closing(sqlite3.connect(chemin)) as connexion, connexion:
        connexion.executescript(SCHEMA)
        connexion.execute("DELETE FROM liste_blanche WHERE domaine = ?", (domaine,))


def complete(chemin: str | Path) -> list[str]:
    """Liste appliquée aux alertes : liste par défaut puis domaines ajoutés."""
    return [*LISTE_BLANCHE, *lire(chemin)]
