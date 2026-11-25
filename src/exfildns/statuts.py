"""Statut des alertes (nouvelle / en cours / faux positif / close), choisi par l'analyste.

Les alertes ne sont pas stockées : elles sont recalculées par domaine parent (`alertes.alertes`).
Le statut s'accroche donc au **domaine parent**. Il vit dans une base SQLite à part
(`statuts.db`), écrite par le dashboard seul : la base des détections reste en lecture seule pour
lui (docs/decisions.md).
"""

import sqlite3
import time
from contextlib import closing
from pathlib import Path

import numpy as np
import pandas as pd

# statut -> libellé affiché
STATUTS = {
    "nouvelle": "nouvelle",
    "en_cours": "en cours",
    "faux_positif": "faux positif",
    "close": "close",
}
OUVERTS = ("nouvelle", "en_cours")  # statuts comptés dans « Alertes ouvertes »

SCHEMA = """
CREATE TABLE IF NOT EXISTS statuts_alertes (
    domaine TEXT PRIMARY KEY,
    statut TEXT NOT NULL CHECK (statut IN ('nouvelle', 'en_cours', 'faux_positif', 'close')),
    commentaire TEXT,
    modifie_le REAL NOT NULL
);
"""
COLONNES = ["domaine", "statut", "commentaire", "modifie_le"]


def lire(chemin: str | Path) -> pd.DataFrame:
    """Statuts enregistrés (colonnes `COLONNES`) ; tableau vide si la base n'existe pas encore."""
    if not Path(chemin).exists():
        return pd.DataFrame(columns=COLONNES)
    with closing(sqlite3.connect(chemin)) as connexion:
        return pd.read_sql_query(f"SELECT {', '.join(COLONNES)} FROM statuts_alertes", connexion)


def enregistrer(
    chemin: str | Path,
    domaine: str,
    statut: str,
    commentaire: str = "",
    maintenant: float | None = None,
) -> None:
    """Donne `statut` à l'alerte du domaine parent `domaine` (crée la base si besoin)."""
    if statut not in STATUTS:
        raise ValueError(f"statut inconnu : {statut!r} (attendu : {', '.join(STATUTS)})")
    Path(chemin).parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(chemin)) as connexion, connexion:
        connexion.executescript(SCHEMA)
        connexion.execute(
            "INSERT OR REPLACE INTO statuts_alertes VALUES (?, ?, ?, ?)",
            (domaine, statut, commentaire.strip() or None, maintenant or time.time()),
        )


def appliquer(resume: pd.DataFrame, statuts: pd.DataFrame) -> pd.DataFrame:
    """Ajoute à chaque alerte (sortie de `alertes.alertes`) ses colonnes `statut, commentaire`.

    Sans ligne enregistrée, une alerte est « nouvelle ». Une alerte « close » qui a reçu de
    nouvelles requêtes suspectes après sa clôture (`fin` > `modifie_le`) redevient « nouvelle ».
    """
    connus = statuts.set_index("domaine")
    statut = resume["domaine"].map(connus["statut"]).astype(object).fillna("nouvelle")
    # astype(float) : colonnes sans type quand il n'y a aucune alerte ou aucun statut
    clos_le = resume["domaine"].map(connus["modifie_le"]).astype(float)
    rouverte = (statut == "close") & (resume["fin"].astype(float) > clos_le)
    return resume.assign(
        statut=statut.mask(rouverte, "nouvelle"),
        # None plutôt que NaN : un NaN s'afficherait « nan » dans le champ commentaire
        commentaire=resume["domaine"]
        .map(connus["commentaire"])
        .astype(object)
        .replace({np.nan: None}),
    )


def ouvertes(resume: pd.DataFrame) -> pd.DataFrame:
    """Alertes encore à traiter : nouvelles et en cours (sortie de `appliquer`)."""
    return resume[resume["statut"].isin(OUVERTS)]
