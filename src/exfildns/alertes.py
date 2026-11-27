"""Alertes : requêtes suspectes regroupées par domaine parent.

Un tunnel DNS envoie beaucoup de requêtes vers **un même domaine** (celui de l'attaquant), alors
qu'un faux positif isolé (nom long d'un CDN…) reste rare. On ne lève donc une alerte que si un
domaine parent reçoit au moins `MIN_REQUETES` requêtes suspectes, et jamais pour un domaine de la
liste blanche (docs/decisions.md).
"""

from collections.abc import Iterable
from pathlib import Path

import pandas as pd

from exfildns import SEUIL

MIN_REQUETES = 5
NOM_INCOMPLET = "(nom incomplet dans la capture)"

# Services légitimes connus pour leurs noms longs et aléatoires (CDN, cloud, télémétrie).
LISTE_BLANCHE = (
    "akamaiedge.net",
    "akamaized.net",
    "amazonaws.com",
    "azureedge.net",
    "cloudfront.net",
    "fastly.net",
    "googlevideo.com",
    "1e100.net",
)

COLONNES_ALERTES = [
    "domaine",
    "requetes_suspectes",
    "score_moyen",
    "score_max",
    "sources",
    "postes",  # adresses des postes, séparées par des virgules
    "debut",
    "fin",
]


def domaine_parent(qname: str, tronque: bool = False) -> str:
    """Deux derniers labels du nom (`exemple.com`), ou un marqueur si le nom est coupé."""
    if tronque:
        return NOM_INCOMPLET
    # rsplit limité : ne découpe que la fin du nom (les noms de tunnel sont longs)
    return ".".join(qname.rstrip(".").rsplit(".", 2)[-2:]) or "(racine)"


def lire_liste_blanche(chemin: str | Path) -> list[str]:
    """Un domaine par ligne ; lignes vides et commentaires (`#`) ignorés."""
    lignes = (ligne.strip().lower() for ligne in Path(chemin).read_text("utf-8").splitlines())
    return [ligne for ligne in lignes if ligne and not ligne.startswith("#")]


def est_autorise(qname: str, liste_blanche: Iterable[str]) -> bool:
    """Vrai si le nom est un domaine de la liste blanche ou l'un de ses sous-domaines."""
    nom = qname.rstrip(".").lower()
    domaines = (d.rstrip(".").lower() for d in liste_blanche)
    return any(nom == d or nom.endswith("." + d) for d in domaines)


def domaines_parents(requetes: pd.DataFrame) -> pd.Series:
    """`domaine_parent` de chaque requête. Un `qtype` manquant signale un nom coupé, testé
    d'un bloc (un `pd.isna` par requête coûte cher sur des dizaines de milliers de requêtes).

    Si `requetes` a déjà une colonne `domaine` (calculée ici), elle est réutilisée : le dashboard
    la calcule une fois par rafraîchissement au lieu d'une fois par vue.
    """
    if "domaine" in requetes:
        return requetes["domaine"]
    noms = pd.Series([domaine_parent(q) for q in requetes["qname"]], index=requetes.index)
    return noms.where(requetes["qtype"].notna(), NOM_INCOMPLET)


def autorises(qnames: pd.Series, liste_blanche: Iterable[str]) -> pd.Series:
    """`est_autorise` de chaque nom, calculé d'un bloc (pandas) : une passe par domaine de la
    liste blanche au lieu d'une boucle Python par requête."""
    noms = qnames.astype(str).str.rstrip(".").str.lower()
    masque = pd.Series(False, index=qnames.index)
    for domaine in {d.rstrip(".").lower() for d in liste_blanche}:
        masque |= (noms == domaine) | noms.str.endswith("." + domaine)
    return masque


def alertes(
    requetes: pd.DataFrame,
    seuil: float = SEUIL,
    min_requetes: int = MIN_REQUETES,
    liste_blanche: Iterable[str] = LISTE_BLANCHE,
) -> pd.DataFrame:
    """Domaines parents ayant reçu au moins `min_requetes` requêtes suspectes.

    `requetes` a les colonnes `timestamp, src, qname, qtype, score` (sortie de `exfildns sniff`
    ou de `scan`) ; un `qtype` manquant signale un nom coupé dans la capture. La fonction compte
    sur tout le tableau reçu : c'est l'appelant qui choisit la période (le dashboard filtre la
    base par date). Renvoie une ligne par alerte (colonnes `COLONNES_ALERTES`), de la plus
    fournie à la moins fournie.
    """
    liste_blanche = list(liste_blanche)
    suspectes = requetes[requetes["score"] >= seuil]
    suspectes = suspectes[~autorises(suspectes["qname"], liste_blanche)]
    if suspectes.empty:
        return pd.DataFrame(columns=COLONNES_ALERTES)
    groupes = suspectes.assign(domaine=domaines_parents(suspectes)).groupby("domaine")
    resume = pd.DataFrame(
        {
            "requetes_suspectes": groupes.size(),
            "score_moyen": groupes["score"].mean(),
            "score_max": groupes["score"].max(),
            "sources": groupes["src"].nunique(),
            "postes": groupes["src"].agg(lambda s: ", ".join(sorted(s.unique()))),
            "debut": groupes["timestamp"].min(),
            "fin": groupes["timestamp"].max(),
        }
    )
    resume = resume[resume["requetes_suspectes"] >= min_requetes]
    resume = resume.reset_index().sort_values(
        ["requetes_suspectes", "domaine"], ascending=[False, True], ignore_index=True
    )
    return resume[COLONNES_ALERTES]
