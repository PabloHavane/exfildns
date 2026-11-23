"""Construction du jeu de données étiqueté à partir des PCAP du dataset.

Arborescence attendue (docs/donnees.md) :
    <dossier>/Attacks/*.pcap   captures pendant une exfiltration
    <dossier>/Benign/*.pcap    captures de trafic normal

Étiquettes (docs/decisions.md) :
    1 : requête d'une capture d'attaque envoyée au serveur DNS de l'attaquant ;
    0 : toute autre requête (captures bénignes et trafic de fond des captures d'attaque).
"""

from pathlib import Path

import pandas as pd

from exfildns.features import FEATURES, features_dataframe
from exfildns.pcap import read_dns_queries

IP_ATTAQUANT = "192.168.20.72"
NOM_CACHE = "requetes.csv"
COLONNES_REQUETES = ["capture", "dst", "qname", "label"]


def extraire_requetes(dossier: str | Path) -> pd.DataFrame:
    """Lit toutes les captures et étiquette chaque requête (colonnes `COLONNES_REQUETES`)."""
    dossier = Path(dossier)
    morceaux = []
    for sous_dossier, est_attaque in (("Attacks", True), ("Benign", False)):
        for chemin in sorted((dossier / sous_dossier).glob("*.pcap")):
            requetes = read_dns_queries(chemin)
            requetes["capture"] = chemin.stem
            requetes["label"] = (est_attaque & (requetes["dst"] == IP_ATTAQUANT)).astype(int)
            morceaux.append(requetes[COLONNES_REQUETES])
    if not morceaux:
        raise FileNotFoundError(f"Aucun PCAP dans {dossier}/Attacks ni {dossier}/Benign")
    requetes = pd.concat(morceaux, ignore_index=True)
    if requetes.empty:
        raise ValueError(f"Aucune requête DNS dans les PCAP de {dossier}")
    return requetes


def load_dataset(dossier: str | Path = "data", cache: bool = True) -> pd.DataFrame:
    """Renvoie les requêtes étiquetées et leurs features.

    Colonnes : `COLONNES_REQUETES` puis `FEATURES`. Pour l'entraînement :
    `X = df[FEATURES]`, `y = df["label"]`, et `df["capture"]` pour découper par capture.

    Relire les PCAP prend environ 1 min 30 : avec `cache=True`, les requêtes brutes
    sont gardées dans `<dossier>/requetes.csv`. Les features sont recalculées à chaque
    appel, pour qu'une modification de `features.py` soit toujours prise en compte.
    Supprimer le fichier cache pour relire les PCAP.
    """
    chemin_cache = Path(dossier) / NOM_CACHE
    if cache and chemin_cache.exists():
        # keep_default_na=False : un nom vide reste "" et ne devient pas NaN
        texte = {"capture": str, "dst": str, "qname": str}
        requetes = pd.read_csv(chemin_cache, dtype=texte, keep_default_na=False)
    else:
        requetes = extraire_requetes(dossier)
        if cache:
            requetes.to_csv(chemin_cache, index=False)
    features = features_dataframe(requetes["qname"])
    return pd.concat([requetes, features], axis=1)[COLONNES_REQUETES + FEATURES]
