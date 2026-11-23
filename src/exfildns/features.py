"""Features d'une requête DNS calculées à partir de son seul nom de domaine.

Ce module sert à la fois à l'entraînement et à l'inférence : le modèle voit ainsi
exactement les mêmes features sur le dataset et sur une capture analysée.

Les noms reprennent ceux de l'article de référence (Mahdavifar et al., 2021).
Seules les features qui ne dépendent que des caractères du nom sont gardées
(voir docs/decisions.md).
"""

import math
from collections import Counter
from collections.abc import Iterable

import pandas as pd

# Les paquets du dataset sont tronqués : les noms d'exfiltration y font au plus
# 41 caractères. On coupe tous les noms un peu en dessous (40), à l'entraînement comme
# à l'inférence, pour que tous les noms longs soient traités pareil (docs/donnees.md).
LONGUEUR_MAX = 40

FEATURES = [
    "FQDN_count",  # nombre de caractères du nom
    "upper",  # nombre de majuscules
    "lower",  # nombre de minuscules
    "numeric",  # nombre de chiffres
    "special",  # nombre d'autres caractères (points, tirets, _, non ASCII …)
    "entropy",  # entropie de Shannon des caractères, en bits
    "labels",  # nombre de labels (parties séparées par des points)
    "labels_max",  # longueur du plus long label
    "labels_average",  # longueur moyenne des labels
]


def entropie(texte: str) -> float:
    """Entropie de Shannon (en bits par caractère) ; 0 pour un texte vide."""
    if not texte:
        return 0.0
    n = len(texte)
    return -sum(c / n * math.log2(c / n) for c in Counter(texte).values())


def extract_features(qname: str) -> dict[str, float]:
    """Calcule les features `FEATURES` d'un nom de domaine."""
    nom = qname.rstrip(".")[:LONGUEUR_MAX]
    labels = [label for label in nom.split(".") if label]
    longueurs = [len(label) for label in labels] or [0]
    upper = sum(c.isascii() and c.isupper() for c in nom)
    lower = sum(c.isascii() and c.islower() for c in nom)
    numeric = sum(c.isascii() and c.isdigit() for c in nom)
    return {
        "FQDN_count": len(nom),
        "upper": upper,
        "lower": lower,
        "numeric": numeric,
        "special": len(nom) - upper - lower - numeric,
        "entropy": entropie(nom),
        "labels": len(labels),
        "labels_max": max(longueurs),
        "labels_average": sum(longueurs) / len(longueurs),
    }


def features_dataframe(qnames: Iterable[str]) -> pd.DataFrame:
    """Applique `extract_features` à une suite de noms ; colonnes dans l'ordre `FEATURES`."""
    return pd.DataFrame([extract_features(q) for q in qnames], columns=FEATURES)
