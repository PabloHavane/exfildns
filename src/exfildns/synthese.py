"""Synthèse de la supervision : chiffres clés, file d'alertes, état du capteur.

Fonctions pures utilisées par le bandeau et la vue en direct du dashboard (testées sans
navigateur). La sévérité d'une alerte est une aide au tri pour l'analyste : elle ne change
pas quelles alertes sont levées (règle de `alertes.alertes`, docs/decisions.md).
"""

import hashlib
import re
from datetime import datetime
from functools import lru_cache
from pathlib import Path

import pandas as pd

from exfildns.alertes import domaine_parent

QTYPES_TUNNEL = (10, 16)  # NULL et TXT : réponses longues, prisées des outils de tunneling
SCORE_ELEVE = 0.9  # score max à partir duquel une alerte est jugée nette
SEVERITES = {"haute": "red", "moyenne": "orange", "basse": "blue"}  # ordre de tri, couleur
CAPTEUR_ACTIF = 60  # secondes sans requête avant de juger le capteur silencieux
CAPTEUR_SILENCIEUX = 5 * 60  # puis inactif


def indicateurs(requetes: pd.DataFrame, seuil: float, resume: pd.DataFrame) -> dict[str, float]:
    """Chiffres clés de la période.

    `taux_suspect` et `txt_null` sont en pourcentage des requêtes analysées ; `score_max` vaut
    NaN sans requête. `resume` est la sortie de `alertes` sur les mêmes requêtes.
    """
    n = len(requetes)
    suspectes = int((requetes["score"] >= seuil).sum())
    domaines = {
        domaine_parent(q, pd.isna(t))
        for q, t in zip(requetes["qname"], requetes["qtype"], strict=True)
    }
    return {
        "analysees": n,
        "suspectes": suspectes,
        "taux_suspect": 100 * suspectes / n if n else 0.0,
        "alertes": len(resume),
        "postes": requetes["src"].nunique(),
        "domaines": len(domaines),
        "score_max": float(requetes["score"].max()) if n else float("nan"),
        "txt_null": 100 * requetes["qtype"].isin(QTYPES_TUNNEL).sum() / n if n else 0.0,
    }


def ecarts(actuels: dict, precedents: dict | None) -> dict:
    """Variation de chaque chiffre clé par rapport à la période précédente (None si inconnue)."""
    if precedents is None:
        return dict.fromkeys(actuels)
    return {
        cle: None if pd.isna(actuels[cle]) or pd.isna(precedents[cle]) else actuels[cle] - v
        for cle, v in precedents.items()
    }


def severite(requetes_suspectes: int, score_max: float, min_requetes: int) -> str:
    """`haute` si l'alerte est à la fois nette (score max >= 0,9) et fournie (au moins deux fois
    le minimum de requêtes), `moyenne` si l'une des deux, `basse` sinon."""
    nette = score_max >= SCORE_ELEVE
    fournie = requetes_suspectes >= 2 * min_requetes
    return "haute" if nette and fournie else "moyenne" if nette or fournie else "basse"


def file_alertes(resume: pd.DataFrame, min_requetes: int) -> pd.DataFrame:
    """Alertes avec leur sévérité, triées par sévérité puis de la plus récente à la plus ancienne
    (date de la dernière requête suspecte)."""
    if resume.empty:
        return resume.assign(severite=pd.Series(dtype=str))
    file = resume.assign(
        severite=[
            severite(n, s, min_requetes)
            for n, s in zip(resume["requetes_suspectes"], resume["score_max"], strict=True)
        ]
    )
    rang = file["severite"].map(list(SEVERITES).index)
    return (
        file.assign(rang=rang)
        .sort_values(["rang", "fin"], ascending=[True, False])
        .drop(columns="rang")
        .reset_index(drop=True)
    )


def etat_capteur(derniere: float | None, maintenant: float) -> tuple[str, str]:
    """État de la capture d'après l'âge de la dernière requête reçue : `(libellé, couleur)`.

    Limite : sur un réseau très calme, un capteur en marche paraît silencieux.
    """
    if derniere is None or pd.isna(derniere):
        return "aucune requête", "red"
    age = maintenant - derniere
    if age < CAPTEUR_ACTIF:
        return "actif", "green"
    if age < CAPTEUR_SILENCIEUX:
        return "silencieux", "orange"
    return "inactif", "red"


def duree_lisible(secondes: float) -> str:
    """`42 s`, `3 min`, `2 h`, `4 j` (arrondi vers le bas)."""
    secondes = max(0, int(secondes))
    for unite, taille in (("j", 86400), ("h", 3600), ("min", 60)):
        if secondes >= taille:
            return f"{secondes // taille} {unite}"
    return f"{secondes} s"


def infos_modele(chemin: str | Path) -> str:
    """`exfildns.keras · 24/11 14:02 · a1b2c3d4` (nom, date du fichier, début de son SHA-256)."""
    chemin = Path(chemin)
    if not chemin.exists():
        return "modèle absent"
    date = chemin.stat().st_mtime
    return _infos_modele(str(chemin), date)


@lru_cache(maxsize=4)
def _infos_modele(chemin: str, date: float) -> str:
    """Empreinte calculée une fois par version du fichier (le bandeau se rafraîchit souvent)."""
    empreinte = hashlib.sha256(Path(chemin).read_bytes()).hexdigest()[:8]
    return f"{Path(chemin).name} · {datetime.fromtimestamp(date):%d/%m %H:%M} · {empreinte}"


def echapper_markdown(texte: str) -> str:
    """Texte venu du réseau (nom de domaine) affichable dans `st.markdown` sans être interprété.

    Caractères de contrôle et non ASCII en `\\xNN`, ponctuation Markdown précédée de `\\`.
    """
    sur = "".join(c if 32 <= ord(c) < 127 else f"\\x{ord(c):02x}" for c in texte)
    return re.sub(r"([\\`*_{}\[\]()#+\-.!|<>~:$&])", r"\\\1", sur)
