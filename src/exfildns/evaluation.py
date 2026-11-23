"""Évaluation des modèles de détection."""

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from exfildns.model import predire_proba

# Seuil de décision : une requête est signalée si sa probabilité d'exfiltration dépasse 0,5.
SEUIL = 0.5


def evaluer_predictions(y, proba, seuil: float = SEUIL) -> dict[str, float]:
    """Métriques de détection, la classe positive (1) étant l'exfiltration.

    - rappel : part des exfiltrations détectées (métrique principale) ;
    - taux_faux_positifs : part des requêtes bénignes signalées à tort ;
    - précision : part des alertes qui sont de vraies exfiltrations ;
    - pr_auc : aire sous la courbe précision-rappel, indépendante du seuil.
    """
    y = np.asarray(y)
    proba = np.asarray(proba)
    pred = (proba >= seuil).astype(int)
    vn, fp, fn, vp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "rappel": recall_score(y, pred, zero_division=0),
        "precision": precision_score(y, pred, zero_division=0),
        "f1": f1_score(y, pred, zero_division=0),
        "pr_auc": average_precision_score(y, proba),
        "taux_faux_positifs": fp / (fp + vn) if fp + vn else 0.0,
        "vrais_positifs": int(vp),
        "faux_positifs": int(fp),
        "faux_negatifs": int(fn),
        "vrais_negatifs": int(vn),
    }


def evaluer(modele, X, y, seuil: float = SEUIL) -> dict[str, float]:
    """Évalue un modèle (réseau Keras ou référence scikit-learn) sur `X`, `y`."""
    return evaluer_predictions(y, predire_proba(modele, X), seuil)
