"""Évaluation des modèles et explication par importance des features."""

import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
)

from exfildns.model import GRAINE, predire_proba

# Seuil de décision : une requête est signalée si sa probabilité d'exfiltration dépasse 0,5.
SEUIL = 0.5


def evaluer_predictions(y, proba, seuil: float = SEUIL) -> dict[str, float | int]:
    """Métriques de détection, la classe positive (1) étant l'exfiltration.

    - rappel : part des exfiltrations détectées (métrique principale) ;
    - taux_faux_positifs : part des requêtes bénignes signalées à tort ;
    - précision : part des alertes qui sont de vraies exfiltrations ;
    - pr_auc : aire sous la courbe précision-rappel, indépendante du seuil
      (sans signification si `y` ne contient aucune exfiltration).
    """
    y = np.asarray(y)
    proba = np.asarray(proba)
    pred = (proba >= seuil).astype(int)
    vn, fp, fn, vp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "rappel": float(recall_score(y, pred, zero_division=0)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "pr_auc": float(average_precision_score(y, proba)),
        "taux_faux_positifs": float(fp / (fp + vn)) if fp + vn else 0.0,
        "vrais_positifs": int(vp),
        "faux_positifs": int(fp),
        "faux_negatifs": int(fn),
        "vrais_negatifs": int(vn),
    }


def evaluer(modele, X, y, seuil: float = SEUIL) -> dict[str, float | int]:
    """Évalue un modèle (réseau Keras ou référence scikit-learn) sur `X`, `y`."""
    return evaluer_predictions(y, predire_proba(modele, X), seuil)


def importance_permutation(modele, X: pd.DataFrame, y, repetitions: int = 3) -> pd.Series:
    """Importance de chaque feature : hausse de la perte quand on mélange ses valeurs.

    On mélange une colonne à la fois, ce qui casse son lien avec l'étiquette, puis on mesure
    de combien la perte (entropie croisée binaire) augmente. Plus la hausse est forte, plus le
    modèle s'appuie sur cette feature ; une valeur nulle ou négative signifie « aucun effet ».
    `X` doit être un DataFrame. Fonctionne pour n'importe quel modèle.
    """
    rng = np.random.default_rng(GRAINE)
    y = np.asarray(y)
    perte_ref = log_loss(y, predire_proba(modele, X), labels=[0, 1])
    hausses = {}
    for colonne in X.columns:
        pertes = []
        for _ in range(repetitions):
            X_melange = X.copy()
            X_melange[colonne] = rng.permutation(X_melange[colonne].values)
            pertes.append(log_loss(y, predire_proba(modele, X_melange), labels=[0, 1]))
        hausses[colonne] = float(np.mean(pertes) - perte_ref)
    return pd.Series(hausses, name="hausse_perte").sort_values(ascending=False)
