"""Découpage des données et modèles de détection."""

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler

GRAINE = 0

# Captures mises de côté pour le test : les requêtes d'une même capture se ressemblent,
# un tirage aléatoire mettrait des quasi-doublons des deux côtés (docs/donnees.md).
# Une capture d'attaque et une capture bénigne, soit ~24 % des requêtes.
CAPTURES_TEST = ("heavy_video", "benign_heavy_3")


def split_par_capture(
    df: pd.DataFrame, captures_test: tuple[str, ...] = CAPTURES_TEST
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Sépare entraînement et test selon la colonne `capture`."""
    est_test = df["capture"].isin(captures_test)
    if not est_test.any() or est_test.all():
        raise ValueError(f"Les captures de test {captures_test} doivent couvrir une partie du jeu")
    return df[~est_test], df[est_test]


def entrainer_reference(X: pd.DataFrame, y: pd.Series) -> Pipeline:
    """Modèle de référence : standardisation puis régression logistique.

    La standardisation fait partie du pipeline : elle est ajustée sur les seules données
    d'entraînement. `class_weight="balanced"` compense le déséquilibre des classes.
    """
    modele = make_pipeline(
        StandardScaler(),
        LogisticRegression(class_weight="balanced", max_iter=1000, random_state=GRAINE),
    )
    return modele.fit(X, y)
