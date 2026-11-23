"""Découpage des données et modèles de détection."""

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline, make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_class_weight
from tensorflow import keras

from exfildns.features import FEATURES

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
    return df[~est_test].copy(), df[est_test].copy()


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


# --- Réseau de neurones (TensorFlow / Keras) ---


def construire_mlp(X_train) -> keras.Model:
    """Petit réseau dense, dans le style du TP Spam.

    La couche `Normalization` met chaque feature à l'échelle (moyenne 0, écart-type 1) ;
    elle est adaptée sur `X_train` seulement et sauvegardée avec le modèle, donc
    l'inférence applique exactement la même mise à l'échelle.
    """
    normalisation = keras.layers.Normalization()
    normalisation.adapt(np.asarray(X_train, dtype="float32"))
    modele = keras.Sequential(
        [
            keras.Input(shape=(len(FEATURES),)),
            normalisation,
            keras.layers.Dense(32, activation="relu"),
            keras.layers.Dense(16, activation="relu"),
            keras.layers.Dense(1, activation="sigmoid"),
        ]
    )
    modele.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return modele


def entrainer_mlp(X, y, epochs: int = 30, verbose: int = 0) -> tuple[keras.Model, dict]:
    """Entraîne le réseau et renvoie `(modele, historique)`.

    20 % du jeu d'entraînement sert de validation. L'arrêt anticipé garde les poids de
    l'époque où la perte de validation est la plus basse (le choix « argmin val_loss »
    du TP, automatisé). `class_weight` compense le déséquilibre des classes.
    """
    keras.utils.set_random_seed(GRAINE)
    X = np.asarray(X, dtype="float32")
    y = np.asarray(y)
    X_tr, X_val, y_tr, y_val = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=GRAINE
    )
    modele = construire_mlp(X_tr)
    poids = compute_class_weight("balanced", classes=np.array([0, 1]), y=y_tr)
    arret = keras.callbacks.EarlyStopping(monitor="val_loss", patience=3, restore_best_weights=True)
    historique = modele.fit(
        X_tr,
        y_tr,
        validation_data=(X_val, y_val),
        epochs=epochs,
        batch_size=256,
        class_weight={0: poids[0], 1: poids[1]},
        callbacks=[arret],
        verbose=verbose,
    )
    return modele, historique.history


def sauvegarder(modele: keras.Model, chemin: str | Path) -> None:
    """Sauvegarde le réseau (normalisation comprise) dans un fichier `.keras`."""
    Path(chemin).parent.mkdir(parents=True, exist_ok=True)
    modele.save(chemin)


def charger(chemin: str | Path) -> keras.Model:
    return keras.models.load_model(chemin)


def predire_proba(modele, X) -> np.ndarray:
    """Probabilité d'exfiltration de chaque requête, pour le réseau comme pour la référence."""
    if hasattr(modele, "predict_proba"):
        return modele.predict_proba(X)[:, 1]
    return modele.predict(np.asarray(X, dtype="float32"), verbose=0).ravel()
