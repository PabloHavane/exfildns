import numpy as np
import pandas as pd
import pytest

from exfildns.features import FEATURES
from exfildns.model import entrainer_reference, split_par_capture


def jeu_synthetique(n=400, graine=0):
    """Deux classes séparables : la classe 1 a des valeurs plus grandes sur toutes les features."""
    rng = np.random.default_rng(graine)
    y = np.arange(n) % 2
    X = rng.normal(size=(n, len(FEATURES))) + 3 * y[:, None]
    df = pd.DataFrame(X, columns=FEATURES)
    df["label"] = y
    df["capture"] = np.where(np.arange(n) < n * 3 // 4, "train", "test")
    return df


def test_split_par_capture():
    df = jeu_synthetique()
    train, test = split_par_capture(df, ("test",))
    assert set(train.capture) == {"train"}
    assert set(test.capture) == {"test"}
    assert len(train) + len(test) == len(df)


def test_split_refuse_un_test_vide():
    with pytest.raises(ValueError):
        split_par_capture(jeu_synthetique(), ("inconnue",))


def test_reference_bat_le_hasard():
    train, test = split_par_capture(jeu_synthetique(), ("test",))
    modele = entrainer_reference(train[FEATURES], train.label)
    assert modele.score(test[FEATURES], test.label) > 0.9
