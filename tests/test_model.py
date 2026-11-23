import numpy as np
import pytest
from conftest import jeu_synthetique

from exfildns.features import FEATURES
from exfildns.model import (
    charger,
    entrainer_mlp,
    entrainer_reference,
    predire_proba,
    sauvegarder,
    split_par_capture,
)


def test_split_par_capture():
    df = jeu_synthetique()
    train, test = split_par_capture(df, ("test",))
    assert set(train.capture) == {"train"}
    assert set(test.capture) == {"test"}
    assert len(train) + len(test) == len(df)


@pytest.mark.parametrize("captures_test", [("inconnue",), ("train", "test")])
def test_split_refuse_un_train_ou_un_test_vide(captures_test):
    with pytest.raises(ValueError):
        split_par_capture(jeu_synthetique(), captures_test)


def test_reference_bat_le_hasard():
    train, test = split_par_capture(jeu_synthetique(), ("test",))
    modele = entrainer_reference(train[FEATURES], train.label)
    assert modele.score(test[FEATURES], test.label) > 0.9


def test_mlp_apprend_et_se_recharge(tmp_path):
    train, test = split_par_capture(jeu_synthetique(n=600), ("test",))
    modele, historique = entrainer_mlp(train[FEATURES], train.label, epochs=15)

    proba = predire_proba(modele, test[FEATURES])
    assert ((proba > 0.5) == test.label.values).mean() > 0.9
    assert len(historique["val_loss"]) <= 15

    chemin = tmp_path / "modeles" / "exfildns.keras"
    sauvegarder(modele, chemin)
    np.testing.assert_allclose(predire_proba(charger(chemin), test[FEATURES]), proba, rtol=1e-5)


def test_predire_proba_reference():
    train, test = split_par_capture(jeu_synthetique(), ("test",))
    proba = predire_proba(entrainer_reference(train[FEATURES], train.label), test[FEATURES])
    assert proba.shape == (len(test),)
    assert ((proba >= 0) & (proba <= 1)).all()
