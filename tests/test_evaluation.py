import pytest
from conftest import jeu_synthetique

from exfildns.evaluation import evaluer, evaluer_predictions
from exfildns.features import FEATURES
from exfildns.model import entrainer_reference


def test_metriques_sur_predictions_connues():
    y = [1, 1, 1, 1, 0, 0, 0, 0]
    proba = [0.9, 0.8, 0.7, 0.2, 0.6, 0.1, 0.1, 0.1]  # 3 VP, 1 FN, 1 FP, 3 VN

    m = evaluer_predictions(y, proba)

    assert (m["vrais_positifs"], m["faux_negatifs"]) == (3, 1)
    assert (m["faux_positifs"], m["vrais_negatifs"]) == (1, 3)
    assert m["rappel"] == pytest.approx(3 / 4)
    assert m["precision"] == pytest.approx(3 / 4)
    assert m["taux_faux_positifs"] == pytest.approx(1 / 4)
    assert m["f1"] == pytest.approx(0.75)
    assert m["pr_auc"] == pytest.approx(0.95)


def test_seuil():
    m = evaluer_predictions([1, 0], [0.4, 0.1], seuil=0.3)
    assert m["rappel"] == 1
    assert m["faux_positifs"] == 0


def test_evaluer_un_modele():
    df = jeu_synthetique()
    modele = entrainer_reference(df[FEATURES], df.label)
    m = evaluer(modele, df[FEATURES], df.label)
    assert m["rappel"] > 0.9
    assert m["vrais_positifs"] + m["faux_negatifs"] == df.label.sum()
