import pytest

from exfildns.features import (
    FEATURES,
    LONGUEUR_MAX,
    entropie,
    extract_features,
    features_dataframe,
)

EXFIL = "0.J4HgHlgzQH6j0WZF8m3DQx3jGodWnpcKYKFAeUM.attaquant.example"


def test_domaine_benin():
    f = extract_features("www.example.com")
    assert list(f) == FEATURES
    assert f["FQDN_count"] == 15
    assert (f["upper"], f["lower"], f["numeric"], f["special"]) == (0, 13, 0, 2)
    assert f["labels"] == 3
    assert f["labels_max"] == 7
    assert f["labels_average"] == pytest.approx(13 / 3)


def test_exemple_verifie_sur_le_dataset():
    # valeurs lues dans les CSV du dataset pour ce nom (cf. docs/donnees.md)
    f = extract_features("10.1.168.192.in-addr.arpa")
    assert f["FQDN_count"] == 25
    assert (f["lower"], f["numeric"], f["special"]) == (10, 9, 6)
    assert (f["labels"], f["labels_max"]) == (6, 7)
    assert f["labels_average"] == pytest.approx(20 / 6)


def test_nom_tronque_a_longueur_max():
    assert extract_features(EXFIL) == extract_features(EXFIL[:LONGUEUR_MAX])
    assert extract_features(EXFIL)["FQDN_count"] == LONGUEUR_MAX


def test_exfiltration_plus_aleatoire_que_benin():
    exfil, benin = extract_features(EXFIL), extract_features("www.example.com")
    assert exfil["entropy"] > benin["entropy"]
    assert exfil["upper"] > 0
    assert exfil["labels_max"] > benin["labels_max"]


def test_point_final_ignore():
    assert extract_features("example.com.") == extract_features("example.com")


def test_nom_vide():
    f = extract_features("")
    assert all(v == 0 for v in f.values())
    assert extract_features(".") == f
    assert extract_features("a..b")["labels"] == 2


def test_entropie():
    assert entropie("aaaa") == 0
    assert entropie("ab") == pytest.approx(1.0)
    assert entropie("abcd") == pytest.approx(2.0)


def test_features_dataframe():
    df = features_dataframe(["example.com", EXFIL])
    assert list(df.columns) == FEATURES
    assert len(df) == 2
    assert features_dataframe([]).columns.tolist() == FEATURES
