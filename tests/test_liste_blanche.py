import sqlite3

import pytest

from exfildns import statuts
from exfildns.alertes import LISTE_BLANCHE
from exfildns.liste_blanche import ajouter, complete, lire, normaliser, retirer


@pytest.mark.parametrize(
    ("saisie", "attendu"),
    [
        ("exemple.com", "exemple.com"),
        ("  Exemple.COM.  ", "exemple.com"),
        ("_dmarc.mon-site.fr", "_dmarc.mon-site.fr"),
        ("a.b.c.d.example", "a.b.c.d.example"),
    ],
)
def test_normaliser(saisie, attendu):
    assert normaliser(saisie) == attendu


@pytest.mark.parametrize(
    "saisie",
    ["", "   ", "com", ".", "exemple..com", "exe mple.com", "<b>x</b>.com", "*.exemple.com",
     "a" * 64 + ".com", ("a" * 60 + ".") * 5 + "com"],
)  # fmt: skip
def test_normaliser_refuse_les_domaines_mal_formes(saisie):
    with pytest.raises(ValueError, match="domaine invalide"):
        normaliser(saisie)


def test_lire_base_absente(tmp_path):
    assert lire(tmp_path / "statuts.db") == []
    assert not (tmp_path / "statuts.db").exists()  # la lecture ne crée pas la base


def test_ajouter_puis_lire_tries_et_normalises(tmp_path):
    base = tmp_path / "etat" / "statuts.db"

    assert ajouter(base, "Zeta.example.") == "zeta.example"
    ajouter(base, "alpha.example")

    assert lire(base) == ["alpha.example", "zeta.example"]


def test_ajouter_deux_fois_sans_doublon(tmp_path):
    base = tmp_path / "statuts.db"

    ajouter(base, "exemple.com", maintenant=1.0)
    ajouter(base, "EXEMPLE.com", maintenant=2.0)

    assert lire(base) == ["exemple.com"]


def test_ajouter_domaine_invalide_n_ecrit_rien(tmp_path):
    with pytest.raises(ValueError):
        ajouter(tmp_path / "statuts.db", "pas un domaine")

    assert not (tmp_path / "statuts.db").exists()


def test_retirer(tmp_path):
    base = tmp_path / "statuts.db"
    ajouter(base, "a.example")
    ajouter(base, "b.example")

    retirer(base, "a.example")
    retirer(base, "inconnu.example")  # sans effet

    assert lire(base) == ["b.example"]


def test_retirer_base_absente(tmp_path):
    retirer(tmp_path / "statuts.db", "a.example")

    assert not (tmp_path / "statuts.db").exists()


def test_meme_base_que_les_statuts(tmp_path):
    base = tmp_path / "statuts.db"
    statuts.enregistrer(base, "attaquant.example", "close")

    assert lire(base) == []  # base des statuts sans table liste_blanche
    ajouter(base, "exemple.com")

    assert lire(base) == ["exemple.com"]
    assert statuts.lire(base)["domaine"].tolist() == ["attaquant.example"]


def test_base_illisible(tmp_path):
    base = tmp_path / "statuts.db"
    base.write_text("pas une base SQLite")

    with pytest.raises(sqlite3.DatabaseError):
        lire(base)


def test_complete_garde_la_liste_par_defaut(tmp_path):
    base = tmp_path / "statuts.db"
    assert complete(base) == list(LISTE_BLANCHE)

    ajouter(base, "exemple.com")

    assert complete(base) == [*LISTE_BLANCHE, "exemple.com"]
