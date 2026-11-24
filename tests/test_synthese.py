import hashlib
import math
import os

import pandas as pd
import pytest

from exfildns.alertes import alertes
from exfildns.synthese import (
    duree_lisible,
    ecarts,
    echapper_markdown,
    etat_capteur,
    file_alertes,
    indicateurs,
    infos_modele,
    severite,
)


def requetes(*lignes):
    """Lignes (src, qname, qtype, score) -> requêtes notées."""
    return pd.DataFrame(
        [
            {"timestamp": float(i), "src": s, "qname": q, "qtype": t, "score": sc}
            for i, (s, q, t, sc) in enumerate(lignes)
        ]
    ).astype({"qtype": "Int64"})


# --- indicateurs ---


def test_indicateurs():
    lot = requetes(
        ("a", "www.site.fr", 1, 0.1),
        ("a", "mail.site.fr", 15, 0.2),
        ("b", "x1.pirate.example", 16, 0.95),
        ("b", "x2.pirate.example", 10, 0.97),
        ("c", "nom-coupe", None, 0.6),
    )
    resume = alertes(lot, 0.5, 2)

    chiffres = indicateurs(lot, 0.5, resume)

    assert chiffres == {
        "analysees": 5,
        "suspectes": 3,
        "taux_suspect": 60.0,
        "alertes": 1,
        "postes": 3,
        "domaines": 3,  # site.fr, pirate.example, (nom incomplet)
        "score_max": 0.97,
        "txt_null": 40.0,  # un TXT et un NULL sur 5
    }


def test_indicateurs_sans_requete():
    vide = pd.DataFrame(
        {
            "timestamp": pd.Series(dtype=float),
            "src": pd.Series(dtype=str),
            "qname": pd.Series(dtype=str),
            "qtype": pd.Series(dtype="Int64"),
            "score": pd.Series(dtype=float),
        }
    )

    chiffres = indicateurs(vide, 0.5, alertes(vide))

    assert chiffres["analysees"] == 0
    assert chiffres["taux_suspect"] == 0.0 and chiffres["txt_null"] == 0.0
    assert math.isnan(chiffres["score_max"])


def test_ecarts():
    actuels = {"analysees": 10, "score_max": 0.9}

    assert ecarts(actuels, {"analysees": 4, "score_max": 0.5}) == {
        "analysees": 6,
        "score_max": pytest.approx(0.4),
    }
    assert ecarts(actuels, None) == {"analysees": None, "score_max": None}
    # période précédente vide : pas de score max, donc pas de variation
    assert ecarts(actuels, {"analysees": 0, "score_max": float("nan")})["score_max"] is None


# --- file d'alertes ---


@pytest.mark.parametrize(
    ("n", "score_max", "attendu"),
    [(10, 0.95, "haute"), (10, 0.6, "moyenne"), (5, 0.95, "moyenne"), (5, 0.6, "basse")],
)
def test_severite(n, score_max, attendu):
    assert severite(n, score_max, min_requetes=5) == attendu


def test_file_alertes_par_severite_puis_plus_recente():
    resume = pd.DataFrame(
        {
            "domaine": ["basse.ex", "haute-ancienne.ex", "haute-recente.ex", "moyenne.ex"],
            "requetes_suspectes": [5, 20, 20, 20],
            "score_max": [0.6, 0.99, 0.99, 0.6],
            "fin": [400.0, 100.0, 300.0, 500.0],
        }
    )

    file = file_alertes(resume, min_requetes=5)

    assert file["domaine"].tolist() == [
        "haute-recente.ex",
        "haute-ancienne.ex",
        "moyenne.ex",
        "basse.ex",
    ]
    assert file["severite"].tolist() == ["haute", "haute", "moyenne", "basse"]


def test_file_alertes_vide():
    vide = alertes(requetes(("a", "x.fr", 1, 0.1)))

    file = file_alertes(vide, 5)

    assert file.empty and "severite" in file


# --- bandeau ---


@pytest.mark.parametrize(
    ("age", "etat"),
    [(0, ("actif", "green")), (59, ("actif", "green")), (60, ("silencieux", "orange"))]
    + [(299, ("silencieux", "orange")), (300, ("inactif", "red"))],
)
def test_etat_capteur(age, etat):
    assert etat_capteur(1000.0 - age, 1000.0) == etat


def test_etat_capteur_sans_requete():
    assert etat_capteur(None, 1000.0) == ("aucune requête", "red")


@pytest.mark.parametrize(
    ("secondes", "texte"),
    [(0, "0 s"), (59.9, "59 s"), (60, "1 min"), (3599, "59 min"), (7200, "2 h")]
    + [(3 * 86400 + 5, "3 j"), (-4, "0 s")],
)
def test_duree_lisible(secondes, texte):
    assert duree_lisible(secondes) == texte


def test_infos_modele(tmp_path):
    modele = tmp_path / "exfildns.keras"
    modele.write_bytes(b"poids")
    os.utime(modele, (0, 1_700_000_000))

    infos = infos_modele(modele)

    nom, date, empreinte = infos.split(" · ")
    assert nom == "exfildns.keras"
    assert len(date) == len("14/11 22:13")
    assert empreinte == hashlib.sha256(b"poids").hexdigest()[:8]


def test_infos_modele_change_avec_le_fichier(tmp_path):
    modele = tmp_path / "m.keras"
    modele.write_bytes(b"v1")
    os.utime(modele, (0, 1_700_000_000))
    avant = infos_modele(modele)

    modele.write_bytes(b"v2")
    os.utime(modele, (0, 1_700_000_100))

    assert infos_modele(modele) != avant


def test_infos_modele_absent(tmp_path):
    assert infos_modele(tmp_path / "absent.keras") == "modèle absent"
    assert infos_modele(tmp_path) == "modèle absent"  # un dossier ne fait pas planter le bandeau


def test_echapper_markdown():
    assert echapper_markdown("pirate.example") == "pirate\\.example"
    assert echapper_markdown("[clic](http://e)") == "\\[clic\\]\\(http\\://e\\)"
    assert echapper_markdown("**gras**") == "\\*\\*gras\\*\\*"
    assert echapper_markdown("a\n\nb") == "a\\\\x0a\\\\x0ab"
    assert echapper_markdown(":red-badge[x]") == "\\:red\\-badge\\[x\\]"
    assert echapper_markdown("é\xff") == "\\\\xe9\\\\xff"  # octets latin-1 du réseau
