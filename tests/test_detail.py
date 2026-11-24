import base64
import json

import pandas as pd
import pytest

from exfildns.detail import (
    ascii_echappe,
    comparaison_features,
    essais_decodage,
    exporter,
    filtrer,
    nom_qtype,
    nom_vu_par_le_modele,
    qname_html,
    sequence,
    sous_domaine,
    tableau_detaille,
)
from exfildns.features import FEATURES, extract_features


def requetes(*lignes):
    """Lignes (src, qname, qtype, score) -> requêtes comme les rend `lire_requetes`."""
    return pd.DataFrame(
        [
            {
                "id": i + 1,
                "timestamp": float(i),
                "src": src,
                "dst": "10.0.0.254",
                "qname": qname,
                "qtype": qtype,
                "score": score,
                "taille": 30,
            }
            for i, (src, qname, qtype, score) in enumerate(lignes)
        ]
    ).astype({"qtype": "Int64", "taille": "Int64"})


@pytest.fixture
def tableau():
    return tableau_detaille(
        requetes(
            ("10.0.0.1", "www.site.fr", 1, 0.05),
            ("10.0.0.66", "abcd1234.pirate.example", 16, 0.95),
            ("10.0.0.66", "efgh5678.pirate.example", 16, 0.90),
            ("10.0.0.2", "mail.site.fr", 15, 0.10),
            ("10.0.0.66", "nom-coupe-dans-la-capt", None, 0.70),
        ),
        seuil=0.5,
    )


# --- petites fonctions ---


@pytest.mark.parametrize(
    ("qtype", "nom"), [(1, "A"), (16, "TXT"), (10, "NULL"), (28, "AAAA"), (99, "99"), (pd.NA, "?")]
)
def test_nom_qtype(qtype, nom):
    assert nom_qtype(qtype) == nom


@pytest.mark.parametrize(
    ("qname", "tronque", "attendu"),
    [
        ("abc.def.exemple.com", False, "abc.def"),
        ("abc.def.exemple.com.", False, "abc.def"),
        ("exemple.com", False, ""),
        ("com", False, ""),
        ("nom.coupe", True, "nom.coupe"),
    ],
)
def test_sous_domaine(qname, tronque, attendu):
    assert sous_domaine(qname, tronque) == attendu


def test_nom_vu_par_le_modele_coupe_a_40_caracteres():
    assert nom_vu_par_le_modele("a" * 50 + ".fr") == "a" * 40
    assert nom_vu_par_le_modele("court.fr.") == "court.fr"


# --- tableau détaillé et filtres ---


def test_tableau_detaille_features_identiques_au_modele(tableau):
    """Les features affichées sont exactement celles que reçoit le modèle."""
    ligne = tableau.iloc[1]

    assert {f: ligne[f] for f in FEATURES} == extract_features("abcd1234.pirate.example")


def test_tableau_detaille_colonnes_derivees(tableau):
    assert tableau["domaine"].tolist() == [
        "site.fr",
        "pirate.example",
        "pirate.example",
        "site.fr",
        "(nom incomplet dans la capture)",
    ]
    assert tableau["type"].tolist() == ["A", "TXT", "TXT", "MX", "?"]
    assert tableau["sous_domaine"].tolist() == [3, 8, 8, 4, len("nom-coupe-dans-la-capt")]
    assert tableau["verdict"].tolist() == ["bénigne", "suspecte", "suspecte", "bénigne", "suspecte"]
    assert tableau.index.equals(pd.RangeIndex(5))  # même index que les requêtes


def test_tableau_detaille_verdict_au_seuil():
    tableau = tableau_detaille(requetes(("a", "x.fr", 1, 0.5)), seuil=0.5)

    assert tableau["verdict"].tolist() == ["suspecte"]  # même règle que le reste : score >= seuil


def test_filtrer_sans_filtre_garde_tout(tableau):
    assert len(filtrer(tableau)) == 5


def test_filtrer_par_poste_domaine_et_verdict(tableau):
    assert filtrer(tableau, postes=["10.0.0.66"])["id"].tolist() == [2, 3, 5]
    assert filtrer(tableau, domaines=["site.fr"])["id"].tolist() == [1, 4]
    assert filtrer(tableau, verdicts=["bénigne"])["id"].tolist() == [1, 4]
    assert filtrer(tableau, postes=["10.0.0.66"], domaines=["site.fr"]).empty


def test_filtrer_score_minimum(tableau):
    assert filtrer(tableau, score_min=0.9)["id"].tolist() == [2, 3]


def test_filtrer_texte_sans_casse_ni_regex(tableau):
    assert filtrer(tableau, texte="ABCD")["id"].tolist() == [2]
    assert filtrer(tableau, texte=".*").empty  # cherché tel quel, pas comme une regex
    assert filtrer(tableau, texte="(")["id"].tolist() == []


# --- panneau de détail ---


def test_qname_html_met_en_evidence_le_sous_domaine():
    rendu = qname_html("abc.def.exemple.com")

    assert rendu.count('class="label suspect"') == 2
    assert rendu.count('class="label parent"') == 2
    assert rendu.index(">abc<") < rendu.index(">exemple<")


def test_qname_html_echappe_le_html():
    """Le nom vient du réseau : il ne doit jamais être interprété par le navigateur."""
    rendu = qname_html('<script>alert(1)</script>.<img src=x onerror="a">.evil.com')

    assert "<script>" not in rendu and "<img" not in rendu
    assert "&lt;script&gt;" in rendu
    assert "&quot;" in rendu


def test_qname_html_nom_tronque_tout_en_suspect():
    rendu = qname_html("abc.coupe", tronque=True)

    assert 'class="label parent"' not in rendu


def test_comparaison_features(tableau):
    benignes = tableau[tableau["verdict"] == "bénigne"]

    comparaison = comparaison_features(tableau.iloc[1], benignes)

    assert comparaison["feature"].tolist() == FEATURES
    fqdn = comparaison.set_index("feature").loc["FQDN_count"]
    assert fqdn["valeur"] == len("abcd1234.pirate.example")
    assert fqdn["moyenne bénigne"] == (len("www.site.fr") + len("mail.site.fr")) / 2
    assert fqdn["écart"] > 0
    # labels : 3 pour les deux bénignes, écart-type nul -> écart indéfini plutôt qu'infini
    assert pd.isna(comparaison.set_index("feature").loc["labels", "écart"])


def test_comparaison_features_sans_reference(tableau):
    comparaison = comparaison_features(tableau.iloc[1], tableau.iloc[:0])

    assert comparaison["moyenne bénigne"].isna().all()
    assert comparaison["écart"].isna().all()


def test_sequence_meme_poste_et_meme_domaine(tableau):
    suite = sequence(tableau, tableau.iloc[2])

    assert suite["id"].tolist() == [2, 3]  # pas la requête tronquée du même poste
    assert suite["timestamp"].is_monotonic_increasing


# --- décodage ---


def test_ascii_echappe():
    assert ascii_echappe(b"abc\x00\xff\n\\") == "abc\\x00\\xff\\x0a\\x5c"


def test_essais_decodage_base32():
    donnees = base64.b32encode(b"secret!!!!").decode().lower().rstrip("=")
    sous = donnees[:8] + "." + donnees[8:]  # données réparties sur deux labels

    essais = {e["encodage"]: e for e in essais_decodage(sous)}

    assert essais["base32"]["ASCII échappé"] == "secret!!!!"
    assert essais["base32"]["hexadécimal"] == b"secret!!!!".hex(" ")
    assert essais["base32"]["octets"] == 10


def test_essais_decodage_base64_url():
    donnees = base64.urlsafe_b64encode(b"\xfb\xff\x00 mot").decode().rstrip("=")

    essais = {e["encodage"]: e for e in essais_decodage(donnees)}

    assert essais["base64"]["ASCII échappé"] == "\\xfb\\xff\\x00 mot"


def test_essais_decodage_hexadecimal():
    essais = {e["encodage"]: e for e in essais_decodage("6869")}

    assert essais["hexadécimal"]["ASCII échappé"] == "hi"


def test_essais_decodage_rien_ne_marche():
    assert essais_decodage("") == []
    assert essais_decodage("a") == []  # trop court pour tout encodage
    assert [e["encodage"] for e in essais_decodage("www-site!")] == []


def test_essais_decodage_tronque_l_affichage():
    donnees = base64.b32encode(bytes(range(200))).decode().rstrip("=")

    (essai,) = [e for e in essais_decodage(donnees) if e["encodage"] == "base32"]

    assert essai["octets"] == 200
    assert len(essai["hexadécimal"].split()) == 64


# --- export ---


def test_exporter_csv(tableau):
    texte = exporter(tableau.iloc[:2], "csv")

    lignes = texte.strip().splitlines()
    assert len(lignes) == 3
    assert "qname" in lignes[0] and "heure" in lignes[0] and "entropy" in lignes[0]
    assert "1970-01-01T00:00:00.000000Z" in lignes[1]


def test_exporter_json(tableau):
    donnees = json.loads(exporter(tableau.iloc[[4]], "json"))

    assert len(donnees) == 1
    assert donnees[0]["qname"] == "nom-coupe-dans-la-capt"
    assert donnees[0]["qtype"] is None
    assert donnees[0]["domaine"] == "(nom incomplet dans la capture)"


def test_exporter_vide_et_format_inconnu(tableau):
    assert json.loads(exporter(tableau.iloc[:0], "json")) == []
    with pytest.raises(ValueError, match="inconnu"):
        exporter(tableau, "xml")
