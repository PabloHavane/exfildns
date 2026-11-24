import pandas as pd
import pytest
from conftest import ecrire_pcap, noms_benins, noms_exfil, requete

from exfildns.alertes import (
    COLONNES_ALERTES,
    LISTE_BLANCHE,
    NOM_INCOMPLET,
    alertes,
    domaine_parent,
    est_autorise,
    lire_liste_blanche,
)
from exfildns.cli import main


def requetes(*lignes):
    """DataFrame façon `exfildns sniff` : (timestamp, src, qname, score[, qtype])."""
    lignes = [ligne if len(ligne) == 5 else (*ligne, 1) for ligne in lignes]
    return pd.DataFrame(lignes, columns=["timestamp", "src", "qname", "score", "qtype"]).astype(
        {"qtype": "Int64"}
    )


def tunnel(n, domaine="attaquant.example", src="10.0.0.2", debut=0.0, score=0.99):
    return [(debut + i, src, f"{i}.AbCdEf0123456789.{domaine}", score) for i in range(n)]


# --- domaine_parent ---


@pytest.mark.parametrize(
    ("qname", "attendu"),
    [
        ("www.example.com", "example.com"),
        ("a.b.c.attaquant.example", "attaquant.example"),
        ("example.com.", "example.com"),
        ("localhost", "localhost"),
        ("", "(racine)"),
    ],
)
def test_domaine_parent(qname, attendu):
    assert domaine_parent(qname) == attendu


def test_domaine_parent_nom_coupe():
    assert domaine_parent("0.AbCd", tronque=True) == NOM_INCOMPLET


# --- liste blanche ---


@pytest.mark.parametrize(
    ("qname", "autorise"),
    [
        ("d1234abcd.cloudfront.net", True),
        ("cloudfront.net", True),
        ("A.B.CLOUDFRONT.NET.", True),
        ("evilcloudfront.net", False),  # pas un sous-domaine
        ("cloudfront.net.attaquant.example", False),
    ],
)
def test_est_autorise(qname, autorise):
    assert est_autorise(qname, ["cloudfront.net"]) is autorise


def test_lire_liste_blanche(tmp_path):
    fichier = tmp_path / "blanche.txt"
    fichier.write_text("# CDN internes\ncdn.entreprise.fr\n\n  Partenaire.COM  \n   # retrait\n")

    assert lire_liste_blanche(fichier) == ["cdn.entreprise.fr", "partenaire.com"]


def test_liste_blanche_par_defaut_contient_des_cdn():
    assert "cloudfront.net" in LISTE_BLANCHE
    assert all(d == d.lower() and not d.startswith(".") for d in LISTE_BLANCHE)


# --- alertes ---


def test_alerte_au_dela_du_minimum():
    df = requetes(*tunnel(5))

    resume = alertes(df, min_requetes=5)

    assert list(resume.columns) == COLONNES_ALERTES
    assert resume["domaine"].tolist() == ["attaquant.example"]
    ligne = resume.iloc[0]
    assert ligne["requetes_suspectes"] == 5
    assert ligne["sources"] == 1
    assert (ligne["debut"], ligne["fin"]) == (0.0, 4.0)
    assert ligne["score_moyen"] == pytest.approx(0.99)


def test_pas_d_alerte_sous_le_minimum():
    resume = alertes(requetes(*tunnel(4)), min_requetes=5)

    assert resume.empty
    assert list(resume.columns) == COLONNES_ALERTES


def test_faux_positifs_isoles_ignores():
    # noms longs suspects mais tous vers des domaines différents : pas de tunnel
    df = requetes(*[(i, "10.0.0.3", f"x{i}AbCdEf0123456789.site{i}.com", 0.9) for i in range(10)])

    assert alertes(df, min_requetes=3).empty


def test_requetes_sous_le_seuil_non_comptees():
    df = requetes(*tunnel(5, score=0.4), *tunnel(2, debut=100))

    assert alertes(df, seuil=0.5, min_requetes=3).empty
    assert len(alertes(df, seuil=0.3, min_requetes=3)) == 1


def test_liste_blanche_supprime_l_alerte():
    df = requetes(*tunnel(10, domaine="cloudfront.net"))

    assert alertes(df, min_requetes=5).empty
    assert len(alertes(df, min_requetes=5, liste_blanche=[])) == 1


def test_plusieurs_alertes_triees_et_sources_comptees():
    df = requetes(
        *tunnel(3, domaine="petit.example"),
        *tunnel(4, domaine="gros.example", src="10.0.0.2"),
        *tunnel(4, domaine="gros.example", src="10.0.0.9", debut=50),
    )

    resume = alertes(df, min_requetes=3)

    assert resume["domaine"].tolist() == ["gros.example", "petit.example"]
    assert resume["requetes_suspectes"].tolist() == [8, 3]
    assert resume["sources"].tolist() == [2, 1]


def test_noms_coupes_regroupes():
    df = requetes(*[(i, "10.0.0.2", f"{i}.AbCdEf0123456789xyz", 0.99, None) for i in range(6)])

    assert alertes(df, min_requetes=5)["domaine"].tolist() == [NOM_INCOMPLET]


def test_alertes_sur_tableau_vide():
    assert alertes(requetes(), min_requetes=1).empty


# --- branchement dans exfildns scan ---


def test_scan_affiche_les_alertes(tmp_path, modele, capsys):
    capture = tmp_path / "capture.pcap"
    paquets = [requete(q) for q in noms_benins(10, graine=7)]
    paquets += [requete(q, dst="10.6.6.6") for q in noms_exfil(6, graine=7)]
    ecrire_pcap(capture, paquets)

    assert main(["scan", str(capture), "-m", str(modele), "--min-requetes", "5"]) == 1

    sortie = capsys.readouterr().out
    assert "Alertes : domaines ayant reçu au moins 5 requêtes suspectes (1)" in sortie
    assert any(
        "attaquant.example" in ligne and ligne.split()[-1] == "6" for ligne in sortie.splitlines()
    )


def test_scan_liste_blanche(tmp_path, modele, capsys):
    capture = tmp_path / "capture.pcap"
    ecrire_pcap(capture, [requete(q, dst="10.6.6.6") for q in noms_exfil(6, graine=8)])
    blanche = tmp_path / "blanche.txt"
    blanche.write_text("attaquant.example\n")

    code = main(["scan", str(capture), "-m", str(modele), "--liste-blanche", str(blanche)])

    # les requêtes restent listées comme suspectes, mais aucune alerte n'est levée
    assert code == 0
    sortie = capsys.readouterr().out
    assert "6 suspectes" in sortie
    assert "requêtes suspectes (0)" in sortie


def test_alertes_a_egalite_triees_par_nom():
    df = requetes(*tunnel(3, domaine="zz.example"), *tunnel(3, domaine="aa.example", debut=10))

    assert alertes(df, min_requetes=3)["domaine"].tolist() == ["aa.example", "zz.example"]


def test_est_autorise_normalise_la_liste():
    assert est_autorise("x.cdn.fr", ["CDN.fr."])


def test_scan_sans_alerte_code_0(tmp_path, modele, capsys):
    # deux requêtes suspectes seulement : listées, mais pas d'alerte, donc code 0
    capture = tmp_path / "capture.pcap"
    ecrire_pcap(capture, [requete(q, dst="10.6.6.6") for q in noms_exfil(2, graine=9)])

    assert main(["scan", str(capture), "-m", str(modele)]) == 0
    assert "2 suspectes" in capsys.readouterr().out


def test_scan_liste_blanche_introuvable_signalee_avant_l_analyse(tmp_path, modele):
    with pytest.raises(FileNotFoundError):
        main(["scan", str(tmp_path / "absente.pcap"), "--liste-blanche", str(tmp_path / "x.txt")])
