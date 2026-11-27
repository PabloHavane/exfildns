import os
import signal

import pytest
from conftest import NOM_EXFIL, noms_benins

from exfildns.cli import main
from exfildns.journal import RESOLVEUR, lots_journal, requete_journal
from exfildns.model import charger
from exfildns.sniff import noter, ouvrir_base, surveiller


def ligne(nom, client="192.168.1.20", type_="A", instant=1764158400):
    return f"[{instant}] unbound[812:0] info: {client} {nom}. {type_} IN"


@pytest.fixture(autouse=True)
def restaurer_sigterm():
    """`exfildns sniff` détourne SIGTERM : on remet le gestionnaire de pytest après chaque test."""
    precedent = signal.getsignal(signal.SIGTERM)
    yield
    signal.signal(signal.SIGTERM, precedent)


@pytest.fixture(scope="module")
def reseau_modele(modele):
    return charger(modele)


# --- décodage d'une ligne ---


def test_requete_journal():
    assert requete_journal(ligne("www.exemple.fr")) == (
        1764158400.0, "192.168.1.20", RESOLVEUR, "www.exemple.fr", 1, None,
    )  # fmt: skip


@pytest.mark.parametrize(
    ("type_", "qtype"), [("TXT", 16), ("AAAA", 28), ("NULL", 10), ("TYPE99", 99), ("NAPTR", None)]
)
def test_requete_journal_types(type_, qtype):
    assert requete_journal(ligne("a.fr", type_=type_))[4] == qtype


def test_requete_journal_client_ipv6_et_fin_de_ligne():
    resultat = requete_journal(ligne("a.fr", client="fd00::20") + "\r\n")

    assert resultat[1] == "fd00::20"


def test_requete_journal_racine():
    assert requete_journal("[1] unbound[1:0] info: 10.0.0.1 . NS IN")[3] == ""


@pytest.mark.parametrize(
    "texte",
    [
        "",
        "[1764158400] unbound[812:0] info: start of service (unbound 1.22.0).",
        ligne("a.fr") + " NOERROR 0.000123 0 45",  # réponse (log-replies) : déjà comptée
        "Nov 26 13:00:00 unbound[812:0] info: 192.168.1.20 a.fr. A IN",  # log-time-ascii
        "[1764158400] unbound[812:0] info: 192.168.1.20 a.fr. A CH",  # classe CHAOS
    ],
)
def test_requete_journal_lignes_ignorees(texte):
    assert requete_journal(texte) is None


def test_noter_lignes_de_journal_meme_score_que_le_reseau(reseau_modele):
    lignes = [ligne(q) for q in noms_benins(5, graine=1)] + [ligne(NOM_EXFIL), "bruit"]

    requetes = noter(reseau_modele, lignes, requete_journal)

    assert len(requetes) == 6
    assert requetes["taille"].isna().all()
    assert requetes["score"].iloc[-1] > 0.5 > requetes["score"].iloc[:5].max()


# --- suivi du fichier ---


@pytest.fixture
def journal(tmp_path):
    chemin = tmp_path / "unbound.log"
    chemin.write_text(ligne("ancienne.fr") + "\n")
    return chemin


def ecrire(chemin, texte):
    with open(chemin, "a") as f:
        f.write(texte)


def test_lots_journal_part_de_la_fin(journal):
    lots = lots_journal(journal, duree_lot=0)
    ecrire(journal, ligne("nouvelle.fr") + "\n")

    assert next(lots) == [ligne("nouvelle.fr")]
    assert next(lots) == []  # rien de nouveau
    lots.close()


def test_lots_journal_depuis_le_debut(journal):
    assert next(lots_journal(journal, duree_lot=0, depuis_debut=True)) == [ligne("ancienne.fr")]


def test_lots_journal_ligne_incomplete_attendue(journal):
    lots = lots_journal(journal, duree_lot=0)
    ecrire(journal, ligne("coupee.fr")[:20])
    assert next(lots) == []

    ecrire(journal, ligne("coupee.fr")[20:] + "\n")

    assert next(lots) == [ligne("coupee.fr")]


def test_lots_journal_rotation(journal):
    lots = lots_journal(journal, duree_lot=0)
    ecrire(journal, ligne("avant.fr") + "\n")
    os.rename(journal, journal.with_suffix(".log.1"))
    journal.write_text(ligne("apres.fr") + "\n")

    assert next(lots) == [ligne("avant.fr")]  # fin de l'ancien fichier
    assert next(lots) == [ligne("apres.fr")]  # puis le nouveau, depuis le début


def test_lots_journal_troncature(journal):
    lots = lots_journal(journal, duree_lot=0)
    ecrire(journal, ligne("x.fr") + "\n")
    next(lots)
    journal.write_text("")  # vidé (copytruncate)
    next(lots)
    ecrire(journal, ligne("y.fr") + "\n")

    assert next(lots) == [ligne("y.fr")]


def test_lots_journal_absent(tmp_path):
    with pytest.raises(FileNotFoundError):
        lots_journal(tmp_path / "absent.log")


def test_surveiller_journal(journal, reseau_modele, tmp_path):
    lots = [[ligne("a.fr"), ligne(NOM_EXFIL, client="192.168.1.66")], []]
    affiche = []

    bilan = surveiller(
        lots, reseau_modele, ouvrir_base(tmp_path / "d.db"), 0.5,
        afficher=affiche.append, decoder=requete_journal,
    )  # fmt: skip

    assert bilan == (2, 1)
    assert affiche[0].endswith(f"192.168.1.66 -> {RESOLVEUR}  {NOM_EXFIL}")


# --- commande exfildns sniff --journal ---


def test_cli_sniff_journal(journal, modele, tmp_path, monkeypatch, capsys):
    base = tmp_path / "detections.db"

    def lots_puis_arret(chemin):
        assert str(chemin) == str(journal)
        yield [ligne("a.fr"), ligne(NOM_EXFIL)]
        raise KeyboardInterrupt

    monkeypatch.setattr("exfildns.cli.lots_journal", lots_puis_arret)

    code = main(["sniff", "--journal", str(journal), "-m", str(modele), "--base", str(base)])

    sortie = capsys.readouterr().out
    assert code == 0
    assert f"Capture DNS sur le journal {journal}" in sortie
    assert "2 requêtes analysées, 1 suspectes" in sortie
    lignes = ouvrir_base(base).execute("SELECT src, dst, taille FROM requetes").fetchall()
    assert lignes[0] == ("192.168.1.20", RESOLVEUR, None)


def test_cli_sniff_journal_absent(tmp_path, modele, capsys):
    code = main(["sniff", "--journal", str(tmp_path / "absent.log"), "-m", str(modele)])

    assert code == 2
    assert "Journal illisible" in capsys.readouterr().err


def test_cli_sniff_journal_et_interface_exclusifs(journal, modele, capsys):
    with pytest.raises(SystemExit):
        main(["sniff", "-i", "eth0", "--journal", str(journal), "-m", str(modele)])

    assert "not allowed with" in capsys.readouterr().err
