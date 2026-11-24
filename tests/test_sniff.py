import os
import signal
import sqlite3

import pytest
from conftest import NOM_EXFIL, noms_benins, noms_exfil, requete
from scapy.config import conf
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from exfildns.cli import main
from exfildns.model import charger
from exfildns.sniff import FILTRE_BPF, enregistrer, lots_reseau, noter, ouvrir_base, surveiller


def recu(paquet, instant=1000.0):
    """Paquet tel que le renvoie sniff() : disséqué depuis des octets, avec son heure."""
    paquet = Ether(bytes(paquet))
    paquet.time = instant
    return paquet


def lignes(base):
    with sqlite3.connect(base) as connexion:
        return connexion.execute("SELECT src, dst, qname, qtype, score FROM requetes").fetchall()


@pytest.fixture(scope="module")
def reseau(modele):
    return charger(modele)


# --- base SQLite ---


def test_ouvrir_base_cree_la_table_et_le_dossier(tmp_path):
    base = tmp_path / "sous" / "dossier" / "detections.db"

    connexion = ouvrir_base(base)

    colonnes = [c[1] for c in connexion.execute("PRAGMA table_info(requetes)")]
    assert colonnes == ["timestamp", "src", "dst", "qname", "qtype", "score"]
    assert connexion.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    connexion.close()


def test_ouvrir_base_garde_les_donnees_existantes(tmp_path, reseau):
    base = tmp_path / "detections.db"
    connexion = ouvrir_base(base)
    enregistrer(connexion, noter(reseau, [recu(requete("a.fr"))]))
    connexion.close()

    ouvrir_base(base).close()

    assert len(lignes(base)) == 1


# --- noter ---


def test_noter_separe_exfiltration_et_trafic_normal(reseau):
    paquets = [recu(requete(q)) for q in noms_benins(5, graine=4)]
    paquets += [recu(requete(q, dst="10.6.6.6")) for q in noms_exfil(5, graine=4)]

    requetes = noter(reseau, paquets)

    assert len(requetes) == 10
    assert (requetes.loc[requetes["dst"] == "8.8.8.8", "score"] < 0.5).all()
    assert (requetes.loc[requetes["dst"] == "10.6.6.6", "score"] >= 0.5).all()


def test_noter_ignore_les_paquets_non_dns(reseau):
    paquets = [recu(Ether() / IP() / TCP(dport=443)), recu(requete("a.fr"))]

    requetes = noter(reseau, paquets)

    assert requetes["qname"].tolist() == ["a.fr"]


def test_noter_paquet_tronque(reseau):
    paquet = Ether(bytes(requete(NOM_EXFIL, dst="10.6.6.6"))[:96])
    paquet.time = 1.0

    requetes = noter(reseau, [paquet])

    assert requetes.loc[0, "score"] >= 0.5
    assert requetes["qtype"].isna().all()


def test_noter_lot_vide(reseau):
    requetes = noter(reseau, [])

    assert requetes.empty
    assert "score" in requetes.columns


# --- enregistrer ---


def test_enregistrer_type_inconnu_en_null(tmp_path, reseau):
    base = tmp_path / "detections.db"
    paquet = Ether(bytes(requete(NOM_EXFIL))[:96])
    paquet.time = 1.0
    connexion = ouvrir_base(base)

    enregistrer(connexion, noter(reseau, [recu(requete("a.fr", qtype="TXT")), paquet]))

    types = [ligne[3] for ligne in lignes(base)]
    assert types == [16, None]


# --- surveiller ---


def test_surveiller_enregistre_tout_et_affiche_les_suspectes(tmp_path, reseau):
    base = tmp_path / "detections.db"
    lots = [
        [recu(requete(q)) for q in noms_benins(4, graine=5)],
        [],  # seconde sans trafic DNS
        [recu(requete(q, dst="10.6.6.6")) for q in noms_exfil(3, graine=5)],
    ]
    affiche = []

    bilan = surveiller(lots, reseau, ouvrir_base(base), seuil=0.5, afficher=affiche.append)

    assert bilan == (7, 3)
    assert len(lignes(base)) == 7
    assert len(affiche) == 3
    assert all("-> 10.6.6.6" in ligne and "attaquant.example" in ligne for ligne in affiche)


def test_surveiller_seuil(tmp_path, reseau):
    lots = [[recu(requete(q)) for q in noms_benins(4, graine=6)]]

    _, suspectes = surveiller(lots, reseau, ouvrir_base(tmp_path / "d.db"), seuil=0.0)

    assert suspectes == 4  # seuil 0 : tout est signalé


def test_surveiller_s_arrete_proprement_sur_ctrl_c(tmp_path, reseau):
    base = tmp_path / "detections.db"

    def lots():
        yield [recu(requete("a.fr")), recu(requete("b.fr"))]
        raise KeyboardInterrupt

    bilan = surveiller(lots(), reseau, ouvrir_base(base), seuil=0.5, afficher=lambda _: None)

    assert bilan == (2, 0)
    assert len(lignes(base)) == 2


# --- commande exfildns sniff (capture remplacée par des lots synthétiques) ---


def test_cli_sniff(tmp_path, modele, monkeypatch, capsys):
    base = tmp_path / "detections.db"
    interfaces = []

    def faux_reseau(interface):
        interfaces.append(interface)
        yield [recu(requete("a.fr")), recu(requete(NOM_EXFIL, dst="10.6.6.6"))]
        raise KeyboardInterrupt

    monkeypatch.setattr("exfildns.cli.lots_reseau", faux_reseau)

    code = main(["sniff", "-i", "eth0", "-m", str(modele), "--base", str(base)])

    sortie = capsys.readouterr().out
    assert code == 0
    assert interfaces == ["eth0"]
    assert "10.6.6.6" in sortie
    assert "2 requêtes analysées, 1 suspectes" in sortie
    assert len(lignes(base)) == 2


def test_cli_sniff_sans_droits(tmp_path, modele, monkeypatch, capsys):
    def sans_droits(interface):
        raise PermissionError(1, "Operation not permitted")
        yield

    monkeypatch.setattr("exfildns.cli.lots_reseau", sans_droits)

    code = main(["sniff", "-m", str(modele), "--base", str(tmp_path / "d.db")])

    assert code == 2
    assert "CAP_NET_RAW" in capsys.readouterr().err


def test_cli_sniff_interface_inconnue(tmp_path, modele, monkeypatch, capsys):
    def inconnue(interface):
        raise ValueError(f"Interface '{interface}' not found !")
        yield

    monkeypatch.setattr("exfildns.cli.lots_reseau", inconnue)

    code = main(["sniff", "-i", "eth9", "-m", str(modele), "--base", str(tmp_path / "d.db")])

    assert code == 2
    assert "eth9" in capsys.readouterr().err


def test_cli_sniff_modele_absent(tmp_path, capsys):
    code = main(["sniff", "-m", str(tmp_path / "absent.keras"), "--base", str(tmp_path / "d.db")])

    assert code == 2
    assert "Modèle introuvable" in capsys.readouterr().err
    assert not (tmp_path / "d.db").exists()


# --- lots_reseau (socket de capture remplacé par un tube, pour select) ---


class FauxSocket:
    """Imite le socket de capture de scapy : un octet écrit dans le tube = un paquet reçu."""

    ouverts: list["FauxSocket"] = []

    def __init__(self, iface, filter):
        self.iface, self.filtre = iface, filter
        self.paquets = []
        self.lecture, self.ecriture = os.pipe()
        self.ferme = False
        FauxSocket.ouverts.append(self)

    def fileno(self):
        return self.lecture

    def recevoir(self, paquet):
        self.paquets.append(paquet)
        os.write(self.ecriture, b"x")

    def recv(self):
        os.read(self.lecture, 1)
        return self.paquets.pop(0)

    def close(self):
        self.ferme = True
        os.close(self.lecture)
        os.close(self.ecriture)


@pytest.fixture
def faux_socket(monkeypatch):
    monkeypatch.setattr(FauxSocket, "ouverts", [])
    monkeypatch.setattr("exfildns.sniff.conf.L2listen", FauxSocket)
    return FauxSocket.ouverts


def test_lots_reseau_regroupe_les_paquets_par_lot(faux_socket):
    lots = lots_reseau("eth0", duree_lot=0.05)
    premier = next(lots)  # ouvre le socket ; aucun paquet pendant ce lot
    socket = faux_socket[0]
    socket.recevoir("p1")
    socket.recevoir("p2")

    second = next(lots)

    assert premier == []
    assert second == ["p1", "p2"]
    assert socket.filtre == FILTRE_BPF
    lots.close()
    assert socket.ferme


def test_lots_reseau_interface_par_defaut(faux_socket):
    lots = lots_reseau(duree_lot=0.01)
    next(lots)

    assert faux_socket[0].iface == conf.iface
    lots.close()


def test_lots_reseau_bouclage_ne_garde_que_l_entrant(faux_socket):
    lots = lots_reseau("lo", duree_lot=0.01)
    next(lots)

    assert faux_socket[0].filtre == f"inbound and {FILTRE_BPF}"
    lots.close()


def test_cli_sniff_s_arrete_proprement_sur_sigterm(tmp_path, modele, monkeypatch, capsys):
    # `docker stop` envoie SIGTERM : la capture doit s'arrêter comme sur Ctrl+C
    base = tmp_path / "detections.db"

    def reseau_puis_sigterm(interface):
        yield [recu(requete("a.fr"))]
        os.kill(os.getpid(), signal.SIGTERM)
        yield [recu(requete("jamais.fr"))]

    monkeypatch.setattr("exfildns.cli.lots_reseau", reseau_puis_sigterm)
    precedent = signal.getsignal(signal.SIGTERM)
    try:
        code = main(["sniff", "-m", str(modele), "--base", str(base)])
    finally:
        signal.signal(signal.SIGTERM, precedent)

    assert code == 0
    assert "1 requêtes analysées" in capsys.readouterr().out
    assert [ligne[2] for ligne in lignes(base)] == ["a.fr"]
