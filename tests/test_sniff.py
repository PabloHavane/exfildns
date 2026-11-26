import os
import signal
import sqlite3

import pytest
from conftest import NOM_EXFIL, noms_benins, noms_exfil, requete
from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from exfildns.cli import main
from exfildns.model import charger
from exfildns.sniff import (
    FILTRE_BPF,
    PERIODE_PURGE,
    enregistrer,
    lots_reseau,
    noter,
    ouvrir_base,
    purger,
    surveiller,
)


def recu(paquet, instant=1000.0):
    """Paquet tel que le renvoie sniff() : disséqué depuis des octets, avec son heure."""
    paquet = Ether(bytes(paquet))
    paquet.time = instant
    return paquet


def lignes(base):
    with sqlite3.connect(base) as connexion:
        return connexion.execute("SELECT src, dst, qname, qtype, score FROM requetes").fetchall()


@pytest.fixture(autouse=True)
def restaurer_sigterm():
    """`exfildns sniff` détourne SIGTERM : on remet le gestionnaire de pytest après chaque test."""
    precedent = signal.getsignal(signal.SIGTERM)
    yield
    signal.signal(signal.SIGTERM, precedent)


@pytest.fixture(scope="module")
def reseau(modele):
    return charger(modele)


# --- base SQLite ---


def test_ouvrir_base_cree_la_table_et_le_dossier(tmp_path):
    base = tmp_path / "sous" / "dossier" / "detections.db"

    connexion = ouvrir_base(base)

    colonnes = [c[1] for c in connexion.execute("PRAGMA table_info(requetes)")]
    assert colonnes == ["timestamp", "src", "dst", "qname", "qtype", "score", "taille"]
    assert connexion.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    connexion.close()


def test_ouvrir_base_garde_les_donnees_existantes(tmp_path, reseau):
    base = tmp_path / "detections.db"
    connexion = ouvrir_base(base)
    enregistrer(connexion, noter(reseau, [recu(requete("a.fr"))]))
    connexion.close()

    ouvrir_base(base).close()

    assert len(lignes(base)) == 1


ANCIEN_SCHEMA = """CREATE TABLE requetes (timestamp REAL NOT NULL, src TEXT NOT NULL,
    dst TEXT NOT NULL, qname TEXT NOT NULL, qtype INTEGER, score REAL NOT NULL)"""


def test_ouvrir_base_migre_une_base_anterieure(tmp_path, reseau):
    base = tmp_path / "detections.db"
    with sqlite3.connect(base) as ancienne:
        ancienne.execute(ANCIEN_SCHEMA)
        ancienne.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 'x.fr', 1, 0.1)")
    ancienne.close()

    connexion = ouvrir_base(base)
    enregistrer(connexion, noter(reseau, [recu(requete("a.fr"))]))
    connexion.close()

    with sqlite3.connect(base) as lecture:
        tailles = lecture.execute("SELECT qname, taille FROM requetes ORDER BY rowid").fetchall()
    lecture.close()
    assert tailles[0] == ("x.fr", None)  # ligne existante conservée, sans taille
    assert tailles[1][0] == "a.fr" and tailles[1][1] > 0


def test_ouvrir_base_migration_idempotente(tmp_path):
    base = tmp_path / "detections.db"
    ouvrir_base(base).close()

    connexion = ouvrir_base(base)  # la colonne existe déjà : pas de second ALTER

    colonnes = [c[1] for c in connexion.execute("PRAGMA table_info(requetes)")]
    assert colonnes.count("taille") == 1
    connexion.close()


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


def test_enregistrer_taille_du_message(tmp_path, reseau):
    base = tmp_path / "detections.db"
    court, long = recu(requete("a.fr")), recu(requete("un-nom-bien-plus-long.example.com"))
    connexion = ouvrir_base(base)

    enregistrer(connexion, noter(reseau, [court, long]))

    with sqlite3.connect(base) as lecture:
        tailles = [t for (t,) in lecture.execute("SELECT taille FROM requetes ORDER BY rowid")]
    lecture.close()
    assert tailles == [len(court[UDP].payload), len(long[UDP].payload)]


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


# --- rétention ---

JOUR = 86400


def base_datee(tmp_path, reseau, instants):
    """Base contenant une requête bénigne par instant donné."""
    connexion = ouvrir_base(tmp_path / "d.db")
    paquets = [recu(requete(f"r{i}.fr"), instant=t) for i, t in enumerate(instants)]
    enregistrer(connexion, noter(reseau, paquets))
    return connexion


def instants_restants(connexion):
    return sorted(t for (t,) in connexion.execute("SELECT timestamp FROM requetes"))


def test_purger_supprime_seulement_les_requetes_trop_anciennes(tmp_path, reseau):
    maintenant = 100 * JOUR
    connexion = base_datee(tmp_path, reseau, [maintenant - 40 * JOUR, maintenant - 10 * JOUR])

    supprimees = purger(connexion, 30, maintenant)

    assert supprimees == 1
    assert instants_restants(connexion) == [maintenant - 10 * JOUR]


def test_purger_limite_exacte_conservee(tmp_path, reseau):
    maintenant = 100 * JOUR
    connexion = base_datee(tmp_path, reseau, [maintenant - 30 * JOUR])

    assert purger(connexion, 30, maintenant) == 0


def test_purger_base_vide(tmp_path):
    assert purger(ouvrir_base(tmp_path / "d.db"), 30, 100 * JOUR) == 0


def test_purger_fraction_de_jour(tmp_path, reseau):
    maintenant = 100 * JOUR
    connexion = base_datee(tmp_path, reseau, [maintenant - 3600 * 13, maintenant - 3600 * 11])

    assert purger(connexion, 0.5, maintenant) == 1  # 12 h


def test_surveiller_purge_au_demarrage_puis_periodiquement(tmp_path, reseau):
    maintenant = [100 * JOUR]
    connexion = base_datee(tmp_path, reseau, [maintenant[0] - 40 * JOUR])

    def lots():
        yield []  # purge au démarrage
        assert instants_restants(connexion) == []
        enregistrer(connexion, noter(reseau, [recu(requete("x.fr"), instant=maintenant[0])]))
        maintenant[0] += 31 * JOUR
        assert PERIODE_PURGE < 31 * JOUR
        yield []  # période écoulée : nouvelle purge

    surveiller(lots(), reseau, connexion, 0.5, retention_jours=30, horloge=lambda: maintenant[0])

    assert instants_restants(connexion) == []


def test_surveiller_ne_purge_pas_avant_la_periode(tmp_path, reseau):
    maintenant = [100 * JOUR]
    connexion = base_datee(tmp_path, reseau, [])

    def lots():
        yield []
        enregistrer(connexion, noter(reseau, [recu(requete("x.fr"), instant=maintenant[0])]))
        maintenant[0] += PERIODE_PURGE - 1  # la requête devient trop vieille, période non écoulée
        yield []

    surveiller(
        lots(),
        reseau,
        connexion,
        0.5,
        retention_jours=PERIODE_PURGE / 2 / JOUR,
        horloge=lambda: maintenant[0],
    )

    assert len(instants_restants(connexion)) == 1


def test_surveiller_sans_retention_garde_tout(tmp_path, reseau):
    connexion = base_datee(tmp_path, reseau, [1.0])

    surveiller([[]], reseau, connexion, 0.5, horloge=lambda: 100 * JOUR)

    assert instants_restants(connexion) == [1.0]


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


def test_cli_sniff_retention(tmp_path, modele, monkeypatch):
    base = tmp_path / "detections.db"
    retentions = []

    def faux_surveiller(lots, modele, connexion, seuil, retention_jours=None):
        retentions.append(retention_jours)
        return 0, 0

    monkeypatch.setattr("exfildns.cli.lots_reseau", lambda interface: iter([]))
    monkeypatch.setattr("exfildns.cli.surveiller", faux_surveiller)

    main(["sniff", "-m", str(modele), "--base", str(base), "--retention", "30"])
    main(["sniff", "-m", str(modele), "--base", str(base)])

    assert retentions == [30.0, None]


@pytest.mark.parametrize("valeur", ["0", "-3", "abc", "nan"])
def test_cli_sniff_retention_invalide(tmp_path, modele, valeur, capsys):
    with pytest.raises(SystemExit) as sortie:
        main(["sniff", "-m", str(modele), "--retention", valeur])

    assert sortie.value.code == 2
    assert "nombre positif" in capsys.readouterr().err


def test_cli_sniff_sans_droits(tmp_path, modele, monkeypatch, capsys):
    def sans_droits(interface):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr("exfildns.cli.lots_reseau", sans_droits)

    code = main(["sniff", "-m", str(modele), "--base", str(tmp_path / "d.db")])

    assert code == 2
    assert "CAP_NET_RAW" in capsys.readouterr().err


def test_cli_sniff_interface_inconnue(tmp_path, modele, monkeypatch, capsys):
    def inconnue(interface):
        raise ValueError(f"Interface '{interface}' not found !")

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

    code = main(["sniff", "-m", str(modele), "--base", str(base)])

    assert code == 0
    assert "1 requêtes analysées" in capsys.readouterr().out
    assert [ligne[2] for ligne in lignes(base)] == ["a.fr"]


def test_cli_sniff_sans_libpcap(tmp_path, modele, monkeypatch, capsys):
    def sans_libpcap(interface):
        raise Scapy_Exception("Cannot set filter: libpcap is not available")

    monkeypatch.setattr("exfildns.cli.lots_reseau", sans_libpcap)

    code = main(["sniff", "-m", str(modele), "--base", str(tmp_path / "d.db")])

    assert code == 2
    assert "libpcap" in capsys.readouterr().err


def test_cli_sniff_erreur_du_modele_non_masquee(tmp_path, modele, monkeypatch):
    # une erreur pendant la notation n'est pas confondue avec une erreur de capture
    def lots(interface):
        yield [recu(requete("a.fr"))]

    def modele_casse(*_):
        raise ValueError("nombre de features incohérent")

    monkeypatch.setattr("exfildns.cli.lots_reseau", lots)
    monkeypatch.setattr("exfildns.sniff.predire_proba", modele_casse)

    with pytest.raises(ValueError, match="features incohérent"):
        main(["sniff", "-m", str(modele), "--base", str(tmp_path / "d.db")])


def test_lots_reseau_erreur_de_capture_immediate(monkeypatch):
    def refuse(iface, filter):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr("exfildns.sniff.conf.L2listen", refuse)

    with pytest.raises(PermissionError):
        lots_reseau("eth0")  # sans attendre la première lecture
