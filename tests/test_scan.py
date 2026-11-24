from conftest import ecrire_pcap, noms_benins, noms_exfil, requete
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from exfildns.cli import domaine_parent, main


def test_scan_detecte_l_exfiltration(tmp_path, modele, capsys):
    capture = tmp_path / "capture.pcap"
    paquets = [requete(q) for q in noms_benins(20, graine=2)]
    paquets += [requete(q, dst="10.6.6.6") for q in noms_exfil(5, graine=2)]
    ecrire_pcap(capture, paquets)

    code = main(["scan", str(capture), "-m", str(modele)])

    sortie = capsys.readouterr().out
    assert code == 1
    assert "25 requêtes DNS analysées, 5 suspectes" in sortie
    assert "10.6.6.6" in sortie
    lignes = sortie.splitlines()
    assert any("attaquant.example" in ligne and ligne.split()[-1] == "5" for ligne in lignes)


def test_scan_trafic_normal(tmp_path, modele, capsys):
    capture = tmp_path / "normal.pcap"
    ecrire_pcap(capture, [requete(q) for q in noms_benins(20, graine=3)])

    assert main(["scan", str(capture), "-m", str(modele)]) == 0
    assert "0 suspectes" in capsys.readouterr().out


def test_scan_sans_dns(tmp_path, modele, capsys):
    capture = tmp_path / "vide.pcap"
    ecrire_pcap(capture, [Ether() / IP() / TCP(dport=443)])

    assert main(["scan", str(capture), "-m", str(modele)]) == 0
    assert "Aucune requête DNS" in capsys.readouterr().out


def test_scan_modele_absent(tmp_path, capsys):
    capture = tmp_path / "capture.pcap"
    ecrire_pcap(capture, [requete("example.com")])

    assert main(["scan", str(capture), "-m", str(tmp_path / "absent.keras")]) == 2
    assert "Modèle introuvable" in capsys.readouterr().err


def test_domaine_parent():
    assert domaine_parent("www.example.com", tronque=False) == "example.com"
    assert domaine_parent("0.AbCd", tronque=True).startswith("(nom incomplet")
    assert domaine_parent("", tronque=False) == "(racine)"
