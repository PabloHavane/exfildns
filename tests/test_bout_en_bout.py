"""Test de bout en bout : PCAP d'entraînement → train → scan d'une nouvelle capture."""

from conftest import ecrire_pcap, noms_benins, noms_exfil, requete

from exfildns.cli import main


def test_train_puis_scan_detecte_le_tunneling(dossier_donnees, tmp_path, capsys):
    modele = tmp_path / "exfildns.keras"
    assert main(["train", str(dossier_donnees), "-o", str(modele), "--epochs", "50"]) == 0

    # Nouvelle capture, jamais vue : trafic normal + tunneling vers un autre serveur
    capture = tmp_path / "nouvelle_capture.pcap"
    paquets = [requete(q) for q in noms_benins(15, graine=40)]
    paquets += [requete(q, dst="10.6.6.6") for q in noms_exfil(10, graine=40)]
    ecrire_pcap(capture, paquets, snaplen=96)
    capsys.readouterr()

    code = main(["scan", str(capture), "-m", str(modele), "--max", "50"])

    sortie = capsys.readouterr().out
    assert code == 1
    assert "25 requêtes DNS analysées, 10 suspectes" in sortie
    lignes_suspectes = sortie.split("plus probables) :")[1].strip().splitlines()
    assert len(lignes_suspectes) == 10
    assert all("-> 10.6.6.6" in ligne for ligne in lignes_suspectes)
