import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pandas as pd
import pytest
from conftest import ecrire_pcap, noms_benins, noms_exfil, requete
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from streamlit.testing.v1 import AppTest

from exfildns import dashboard
from exfildns.alertes import alertes
from exfildns.cli import main
from exfildns.dashboard import (
    activite_par_minute,
    analyser_capture,
    classement,
    en_heure,
    graphique_activite,
    indicateurs,
    lire_requetes,
    tableau_alertes,
    tableau_requetes,
)
from exfildns.features import features_dataframe
from exfildns.model import charger, predire_proba
from exfildns.pcap import read_dns_queries
from exfildns.sniff import ouvrir_base

FICHIER_APP = str(Path(dashboard.__file__))


def remplir(base, lignes):
    """Écrit des lignes (timestamp, src, dst, qname, qtype, score) comme le ferait sniff."""
    connexion = ouvrir_base(base)
    with connexion:
        connexion.executemany("INSERT INTO requetes VALUES (?, ?, ?, ?, ?, ?)", lignes)
    connexion.close()


@pytest.fixture
def base_demo(tmp_path):
    """Deux postes qui naviguent, un poste qui exfiltre, une vieille requête et un CDN."""
    maintenant = time.time()  # au moment du test : l'app filtre par rapport à l'heure courante
    lignes = [
        (maintenant - 120 + i, f"10.0.0.{1 + i % 2}", "10.0.0.254", f"site{i}.fr", 1, 0.01)
        for i in range(20)
    ]
    lignes += [
        (
            maintenant - 60 + i,
            "10.0.0.66",
            "10.0.0.254",
            f"{i}.AbCdEf0123.attaquant.example",
            16,
            0.97,
        )
        for i in range(8)
    ]
    lignes.append((maintenant - 30, "10.0.0.1", "10.0.0.254", "d1x2y3.cloudfront.net", 1, 0.8))
    lignes.append((maintenant - 2 * 86400, "10.0.0.9", "10.0.0.254", "vieux.fr", 1, 0.02))
    base = tmp_path / "detections.db"
    remplir(base, lignes)
    return base


def app(base, monkeypatch):
    monkeypatch.setenv("EXFILDNS_BASE", str(base))
    return AppTest.from_file(FICHIER_APP, default_timeout=60)


# --- lecture de la base ---


def test_lire_requetes_toute_la_base(base_demo):
    requetes = lire_requetes(base_demo)

    assert len(requetes) == 30
    assert list(requetes.columns) == ["timestamp", "src", "dst", "qname", "qtype", "score"]
    assert requetes["timestamp"].is_monotonic_increasing
    assert requetes["qtype"].dtype == "Int64"


def test_lire_requetes_depuis_un_instant(base_demo):
    assert len(lire_requetes(base_demo, depuis=time.time() - 3600)) == 29


def test_lire_requetes_base_vide(tmp_path):
    base = tmp_path / "vide.db"
    ouvrir_base(base).close()

    requetes = lire_requetes(base)

    assert requetes.empty
    assert "score" in requetes.columns


def test_lire_requetes_en_lecture_seule(base_demo):
    lire_requetes(base_demo)
    uri = f"{base_demo.resolve().as_uri()}?mode=ro"
    with pytest.raises(sqlite3.OperationalError, match="readonly"):
        sqlite3.connect(uri, uri=True).execute("DELETE FROM requetes")


def test_lire_requetes_fichiers_non_modifiables_capture_arretee(base_demo):
    # `sniff` lancé en root puis arrêté : plus de fichier -shm, et impossible d'en créer un
    assert not Path(f"{base_demo}-shm").exists()
    for fichier in base_demo.parent.iterdir():
        fichier.chmod(0o444)
    base_demo.parent.chmod(0o555)
    try:
        assert len(lire_requetes(base_demo)) == 30
    finally:
        base_demo.parent.chmod(0o755)


def test_lire_requetes_fichiers_non_modifiables_capture_en_cours(tmp_path):
    # `sniff` lancé en root et toujours actif : -wal et -shm existent mais sont protégés
    base = tmp_path / "detections.db"
    ecrivain = ouvrir_base(base)
    with ecrivain:
        ecrivain.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 'x.fr', 1, 0.1)")
    for fichier in tmp_path.iterdir():
        fichier.chmod(0o444)
    tmp_path.chmod(0o555)
    try:
        assert len(lire_requetes(base)) == 1
    finally:
        tmp_path.chmod(0o755)
        ecrivain.close()


def test_lire_requetes_autre_erreur_non_masquee(tmp_path):
    base = tmp_path / "pas_une_base.db"
    base.write_text("ceci n'est pas une base SQLite")

    with pytest.raises(pd.errors.DatabaseError, match="not a database"):
        lire_requetes(base)


def test_lire_requetes_ecriture_en_cours(tmp_path):
    # sniff garde la base ouverte et écrit pendant que le dashboard lit
    base = tmp_path / "detections.db"
    ecrivain = ouvrir_base(base)
    with ecrivain:
        ecrivain.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 'x.fr', 1, 0.1)")

    premiere = lire_requetes(base)
    with ecrivain:
        ecrivain.execute("INSERT INTO requetes VALUES (2, 'a', 'b', 'y.fr', 1, 0.1)")

    assert len(premiere) == 1
    assert len(lire_requetes(base)) == 2
    ecrivain.close()


# --- préparation des données ---


def test_en_heure_fuseau_local():
    heures = en_heure(pd.Series([0.0, 60.0]))

    assert heures.dt.tz is not None
    assert (heures.iloc[1] - heures.iloc[0]) == pd.Timedelta(minutes=1)


def test_indicateurs(base_demo):
    requetes = lire_requetes(base_demo)
    resume = alertes(requetes, 0.5, 5)

    assert indicateurs(requetes, 0.5, resume) == {
        "analysees": 30,
        "suspectes": 9,  # le CDN suspect est compté, mais sans alerte (liste blanche)
        "alertes": 1,
        "postes": 4,
    }


def test_activite_par_minute():
    requetes = pd.DataFrame(
        {"timestamp": [0.0, 10.0, 70.0, 75.0], "score": [0.1, 0.9, 0.9, 0.2], "src": ["a"] * 4}
    )

    activite = activite_par_minute(requetes, seuil=0.5)

    assert list(activite.columns) == ["bénignes", "suspectes"]
    assert activite["bénignes"].tolist() == [1, 1]
    assert activite["suspectes"].tolist() == [1, 1]


def test_activite_par_minute_sans_suspecte():
    requetes = pd.DataFrame({"timestamp": [0.0], "score": [0.1], "src": ["a"]})

    assert activite_par_minute(requetes, 0.5)["suspectes"].tolist() == [0]


def test_activite_par_minute_vide():
    activite = activite_par_minute(pd.DataFrame(columns=["timestamp", "score"]), 0.5)

    assert activite.empty
    assert list(activite.columns) == ["bénignes", "suspectes"]


def test_classement():
    suspectes = pd.DataFrame({"src": ["a", "b", "a", "a", "c", "b"]})

    tableau = classement(suspectes, "src", "poste", n=2)

    assert tableau.values.tolist() == [["a", 3], ["b", 2]]
    assert list(tableau.columns) == ["poste", "requêtes suspectes"]


def test_tableau_alertes(base_demo):
    resume = alertes(lire_requetes(base_demo), 0.5, 5)

    tableau = tableau_alertes(resume)

    assert tableau.loc[0, "domaine"] == "attaquant.example"
    assert tableau.loc[0, "requêtes suspectes"] == 8
    assert tableau.loc[0, "postes"] == 1
    assert len(tableau.loc[0, "début"]) == len("24/11 14:00:00")


def test_tableau_requetes_plus_recentes_d_abord():
    suspectes = pd.DataFrame(
        {
            "timestamp": [1.0, 3.0, 2.0],
            "src": ["a", "b", "c"],
            "dst": ["s"] * 3,
            "qname": ["x", "y", "z"],
            "score": [0.91234, 0.8, 0.7],
        }
    )

    tableau = tableau_requetes(suspectes, n=2)

    assert tableau["nom demandé"].tolist() == ["y", "z"]
    assert list(tableau.columns) == ["heure", "score", "poste", "serveur DNS", "nom demandé"]


# --- application Streamlit (AppTest) ---


def test_app_sans_base(tmp_path, monkeypatch):
    at = app(tmp_path / "absente.db", monkeypatch).run()

    assert not at.exception
    assert "exfildns sniff" in at.info[0].value
    assert not at.metric


def test_app_base_vide(tmp_path, monkeypatch):
    base = tmp_path / "vide.db"
    ouvrir_base(base).close()

    at = app(base, monkeypatch).run()

    assert not at.exception
    assert at.metric[0].value == "0"
    assert "Aucune requête DNS" in at.info[0].value


def test_app_affiche_l_alerte(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()  # période par défaut : dernière heure

    assert not at.exception
    valeurs = {m.label: m.value for m in at.metric}
    assert valeurs == {
        "Requêtes analysées": "29",
        "Requêtes suspectes": "9",
        "Alertes": "1",
        "Postes observés": "3",
    }
    assert "attaquant.example" in at.error[0].value
    alerte = at.dataframe[0].value
    assert alerte.loc[0, "domaine"] == "attaquant.example"
    assert len(at.dataframe) == 4  # alertes, postes, serveurs, requêtes suspectes
    assert at.dataframe[1].value.iloc[0]["poste"] == "10.0.0.66"
    assert at.dataframe[2].value.columns[0] == "serveur DNS"


def test_app_seuil_plus_strict(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.slider(key="seuil").set_value(1.0).run()

    assert not at.exception
    assert {m.label: m.value for m in at.metric}["Requêtes suspectes"] == "0"
    assert at.success
    assert len(at.dataframe) == 0


def test_app_minimum_de_requetes(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.number_input(key="min_requetes").set_value(20).run()

    assert not at.exception
    assert {m.label: m.value for m in at.metric}["Alertes"] == "0"
    assert "Aucune alerte" in at.success[0].value


def test_app_periode(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.selectbox(key="periode").set_value("tout").run()
    assert {m.label: m.value for m in at.metric}["Requêtes analysées"] == "30"

    at.selectbox(key="periode").set_value("5 dernières minutes").run()
    assert {m.label: m.value for m in at.metric}["Requêtes analysées"] == "29"


def test_app_sans_rafraichissement(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.toggle(key="auto").set_value(False).run()

    assert not at.exception
    assert {m.label: m.value for m in at.metric}["Alertes"] == "1"


# --- commande exfildns dashboard ---


def test_cli_dashboard_lance_streamlit(tmp_path, monkeypatch, capsys):
    appels = []

    def faux_exec(programme, commande, env):
        assert programme == commande[0] == sys.executable  # l'interpréteur courant
        appels.append((commande, env))

    monkeypatch.setattr("exfildns.cli.os.execvpe", faux_exec)
    monkeypatch.chdir(tmp_path)

    code = main(["dashboard", "--base", "detections.db", "--port", "9000"])

    assert code == 0
    commande, env = appels[0]
    assert commande[1:4] == ["-m", "streamlit", "run"]
    assert commande[4] == FICHIER_APP
    assert commande[commande.index("--server.port") + 1] == "9000"
    assert commande[commande.index("--server.address") + 1] == "localhost"  # pas exposé
    assert commande[commande.index("--client.toolbarMode") + 1] == "viewer"
    assert env["EXFILDNS_BASE"] == str(tmp_path / "detections.db")
    assert env["EXFILDNS_MODELE"] == str(tmp_path / "models" / "exfildns.keras")
    assert commande[commande.index("--server.maxUploadSize") + 1] == "100"
    assert "localhost:9000" in capsys.readouterr().out


def test_cli_dashboard_adresse_explicite(monkeypatch):
    appels = []
    monkeypatch.setattr("exfildns.cli.os.execvpe", lambda p, c, env: appels.append(c))

    main(["dashboard", "--adresse", "0.0.0.0"])

    assert appels[0][appels[0].index("--server.address") + 1] == "0.0.0.0"


# --- onglet « Analyser une capture » (#41) ---


def octets_pcap(tmp_path, paquets, snaplen=65535):
    chemin = tmp_path / "capture.pcap"
    ecrire_pcap(chemin, paquets, snaplen)
    return chemin.read_bytes()


def test_analyser_capture(tmp_path, modele):
    contenu = octets_pcap(
        tmp_path,
        [requete(q) for q in noms_benins(5, graine=11)]
        + [requete(q, dst="10.6.6.6") for q in noms_exfil(5, graine=11)],
    )

    requetes = analyser_capture(contenu, str(modele))

    assert len(requetes) == 10
    assert (requetes.loc[requetes["dst"] == "10.6.6.6", "score"] >= 0.5).all()
    assert (requetes.loc[requetes["dst"] == "8.8.8.8", "score"] < 0.5).all()


def test_analyser_capture_meme_resultat_que_scan(tmp_path, modele):
    paquets = [requete(q) for q in noms_benins(5, graine=12)]
    paquets += [requete(q, dst="10.6.6.6") for q in noms_exfil(5, graine=12)]
    contenu = octets_pcap(tmp_path, paquets, snaplen=96)  # paquets tronqués comme le dataset

    requetes = analyser_capture(contenu, str(modele))
    attendu = read_dns_queries(tmp_path / "capture.pcap")
    attendu["score"] = predire_proba(charger(modele), features_dataframe(attendu["qname"]))

    pd.testing.assert_frame_equal(requetes, attendu)


def test_analyser_capture_fichier_invalide(modele):
    with pytest.raises(Scapy_Exception):
        analyser_capture(b"ceci n'est pas une capture", str(modele))


def deposer(at, nom, contenu):
    at.tabs[1].file_uploader(key="capture").set_value((nom, contenu, "application/octet-stream"))
    return at.run()


def app_capture(tmp_path, modele, monkeypatch):
    monkeypatch.setenv("EXFILDNS_MODELE", str(modele))
    return app(tmp_path / "absente.db", monkeypatch).run()


def test_app_onglet_capture_sans_fichier(tmp_path, modele, monkeypatch):
    at = app_capture(tmp_path, modele, monkeypatch)

    assert [t.label for t in at.tabs] == ["Supervision en direct", "Analyser une capture"]
    assert "exfildns scan" in at.tabs[1].caption[0].value
    assert not at.exception


def test_app_capture_avec_tunneling(tmp_path, modele, monkeypatch):
    contenu = octets_pcap(
        tmp_path,
        [requete(q) for q in noms_benins(10, graine=13)]
        + [requete(q, dst="10.6.6.6") for q in noms_exfil(6, graine=13)],
    )
    at = app_capture(tmp_path, modele, monkeypatch)

    at = deposer(at, "tunnel.pcap", contenu)

    assert not at.exception
    onglet = at.tabs[1]
    valeurs = {m.label: m.value for m in onglet.metric}
    assert valeurs["Requêtes analysées"] == "16"
    assert valeurs["Requêtes suspectes"] == "6"
    assert valeurs["Alertes"] == "1"
    assert "attaquant.example" in onglet.error[0].value
    assert "tunnel.pcap" in onglet.caption[0].value


def test_app_capture_benigne(tmp_path, modele, monkeypatch):
    contenu = octets_pcap(tmp_path, [requete(q) for q in noms_benins(10, graine=14)])
    at = app_capture(tmp_path, modele, monkeypatch)

    at = deposer(at, "normal.pcap", contenu)

    onglet = at.tabs[1]
    assert not at.exception
    assert {m.label: m.value for m in onglet.metric}["Alertes"] == "0"
    assert "Aucune alerte" in onglet.success[0].value


def test_app_capture_sans_dns(tmp_path, modele, monkeypatch):
    contenu = octets_pcap(tmp_path, [Ether() / IP() / TCP(dport=443)])
    at = app_capture(tmp_path, modele, monkeypatch)

    at = deposer(at, "web.pcap", contenu)

    assert not at.exception
    assert "Aucune requête DNS" in at.tabs[1].info[0].value


def test_app_capture_fichier_invalide(tmp_path, modele, monkeypatch):
    at = app_capture(tmp_path, modele, monkeypatch)

    at = deposer(at, "faux.pcap", b"ceci n'est pas une capture")

    assert not at.exception
    assert "n'est pas une capture réseau lisible" in at.tabs[1].error[0].value


def test_app_capture_modele_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("EXFILDNS_MODELE", str(tmp_path / "absent.keras"))
    at = app(tmp_path / "absente.db", monkeypatch).run()

    at = deposer(at, "capture.pcap", b"peu importe")

    assert not at.exception
    assert "Modèle introuvable" in at.tabs[1].warning[0].value


def test_app_capture_reglages_appliques(tmp_path, modele, monkeypatch):
    contenu = octets_pcap(tmp_path, [requete(q, dst="10.6.6.6") for q in noms_exfil(6, graine=15)])
    at = deposer(app_capture(tmp_path, modele, monkeypatch), "tunnel.pcap", contenu)
    assert {m.label: m.value for m in at.tabs[1].metric}["Alertes"] == "1"

    at.number_input(key="min_requetes").set_value(10).run()

    assert not at.exception
    assert {m.label: m.value for m in at.tabs[1].metric}["Alertes"] == "0"


def test_dashboard_et_alertes_sans_tensorflow():
    # le dashboard démarre vite : il ne charge TensorFlow que pour analyser une capture (#52)
    code = "import sys, exfildns.dashboard, exfildns.alertes; print('tensorflow' in sys.modules)"
    sortie = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )

    assert sortie.stdout.strip() == "False"


def test_graphique_activite_fixe_et_empile():
    activite = activite_par_minute(
        pd.DataFrame({"timestamp": [0.0, 10.0, 70.0], "score": [0.1, 0.9, 0.2], "src": ["a"] * 3}),
        seuil=0.5,
    )

    spec = graphique_activite(activite).to_dict()

    assert spec["mark"]["type"] == "bar"
    assert spec["encoding"]["x"]["axis"]["format"] == "%H:%M"  # 24 h, pas 03:31 pour 15:31
    assert spec["encoding"]["y"]["stack"] is True
    assert spec["encoding"]["color"]["scale"]["domain"] == ["bénignes", "suspectes"]
    assert "params" not in spec  # pas de sélection ni de zoom (.interactive() absent)
    assert len(spec["datasets"][spec["data"]["name"]]) == 4  # 2 minutes x 2 classes
