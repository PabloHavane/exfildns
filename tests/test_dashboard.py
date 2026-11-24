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
    activite_dns,
    analyser_capture,
    derniere_requete,
    en_heure,
    graduations,
    graphique_activite,
    graphique_histogramme,
    graphique_qtypes,
    instants_alertes,
    intervalle,
    lire_requetes,
    pas_graduations,
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
        connexion.executemany(
            "INSERT INTO requetes (timestamp, src, dst, qname, qtype, score)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            lignes,
        )
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


def texte(bloc):
    """Tout le texte Markdown et les légendes d'un bloc de l'application (AppTest)."""
    return "\n".join(e.value for e in [*bloc.markdown, *bloc.caption])


def app(base, monkeypatch):
    monkeypatch.setenv("EXFILDNS_BASE", str(base))
    return AppTest.from_file(FICHIER_APP, default_timeout=60)


# --- lecture de la base ---


def test_lire_requetes_toute_la_base(base_demo):
    requetes = lire_requetes(base_demo)

    assert len(requetes) == 30
    assert list(requetes.columns) == [
        "id",
        "timestamp",
        "src",
        "dst",
        "qname",
        "qtype",
        "score",
        "taille",
    ]
    assert requetes["timestamp"].is_monotonic_increasing
    assert requetes["qtype"].dtype == "Int64"


def test_lire_requetes_depuis_un_instant(base_demo):
    assert len(lire_requetes(base_demo, depuis=time.time() - 3600)) == 29


def test_lire_requetes_taille(tmp_path):
    base = tmp_path / "detections.db"
    connexion = ouvrir_base(base)
    with connexion:
        connexion.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 'x.fr', 1, 0.1, 26)")
        connexion.execute("INSERT INTO requetes VALUES (2, 'a', 'b', 'y.fr', 1, 0.1, NULL)")
    connexion.close()

    requetes = lire_requetes(base)

    assert requetes["taille"].dtype == "Int64"
    assert requetes["taille"].tolist()[0] == 26
    assert requetes["taille"].isna().tolist() == [False, True]


def test_lire_requetes_base_anterieure_non_migree(tmp_path):
    """Dashboard ouvert sur une base que la capture n'a pas encore migrée (lecture seule)."""
    base = tmp_path / "detections.db"
    with sqlite3.connect(base) as ancienne:
        ancienne.execute(
            "CREATE TABLE requetes (timestamp REAL, src TEXT, dst TEXT, qname TEXT,"
            " qtype INTEGER, score REAL)"
        )
        ancienne.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 'x.fr', 1, 0.1)")
    ancienne.close()

    requetes = lire_requetes(base)

    assert requetes["taille"].isna().all()
    assert requetes["taille"].dtype == "Int64"


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
        ecrivain.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 'x.fr', 1, 0.1, 40)")
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
        ecrivain.execute("INSERT INTO requetes VALUES (1, 'a', 'b', 'x.fr', 1, 0.1, 40)")

    premiere = lire_requetes(base)
    with ecrivain:
        ecrivain.execute("INSERT INTO requetes VALUES (2, 'a', 'b', 'y.fr', 1, 0.1, 40)")

    assert len(premiere) == 1
    assert len(lire_requetes(base)) == 2
    ecrivain.close()


# --- préparation des données ---


def test_en_heure_fuseau_local():
    heures = en_heure(pd.Series([0.0, 60.0]))

    assert heures.dt.tz is not None
    assert (heures.iloc[1] - heures.iloc[0]) == pd.Timedelta(minutes=1)


def test_activite_dns():
    requetes = pd.DataFrame(
        {"timestamp": [0.0, 10.0, 70.0, 75.0], "score": [0.1, 0.9, 0.9, 0.2], "src": ["a"] * 4}
    )

    activite = activite_dns(requetes, seuil=0.5)

    assert list(activite.columns) == ["bénignes", "suspectes"]
    assert activite["bénignes"].tolist() == [1, 1]
    assert activite["suspectes"].tolist() == [1, 1]


def test_activite_dns_sans_suspecte():
    requetes = pd.DataFrame({"timestamp": [0.0], "score": [0.1], "src": ["a"]})

    assert activite_dns(requetes, 0.5)["suspectes"].tolist() == [0]


def test_activite_dns_par_tranche_de_5_minutes():
    requetes = pd.DataFrame(
        {"timestamp": [0.0, 290.0, 610.0], "score": [0.1] * 3, "src": ["a"] * 3}
    )

    activite = activite_dns(requetes, 0.5, minutes=5)

    assert activite["bénignes"].tolist() == [2, 0, 1]  # 0-5 min, 5-10 min (vide), 10-15 min
    assert (activite.index.to_series().diff().dropna() == pd.Timedelta(minutes=5)).all()


@pytest.mark.parametrize(
    ("duree_h", "minutes"), [(0, 1), (23, 1), (25, 5), (100, 5), (200, 15), (24 * 30, 60)]
)
def test_intervalle_selon_la_duree(duree_h, minutes):
    requetes = pd.DataFrame({"timestamp": [0.0, duree_h * 3600.0]})

    assert intervalle(requetes) == minutes


def test_intervalle_vide_et_tres_longue_duree():
    assert intervalle(pd.DataFrame({"timestamp": []})) == 1
    assert intervalle(pd.DataFrame({"timestamp": [0.0, 10 * 365 * 86400.0]})) == 1440


def test_graphique_activite_longue_periode_sous_la_limite_d_altair():
    """Régression : une grille à la minute sur 3 jours dépassait les 5000 lignes d'Altair."""
    requetes = pd.DataFrame(
        {"timestamp": [0.0, 3 * 86400.0], "score": [0.1, 0.9], "src": ["a"] * 2}
    )
    minutes = intervalle(requetes)

    spec = graphique_activite(activite_dns(requetes, 0.5, minutes), minutes).to_dict()

    assert len(spec["datasets"][spec["data"]["name"]]) < 5000
    assert spec["encoding"]["x"]["axis"]["format"] == "%d/%m %H:%M"  # plusieurs jours : la date


def test_graduations_sur_des_heures_rondes():
    debuts = pd.date_range("2026-11-24 18:07", periods=30, freq="min", tz="Europe/Paris")

    valeurs = graduations(debuts, 1)  # 18:07 -> 18:36, une graduation toutes les 5 min

    assert [m.strftime("%H:%M") for m in valeurs] == [
        "18:10",
        "18:15",
        "18:20",
        "18:25",
        "18:30",
        "18:35",
    ]


def test_graduations_sans_heure_ronde_ni_tranche():
    debuts = pd.date_range("2026-11-24 18:07", periods=1, freq="min", tz="Europe/Paris")

    assert [m.strftime("%H:%M") for m in graduations(debuts, 1)] == ["18:07"]
    assert graduations(debuts[:0], 1) == []


def test_activite_dns_minutes_sans_trafic_a_zero():
    requetes = pd.DataFrame({"timestamp": [0.0, 185.0], "score": [0.9, 0.1], "src": ["a"] * 2})

    activite = activite_dns(requetes, 0.5)

    assert len(activite) == 4  # minutes 0, 1, 2, 3 : aucune ne manque
    assert (activite.index.to_series().diff().dropna() == pd.Timedelta(minutes=1)).all()
    assert activite["bénignes"].tolist() == [0, 0, 0, 1]
    assert activite["suspectes"].tolist() == [1, 0, 0, 0]


def test_activite_dns_une_ligne_par_minute():
    """Le bug d'origine : des requêtes d'une même minute ne donnent qu'une seule ligne."""
    requetes = pd.DataFrame(
        {"timestamp": [60.0 + i for i in range(0, 60, 5)], "score": [0.1] * 12, "src": ["a"] * 12}
    )

    activite = activite_dns(requetes, 0.5)

    assert len(activite) == 1
    assert activite["bénignes"].tolist() == [12]


def test_activite_dns_vide():
    activite = activite_dns(pd.DataFrame(columns=["timestamp", "score"]), 0.5)

    assert activite.empty
    assert list(activite.columns) == ["bénignes", "suspectes"]


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
        "Analysées": "29",
        "Suspectes": "9",
        "Taux suspect": "31.0 %",
        "Alertes ouvertes": "1",
        "Postes": "3",
        "Domaines parents": "22",  # site0.fr … site19.fr, attaquant.example, cloudfront.net
        "Score max": "0.970",
        "TXT / NULL": "27.6 %",
    }
    # file d'alertes : le domaine est échappé pour le Markdown
    assert "attaquant\\.example" in texte(at.tabs[0])
    assert "File d'alertes (1)" in [s.value for s in at.tabs[0].subheader]
    domaines, postes, recentes = at.tabs[0].dataframe  # top domaines, top postes, récentes
    assert domaines.value.loc[0, "domaine"] == "attaquant.example"  # 8 requêtes, le plus gros
    assert postes.value.loc[0, "poste"] == "10.0.0.66"  # le plus de requêtes suspectes
    assert len(recentes.value) == 9


def test_app_seuil_plus_strict(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.slider(key="seuil").set_value(1.0).run()

    assert not at.exception
    assert {m.label: m.value for m in at.metric}["Suspectes"] == "0"
    assert "Aucune alerte" in texte(at.tabs[0])
    assert len(at.tabs[0].dataframe) == 2  # panneaux top, pas de requête suspecte récente


def test_app_minimum_de_requetes(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.number_input(key="min_requetes").set_value(20).run()

    assert not at.exception
    assert {m.label: m.value for m in at.metric}["Alertes ouvertes"] == "0"
    assert "Aucune alerte" in texte(at.tabs[0])


def test_app_periode(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.selectbox(key="periode").set_value("tout").run()
    assert {m.label: m.value for m in at.metric}["Analysées"] == "30"

    at.selectbox(key="periode").set_value("5 dernières minutes").run()
    assert {m.label: m.value for m in at.metric}["Analysées"] == "29"


def test_app_sans_rafraichissement(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.toggle(key="auto").set_value(False).run()

    assert not at.exception
    assert {m.label: m.value for m in at.metric}["Alertes ouvertes"] == "1"


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
    at.tabs[2].file_uploader(key="capture").set_value((nom, contenu, "application/octet-stream"))
    return at.run()


def app_capture(tmp_path, modele, monkeypatch):
    monkeypatch.setenv("EXFILDNS_MODELE", str(modele))
    return app(tmp_path / "absente.db", monkeypatch).run()


def test_app_onglet_capture_sans_fichier(tmp_path, modele, monkeypatch):
    at = app_capture(tmp_path, modele, monkeypatch)

    assert [t.label for t in at.tabs] == [
        "Supervision en direct",
        "Requêtes",
        "Analyser une capture",
    ]
    assert "exfildns scan" in at.tabs[2].caption[0].value
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
    onglet = at.tabs[2]
    valeurs = {m.label: m.value for m in onglet.metric}
    assert valeurs["Analysées"] == "16"
    assert valeurs["Suspectes"] == "6"
    assert valeurs["Taux suspect"] == "37.5 %"
    assert valeurs["Alertes ouvertes"] == "1"
    assert "attaquant\\.example" in texte(onglet)
    assert "tunnel.pcap" in onglet.caption[0].value


def test_app_capture_benigne(tmp_path, modele, monkeypatch):
    contenu = octets_pcap(tmp_path, [requete(q) for q in noms_benins(10, graine=14)])
    at = app_capture(tmp_path, modele, monkeypatch)

    at = deposer(at, "normal.pcap", contenu)

    onglet = at.tabs[2]
    assert not at.exception
    assert {m.label: m.value for m in onglet.metric}["Alertes ouvertes"] == "0"
    assert "Aucune alerte" in texte(onglet)


def test_app_capture_sans_dns(tmp_path, modele, monkeypatch):
    contenu = octets_pcap(tmp_path, [Ether() / IP() / TCP(dport=443)])
    at = app_capture(tmp_path, modele, monkeypatch)

    at = deposer(at, "web.pcap", contenu)

    assert not at.exception
    assert "Aucune requête DNS" in at.tabs[2].info[0].value


def test_app_capture_fichier_invalide(tmp_path, modele, monkeypatch):
    at = app_capture(tmp_path, modele, monkeypatch)

    at = deposer(at, "faux.pcap", b"ceci n'est pas une capture")

    assert not at.exception
    assert "n'est pas une capture réseau lisible" in at.tabs[2].error[0].value


def test_app_capture_modele_absent(tmp_path, monkeypatch):
    monkeypatch.setenv("EXFILDNS_MODELE", str(tmp_path / "absent.keras"))
    at = app(tmp_path / "absente.db", monkeypatch).run()

    at = deposer(at, "capture.pcap", b"peu importe")

    assert not at.exception
    assert "Modèle introuvable" in at.tabs[2].warning[0].value


def test_app_capture_reglages_appliques(tmp_path, modele, monkeypatch):
    contenu = octets_pcap(tmp_path, [requete(q, dst="10.6.6.6") for q in noms_exfil(6, graine=15)])
    at = deposer(app_capture(tmp_path, modele, monkeypatch), "tunnel.pcap", contenu)
    assert {m.label: m.value for m in at.tabs[2].metric}["Alertes ouvertes"] == "1"

    at.number_input(key="min_requetes").set_value(10).run()

    assert not at.exception
    assert {m.label: m.value for m in at.tabs[2].metric}["Alertes ouvertes"] == "0"


def test_dashboard_et_alertes_sans_tensorflow():
    # le dashboard démarre vite : il ne charge TensorFlow que pour analyser une capture (#52)
    code = "import sys, exfildns.dashboard, exfildns.alertes; print('tensorflow' in sys.modules)"
    sortie = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )

    assert sortie.stdout.strip() == "False"


def test_graphique_activite_fixe_et_empile():
    activite = activite_dns(
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


def suspectes_vers(domaine, instants, qtype=16, score=0.9):
    return [
        {"timestamp": t, "src": "a", "qname": f"{i}x.{domaine}", "qtype": qtype, "score": score}
        for i, t in enumerate(instants)
    ]


def test_instants_alertes_a_la_n_ieme_requete_suspecte():
    requetes = pd.DataFrame(
        suspectes_vers("pirate.example", [10.0, 30.0, 20.0, 40.0])
        + suspectes_vers("autre.example", [5.0, 6.0])
        + suspectes_vers("calme.example", [1.0, 2.0, 3.0], score=0.1)
    )

    instants = instants_alertes(requetes, seuil=0.5, min_requetes=3)

    # 3e requête suspecte dans l'ordre du temps (10, 20, 30), pas dans l'ordre des lignes
    assert instants.to_dict("records") == [{"domaine": "pirate.example", "instant": 30.0}]


def test_instants_alertes_memes_alertes_que_le_resume(base_demo):
    requetes = lire_requetes(base_demo)

    instants = instants_alertes(requetes, 0.5, 5)

    assert sorted(instants["domaine"]) == sorted(alertes(requetes, 0.5, 5)["domaine"])


def test_instants_alertes_liste_blanche_et_nom_tronque():
    requetes = pd.DataFrame(
        suspectes_vers("cloudfront.net", [1.0, 2.0]) + suspectes_vers("coupe", [3.0, 4.0], None)
    )

    instants = instants_alertes(requetes, 0.5, 2, liste_blanche=["cloudfront.net"])

    assert instants["domaine"].tolist() == ["(nom incomplet dans la capture)"]


def test_instants_alertes_toutes_en_liste_blanche():
    requetes = pd.DataFrame(suspectes_vers("cloudfront.net", [1.0, 2.0, 3.0]))

    instants = instants_alertes(requetes, 0.5, 1, liste_blanche=["cloudfront.net"])

    assert instants.empty
    assert list(instants.columns) == ["domaine", "instant"]


def test_instants_alertes_sans_suspecte():
    requetes = pd.DataFrame(suspectes_vers("calme.example", [1.0], score=0.1))

    assert instants_alertes(requetes, 0.5, 1).empty
    assert instants_alertes(requetes.iloc[:0], 0.5, 1).empty


@pytest.mark.parametrize(
    ("minutes", "pas"), [(1, 1), (12, 1), (13, 2), (60, 5), (24 * 60, 120), (10**6, 10080)]
)
def test_pas_graduations(minutes, pas):
    assert pas_graduations(minutes) == pas


def test_graphique_activite_graduations_a_la_minute():
    activite = activite_dns(
        pd.DataFrame({"timestamp": [0.0, 125.0], "score": [0.1, 0.9], "src": ["a"] * 2}), 0.5
    )

    x = graphique_activite(activite).to_dict()["encoding"]["x"]

    assert x["type"] == "temporal"
    assert graphique_activite(activite).to_dict()["encoding"]["x2"]["field"] == "fin"
    # une graduation par minute, alignée sur la minute (l'heure dépend du fuseau de la machine)
    assert [v["minutes"] for v in x["axis"]["values"]] == [0, 1, 2]


def test_graphique_activite_marqueurs_d_alerte():
    activite = activite_dns(
        pd.DataFrame({"timestamp": [0.0, 125.0], "score": [0.1, 0.9], "src": ["a"] * 2}), 0.5
    )
    instants = pd.DataFrame({"domaine": ["pirate.example"], "instant": [100.0]})

    spec = graphique_activite(activite, 1, instants).to_dict()

    barres, marqueurs = spec["layer"]
    assert barres["mark"]["type"] == "bar"
    assert marqueurs["mark"]["type"] == "rule"
    assert len(spec["datasets"][marqueurs["data"]["name"]]) == 1


def test_graphique_activite_sans_alerte_pas_de_marqueur():
    activite = activite_dns(pd.DataFrame({"timestamp": [0.0], "score": [0.1], "src": ["a"]}), 0.5)
    vide = pd.DataFrame(columns=["domaine", "instant"])

    assert "layer" not in graphique_activite(activite, 1, vide).to_dict()


# --- onglet « Requêtes » ---


def onglet_requetes(at):
    return at.tabs[1]


def test_app_onglet_requetes_tableau(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    onglet = onglet_requetes(at)
    assert not at.exception
    (tableau,) = onglet.dataframe
    assert len(tableau.value) == 29  # la requête d'il y a 2 jours est hors de la dernière heure
    assert list(tableau.value.columns) == [
        "heure",
        "poste",
        "nom demandé",
        "type",
        "taille",
        "sous-domaine",
        "entropie",
        "labels",
        "score",
        "verdict",
    ]
    assert "Sélectionner une ligne" in onglet.caption[-1].value


def test_app_onglet_requetes_plus_recentes_d_abord(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    heures = onglet_requetes(at).dataframe[0].value["heure"]

    assert heures.is_monotonic_decreasing


def test_app_onglet_requetes_filtres(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.multiselect(key="f_verdicts").set_value(["suspecte"]).run()
    assert set(onglet_requetes(at).dataframe[0].value["verdict"]) == {"suspecte"}
    assert len(onglet_requetes(at).dataframe[0].value) == 9  # 8 tunnel + 1 CDN

    at.text_input(key="f_texte").set_value("ATTAQUANT").run()
    assert len(onglet_requetes(at).dataframe[0].value) == 8

    at.multiselect(key="f_postes").set_value(["10.0.0.1"]).run()
    assert onglet_requetes(at).dataframe[0].value.empty
    assert "0 requête(s) affichée(s) sur 29" in onglet_requetes(at).caption[1].value


def test_app_onglet_requetes_figees_jusqu_a_actualiser(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()
    remplir(base_demo, [(time.time(), "10.0.0.7", "10.0.0.254", "nouveau.fr", 1, 0.01)])

    at.text_input(key="f_texte").set_value("").run()  # une interaction quelconque
    assert len(onglet_requetes(at).dataframe[0].value) == 29  # données figées

    at.button(key="actualiser_requetes").click().run()
    assert len(onglet_requetes(at).dataframe[0].value) == 30


def test_app_onglet_requetes_seuil_change_le_verdict(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.slider(key="seuil").set_value(0.99).run()

    assert set(onglet_requetes(at).dataframe[0].value["verdict"]) == {"bénigne"}


def test_app_onglet_requetes_sans_base(tmp_path, monkeypatch):
    at = app(tmp_path / "absente.db", monkeypatch).run()

    assert "Aucune base" in onglet_requetes(at).info[0].value


def test_app_onglet_requetes_base_vide(tmp_path, monkeypatch):
    base = tmp_path / "detections.db"
    ouvrir_base(base).close()

    at = app(base, monkeypatch).run()

    assert "Aucune requête DNS sur la période" in onglet_requetes(at).info[0].value


def detail_de_la_requete(qname, base):
    """Script Streamlit : panneau de détail de la requête `qname` de la base."""
    import streamlit as st

    from exfildns import detail
    from exfildns.dashboard import afficher_detail, lire_requetes

    tableau = detail.tableau_detaille(lire_requetes(base), 0.5)
    afficher_detail(st, tableau[tableau["qname"] == qname].iloc[0], tableau)


def test_afficher_detail(base_demo):
    qname = "3.AbCdEf0123.attaquant.example"
    at = AppTest.from_function(detail_de_la_requete, args=(qname, str(base_demo))).run()

    assert not at.exception
    rendu = "".join(m.value for m in at.markdown)
    assert '<span class="label suspect">AbCdEf0123</span>' in rendu
    assert '<span class="label parent">attaquant</span>' in rendu
    comparaison, suite = at.dataframe[:2]
    assert comparaison.value["feature"].tolist()[0] == "FQDN_count"
    assert len(suite.value) == 8  # les 8 requêtes du poste vers attaquant.example
    assert suite.value["sélection"].sum() == 1
    assert [b.label for b in at.get("download_button")] == [
        "Exporter cette requête (JSON)",
        "Exporter la séquence (CSV)",
    ]


def test_afficher_detail_echappe_un_nom_malveillant(tmp_path):
    base = tmp_path / "detections.db"
    remplir(
        base, [(1.0, "10.0.0.6", "10.0.0.254", "<img src=x onerror=alert(1)>.evil.com", 1, 0.9)]
    )

    at = AppTest.from_function(
        detail_de_la_requete, args=("<img src=x onerror=alert(1)>.evil.com", str(base))
    ).run()

    assert not at.exception
    rendu = "".join(m.value for m in at.markdown)
    assert "<img" not in rendu
    assert "&lt;img src=x onerror=alert(1)&gt;" in rendu


def test_app_onglet_requetes_cle_du_tableau_change_a_chaque_lecture(base_demo, monkeypatch):
    """Streamlit garde la sélection (une position) si la clé ne change pas : après une relecture,
    elle désignerait une autre requête."""
    at = app(base_demo, monkeypatch).run()
    avant = onglet_requetes(at).dataframe[0].key

    at.text_input(key="f_texte").set_value("").run()
    assert onglet_requetes(at).dataframe[0].key == avant  # simple interaction : même sélection

    at.button(key="actualiser_requetes").click().run()
    assert onglet_requetes(at).dataframe[0].key != avant


# --- bandeau d'état, variations, file d'alertes ---


def test_derniere_requete(base_demo, tmp_path):
    assert derniere_requete(base_demo) == pytest.approx(time.time() - 30, abs=5)
    vide = tmp_path / "vide.db"
    ouvrir_base(vide).close()
    assert derniere_requete(vide) is None


def test_app_bandeau(base_demo, monkeypatch, tmp_path):
    modele = tmp_path / "exfildns.keras"
    modele.write_bytes(b"poids")
    monkeypatch.setenv("EXFILDNS_MODELE", str(modele))

    at = app(base_demo, monkeypatch).run()

    bandeau = at.markdown[0].value
    assert 'class="bandeau"' in bandeau
    assert "capteur " in bandeau and "dernière requête il y a " in bandeau
    assert "exfildns.keras" in bandeau and "seuil 0.50" in bandeau
    assert not at.title  # le bandeau remplace le gros titre


def test_app_bandeau_sans_base_ni_modele(tmp_path, monkeypatch):
    monkeypatch.setenv("EXFILDNS_MODELE", str(tmp_path / "absent.keras"))

    at = app(tmp_path / "absente.db", monkeypatch).run()

    assert "aucune requête reçue" in at.markdown[0].value
    assert "modèle absent" in at.markdown[0].value


def test_app_variations_par_rapport_a_la_periode_precedente(base_demo, monkeypatch):
    maintenant = time.time()
    # période précédente (il y a 1 h à 2 h) : 4 requêtes bénignes
    remplir(
        base_demo,
        [(maintenant - 5400 + i, "10.0.0.1", "10.0.0.254", "avant.fr", 1, 0.01) for i in range(4)],
    )

    at = app(base_demo, monkeypatch).run()

    deltas = {m.label: m.delta for m in at.metric}
    assert deltas["Analysées"] == "+25"  # 29 contre 4
    assert deltas["Suspectes"] == "+9"
    assert deltas["Alertes ouvertes"] == "+1"
    assert deltas["Score max"] == "+0.960"  # 0.97 contre 0.01


def test_app_pas_de_variation_si_la_periode_precedente_est_vide(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()  # rien entre il y a 1 h et il y a 2 h

    assert all(not m.delta for m in at.metric)


def test_app_pas_de_variation_sur_toute_la_base(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()

    at.selectbox(key="periode").set_value("tout").run()

    assert all(not m.delta for m in at.metric)


def test_app_file_d_alertes_nom_malveillant_echappe(tmp_path, monkeypatch):
    base = tmp_path / "detections.db"
    maintenant = time.time()
    remplir(
        base,
        [
            (maintenant - 10 + i, "10.0.0.6", "10.0.0.254", f"{i}.x.[clic](http:", 16, 0.99)
            for i in range(6)
        ],
    )

    at = app(base, monkeypatch).run()

    cartes = texte(at.tabs[0])
    assert "\\[clic\\]\\(http\\:" in cartes
    assert "MOYENNE" in cartes  # score net mais pas assez de requêtes pour « haute »


# --- panneaux « top » et histogramme ---


def test_app_panneaux_tri_des_domaines(base_demo, monkeypatch):
    at = app(base_demo, monkeypatch).run()
    assert at.tabs[0].dataframe[0].value.loc[0, "domaine"] == "attaquant.example"

    at.segmented_control(key="tri_domaines_direct").set_value("score").run()

    assert at.tabs[0].dataframe[0].value.loc[0, "domaine"] == "attaquant.example"  # 0.97
    assert at.tabs[0].dataframe[0].value.loc[1, "domaine"] == "cloudfront.net"  # 0.8


def test_graphique_histogramme_seuil():
    from exfildns.synthese import histogramme_scores

    spec = graphique_histogramme(histogramme_scores(pd.Series([0.1, 0.9])), 0.7).to_dict()

    barres, trait = spec["layer"]
    assert trait["mark"]["type"] == "rule"
    assert spec["datasets"][trait["data"]["name"]] == [{"seuil": 0.7}]
    couleurs = {d["début"]: d["classe"] for d in spec["datasets"][barres["data"]["name"]]}
    assert couleurs[0.65] == "bénignes" and couleurs[0.7] == "suspectes"


def test_graphique_qtypes():
    spec = graphique_qtypes(pd.DataFrame({"type": ["A", "TXT"], "requêtes": [5, 2]})).to_dict()

    assert spec["mark"]["type"] == "bar"
    assert spec["encoding"]["y"]["sort"] == "-x"


def test_app_supervision_et_capture_en_meme_temps(base_demo, tmp_path, modele, monkeypatch):
    """Les deux onglets affichent des panneaux : leurs widgets ne doivent pas partager de clé."""
    contenu = octets_pcap(
        tmp_path,
        [requete(q) for q in noms_benins(5, graine=15)]
        + [requete(q, dst="10.6.6.6") for q in noms_exfil(6, graine=15)],
    )
    monkeypatch.setenv("EXFILDNS_MODELE", str(modele))
    at = app(base_demo, monkeypatch).run()

    at = deposer(at, "tunnel.pcap", contenu)

    assert not at.exception
    assert at.tabs[0].metric and at.tabs[2].metric
