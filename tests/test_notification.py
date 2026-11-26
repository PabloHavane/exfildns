import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from exfildns import liste_blanche, statuts
from exfildns.cli import main
from exfildns.notification import assainir, envoyer, message, tour
from exfildns.sniff import ouvrir_base

MAINTENANT = 1_000_000.0


def remplir(base, domaine="attaquant.example", n=12, score=0.97, debut=MAINTENANT - 60):
    """`n` requêtes vers `domaine`, une par seconde, toutes avec le même score."""
    connexion = ouvrir_base(base)
    with connexion:
        connexion.executemany(
            "INSERT INTO requetes (timestamp, src, dst, qname, qtype, score)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (debut + i, "10.0.0.66", "10.0.0.254", f"{i}.x.{domaine}", 16, score)
                for i in range(n)
            ],
        )
    connexion.close()


@pytest.fixture
def base(tmp_path):
    chemin = tmp_path / "detections.db"
    remplir(chemin)
    return chemin


def passer(base, deja, envoi=None, maintenant=MAINTENANT):
    """Un tour de notification ; renvoie (messages envoyés, lignes de journal)."""
    envoyes, journal = [], []
    tour(
        base, base.with_name("statuts.db"), deja, 0.5, 5, 3600,
        envoi or envoyes.append, maintenant, journal.append,
    )  # fmt: skip
    return envoyes, journal


def test_assainir():
    assert assainir("attaquant.example") == "attaquant.example"
    assert assainir("<@channel>[lien](http://x)`") == "??channel??lien??http:??x??"
    assert assainir("a" * 300) == "a" * 99 + "…"


def test_message_alerte_haute(base):
    envoyes, journal = passer(base, set())

    assert len(envoyes) == 1
    corps = envoyes[0]
    assert corps["domaine"] == "attaquant.example"
    assert corps["requetes_suspectes"] == 12
    assert corps["score_max"] == 0.97
    assert corps["postes"] == ["10.0.0.66"]
    assert corps["derniere_requete"].endswith("+00:00")
    assert "`attaquant.example`" in corps["text"]
    assert journal == ["Alerte haute notifiée : attaquant.example"]


def test_message_domaine_forge_neutralise():
    alerte = type("A", (), {"domaine": "x`<!here>.com", "postes": "10.0.0.1, fe80::1, <b>",
                            "requetes_suspectes": 10, "score_max": 0.95, "fin": 0.0})  # fmt: skip

    corps = message(alerte)

    assert corps["domaine"] == "x???here?.com"
    assert "<" not in corps["text"] and corps["text"].count("`") == 2
    assert corps["postes"] == ["10.0.0.1", "fe80::1", "?b?"]


def test_une_seule_notification_par_alerte(base):
    deja = set()
    passer(base, deja)

    envoyes, _ = passer(base, deja)

    assert envoyes == []


def test_alerte_renotifiee_si_elle_revient(base):
    deja = set()
    passer(base, deja)
    passer(base, deja, maintenant=MAINTENANT + 7200)  # hors fenêtre : l'alerte disparaît
    assert deja == set()
    remplir(base, debut=MAINTENANT + 7200 - 30)

    envoyes, _ = passer(base, deja, maintenant=MAINTENANT + 7200)

    assert len(envoyes) == 1


def test_pas_de_notification_sans_alerte_haute(tmp_path):
    base = tmp_path / "detections.db"
    remplir(base, n=6)  # alerte, mais pas fournie (< 2 x 5 requêtes)
    remplir(base, domaine="autre.example", n=12, score=0.7)  # fournie, mais pas nette

    assert passer(base, set())[0] == []


def test_base_vide(tmp_path):
    base = tmp_path / "detections.db"
    ouvrir_base(base).close()

    assert passer(base, set()) == ([], [])


def test_statut_faux_positif_ou_close_pas_notifie(base):
    statuts.enregistrer(base.with_name("statuts.db"), "attaquant.example", "faux_positif")

    assert passer(base, set())[0] == []


def test_liste_blanche_du_dashboard_appliquee(base):
    liste_blanche.ajouter(base.with_name("statuts.db"), "attaquant.example")

    assert passer(base, set())[0] == []


def test_adresse_malformee_journalisee_sans_arret(base):
    envoyes, journal = passer(base, set(), envoi=lambda corps: envoyer("http://x:port/", corps))

    assert "Notification non envoyée" in journal[0]


def test_envoi_rate_retente_au_tour_suivant(base):
    deja = set()

    def en_panne(corps):
        raise OSError("connexion refusée")

    envoyes, journal = passer(base, deja, envoi=en_panne)

    assert deja == set()
    assert "Notification non envoyée (attaquant.example) : connexion refusée" in journal
    assert len(passer(base, deja)[0]) == 1


# --- envoi HTTP réel vers un serveur local ---


@pytest.fixture
def serveur():
    recus = []

    class Gestionnaire(BaseHTTPRequestHandler):
        def do_POST(self):
            longueur = int(self.headers["Content-Length"])
            recus.append((self.headers["Content-Type"], json.loads(self.rfile.read(longueur))))
            self.send_response(204 if self.path == "/ok" else 500)
            self.end_headers()

        def log_message(self, *args):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), Gestionnaire)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}", recus
    httpd.shutdown()


def test_envoyer_poste_du_json(serveur):
    url, recus = serveur

    envoyer(url + "/ok", {"text": "été"})

    assert recus == [("application/json", {"text": "été"})]


def test_envoyer_erreur_http_levee(serveur):
    url, _ = serveur

    with pytest.raises(OSError):
        envoyer(url + "/erreur", {"text": "x"})


# --- commande exfildns notifier ---


def un_tour(secondes):
    """Remplace l'attente entre deux tours : arrête la boucle comme Ctrl+C."""
    raise KeyboardInterrupt


def test_cli_notifier(base, serveur, monkeypatch, capsys):
    url, recus = serveur
    monkeypatch.setattr("exfildns.notification.time.time", lambda: MAINTENANT)

    monkeypatch.setattr("exfildns.notification.time.sleep", un_tour)

    code = main(["notifier", "--base", str(base), "--webhook", url + "/ok"])

    assert code == 0
    assert [corps["domaine"] for _, corps in recus] == ["attaquant.example"]
    assert "Alerte haute notifiée" in capsys.readouterr().err


def test_cli_notifier_webhook_par_variable(base, serveur, monkeypatch):
    url, recus = serveur
    monkeypatch.setenv("EXFILDNS_WEBHOOK", url + "/ok")
    monkeypatch.setattr("exfildns.notification.time.time", lambda: MAINTENANT)
    monkeypatch.setattr("exfildns.notification.time.sleep", un_tour)

    assert main(["notifier", "--base", str(base)]) == 0
    assert len(recus) == 1


@pytest.mark.parametrize("variable", [None, ""])  # absente, ou vide comme dans compose
def test_cli_notifier_sans_webhook(base, variable, monkeypatch, capsys):
    if variable is None:
        monkeypatch.delenv("EXFILDNS_WEBHOOK", raising=False)
    else:
        monkeypatch.setenv("EXFILDNS_WEBHOOK", variable)

    assert main(["notifier", "--base", str(base)]) == 2
    assert "EXFILDNS_WEBHOOK" in capsys.readouterr().err


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x", "exemple.com"])
def test_cli_notifier_webhook_invalide(url, capsys):
    with pytest.raises(SystemExit) as sortie:
        main(["notifier", "--webhook", url])

    assert sortie.value.code == 2
    assert "http:// ou https://" in capsys.readouterr().err


def test_cli_notifier_base_absente_attend(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("exfildns.notification.time.sleep", un_tour)

    code = main(
        ["notifier", "--base", str(tmp_path / "absente.db"), "--webhook", "http://127.0.0.1:9/"]
    )

    assert code == 0
    assert not (tmp_path / "absente.db").exists()


def test_cli_notifier_base_illisible_signalee(tmp_path, monkeypatch, capsys):
    base = tmp_path / "detections.db"
    base.write_text("pas une base SQLite")
    monkeypatch.setattr("exfildns.notification.time.sleep", un_tour)

    assert main(["notifier", "--base", str(base), "--webhook", "http://127.0.0.1:9/"]) == 0
    assert "Lecture impossible" in capsys.readouterr().err
