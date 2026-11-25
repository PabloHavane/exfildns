"""Utilitaires partagés par les tests : captures et jeux de données synthétiques."""

import numpy as np
import pandas as pd
import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter

from exfildns.features import FEATURES, features_dataframe
from exfildns.model import entrainer_mlp, sauvegarder

NOM_EXFIL = "0.J4HgHlgzQH6j0WZF8m3DQx3jGodWnpcKYKFAeUM.attaquant.example"


def requete(nom, src="192.168.20.38", dst="8.8.8.8", qtype="A"):
    """Paquet Ethernet contenant une requête DNS."""
    return (
        Ether()
        / IP(src=src, dst=dst)
        / UDP(sport=50000, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=nom, qtype=qtype))
    )


def ecrire_pcap(chemin, paquets, snaplen=65535):
    """Écrit des paquets bruts, tronqués à `snaplen` octets comme le ferait tcpdump -s."""
    with RawPcapWriter(str(chemin), linktype=1, snaplen=snaplen) as w:
        for p in paquets:
            w.write(bytes(p)[:snaplen])


def jeu_synthetique(n=400, graine=0):
    """Deux classes séparables : la classe 1 a des valeurs plus grandes sur toutes les features."""
    rng = np.random.default_rng(graine)
    y = np.arange(n) % 2
    X = rng.normal(size=(n, len(FEATURES))) + 3 * y[:, None]
    df = pd.DataFrame(X, columns=FEATURES)
    df["label"] = y
    df["capture"] = np.where(np.arange(n) < n * 3 // 4, "train", "test")
    return df


MOTS = ["google", "wikipedia", "meteo", "boutique", "news", "mail", "cdn", "photos", "bank", "shop"]
TLDS = ["com", "fr", "org", "net", "co.jp", "de"]
BASE64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def noms_benins(n, graine=0):
    """Noms de domaine courts et lisibles, comme ceux du top Alexa."""
    rng = np.random.default_rng(graine)
    return [
        f"{'www.' if i % 3 == 0 else ''}{rng.choice(MOTS)}{rng.choice(MOTS)}.{rng.choice(TLDS)}"
        for i in range(n)
    ]


def noms_exfil(n, graine=0):
    """Requêtes façon DNSExfiltrator : numéro de morceau, données base64, domaine de l'attaquant."""
    rng = np.random.default_rng(graine)
    return [f"{i}.{''.join(rng.choice(list(BASE64URL), 50))}.attaquant.example" for i in range(n)]


@pytest.fixture
def dossier_donnees(tmp_path):
    """Mini-dataset de PCAP aux noms des vraies captures (dont celles du test, CAPTURES_TEST)."""
    dossier = tmp_path / "data"
    (dossier / "Attacks").mkdir(parents=True)
    (dossier / "Benign").mkdir()
    for graine, nom in enumerate(["heavy_audio", "heavy_video"]):
        paquets = [requete(q, dst="192.168.20.72") for q in noms_exfil(200, graine)]
        paquets += [requete(q) for q in noms_benins(10, graine + 10)]  # trafic de fond
        # snaplen=96 : paquets coupés comme dans le vrai dataset (docs/donnees.md)
        ecrire_pcap(dossier / "Attacks" / f"{nom}.pcap", paquets, snaplen=96)
    for graine, nom in enumerate(["benign_heavy_1", "benign_heavy_3"]):
        paquets = [requete(q) for q in noms_benins(200, graine + 20)]
        ecrire_pcap(dossier / "Benign" / f"{nom}.pcap", paquets)
    return dossier


@pytest.fixture(scope="session")
def modele(tmp_path_factory):
    """Chemin d'un petit réseau entraîné sur des noms synthétiques (bénins / base64)."""
    noms = noms_benins(300, graine=1) + noms_exfil(300, graine=1)
    y = pd.Series([0] * 300 + [1] * 300)
    reseau, _ = entrainer_mlp(features_dataframe(noms), y, epochs=30)
    chemin = tmp_path_factory.mktemp("modele") / "exfildns.keras"
    sauvegarder(reseau, chemin)
    return chemin
