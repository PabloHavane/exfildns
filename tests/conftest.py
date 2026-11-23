"""Utilitaires partagés par les tests : captures et jeux de données synthétiques."""

import numpy as np
import pandas as pd
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter

from exfildns.features import FEATURES

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
