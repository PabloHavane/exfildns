"""Utilitaires partagés par les tests : fabrication de captures synthétiques."""

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter

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
