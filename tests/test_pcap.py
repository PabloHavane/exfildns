from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapWriter

from exfildns.pcap import COLONNES, est_requete, lire_question, read_dns_queries

NOM_EXFIL = "0.J4HgHlgzQH6j0WZF8m3DQx3jGodWnpcKYKFAeUM.attaquant.example"


def requete(nom, src="192.168.20.38", dst="8.8.8.8", qtype="A"):
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


def test_lire_question_nom_complet():
    dns = bytes(DNS(qd=DNSQR(qname="www.example.com", qtype="TXT")))
    assert lire_question(dns) == ("www.example.com", 16)


def test_lire_question_nom_tronque():
    dns = bytes(DNS(qd=DNSQR(qname=NOM_EXFIL)))[:42]
    nom, qtype = lire_question(dns)
    assert NOM_EXFIL.startswith(nom)
    assert len(nom) > 20
    assert qtype is None


def test_est_requete():
    assert est_requete(bytes(DNS(qd=DNSQR(qname="a.fr"))))
    assert not est_requete(bytes(DNS(qr=1, qd=DNSQR(qname="a.fr"))))
    assert not est_requete(b"\x00" * 12)


def test_read_dns_queries_filtre_et_extrait(tmp_path):
    chemin = tmp_path / "capture.pcap"
    reponse = (
        Ether()
        / IP(src="8.8.8.8", dst="192.168.20.38")
        / UDP(sport=53, dport=50000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com"))
    )
    ipv6 = (
        Ether() / IPv6(src="fe80::1", dst="fe80::2") / UDP(dport=53) / DNS(qd=DNSQR(qname="v6.fr"))
    )
    tcp = Ether() / IP() / TCP(dport=443)
    udp_vide = Ether() / IP() / UDP(dport=53)
    ecrire_pcap(chemin, [requete("example.com"), reponse, ipv6, tcp, udp_vide])

    df = read_dns_queries(chemin)

    assert list(df.columns) == COLONNES
    assert df.qname.tolist() == ["example.com", "v6.fr"]
    assert df.loc[0, "src"] == "192.168.20.38"
    assert df.loc[0, "dst"] == "8.8.8.8"
    assert df.loc[0, "qtype"] == 1
    assert df.loc[1, "dst"] == "fe80::2"


def test_read_dns_queries_paquets_tronques_a_96_octets(tmp_path):
    chemin = tmp_path / "tronque.pcap"
    ecrire_pcap(chemin, [requete(NOM_EXFIL, dst="192.168.20.72")], snaplen=96)

    df = read_dns_queries(chemin)

    assert len(df) == 1
    assert NOM_EXFIL.startswith(df.loc[0, "qname"])
    assert df.loc[0, "qname"].startswith("0.J4HgHlgzQH6j0")
    assert df.loc[0, "dst"] == "192.168.20.72"
    assert df.qtype.isna().all()


def test_read_dns_queries_capture_sans_dns(tmp_path):
    chemin = tmp_path / "vide.pcap"
    ecrire_pcap(chemin, [Ether() / IP() / TCP(dport=443)])

    df = read_dns_queries(chemin)

    assert df.empty
    assert list(df.columns) == COLONNES
