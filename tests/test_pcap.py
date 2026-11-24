from conftest import NOM_EXFIL, ecrire_pcap, requete
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from exfildns.pcap import (
    COLONNES,
    en_dataframe,
    est_requete,
    lire_question,
    read_dns_queries,
    requete_dns,
)


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


# --- requete_dns : décodage d'un seul paquet (fichier et capture en direct) ---


def test_requete_dns_paquet_construit_en_memoire():
    # paquet sans octets d'origine (`original` vide) : il est sérialisé
    paquet = requete("example.com", src="10.0.0.2", dst="10.0.0.1", qtype="TXT")
    paquet.time = 12.5

    assert requete_dns(paquet) == (12.5, "10.0.0.2", "10.0.0.1", "example.com", 16)


def test_requete_dns_paquet_recu_du_reseau():
    # paquet disséqué depuis des octets, comme ceux de sniff() ou d'un fichier
    paquet = Ether(bytes(requete("www.example.com")))

    _, src, dst, qname, qtype = requete_dns(paquet)

    assert (src, dst, qname, qtype) == ("192.168.20.38", "8.8.8.8", "www.example.com", 1)


def test_requete_dns_paquet_tronque():
    paquet = Ether(bytes(requete(NOM_EXFIL, dst="192.168.20.72"))[:96])

    _, _, dst, qname, qtype = requete_dns(paquet)

    assert dst == "192.168.20.72"
    assert NOM_EXFIL.startswith(qname) and len(qname) > 20
    assert qtype is None


def test_requete_dns_ipv6():
    ipv6 = IPv6(src="fe80::1", dst="fe80::2")
    paquet = Ether() / ipv6 / UDP(dport=53) / DNS(qd=DNSQR(qname="v6.fr"))

    assert requete_dns(paquet)[1:4] == ("fe80::1", "fe80::2", "v6.fr")


def test_requete_dns_ignore_ce_qui_n_est_pas_une_requete():
    reponse = (
        Ether()
        / IP(src="8.8.8.8", dst="192.168.20.38")
        / UDP(sport=53, dport=50000)
        / DNS(qr=1, qd=DNSQR(qname="example.com"))
    )
    reponse_port_53 = Ether() / IP() / UDP(sport=53, dport=53) / DNS(qr=1, qd=DNSQR(qname="a.fr"))
    autre_port = Ether() / IP() / UDP(dport=5353) / DNS(qd=DNSQR(qname="a.local"))
    tcp = Ether() / IP() / TCP(dport=53)
    udp_vide = Ether() / IP() / UDP(dport=53)
    sans_ip = Ether() / UDP(dport=53) / DNS(qd=DNSQR(qname="a.fr"))

    for paquet in (reponse, reponse_port_53, autre_port, tcp, udp_vide, sans_ip):
        assert requete_dns(paquet) is None, paquet.summary()


def test_en_dataframe_vide_garde_les_colonnes():
    df = en_dataframe([])

    assert df.empty
    assert list(df.columns) == COLONNES


def test_en_dataframe_type_inconnu():
    df = en_dataframe([(1.0, "a", "b", "x.fr", 1), (2.0, "a", "b", "y.fr", None)])

    assert df["qtype"].dtype == "Int64"
    assert df.loc[0, "qtype"] == 1
    assert df["qtype"].isna().tolist() == [False, True]
