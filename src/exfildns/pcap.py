"""Lecture des requêtes DNS d'une capture réseau (pcap ou pcapng)."""

import struct
from pathlib import Path

import pandas as pd
from scapy.layers.inet import IP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

COLONNES = ["timestamp", "src", "dst", "qname", "qtype", "taille"]
PORT_DNS = 53
TAILLE_ENTETE_DNS = 12
TAILLE_ENTETE_UDP = 8


def est_requete(dns: bytes) -> bool:
    """Vrai si le message DNS est une requête (bit QR à 0) avec au moins une question."""
    if len(dns) <= TAILLE_ENTETE_DNS:
        return False
    qr = dns[2] & 0x80
    (nb_questions,) = struct.unpack(">H", dns[4:6])
    return not qr and nb_questions > 0


def lire_question(dns: bytes) -> tuple[str, int | None]:
    """Lit le nom et le type de la première question d'un message DNS, même tronqué.

    Le message est lu octet par octet, car scapy ne décode pas les messages coupés
    (paquets capturés avec une petite taille de capture, cf. docs/donnees.md).
    Si le nom est coupé, on renvoie la partie lisible et un type `None`.
    """
    labels = []
    i = TAILLE_ENTETE_DNS
    while i < len(dns):
        longueur = dns[i]
        if longueur == 0:  # fin du nom : le type suit sur 2 octets
            if len(dns) >= i + 3:
                return ".".join(labels), struct.unpack(">H", dns[i + 1 : i + 3])[0]
            return ".".join(labels), None
        if longueur >= 0x40:  # pointeur de compression ou type réservé : pas un label normal
            break
        # latin-1 : un octet = un caractère, pour que les longueurs restent justes
        labels.append(dns[i + 1 : i + 1 + longueur].decode("latin-1"))
        i += 1 + longueur
    return ".".join(labels), None


def requete_dns(paquet) -> tuple[float, str, str, str, int | None, int] | None:
    """Transforme un paquet scapy en requête `(timestamp, src, dst, qname, qtype, taille)`.

    `taille` est la taille du message DNS en octets, lue dans l'en-tête UDP : elle reste juste
    même si la capture a tronqué le paquet. Renvoie `None` si le paquet n'est pas une requête.

    Seules les requêtes DNS (UDP, port 53, IPv4 ou IPv6) sont gardées : réponses et trafic
    non DNS donnent `None`. Sert à la lecture d'un fichier comme à la capture en direct,
    pour que les deux voient exactement les mêmes requêtes.
    """
    if UDP not in paquet or paquet[UDP].dport != PORT_DNS:
        return None
    couche_ip = paquet[IP] if IP in paquet else paquet[IPv6] if IPv6 in paquet else None
    if couche_ip is None:
        return None
    # octets bruts reçus, et non le DNS ré-encodé par scapy (qui échoue sur un paquet tronqué) ;
    # pour un paquet construit en mémoire, sans octets d'origine, on le sérialise
    charge = paquet[UDP].payload
    dns = charge.original or bytes(charge)
    if not est_requete(dns):
        return None
    qname, qtype = lire_question(dns)
    # longueur UDP (en-tête de 8 octets compris) ; absente d'un paquet construit en mémoire
    longueur_udp = paquet[UDP].len
    taille = longueur_udp - TAILLE_ENTETE_UDP if longueur_udp else len(dns)
    return float(paquet.time), couche_ip.src, couche_ip.dst, qname, qtype, taille


def en_dataframe(requetes: list[tuple]) -> pd.DataFrame:
    """Range des requêtes renvoyées par `requete_dns` dans un DataFrame aux colonnes `COLONNES`."""
    return pd.DataFrame(requetes, columns=COLONNES).astype({"qtype": "Int64", "taille": "Int64"})


def read_dns_queries(chemin: str | Path) -> pd.DataFrame:
    """Extrait les requêtes DNS (UDP, port 53, IPv4 ou IPv6) d'une capture.

    Renvoie un DataFrame aux colonnes `COLONNES`, vide si la capture ne contient
    aucune requête DNS. Les réponses et le trafic non DNS sont ignorés.
    """
    with PcapReader(str(chemin)) as paquets:
        requetes = [r for paquet in paquets if (r := requete_dns(paquet)) is not None]
    return en_dataframe(requetes)
