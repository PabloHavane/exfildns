"""Détection en direct : chaque requête DNS capturée est notée par le modèle puis enregistrée.

Les requêtes et leur score vont dans une base SQLite que le dashboard lit sans privilège ;
seule la capture demande root ou la capacité `CAP_NET_RAW` (docs/decisions.md).
Le décodage des paquets et le calcul des features sont ceux de l'analyse d'un fichier PCAP.
"""

import select
import sqlite3
import time
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

import pandas as pd
from scapy.all import conf  # scapy.all charge les sockets de capture et l'interface par défaut

from exfildns.features import features_dataframe
from exfildns.model import predire_proba
from exfildns.pcap import en_dataframe, requete_dns

# Filtre appliqué par le noyau : seules les requêtes vers un serveur DNS remontent à Python.
FILTRE_BPF = "udp dst port 53"

SCHEMA = """
CREATE TABLE IF NOT EXISTS requetes (
    timestamp REAL NOT NULL,  -- secondes depuis le 1er janvier 1970 (UTC)
    src TEXT NOT NULL,        -- poste qui pose la question
    dst TEXT NOT NULL,        -- serveur DNS interrogé
    qname TEXT NOT NULL,      -- nom demandé
    qtype INTEGER,            -- type d'enregistrement (1 = A, 16 = TXT…), NULL si inconnu
    score REAL NOT NULL       -- probabilité d'exfiltration donnée par le modèle
);
CREATE INDEX IF NOT EXISTS requetes_timestamp ON requetes (timestamp);
"""


def ouvrir_base(chemin: str | Path) -> sqlite3.Connection:
    """Ouvre (ou crée) la base des requêtes notées."""
    Path(chemin).parent.mkdir(parents=True, exist_ok=True)
    connexion = sqlite3.connect(chemin)
    # WAL : le dashboard peut lire pendant que la capture écrit
    connexion.execute("PRAGMA journal_mode=WAL")
    connexion.executescript(SCHEMA)
    return connexion


def noter(modele, paquets: Iterable) -> pd.DataFrame:
    """Requêtes DNS contenues dans `paquets`, avec leur probabilité d'exfiltration (`score`)."""
    requetes = en_dataframe([r for p in paquets if (r := requete_dns(p)) is not None])
    if requetes.empty:
        requetes["score"] = pd.Series(dtype=float)
    else:
        requetes["score"] = predire_proba(modele, features_dataframe(requetes["qname"]))
    return requetes


def enregistrer(connexion: sqlite3.Connection, requetes: pd.DataFrame) -> None:
    """Ajoute des requêtes notées (sortie de `noter`) à la base."""
    lignes = [
        (r.timestamp, r.src, r.dst, r.qname, None if pd.isna(r.qtype) else int(r.qtype), r.score)
        for r in requetes.itertuples()
    ]
    with connexion:  # une transaction par lot
        connexion.executemany("INSERT INTO requetes VALUES (?, ?, ?, ?, ?, ?)", lignes)


def surveiller(
    lots: Iterable[Iterable],
    modele,
    connexion: sqlite3.Connection,
    seuil: float,
    afficher: Callable[[str], None] = lambda ligne: print(ligne, flush=True),
) -> tuple[int, int]:
    """Note et enregistre chaque lot de paquets ; affiche les requêtes suspectes au fil de l'eau.

    S'arrête quand les lots sont épuisés ou sur Ctrl+C (le lot en cours n'est alors pas
    enregistré) ; renvoie `(requêtes analysées, requêtes suspectes)`.
    """
    analysees = suspectes = 0
    try:
        for paquets in lots:
            requetes = noter(modele, paquets)
            if requetes.empty:
                continue
            enregistrer(connexion, requetes)
            alertes = requetes[requetes["score"] >= seuil]
            for r in alertes.itertuples():
                afficher(f"{r.score:.3f}  {r.src} -> {r.dst}  {r.qname}")
            analysees += len(requetes)
            suspectes += len(alertes)
    except KeyboardInterrupt:
        pass
    return analysees, suspectes


def lots_reseau(interface: str | None = None, duree_lot: float = 1.0) -> Iterator[list]:
    """Paquets DNS capturés sur `interface` (par défaut celle de scapy), par lots de `duree_lot` s.

    Le socket est ouvert **tout de suite**, avant la première lecture : les erreurs de capture
    sortent ici et non au milieu de la notation. Lève `PermissionError` sans root ni
    `CAP_NET_RAW`, `ValueError` si l'interface n'existe pas, `Scapy_Exception` sans libpcap.
    """
    interface = interface or conf.iface
    filtre = FILTRE_BPF
    if interface == "lo":  # bouclage : chaque paquet est vu en sortie puis en entrée
        filtre = f"inbound and {filtre}"
    return _lire_par_lots(conf.L2listen(iface=interface, filter=filtre), duree_lot)


def _lire_par_lots(socket, duree_lot: float) -> Iterator[list]:
    """Lit le socket par lots ; le ferme quand la lecture s'arrête.

    Le socket est ouvert une seule fois : aucun paquet n'est perdu entre deux lots. Il est lu
    directement plutôt qu'avec `scapy.sniff`, qui avalerait Ctrl+C au lieu de le transmettre.
    """
    try:
        while True:
            lot = []
            fin = time.monotonic() + duree_lot
            while (reste := fin - time.monotonic()) > 0:
                if select.select([socket], [], [], reste)[0]:
                    paquet = socket.recv()
                    if paquet is not None:
                        lot.append(paquet)
            yield lot
    finally:
        socket.close()
