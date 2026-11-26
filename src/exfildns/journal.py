"""Requêtes DNS lues dans le journal d'un résolveur Unbound, au lieu du trafic réseau.

Le résolveur voit les requêtes de **tout le réseau** sans port miroir. Unbound les journalise
avec `log-queries: yes` (dans un fichier : `logfile:` et `use-syslog: no`), une ligne par
requête :

    [1764158400] unbound[812:0] info: 192.168.1.20 www.exemple.fr. A IN

Chaque ligne devient le même tuple que `pcap.requete_dns` : la notation et l'enregistrement
sont ceux de la capture réseau. Limites (docs/deploiement.md) : pas de taille de message, le
poste est le client vu par le résolveur, le serveur interrogé est le résolveur lui-même, et
Unbound peut écrire `?` à la place des caractères inhabituels d'un nom.
"""

import os
import re
import time
from collections.abc import Iterator
from pathlib import Path

# Valeur de la colonne `dst` : le journal ne dit pas sur quelle adresse le résolveur a répondu
RESOLVEUR = "résolveur"

# Horodatage Unix (log-time-ascii: no, défaut), client, nom, type, classe IN en fin de ligne.
# Les lignes de réponse (log-replies) continuent après IN : elles ne correspondent pas.
LIGNE = re.compile(r"^\[(\d+(?:\.\d+)?)\] unbound\[[^\]]*\] info: (\S+) (\S+) (\S+) IN$")

# Types d'enregistrement par nom -> numéro (les autres s'écrivent TYPE<n> dans le journal)
TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "NULL": 10, "PTR": 12, "MX": 15, "TXT": 16,
         "AAAA": 28, "SRV": 33, "SVCB": 64, "HTTPS": 65, "ANY": 255}  # fmt: skip


def requete_journal(ligne: str) -> tuple[float, str, str, str, int | None, None] | None:
    """`(timestamp, src, dst, qname, qtype, taille)` d'une ligne de requête, sinon `None`."""
    trouve = LIGNE.match(ligne.strip())
    if trouve is None:
        return None
    instant, client, nom, type_ = trouve.groups()
    qtype = TYPES.get(type_)
    if qtype is None and type_.startswith("TYPE") and type_[4:].isdigit():
        qtype = int(type_[4:])
    return float(instant), client, RESOLVEUR, nom.rstrip("."), qtype, None


def lots_journal(
    chemin: str | Path, duree_lot: float = 1.0, depuis_debut: bool = False
) -> Iterator[list[str]]:
    """Lignes ajoutées au journal, par lots de `duree_lot` secondes (comme `tail -F`).

    Le fichier est ouvert **tout de suite** : `FileNotFoundError` ou `PermissionError` sortent
    ici. On part de la fin (seules les nouvelles requêtes comptent) sauf avec `depuis_debut`.
    Rotation (fichier renommé puis recréé) ou troncature : le fichier est relu depuis le début.
    """
    fichier = open(chemin, encoding="utf-8", errors="replace")  # noqa: SIM115 (fermé plus bas)
    if not depuis_debut:
        fichier.seek(0, os.SEEK_END)
    return _suivre(fichier, Path(chemin), duree_lot)


def _suivre(fichier, chemin: Path, duree_lot: float) -> Iterator[list[str]]:
    reste = ""  # ligne en cours d'écriture, complétée au lot suivant
    try:
        while True:
            time.sleep(duree_lot)
            texte = reste + fichier.read()
            if _remplace(fichier, chemin):
                texte += fichier.read()  # dernières lignes de l'ancien fichier
                fichier.close()
                fichier = open(chemin, encoding="utf-8", errors="replace")  # noqa: SIM115
                texte += "\n" if texte and not texte.endswith("\n") else ""
            *lignes, reste = texte.split("\n")
            yield lignes
    finally:
        fichier.close()


def _remplace(fichier, chemin: Path) -> bool:
    """Vrai si le journal a tourné (autre fichier au même chemin) ou a été tronqué."""
    try:
        actuel = chemin.stat()
    except FileNotFoundError:  # entre le renommage et la recréation : on attend
        return False
    return actuel.st_ino != os.fstat(fichier.fileno()).st_ino or actuel.st_size < fichier.tell()
