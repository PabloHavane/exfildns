"""Notification des alertes de sévérité haute par webhook HTTP, sans garder le dashboard ouvert.

Un petit service à part (`exfildns notifier`) relit périodiquement la base des détections et
celle du dashboard, **en lecture seule**, recalcule les alertes comme le dashboard (même liste
blanche, mêmes statuts, même sévérité) et envoie un message JSON par alerte haute nouvellement
apparue. Il ne demande aucun privilège ; la capture, elle, n'a rien à savoir des notifications
(docs/decisions.md).
"""

import json
import re
import sqlite3
import sys
import time
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pandas as pd

from exfildns import liste_blanche, statuts, synthese
from exfildns.alertes import alertes
from exfildns.dashboard import lire_requetes

# Caractères gardés tels quels dans le texte d'un message : le reste vient du réseau, il est
# remplacé pour qu'un nom forgé ne puisse pas injecter de mise en forme, de lien ni de mention.
CARACTERES_SURS = re.compile(r"[^A-Za-z0-9._-]")
LONGUEUR_MAX = 100
DELAI_ENVOI = 10  # secondes avant d'abandonner un envoi (réessayé au tour suivant)


def assainir(texte: str) -> str:
    """Texte réduit aux lettres, chiffres, `.`, `_`, `-` (autres caractères -> `?`), tronqué."""
    sur = CARACTERES_SURS.sub("?", str(texte))
    return sur if len(sur) <= LONGUEUR_MAX else sur[: LONGUEUR_MAX - 1] + "…"


def alertes_hautes(
    requetes: pd.DataFrame,
    seuil: float,
    min_requetes: int,
    liste: list[str],
    connus: pd.DataFrame,
) -> pd.DataFrame:
    """Alertes ouvertes (ni faux positif ni close) de sévérité haute, comme dans le dashboard."""
    resume = statuts.ouvertes(
        statuts.appliquer(alertes(requetes, seuil, min_requetes, liste), connus)
    )
    file = synthese.file_alertes(resume, min_requetes)
    return file[file["severite"] == "haute"]


def message(alerte) -> dict:
    """Corps JSON envoyé pour une alerte ; `text` est lu par Slack, Mattermost, Rocket.Chat…"""
    domaine = assainir(alerte.domaine)
    postes = [assainir(p) for p in str(alerte.postes).split(",")][:5]
    fin = datetime.fromtimestamp(alerte.fin, UTC).isoformat(timespec="seconds")
    return {
        "text": (
            f"exfildns : alerte haute, `{domaine}` ({alerte.requetes_suspectes} requêtes "
            f"suspectes, score max {alerte.score_max:.2f}, postes {', '.join(postes)})"
        ),
        "domaine": domaine,
        "requetes_suspectes": int(alerte.requetes_suspectes),
        "score_max": round(float(alerte.score_max), 3),
        "postes": postes,
        "derniere_requete": fin,
    }


def envoyer(url: str, corps: dict) -> None:
    """POST JSON vers le webhook ; lève `OSError` (dont `urllib.error.URLError`) en cas d'échec."""
    requete = urllib.request.Request(
        url,
        data=json.dumps(corps, ensure_ascii=False).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(requete, timeout=DELAI_ENVOI):
        pass


def tour(
    base: str | Path,
    chemin_statuts: str | Path,
    deja: set[str],
    seuil: float,
    min_requetes: int,
    fenetre: float,
    envoi: Callable[[dict], None],
    maintenant: float,
    journal: Callable[[str], None],
) -> None:
    """Un passage : notifie chaque alerte haute absente de `deja` (mis à jour en place).

    Anti-répétition : une alerte est notifiée une fois. Elle sort de `deja` quand elle n'est
    plus haute et ouverte sur la fenêtre (tunnel arrêté, statut close…) : si elle revient,
    c'est une nouvelle alerte, notifiée à nouveau. Un envoi raté est retenté au tour suivant.
    """
    requetes = lire_requetes(base, maintenant - fenetre)
    liste = liste_blanche.complete(chemin_statuts)
    hautes = alertes_hautes(requetes, seuil, min_requetes, liste, statuts.lire(chemin_statuts))
    deja.intersection_update(hautes["domaine"])
    for alerte in hautes.itertuples():
        if alerte.domaine in deja:
            continue
        try:
            envoi(message(alerte))
        except OSError as erreur:
            journal(f"Notification non envoyée ({assainir(alerte.domaine)}) : {erreur}")
            continue
        deja.add(alerte.domaine)
        journal(f"Alerte haute notifiée : {assainir(alerte.domaine)}")


def surveiller(
    base: str | Path,
    chemin_statuts: str | Path,
    url: str,
    seuil: float,
    min_requetes: int,
    fenetre: float,
    intervalle: float,
    journal: Callable[[str], None] = lambda ligne: print(ligne, file=sys.stderr, flush=True),
) -> None:
    """Boucle de notification jusqu'à Ctrl+C ; une base illisible est signalée et réessayée."""
    deja: set[str] = set()
    try:
        while True:
            if Path(base).exists():
                try:
                    tour(
                        base,
                        chemin_statuts,
                        deja,
                        seuil,
                        min_requetes,
                        fenetre,
                        lambda corps: envoyer(url, corps),
                        time.time(),
                        journal,
                    )
                except (sqlite3.Error, pd.errors.DatabaseError, OSError) as erreur:
                    journal(f"Lecture impossible : {erreur}")
            time.sleep(intervalle)
    except KeyboardInterrupt:
        pass
