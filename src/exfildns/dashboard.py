"""Dashboard Streamlit : supervision des requêtes DNS notées par `exfildns sniff`.

Lancement : `exfildns dashboard` (ou `streamlit run src/exfildns/dashboard.py`).
La base à lire est donnée par la variable d'environnement `EXFILDNS_BASE`, le modèle utilisé
pour analyser une capture importée par `EXFILDNS_MODELE`.

Les fonctions de préparation des données sont pures et testées sans navigateur ; l'interface
n'est construite que lorsque Streamlit exécute ce fichier (`page()`, tout en bas).
"""

import io
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pandas as pd

from exfildns.alertes import MIN_REQUETES, alertes
from exfildns.evaluation import SEUIL

BASE_PAR_DEFAUT = "detections.db"
MODELE_PAR_DEFAUT = "models/exfildns.keras"
EXTENSIONS_CAPTURE = ["pcap", "pcapng"]
CAPTURES_EN_CACHE = 5  # analyses gardées en mémoire (une par fichier déposé)
RAFRAICHISSEMENT = 5  # secondes

# Période affichée -> durée en secondes (None : toute la base)
PERIODES = {
    "5 dernières minutes": 5 * 60,
    "15 dernières minutes": 15 * 60,
    "dernière heure": 60 * 60,
    "24 dernières heures": 24 * 60 * 60,
    "tout": None,
}


def lire_requetes(base: str | Path, depuis: float | None = None) -> pd.DataFrame:
    """Requêtes enregistrées par `exfildns sniff`, depuis l'instant `depuis` (timestamp Unix).

    La base est ouverte en **lecture seule** : le dashboard ne modifie jamais les détections.
    Si la capture tourne en root, le dashboard ne peut pas écrire dans ses fichiers : tant que
    la capture écrit, SQLite le gère ; une fois la capture arrêtée, le fichier `-shm` a disparu
    et ne peut pas être recréé, on relit alors la base comme figée (`immutable`), ce qui est
    sûr puisque plus personne ne l'écrit.
    """
    sql = "SELECT * FROM requetes"
    params: tuple = ()
    if depuis is not None:
        sql += " WHERE timestamp >= ?"
        params = (depuis,)
    uri = f"{Path(base).resolve().as_uri()}?mode=ro"
    try:
        requetes = _lire(uri, sql, params)
    except pd.errors.DatabaseError as erreur:
        if "readonly" not in str(erreur):
            raise
        requetes = _lire(uri + "&immutable=1", sql, params)
    return requetes.astype({"qtype": "Int64", "score": float})


def _lire(uri: str, sql: str, params: tuple) -> pd.DataFrame:
    with closing(sqlite3.connect(uri, uri=True)) as connexion:
        return pd.read_sql_query(sql + " ORDER BY timestamp", connexion, params=params)


def en_heure(timestamps: pd.Series) -> pd.Series:
    """Timestamps Unix -> dates à l'heure locale de la machine."""
    fuseau = datetime.now().astimezone().tzinfo
    return pd.to_datetime(timestamps, unit="s", utc=True).dt.tz_convert(fuseau)


def indicateurs(requetes: pd.DataFrame, seuil: float, resume: pd.DataFrame) -> dict[str, int]:
    """Chiffres clés de la période : requêtes analysées, suspectes, alertes, postes."""
    return {
        "analysees": len(requetes),
        "suspectes": int((requetes["score"] >= seuil).sum()),
        "alertes": len(resume),
        "postes": requetes["src"].nunique(),
    }


def activite_par_minute(requetes: pd.DataFrame, seuil: float) -> pd.DataFrame:
    """Nombre de requêtes bénignes et suspectes par minute (index : la minute)."""
    if requetes.empty:
        return pd.DataFrame(columns=["bénignes", "suspectes"])
    minute = en_heure(requetes["timestamp"]).dt.floor("min")
    classe = (requetes["score"] >= seuil).map({False: "bénignes", True: "suspectes"})
    activite = pd.crosstab(minute, classe).reindex(columns=["bénignes", "suspectes"], fill_value=0)
    activite.index.name = "minute"
    activite.columns.name = None
    return activite


def classement(suspectes: pd.DataFrame, colonne: str, n: int = 10) -> pd.DataFrame:
    """Les `n` valeurs de `colonne` les plus fréquentes parmi les requêtes suspectes."""
    compte = suspectes[colonne].value_counts().head(n)
    return compte.rename_axis(colonne).reset_index(name="requêtes suspectes")


def tableau_alertes(resume: pd.DataFrame) -> pd.DataFrame:
    """Alertes mises en forme pour l'affichage (heures lisibles, colonnes en français)."""
    return pd.DataFrame(
        {
            "domaine": resume["domaine"],
            "requêtes suspectes": resume["requetes_suspectes"],
            "score moyen": resume["score_moyen"].round(3),
            "postes": resume["sources"],
            "début": en_heure(resume["debut"]).dt.strftime("%d/%m %H:%M:%S"),
            "fin": en_heure(resume["fin"]).dt.strftime("%d/%m %H:%M:%S"),
        }
    )


def tableau_requetes(suspectes: pd.DataFrame, n: int = 100) -> pd.DataFrame:
    """Les `n` requêtes suspectes les plus récentes, mises en forme."""
    recentes = suspectes.sort_values("timestamp", ascending=False).head(n)
    return pd.DataFrame(
        {
            "heure": en_heure(recentes["timestamp"]).dt.strftime("%d/%m %H:%M:%S"),
            "score": recentes["score"].round(3),
            "poste": recentes["src"],
            "serveur DNS": recentes["dst"],
            "nom demandé": recentes["qname"],
        }
    )


def analyser_capture(contenu: bytes, chemin_modele: str) -> pd.DataFrame:
    """Requêtes DNS d'un fichier de capture (contenu brut), notées par le modèle.

    Même chaîne que `exfildns sniff` (`noter` : décodage des paquets, features, modèle).
    Lève `Scapy_Exception` si le fichier n'est pas une capture lisible. Le résultat est mis en
    cache par le dashboard : après un réentraînement, relancer le dashboard.
    """
    from scapy.utils import PcapReader

    from exfildns.model import charger
    from exfildns.sniff import noter

    with PcapReader(io.BytesIO(contenu)) as paquets:
        return noter(charger(chemin_modele), paquets)


# --- Interface (exécutée par Streamlit uniquement) ---


def afficher_resultats(st, requetes: pd.DataFrame, seuil: float, min_requetes: int) -> None:
    """Chiffres clés, alertes, activité et requêtes suspectes d'un ensemble de requêtes notées."""
    resume = alertes(requetes, seuil, min_requetes)
    suspectes = requetes[requetes["score"] >= seuil]
    chiffres = indicateurs(requetes, seuil, resume)

    colonnes = st.columns(4)
    colonnes[0].metric("Requêtes analysées", chiffres["analysees"])
    colonnes[1].metric("Requêtes suspectes", chiffres["suspectes"])
    colonnes[2].metric("Alertes", chiffres["alertes"])
    colonnes[3].metric("Postes observés", chiffres["postes"])

    if requetes.empty:
        st.info("Aucune requête DNS à analyser.")
        return
    if resume.empty:
        st.success("Aucune alerte : pas d'exfiltration détectée.")
    else:
        domaines = ", ".join(resume["domaine"].head(3))
        st.error(f"{len(resume)} alerte(s) : exfiltration DNS probable vers {domaines}.")
        st.dataframe(tableau_alertes(resume), hide_index=True, width="stretch")

    st.subheader("Activité DNS par minute")
    st.bar_chart(activite_par_minute(requetes, seuil), color=["#4c78a8", "#e45756"])

    if suspectes.empty:
        return
    gauche, droite = st.columns(2)
    gauche.subheader("Postes à l'origine des requêtes suspectes")
    gauche.dataframe(classement(suspectes, "src"), hide_index=True, width="stretch")
    droite.subheader("Serveurs DNS interrogés")
    droite.dataframe(classement(suspectes, "dst"), hide_index=True, width="stretch")
    st.subheader("Requêtes suspectes les plus récentes")
    st.dataframe(tableau_requetes(suspectes), hide_index=True, width="stretch")


def supervision(st, base: str, seuil: float, min_requetes: int, periode: str) -> None:
    """Onglet de supervision en direct : requêtes de la base écrite par `exfildns sniff`."""
    if not Path(base).exists():
        st.info(
            f"Aucune base de détections ({base}). Lancer la capture : "
            "`exfildns sniff -i <interface>`."
        )
        return
    duree = PERIODES[periode]
    requetes = lire_requetes(base, None if duree is None else time.time() - duree)
    st.caption(f"Période : {periode}.")
    afficher_resultats(st, requetes, seuil, min_requetes)


def capture_importee(st, chemin_modele: str, seuil: float, min_requetes: int) -> None:
    """Onglet d'analyse d'un fichier de capture déposé par l'utilisateur."""
    from scapy.error import Scapy_Exception

    fichier = st.file_uploader("Capture réseau à analyser", type=EXTENSIONS_CAPTURE, key="capture")
    if fichier is None:
        st.caption("Déposer un fichier .pcap ou .pcapng : il est analysé comme `exfildns scan`.")
        return
    if not Path(chemin_modele).exists():
        st.warning(f"Modèle introuvable : {chemin_modele} (lancer d'abord `exfildns train`).")
        return
    try:
        with st.spinner(f"Analyse de {fichier.name}…"):
            analyse = st.cache_data(
                analyser_capture, show_spinner=False, max_entries=CAPTURES_EN_CACHE
            )
            requetes = analyse(fichier.getvalue(), chemin_modele)
    except Scapy_Exception:
        st.error(f"{fichier.name} n'est pas une capture réseau lisible (pcap ou pcapng).")
        return
    st.caption(f"Capture : {fichier.name}.")
    afficher_resultats(st, requetes, seuil, min_requetes)


def page() -> None:
    import streamlit as st

    st.set_page_config(page_title="exfildns", layout="wide")
    st.title("exfildns — détection d'exfiltration DNS")
    base = os.environ.get("EXFILDNS_BASE", BASE_PAR_DEFAUT)
    chemin_modele = os.environ.get("EXFILDNS_MODELE", MODELE_PAR_DEFAUT)

    with st.sidebar:
        st.header("Réglages")
        seuil = st.slider("Seuil de détection", 0.0, 1.0, SEUIL, 0.05, key="seuil")
        min_requetes = st.number_input(
            "Requêtes suspectes pour une alerte", 1, 10_000, MIN_REQUETES, key="min_requetes"
        )
        periode = st.selectbox("Période", list(PERIODES), index=2, key="periode")
        auto = st.toggle(f"Rafraîchir toutes les {RAFRAICHISSEMENT} s", True, key="auto")
        st.caption(f"Base : `{base}`")

    direct, importee = st.tabs(["Supervision en direct", "Analyser une capture"])

    @st.fragment(run_every=RAFRAICHISSEMENT if auto else None)
    def vue_directe() -> None:
        supervision(st, base, seuil, int(min_requetes), periode)

    with direct:
        vue_directe()
    with importee:
        capture_importee(st, chemin_modele, seuil, int(min_requetes))


if __name__ == "__main__":
    page()
