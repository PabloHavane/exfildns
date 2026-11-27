"""Dashboard Streamlit : supervision des requêtes DNS notées par `exfildns sniff`.

Lancement : `exfildns dashboard` (ou `streamlit run src/exfildns/dashboard.py`).
La base à lire est donnée par la variable d'environnement `EXFILDNS_BASE`, le modèle utilisé
pour analyser une capture importée par `EXFILDNS_MODELE`, la base des statuts d'alertes et de la
liste blanche (la seule où le dashboard écrit) par `EXFILDNS_STATUTS` (par défaut `statuts.db` à
côté de la base). Si `EXFILDNS_MOT_DE_PASSE` est définie, le dashboard demande ce mot de passe
avant d'afficher quoi que ce soit (docs/decisions.md).

Les fonctions de préparation des données sont pures et testées sans navigateur ; l'interface
n'est construite que lorsque Streamlit exécute ce fichier (`page()`, tout en bas).
"""

import hmac
import html
import io
import os
import sqlite3
import time
import zlib
from collections.abc import Sequence
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pandas as pd

from exfildns import SEUIL, __version__, detail, liste_blanche, statuts, synthese
from exfildns.alertes import LISTE_BLANCHE, MIN_REQUETES, alertes, domaine_parent, est_autorise

BASE_PAR_DEFAUT = "detections.db"
STATUTS = "statuts.db"  # nom par défaut de la base des statuts, à côté de la base des détections
MODELE_PAR_DEFAUT = "models/exfildns.keras"
EXTENSIONS_CAPTURE = ["pcap", "pcapng"]
PAUSE_ECHEC = 1.0  # secondes d'attente après un mauvais mot de passe
CAPTURES_EN_CACHE = 5  # analyses gardées en mémoire (une par fichier déposé)
RAFRAICHISSEMENT = 5  # secondes
ALERTES_MAX = 20  # cartes affichées dans la file d'alertes
LIGNES_MAX = 5000  # requêtes affichées dans l'onglet « Requêtes » (les plus récentes)

# Bandeau d'état (une ligne, en tête de page)
STYLE_BANDEAU = """<style>
.bandeau { display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem 1.2rem;
  font-size: 0.9rem; padding: 0.4rem 0 0.6rem; border-bottom: 1px solid rgba(128,128,128,0.3); }
.bandeau .marque { font-weight: 700; font-size: 1.1rem; }
.bandeau .pastille { display: inline-block; width: 0.7rem; height: 0.7rem; border-radius: 50%;
  margin-right: 0.35rem; vertical-align: middle; }
.bandeau .discret { opacity: 0.7; }
</style>"""
COULEURS_CAPTEUR = {"green": "#2ca02c", "orange": "#ff9f1c", "red": "#e45756"}

# Mise en évidence du nom découpé label par label (onglet « Requêtes »)
STYLE_QNAME = """<style>
.qname { font-family: monospace; font-size: 1.1rem; line-height: 2.2; word-break: break-all; }
.qname .label { padding: 0.15rem 0.4rem; border-radius: 0.3rem; }
.qname .suspect { background: rgba(228, 87, 86, 0.25); border: 1px solid #e45756; }
.qname .parent { background: rgba(128, 128, 128, 0.2); }
.qname .point { opacity: 0.6; padding: 0 0.1rem; }
</style>"""

# Timeline : largeur d'une barre en minutes, la plus petite qui donne au plus `BARRES_MAX` barres
# (Altair refuse plus de 5000 lignes, soit 2500 barres de deux classes).
INTERVALLES = {
    1: "minute",
    5: "tranche de 5 min",
    15: "tranche de 15 min",
    60: "heure",
    360: "tranche de 6 h",
    1440: "jour",
}
BARRES_MAX = 1440
# Écart entre deux graduations, en minutes : le plus petit qui donne au plus `GRADUATIONS_MAX`
# libellés, pour qu'ils restent lisibles.
PAS_GRADUATIONS = (1, 2, 5, 10, 15, 30, 60, 120, 180, 360, 720, 1440, 2880, 10080)
GRADUATIONS_MAX = 12

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
    sql = "SELECT rowid AS id, * FROM requetes"  # id : identifiant stable d'une requête
    params: tuple = ()
    if depuis is not None:
        sql += " WHERE timestamp >= ?"
        params = (depuis,)
    requetes = _lecture_seule(base, sql + " ORDER BY timestamp", params)
    if "taille" not in requetes:  # base écrite par une version antérieure, pas encore migrée
        requetes["taille"] = pd.NA
    return requetes.astype({"qtype": "Int64", "score": float, "taille": "Int64"})


def derniere_requete(base: str | Path) -> float | None:
    """Instant (timestamp Unix) de la dernière requête enregistrée, `None` si la base est vide."""
    resultat = _lecture_seule(base, "SELECT MAX(timestamp) AS t FROM requetes", ())
    return None if pd.isna(resultat.loc[0, "t"]) else float(resultat.loc[0, "t"])


ERREURS_LECTURE_SEULE = ("readonly", "unable to open database file")


def _lecture_seule(base: str | Path, sql: str, params: tuple) -> pd.DataFrame:
    """Exécute `sql` sur la base ouverte en lecture seule (voir `lire_requetes`)."""
    uri = f"{Path(base).resolve().as_uri()}?mode=ro"
    try:
        return _lire(uri, sql, params)
    except pd.errors.DatabaseError as erreur:
        # « readonly » : fichiers non modifiables (sniff lancé en root) ; « unable to open » :
        # système de fichiers en lecture seule (volume Docker :ro), -shm impossible à créer
        if not any(cause in str(erreur) for cause in ERREURS_LECTURE_SEULE):
            raise
        return _lire(uri + "&immutable=1", sql, params)


def _lire(uri: str, sql: str, params: tuple) -> pd.DataFrame:
    with closing(sqlite3.connect(uri, uri=True)) as connexion:
        return pd.read_sql_query(sql, connexion, params=params)


def en_heure(timestamps: pd.Series) -> pd.Series:
    """Timestamps Unix -> dates à l'heure locale de la machine."""
    fuseau = datetime.now().astimezone().tzinfo
    return pd.to_datetime(timestamps, unit="s", utc=True).dt.tz_convert(fuseau)


def intervalle(requetes: pd.DataFrame) -> int:
    """Largeur des barres de la timeline, en minutes, selon la durée couverte par les requêtes."""
    duree = (requetes["timestamp"].max() - requetes["timestamp"].min()) / 60 if len(requetes) else 0
    return next((i for i in INTERVALLES if duree / i < BARRES_MAX), max(INTERVALLES))


def activite_dns(requetes: pd.DataFrame, seuil: float, minutes: int = 1) -> pd.DataFrame:
    """Nombre de requêtes bénignes et suspectes par tranche de `minutes` (index : son début).

    Grille fixe, de la première à la dernière requête : une tranche sans trafic apparaît avec
    0 requête au lieu de disparaître du graphique. Les tranches sont alignées sur l'heure locale.
    """
    if requetes.empty:
        return pd.DataFrame(columns=["bénignes", "suspectes"])
    debut = en_heure(requetes["timestamp"]).dt.floor(f"{minutes}min")
    classe = (requetes["score"] >= seuil).map({False: "bénignes", True: "suspectes"})
    activite = pd.crosstab(debut, classe).reindex(columns=["bénignes", "suspectes"], fill_value=0)
    grille = pd.date_range(debut.min(), debut.max(), freq=f"{minutes}min")
    activite = activite.reindex(grille, fill_value=0)
    activite.index.name = "début"
    activite.columns.name = None
    return activite


def instants_alertes(
    requetes: pd.DataFrame,
    seuil: float,
    min_requetes: int,
    liste_blanche=LISTE_BLANCHE,
) -> pd.DataFrame:
    """Instant où chaque alerte est levée : l'arrivée de sa `min_requetes`-ième requête suspecte.

    Mêmes règles que `alertes` (domaine parent, liste blanche) ; colonnes `domaine, instant`
    (timestamp Unix), une ligne par alerte, dans l'ordre chronologique.
    """
    liste_blanche = list(liste_blanche)
    suspectes = requetes[requetes["score"] >= seuil]
    if suspectes.empty:  # une liste vide sélectionnerait des colonnes, pas des lignes
        return pd.DataFrame(columns=["domaine", "instant"])
    suspectes = suspectes[[not est_autorise(q, liste_blanche) for q in suspectes["qname"]]]
    domaines = [
        domaine_parent(q, pd.isna(t))
        for q, t in zip(suspectes["qname"], suspectes["qtype"], strict=True)
    ]
    suspectes = suspectes.assign(domaine=domaines).sort_values("timestamp")
    rang = suspectes.groupby("domaine").cumcount()  # 0 pour la 1re requête suspecte du domaine
    levees = suspectes[rang == min_requetes - 1]
    return pd.DataFrame(
        {"domaine": levees["domaine"].to_numpy(), "instant": levees["timestamp"].to_numpy()}
    )


def pas_graduations(minutes: float) -> int:
    """Écart en minutes entre deux graduations pour une timeline de `minutes` minutes."""
    return next((p for p in PAS_GRADUATIONS if minutes / p <= GRADUATIONS_MAX), PAS_GRADUATIONS[-1])


def graduations(debuts: pd.DatetimeIndex, minutes: int) -> list[pd.Timestamp]:
    """Débuts de tranche où placer une graduation : heures rondes (18:05, 18:10…), à l'heure locale.

    `minutes` est la largeur d'une tranche ; s'il n'y a aucune heure ronde, la première tranche.
    """
    if debuts.empty:
        return []
    ecart = max(pas_graduations(len(debuts) * minutes), minutes)
    minute_locale = (debuts.tz_localize(None) - pd.Timestamp(0)) // pd.Timedelta(minutes=1)
    rondes = debuts[minute_locale % ecart == 0]
    return list(rondes if len(rondes) else debuts[:1])


def graphique_histogramme(histogramme: pd.DataFrame, seuil: float):
    """Histogramme des scores du modèle, seuil de la sidebar en trait vertical."""
    import altair as alt

    # couleur selon le début de tranche : juste tant que le seuil tombe sur une borne
    # (pas du curseur = pas de l'histogramme, 0,05)
    donnees = histogramme.assign(
        classe=["suspectes" if d >= seuil else "bénignes" for d in histogramme["début"]]
    )
    couleurs = alt.Scale(domain=["bénignes", "suspectes"], range=["#4c78a8", "#e45756"])
    barres = (
        alt.Chart(donnees)
        .mark_bar(orient="vertical")
        .encode(
            x=alt.X("début:Q", title="score", scale=alt.Scale(domain=[0, 1])),
            x2="fin:Q",
            # échelle symlog : les nombreuses requêtes bénignes près de 0 n'écrasent pas le reste
            y=alt.Y("requêtes:Q", scale=alt.Scale(type="symlog"), title="requêtes"),
            color=alt.Color("classe:N", scale=couleurs, legend=None),
            tooltip=[
                alt.Tooltip("début:Q", title="de", format=".2f"),
                alt.Tooltip("fin:Q", title="à", format=".2f"),
                "requêtes:Q",
            ],
        )
    )
    trait = (
        alt.Chart(pd.DataFrame({"seuil": [seuil]}))
        .mark_rule(color="#b30000", strokeDash=[4, 3], strokeWidth=2)
        .encode(x="seuil:Q", tooltip=[alt.Tooltip("seuil:Q", format=".2f")])
    )
    return (barres + trait).properties(height=220)


def graphique_qtypes(repartition: pd.DataFrame):
    """Barres horizontales : nombre de requêtes par type d'enregistrement."""
    import altair as alt

    return (
        alt.Chart(repartition)
        .mark_bar(color="#4c78a8")
        .encode(
            x=alt.X("requêtes:Q", title=None),
            y=alt.Y("type:N", sort="-x", title=None),
            tooltip=["type:N", "requêtes:Q"],
        )
        .properties(height=220)
    )


def graphique_activite(
    activite: pd.DataFrame, minutes: int = 1, instants: pd.DataFrame | None = None
):
    """Barres empilées bénignes / suspectes par tranche de `minutes`, sans zoom à la molette.

    Le graphique par défaut de Streamlit est zoomable : la molette le zoomait au lieu de faire
    défiler la page. Un graphique Altair sans `.interactive()` reste fixe.
    Chaque barre couvre sa tranche (`x` à `x2`). Les graduations sont données explicitement
    (`graduations`) : laissé libre, Vega en place toutes les 10-30 s et le format `%H:%M` répète
    le même libellé (et le `tickCount` par intervalle plante le Vega de Streamlit).
    Les instants où une alerte est levée (`instants_alertes`) sont marqués d'un trait vertical.

    Limite connue : les graduations sont en heure locale du serveur et Vega les lit en heure
    locale du navigateur ; les deux doivent avoir le même fuseau (`TZ` dans compose.yaml),
    sinon l'axe n'a plus de libellés (les barres restent justes).
    """
    import altair as alt

    donnees = activite.reset_index().melt("début", var_name="classe", value_name="requêtes")
    donnees["fin"] = donnees["début"] + pd.Timedelta(minutes=minutes)
    couleurs = alt.Scale(domain=["bénignes", "suspectes"], range=["#4c78a8", "#e45756"])
    # en date et heure locales (comme `en_heure`) : Vega n'affiche pas de graduations données
    # en millisecondes sur ce graphique
    valeurs = [
        alt.DateTime(year=m.year, month=m.month, date=m.day, hours=m.hour, minutes=m.minute)
        for m in graduations(activite.index, minutes)
    ]
    # format 24 h : par défaut, Vega affiche 03:31 pour 15:31 (12 h sans AM/PM) ;
    # au-delà d'un jour, la même heure revient : on ajoute la date
    plusieurs_jours = len(activite) * minutes > 24 * 60
    format_heure = "%d/%m %H:%M" if plusieurs_jours else "%H:%M"
    barres = (
        alt.Chart(donnees)
        .mark_bar(orient="vertical")  # avec x et x2, Vega dessinerait des barres horizontales
        .encode(
            x=alt.X(
                "début:T",
                title=None,
                axis=alt.Axis(format=format_heure, values=valeurs, labelOverlap=True),
            ),
            x2="fin:T",
            y=alt.Y("requêtes:Q", stack=True),
            color=alt.Color(
                "classe:N", scale=couleurs, legend=alt.Legend(title=None, orient="top")
            ),
            tooltip=[
                alt.Tooltip("début:T", format=format_heure),
                "classe:N",
                "requêtes:Q",
            ],
        )
    )
    if instants is None or instants.empty:
        return barres
    marqueurs = (
        alt.Chart(instants.assign(instant=en_heure(instants["instant"])))
        .mark_rule(color="#b30000", strokeDash=[4, 3], strokeWidth=2)
        .encode(
            x="instant:T",
            tooltip=[
                alt.Tooltip("domaine:N", title="alerte"),
                alt.Tooltip("instant:T", title="levée à", format="%d/%m %H:%M:%S"),
            ],
        )
    )
    return barres + marqueurs


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


def tableau_affiche(vue: pd.DataFrame) -> pd.DataFrame:
    """Colonnes de l'onglet « Requêtes », libellés en français (même ordre de lignes que `vue`)."""
    return pd.DataFrame(
        {
            "heure": en_heure(vue["timestamp"]),
            "poste": vue["src"],
            "nom demandé": vue["qname"],
            "type": vue["type"],
            "taille": vue["taille"],
            "sous-domaine": vue["sous_domaine"],
            "entropie": vue["entropy"],
            "labels": vue["labels"],
            "score": vue["score"],
            "verdict": vue["verdict"],
        }
    ).reset_index(drop=True)


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


def afficher_indicateurs(st, chiffres: dict, variations: dict) -> None:
    """Rangée de chiffres clés ; variation par rapport à la période précédente si connue.

    `delta_color="inverse"` : une hausse est mauvais signe (rouge), comme les requêtes suspectes.
    """

    def ecart(cle: str, format_: str = "{:+d}") -> str | None:
        v = variations[cle]
        return None if v is None else format_.format(v)

    colonnes = st.columns(8)
    # volumes : une hausse n'est ni bonne ni mauvaise en soi, variation en gris
    colonnes[0].metric("Analysées", chiffres["analysees"], ecart("analysees"), delta_color="off")
    colonnes[1].metric(
        "Suspectes", chiffres["suspectes"], ecart("suspectes"), delta_color="inverse"
    )
    colonnes[2].metric(
        "Taux suspect",
        f"{chiffres['taux_suspect']:.1f} %",
        ecart("taux_suspect", "{:+.1f} pts"),
        delta_color="inverse",
    )
    colonnes[3].metric(
        "Alertes ouvertes",
        chiffres["alertes"],
        ecart("alertes"),
        delta_color="inverse",
        help="Alertes de la période au statut « nouvelle » ou « en cours ».",
    )
    colonnes[4].metric("Postes", chiffres["postes"], ecart("postes"), delta_color="off")
    colonnes[5].metric(
        "Domaines parents", chiffres["domaines"], ecart("domaines"), delta_color="off"
    )
    score_max = chiffres["score_max"]
    colonnes[6].metric(
        "Score max",
        "—" if pd.isna(score_max) else f"{score_max:.3f}",
        ecart("score_max", "{:+.3f}"),
        delta_color="inverse",
    )
    colonnes[7].metric(
        "TXT / NULL",
        f"{chiffres['txt_null']:.1f} %",
        ecart("txt_null", "{:+.1f} pts"),
        delta_color="inverse",
        help="Part des requêtes TXT ou NULL, types prisés des outils de tunneling.",
    )


# filtre de la file d'alertes -> statuts affichés
FILTRES_ALERTES = {
    "ouvertes": statuts.OUVERTS,
    "faux positifs": ("faux_positif",),
    "closes": ("close",),
    "toutes": tuple(statuts.STATUTS),
}


def afficher_file_alertes(
    st, resume: pd.DataFrame, min_requetes: int, chemin_statuts: str | None = None
) -> None:
    """File d'alertes : une carte par alerte, la plus grave et la plus récente en tête.

    Avec `chemin_statuts` (supervision en direct), chaque carte montre son statut et permet de
    le changer ; un filtre choisit les statuts affichés (par défaut : alertes ouvertes).
    """
    file = synthese.file_alertes(resume, min_requetes)
    if chemin_statuts is not None:
        filtre = st.segmented_control(
            "Alertes affichées", list(FILTRES_ALERTES), default="ouvertes", key="filtre_alertes"
        )
        file = file[file["statut"].isin(FILTRES_ALERTES[filtre or "ouvertes"])]
    st.subheader(f"File d'alertes ({len(file)})")
    if file.empty:
        st.caption("Aucune alerte à afficher sur la période.")
        return
    with st.container(height=380, border=False):
        for alerte in file.head(ALERTES_MAX).itertuples():
            with st.container(border=True):
                couleur = synthese.SEVERITES[alerte.severite]
                # le domaine vient du réseau : échappé avant d'entrer dans du Markdown
                statut = f":gray-badge[{statuts.STATUTS[alerte.statut]}] " if chemin_statuts else ""
                st.markdown(
                    f":{couleur}-badge[{alerte.severite.upper()}] {statut}"
                    f"**{synthese.echapper_markdown(alerte.domaine)}**"
                )
                st.caption(
                    f"{alerte.requetes_suspectes} requêtes suspectes · score max "
                    f"{alerte.score_max:.3f} · postes : "
                    f"{synthese.echapper_markdown(alerte.postes)}"
                )
                debut, fin = en_heure(pd.Series([alerte.debut, alerte.fin])).dt.strftime(
                    "%d/%m %H:%M:%S"
                )
                st.caption(f"du {debut} au {fin}")
                if chemin_statuts is not None:
                    afficher_statut(st, alerte, chemin_statuts)
        if len(file) > ALERTES_MAX:
            st.caption(f"… et {len(file) - ALERTES_MAX} autre(s).")


def afficher_statut(st, alerte, chemin_statuts: str) -> None:
    """Statut de l'alerte et formulaire pour le changer (écrit dans la base des statuts)."""
    if pd.notna(alerte.commentaire):
        st.text(f"Note : {alerte.commentaire}")  # st.text : saisie affichée telle quelle
    cle = f"statut_{alerte.domaine}"

    def changer() -> None:
        try:
            statuts.enregistrer(
                chemin_statuts,
                alerte.domaine,
                st.session_state[f"{cle}_choix"],
                st.session_state[f"{cle}_note"],
            )
        except (sqlite3.Error, OSError) as erreur:
            st.session_state["erreur_statut"] = (
                f"Statut non enregistré ({chemin_statuts}) : {erreur}"
            )

    with st.popover("Changer le statut"):
        with st.form(cle, border=False):
            st.selectbox(
                "Statut",
                list(statuts.STATUTS),
                index=list(statuts.STATUTS).index(alerte.statut),
                format_func=statuts.STATUTS.get,
                key=f"{cle}_choix",
            )
            st.text_input("Commentaire", value=alerte.commentaire or "", key=f"{cle}_note")
            st.form_submit_button("Enregistrer", on_click=changer)


def afficher_panneaux(st, requetes: pd.DataFrame, seuil: float, onglet: str) -> None:
    """Rangée de panneaux : top domaines, top postes, types de requêtes, scores du modèle.

    `onglet` préfixe la clé des widgets : la supervision et la capture importée affichent
    chacune ces panneaux dans la même page.
    """
    domaines, postes, types, scores = st.columns(4, gap="medium")
    with domaines:
        st.markdown("**Top domaines parents**")
        tri = st.segmented_control(
            "Tri",
            ["volume", "score"],
            default="volume",
            key=f"tri_domaines_{onglet}",
            label_visibility="collapsed",
        )
        st.dataframe(
            synthese.top_domaines(requetes, seuil, tri or "volume"),
            hide_index=True,
            width="stretch",
            column_config={"score moyen": st.column_config.NumberColumn(format="%.2f")},
        )
    with postes:
        st.markdown("**Top postes**")
        st.dataframe(
            synthese.top_postes(requetes, seuil),
            hide_index=True,
            width="stretch",
            column_config={"score max": st.column_config.NumberColumn(format="%.2f")},
        )
    with types:
        st.markdown("**Types de requêtes**")
        repartition = synthese.repartition_qtypes(requetes, detail.nom_qtype)
        st.altair_chart(graphique_qtypes(repartition), width="stretch")
    with scores:
        st.markdown("**Scores du modèle**")
        histogramme = synthese.histogramme_scores(requetes["score"])
        st.altair_chart(graphique_histogramme(histogramme, seuil), width="stretch")
        st.caption(f"Trait rouge : seuil {seuil:.2f}. Échelle logarithmique.")


def afficher_resultats(
    st,
    requetes: pd.DataFrame,
    seuil: float,
    min_requetes: int,
    precedentes: pd.DataFrame | None = None,
    onglet: str = "direct",
    chemin_statuts: str | None = None,
    liste: Sequence[str] = LISTE_BLANCHE,
) -> None:
    """Chiffres clés, timeline, file d'alertes, panneaux « top » et requêtes suspectes récentes.

    `precedentes` : requêtes de la période précédente, pour afficher les variations (aucune
    si elle est vide). `onglet` préfixe la clé des widgets (`direct` ou `capture`).
    `chemin_statuts` : base des statuts d'alertes ; sans elle, toutes les alertes sont nouvelles.
    `liste` : domaines jamais signalés (liste blanche complète).
    """
    if "erreur_statut" in st.session_state:
        st.error(st.session_state.pop("erreur_statut"))
    connus = pd.DataFrame(columns=statuts.COLONNES)
    if chemin_statuts is not None:
        try:
            connus = statuts.lire(chemin_statuts)
        except (sqlite3.Error, OSError, pd.errors.DatabaseError) as erreur:
            st.warning(f"Statuts d'alertes illisibles ({chemin_statuts}) : {erreur}")

    def resume_de(lues: pd.DataFrame) -> pd.DataFrame:
        return statuts.appliquer(alertes(lues, seuil, min_requetes, liste), connus)

    resume = resume_de(requetes)
    suspectes = requetes[requetes["score"] >= seuil]
    chiffres = synthese.indicateurs(requetes, seuil, statuts.ouvertes(resume))
    avant = None
    # période précédente vide (capture arrêtée) : une variation « +625 » ne dirait rien
    if precedentes is not None and not precedentes.empty:
        avant = synthese.indicateurs(precedentes, seuil, statuts.ouvertes(resume_de(precedentes)))
    afficher_indicateurs(st, chiffres, synthese.ecarts(chiffres, avant))

    if requetes.empty:
        st.info("Aucune requête DNS à analyser.")
        return

    gauche, droite = st.columns([2, 1], gap="large")
    with gauche:
        minutes = intervalle(requetes)
        st.subheader(f"Activité DNS par {INTERVALLES[minutes]}")
        graphique = graphique_activite(
            activite_dns(requetes, seuil, minutes),
            minutes,
            instants_alertes(requetes, seuil, min_requetes, liste),
        )
        st.altair_chart(graphique, width="stretch")
    with droite:
        afficher_file_alertes(st, resume, min_requetes, chemin_statuts)

    afficher_panneaux(st, requetes, seuil, onglet)

    if suspectes.empty:
        return
    st.subheader("Requêtes suspectes les plus récentes")
    st.dataframe(
        tableau_requetes(suspectes),
        hide_index=True,
        width="stretch",
        column_config={"score": st.column_config.NumberColumn(format="%.3f")},
    )


def supervision(
    st,
    base: str,
    seuil: float,
    min_requetes: int,
    periode: str,
    chemin_statuts: str,
    liste: Sequence[str] = LISTE_BLANCHE,
) -> None:
    """Onglet de supervision en direct : requêtes de la base écrite par `exfildns sniff`."""
    if not Path(base).exists():
        st.info(
            f"Aucune base de détections ({base}). Lancer la capture : "
            "`exfildns sniff -i <interface>`."
        )
        return
    duree = PERIODES[periode]
    if duree is None:  # toute la base : pas de période précédente
        afficher_resultats(
            st, lire_requetes(base), seuil, min_requetes, chemin_statuts=chemin_statuts, liste=liste
        )
        return
    # une seule lecture pour la période et la précédente (variations des chiffres clés)
    debut = time.time() - duree
    lues = lire_requetes(base, debut - duree)
    afficher_resultats(
        st,
        lues[lues["timestamp"] >= debut],
        seuil,
        min_requetes,
        precedentes=lues[lues["timestamp"] < debut],
        chemin_statuts=chemin_statuts,
        liste=liste,
    )


def bandeau(st, base: str, chemin_modele: str, seuil: float, periode: str) -> None:
    """Bandeau d'état sur une ligne : capteur, dernière requête, modèle, seuil, mise à jour."""
    maintenant = time.time()
    derniere = derniere_requete(base) if Path(base).exists() else None
    etat, couleur = synthese.etat_capteur(derniere, maintenant)
    depuis = (
        "aucune requête reçue"
        if derniere is None
        else f"dernière requête il y a {synthese.duree_lisible(maintenant - derniere)}"
    )
    morceaux = [
        '<span class="marque">exfildns</span>',
        f'<span><span class="pastille" style="background:{COULEURS_CAPTEUR[couleur]}"></span>'
        f"capteur {etat}</span>",
        f"<span>{depuis}</span>",
        f'<span class="discret">modèle {html.escape(synthese.infos_modele(chemin_modele))}'
        f" · v{__version__}</span>",
        f"<span>seuil {seuil:.2f} · {periode}</span>",
        f'<span class="discret">mis à jour à {datetime.now():%H:%M:%S}</span>',
    ]
    st.markdown(
        STYLE_BANDEAU + f'<div class="bandeau">{"".join(morceaux)}</div>', unsafe_allow_html=True
    )


def requetes_figees(st, base: str, periode: str, seuil: float) -> pd.DataFrame:
    """Tableau détaillé des requêtes de la période, relu seulement sur « Actualiser » ou si la
    période change.

    Sans cela, chaque clic relirait la base : de nouvelles lignes décaleraient le tableau et
    la ligne sélectionnée désignerait une autre requête. Les features (coûteuses) sont calculées
    à la lecture ; seul le verdict, qui dépend du seuil, est recalculé à chaque exécution.
    `requetes_version` augmente à chaque lecture : il entre dans la clé du tableau affiché.
    """
    cle = (base, periode)
    actualiser = st.button("Actualiser", icon=":material/refresh:", key="actualiser_requetes")
    if actualiser or st.session_state.get("requetes_cle") != cle:
        duree = PERIODES[periode]
        requetes = lire_requetes(base, None if duree is None else time.time() - duree)
        st.session_state["requetes_cle"] = cle
        st.session_state["requetes_figees"] = detail.tableau_detaille(requetes, seuil)
        st.session_state["requetes_lues_a"] = datetime.now().strftime("%H:%M:%S")
        st.session_state["requetes_version"] = st.session_state.get("requetes_version", 0) + 1
    tableau = st.session_state["requetes_figees"]
    return tableau.assign(verdict=detail.verdicts(tableau["score"], seuil))


def afficher_detail(st, ligne: pd.Series, tableau: pd.DataFrame, prefixe: str = "") -> None:
    """Panneau de détail d'une requête : nom découpé, features, séquence, décodage, export."""
    tronque = pd.isna(ligne["qtype"])
    st.subheader("Détail de la requête")
    st.markdown(STYLE_QNAME, unsafe_allow_html=True)
    # qname_html échappe chaque label : le nom vient du réseau
    st.markdown(
        f'<div class="qname">{detail.qname_html(ligne["qname"], tronque)}</div>',
        unsafe_allow_html=True,
    )
    legende = "Sous-domaine encadré en rouge, domaine parent en gris."
    if tronque:
        legende += " Nom coupé dans la capture : le domaine parent est inconnu."
    if detail.nom_vu_par_le_modele(ligne["qname"]) != ligne["qname"].rstrip("."):
        legende += f" Le modèle ne voit que les {detail.LONGUEUR_MAX} premiers caractères."
    st.caption(legende)
    taille = "?" if pd.isna(ligne["taille"]) else f"{int(ligne['taille'])} octets"
    st.caption(
        f"{ligne['src']} → {ligne['dst']} · type {ligne['type']} · {taille} · "
        f"score {ligne['score']:.3f} ({ligne['verdict']})"
    )

    gauche, droite = st.columns(2)
    with gauche:
        st.markdown("**Features envoyées au modèle**")
        benignes = tableau[tableau["verdict"] == "bénigne"]
        comparaison = detail.comparaison_features(ligne, benignes)
        # écart indéfini (référence vide ou constante) : un tiret plutôt que « None »
        comparaison["écart"] = ["—" if pd.isna(e) else f"{e:+.1f} σ" for e in comparaison["écart"]]
        st.dataframe(
            comparaison,
            hide_index=True,
            width="stretch",
            column_config={
                "valeur": st.column_config.NumberColumn(format="%.2f"),
                "moyenne bénigne": st.column_config.NumberColumn(format="%.2f"),
                "écart": st.column_config.TextColumn(
                    help="écart à la moyenne bénigne, en écarts-types"
                ),
            },
        )
        st.caption(
            f"Moyenne sur les {len(benignes)} requêtes jugées bénignes par le modèle "
            "sur la période ou dans la capture (pas une vérité terrain)."
        )
    with droite:
        suite = detail.sequence(tableau, ligne)
        st.markdown(f"**Séquence : {len(suite)} requête(s) de ce poste vers ce domaine**")
        st.dataframe(
            pd.DataFrame(
                {
                    "sélection": suite["id"] == ligne["id"],
                    "heure": en_heure(suite["timestamp"]),
                    "nom demandé": suite["qname"],
                    "type": suite["type"],
                    "score": suite["score"],
                }
            ),
            hide_index=True,
            width="stretch",
            height=300,
            column_config={
                "heure": st.column_config.DatetimeColumn(format="HH:mm:ss"),
                "score": st.column_config.NumberColumn(format="%.3f"),
            },
        )

    with st.expander("Essai de décodage du sous-domaine"):
        essais = detail.essais_decodage(detail.sous_domaine(ligne["qname"], tronque))
        st.caption(
            "Affiché en hexadécimal et en ASCII échappé uniquement : rien n'est exécuté ni "
            "interprété. Un décodage qui réussit n'est pas une preuve, juste une piste."
        )
        if essais:
            st.dataframe(pd.DataFrame(essais), hide_index=True, width="stretch")
        else:
            st.write("Aucun encodage reconnu (base32, base64, hexadécimal).")

    une = tableau[tableau["id"] == ligne["id"]]
    gauche, droite = st.columns(2)
    gauche.download_button(
        "Exporter cette requête (JSON)",
        detail.exporter(une, "json"),
        file_name=f"requete-{ligne['id']}.json",
        mime="application/json",
        on_click="ignore",
        key=f"{prefixe}export_requete",
    )
    droite.download_button(
        "Exporter la séquence (CSV)",
        detail.exporter(suite, "csv"),
        file_name=f"sequence-{ligne['id']}.csv",
        mime="text/csv",
        on_click="ignore",
        key=f"{prefixe}export_sequence",
    )


def vue_requetes(st, base: str, seuil: float, periode: str) -> None:
    """Onglet « Requêtes » : tableau filtrable des requêtes et détail de la ligne sélectionnée."""
    if not Path(base).exists():
        st.info(f"Aucune base de détections ({base}).")
        return
    tableau = requetes_figees(st, base, periode, seuil)
    st.caption(f"Période : {periode}, lue à {st.session_state['requetes_lues_a']}.")
    if tableau.empty:
        st.info("Aucune requête DNS sur la période.")
        return
    explorer_requetes(st, tableau, seuil, st.session_state["requetes_version"])


def explorer_requetes(st, tableau: pd.DataFrame, seuil: float, version, prefixe: str = "") -> None:
    """Tableau filtrable de toutes les requêtes (bénignes comprises), export, détail d'une ligne.

    Partagé par l'onglet « Requêtes » et l'analyse d'une capture. `tableau` vient de
    `detail.tableau_detaille`, avec des verdicts au seuil `seuil`. `version` change quand les
    données changent (efface la sélection). `prefixe` distingue les clés des deux onglets.
    """
    colonnes = st.columns([2, 2, 2, 2, 3])
    postes = colonnes[0].multiselect(
        "Poste", sorted(tableau["src"].unique()), key=f"{prefixe}f_postes", placeholder="Tous"
    )
    domaines = colonnes[1].multiselect(
        "Domaine parent",
        tableau["domaine"].value_counts().index.tolist(),  # les plus fréquents d'abord
        key=f"{prefixe}f_domaines",
        placeholder="Tous",
    )
    verdicts = colonnes[2].multiselect(
        "Verdict", detail.VERDICTS, key=f"{prefixe}f_verdicts", placeholder="Tous"
    )
    score_min = colonnes[3].slider("Score minimum", 0.0, 1.0, 0.0, 0.05, key=f"{prefixe}f_score")
    texte = colonnes[4].text_input("Rechercher dans le nom", key=f"{prefixe}f_texte")
    filtrees = detail.filtrer(tableau, postes, domaines, verdicts, score_min, texte)
    vue = filtrees.sort_values("timestamp", ascending=False).head(LIGNES_MAX)

    gauche, milieu, droite = st.columns([6, 1, 1])
    gauche.caption(
        f"{len(vue)} requête(s) affichée(s) sur {len(tableau)}"
        + (f" (les {LIGNES_MAX} plus récentes)" if len(filtrees) > LIGNES_MAX else "")
    )
    milieu.download_button(
        "CSV",
        detail.exporter(vue, "csv"),
        "requetes.csv",
        "text/csv",
        on_click="ignore",
        key=f"{prefixe}export_csv",
    )
    droite.download_button(
        "JSON",
        detail.exporter(vue, "json"),
        "requetes.json",
        "application/json",
        on_click="ignore",
        key=f"{prefixe}export_json",
    )
    # une clé par jeu de filtres et par lecture de la base : Streamlit garde la sélection (une
    # position) quand les données changent ; changer de clé l'efface au lieu de la reporter sur
    # la ligne qui occupe désormais la même position
    filtres = repr((postes, domaines, verdicts, score_min, texte, seuil, version))
    selection = st.dataframe(
        tableau_affiche(vue),
        key=f"{prefixe}table_requetes_{zlib.crc32(filtres.encode())}",
        on_select="rerun",
        selection_mode="single-row",
        hide_index=True,
        width="stretch",
        height=400,
        column_config={
            "heure": st.column_config.DatetimeColumn(format="DD/MM HH:mm:ss"),
            "taille": st.column_config.NumberColumn(help="octets du message DNS"),
            "sous-domaine": st.column_config.NumberColumn(
                help="caractères avant le domaine parent, sur le nom complet"
            ),
            "entropie": st.column_config.NumberColumn(
                format="%.2f",
                help="bits par caractère, sur les 40 premiers caractères (comme le modèle)",
            ),
            "labels": st.column_config.NumberColumn(
                help="sur les 40 premiers caractères (comme le modèle)"
            ),
            "score": st.column_config.ProgressColumn(min_value=0.0, max_value=1.0, format="%.3f"),
        },
    )
    lignes = [i for i in selection.selection.rows if i < len(vue)]
    if not lignes:
        st.caption("Sélectionner une ligne pour afficher son détail.")
        return
    afficher_detail(st, vue.iloc[lignes[0]], tableau, prefixe)


def capture_importee(
    st, chemin_modele: str, seuil: float, min_requetes: int, liste: Sequence[str] = LISTE_BLANCHE
) -> None:
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
    afficher_resultats(st, requetes, seuil, min_requetes, onglet="capture", liste=liste)
    if requetes.empty:
        return
    st.subheader("Toutes les requêtes de la capture")
    # id : position dans la capture (pas de rowid hors base), sert au détail et à l'export
    detaille = st.cache_data(
        detail.tableau_detaille, show_spinner=False, max_entries=CAPTURES_EN_CACHE
    )
    # seuil fixe dans le cache : bouger le curseur ne recalcule pas les features
    tableau = detaille(requetes.assign(id=range(1, len(requetes) + 1)), SEUIL)
    tableau = tableau.assign(verdict=detail.verdicts(tableau["score"], seuil))
    explorer_requetes(st, tableau, seuil, zlib.crc32(fichier.getvalue()), prefixe="capture_")


def panneau_liste_blanche(st, chemin: str) -> list[str]:
    """Barre latérale : ajout / retrait de domaines jamais signalés ; renvoie la liste complète.

    Les domaines ajoutés sont écrits dans la base des statuts (`chemin`) ; la liste par défaut
    (CDN) est toujours appliquée et n'est pas modifiable ici.
    """

    def ajouter() -> None:
        try:
            liste_blanche.ajouter(chemin, st.session_state["liste_blanche_nouveau"])
            st.session_state["liste_blanche_nouveau"] = ""  # vidé seulement si ajouté
        except ValueError as erreur:
            st.session_state["erreur_liste_blanche"] = str(erreur)
        except (sqlite3.Error, OSError) as erreur:
            st.session_state["erreur_liste_blanche"] = (
                f"Domaine non enregistré ({chemin}) : {erreur}"
            )

    def retirer(domaine: str) -> None:
        try:
            liste_blanche.retirer(chemin, domaine)
        except (sqlite3.Error, OSError) as erreur:
            st.session_state["erreur_liste_blanche"] = f"Domaine non retiré ({chemin}) : {erreur}"

    try:
        ajoutes = liste_blanche.lire(chemin)
    except (sqlite3.Error, OSError) as erreur:
        st.warning(f"Liste blanche illisible ({chemin}) : {erreur}")
        ajoutes = []
    with st.expander(f"Liste blanche ({len(LISTE_BLANCHE) + len(ajoutes)} domaines)"):
        with st.form("liste_blanche", border=False):
            st.text_input(
                "Domaine à ne jamais signaler",
                placeholder="exemple.com",
                key="liste_blanche_nouveau",
                help="Le domaine et tous ses sous-domaines ne lèvent plus d'alerte.",
            )
            st.form_submit_button("Ajouter", on_click=ajouter)
        if "erreur_liste_blanche" in st.session_state:
            st.error(st.session_state.pop("erreur_liste_blanche"))
        for domaine in ajoutes:
            nom, bouton = st.columns([3, 1], vertical_alignment="center")
            nom.text(domaine)
            bouton.button(
                "Retirer", key=f"liste_blanche_retirer_{domaine}", on_click=retirer, args=(domaine,)
            )
        st.caption("Toujours appliqués (CDN) : " + ", ".join(LISTE_BLANCHE))
    return [*LISTE_BLANCHE, *ajoutes]


def authentifie(st, attendu: str | None) -> bool:
    """Vrai si l'accès est ouvert ; sinon affiche le formulaire de connexion et renvoie Faux.

    Sans mot de passe configuré (`attendu` vide), le dashboard est ouvert : il n'écoute alors
    que sur localhost par défaut. La connexion vaut pour la session Streamlit : un rechargement
    de la page ou un nouvel onglet redemande le mot de passe.
    """
    if not attendu or st.session_state.get("authentifie"):
        return True

    def verifier() -> None:
        saisi = st.session_state.get("mot_de_passe", "")
        if hmac.compare_digest(saisi.encode(), attendu.encode()):  # temps constant
            st.session_state["authentifie"] = True
        else:
            time.sleep(PAUSE_ECHEC)  # freine les essais en rafale
            st.session_state["erreur_connexion"] = True
        st.session_state["mot_de_passe"] = ""

    st.title("exfildns")
    with st.form("connexion"):
        st.text_input("Mot de passe", type="password", key="mot_de_passe")
        st.form_submit_button("Se connecter", on_click=verifier)
    if st.session_state.pop("erreur_connexion", False):
        st.error("Mot de passe incorrect.")
    return False


def page() -> None:
    import streamlit as st

    st.set_page_config(page_title="exfildns", layout="wide")
    mot_de_passe = os.environ.get("EXFILDNS_MOT_DE_PASSE")
    if not authentifie(st, mot_de_passe):
        st.stop()
    base = os.environ.get("EXFILDNS_BASE", BASE_PAR_DEFAUT)
    chemin_modele = os.environ.get("EXFILDNS_MODELE", MODELE_PAR_DEFAUT)
    chemin_statuts = os.environ.get("EXFILDNS_STATUTS") or str(Path(base).with_name(STATUTS))

    with st.sidebar:
        st.header("Réglages")
        seuil = st.slider("Seuil de détection", 0.0, 1.0, SEUIL, 0.05, key="seuil")
        min_requetes = st.number_input(
            "Requêtes suspectes pour une alerte", 1, 10_000, MIN_REQUETES, key="min_requetes"
        )
        periode = st.selectbox("Période", list(PERIODES), index=2, key="periode")
        auto = st.toggle(f"Rafraîchir toutes les {RAFRAICHISSEMENT} s", True, key="auto")
        liste = panneau_liste_blanche(st, chemin_statuts)
        st.caption(f"Base : `{base}`")
        if mot_de_passe:
            st.button("Se déconnecter", on_click=st.session_state.clear, key="deconnexion")

    rafraichissement = RAFRAICHISSEMENT if auto else None

    @st.fragment(run_every=rafraichissement)
    def etat() -> None:
        bandeau(st, base, chemin_modele, seuil, periode)

    etat()
    direct, onglet_requetes, importee = st.tabs(
        ["Supervision en direct", "Requêtes", "Analyser une capture"]
    )

    @st.fragment(run_every=rafraichissement)
    def vue_directe() -> None:
        supervision(st, base, seuil, int(min_requetes), periode, chemin_statuts, liste)

    with direct:
        vue_directe()
    with onglet_requetes:
        vue_requetes(st, base, seuil, periode)
    with importee:
        capture_importee(st, chemin_modele, seuil, int(min_requetes), liste)


if __name__ == "__main__":
    page()
