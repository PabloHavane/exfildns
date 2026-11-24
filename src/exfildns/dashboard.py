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
import zlib
from contextlib import closing
from datetime import datetime
from pathlib import Path

import pandas as pd

from exfildns import SEUIL, detail
from exfildns.alertes import LISTE_BLANCHE, MIN_REQUETES, alertes, domaine_parent, est_autorise

BASE_PAR_DEFAUT = "detections.db"
MODELE_PAR_DEFAUT = "models/exfildns.keras"
EXTENSIONS_CAPTURE = ["pcap", "pcapng"]
CAPTURES_EN_CACHE = 5  # analyses gardées en mémoire (une par fichier déposé)
RAFRAICHISSEMENT = 5  # secondes
LIGNES_MAX = 5000  # requêtes affichées dans l'onglet « Requêtes » (les plus récentes)

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
    uri = f"{Path(base).resolve().as_uri()}?mode=ro"
    try:
        requetes = _lire(uri, sql, params)
    except pd.errors.DatabaseError as erreur:
        if "readonly" not in str(erreur):
            raise
        requetes = _lire(uri + "&immutable=1", sql, params)
    if "taille" not in requetes:  # base écrite par une version antérieure, pas encore migrée
        requetes["taille"] = pd.NA
    return requetes.astype({"qtype": "Int64", "score": float, "taille": "Int64"})


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


def classement(suspectes: pd.DataFrame, colonne: str, libelle: str, n: int = 10) -> pd.DataFrame:
    """Les `n` valeurs de `colonne` les plus fréquentes parmi les requêtes suspectes."""
    compte = suspectes[colonne].value_counts().head(n)
    return compte.rename_axis(libelle).reset_index(name="requêtes suspectes")


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
        st.dataframe(
            tableau_alertes(resume),
            hide_index=True,
            width="stretch",
            column_config={"score moyen": st.column_config.NumberColumn(format="%.3f")},
        )

    minutes = intervalle(requetes)
    st.subheader(f"Activité DNS par {INTERVALLES[minutes]}")
    graphique = graphique_activite(
        activite_dns(requetes, seuil, minutes),
        minutes,
        instants_alertes(requetes, seuil, min_requetes),
    )
    st.altair_chart(graphique, width="stretch")

    if suspectes.empty:
        return
    gauche, droite = st.columns(2)
    gauche.subheader("Postes à l'origine des requêtes suspectes")
    gauche.dataframe(classement(suspectes, "src", "poste"), hide_index=True, width="stretch")
    droite.subheader("Serveurs DNS interrogés")
    droite.dataframe(classement(suspectes, "dst", "serveur DNS"), hide_index=True, width="stretch")
    st.subheader("Requêtes suspectes les plus récentes")
    st.dataframe(
        tableau_requetes(suspectes),
        hide_index=True,
        width="stretch",
        column_config={"score": st.column_config.NumberColumn(format="%.3f")},
    )


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


def requetes_figees(st, base: str, periode: str) -> pd.DataFrame:
    """Requêtes de la période, relues seulement sur « Actualiser » ou si la période change.

    Sans cela, chaque clic relirait la base : de nouvelles lignes décaleraient le tableau et
    la ligne sélectionnée désignerait une autre requête.
    """
    cle = (base, periode)
    actualiser = st.button("Actualiser", icon=":material/refresh:", key="actualiser_requetes")
    if actualiser or st.session_state.get("requetes_cle") != cle:
        duree = PERIODES[periode]
        st.session_state["requetes_cle"] = cle
        st.session_state["requetes_figees"] = lire_requetes(
            base, None if duree is None else time.time() - duree
        )
        st.session_state["requetes_lues_a"] = datetime.now().strftime("%H:%M:%S")
    return st.session_state["requetes_figees"]


def afficher_detail(st, ligne: pd.Series, tableau: pd.DataFrame) -> None:
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
            "sur la période (pas une vérité terrain)."
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
    )
    droite.download_button(
        "Exporter la séquence (CSV)",
        detail.exporter(suite, "csv"),
        file_name=f"sequence-{ligne['id']}.csv",
        mime="text/csv",
        on_click="ignore",
    )


def vue_requetes(st, base: str, seuil: float, periode: str) -> None:
    """Onglet « Requêtes » : tableau filtrable des requêtes et détail de la ligne sélectionnée."""
    if not Path(base).exists():
        st.info(f"Aucune base de détections ({base}).")
        return
    requetes = requetes_figees(st, base, periode)
    st.caption(f"Période : {periode}, lue à {st.session_state['requetes_lues_a']}.")
    if requetes.empty:
        st.info("Aucune requête DNS sur la période.")
        return
    tableau = detail.tableau_detaille(requetes, seuil)

    colonnes = st.columns([2, 2, 2, 2, 3])
    postes = colonnes[0].multiselect(
        "Poste", sorted(tableau["src"].unique()), key="f_postes", placeholder="Tous"
    )
    domaines = colonnes[1].multiselect(
        "Domaine parent",
        tableau["domaine"].value_counts().index.tolist(),  # les plus fréquents d'abord
        key="f_domaines",
        placeholder="Tous",
    )
    verdicts = colonnes[2].multiselect(
        "Verdict", detail.VERDICTS, key="f_verdicts", placeholder="Tous"
    )
    score_min = colonnes[3].slider("Score minimum", 0.0, 1.0, 0.0, 0.05, key="f_score")
    texte = colonnes[4].text_input("Rechercher dans le nom", key="f_texte")
    vue = detail.filtrer(tableau, postes, domaines, verdicts, score_min, texte)
    vue = vue.sort_values("timestamp", ascending=False).head(LIGNES_MAX)

    gauche, milieu, droite = st.columns([6, 1, 1])
    gauche.caption(
        f"{len(vue)} requête(s) affichée(s) sur {len(tableau)}"
        + (f" (les {LIGNES_MAX} plus récentes)" if len(vue) == LIGNES_MAX else "")
    )
    milieu.download_button(
        "CSV", detail.exporter(vue, "csv"), "requetes.csv", "text/csv", on_click="ignore"
    )
    droite.download_button(
        "JSON",
        detail.exporter(vue, "json"),
        "requetes.json",
        "application/json",
        on_click="ignore",
    )
    # une clé par jeu de filtres : changer un filtre efface la sélection au lieu de la reporter
    # sur la ligne qui occupe désormais la même position
    filtres = repr((postes, domaines, verdicts, score_min, texte, seuil))
    selection = st.dataframe(
        tableau_affiche(vue),
        key=f"table_requetes_{zlib.crc32(filtres.encode())}",
        on_select="rerun",
        selection_mode="single-row",
        hide_index=True,
        width="stretch",
        height=400,
        column_config={
            "heure": st.column_config.DatetimeColumn(format="DD/MM HH:mm:ss"),
            "taille": st.column_config.NumberColumn(help="octets du message DNS"),
            "sous-domaine": st.column_config.NumberColumn(
                help="caractères avant le domaine parent"
            ),
            "entropie": st.column_config.NumberColumn(format="%.2f", help="bits par caractère"),
            "score": st.column_config.ProgressColumn(min_value=0.0, max_value=1.0, format="%.3f"),
        },
    )
    lignes = selection.selection.rows
    if not lignes:
        st.caption("Sélectionner une ligne pour afficher son détail.")
        return
    afficher_detail(st, vue.iloc[lignes[0]], tableau)


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

    direct, onglet_requetes, importee = st.tabs(
        ["Supervision en direct", "Requêtes", "Analyser une capture"]
    )

    @st.fragment(run_every=RAFRAICHISSEMENT if auto else None)
    def vue_directe() -> None:
        supervision(st, base, seuil, int(min_requetes), periode)

    with direct:
        vue_directe()
    with onglet_requetes:
        vue_requetes(st, base, seuil, periode)
    with importee:
        capture_importee(st, chemin_modele, seuil, int(min_requetes))


if __name__ == "__main__":
    page()
