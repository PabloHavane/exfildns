"""Vue détaillée des requêtes DNS : préparation des données de l'onglet « Requêtes » du dashboard.

Fonctions pures, testées sans navigateur. Les features affichées sont recalculées par
`features_dataframe`, la fonction même qui alimente le modèle : on montre exactement ce qu'il a vu.
Rien ici n'interprète le contenu d'un nom : un essai de décodage n'est montré qu'en hexadécimal
ou en ASCII échappé.
"""

import base64
import binascii
import html

import pandas as pd

from exfildns.alertes import domaine_parent
from exfildns.features import FEATURES, LONGUEUR_MAX, features_dataframe

# Types d'enregistrement DNS courants (RFC 1035 et suivantes) ; les autres restent en chiffres.
QTYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}
VERDICTS = ["suspecte", "bénigne"]
OCTETS_AFFICHES = 64  # au-delà, le décodage est tronqué à l'affichage


def nom_qtype(qtype) -> str:
    """`16` -> `TXT` ; type inconnu -> son numéro ; absent (nom tronqué) -> `?`."""
    if pd.isna(qtype):
        return "?"
    return QTYPES.get(int(qtype), str(int(qtype)))


def sous_domaine(qname: str, tronque: bool = False) -> str:
    """Partie du nom avant le domaine parent (`abc.def` pour `abc.def.exemple.com`)."""
    if tronque:  # nom coupé : on ne sait pas où commence le domaine parent
        return qname.rstrip(".")
    labels = qname.rstrip(".").split(".")
    return ".".join(labels[:-2])


def tableau_detaille(requetes: pd.DataFrame, seuil: float) -> pd.DataFrame:
    """Une ligne par requête, avec domaine parent, features du modèle et verdict.

    `requetes` vient de `lire_requetes` (colonnes `id, timestamp, src, dst, qname, qtype, score,
    taille`). Les colonnes `FEATURES` sont celles calculées pour le modèle.
    """
    tronques = requetes["qtype"].isna()
    features = features_dataframe(requetes["qname"]).set_index(requetes.index)
    return pd.concat(
        [
            requetes,
            pd.DataFrame(
                {
                    "domaine": [
                        domaine_parent(q, t)
                        for q, t in zip(requetes["qname"], tronques, strict=True)
                    ],
                    "type": [nom_qtype(q) for q in requetes["qtype"]],
                    "sous_domaine": [
                        len(sous_domaine(q, t))
                        for q, t in zip(requetes["qname"], tronques, strict=True)
                    ],
                    "verdict": [
                        VERDICTS[0] if s >= seuil else VERDICTS[1] for s in requetes["score"]
                    ],
                },
                index=requetes.index,
            ),
            features,
        ],
        axis=1,
    )


def filtrer(
    tableau: pd.DataFrame,
    postes: list[str] = (),
    domaines: list[str] = (),
    verdicts: list[str] = (),
    score_min: float = 0.0,
    texte: str = "",
) -> pd.DataFrame:
    """Lignes de `tableau_detaille` qui passent les filtres ; un filtre vide ne filtre rien.

    `texte` est cherché tel quel (sans expression régulière), sans tenir compte de la casse.
    """
    garde = tableau["score"] >= score_min
    if postes:
        garde &= tableau["src"].isin(postes)
    if domaines:
        garde &= tableau["domaine"].isin(domaines)
    if verdicts:
        garde &= tableau["verdict"].isin(verdicts)
    if texte:
        garde &= tableau["qname"].str.contains(texte, case=False, regex=False)
    return tableau[garde]


def qname_html(qname: str, tronque: bool = False) -> str:
    """Le nom découpé label par label, sous-domaine mis en évidence, **échappé** pour le HTML.

    Le nom vient du réseau : sans échappement, un label `<script>` serait interprété.
    """
    nom = qname.rstrip(".")
    sous = sous_domaine(qname, tronque)
    parent = nom[len(sous) :].lstrip(".") if sous else nom
    morceaux = [
        f'<span class="label suspect">{html.escape(label)}</span>'
        for label in sous.split(".")
        if label
    ]
    morceaux += [
        f'<span class="label parent">{html.escape(label)}</span>'
        for label in parent.split(".")
        if label
    ]
    return '<span class="point">.</span>'.join(morceaux)


def comparaison_features(ligne: pd.Series, reference: pd.DataFrame) -> pd.DataFrame:
    """Features de la requête face à leur moyenne sur `reference` (les requêtes jugées bénignes).

    Colonnes : `feature`, `valeur`, `moyenne bénigne`, `écart` (en écarts-types, NaN si la
    référence est vide ou constante).
    """
    moyenne = reference[FEATURES].mean() if len(reference) else pd.Series(float("nan"), FEATURES)
    ecart_type = (
        reference[FEATURES].std() if len(reference) > 1 else pd.Series(float("nan"), FEATURES)
    )
    valeurs = ligne[FEATURES].astype(float)
    ecart = (valeurs - moyenne) / ecart_type.where(ecart_type > 0)
    return pd.DataFrame(
        {
            "feature": FEATURES,
            "valeur": valeurs.to_numpy(),
            "moyenne bénigne": moyenne.to_numpy(),
            "écart": ecart.to_numpy(),
        }
    )


def sequence(tableau: pd.DataFrame, ligne: pd.Series) -> pd.DataFrame:
    """Requêtes du même poste vers le même domaine parent, dans l'ordre du temps."""
    memes = tableau[(tableau["src"] == ligne["src"]) & (tableau["domaine"] == ligne["domaine"])]
    return memes.sort_values("timestamp")


def ascii_echappe(octets: bytes) -> str:
    """Octets -> texte affichable : ASCII imprimable tel quel, le reste en `\\xNN`."""
    return "".join(chr(o) if 32 <= o < 127 and o != 0x5C else f"\\x{o:02x}" for o in octets)


def essais_decodage(sous: str) -> list[dict[str, str]]:
    """Essaie de décoder le sous-domaine en base32, base64 et hexadécimal.

    Les labels sont recollés (un tunnel découpe ses données en labels de 63 caractères au plus).
    Renvoie, pour chaque encodage qui réussit, les octets en hexadécimal et en ASCII échappé
    (`OCTETS_AFFICHES` premiers octets). Le résultat n'est jamais exécuté ni interprété.
    """
    donnees = sous.replace(".", "")
    if not donnees:
        return []
    essais = {
        "base32": lambda d: base64.b32decode(d.upper() + "=" * (-len(d) % 8)),
        "base64": lambda d: base64.b64decode(
            d + "=" * (-len(d) % 4), altchars=b"-_", validate=True
        ),
        "hexadécimal": bytes.fromhex,
    }
    resultats = []
    for encodage, decoder in essais.items():
        try:
            octets = decoder(donnees)
        except (binascii.Error, ValueError):
            continue
        if not octets:
            continue
        extrait = octets[:OCTETS_AFFICHES]
        resultats.append(
            {
                "encodage": encodage,
                "octets": len(octets),
                "hexadécimal": extrait.hex(" "),
                "ASCII échappé": ascii_echappe(extrait),
            }
        )
    return resultats


def nom_vu_par_le_modele(qname: str) -> str:
    """Partie du nom réellement utilisée par les features (le modèle coupe à `LONGUEUR_MAX`)."""
    return qname.rstrip(".")[:LONGUEUR_MAX]


def exporter(tableau: pd.DataFrame, format_: str) -> str:
    """Requêtes au format `csv` ou `json` (une liste d'objets), heure en ISO 8601 UTC."""
    sortie = tableau.assign(
        heure=pd.to_datetime(tableau["timestamp"], unit="s", utc=True).dt.strftime(
            "%Y-%m-%dT%H:%M:%S.%fZ"
        )
    )
    if format_ == "csv":
        return sortie.to_csv(index=False)
    if format_ == "json":
        return sortie.to_json(orient="records", force_ascii=False, indent=2)
    raise ValueError(f"Format d'export inconnu : {format_}")
