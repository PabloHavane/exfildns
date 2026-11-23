"""Point d'entrée en ligne de commande : `exfildns <commande>`."""

import argparse

import pandas as pd

from exfildns import __version__
from exfildns.dataset import load_dataset
from exfildns.evaluation import SEUIL, evaluer
from exfildns.features import FEATURES, features_dataframe
from exfildns.model import (
    CAPTURES_TEST,
    charger,
    entrainer_mlp,
    predire_proba,
    sauvegarder,
    split_par_capture,
)
from exfildns.pcap import read_dns_queries

MODELE_PAR_DEFAUT = "models/exfildns.keras"


def afficher_metriques(metriques: dict[str, float | int]) -> None:
    print(
        f"  rappel (exfiltrations détectées) : {metriques['rappel']:.4f}\n"
        f"  taux de faux positifs            : {metriques['taux_faux_positifs']:.6f}\n"
        f"  précision                        : {metriques['precision']:.4f}\n"
        f"  F1                               : {metriques['f1']:.4f}\n"
        f"  PR-AUC                           : {metriques['pr_auc']:.4f}\n"
        f"  exfiltrations détectées / manquées : "
        f"{metriques['vrais_positifs']} / {metriques['faux_negatifs']}\n"
        f"  fausses alertes / bénins corrects  : "
        f"{metriques['faux_positifs']} / {metriques['vrais_negatifs']}"
    )


def charger_jeu(args):
    df = load_dataset(args.donnees)
    return split_par_capture(df, tuple(args.captures_test))


def commande_train(args) -> int:
    train, test = charger_jeu(args)
    print(f"Entraînement sur {len(train)} requêtes, test sur {len(test)}.")
    modele, historique = entrainer_mlp(train[FEATURES], train["label"], epochs=args.epochs)
    print(f"Arrêt après {len(historique['loss'])} époques.")
    sauvegarder(modele, args.sortie)
    print(f"Modèle sauvegardé : {args.sortie}")
    print("Résultats sur le jeu de test :")
    afficher_metriques(evaluer(modele, test[FEATURES], test["label"]))
    return 0


def commande_evaluate(args) -> int:
    _, test = charger_jeu(args)
    print(f"Évaluation de {args.modele} sur {len(test)} requêtes de test :")
    afficher_metriques(evaluer(charger(args.modele), test[FEATURES], test["label"]))
    return 0


def domaine_parent(qname: str, tronque: bool) -> str:
    """Deux derniers labels du nom (`exemple.com`), ou un marqueur si le nom est coupé."""
    if tronque:
        return "(nom tronqué dans la capture)"
    return ".".join(qname.split(".")[-2:]) or "(racine)"


def commande_scan(args) -> int:
    requetes = read_dns_queries(args.capture)
    if requetes.empty:
        print(f"Aucune requête DNS dans {args.capture}.")
        return 0
    modele = charger(args.modele)
    requetes["score"] = predire_proba(modele, features_dataframe(requetes["qname"]))
    suspectes = requetes[requetes["score"] >= args.seuil].sort_values("score", ascending=False)
    print(
        f"{len(requetes)} requêtes DNS analysées, {len(suspectes)} suspectes (seuil {args.seuil})."
    )
    if suspectes.empty:
        return 0

    print("\nServeurs DNS destinataires des requêtes suspectes :")
    for serveur, nombre in suspectes["dst"].value_counts().head(5).items():
        print(f"  {serveur:<40} {nombre}")
    parents = [
        domaine_parent(q, pd.isna(t))
        for q, t in zip(suspectes["qname"], suspectes["qtype"], strict=True)
    ]
    print("\nDomaines parents les plus touchés :")
    for parent, nombre in pd.Series(parents).value_counts().head(5).items():
        print(f"  {parent:<40} {nombre}")

    print(f"\nRequêtes suspectes ({min(args.max, len(suspectes))} plus probables) :")
    for r in suspectes.head(args.max).itertuples():
        print(f"  {r.score:.3f}  {r.src} -> {r.dst}  {r.qname}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exfildns",
        description="Détecte les requêtes DNS servant à exfiltrer des données.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commandes = parser.add_subparsers(dest="command")

    donnees = argparse.ArgumentParser(add_help=False)
    donnees.add_argument(
        "donnees", nargs="?", default="data", help="dossier contenant Attacks/ et Benign/"
    )
    donnees.add_argument(
        "--captures-test",
        nargs="+",
        default=list(CAPTURES_TEST),
        help="captures mises de côté pour le test (les mêmes pour train et evaluate ; "
        "placer le dossier de données avant cette option)",
    )

    train = commandes.add_parser("train", parents=[donnees], help="entraîne le modèle")
    train.add_argument("-o", "--sortie", default=MODELE_PAR_DEFAUT, help="fichier .keras")
    train.add_argument("--epochs", type=int, default=30, help="nombre maximal d'époques")
    train.set_defaults(fonction=commande_train)

    evaluate = commandes.add_parser("evaluate", parents=[donnees], help="évalue un modèle")
    evaluate.add_argument("-m", "--modele", default=MODELE_PAR_DEFAUT, help="fichier .keras")
    evaluate.set_defaults(fonction=commande_evaluate)

    scan = commandes.add_parser(
        "scan",
        help="analyse une capture réseau (code de sortie 1 si des requêtes sont suspectes)",
    )
    scan.add_argument("capture", help="fichier .pcap ou .pcapng")
    scan.add_argument("-m", "--modele", default=MODELE_PAR_DEFAUT, help="fichier .keras")
    scan.add_argument("--seuil", type=float, default=SEUIL, help="seuil de probabilité")
    scan.add_argument("--max", type=int, default=20, help="nombre de requêtes suspectes listées")
    scan.set_defaults(fonction=commande_scan)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    return args.fonction(args)


if __name__ == "__main__":
    raise SystemExit(main())
