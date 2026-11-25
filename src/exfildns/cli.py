"""Point d'entrée en ligne de commande : `exfildns <commande>`."""

import argparse
import os
import signal
import sys
from pathlib import Path

from scapy.error import Scapy_Exception

from exfildns import __version__, dashboard
from exfildns.alertes import LISTE_BLANCHE, MIN_REQUETES, alertes, lire_liste_blanche
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
from exfildns.sniff import lots_reseau, ouvrir_base, surveiller

MODELE_PAR_DEFAUT = "models/exfildns.keras"
BASE_PAR_DEFAUT = "detections.db"
TAILLE_MAX_CAPTURE = 100  # Mo, pour les captures déposées dans le dashboard


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


def commande_scan(args) -> int:
    liste_blanche = list(LISTE_BLANCHE)
    if args.liste_blanche:  # lu d'abord : un chemin erroné est signalé avant la longue analyse
        liste_blanche += lire_liste_blanche(args.liste_blanche)
    requetes = read_dns_queries(args.capture)
    if requetes.empty:
        print(f"Aucune requête DNS dans {args.capture}.")
        return 0
    if not Path(args.modele).exists():
        print(
            f"Modèle introuvable : {args.modele} (lancer d'abord exfildns train).", file=sys.stderr
        )
        return 2
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
    resume = alertes(requetes, args.seuil, args.min_requetes, liste_blanche)
    print(
        f"\nAlertes : domaines ayant reçu au moins {args.min_requetes} requêtes suspectes "
        f"({len(resume)}) :"
    )
    for a in resume.head(5).itertuples():
        print(f"  {a.domaine:<40} {a.requetes_suspectes}")

    print(f"\nRequêtes suspectes ({min(args.max, len(suspectes))} plus probables) :")
    for r in suspectes.head(args.max).itertuples():
        print(f"  {r.score:.3f}  {r.src} -> {r.dst}  {r.qname}")
    return 1 if len(resume) else 0


def commande_sniff(args) -> int:
    if not Path(args.modele).exists():
        print(
            f"Modèle introuvable : {args.modele} (lancer d'abord exfildns train).", file=sys.stderr
        )
        return 2
    modele = charger(args.modele)
    try:
        lots = lots_reseau(args.interface)
    except PermissionError:
        print(
            "Droits insuffisants pour capturer : lancer en root ou donner la capacité "
            "CAP_NET_RAW à l'interpréteur Python.",
            file=sys.stderr,
        )
        return 2
    except (ValueError, Scapy_Exception) as erreur:  # interface inconnue, libpcap absent
        print(f"Capture impossible : {erreur}", file=sys.stderr)
        return 2
    # `docker stop` envoie SIGTERM : on l'interprète comme Ctrl+C pour s'arrêter proprement
    signal.signal(signal.SIGTERM, signal.default_int_handler)
    interface = args.interface or "l'interface par défaut"
    print(f"Capture DNS sur {interface}, requêtes enregistrées dans {args.base}.")
    print(f"Requêtes suspectes (seuil {args.seuil}) ; Ctrl+C pour arrêter.", flush=True)
    connexion = ouvrir_base(args.base)
    try:
        analysees, suspectes = surveiller(lots, modele, connexion, args.seuil)
    finally:
        connexion.close()
    print(f"\nCapture arrêtée : {analysees} requêtes analysées, {suspectes} suspectes.")
    return 0


def commande_dashboard(args) -> int:
    """Remplace le processus par le serveur Streamlit du dashboard (base et modèle en variables).

    `exec` plutôt qu'un sous-processus : Streamlit reçoit directement les signaux (Ctrl+C,
    SIGTERM de `docker stop`) et s'arrête proprement.
    """
    env = {
        **os.environ,
        "EXFILDNS_BASE": str(Path(args.base).resolve()),
        "EXFILDNS_MODELE": str(Path(args.modele).resolve()),
    }
    if args.statuts:  # sinon : statuts.db à côté de la base (voir dashboard.page)
        env["EXFILDNS_STATUTS"] = str(Path(args.statuts).resolve())
    commande = [sys.executable, "-m", "streamlit", "run", dashboard.__file__]
    # localhost par défaut : le dashboard montre les noms demandés et les postes, il ne doit
    # pas être exposé sur le réseau sans le vouloir (dans un conteneur : --adresse 0.0.0.0)
    commande += ["--server.address", args.adresse, "--server.port", str(args.port)]
    commande += ["--server.headless", "true", "--server.maxUploadSize", str(TAILLE_MAX_CAPTURE)]
    # toolbarMode viewer : masque le bouton « Deploy » de Streamlit, sans objet ici
    commande += ["--browser.gatherUsageStats", "false", "--client.toolbarMode", "viewer"]
    print(
        f"Dashboard : http://{args.adresse}:{args.port} (base {args.base}) ; Ctrl+C pour arrêter."
    )
    sys.stdout.flush()
    os.execvpe(commande[0], commande, env)
    return 0  # jamais atteint (sauf quand exec est remplacé dans les tests)


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
    scan.add_argument(
        "--min-requetes",
        type=int,
        default=MIN_REQUETES,
        help="requêtes suspectes vers un même domaine pour lever une alerte",
    )
    scan.add_argument(
        "--liste-blanche", help="fichier de domaines à ne jamais signaler (un par ligne)"
    )
    scan.set_defaults(fonction=commande_scan)

    sniff = commandes.add_parser(
        "sniff",
        help="détecte en direct sur une interface réseau (root ou CAP_NET_RAW)",
    )
    sniff.add_argument("-i", "--interface", help="interface à écouter (défaut : celle de scapy)")
    sniff.add_argument("-m", "--modele", default=MODELE_PAR_DEFAUT, help="fichier .keras")
    sniff.add_argument("--seuil", type=float, default=SEUIL, help="seuil d'affichage")
    sniff.add_argument(
        "--base", default=BASE_PAR_DEFAUT, help="base SQLite où enregistrer les requêtes"
    )
    sniff.set_defaults(fonction=commande_sniff)

    tableau = commandes.add_parser("dashboard", help="ouvre le dashboard web de supervision")
    tableau.add_argument("--base", default=BASE_PAR_DEFAUT, help="base SQLite écrite par sniff")
    tableau.add_argument("--port", type=int, default=8501, help="port HTTP du dashboard")
    tableau.add_argument(
        "--statuts",
        help="base SQLite des statuts d'alertes, écrite par le dashboard (défaut : statuts.db "
        "dans le dossier de --base)",
    )
    tableau.add_argument(
        "-m", "--modele", default=MODELE_PAR_DEFAUT, help="modèle pour analyser une capture"
    )
    tableau.add_argument(
        "--adresse", default="localhost", help="adresse d'écoute (0.0.0.0 : tout le réseau)"
    )
    tableau.set_defaults(fonction=commande_dashboard)
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
