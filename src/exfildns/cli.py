"""Point d'entrée en ligne de commande : `exfildns <commande>`."""

import argparse

from exfildns import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="exfildns",
        description="Détecte les requêtes DNS servant à exfiltrer des données.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_subparsers(dest="command")
    # Les sous-commandes (train, evaluate, scan) sont ajoutées par les issues dédiées.
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
