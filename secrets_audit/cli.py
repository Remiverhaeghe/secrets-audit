"""Ligne de commande : python -m secrets_audit [dossier]."""

import argparse
import logging
import sys
from pathlib import Path

from secrets_audit import gitutil, report
from secrets_audit.models import SEVERITIES
from secrets_audit.scanner import scan_repo

logger = logging.getLogger("secrets_audit")


def build_parser() -> argparse.ArgumentParser:
    """Arguments de la commande."""
    rParser = argparse.ArgumentParser(
        prog="secrets-audit",
        description="Audit d'hygiène des secrets dans les dépôts git d'un dossier.",
    )
    rParser.add_argument("root", nargs="?", default=".", help="dossier à analyser")
    rParser.add_argument("--json", action="store_true", help="rapport au format JSON")
    rParser.add_argument(
        "--ignore",
        action="append",
        default=[],
        metavar="MOTIF",
        help="motif de chemin à ignorer (répétable), par exemple 'tests/*'",
    )
    rParser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default="medium",
        help="gravité minimale qui fait échouer la commande (défaut : medium)",
    )
    rParser.add_argument(
        "--no-history", action="store_true", help="ne pas analyser l'historique git"
    )
    rParser.add_argument("--verbose", action="store_true", help="journal détaillé")
    return rParser


def run(pArgv: list[str]) -> int:
    """Lance l'audit. Code de sortie : 0 propre, 1 problèmes trouvés, 2 erreur."""
    vArgs = build_parser().parse_args(pArgv)
    logging.basicConfig(
        level=logging.DEBUG if vArgs.verbose else logging.WARNING,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    vRoot = Path(vArgs.root)
    if not vRoot.is_dir():
        logger.error("Dossier introuvable : %s", vRoot)
        return 2

    vRepos = gitutil.find_repos(vRoot.resolve())
    vFindings = []
    try:
        for vRepo in vRepos:
            logger.debug("Analyse de %s", vRepo)
            vFindings.extend(
                scan_repo(vRepo, tuple(vArgs.ignore), pHistory=not vArgs.no_history)
            )
    except gitutil.GitError as vError:
        logger.error("git : %s", vError)
        return 2

    vFormat = report.format_json if vArgs.json else report.format_text
    print(vFormat(vFindings, len(vRepos)))
    vLimit = report.severity_rank(vArgs.min_severity)
    vBlocking = [
        vFinding
        for vFinding in vFindings
        if report.severity_rank(vFinding.severity) <= vLimit
    ]
    rCode = 1 if vBlocking else 0
    return rCode


def main() -> int:
    """Entrée de la commande."""
    rCode = run(sys.argv[1:])
    return rCode
