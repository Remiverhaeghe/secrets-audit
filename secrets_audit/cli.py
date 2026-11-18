"""Ligne de commande : python -m secrets_audit [dossier]."""

import argparse
import logging
import sys
from pathlib import Path

from secrets_audit import gitutil, report
from secrets_audit.models import SEVERITIES
from secrets_audit.scanner import scan_repo, scan_staged

logger = logging.getLogger("secrets_audit")

HOOK_MARKER = "# Installé par secrets-audit"
HOOK_SCRIPT = f"""#!/bin/sh
{HOOK_MARKER} : bloque un commit qui contiendrait un secret.
# Pour passer outre une fois, en connaissance de cause : git commit --no-verify
exec python3 -m secrets_audit . --staged --min-severity high
"""


def install_hook(pRepo: Path) -> int:
    """Pose le hook pre-commit dans le dépôt ; refuse d'écraser un hook qui n'est pas le sien."""
    vHooks = pRepo / ".git" / "hooks"
    if not vHooks.is_dir():
        logger.error("Pas un dépôt git : %s", pRepo)
        return 2
    vHook = vHooks / "pre-commit"
    if vHook.exists() and HOOK_MARKER not in vHook.read_text(encoding="utf-8"):
        logger.error("Un autre hook pre-commit existe déjà : %s", vHook)
        return 2
    vHook.write_text(HOOK_SCRIPT, encoding="utf-8")
    vHook.chmod(0o755)
    print(f"Hook pre-commit installé dans {vHook}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Arguments de la commande."""
    rParser = argparse.ArgumentParser(
        prog="secrets-audit",
        description="Audit d'hygiène des secrets dans les dépôts git d'un dossier.",
    )
    rParser.add_argument("root", nargs="?", default=".", help="dossier à analyser")
    vFormat = rParser.add_mutually_exclusive_group()
    vFormat.add_argument("--json", action="store_true", help="rapport au format JSON")
    vFormat.add_argument(
        "--sarif",
        action="store_true",
        help="rapport SARIF 2.1.0, pour l'analyse du code de GitHub",
    )
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
    rParser.add_argument(
        "--staged",
        action="store_true",
        help="analyser seulement ce qui est dans l'index, pour un hook pre-commit",
    )
    rParser.add_argument(
        "--install-hook",
        action="store_true",
        help="poser le hook pre-commit dans le dépôt donné",
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

    if vArgs.install_hook:
        return install_hook(vRoot.resolve())

    vRepos = [vRoot.resolve()] if vArgs.staged else gitutil.find_repos(vRoot.resolve())
    vFindings = []
    try:
        for vRepo in vRepos:
            logger.debug("Analyse de %s", vRepo)
            if vArgs.staged:
                vFindings.extend(scan_staged(vRepo, tuple(vArgs.ignore)))
            else:
                vFindings.extend(
                    scan_repo(vRepo, tuple(vArgs.ignore), pHistory=not vArgs.no_history)
                )
    except gitutil.GitError as vError:
        logger.error("git : %s", vError)
        return 2

    vFormat = report.format_text
    if vArgs.json:
        vFormat = report.format_json
    elif vArgs.sarif:
        vFormat = report.format_sarif
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
