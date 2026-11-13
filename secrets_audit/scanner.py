"""Analyse d'un dépôt : fichiers sensibles, secrets en clair, historique."""

import fnmatch
import logging
from dataclasses import replace
from pathlib import Path

from secrets_audit import gitutil
from secrets_audit.models import Finding
from secrets_audit.rules import (
    IGNORE_MARKER,
    SECRET_RULES,
    is_benign_key,
    is_placeholder,
    is_sensitive_name,
    is_test_path,
    redact,
)

MAX_FILE_BYTES = 1_000_000
DOWNGRADABLE_RULES = {"generic-assignment", "jwt", "sensitive-file-tracked"}
SKIPPED_SUFFIXES = (".lock", ".min.js", ".min.css", "package-lock.json")

logger = logging.getLogger(__name__)


def is_ignored(pPath: str, pIgnore: tuple[str, ...]) -> bool:
    """Le chemin correspond à un motif --ignore."""
    rIgnored = any(fnmatch.fnmatch(pPath, vPattern) for vPattern in pIgnore)
    return rIgnored


def scan_text(pRepo: str, pPath: str, pText: str) -> list[Finding]:
    """Cherche des secrets ligne par ligne, une trouvaille au plus par ligne."""
    rFindings: list[Finding] = []
    for vNumber, vLine in enumerate(pText.splitlines(), start=1):
        if IGNORE_MARKER in vLine:
            continue
        for vRule in SECRET_RULES:
            # pylint se trompe sur le type du motif (re.Pattern) dans cette dataclass
            vMatch = vRule.pattern.search(vLine)  # pylint: disable=no-member
            if vMatch is None:
                continue
            vKey = vMatch.groupdict().get("key")
            if vKey is not None and is_benign_key(vKey):
                continue
            vValue = vMatch.group(vRule.group) if vRule.group is not None else None
            if vRule.check_placeholder and vValue is not None:
                if is_placeholder(vValue):
                    continue
            vDetail = vRule.description
            if vValue is not None:
                vDetail = f"{vDetail} ({redact(vValue)})"
            rFindings.append(
                Finding(pRepo, pPath, vNumber, vRule.name, vRule.severity, vDetail)
            )
            break
    return rFindings


def lower_in_tests(pFindings: list[Finding]) -> list[Finding]:
    """Ramène à « low » les trouvailles ambiguës situées dans des chemins de test.

    Un jeton, une clé d'accès ou une clé privée reste de gravité haute partout.
    """
    rFindings = [
        (
            replace(vFinding, severity="low")
            if vFinding.rule in DOWNGRADABLE_RULES and is_test_path(vFinding.path)
            else vFinding
        )
        for vFinding in pFindings
    ]
    return rFindings


def read_text(pFile: Path) -> str | None:
    """Contenu texte d'un fichier, None s'il est absent, trop gros ou binaire."""
    try:
        if not pFile.is_file() or pFile.stat().st_size > MAX_FILE_BYTES:
            return None
        vData = pFile.read_bytes()
    except OSError as vError:
        logger.warning("Fichier illisible %s : %s", pFile, vError)
        return None
    if b"\0" in vData[:8000]:
        return None
    rText = vData.decode("utf-8", "replace")
    return rText


def scan_repo(
    pRepo: Path, pIgnore: tuple[str, ...] = (), pHistory: bool = True
) -> list[Finding]:
    """Audit complet d'un dépôt."""
    vName = pRepo.name
    rFindings: list[Finding] = []
    vTracked = gitutil.tracked_files(pRepo)

    for vPath in vTracked:
        if is_ignored(vPath, pIgnore):
            continue
        if is_sensitive_name(vPath):
            rFindings.append(
                Finding(
                    vName,
                    vPath,
                    None,
                    "sensitive-file-tracked",
                    "high",
                    "fichier sensible suivi par git",
                )
            )
        if vPath.endswith(SKIPPED_SUFFIXES):
            continue
        vText = read_text(pRepo / vPath)
        if vText is not None:
            rFindings.extend(scan_text(vName, vPath, vText))

    for vPath in gitutil.untracked_files(pRepo):
        if is_sensitive_name(vPath) and not is_ignored(vPath, pIgnore):
            rFindings.append(
                Finding(
                    vName,
                    vPath,
                    None,
                    "sensitive-file-unignored",
                    "medium",
                    "fichier sensible présent mais absent du .gitignore",
                )
            )

    if pHistory:
        vTrackedSet = set(vTracked)
        for vPath in gitutil.history_added_files(pRepo):
            if vPath in vTrackedSet or is_ignored(vPath, pIgnore):
                continue
            if is_sensitive_name(vPath):
                rFindings.append(
                    Finding(
                        vName,
                        vPath,
                        None,
                        "sensitive-file-in-history",
                        "high",
                        "fichier sensible présent dans l'historique git",
                    )
                )
    return lower_in_tests(rFindings)
