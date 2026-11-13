"""Rendu du rapport en texte ou en JSON."""

import json
from itertools import groupby

from secrets_audit.models import SEVERITIES, Finding

LABELS = {"high": "haute", "medium": "moyenne", "low": "faible"}


def severity_rank(pSeverity: str) -> int:
    """Rang de gravité : 0 pour la plus grave."""
    rRank = SEVERITIES.index(pSeverity)
    return rRank


def sort_findings(pFindings: list[Finding]) -> list[Finding]:
    """Trie par dépôt, gravité décroissante, puis chemin et ligne."""
    rSorted = sorted(
        pFindings,
        key=lambda pItem: (
            pItem.repo,
            severity_rank(pItem.severity),
            pItem.path,
            pItem.line or 0,
        ),
    )
    return rSorted


def format_text(pFindings: list[Finding], pRepoCount: int) -> str:
    """Rapport lisible, groupé par dépôt."""
    if not pFindings:
        return f"Aucun problème trouvé dans {pRepoCount} dépôt(s)."
    vLines = [f"{len(pFindings)} problème(s) dans {pRepoCount} dépôt(s) analysé(s)", ""]
    for vRepo, vGroup in groupby(
        sort_findings(pFindings), key=lambda pItem: pItem.repo
    ):
        vLines.append(vRepo)
        for vFinding in vGroup:
            vPlace = vFinding.path
            if vFinding.line is not None:
                vPlace = f"{vPlace}:{vFinding.line}"
            vLabel = f"[{LABELS[vFinding.severity]}]".ljust(10)
            vLines.append(f"  {vLabel} {vPlace} — {vFinding.detail} ({vFinding.rule})")
        vLines.append("")
    rText = "\n".join(vLines).rstrip()
    return rText


def format_json(pFindings: list[Finding], pRepoCount: int) -> str:
    """Rapport JSON, pour un script ou la CI."""
    vReport = {
        "repos": pRepoCount,
        "findings": [vFinding.to_dict() for vFinding in sort_findings(pFindings)],
    }
    rJson = json.dumps(vReport, ensure_ascii=False, indent=2)
    return rJson
