"""Rendu du rapport en texte, en JSON ou en SARIF."""

import json
from itertools import groupby

from secrets_audit import __version__
from secrets_audit.models import SEVERITIES, Finding
from secrets_audit.rules import FILE_RULES, SECRET_RULES

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


# Niveau SARIF de chaque gravité : « error » fait échouer l'analyse du code de GitHub
SARIF_LEVELS = {"high": "error", "medium": "warning", "low": "note"}
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def sarif_rules() -> list[dict]:
    """Description de toutes les règles, dans l'ordre où l'outil les applique."""
    vDescriptions = {vRule.name: vRule.description for vRule in SECRET_RULES}
    vDescriptions.update(FILE_RULES)
    rRules = [
        {
            "id": vName,
            "shortDescription": {"text": vText[:1].upper() + vText[1:]},
        }
        for vName, vText in vDescriptions.items()
    ]
    return rRules


def format_sarif(pFindings: list[Finding], pRepoCount: int) -> str:
    """Rapport SARIF 2.1.0, à envoyer à l'analyse du code de GitHub.

    Un seul dépôt : chemins relatifs à sa racine, comme les attend GitHub. Plusieurs
    dépôts : le nom du dépôt précède le chemin.
    """
    vResults = []
    for vFinding in sort_findings(pFindings):
        vUri = vFinding.path if pRepoCount == 1 else f"{vFinding.repo}/{vFinding.path}"
        vLocation: dict = {"artifactLocation": {"uri": vUri}}
        if vFinding.line is not None:
            vLocation["region"] = {"startLine": vFinding.line}
        vResults.append(
            {
                "ruleId": vFinding.rule,
                "level": SARIF_LEVELS[vFinding.severity],
                "message": {"text": vFinding.detail},
                "locations": [{"physicalLocation": vLocation}],
            }
        )
    vReport = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secrets-audit",
                        "version": __version__,
                        "informationUri": "https://github.com/Remiverhaeghe/secrets-audit",
                        "rules": sarif_rules(),
                    }
                },
                "results": vResults,
            }
        ],
    }
    rSarif = json.dumps(vReport, ensure_ascii=False, indent=2)
    return rSarif
