"""Modèles de données de l'audit."""

from dataclasses import asdict, dataclass

SEVERITIES = ("high", "medium", "low")


@dataclass(frozen=True)
class Finding:
    """Un problème trouvé dans un dépôt. Ne contient jamais la valeur complète d'un secret."""

    repo: str
    path: str
    line: int | None
    rule: str
    severity: str
    detail: str

    def to_dict(self) -> dict:
        """Représentation simple, prête pour le JSON."""
        rDict = asdict(self)
        return rDict
