"""Aides de test : dépôts git temporaires."""

import shutil
import subprocess  # nosec B404
import tempfile
import unittest
from pathlib import Path

# Valeurs de test construites par morceaux : le dépôt peut ainsi s'auditer lui-même
GITHUB_TOKEN = "gh" + "p_" + "A1b2C3" * 6
AWS_KEY = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
PRIVATE_KEY_LINE = "-----BEGIN " + "RSA PRIVATE KEY-----"
REAL_PASSWORD = "Zx9q" + "T7vLm2Qw"


def git(pRepo: Path, *pArgs: str) -> None:
    """Lance git dans un dépôt de test, avec une identité fixe."""
    vCommand = [
        "git",
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "-C",
        str(pRepo),
        *pArgs,
    ]
    subprocess.run(vCommand, check=True, capture_output=True)  # nosec B603 B607


def make_repo(pRoot: Path, pName: str = "projet") -> Path:
    """Crée un dépôt git vide."""
    rRepo = pRoot / pName
    rRepo.mkdir(parents=True)
    git(rRepo, "init", "-q", "-b", "main")
    return rRepo


def write(pRepo: Path, pPath: str, pText: str) -> None:
    """Écrit un fichier dans le dépôt."""
    vFile = pRepo / pPath
    vFile.parent.mkdir(parents=True, exist_ok=True)
    vFile.write_text(pText, encoding="utf-8")


def commit_all(pRepo: Path, pMessage: str = "commit") -> None:
    """Ajoute tout et commite."""
    git(pRepo, "add", "-A")
    git(pRepo, "commit", "-q", "-m", pMessage)


class RepoTestCase(unittest.TestCase):
    """Fournit un dossier temporaire supprimé à la fin du test."""

    def setUp(self) -> None:
        self.aRoot = Path(tempfile.mkdtemp(prefix="secrets-audit-"))
        self.addCleanup(shutil.rmtree, self.aRoot, True)
