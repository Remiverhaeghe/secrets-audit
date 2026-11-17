"""Appels à git : dépôts, fichiers suivis, non suivis, historique."""

import logging
import shutil

# git est lancé sans shell, avec des arguments fixes
import subprocess  # nosec B404
from pathlib import Path

SKIPPED_DIRS = {"node_modules", "vendor", "__pycache__", "venv", ".venv", "dist"}

logger = logging.getLogger(__name__)


class GitError(RuntimeError):
    """git a échoué ou n'est pas installé."""


def _git(pRepo: Path, *pArgs: str) -> bytes:
    vGit = shutil.which("git")
    if vGit is None:
        raise GitError("git est introuvable dans le PATH")
    vCommand = [vGit, "-c", "core.quotepath=off", "-C", str(pRepo), *pArgs]
    # Arguments fixes construits ici, sans shell : pas d'injection possible
    vProcess = subprocess.run(vCommand, capture_output=True, check=False)  # nosec B603
    if vProcess.returncode != 0:
        raise GitError(vProcess.stderr.decode("utf-8", "replace").strip())
    rOutput = vProcess.stdout
    return rOutput


def _split_nul(pOutput: bytes) -> list[str]:
    vItems = (
        vItem.decode("utf-8", "replace").strip("\n") for vItem in pOutput.split(b"\0")
    )
    rPaths = [vItem for vItem in vItems if vItem]
    return rPaths


def _walk(pDir: Path, pLevel: int, pDepth: int, pRepos: list[Path]) -> None:
    if (pDir / ".git").exists():
        pRepos.append(pDir)
        return
    if pLevel >= pDepth:
        return
    try:
        vChildren = sorted(pDir.iterdir())
    except OSError as vError:
        logger.warning("Dossier illisible %s : %s", pDir, vError)
        return
    for vChild in vChildren:
        vSkipped = vChild.name in SKIPPED_DIRS or vChild.name.startswith(".")
        if vChild.is_dir() and not vSkipped:
            _walk(vChild, pLevel + 1, pDepth, pRepos)


def find_repos(pRoot: Path, pDepth: int = 2) -> list[Path]:
    """Dépôts git sous pRoot (pRoot compris), sur pDepth niveaux au plus."""
    rRepos: list[Path] = []
    _walk(pRoot, 0, pDepth, rRepos)
    return rRepos


def tracked_files(pRepo: Path) -> list[str]:
    """Fichiers suivis par git."""
    rFiles = _split_nul(_git(pRepo, "ls-files", "-z"))
    return rFiles


def untracked_files(pRepo: Path) -> list[str]:
    """Fichiers présents, non suivis et non ignorés (donc prêts à être commités par erreur)."""
    rFiles = _split_nul(_git(pRepo, "ls-files", "--others", "--exclude-standard", "-z"))
    return rFiles


def history_added_files(pRepo: Path) -> list[str]:
    """Chemins ajoutés une fois dans l'historique, toutes branches ; vide sans commit."""
    try:
        vOutput = _git(
            pRepo,
            "log",
            "--all",
            "--diff-filter=A",
            "--name-only",
            "--pretty=format:",
            "-z",
        )
    except GitError as vError:
        logger.debug("Historique illisible pour %s : %s", pRepo, vError)
        return []
    rFiles = sorted(set(_split_nul(vOutput)))
    return rFiles


def staged_files(pRepo: Path) -> list[str]:
    """Fichiers ajoutés ou modifiés dans l'index, prêts à partir au prochain commit."""
    rFiles = _split_nul(
        _git(pRepo, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z")
    )
    return rFiles


def staged_bytes(pRepo: Path, pPath: str) -> bytes:
    """Contenu d'un fichier tel qu'il est dans l'index, pas tel qu'il est sur le disque."""
    rData = _git(pRepo, "show", f":{pPath}")
    return rData
