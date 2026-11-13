import unittest

from secrets_audit.scanner import read_text, scan_repo
from tests.support import (
    GITHUB_TOKEN,
    REAL_PASSWORD,
    RepoTestCase,
    commit_all,
    git,
    make_repo,
    write,
)


class ScanRepoTest(RepoTestCase):
    def rules(self, pRepo, **pOptions):
        return sorted(vFinding.rule for vFinding in scan_repo(pRepo, **pOptions))

    def test_clean_repo_has_no_finding(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "README.md", "# Projet\n")
        write(vRepo, ".env.example", "TOKEN=changeme\n")
        commit_all(vRepo)
        self.assertEqual([], scan_repo(vRepo))

    def test_tracked_sensitive_file_and_secret_in_content(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "config/.env.local", f"GH={GITHUB_TOKEN}\n")
        commit_all(vRepo)
        vFindings = scan_repo(vRepo)
        self.assertEqual(["github-token", "sensitive-file-tracked"], self.rules(vRepo))
        vToken = next(
            vFinding for vFinding in vFindings if vFinding.rule == "github-token"
        )
        self.assertEqual(
            (vRepo.name, "config/.env.local", 1),
            (vToken.repo, vToken.path, vToken.line),
        )

    def test_unignored_sensitive_file_then_ignored(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "a.txt", "x")
        commit_all(vRepo)
        write(vRepo, ".env.nas", "A=1\n")
        self.assertEqual(["sensitive-file-unignored"], self.rules(vRepo))
        write(vRepo, ".gitignore", ".env.nas\n")
        self.assertEqual([], self.rules(vRepo))

    def test_sensitive_file_removed_stays_in_history(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "serveur.key", "contenu")
        commit_all(vRepo)
        git(vRepo, "rm", "-q", "serveur.key")
        git(vRepo, "commit", "-q", "-m", "retrait")
        self.assertEqual(["sensitive-file-in-history"], self.rules(vRepo))
        self.assertEqual([], self.rules(vRepo, pHistory=False))

    def test_removed_ordinary_file_is_not_reported(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "notes.txt", "rien")
        commit_all(vRepo)
        git(vRepo, "rm", "-q", "notes.txt")
        git(vRepo, "commit", "-q", "-m", "retrait")
        self.assertEqual([], scan_repo(vRepo))

    def test_tracked_sensitive_file_is_not_reported_twice(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "serveur.key", "contenu")
        commit_all(vRepo)
        self.assertEqual(["sensitive-file-tracked"], self.rules(vRepo))

    def test_ignore_glob_skips_path_everywhere(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "tests/a.env", f"X={GITHUB_TOKEN}\n")
        write(vRepo, "tests/serveur.key", "x")
        commit_all(vRepo)
        self.assertEqual([], self.rules(vRepo, pIgnore=("tests/*",)))

    def test_ambiguous_findings_in_test_paths_are_low_but_tokens_stay_high(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "tests/a.env", "DB_PASSWORD=" + REAL_PASSWORD + "\n")
        write(vRepo, "tests/b.env", f"X={GITHUB_TOKEN}\n")
        write(vRepo, "tests/serveur.key", "x")
        write(vRepo, "src/c.env", "DB_PASSWORD=" + REAL_PASSWORD + "\n")
        commit_all(vRepo)
        vSeverities = {
            (vFinding.path, vFinding.rule): vFinding.severity
            for vFinding in scan_repo(vRepo)
        }
        self.assertEqual(
            {
                ("tests/a.env", "generic-assignment"): "low",
                ("tests/b.env", "github-token"): "high",
                ("tests/serveur.key", "sensitive-file-tracked"): "low",
                ("src/c.env", "generic-assignment"): "medium",
            },
            vSeverities,
        )

    def test_lock_files_binary_and_big_files_are_not_read(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "composer.lock", f"x {GITHUB_TOKEN}\n")
        (vRepo / "image.bin").write_bytes(b"\0\1" + GITHUB_TOKEN.encode())
        write(vRepo, "gros.txt", f"{GITHUB_TOKEN}\n" + "a" * 1_000_001)
        commit_all(vRepo)
        self.assertEqual([], scan_repo(vRepo))

    def test_read_text_missing_file_is_none(self):
        self.assertIsNone(read_text(self.aRoot / "absent.txt"))

    def test_read_text_unreadable_file_is_none(self):
        vFile = self.aRoot / "f.txt"
        vFile.write_text("a", encoding="utf-8")
        from unittest import mock

        with mock.patch("pathlib.Path.read_bytes", side_effect=OSError("non")):
            with self.assertLogs("secrets_audit.scanner", "WARNING"):
                self.assertIsNone(read_text(vFile))


if __name__ == "__main__":
    unittest.main()
