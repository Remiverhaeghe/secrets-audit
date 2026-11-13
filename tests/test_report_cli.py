import contextlib
import io
import json
import unittest

from secrets_audit import cli
from secrets_audit.models import Finding
from secrets_audit.report import format_json, format_text, sort_findings
from tests.support import GITHUB_TOKEN, RepoTestCase, commit_all, make_repo, write

HIGH = Finding("b", "z.env", None, "sensitive-file-tracked", "high", "suivi")
MEDIUM = Finding("b", "a.txt", 4, "generic-assignment", "medium", "secret")
OTHER = Finding("a", "k.pem", None, "sensitive-file-in-history", "high", "historique")


class ReportTest(unittest.TestCase):
    def test_sort_by_repo_then_severity(self):
        self.assertEqual([OTHER, HIGH, MEDIUM], sort_findings([MEDIUM, HIGH, OTHER]))

    def test_text_groups_by_repo_with_places(self):
        vText = format_text([MEDIUM, HIGH, OTHER], 3)
        self.assertEqual(
            "3 problème(s) dans 3 dépôt(s) analysé(s)\n\n"
            "a\n  [haute]    k.pem — historique (sensitive-file-in-history)\n\n"
            "b\n  [haute]    z.env — suivi (sensitive-file-tracked)\n"
            "  [moyenne]  a.txt:4 — secret (generic-assignment)",
            vText,
        )

    def test_text_without_finding(self):
        self.assertEqual("Aucun problème trouvé dans 2 dépôt(s).", format_text([], 2))

    def test_json(self):
        vData = json.loads(format_json([MEDIUM], 1))
        self.assertEqual(1, vData["repos"])
        self.assertEqual("a.txt", vData["findings"][0]["path"])


class CliTest(RepoTestCase):
    def execute(self, *pArgs):
        vOut = io.StringIO()
        with contextlib.redirect_stdout(vOut):
            vCode = cli.run([str(vArg) for vArg in pArgs])
        return vCode, vOut.getvalue()

    def test_clean_folder_exits_zero(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "a.txt", "ok")
        commit_all(vRepo)
        vCode, vOut = self.execute(self.aRoot)
        self.assertEqual(0, vCode)
        self.assertIn("Aucun problème", vOut)

    def test_findings_exit_one_and_json_is_parseable(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "a.txt", f"x {GITHUB_TOKEN}")
        commit_all(vRepo)
        vCode, vOut = self.execute(self.aRoot, "--json")
        self.assertEqual(1, vCode)
        self.assertEqual("github-token", json.loads(vOut)["findings"][0]["rule"])
        self.assertNotIn(GITHUB_TOKEN, vOut)

    def test_min_severity_filters_exit_code(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "a.txt", "DB_PASSWORD=" + "Zx9q" + "T7vLm2Qw")
        commit_all(vRepo)
        self.assertEqual(1, self.execute(self.aRoot)[0])
        self.assertEqual(1, self.execute(self.aRoot, "--min-severity", "low")[0])
        self.assertEqual(0, self.execute(self.aRoot, "--min-severity", "high")[0])

    def test_low_findings_do_not_fail_by_default(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "tests/a.env", "DB_PASSWORD=" + "Zx9q" + "T7vLm2Qw")
        commit_all(vRepo)
        self.assertEqual(0, self.execute(self.aRoot)[0])
        self.assertEqual(1, self.execute(self.aRoot, "--min-severity", "low")[0])

    def test_ignore_and_no_history_options(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "a.txt", f"x {GITHUB_TOKEN}")
        commit_all(vRepo)
        self.assertEqual(
            0, self.execute(self.aRoot, "--ignore", "a.txt", "--no-history")[0]
        )

    def test_missing_folder_exits_two(self):
        with self.assertLogs("secrets_audit", "ERROR"):
            self.assertEqual(2, self.execute(self.aRoot / "absent")[0])

    def test_git_error_exits_two(self):
        (self.aRoot / "faux" / ".git").mkdir(parents=True)
        with self.assertLogs("secrets_audit", "ERROR"):
            self.assertEqual(2, self.execute(self.aRoot)[0])

    def test_main_uses_command_line_arguments(self):
        from unittest import mock

        with mock.patch("sys.argv", ["secrets-audit", str(self.aRoot)]):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, cli.main())


if __name__ == "__main__":
    unittest.main()
