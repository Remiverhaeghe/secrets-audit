import contextlib
import io
import json
import unittest

from secrets_audit import cli
from secrets_audit.models import Finding
from secrets_audit.report import format_json, format_sarif, format_text, sort_findings
from tests.support import GITHUB_TOKEN, RepoTestCase, commit_all, git, make_repo, write

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


class SarifTest(unittest.TestCase):
    def test_results_levels_and_locations(self):
        vRun = json.loads(format_sarif([MEDIUM, HIGH], 1))["runs"][0]
        self.assertEqual("secrets-audit", vRun["tool"]["driver"]["name"])
        self.assertEqual(
            ["error", "warning"], [vItem["level"] for vItem in vRun["results"]]
        )
        vLocation = vRun["results"][1]["locations"][0]["physicalLocation"]
        self.assertEqual("a.txt", vLocation["artifactLocation"]["uri"])
        self.assertEqual(4, vLocation["region"]["startLine"])
        self.assertNotIn(
            "region", vRun["results"][0]["locations"][0]["physicalLocation"]
        )

    def test_every_reported_rule_is_described(self):
        vRun = json.loads(format_sarif([MEDIUM, HIGH, OTHER], 2))["runs"][0]
        vIds = {vRule["id"] for vRule in vRun["tool"]["driver"]["rules"]}
        self.assertTrue({vItem["ruleId"] for vItem in vRun["results"]} <= vIds)
        self.assertIn("database-url", vIds)
        # Plusieurs dépôts : le nom du dépôt précède le chemin
        self.assertEqual(
            "a/k.pem",
            vRun["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
                "uri"
            ],
        )


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

    def test_sarif_option_hides_the_secret(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "a.txt", f"x {GITHUB_TOKEN}")
        commit_all(vRepo)
        vCode, vOut = self.execute(self.aRoot, "--sarif")
        self.assertEqual(1, vCode)
        self.assertEqual("2.1.0", json.loads(vOut)["version"])
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


class StagedAndHookTest(RepoTestCase):
    def run_cli(self, *pArgs):
        vOut = io.StringIO()
        with contextlib.redirect_stdout(vOut):
            rCode = cli.run(list(pArgs))
        return rCode, vOut.getvalue()

    def test_staged_reads_the_index_not_the_disk(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "README.md", "propre\n")
        commit_all(vRepo)
        write(vRepo, "config.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
        git(vRepo, "add", "config.py")
        # Le secret retiré du disque reste dans l'index : il partirait quand même
        write(vRepo, "config.py", "TOKEN = lire_variable()\n")
        vCode, vText = self.run_cli(str(vRepo), "--staged", "--min-severity", "high")
        self.assertEqual(1, vCode)
        self.assertIn("config.py:1", vText)
        self.assertNotIn(GITHUB_TOKEN, vText)

    def test_staged_flags_a_sensitive_file_and_skips_the_committed_ones(self):
        vRepo = make_repo(self.aRoot)
        write(vRepo, "ancien.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
        commit_all(vRepo)
        write(vRepo, ".env.local", "A=1\n")
        git(vRepo, "add", "-f", ".env.local")
        vCode, vText = self.run_cli(str(vRepo), "--staged")
        self.assertEqual(1, vCode)
        self.assertIn(".env.local", vText)
        self.assertNotIn("ancien.py", vText)

    def test_install_hook_then_refuses_a_foreign_hook(self):
        vRepo = make_repo(self.aRoot)
        vCode, _ = self.run_cli(str(vRepo), "--install-hook")
        self.assertEqual(0, vCode)
        vHook = vRepo / ".git" / "hooks" / "pre-commit"
        self.assertIn("--staged", vHook.read_text(encoding="utf-8"))
        self.assertEqual(0, self.run_cli(str(vRepo), "--install-hook")[0])
        vHook.write_text("#!/bin/sh\necho autre\n", encoding="utf-8")
        with self.assertLogs("secrets_audit", "ERROR"):
            self.assertEqual(2, self.run_cli(str(vRepo), "--install-hook")[0])
        with self.assertLogs("secrets_audit", "ERROR"):
            self.assertEqual(2, self.run_cli(str(self.aRoot), "--install-hook")[0])
