import unittest

from secrets_audit.rules import (
    is_benign_key,
    is_placeholder,
    is_sensitive_name,
    is_test_path,
    redact,
)
from secrets_audit.scanner import scan_text
from tests.support import (
    ANTHROPIC_KEY,
    AWS_KEY,
    DATABASE_URL,
    GITHUB_TOKEN,
    GITLAB_TOKEN,
    GOOGLE_KEY,
    NPM_TOKEN,
    OPENAI_KEY,
    PRIVATE_KEY_LINE,
    REAL_PASSWORD,
    STRIPE_KEY,
    TELEGRAM_TOKEN,
)


class PlaceholderTest(unittest.TestCase):
    def test_examples_and_code_are_placeholders(self):
        for vValue in (
            "changeme123",
            "your-api-key",
            "${DB_PASSWORD}",
            "$_ENV['X']",
            "self.password",
            "aaaaaaaaaa",
            "<token-here>",
            "%env(SECRET)%",
            "password_hash",
            "none-given",
            "?Chose-obligatoire",
            "ApiTokenHandlerService",
            "csrfField.value;",
            "pCsrfToken,",
            "App\\Security\\Handler",
            "/run/secrets/token",
        ):
            with self.subTest(vValue):
                self.assertTrue(is_placeholder(vValue))

    def test_realistic_value_is_not_a_placeholder(self):
        self.assertFalse(is_placeholder(REAL_PASSWORD))


class RedactTest(unittest.TestCase):
    def test_short_value_is_fully_hidden(self):
        self.assertEqual("**…, 8 car.", redact("abcdefgh"))

    def test_long_value_shows_two_characters_and_length(self):
        self.assertEqual("gh…, 40 car.", redact("g" + "h" * 39))


class SensitiveNameTest(unittest.TestCase):
    def test_sensitive_names(self):
        for vPath in (
            ".env.local",
            "config/.env.prod.local",
            "secrets/.env.nas",
            "a/b/cle.key",
            "id_rsa",
            "coffre.kdbx",
            "simulation/tokens.env",
            "Server.KEY",
        ):
            with self.subTest(vPath):
                self.assertTrue(is_sensitive_name(vPath))

    def test_safe_names(self):
        for vPath in (
            ".env",
            ".env.test",
            ".env.example",
            "id_rsa.pub",
            "cle.key.example",
            "certificat.pem",
            "src/environment.py",
            ".env.local.dist",
        ):
            with self.subTest(vPath):
                self.assertFalse(is_sensitive_name(vPath))


class ContextTest(unittest.TestCase):
    def test_benign_keys(self):
        for vKey in (
            "PASSWORD_ALGORITHM",
            "CSRF_TOKEN_ID",
            "session_cookie",
            "TOKEN_HEADER",
        ):
            with self.subTest(vKey):
                self.assertTrue(is_benign_key(vKey))
        for vKey in ("DB_PASSWORD", "APP_SECRET", "api_key"):
            with self.subTest(vKey):
                self.assertFalse(is_benign_key(vKey))

    def test_test_paths(self):
        for vPath in (
            "tests/a.py",
            "src/tests/a.py",
            "test_a.py",
            "x/test_a.py",
            "a_test.go",
            "tests/fixtures/k.key",
            "simulation/x.env",
            "docs/a.md",
            ".env.dev",
        ):
            with self.subTest(vPath):
                self.assertTrue(is_test_path(vPath))
        for vPath in ("src/app.py", "config/prod.env", "contest.py"):
            with self.subTest(vPath):
                self.assertFalse(is_test_path(vPath))


class ScanTextTest(unittest.TestCase):
    def rules_found(self, pText):
        return [vFinding.rule for vFinding in scan_text("repo", "f.txt", pText)]

    def test_each_specific_rule(self):
        self.assertEqual(
            ["github-token"], self.rules_found(f"token_x = {GITHUB_TOKEN}")
        )
        self.assertEqual(["aws-access-key"], self.rules_found(f"key {AWS_KEY}"))
        self.assertEqual(["private-key"], self.rules_found(PRIVATE_KEY_LINE))
        self.assertEqual(
            ["slack-token"], self.rules_found("x " + "xox" + "b-1234567890-abcdefghij")
        )
        self.assertEqual(
            ["jwt"],
            self.rules_found(
                "Bearer "
                + "eyJ"
                + "hbGciOiJIUzI1NiJ9."
                + "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
                + "abcdefghijk"
            ),
        )

    def test_service_keys(self):
        for vRule, vValue in (
            ("gitlab-token", GITLAB_TOKEN),
            ("stripe-key", STRIPE_KEY),
            ("google-api-key", GOOGLE_KEY),
            ("anthropic-key", ANTHROPIC_KEY),
            ("openai-key", OPENAI_KEY),
            ("npm-token", NPM_TOKEN),
            ("telegram-bot-token", TELEGRAM_TOKEN),
        ):
            with self.subTest(vRule):
                self.assertEqual([vRule], self.rules_found(f"cle = {vValue}"))
                vDetail = scan_text("repo", "f", vValue)[0].detail
                self.assertNotIn(vValue, vDetail)

    def test_test_mode_keys_are_not_reported(self):
        self.assertEqual([], self.rules_found("sk" + "_test_" + "a1B2c3D4" * 3))

    def test_database_url_hides_password_and_skips_examples(self):
        vFindings = scan_text("repo", "compose.yml", f"DATABASE_URL={DATABASE_URL}")
        self.assertEqual(["database-url"], [vItem.rule for vItem in vFindings])
        self.assertNotIn(REAL_PASSWORD, vFindings[0].detail)
        self.assertEqual(
            [], self.rules_found("postgres" + "ql://app:${DB_PASSWORD}@db/app")
        )
        self.assertEqual([], self.rules_found("mysql" + "://root:changeme@localhost"))

    def test_generic_assignment_reports_line_and_hides_value(self):
        vFindings = scan_text(
            "repo", "app.env", "A=1\nDB_PASSWORD=" + REAL_PASSWORD + "\n"
        )
        self.assertEqual(1, len(vFindings))
        self.assertEqual(2, vFindings[0].line)
        self.assertEqual("medium", vFindings[0].severity)
        self.assertNotIn(REAL_PASSWORD, vFindings[0].detail)

    def test_generic_assignment_skips_placeholders(self):
        self.assertEqual([], self.rules_found("password = changeme_please"))
        self.assertEqual([], self.rules_found("SECRET=${APP_SECRET}"))

    def test_benign_key_and_prefixed_names(self):
        self.assertEqual([], self.rules_found("PASSWORD_ALGORITHM = argon2id-v19"))
        self.assertEqual(
            ["generic-assignment"], self.rules_found("DB_PASSWORD=" + REAL_PASSWORD)
        )
        self.assertEqual(
            ["generic-assignment"], self.rules_found("api-key: " + REAL_PASSWORD)
        )

    def test_private_key_detail_has_no_value(self):
        vFinding = scan_text("repo", "k", PRIVATE_KEY_LINE)[0]
        self.assertEqual("clé privée", vFinding.detail)

    def test_ignore_marker_skips_line(self):
        vText = f"token_x = {GITHUB_TOKEN}  # secrets-audit: ignore"
        self.assertEqual([], self.rules_found(vText))

    def test_one_finding_per_line(self):
        self.assertEqual(1, len(scan_text("repo", "f", f"{GITHUB_TOKEN} {AWS_KEY}")))


if __name__ == "__main__":
    unittest.main()
