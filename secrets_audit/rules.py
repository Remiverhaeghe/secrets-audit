"""Règles de détection : motifs de secrets, noms de fichiers sensibles, valeurs d'exemple."""

import fnmatch
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

IGNORE_MARKER = "secrets-audit: ignore"


@dataclass(frozen=True)
class SecretRule:
    """Un motif de secret. group vaut None quand la valeur ne doit pas être affichée."""

    name: str
    description: str
    pattern: re.Pattern[str]
    severity: str
    group: int | None = 0
    check_placeholder: bool = False


SECRET_RULES = (
    SecretRule(
        "private-key",
        "clé privée",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY"),
        "high",
        group=None,
    ),
    SecretRule(
        "github-token",
        "jeton GitHub",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        "high",
    ),
    SecretRule(
        "aws-access-key",
        "clé d'accès AWS",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "high",
    ),
    SecretRule(
        "slack-token",
        "jeton Slack",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "high",
    ),
    SecretRule(
        "gitlab-token",
        "jeton GitLab",
        re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
        "high",
    ),
    SecretRule(
        "stripe-key",
        "clé secrète Stripe",
        re.compile(r"\b[sr]k_live_[A-Za-z0-9]{24,}\b"),
        "high",
    ),
    SecretRule(
        "google-api-key",
        "clé d'API Google",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        "high",
    ),
    # Avant la règle OpenAI : une clé Anthropic commence aussi par « sk- »
    SecretRule(
        "anthropic-key",
        "clé d'API Anthropic",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}"),
        "high",
    ),
    SecretRule(
        "openai-key",
        "clé d'API OpenAI",
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"),
        "high",
    ),
    SecretRule(
        "npm-token",
        "jeton npm",
        re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        "high",
    ),
    SecretRule(
        "telegram-bot-token",
        "jeton de bot Telegram",
        re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
        "high",
    ),
    # Seul le mot de passe est masqué et vérifié : « postgres://user:${PASS}@ » est un exemple
    SecretRule(
        "database-url",
        "mot de passe dans une adresse de base de données",
        re.compile(
            r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://"
            r"[^:\s/@]+:(?P<value>[^@\s/]{6,})@"
        ),
        "medium",
        group=1,
        check_placeholder=True,
    ),
    SecretRule(
        "jwt",
        "jeton JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
        "medium",
    ),
    SecretRule(
        "generic-assignment",
        "secret en clair",
        re.compile(
            r"(?i)(?P<key>[a-z0-9_]*(?:password|passwd|secret|api[_-]?key|token)[a-z0-9_]*)"
            r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'#]{8,})"
        ),
        "medium",
        group=2,
        check_placeholder=True,
    ),
)

# Règles qui ne viennent pas d'un motif : description pour les rapports (SARIF)
FILE_RULES = {
    "sensitive-file-tracked": "fichier sensible suivi par git",
    "sensitive-file-unignored": "fichier sensible absent du .gitignore",
    "sensitive-file-in-history": "fichier sensible encore présent dans l'historique git",
}

SENSITIVE_FILE_PATTERNS = (
    ".env.local",
    ".env.*.local",
    ".env.nas",
    ".env.prod",
    ".env.production",
    "*.key",
    "*.kdbx",
    "*.p12",
    "*.keystore",
    "id_rsa",
    "id_ed25519",
    "tokens.env",
)

SAFE_FILE_PATTERNS = ("*.example", "*.dist", "*.pub")

PLACEHOLDER_HINTS = (
    "change",
    "example",
    "exemple",
    "your",
    "xxx",
    "todo",
    "dummy",
    "placeholder",
    "fake",
    "null",
    "none",
)

CODE_CHARS = ("(", ")", "[", "$", "{", "<", "%")

# Un nom de variable qui finit ainsi décrit un réglage (algorithme, identifiant), pas un secret
BENIGN_KEY_SUFFIXES = (
    "algorithm",
    "_id",
    "_name",
    "_field",
    "_header",
    "_cookie",
    "_path",
    "_url",
    "_label",
    "_type",
    "_mode",
    "_length",
    "_ttl",
)

# Chemins de tests, fixtures, simulation ou docs : une trouvaille y est de faible gravité
TEST_PATH_PATTERNS = (
    "tests/*",
    "*/tests/*",
    "test_*",
    "*/test_*",
    "*_test.*",
    "*fixtures*",
    "simulation/*",
    "docs/*",
    ".env.dev",
    ".env.test",
)


def is_placeholder(pValue: str) -> bool:
    """Valeur d'exemple, expression de code ou identifiant : pas un vrai secret."""
    vLower = pValue.lower()
    vResult = (
        any(vChar in pValue for vChar in CODE_CHARS)
        or pValue.startswith(("?", ":"))
        or re.fullmatch(r"[A-Za-z_.\-\\/]+", pValue.rstrip(";,")) is not None
        or any(vHint in vLower for vHint in PLACEHOLDER_HINTS)
        or len(set(vLower)) <= 2
    )
    return vResult


def redact(pValue: str) -> str:
    """Masque une valeur : reste visible la longueur, et deux caractères si elle est longue."""
    vStart = pValue[:2] if len(pValue) >= 16 else "**"
    rText = f"{vStart}…, {len(pValue)} car."
    return rText


def is_sensitive_name(pPath: str) -> bool:
    """Le nom de fichier est celui d'un fichier qui ne doit pas être versionné."""
    vName = PurePosixPath(pPath).name.lower()
    vSafe = any(fnmatch.fnmatch(vName, vPattern) for vPattern in SAFE_FILE_PATTERNS)
    rSensitive = not vSafe and any(
        fnmatch.fnmatch(vName, vPattern) for vPattern in SENSITIVE_FILE_PATTERNS
    )
    return rSensitive


def is_benign_key(pKey: str) -> bool:
    """Le nom de la variable décrit un réglage (algorithme, identifiant...), pas un secret."""
    vLower = pKey.lower()
    rBenign = vLower.endswith(BENIGN_KEY_SUFFIXES)
    return rBenign


def is_test_path(pPath: str) -> bool:
    """Chemin de test, de fixture, de simulation ou de documentation."""
    rTest = any(fnmatch.fnmatch(pPath, vPattern) for vPattern in TEST_PATH_PATTERNS)
    return rTest
