# secrets-audit

Audit d'hygiène des secrets dans les dépôts git d'un dossier. Script Python sans dépendance externe : il repère ce qui ne devrait pas être versionné et ce qui ressemble à un secret, sans jamais afficher la valeur en entier.

## Ce qu'il vérifie

| Règle | Gravité | Ce qu'elle signale |
|---|---|---|
| `sensitive-file-tracked` | haute | fichier sensible suivi par git (`.env.local`, `.env.nas`, `*.key`, `*.kdbx`, `id_rsa`...) |
| `sensitive-file-unignored` | moyenne | fichier sensible présent mais absent du `.gitignore` |
| `sensitive-file-in-history` | haute | fichier sensible supprimé mais toujours dans l'historique |
| `private-key`, `github-token`, `aws-access-key`, `slack-token` | haute | secret reconnu dans un fichier suivi |
| `jwt`, `generic-assignment` | moyenne | jeton JWT, ou `password`, `secret`, `token`, `api_key` affecté à une valeur qui ressemble à un vrai secret |

Les valeurs d'exemple (`changeme`, `${VAR}`), les expressions de code, les noms d'identifiants et les réglages (`PASSWORD_ALGORITHM`) sont ignorés. Dans les chemins de test, de fixture, de simulation et de documentation, les trouvailles ambiguës passent en gravité faible ; un jeton ou une clé privée reste de gravité haute partout.

## Lancer

```bash
python -m secrets_audit D:\Projet_dev          # tous les dépôts jusqu'à 2 niveaux
python -m secrets_audit . --json               # rapport JSON
python -m secrets_audit . --ignore 'docs/*'    # ignorer des chemins (répétable)
python -m secrets_audit . --min-severity high  # n'échouer que pour les gravités hautes
python -m secrets_audit . --no-history         # plus rapide, sans l'historique
```

Code de sortie : 0 propre, 1 problèmes à la gravité demandée ou au-dessus (moyenne par défaut), 2 erreur (dossier introuvable, git absent).

Pour marquer une ligne comme volontaire, ajouter `secrets-audit: ignore` en commentaire sur la même ligne.

## Dans la CI d'un autre dépôt

Le dépôt fournit un workflow réutilisable. Dans le dépôt à surveiller, `.github/workflows/secrets.yml` :

```yaml
name: Secrets
on: [push, pull_request]
permissions:
  contents: read
jobs:
  audit:
    uses: Remiverhaeghe/secrets-audit/.github/workflows/audit.yml@main
    with:
      min-severity: medium      # facultatif
      ignore: "docs/* tests/*"  # facultatif, motifs séparés par des espaces
```

`version` choisit la branche ou le tag de l'outil (`main` par défaut). La CI de ce dépôt appelle le même workflow sur lui-même.

## Tests et qualité

```bash
python3 -m unittest discover -s tests -v
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/black --check . && .venv/bin/pylint secrets_audit && .venv/bin/bandit -r secrets_audit
.venv/bin/coverage run -m unittest discover -s tests && .venv/bin/coverage report
```

La CI exécute la même chose, puis audite le dépôt lui-même.

## Limites

- Il analyse les fichiers suivis par git, pas le contenu des anciens commits : l'historique n'est contrôlé que par les noms de fichiers sensibles.
- La détection de mots de passe est heuristique : elle peut manquer un secret court ou signaler un exemple. Un outil dédié (Gitleaks) reste utile en complément.

## Licence

MIT, voir `LICENSE`.
