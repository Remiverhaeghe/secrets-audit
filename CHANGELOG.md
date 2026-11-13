# Changelog

## Non publié

### Fonctionnalités
- Audit des dépôts git d'un dossier : fichiers sensibles suivis par git, présents sans être ignorés ou restés dans l'historique, et secrets en clair dans les fichiers suivis (clés privées, jetons GitHub, Slack, JWT, clés AWS, mots de passe affectés à une variable)
- Les valeurs trouvées ne sont jamais affichées en entier
- Trouvailles ambiguës ramenées à une gravité faible dans les tests, fixtures, simulations et documentation
- Rapport texte ou JSON, code de sortie utilisable en CI, options `--ignore`, `--min-severity` et `--no-history`

### Tests
- Suite `unittest` sans dépendance, avec de vrais dépôts git temporaires
