# secrets-audit

Outil Python sans dépendance externe. Suivre les conventions de Rémi (skill `conventions-remi`). Toujours répondre en français.

- Il ne doit jamais afficher ni journaliser un secret en entier : passer par `rules.redact`.
- Les valeurs de secret dans les tests sont construites par morceaux (`tests/support.py`) pour que le dépôt puisse s'auditer lui-même en CI.
- Une nouvelle règle de secret se déclare dans `secrets_audit/rules.py` et reçoit un test dans `tests/test_rules.py`.
- Avant de valider : `python3 -m unittest discover -s tests`, puis `black .` et `pylint secrets_audit`.
