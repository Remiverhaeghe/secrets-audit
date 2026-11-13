"""Point d'entrée : python -m secrets_audit."""

import sys

from secrets_audit.cli import main

if __name__ == "__main__":
    sys.exit(main())
