"""Allows `PYTHONPATH=src python3 -m starcouncil ...` out-of-the-box execution."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
