# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Module entrypoint for `python3 -m diffquorum`."""

from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
