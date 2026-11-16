#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarCouncil Contributors
# SPDX-License-Identifier: MIT
"""Convenience entrypoint wrapper so `python3 scripts/starcouncil.py ...` works with zero pip install."""

from __future__ import annotations

import pathlib
import sys

SRC_DIR = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from starcouncil.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
