#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Backward-compatibility CLI shim forwarding `scripts/starcouncil.py` to `diffquorum.cli:main`."""

from __future__ import annotations

import pathlib
import sys

SCRIPT_DIR = str(pathlib.Path(__file__).resolve().parent)
SRC_DIR = str(pathlib.Path(__file__).resolve().parents[1] / "src")
sys.path[:] = [SRC_DIR] + [p for p in sys.path if p not in (SCRIPT_DIR, SRC_DIR)]

from diffquorum.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
