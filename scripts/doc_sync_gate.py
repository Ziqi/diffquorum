#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deterministic anti-doc-drift gate & git pre-push hook for DiffQuorum."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from diffquorum.governance import evaluate_doc_sync_gate  # noqa: E402

PF_ID_RE = re.compile(r"\bPF-\d{3}\b")


def _git_lines(repo_root: pathlib.Path, args: list[str]) -> tuple[int, list[str]]:
    res = subprocess.run(
        ["git", "-c", "core.quotepath=false", "-C", str(repo_root), *args],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
    )
    return res.returncode, [ln.rstrip("\r\n") for ln in (res.stdout or "").splitlines() if ln.strip()]


def _changed_files(repo_root: pathlib.Path, mode: str) -> tuple[list[str], str]:
    if mode == "pre-push":
        rc_u, up = _git_lines(repo_root, ["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
        if rc_u == 0 and up:
            rc_d, lines = _git_lines(repo_root, ["diff", "--name-only", f"{up[0]}..HEAD"])
            if rc_d == 0:
                return lines, f"{up[0]}..HEAD"
        rc_h, lines = _git_lines(repo_root, ["diff", "--name-only", "HEAD~1..HEAD"])
        return (lines, "HEAD~1..HEAD") if rc_h == 0 else ([], "clean")
    rc_s, porc = _git_lines(repo_root, ["status", "--porcelain"])
    if rc_s == 0 and porc:
        out: list[str] = []
        for ln in porc:
            if len(ln) >= 4:
                p = ln[3:].strip()
                out.append((p.split(" -> ", 1)[1] if " -> " in p else p).strip('"'))
        return out, "working-tree"
    rc_h, lines = _git_lines(repo_root, ["diff", "--name-only", "HEAD~1..HEAD"])
    return (lines, "HEAD~1..HEAD") if rc_h == 0 else ([], "clean")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="doc_sync_gate", description="DiffQuorum anti-doc-drift pre-push & doctor gate")
    ap.add_argument("--repo", default=str(REPO_ROOT))
    ap.add_argument("--mode", choices=("doctor", "pre-push"), default="doctor")
    ap.add_argument("--install-hook", action="store_true")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.repo).expanduser().resolve()

    if args.install_hook:
        hp = root / ".git" / "hooks" / "pre-push"
        hp.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            f'python3 "{pathlib.Path(__file__).resolve()}" --repo "{root}" --mode pre-push\n',
            encoding="utf-8",
        )
        os.chmod(hp, 0o755)
        print(json.dumps({"ok": True, "installed_hook": str(hp)}, indent=2))
        return 0

    changed, diff_range = _changed_files(root, args.mode)
    ledger_p = root / "docs" / "PITFALLS_AND_FIXES.md"
    ledger_txt = ledger_p.read_text(encoding="utf-8", errors="replace") if ledger_p.is_file() else ""
    rep = evaluate_doc_sync_gate(changed, pitfall_ledger_text=ledger_txt)
    rep["diff_range"] = diff_range
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return 0 if rep["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
