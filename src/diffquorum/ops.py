#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Zero-Token operational primitives: read-only dual-table HUD, zero-delete ledger curator, secret-scrubbed probe & AST bundler."""

from __future__ import annotations

import ast
import datetime as dt
import fcntl
import hashlib
import json
import os
import pathlib
import re
import subprocess
import tempfile
import time
import unicodedata
from typing import Any

from .blackboard import atomic_write_json, atomic_write_text, read_json_nofollow, utc_iso
from .wake_gates import classify_seat_state

# --- ANSI 16-color palette (mobile-safe) ---
C_RST = "\x1b[0m"
C_BOLD = "\x1b[1m"
C_DIM = "\x1b[2m"
C_RED = "\x1b[31m"
C_GRN = "\x1b[32m"
C_YEL = "\x1b[33m"
C_CYN = "\x1b[36m"
C_MAG = "\x1b[35m"

# --- Routine secret-scrubbing patterns (PF-019) ---
SENSITIVE_ENV_RE = re.compile(
    r"(?:API_KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL|COOKIE|BEARER|PRIVATE_KEY|_KEY$)",
    re.IGNORECASE,
)
SAFE_ENV_ALLOW = frozenset({"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "SSH_AUTH_SOCK", "TMPDIR"})

# --- Curator patterns (PF-020) ---
PIN_BLOCK_RE = re.compile(r"<!--\s*PIN\s*-->.*?<!--\s*/PIN\s*-->", re.DOTALL)
TIMELINE_LINE_RE = re.compile(r"^[ \t]*<!--\s*timeline\s*-->[ \t]*$", re.IGNORECASE)
FENCE_OPEN_RE = re.compile(r"^[ \t]*(`{3,}|~{3,})")
ENTRY_SPLIT_RE = re.compile(r"(?m)^(?=## `?\[?20\d{2}-)")
TITLE_PREFIX_STRIP_RE = re.compile(r"^(?:\s*(?:【[^】]{1,42}】|\[[^\]]{1,42}\])\s*)+")


def _c(text: str, code: str, color: bool) -> str:
    return f"{code}{text}{C_RST}" if color else text


def _fmt_age(sec: float) -> str:
    s = max(0, int(sec))
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m"
    return f"{s // 3600}h{(s % 3600) // 60:02d}m"


def _disp_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1 for ch in text)


def _trunc(text: str, limit: int) -> str:
    clean = str(text or "").replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if _disp_width(clean) <= limit:
        return clean
    if limit <= 2:
        return clean[:limit]
    out: list[str] = []
    used = 0
    for ch in clean:
        cw = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if used + cw > (limit - 2):
            break
        out.append(ch)
        used += cw
    return "".join(out) + ".."


def _pad_disp(text: str, width: int) -> str:
    trimmed = _trunc(text, width)
    return trimmed + (" " * max(0, width - _disp_width(trimmed)))


def _compact_task_title(title: str) -> str:
    raw = " ".join(str(title or "").replace("\r", " ").replace("\n", " ").split())
    stripped = TITLE_PREFIX_STRIP_RE.sub("", raw).strip()
    return stripped or raw


def _render_seat_row(short: str, state: str, tkt: int | None, size: str, width: int, color: bool) -> str:
    tkt_str = "t:-" if tkt is None else f"t:{tkt}"
    mark = " <--!" if state in ("WAIT_APP", "WAIT+CPY") else ""
    row = _trunc(f" {_pad_disp(short, 12)} {state:<8} {tkt_str:<4} {size:<7}{mark}", width)
    if state in ("WAIT_APP", "WAIT+CPY"):
        return _c(row, C_BOLD + C_RED, color)
    if state == "WORK+CPY":
        return _c(row, C_BOLD + C_YEL, color)
    if state == "WORKING":
        return _c(row, C_GRN, color)
    if state == "DAEMON":
        return _c(row, C_CYN, color)
    if state in ("COPY-MOD", "OFFLINE"):
        return _c(row, C_YEL, color)
    return row


def render_dual_hud(snapshot: dict[str, Any], *, width: int = 50, color: bool = False) -> str:
    """Renders a strictly read-only, 50-col mobile-safe unified local+remote HUD (PF-022 & PF-025)."""
    w = max(48, min(int(width), 120))
    clock = str(snapshot.get("clock") or "00:00:00")
    wd_tag = str(snapshot.get("watcher_tag") or "WD:OK")
    lock_tag = str(snapshot.get("lock_tag") or "LOCK:FREE")

    lines: list[str] = [_c(_trunc(f"DQ-HUD [{clock}] {wd_tag} {lock_tag}", w), C_BOLD + C_CYN, color)]

    # Normalize local & remote seats while collecting merged WAIT APPROVE alerts
    waits: list[dict[str, Any]] = []
    local_rows: list[dict[str, Any]] = []
    for raw in list(snapshot.get("local_seats") or []):
        state = str(raw.get("state") or "").upper() or classify_seat_state(
            online=bool(raw.get("online", True)),
            is_daemon=bool(raw.get("is_daemon")),
            pane_busy=bool(raw.get("pane_busy")),
            awaiting_approve=bool(raw.get("awaiting_approve")),
            transcript_busy=bool(raw.get("transcript_busy")),
            copy_mode=bool(raw.get("copy_mode")),
        )
        row = {
            "short": str(raw.get("short") or raw.get("name") or "seat"),
            "state": state,
            "tkt": raw.get("tkt"),
            "size": str(raw.get("size") or "-"),
        }
        local_rows.append(row)
        if state in ("WAIT_APP", "WAIT+CPY"):
            waits.append({
                "host": "LOC",
                "seat": row["short"],
                "wait_sec": float(raw.get("wait_sec") or 0.0),
                "snippet": str(raw.get("snippet") or "Step 1 PLAN"),
                "copy_mode": state == "WAIT+CPY",
            })

    remote = dict(snapshot.get("remote") or {})
    remote_rows: list[dict[str, Any]] = []
    if remote.get("online") is True:
        for raw in list(remote.get("seats") or []):
            state = str(raw.get("state") or "").upper() or classify_seat_state(
                online=True,
                is_daemon=bool(raw.get("is_daemon")),
                pane_busy=bool(raw.get("pane_busy")),
                awaiting_approve=bool(raw.get("awaiting_approve")),
                transcript_busy=bool(raw.get("transcript_busy")),
                copy_mode=bool(raw.get("copy_mode")),
            )
            row = {
                "short": str(raw.get("short") or raw.get("name") or "node"),
                "state": state,
                "tkt": raw.get("tkt"),
                "size": str(raw.get("size") or "-"),
            }
            remote_rows.append(row)
            if state in ("WAIT_APP", "WAIT+CPY"):
                waits.append({
                    "host": "REM",
                    "seat": row["short"],
                    "wait_sec": float(raw.get("wait_sec") or 0.0),
                    "snippet": str(raw.get("snippet") or "Step 1 PLAN"),
                    "copy_mode": state == "WAIT+CPY",
                })

    if waits:
        lines.append(_c(f"[!] WAIT APPROVE ({len(waits)})", C_BOLD + C_RED, color))
        for item in waits:
            cpy = "[CPY] " if item["copy_mode"] else ""
            lines.append(_c(_trunc(f" {item['host']} {item['seat']} {_fmt_age(item['wait_sec'])} {cpy}{item['snippet']}", w), C_RED, color))

    col_hdr = _c(_trunc(" SEAT         STATE    TKT  SIZE", w), C_DIM, color)
    lines.append(_c("-" * w, C_DIM, color))
    local_hw = str(snapshot.get("local_hw") or "").strip()
    local_hdr = f"[LOCAL {len(local_rows)} SEATS]" + (f" {local_hw}" if local_hw else "")
    lines.append(_c(_trunc(local_hdr, w), C_BOLD + C_CYN, color))
    lines.append(col_hdr)
    for row in local_rows:
        lines.append(_render_seat_row(row["short"], row["state"], row["tkt"], row["size"], w, color))

    lines.append(_c("-" * w, C_DIM, color))
    if remote.get("online") is True:
        r_hdr = (
            f"[REMOTE {len(remote_rows)} SEATS] ON {int(remote.get('rtt_ms') or 0)}ms "
            f"{str(remote.get('health') or 'px/wd:OK')} ({_fmt_age(float(remote.get('cache_age_sec') or 0.0))})"
        )
        lines.append(_c(_trunc(r_hdr, w), C_BOLD + C_MAG, color))
        r_hw = str(remote.get("hw") or "").strip()
        if r_hw:
            lines.append(_c(_trunc(" " + r_hw, w), C_CYN, color))
        lines.append(col_hdr)
        for row in remote_rows:
            lines.append(_render_seat_row(row["short"], row["state"], row["tkt"], row["size"], w, color))
    elif remote.get("online") is False:
        fails = int(remote.get("consecutive_failures") or 1)
        err = str(remote.get("error") or "unreachable")
        lines.append(_c(_trunc(f"[REMOTE] OFFLINE fail={fails} ({err})", w), C_BOLD + C_RED, color))
    else:
        lines.append(_c(_trunc(f"[REMOTE] {str(remote.get('note') or 'pending probe')}", w), C_DIM, color))

    # Auto-collapsing active tasks summary (IN_PROGRESS first, then PENDING, max 4)
    raw_tasks = [t for t in list(snapshot.get("active_tasks") or []) if str(t.get("status") or "").upper() in ("IN_PROGRESS", "PENDING")]
    raw_tasks.sort(key=lambda t: (0 if str(t.get("status") or "").upper() == "IN_PROGRESS" else 1, -float(t.get("updated_ts") or 0.0)))
    if raw_tasks:
        shown = raw_tasks[:4]
        cnt = f"{len(shown)}/{len(raw_tasks)}" if len(raw_tasks) > len(shown) else str(len(shown))
        lines.append(_c("-" * w, C_DIM, color))
        lines.append(_c(_trunc(f"[ACTIVE TASKS] ({cnt})", w), C_BOLD + C_CYN, color))
        for tk in shown:
            tag = "RUN" if str(tk.get("status") or "").upper() == "IN_PROGRESS" else "PND"
            seat_c = str(tk.get("seat") or "--")[:4]
            num = str(tk.get("num") or "#000")
            title = _compact_task_title(str(tk.get("title") or ""))
            lines.append(_c(_trunc(f" {tag} {seat_c} {num} {title}", w), C_GRN if tag == "RUN" else C_YEL, color))

    lines.append(_c("-" * w, C_DIM, color))
    lines.append(_c(_trunc("keys: r refresh | s probe remote | q quit", w), C_DIM, color))
    return "\n".join(lines) + "\n"


def scrub_probe_env(base_env: dict[str, str] | None = None) -> dict[str, str]:
    """Strips all API keys, secrets, tokens & passwords so routine probes stay strictly 0-Token (PF-019)."""
    src = os.environ if base_env is None else base_env
    clean: dict[str, str] = {}
    for k, v in src.items():
        if k in SAFE_ENV_ALLOW:
            clean[k] = v
            continue
        if SENSITIVE_ENV_RE.search(k):
            continue
        if k.startswith(("LC_", "XDG_")):
            clean[k] = v
    clean.setdefault("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin")
    return clean


def _safe_probe_output_path(path: pathlib.Path) -> pathlib.Path:
    if path.is_symlink():
        raise ValueError(f"Refusing symlink probe output path: {path}")
    parent = path.parent
    if parent.is_symlink():
        if str(parent) == "/tmp" and parent.resolve() == pathlib.Path("/private/tmp"):
            parent = pathlib.Path("/private/tmp")
        else:
            raise ValueError(f"Refusing symlink probe parent directory: {parent}")
    target = parent / path.name
    if target.is_symlink():
        raise ValueError(f"Refusing symlink probe target: {target}")
    return target


def run_readonly_probe(
    argv: list[str],
    *,
    output_path: pathlib.Path,
    timeout_sec: float = 8.0,
    host_label: str = "remote",
    base_env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Executes a secret-scrubbed, stdin-closed, timeout-bounded probe and writes atomic 0600 JSON (PF-019)."""
    if not argv:
        raise ValueError("Probe command argv must be non-empty")
    target = _safe_probe_output_path(output_path)
    prev_fails = 0
    try:
        if target.exists():
            prev_doc = read_json_nofollow(target)
            prev_fails = max(0, int(prev_doc.get("consecutive_failures") or 0))
    except Exception:
        prev_fails = 0

    clean_env = scrub_probe_env(base_env)
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=clean_env,
            timeout=timeout_sec,
            check=False,
        )
        rtt_ms = int((time.monotonic() - t0) * 1000)
        if proc.returncode != 0 or not proc.stdout.strip():
            err = (proc.stderr or f"rc={proc.returncode}").strip().splitlines()[0][:120]
            payload: dict[str, Any] = {
                "schema": "diffquorum-routine/v1",
                "host": host_label,
                "checked_at": utc_iso(),
                "checked_epoch": time.time(),
                "online": False,
                "rtt_ms": rtt_ms,
                "consecutive_failures": prev_fails + 1,
                "error": err,
            }
        else:
            remote_data = json.loads(proc.stdout.strip().splitlines()[-1])
            if not isinstance(remote_data, dict):
                raise ValueError("Probe output must be a JSON object")
            payload = {
                "schema": "diffquorum-routine/v1",
                "host": str(remote_data.get("host") or host_label)[:48],
                "checked_at": utc_iso(),
                "checked_epoch": time.time(),
                "online": True,
                "rtt_ms": rtt_ms,
                "consecutive_failures": 0,
                "data": remote_data,
            }
    except subprocess.TimeoutExpired:
        payload = {
            "schema": "diffquorum-routine/v1",
            "host": host_label,
            "checked_at": utc_iso(),
            "checked_epoch": time.time(),
            "online": False,
            "rtt_ms": int(timeout_sec * 1000),
            "consecutive_failures": prev_fails + 1,
            "error": f"timeout>{timeout_sec:.1f}s",
        }
    except Exception as exc:
        payload = {
            "schema": "diffquorum-routine/v1",
            "host": host_label,
            "checked_at": utc_iso(),
            "checked_epoch": time.time(),
            "online": False,
            "rtt_ms": int((time.monotonic() - t0) * 1000),
            "consecutive_failures": prev_fails + 1,
            "error": str(exc)[:120],
        }

    atomic_write_json(target, payload)
    return payload


def _validate_ledger_path(raw: str | pathlib.Path) -> pathlib.Path:
    s = str(raw or "").strip()
    if not s or s in (".", "..", "/"):
        raise ValueError(f"Refusing empty or root ledger path: {raw!r}")
    p = pathlib.Path(s).expanduser()
    if p.is_symlink() or not p.is_file() or p.suffix.lower() != ".md":
        raise ValueError(f"Ledger target must be a regular non-symlink .md file: {p}")
    return p.resolve()


def _find_unfenced_timeline_split(text: str) -> tuple[str, str] | None:
    """Splits on the first standalone `<!-- timeline -->` sentinel outside Markdown code fences."""
    fence_char = ""
    fence_len = 0
    offset = 0
    for raw_ln in text.splitlines(keepends=True):
        m_f = FENCE_OPEN_RE.match(raw_ln)
        if m_f:
            tok = m_f.group(1)
            if not fence_char:
                fence_char, fence_len = tok[0], len(tok)
            elif tok[0] == fence_char and len(tok) >= fence_len and raw_ln.strip() == tok:
                fence_char, fence_len = "", 0
        elif not fence_char and TIMELINE_LINE_RE.match(raw_ln.rstrip("\r\n")):
            end_pos = offset + len(raw_ln)
            return text[:end_pos].rstrip("\r\n"), text[end_pos:].lstrip("\r\n")
        offset += len(raw_ln)
    return None


def _split_ledger_parts(text: str) -> tuple[str, str, list[str], bool]:
    tl_split = _find_unfenced_timeline_split(text)
    if tl_split is not None:
        compiled_head, tail_raw = tl_split
        m_first = ENTRY_SPLIT_RE.search(tail_raw)
        if not m_first:
            return compiled_head, "", [], True
        entries = [c.strip() for c in ENTRY_SPLIT_RE.split(tail_raw[m_first.start() :]) if c.strip()]
        return compiled_head, "", entries, True

    pin_m = PIN_BLOCK_RE.search(text)
    pin_block = pin_m.group(0).strip() if pin_m else ""
    body = PIN_BLOCK_RE.sub("", text, count=1) if pin_m else text
    chunks = ENTRY_SPLIT_RE.split(body)
    if len(chunks) <= 1:
        return body.strip(), pin_block, [], False
    return chunks[0].strip(), pin_block, [c.strip() for c in chunks[1:] if c.strip()], False


def curate_ledger(
    ledger_path: str | pathlib.Path,
    *,
    max_bytes: int = 15360,
    keep_entries: int = 5,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Zero-delete whole-file SHA-256 snapshot ledger folder preserving Compiled Truth (`<!-- timeline -->`) or PIN block & newest entries (PF-020)."""
    target = _validate_ledger_path(ledger_path)
    orig_bytes = target.read_bytes()
    orig_sha = hashlib.sha256(orig_bytes).hexdigest()
    orig_size = len(orig_bytes)

    if orig_size <= max_bytes:
        return {
            "ok": True,
            "action": "SKIP_UNDER_BUDGET",
            "orig_bytes": orig_size,
            "max_bytes": max_bytes,
            "orig_sha256": orig_sha,
        }

    text = orig_bytes.decode("utf-8", errors="replace")
    preamble, pin_block, entries, has_timeline_sentinel = _split_ledger_parts(text)
    if not entries:
        raise ValueError("No dated `## 20YY-...` entries found; refusing lossy rewrite")

    utc_stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    snap_name = f"snap-{utc_stamp}-{orig_sha[:12]}.snapshot.txt"
    snap_rel = f"archive/{snap_name}"

    kept = entries[: max(1, keep_entries)]
    while len(kept) > 1:
        cand = _render_curated_md(preamble, pin_block, kept, snap_rel, orig_sha, orig_size, len(entries))
        if len(cand.encode("utf-8")) <= max_bytes:
            break
        kept = kept[:-1]
    hot_md = _render_curated_md(preamble, pin_block, kept, snap_rel, orig_sha, orig_size, len(entries))
    hot_bytes = len(hot_md.encode("utf-8"))

    result: dict[str, Any] = {
        "ok": True,
        "action": "DRY_RUN" if dry_run else "CURATED",
        "mode": "compiled_truth_timeline" if has_timeline_sentinel else "pin_or_header",
        "orig_bytes": orig_size,
        "hot_bytes": hot_bytes,
        "orig_sha256": orig_sha,
        "kept_entries": len(kept),
        "total_entries": len(entries),
        "snapshot": snap_rel,
    }
    if dry_run:
        return result

    lock_key = hashlib.sha256(str(target).encode("utf-8")).hexdigest()[:12]
    lock_path = pathlib.Path(tempfile.gettempdir()) / f"dq_curate_{lock_key}.lock"
    with open(lock_path, "a+", encoding="utf-8") as lf:
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            archive_dir = target.parent / "archive"
            snap_path = archive_dir / snap_name
            atomic_write_text(snap_path, orig_bytes.decode("utf-8", errors="replace"), mode=0o600)
            verify_sha = hashlib.sha256(snap_path.read_bytes()).hexdigest()
            if verify_sha != orig_sha:
                raise RuntimeError(f"Snapshot SHA-256 verification failed: {verify_sha} != {orig_sha}")

            manifest_path = archive_dir / "MANIFEST.tsv"
            prev_manifest = manifest_path.read_text(encoding="utf-8") if manifest_path.is_file() else (
                "utc_ts\tsnapshot_file\torig_bytes\thot_bytes\torig_sha256\tkept_entries\ttotal_entries\n"
            )
            row = f"{utc_stamp}\t{snap_name}\t{orig_size}\t{hot_bytes}\t{orig_sha}\t{len(kept)}\t{len(entries)}\n"
            atomic_write_text(manifest_path, prev_manifest + row, mode=0o600)
            atomic_write_text(target, hot_md, mode=0o600)
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
    return result


def _render_curated_md(
    preamble: str,
    pin_block: str,
    kept_entries: list[str],
    snap_rel: str,
    orig_sha: str,
    orig_bytes: int,
    total_entries: int,
) -> str:
    parts: list[str] = []
    if preamble:
        parts.append(preamble)
    if pin_block:
        parts.append(pin_block)
    parts.append(
        f"> **Lossless Snapshot**: Whole pre-fold ledger ({orig_bytes:,} bytes, {total_entries} entries) "
        f"archived at `{snap_rel}` (SHA-256 `{orig_sha[:16]}...`, index: `archive/MANIFEST.tsv`)."
    )
    parts.extend(kept_entries)
    return "\n\n".join(parts).rstrip() + "\n"


def _resolve_local_module(
    repo_root: pathlib.Path,
    src_file: pathlib.Path,
    module_name: str,
    level: int,
) -> pathlib.Path | None:
    search_bases: list[pathlib.Path] = []
    if level > 0:
        base = src_file.parent
        for _ in range(level - 1):
            base = base.parent
        search_bases.append(base)
    else:
        search_bases.extend([repo_root, repo_root / "src"])

    rel_parts = [p for p in module_name.split(".") if p] if module_name else []
    repo_res = repo_root.resolve()
    for base in search_bases:
        cand_dir = base.joinpath(*rel_parts) if rel_parts else base
        for cand in (cand_dir.with_suffix(".py") if rel_parts else None, cand_dir / "__init__.py"):
            if cand is None or cand.is_symlink() or not cand.is_file():
                continue
            resolved = cand.resolve()
            try:
                resolved.relative_to(repo_res)
            except ValueError:
                continue
            return resolved
    return None


def collect_ast_imports(
    entry_files: list[str | pathlib.Path],
    *,
    repo_root: str | pathlib.Path,
    max_depth: int = 2,
    max_files: int = 32,
) -> dict[str, Any]:
    """Statically traces local Python AST imports inside repo_root for complete blind-review bundles (no code execution)."""
    root = pathlib.Path(repo_root).expanduser().resolve()
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"Invalid repo_root directory: {root}")
    if not entry_files:
        raise ValueError("At least one entry Python file is required")

    visited: dict[pathlib.Path, dict[str, Any]] = {}
    queue: list[tuple[pathlib.Path, int]] = []
    for raw_e in entry_files:
        ep = pathlib.Path(raw_e)
        cand = ep if ep.is_absolute() else (root / ep)
        if cand.is_symlink() or not cand.is_file():
            raise ValueError(f"Entry file missing or symlinked: {raw_e}")
        resolved = cand.resolve()
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"Entry file escapes repo_root: {raw_e}") from exc
        queue.append((resolved, 0))

    edges: list[dict[str, str]] = []
    while queue and len(visited) < max_files:
        cur_file, depth = queue.pop(0)
        if cur_file in visited:
            continue
        raw_bytes = cur_file.read_bytes()
        rel_cur = cur_file.relative_to(root).as_posix()
        visited[cur_file] = {
            "path": rel_cur,
            "bytes": len(raw_bytes),
            "sha256": hashlib.sha256(raw_bytes).hexdigest(),
            "depth": depth,
        }
        if depth >= max_depth:
            continue
        tree = ast.parse(raw_bytes.decode("utf-8", errors="replace"), filename=rel_cur)
        for node in ast.walk(tree):
            targets: list[tuple[str, int]] = []
            if isinstance(node, ast.Import):
                targets.extend((alias.name, 0) for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                base_mod = node.module or ""
                targets.append((base_mod, node.level))
                for alias in node.names:
                    if alias.name != "*":
                        sub = f"{base_mod}.{alias.name}" if base_mod else alias.name
                        targets.append((sub, node.level))
            for mod_name, lvl in targets:
                dep = _resolve_local_module(root, cur_file, mod_name, lvl)
                if dep is not None and dep != cur_file:
                    edges.append({"from": rel_cur, "to": dep.relative_to(root).as_posix()})
                    if dep not in visited and len(visited) + len(queue) < max_files * 2:
                        queue.append((dep, depth + 1))

    ordered_files = sorted(visited.values(), key=lambda x: (x["depth"], x["path"]))
    unique_edges = sorted({(e["from"], e["to"]) for e in edges})
    return {
        "ok": True,
        "repo_root": str(root),
        "file_count": len(ordered_files),
        "files": ordered_files,
        "edges": [{"from": a, "to": b} for a, b in unique_edges],
    }
