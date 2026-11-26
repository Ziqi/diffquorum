#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Zero-Token pending-plan collision lock (`plan open | list | close`) with atomic 0600 + flock persistence."""

from __future__ import annotations

import fcntl
import json
import os
import pathlib
import re
import stat
from typing import Any

from .blackboard import atomic_write_json, utc_iso

PLAN_SCOPE_RE = re.compile(r"^[a-z0-9][a-z0-9_./:-]{0,119}$")
VALID_PLAN_STATUSES = frozenset({"WAITING_APPROVE", "APPROVED", "SUPERSEDED", "CANCELLED"})


class _PlanFileLock:
    def __init__(self, lock_path: pathlib.Path) -> None:
        self.lock_path = lock_path
        self._fd: int | None = None

    def __enter__(self) -> "_PlanFileLock":
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        if self.lock_path.parent.is_symlink() or self.lock_path.is_symlink():
            raise ValueError(f"Refusing symlinked plan lock path: {self.lock_path}")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR | nofollow, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
        except Exception:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


def normalize_plan_scope(raw_scope: str) -> str:
    """Normalizes a plan scope slug into canonical lowercase `[a-z0-9_./:-]`."""
    norm = re.sub(r"\s+", "-", str(raw_scope or "").strip().lower())
    if not PLAN_SCOPE_RE.fullmatch(norm):
        raise ValueError(f"Invalid plan scope {raw_scope!r}: expected ^[a-z0-9][a-z0-9_./:-]{{0,119}}$")
    return norm


def _read_plans_doc_locked(plans_path: pathlib.Path) -> dict[str, Any]:
    if plans_path.is_symlink():
        raise ValueError(f"Symlinked pending_plans file rejected: {plans_path}")
    if not plans_path.exists():
        return {"schema_version": "1.0", "rev": 0, "plans": []}
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(plans_path), os.O_RDONLY | nofollow)
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Non-regular pending_plans file rejected: {plans_path}")
        raw = fh.read()
    if not raw.strip():
        return {"schema_version": "1.0", "rev": 0, "plans": []}
    doc = json.loads(raw.decode("utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("plans"), list):
        raise ValueError(f"Malformed pending_plans schema in {plans_path}")
    return doc


def _write_plans_doc_locked(plans_path: pathlib.Path, doc: dict[str, Any]) -> None:
    plans_path.parent.mkdir(parents=True, exist_ok=True)
    if plans_path.parent.is_symlink() or plans_path.is_symlink():
        raise ValueError(f"Refusing symlinked pending_plans path: {plans_path}")
    doc["rev"] = int(doc.get("rev") or 0) + 1
    doc["updated_at"] = utc_iso()
    atomic_write_json(plans_path, doc)
    os.chmod(plans_path, 0o600)


def _next_plan_id(plans: list[dict[str, Any]], day_tag: str) -> str:
    prefix = f"PLN-{day_tag}-"
    max_seq = 0
    for rec in plans:
        pid = str(rec.get("plan_id") or "")
        if pid.startswith(prefix):
            tail = pid[len(prefix) :]
            if tail.isdigit():
                max_seq = max(max_seq, int(tail))
    return f"{prefix}{max_seq + 1:03d}"


def _normalize_plans_path_nofollow(plans_path: str | pathlib.Path) -> pathlib.Path:
    """Normalizes `plans_path` to an absolute path WITHOUT dereferencing symlinks, rejecting symlinked leaves/parents."""
    p_file = pathlib.Path(os.path.abspath(os.path.expanduser(str(plans_path))))
    if p_file.is_symlink() or p_file.parent.is_symlink():
        raise ValueError(f"Symlinked pending_plans path rejected: {p_file}")
    return p_file


def open_pending_plan(
    plans_path: str | pathlib.Path,
    *,
    seat: str,
    scope: str,
    title: str,
    owner_seat: str = "lead",
) -> dict[str, Any]:
    """Opens a `WAITING_APPROVE` plan or reports `collision: True` if another seat holds `scope`."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    norm_scope = normalize_plan_scope(scope)
    clean_seat = str(seat or "").strip()
    clean_owner = str(owner_seat or "lead").strip() or "lead"
    clean_title = str(title or "").strip()
    if not clean_seat or not clean_title:
        raise ValueError("Both seat and title must be non-empty")

    lock_p = p_file.with_name(f".{p_file.name}.lock")
    with _PlanFileLock(lock_p):
        doc = _read_plans_doc_locked(p_file)
        plans = list(doc.get("plans") or [])
        conflicts = [
            rec
            for rec in plans
            if rec.get("status") == "WAITING_APPROVE"
            and rec.get("scope") == norm_scope
            and str(rec.get("seat") or "") != clean_seat
        ]
        if conflicts:
            return {
                "ok": False,
                "collision": True,
                "scope": norm_scope,
                "seat": clean_seat,
                "primary_approval_seat": clean_owner,
                "conflicts": conflicts,
            }

        ts = utc_iso()
        day_tag = ts[:10].replace("-", "")
        new_id = _next_plan_id(plans, day_tag)
        superseded_own: list[str] = []
        for rec in plans:
            if (
                rec.get("status") == "WAITING_APPROVE"
                and rec.get("scope") == norm_scope
                and str(rec.get("seat") or "") == clean_seat
            ):
                rec["status"] = "SUPERSEDED"
                rec["superseded_by"] = new_id
                rec["updated_at"] = ts
                superseded_own.append(str(rec.get("plan_id") or ""))

        new_rec = {
            "plan_id": new_id,
            "seat": clean_seat,
            "scope": norm_scope,
            "owner_seat": clean_owner,
            "title": clean_title,
            "created_at": ts,
            "updated_at": ts,
            "status": "WAITING_APPROVE",
        }
        plans.append(new_rec)
        doc["plans"] = plans
        _write_plans_doc_locked(p_file, doc)

    return {
        "ok": True,
        "collision": False,
        "storage_path": str(p_file),
        "plan": new_rec,
        "superseded_own_ids": superseded_own,
    }


def list_pending_plans(
    plans_path: str | pathlib.Path,
    *,
    scope: str = "",
    seat: str = "",
    status: str = "",
    include_all: bool = False,
) -> dict[str, Any]:
    """Lists `WAITING_APPROVE` plans (or all historical states when `include_all=True`)."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    filt_scope = normalize_plan_scope(scope) if scope.strip() else ""
    filt_seat = seat.strip()
    filt_status = status.strip().upper()
    if filt_status and filt_status not in VALID_PLAN_STATUSES:
        raise ValueError(f"Unsupported plan status filter: {filt_status}")

    lock_p = p_file.with_name(f".{p_file.name}.lock")
    with _PlanFileLock(lock_p):
        doc = _read_plans_doc_locked(p_file)

    filtered: list[dict[str, Any]] = []
    for rec in list(doc.get("plans") or []):
        st = str(rec.get("status") or "")
        if filt_status:
            if st != filt_status:
                continue
        elif not include_all and st != "WAITING_APPROVE":
            continue
        if filt_scope and rec.get("scope") != filt_scope:
            continue
        if filt_seat and str(rec.get("seat") or "") != filt_seat:
            continue
        filtered.append(rec)

    return {
        "ok": True,
        "storage_path": str(p_file),
        "count": len(filtered),
        "plans": filtered,
    }


def close_pending_plan(
    plans_path: str | pathlib.Path,
    *,
    seat: str,
    plan_id: str = "",
    scope: str = "",
    status: str = "APPROVED",
    note: str = "",
    governance_seats: tuple[str, ...] = ("lead",),
) -> dict[str, Any]:
    """Closes a pending plan (`APPROVED | SUPERSEDED | CANCELLED`) and auto-supersedes older scope drafts."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    actor = str(seat or "").strip()
    new_status = str(status or "").strip().upper()
    if new_status not in ("APPROVED", "SUPERSEDED", "CANCELLED"):
        raise ValueError(f"Invalid close status {status!r}; expected APPROVED, SUPERSEDED, or CANCELLED")
    tid = plan_id.strip()
    tscope = normalize_plan_scope(scope) if scope.strip() else ""
    if not tid and not tscope:
        raise ValueError("close_pending_plan requires plan_id or scope")

    lock_p = p_file.with_name(f".{p_file.name}.lock")
    with _PlanFileLock(lock_p):
        doc = _read_plans_doc_locked(p_file)
        plans = list(doc.get("plans") or [])
        matched = [
            rec
            for rec in plans
            if (tid and rec.get("plan_id") == tid)
            or (not tid and tscope and rec.get("scope") == tscope and rec.get("status") == "WAITING_APPROVE")
        ]
        if not matched:
            raise KeyError("No matching pending plan found")
        target = matched[-1]
        allowed = set(governance_seats) | {str(target.get("seat") or ""), str(target.get("owner_seat") or "")}
        if actor not in allowed:
            raise PermissionError(f"Seat {actor!r} is not authorized to close plan {target.get('plan_id')!r}")

        ts = utc_iso()
        target["status"] = new_status
        target["closed_by"] = actor
        target["updated_at"] = ts
        if note.strip():
            target["note"] = note.strip()

        superseded_ids: list[str] = []
        if new_status == "APPROVED":
            for rec in plans:
                if (
                    rec is not target
                    and rec.get("scope") == target.get("scope")
                    and rec.get("status") == "WAITING_APPROVE"
                ):
                    rec["status"] = "SUPERSEDED"
                    rec["superseded_by"] = str(target.get("plan_id") or "")
                    rec["updated_at"] = ts
                    superseded_ids.append(str(rec.get("plan_id") or ""))

        doc["plans"] = plans
        _write_plans_doc_locked(p_file, doc)

    return {
        "ok": True,
        "plan": target,
        "superseded_plan_ids": superseded_ids,
    }


def supersede_plans_for_scope(
    plans_path: str | pathlib.Path,
    scope: str,
    *,
    superseded_by: str,
) -> list[str]:
    """Marks all `WAITING_APPROVE` plans on `scope` as `SUPERSEDED` upon ticket completion."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    norm_scope = normalize_plan_scope(scope)
    lock_p = p_file.with_name(f".{p_file.name}.lock")
    superseded: list[str] = []
    with _PlanFileLock(lock_p):
        doc = _read_plans_doc_locked(p_file)
        plans = list(doc.get("plans") or [])
        ts = utc_iso()
        for rec in plans:
            if rec.get("status") == "WAITING_APPROVE" and rec.get("scope") == norm_scope:
                rec["status"] = "SUPERSEDED"
                rec["superseded_by"] = str(superseded_by)
                rec["updated_at"] = ts
                superseded.append(str(rec.get("plan_id") or ""))
        if superseded:
            doc["plans"] = plans
            _write_plans_doc_locked(p_file, doc)
    return superseded


PENDING_PLANS_MAX_READ_BYTES = 16384
STRICT_PLAN_ID_RE = re.compile(r"^PLN-\d{8}-\d{3,}$")
TITLE_TAG_PREFIX_RE = re.compile(r"^(?:\s*\[[^\]]{1,42}\]\s*)+")
UNSAFE_BANNER_CHARS_RE = re.compile(r"[\x00-\x1f\x7f<>\[\]`|]+")


def _read_plans_doc_readonly_bounded(path: pathlib.Path) -> dict[str, Any] | None:
    """Pure read-only `O_RDONLY | O_NOFOLLOW` (`<=16KB`) reader that never creates locks or mutates disk."""
    try:
        if path.is_symlink() or not path.exists():
            return None
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > PENDING_PLANS_MAX_READ_BYTES:
                return None
            raw = os.read(fd, PENDING_PLANS_MAX_READ_BYTES)
        finally:
            os.close(fd)
        doc = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None
    if not isinstance(doc, dict) or not isinstance(doc.get("plans"), list):
        return None
    return doc


def sanitize_plan_banner_title(raw_title: str, max_chars: int = 32) -> str:
    """Strips control chars, HTML/XML brackets, backticks, and pipes from plan titles before display."""
    cleaned = UNSAFE_BANNER_CHARS_RE.sub(" ", str(raw_title or ""))
    cleaned = " ".join(cleaned.split())
    stripped = TITLE_TAG_PREFIX_RE.sub("", cleaned).strip()
    return (stripped or cleaned)[:max_chars]


def load_reconciled_pending_plans_ro(
    primary_path: str | pathlib.Path,
    mirror_path: str | pathlib.Path | None = None,
) -> dict[str, Any] | None:
    """Reconciles primary and optional mirror `pending_plans.json` files by highest monotonic integer `rev`."""
    cands: list[pathlib.Path] = [pathlib.Path(primary_path).expanduser()]
    if mirror_path is not None:
        cands.append(pathlib.Path(mirror_path).expanduser())
    best_doc: dict[str, Any] | None = None
    best_rev = -1
    for fp in cands:
        doc = _read_plans_doc_readonly_bounded(fp)
        if doc is None:
            continue
        raw_rev = doc.get("rev")
        rev = int(raw_rev) if isinstance(raw_rev, int) and not isinstance(raw_rev, bool) else 0
        if best_doc is None or rev > best_rev:
            best_doc = doc
            best_rev = rev
    return best_doc


def format_pending_plans_bar(
    primary_path: str | pathlib.Path,
    *,
    mirror_path: str | pathlib.Path | None = None,
    width: int = 80,
    redacted_seats: set[str] | frozenset[str] | None = None,
) -> str:
    """
    Renders a single auto-collapsed HUD/directory pending-approval bar (`""` when `0` `WAITING_APPROVE` plans exist).
    Sensitive seats in `redacted_seats` render strictly as `<seat>(<N> pending)` without exposing plan titles or scopes.
    """
    doc = load_reconciled_pending_plans_ro(primary_path, mirror_path=mirror_path)
    if doc is None:
        return ""
    redacted = set(redacted_seats) if redacted_seats else set()
    total = 0
    red_counts: dict[str, int] = {}
    ordered: list[tuple[bool, str, str]] = []
    title_cap = 28 if width >= 76 else 14
    for rec in doc.get("plans") or []:
        if not isinstance(rec, dict) or str(rec.get("status") or "").strip().upper() != "WAITING_APPROVE":
            continue
        seat = str(rec.get("seat") or "").strip() or "seat"
        total += 1
        if seat in redacted:
            red_counts[seat] = red_counts.get(seat, 0) + 1
            ordered.append((True, seat, ""))
        else:
            t = sanitize_plan_banner_title(str(rec.get("title") or ""), max_chars=title_cap) or str(rec.get("plan_id") or "PLAN")
            ordered.append((False, seat, f"{seat}:{t}"))
    if total <= 0:
        return ""
    tokens: list[str] = []
    seen_red: set[str] = set()
    for is_red, seat, tok in ordered:
        if is_red:
            if seat not in seen_red:
                tokens.append(f"{seat}({red_counts[seat]} pending)")
                seen_red.add(seat)
        else:
            tokens.append(tok)
    line = f"[APR:{total}] " + " | ".join(tokens)
    limit = max(24, int(width))
    return line if len(line) <= limit else (line[: limit - 2] + "..")


def build_pre_invocation_pending_banner(
    seat: str,
    primary_path: str | pathlib.Path,
    *,
    mirror_path: str | pathlib.Path | None = None,
    redacted_seats: set[str] | frozenset[str] | None = None,
) -> str:
    """
    Zero-Token `PreInvocation` hook helper: returns `""` (0 bytes) when no `WAITING_APPROVE` plans exist;
    otherwise emits a 1-line summary explicitly splitting `own` vs `peers` counts so agents never claim
    "0 pending approvals" from stale single-seat memory while peer seats have open plans.
    """
    self_seat = str(seat or "").strip()
    doc = load_reconciled_pending_plans_ro(primary_path, mirror_path=mirror_path)
    if doc is None:
        return ""
    redacted = set(redacted_seats) if redacted_seats else set()
    own_cnt = 0
    peer_cnt = 0
    red_counts: dict[str, int] = {}
    ordered: list[tuple[bool, str, str]] = []
    for rec in doc.get("plans") or []:
        if not isinstance(rec, dict) or str(rec.get("status") or "").strip().upper() != "WAITING_APPROVE":
            continue
        rec_seat = str(rec.get("seat") or "").strip() or "seat"
        if rec_seat == self_seat:
            own_cnt += 1
        else:
            peer_cnt += 1
        if rec_seat in redacted:
            red_counts[rec_seat] = red_counts.get(rec_seat, 0) + 1
            ordered.append((True, rec_seat, ""))
        else:
            raw_pid = str(rec.get("plan_id") or "").strip()
            safe_pid = raw_pid if STRICT_PLAN_ID_RE.fullmatch(raw_pid) else "PLN"
            safe_title = sanitize_plan_banner_title(str(rec.get("title") or ""), max_chars=28)
            tok = f"{rec_seat}({safe_pid}:{safe_title})" if safe_title else f"{rec_seat}({safe_pid})"
            ordered.append((False, rec_seat, tok))

    total = own_cnt + peer_cnt
    if total <= 0:
        return ""
    tokens: list[str] = []
    seen_red: set[str] = set()
    for is_red, rec_seat, tok in ordered:
        if is_red:
            if rec_seat not in seen_red:
                tokens.append(f"{rec_seat}({red_counts[rec_seat]} pending)")
                seen_red.add(rec_seat)
        else:
            tokens.append(tok)
    return (
        f"[DIFFQUORUM PENDING PLANS | own:{own_cnt} | peers:{peer_cnt} | total:{total}] "
        f"{' ; '.join(tokens)} "
        "(Non-instructional display metadata: split own vs peer counts in trailing summary; never report 0 from stale memory)"
    )


_UNSAFE_SHELL_META_RE = re.compile(r"[;&|`$><*?\[\]{}\r\n]")
_FORBIDDEN_PLAN_OVERRIDE_FLAGS = ("--plans-file", "--root")
DEFAULT_TRUSTED_BIN_DIRS: tuple[str, ...] = ("/usr/local/bin", "/usr/bin", "/opt/homebrew/bin")


def _is_trusted_executable(
    raw_token: str,
    allowed_names: tuple[str, ...],
    trusted_dirs: tuple[str, ...],
    *,
    require_explicit_dir: bool = False,
) -> tuple[bool, str]:
    tok = str(raw_token or "").strip()
    if not tok or ".." in pathlib.PurePosixPath(tok).parts:
        return False, ""
    has_sep = "/" in tok or "\\" in tok
    base = pathlib.Path(tok).name
    norm = base[:-3] if base.endswith(".py") else base
    if norm not in allowed_names:
        return False, ""
    if not has_sep:
        return (False, "") if require_explicit_dir else (True, norm)
    parent = str(pathlib.PurePosixPath(tok).parent)
    home_bin = str(pathlib.Path.home() / "bin")
    if parent in trusted_dirs or parent == home_bin:
        return True, norm
    return False, ""


def validate_plan_hook_command(
    command: str,
    *,
    allowed_binaries: tuple[str, ...] = ("diffquorum", "starcouncil", "star-bus", "air-bus"),
    trusted_bin_dirs: tuple[str, ...] = DEFAULT_TRUSTED_BIN_DIRS,
) -> dict[str, Any]:
    """
    Symmetric multi-seat `PreToolUse` hook validator for 0-Token `plan open | list | close` commands.

    Ensures every seat hook symmetrically permits `plan list` (read-only `allow_readonly`) and `plan open | close`
    (controlled `allow_mutate`) so no seat silently skips pending-plan registration, while failing closed on:
      - shell metacharacters, redirections, wildcards, or malformed quoting;
      - untrusted binary paths (e.g. `/tmp/attacker/diffquorum` or `./star-bus`);
      - post-`shlex.split` `--plans-file` / `--root` target-override flags (including quoted forms like `'--root'`).
    """
    import shlex

    raw = str(command or "").strip()
    if not raw:
        return {"allowed": False, "mode": "deny", "reason": "empty_command"}
    if _UNSAFE_SHELL_META_RE.search(raw):
        return {"allowed": False, "mode": "deny", "reason": "unsafe_shell_metacharacters"}
    try:
        tokens = shlex.split(raw)
    except ValueError:
        return {"allowed": False, "mode": "deny", "reason": "malformed_shell_quoting"}
    if not tokens:
        return {"allowed": False, "mode": "deny", "reason": "empty_tokens"}

    idx = 0
    first_tok = tokens[0]
    first_base = pathlib.Path(first_tok).name
    if re.fullmatch(r"python3(?:\.\d+)?", first_base):
        ok_py, _ = _is_trusted_executable(first_tok, (first_base,), trusted_bin_dirs)
        if not ok_py:
            return {"allowed": False, "mode": "deny", "reason": f"untrusted_python_path:{first_tok}"}
        idx = 1
    if idx + 2 >= len(tokens):
        return {"allowed": False, "mode": "deny", "reason": "incomplete_plan_invocation"}

    ok_bin, bin_name = _is_trusted_executable(
        tokens[idx], allowed_binaries, trusted_bin_dirs, require_explicit_dir=(idx == 1)
    )
    if not ok_bin:
        return {"allowed": False, "mode": "deny", "reason": f"untrusted_or_unrecognized_binary:{tokens[idx]}"}

    if tokens[idx + 1] != "plan":
        return {"allowed": False, "mode": "deny", "reason": "not_plan_subcommand"}
    action = tokens[idx + 2]

    # Inspect every post-shlex token so quoted variants like `'--root'` or `"--plans-file=/tmp/x"` never bypass.
    for arg_tok in tokens[idx + 3 :]:
        if arg_tok in _FORBIDDEN_PLAN_OVERRIDE_FLAGS or any(
            arg_tok.startswith(f"{flag}=") for flag in _FORBIDDEN_PLAN_OVERRIDE_FLAGS
        ):
            return {"allowed": False, "mode": "deny", "reason": f"forbidden_target_override_flag:{arg_tok}"}

    if action == "list":
        return {"allowed": True, "mode": "allow_readonly", "action": action, "binary": bin_name}
    if action in ("open", "close"):
        return {"allowed": True, "mode": "allow_mutate", "action": action, "binary": bin_name}
    return {"allowed": False, "mode": "deny", "reason": f"unsupported_plan_action:{action}"}
