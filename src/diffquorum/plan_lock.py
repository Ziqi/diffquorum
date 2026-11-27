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
STRICT_PLAN_ID_RE = re.compile(r"^PLN-\d{8}-\d{3,}$")
VALID_PLAN_STATUSES = frozenset({"WAITING_APPROVE", "APPROVED", "SUPERSEDED", "CANCELLED"})
VALID_PLAN_KINDS: tuple[str, ...] = ("PLAN", "DECISION", "CIRCUIT_BREAKER", "INPUT_REQUIRED")
VALID_REPORT_SCOPES: tuple[str, ...] = ("fleet", "line", "self")
PLAN_KIND_SHORT_TAGS: dict[str, str] = {
    "PLAN": "PLAN",
    "DECISION": "DEC",
    "CIRCUIT_BREAKER": "CB",
    "INPUT_REQUIRED": "INP",
}
PLAN_MAX_CLOSED_RETAIN = 200


def normalize_plan_kind(raw_kind: str | None) -> str:
    val = str(raw_kind or "PLAN").strip().upper()
    if not val:
        return "PLAN"
    if val not in VALID_PLAN_KINDS:
        raise ValueError(f"Unsupported plan kind {raw_kind!r}; expected one of {VALID_PLAN_KINDS}")
    return val


def normalize_report_scope(raw_scope: str | None, *, default: str = "fleet") -> str:
    """Validates pending-plan reporting scope (`fleet` | `line` | `self`), failing closed on unknown values."""
    if raw_scope is None:
        return default
    val = str(raw_scope).strip().lower()
    if not val:
        return default
    if val not in VALID_REPORT_SCOPES:
        raise ValueError(f"Unsupported report_scope {raw_scope!r}; expected one of {VALID_REPORT_SCOPES}")
    return val


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
    raw_plans = list(doc.get("plans") or [])
    waiting = [r for r in raw_plans if isinstance(r, dict) and str(r.get("status") or "").upper() == "WAITING_APPROVE"]
    closed = [r for r in raw_plans if isinstance(r, dict) and str(r.get("status") or "").upper() != "WAITING_APPROVE"]
    if len(closed) > PLAN_MAX_CLOSED_RETAIN:
        kept = {id(r) for r in waiting} | {id(r) for r in closed[-PLAN_MAX_CLOSED_RETAIN:]}
        doc["plans"] = [r for r in raw_plans if id(r) in kept]
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


def _allocate_coexisting_scope(base_scope: str, active_scopes: set[str]) -> str:
    """Allocates a coexisting scope (`<scope>-2`, `<scope>-3`, ...) bounded to 120 chars when `base_scope` is active."""
    if base_scope not in active_scopes:
        return base_scope
    idx = 2
    while True:
        suffix = f"-{idx}"
        prefix = base_scope[: max(1, 120 - len(suffix))].rstrip("-_./:") or base_scope[:1]
        cand = f"{prefix}{suffix}"
        if cand not in active_scopes and PLAN_SCOPE_RE.fullmatch(cand):
            return cand
        idx += 1


def render_live_pending_footer_markdown(
    seat: str,
    doc: dict[str, Any] | None,
    *,
    redacted_seats: set[str] | frozenset[str] | None = None,
    allow_self_view: bool = True,
    report_scope: str = "fleet",
    line_seats: set[str] | frozenset[str] | tuple[str, ...] | list[str] | None = None,
    line_label: str = "",
) -> str:
    """Renders an exact ready-to-paste role-scoped Markdown pending-approval footer directly from live `doc`."""
    if not isinstance(doc, dict):
        return ""
    eff_scope = normalize_report_scope(report_scope, default="fleet")
    self_seat = str(seat or "").strip()
    eff_line_seats = (
        {str(s).strip() for s in line_seats if str(s).strip()} | {self_seat}
        if line_seats is not None
        else {self_seat}
    )
    redacted = set(redacted_seats) if redacted_seats else set()

    own_cnt = 0
    peer_cnt = 0
    line_peer_cnt = 0
    red_counts: dict[str, int] = {}
    red_line_counts: dict[str, int] = {}
    ordered: list[tuple[bool, bool, bool, str, str]] = []
    for rec in doc.get("plans") or []:
        if not isinstance(rec, dict) or str(rec.get("status") or "").strip().upper() != "WAITING_APPROVE":
            continue
        rec_seat = str(rec.get("seat") or "").strip() or "seat"
        is_own = rec_seat == self_seat
        in_line = is_own or (rec_seat in eff_line_seats)
        if is_own:
            own_cnt += 1
        else:
            peer_cnt += 1
            if in_line:
                line_peer_cnt += 1
        if rec_seat in redacted and not (allow_self_view and is_own):
            red_counts[rec_seat] = red_counts.get(rec_seat, 0) + 1
            if in_line:
                red_line_counts[rec_seat] = red_line_counts.get(rec_seat, 0) + 1
            ordered.append((True, is_own, in_line, rec_seat, ""))
        else:
            raw_pid = str(rec.get("plan_id") or "").strip()
            safe_pid = raw_pid if STRICT_PLAN_ID_RE.fullmatch(raw_pid) else "PLN"
            safe_title = sanitize_plan_banner_title(str(rec.get("title") or ""), max_chars=28)
            raw_kind = str(rec.get("kind") or "PLAN").strip().upper()
            ktag = PLAN_KIND_SHORT_TAGS.get(raw_kind, "PLAN")
            badge = f"[{ktag}]" if ktag != "PLAN" else ""
            tok = f"{rec_seat}{badge}({safe_pid}:{safe_title})" if safe_title else f"{rec_seat}{badge}({safe_pid})"
            ordered.append((False, is_own, in_line, rec_seat, tok))

    tokens: list[str] = []
    own_tokens: list[str] = []
    line_tokens: list[str] = []
    seen_red: set[str] = set()
    seen_red_own: set[str] = set()
    seen_red_line: set[str] = set()
    for is_red, is_own, in_line, rec_seat, tok in ordered:
        if is_red:
            if rec_seat not in seen_red:
                tokens.append(f"{rec_seat}({red_counts[rec_seat]} pending)")
                seen_red.add(rec_seat)
            if is_own and rec_seat not in seen_red_own:
                own_tokens.append(f"{rec_seat}({own_cnt} pending)")
                seen_red_own.add(rec_seat)
            if in_line and rec_seat not in seen_red_line:
                line_tokens.append(f"{rec_seat}({red_line_counts[rec_seat]} pending)")
                seen_red_line.add(rec_seat)
        else:
            tokens.append(tok)
            if is_own:
                own_tokens.append(tok)
            if in_line:
                line_tokens.append(tok)

    if eff_scope == "fleet":
        if own_cnt + peer_cnt <= 0:
            return ""
        return f"**Pending approvals (own: {own_cnt} | peers: {peer_cnt}): {' ; '.join(tokens)}**"
    if eff_scope == "line":
        line_total = own_cnt + line_peer_cnt
        if line_total <= 0:
            return ""
        outside_cnt = max(0, peer_cnt - line_peer_cnt)
        out_note = f"; outside: {outside_cnt}" if outside_cnt > 0 else ""
        lbl = sanitize_plan_banner_title(line_label, max_chars=20) or "LINE"
        return (
            f"**Line Pending approvals [{lbl}] (own: {own_cnt} | line_peers: {line_peer_cnt} | total: {line_total}{out_note}): "
            f"{' ; '.join(line_tokens)}**"
        )
    if own_cnt <= 0:
        return ""
    return f"**Own Pending approvals ({own_cnt}): {' ; '.join(own_tokens)}**"


def open_pending_plan(
    plans_path: str | pathlib.Path,
    *,
    seat: str,
    scope: str,
    title: str,
    owner_seat: str = "lead",
    kind: str = "PLAN",
    supersede_ids: list[str] | tuple[str, ...] | None = None,
    governance_seats: tuple[str, ...] = ("lead",),
    report_scope: str = "fleet",
    redacted_seats: set[str] | frozenset[str] | None = None,
    line_seats: set[str] | frozenset[str] | tuple[str, ...] | list[str] | None = None,
    line_label: str = "",
) -> dict[str, Any]:
    """Opens a `WAITING_APPROVE` plan/decision/circuit-breaker with same-seat coexistence & explicit `--supersede`."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    norm_scope = normalize_plan_scope(scope)
    norm_kind = normalize_plan_kind(kind)
    eff_report_scope = normalize_report_scope(report_scope, default="fleet")
    clean_seat = str(seat or "").strip()
    clean_owner = str(owner_seat or "lead").strip() or "lead"
    clean_title = str(title or "").strip()
    if not clean_seat or not clean_title:
        raise ValueError("Both seat and title must be non-empty")

    supersede_req: list[str] = []
    for raw_id in (supersede_ids or ()):
        pid_s = str(raw_id or "").strip()
        if not pid_s:
            continue
        if not STRICT_PLAN_ID_RE.fullmatch(pid_s):
            raise ValueError(f"Invalid supersede plan_id: {pid_s!r}")
        if pid_s not in supersede_req:
            supersede_req.append(pid_s)

    lock_p = p_file.with_name(f".{p_file.name}.lock")
    with _PlanFileLock(lock_p):
        doc = _read_plans_doc_locked(p_file)
        plans = list(doc.get("plans") or [])

        supersede_targets: list[dict[str, Any]] = []
        for spid in supersede_req:
            found = [r for r in plans if isinstance(r, dict) and str(r.get("plan_id") or "") == spid]
            if not found:
                raise KeyError(f"Supersede target not found: {spid}")
            trec = found[-1]
            if str(trec.get("status") or "").upper() != "WAITING_APPROVE":
                raise ValueError(f"Supersede target is not WAITING_APPROVE: {spid}")
            allowed = set(governance_seats) | {str(trec.get("seat") or ""), str(trec.get("owner_seat") or "")}
            if clean_seat not in allowed:
                raise PermissionError(f"Seat {clean_seat!r} is not authorized to supersede plan {spid!r}")
            supersede_targets.append(trec)
        supersede_id_set = {str(r.get("plan_id") or "") for r in supersede_targets}

        conflicts = [
            rec
            for rec in plans
            if rec.get("status") == "WAITING_APPROVE"
            and str(rec.get("plan_id") or "") not in supersede_id_set
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
                "live_footer_markdown": render_live_pending_footer_markdown(
                    clean_seat,
                    doc,
                    redacted_seats=redacted_seats,
                    report_scope=eff_report_scope,
                    line_seats=line_seats,
                    line_label=line_label,
                ),
            }

        ts = utc_iso()
        day_tag = ts[:10].replace("-", "")
        new_id = _next_plan_id(plans, day_tag)
        superseded_own: list[str] = []
        for trec in supersede_targets:
            trec["status"] = "SUPERSEDED"
            trec["superseded_by"] = new_id
            trec["updated_at"] = ts
            superseded_own.append(str(trec.get("plan_id") or ""))

        active_scopes = {
            str(rec.get("scope") or "")
            for rec in plans
            if isinstance(rec, dict) and str(rec.get("status") or "").upper() == "WAITING_APPROVE"
        }
        effective_scope = _allocate_coexisting_scope(norm_scope, active_scopes)

        new_rec = {
            "plan_id": new_id,
            "seat": clean_seat,
            "scope": effective_scope,
            "owner_seat": clean_owner,
            "kind": norm_kind,
            "title": clean_title,
            "created_at": ts,
            "updated_at": ts,
            "status": "WAITING_APPROVE",
        }
        plans.append(new_rec)
        doc["plans"] = plans
        _write_plans_doc_locked(p_file, doc)
        live_footer = render_live_pending_footer_markdown(
            clean_seat,
            doc,
            redacted_seats=redacted_seats,
            report_scope=eff_report_scope,
            line_seats=line_seats,
            line_label=line_label,
        )

    return {
        "ok": True,
        "collision": False,
        "storage_path": str(p_file),
        "plan": new_rec,
        "superseded_own_ids": superseded_own,
        "live_footer_markdown": live_footer,
    }


def list_pending_plans(
    plans_path: str | pathlib.Path,
    *,
    scope: str = "",
    seat: str = "",
    status: str = "",
    kind: str = "",
    include_all: bool = False,
    report_scope: str = "fleet",
    redacted_seats: set[str] | frozenset[str] | None = None,
    line_seats: set[str] | frozenset[str] | tuple[str, ...] | list[str] | None = None,
    line_label: str = "",
) -> dict[str, Any]:
    """Lists `WAITING_APPROVE` items (or all historical states when `include_all=True`) plus `live_footer_markdown`."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    filt_scope = normalize_plan_scope(scope) if scope.strip() else ""
    filt_seat = seat.strip()
    filt_status = status.strip().upper()
    filt_kind = normalize_plan_kind(kind) if kind.strip() else ""
    eff_report_scope = normalize_report_scope(report_scope, default="fleet")
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
        rec_kind = str(rec.get("kind") or "PLAN").strip().upper() or "PLAN"
        if filt_kind and rec_kind != filt_kind:
            continue
        filtered.append(rec)

    return {
        "ok": True,
        "storage_path": str(p_file),
        "count": len(filtered),
        "plans": filtered,
        "live_footer_markdown": render_live_pending_footer_markdown(
            filt_seat or "lead",
            doc,
            redacted_seats=redacted_seats,
            report_scope=eff_report_scope,
            line_seats=line_seats,
            line_label=line_label,
        ),
    }


def reopen_pending_plan(
    plans_path: str | pathlib.Path,
    *,
    seat: str,
    plan_id: str = "",
    scope: str = "",
    kind: str = "",
    title: str = "",
    note: str = "",
    governance_seats: tuple[str, ...] = ("lead",),
    report_scope: str = "fleet",
    redacted_seats: set[str] | frozenset[str] | None = None,
    line_seats: set[str] | frozenset[str] | tuple[str, ...] | list[str] | None = None,
    line_label: str = "",
) -> dict[str, Any]:
    """Reopens a closed (`APPROVED | SUPERSEDED | CANCELLED`) item back to `WAITING_APPROVE` in place (zero gap)."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    actor = str(seat or "").strip()
    tid = plan_id.strip()
    tscope = normalize_plan_scope(scope) if scope.strip() else ""
    new_kind = normalize_plan_kind(kind) if kind.strip() else ""
    eff_report_scope = normalize_report_scope(report_scope, default="fleet")
    if not tid and not tscope:
        raise ValueError("reopen_pending_plan requires plan_id or scope")

    lock_p = p_file.with_name(f".{p_file.name}.lock")
    with _PlanFileLock(lock_p):
        doc = _read_plans_doc_locked(p_file)
        plans = list(doc.get("plans") or [])
        matched = [
            rec
            for rec in plans
            if (tid and rec.get("plan_id") == tid) or (not tid and tscope and rec.get("scope") == tscope)
        ]
        if not matched:
            raise KeyError("No matching plan found to reopen")
        target = matched[-1]
        p_seat = str(target.get("seat") or "")
        allowed = set(governance_seats) | {p_seat, str(target.get("owner_seat") or "")}
        if actor not in allowed:
            raise PermissionError(f"Seat {actor!r} is not authorized to reopen plan {target.get('plan_id')!r}")

        rec_scope = str(target.get("scope") or "")
        conflicts = [
            rec
            for rec in plans
            if rec is not target
            and rec.get("status") == "WAITING_APPROVE"
            and rec.get("scope") == rec_scope
            and str(rec.get("seat") or "") != p_seat
        ]
        if conflicts:
            return {
                "ok": False,
                "collision": True,
                "scope": rec_scope,
                "seat": p_seat,
                "conflicts": conflicts,
                "live_footer_markdown": render_live_pending_footer_markdown(
                    actor,
                    doc,
                    redacted_seats=redacted_seats,
                    report_scope=eff_report_scope,
                    line_seats=line_seats,
                    line_label=line_label,
                ),
            }

        ts = utc_iso()
        prev_status = str(target.get("status") or "")
        other_active_scopes = {
            str(rec.get("scope") or "")
            for rec in plans
            if rec is not target and str(rec.get("status") or "").upper() == "WAITING_APPROVE"
        }
        if rec_scope in other_active_scopes:
            target["scope"] = _allocate_coexisting_scope(rec_scope, other_active_scopes)

        target["status"] = "WAITING_APPROVE"
        target["kind"] = new_kind or str(target.get("kind") or "PLAN").strip().upper() or "PLAN"
        if title.strip():
            target["title"] = title.strip()
        if note.strip():
            target["note"] = note.strip()
        target["reopened_from_status"] = prev_status
        target["reopened_by"] = actor
        target["reopened_at"] = ts
        target["reopen_count"] = int(target.get("reopen_count") or 0) + 1
        target["updated_at"] = ts
        doc["plans"] = plans
        _write_plans_doc_locked(p_file, doc)
        live_footer = render_live_pending_footer_markdown(
            actor,
            doc,
            redacted_seats=redacted_seats,
            report_scope=eff_report_scope,
            line_seats=line_seats,
            line_label=line_label,
        )

    return {
        "ok": True,
        "collision": False,
        "plan": target,
        "superseded_own_ids": [],
        "live_footer_markdown": live_footer,
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
    report_scope: str = "fleet",
    redacted_seats: set[str] | frozenset[str] | None = None,
    line_seats: set[str] | frozenset[str] | tuple[str, ...] | list[str] | None = None,
    line_label: str = "",
) -> dict[str, Any]:
    """Closes a pending plan (`APPROVED | SUPERSEDED | CANCELLED`) and auto-supersedes older scope drafts."""
    p_file = _normalize_plans_path_nofollow(plans_path)
    actor = str(seat or "").strip()
    new_status = str(status or "").strip().upper()
    eff_report_scope = normalize_report_scope(report_scope, default="fleet")
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
        live_footer = render_live_pending_footer_markdown(
            actor,
            doc,
            redacted_seats=redacted_seats,
            report_scope=eff_report_scope,
            line_seats=line_seats,
            line_label=line_label,
        )

    return {
        "ok": True,
        "plan": target,
        "superseded_plan_ids": superseded_ids,
        "live_footer_markdown": live_footer,
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


PENDING_PLANS_MAX_READ_BYTES = 524288  # 512 KiB (prevents silent drop on active multi-seat fleets)
TITLE_TAG_PREFIX_RE = re.compile(r"^(?:\s*\[[^\]]{1,42}\]\s*)+")
UNSAFE_BANNER_CHARS_RE = re.compile(r"[\x00-\x1f\x7f<>\[\]`|]+")


def _read_plans_doc_readonly_bounded(path: pathlib.Path) -> dict[str, Any] | None:
    """Pure read-only `O_RDONLY | O_NOFOLLOW` (`<=512KB`) reader that never creates locks or mutates disk."""
    try:
        if path.is_symlink() or not path.exists():
            return None
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size <= 0 or st.st_size > PENDING_PLANS_MAX_READ_BYTES:
                return None
            chunks: list[bytes] = []
            total = 0
            while total <= PENDING_PLANS_MAX_READ_BYTES:
                part = os.read(fd, min(65536, PENDING_PLANS_MAX_READ_BYTES + 1 - total))
                if not part:
                    break
                chunks.append(part)
                total += len(part)
        finally:
            os.close(fd)
        raw = b"".join(chunks)
        if len(raw) > PENDING_PLANS_MAX_READ_BYTES:
            return None
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
            raw_kind = str(rec.get("kind") or "PLAN").strip().upper()
            ktag = PLAN_KIND_SHORT_TAGS.get(raw_kind, "PLAN")
            badge = f"[{ktag}]" if ktag != "PLAN" else ""
            t = sanitize_plan_banner_title(str(rec.get("title") or ""), max_chars=title_cap) or str(rec.get("plan_id") or "PLAN")
            ordered.append((False, seat, f"{seat}{badge}:{t}"))
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
    allow_self_view: bool = True,
    report_scope: str = "fleet",
    line_seats: set[str] | frozenset[str] | tuple[str, ...] | list[str] | None = None,
    line_label: str = "",
) -> str:
    """
    Zero-Token `PreInvocation` hook helper with role-scoped visibility (`fleet` | `line` | `self`):
      - `fleet` (global hub, default for backward compatibility): splits `own` vs `peers` counts across all seats;
      - `line` (domain hub): shows only `line_seats` items (appending `outside:N` count only when line_total > 0)
        and returns `""` (0 bytes) whenever the line itself has 0 pending items;
      - `self` (execution workers): shows ONLY `seat`'s own pending items and returns `""` (0 bytes) when `own == 0`,
        eliminating stale cross-window peer snapshots while preserving sensitive-seat self-view & peer redaction.
    """
    eff_scope = normalize_report_scope(report_scope, default="fleet")
    self_seat = str(seat or "").strip()
    eff_line_seats = (
        {str(s).strip() for s in line_seats if str(s).strip()} | {self_seat}
        if line_seats is not None
        else {self_seat}
    )
    doc = load_reconciled_pending_plans_ro(primary_path, mirror_path=mirror_path)
    if doc is None:
        return ""
    redacted = set(redacted_seats) if redacted_seats else set()
    own_cnt = 0
    peer_cnt = 0
    line_peer_cnt = 0
    red_counts: dict[str, int] = {}
    red_line_counts: dict[str, int] = {}
    ordered: list[tuple[bool, bool, bool, str, str]] = []
    for rec in doc.get("plans") or []:
        if not isinstance(rec, dict) or str(rec.get("status") or "").strip().upper() != "WAITING_APPROVE":
            continue
        rec_seat = str(rec.get("seat") or "").strip() or "seat"
        is_own = rec_seat == self_seat
        in_line = is_own or (rec_seat in eff_line_seats)
        if is_own:
            own_cnt += 1
        else:
            peer_cnt += 1
            if in_line:
                line_peer_cnt += 1
        if rec_seat in redacted and not (allow_self_view and is_own):
            red_counts[rec_seat] = red_counts.get(rec_seat, 0) + 1
            if in_line:
                red_line_counts[rec_seat] = red_line_counts.get(rec_seat, 0) + 1
            ordered.append((True, is_own, in_line, rec_seat, ""))
        else:
            raw_pid = str(rec.get("plan_id") or "").strip()
            safe_pid = raw_pid if STRICT_PLAN_ID_RE.fullmatch(raw_pid) else "PLN"
            safe_title = sanitize_plan_banner_title(str(rec.get("title") or ""), max_chars=28)
            raw_kind = str(rec.get("kind") or "PLAN").strip().upper()
            ktag = PLAN_KIND_SHORT_TAGS.get(raw_kind, "PLAN")
            badge = f"[{ktag}]" if ktag != "PLAN" else ""
            tok = f"{rec_seat}{badge}({safe_pid}:{safe_title})" if safe_title else f"{rec_seat}{badge}({safe_pid})"
            ordered.append((False, is_own, in_line, rec_seat, tok))

    total = own_cnt + peer_cnt
    if total <= 0:
        return ""
    tokens: list[str] = []
    own_tokens: list[str] = []
    line_tokens: list[str] = []
    seen_red: set[str] = set()
    seen_red_own: set[str] = set()
    seen_red_line: set[str] = set()
    for is_red, is_own, in_line, rec_seat, tok in ordered:
        if is_red:
            if rec_seat not in seen_red:
                tokens.append(f"{rec_seat}({red_counts[rec_seat]} pending)")
                seen_red.add(rec_seat)
            if is_own and rec_seat not in seen_red_own:
                own_tokens.append(f"{rec_seat}({own_cnt} pending)")
                seen_red_own.add(rec_seat)
            if in_line and rec_seat not in seen_red_line:
                line_tokens.append(f"{rec_seat}({red_line_counts[rec_seat]} pending)")
                seen_red_line.add(rec_seat)
        else:
            tokens.append(tok)
            if is_own:
                own_tokens.append(tok)
            if in_line:
                line_tokens.append(tok)

    if eff_scope == "fleet":
        return (
            f"[DIFFQUORUM PENDING PLANS | own:{own_cnt} | peers:{peer_cnt} | total:{total}] "
            f"{' ; '.join(tokens)} "
            "(Non-instructional display metadata: split own vs peer counts in trailing summary; never report 0 from stale memory)"
        )
    if eff_scope == "line":
        line_total = own_cnt + line_peer_cnt
        if line_total <= 0:
            return ""
        outside_cnt = max(0, peer_cnt - line_peer_cnt)
        out_note = f" | outside:{outside_cnt}" if outside_cnt > 0 else ""
        lbl = sanitize_plan_banner_title(line_label, max_chars=20) or "LINE"
        return (
            f"[DIFFQUORUM {lbl} PENDING PLANS | own:{own_cnt} | line_peers:{line_peer_cnt} | line_total:{line_total}{out_note}] "
            f"{' ; '.join(line_tokens)} "
            "(Non-instructional display metadata: report only this line's pending approvals; never report 0 from stale memory)"
        )
    if own_cnt <= 0:
        return ""
    return (
        f"[DIFFQUORUM OWN PENDING PLANS | own:{own_cnt}] "
        f"{' ; '.join(own_tokens)} "
        "(Non-instructional display metadata: summarize only your own pending approvals; omit peer lists and never report own 0 from stale memory)"
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
    if parent in trusted_dirs or parent in (home_bin, "~/bin"):
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
    if action in ("open", "close", "reopen"):
        return {"allowed": True, "mode": "allow_mutate", "action": action, "binary": bin_name}
    return {"allowed": False, "mode": "deny", "reason": f"unsupported_plan_action:{action}"}


_FENCED_CODE_BLOCK_RE = re.compile(r"(`{3,}|~{3,})[\s\S]*?\1")
_INLINE_CODE_SPAN_RE = re.compile(r"`[^`\n]+`")
_TRAILING_PENDING_FOOTER_RE = re.compile(
    r"^\s*\*\*(?:当前(?:全机|[^\n*]{0,16}线)?待你拍板清单|本席待你拍板|(?:Own |Line )?Pending approvals).*$",
    re.MULTILINE | re.IGNORECASE,
)
_STOP_WAIT_PLAN_RE = re.compile(
    r"(?:请先审核上面的计划|回复[“\"『]?\s*Approve\s*[”\"』]?后(?:我再|开始|执行|再)|"
    r"\breply\s+['\"]?approve['\"]?\s+to\s+(?:proceed|execute)\b|\bawaiting\s+your\s+approval\b)",
    re.IGNORECASE,
)
_STOP_WAIT_CB_RE = re.compile(
    r"(?:(?:强制|触发|进入)(?:熔断|人工门禁)[^\n。！？!?]{0,60}(?:等待|请|需|拍板|定夺|介入|处理)|"
    r"\bcircuit[- ]breaker\s+triggered\b[^\n.!?]{0,60}\b(?:awaiting|waiting|please)\b)",
    re.IGNORECASE,
)
_STOP_WAIT_DECISION_RE = re.compile(
    r"(?:(?:请您|请你|交主理人|交给你|交给您|需要你|需要您|等你|等待[你您]?)(?:来)?(?:拍板|定夺|选定|选择方案|选择路径|二选一)|请选择(?:方案|路径)|"
    r"(?:(?<![已曾])(?:怎么(?:来)?定|选哪个|定哪个)[^\n。！!；;]{0,18}[？?]|"
    r"是否可行\s*(?:[？?]|[，,]\s*(?:(?:你|您)?(?:确认|同意|点头)后|请|等你|等待|回复))|"
    r"要不要(?:一起|一并|顺手)[^\n。！!；;]{0,24}[？?]|"
    r"(?:(?:你|您)(?:确认|同意|点头)后(?:我)?(?:再)?|(?<![按经由在被于已曾获])(?:确认|同意|点头)后(?:我)?再)"
    r"(?:推进|执行|开始|启动|落地|动手)(?![了过完毕着])(?![^\n。！!；;]{0,20}(?:已完成|已执行|已上线|已恢复|已通过|全部通过|已交付))|"
    r"(?:^|[，,。；;\n]\s*)(?:确认|同意|点头)后(?:我)?(?:推进|执行|开始|启动|落地|动手)\s*(?:[。！!？?]|$))|"
    r"\bplease\s+(?:choose|decide|pick)\s+(?:between|option|path)\b)",
    re.IGNORECASE,
)
_STOP_WAIT_INPUT_RE = re.compile(
    r"(?:请(?:你|您)(?:先)?(?:补充|提供|确认)[^\n。！？!?]{0,30}(?:后(?:我)?再继续|后再执行|才能继续)|"
    r"\bplease\s+provide\b[^\n.!?]{0,40}\bbefore\s+(?:I\s+)?continu)",
    re.IGNORECASE,
)
_STOP_FOOTER_OWN_ZERO_RE = re.compile(
    r"(?:本席\s*[`*]*\s*0\s*[`*]*\s*项|本席(?:当前)?(?:无|没有)待(?:你|您)?(?:拍板|批|决)|\bown\s*[:=]\s*0\b)",
    re.IGNORECASE,
)
_STOP_FOOTER_PEER_ZERO_RE = re.compile(r"(?:全机他席\s*[`*]*\s*0\s*[`*]*\s*项|\bpeers?\s*[:=]\s*0\b)", re.IGNORECASE)
_STOP_FOOTER_LINE_ZERO_RE = re.compile(
    r"(?:线内他席\s*[`*]*\s*0\s*[`*]*\s*项|(?:本线|线内)[^\n。！？!?]{0,18}(?:共\s*0\s*项|(?:均)?(?:无|没有)待(?:你|您)?(?:拍板|批|决))|\bline_peers?\s*[:=]\s*0\b)",
    re.IGNORECASE,
)
_STOP_FOOTER_ALL_ZERO_RE = re.compile(r"(?:(?:当前|全机)(?:均)?(?:无|没有|0\s*项)待(?:你|您)?(?:拍板|批|决)|\b0\s+pending\s+approvals?\b)", re.IGNORECASE)

FLAT_HOOK_EVENTS = frozenset({"SessionStart", "PreInvocation", "PostInvocation", "Stop"})
GROUPED_HOOK_EVENTS = frozenset({"PreToolUse", "PostToolUse"})


def evaluate_stop_consistency_gate(
    *,
    response_text: str,
    own_waiting_count: int,
    peer_waiting_count: int,
    termination_reason: str = "NO_TOOL_CALL",
    fully_idle: bool = True,
    continuation_active: bool = False,
    readonly_auto_register: bool = False,
    report_scope: str = "fleet",
    line_peer_waiting_count: int | None = None,
) -> dict[str, Any]:
    """
    Role-scoped Zero-Token `Stop` lifecycle hook consistency evaluator:
      1. Fires ONLY when `termination_reason == "NO_TOOL_CALL"` and `fully_idle is True`;
      2. Strips fenced & inline code blocks before checking whether the response body asks for
         human approval/decision/circuit-breaker/input while `own_waiting_count == 0` -> returns
         `decision="continue"` (or `action="auto_register"` for shell-less seats or when `continuation_active=True`);
      3. Checks the trailing 600 chars for false-zero footers scoped by `report_scope` (`fleet` checks own + peers,
         `line` checks own + `line_peer_waiting_count`, `self` checks own only) when `continuation_active=False`;
      4. Hard 1-retry anti-loop invariant: NEVER returns `decision="continue"` when `continuation_active=True`.
    """
    eff_scope = normalize_report_scope(report_scope, default="fleet")
    if str(termination_reason or "").strip() != "NO_TOOL_CALL" or not fully_idle:
        return {"decision": "allow", "action": "allow", "reason": ""}
    text = str(response_text or "")
    if not text.strip():
        return {"decision": "allow", "action": "allow", "reason": ""}

    if int(own_waiting_count) == 0:
        body_clean = _TRAILING_PENDING_FOOTER_RE.sub("", _INLINE_CODE_SPAN_RE.sub(" ", _FENCED_CODE_BLOCK_RE.sub(" ", text)))
        matched_kind = ""
        matched_cue = ""
        for kind, pat in (
            ("PLAN", _STOP_WAIT_PLAN_RE),
            ("CIRCUIT_BREAKER", _STOP_WAIT_CB_RE),
            ("DECISION", _STOP_WAIT_DECISION_RE),
            ("INPUT_REQUIRED", _STOP_WAIT_INPUT_RE),
        ):
            m = pat.search(body_clean)
            if m:
                matched_kind = kind
                matched_cue = " ".join(m.group(0).split())[:48]
                break
        if matched_kind:
            if readonly_auto_register or continuation_active:
                return {
                    "decision": "allow",
                    "action": "auto_register",
                    "inferred_kind": matched_kind,
                    "matched_cue": matched_cue,
                    "reason": "",
                }
            return {
                "decision": "continue",
                "action": "continue",
                "inferred_kind": matched_kind,
                "matched_cue": matched_cue,
                "reason": (
                    f"Stop consistency gate: response pauses for human action ({matched_kind}: {matched_cue!r}) "
                    "while own_waiting_count == 0; register via `plan open --kind ...` or `plan reopen` first."
                ),
            }

    if not continuation_active:
        footer_tail = text[-600:]
        if int(own_waiting_count) > 0 and (_STOP_FOOTER_OWN_ZERO_RE.search(footer_tail) or _STOP_FOOTER_ALL_ZERO_RE.search(footer_tail)):
            return {
                "decision": "continue",
                "action": "continue",
                "reason": (
                    f"Stop consistency gate: footer reports 0 own pending items while own_waiting_count == {int(own_waiting_count)}; "
                    "close completed items or correct the trailing summary."
                ),
            }
        if eff_scope == "fleet" and int(peer_waiting_count) > 0 and (
            _STOP_FOOTER_PEER_ZERO_RE.search(footer_tail) or _STOP_FOOTER_ALL_ZERO_RE.search(footer_tail)
        ):
            return {
                "decision": "continue",
                "action": "continue",
                "reason": (
                    f"Stop consistency gate: footer reports 0 peer pending items while peer_waiting_count == {int(peer_waiting_count)}; "
                    "correct the trailing summary against live pending_plans.json."
                ),
            }
        if eff_scope == "line":
            eff_line_peers = int(line_peer_waiting_count) if line_peer_waiting_count is not None else int(peer_waiting_count)
            if eff_line_peers > 0 and (
                _STOP_FOOTER_LINE_ZERO_RE.search(footer_tail)
                or _STOP_FOOTER_PEER_ZERO_RE.search(footer_tail)
                or _STOP_FOOTER_ALL_ZERO_RE.search(footer_tail)
            ):
                return {
                    "decision": "continue",
                    "action": "continue",
                    "reason": (
                        f"Stop consistency gate: footer reports 0 line peer pending items while line_peer_waiting_count == {eff_line_peers}; "
                        "correct the trailing summary against live pending_plans.json."
                    ),
                }

    return {"decision": "allow", "action": "allow", "reason": ""}


def validate_hooks_json_schema(doc: Any) -> dict[str, Any]:
    """
    Validates lifecycle `hooks.json` structural compliance:
      - Flat events (`SessionStart`, `PreInvocation`, `PostInvocation`, `Stop`) MUST be flat handler lists
        (no `matcher`/`hooks` wrapper dict);
      - Tool events (`PreToolUse`, `PostToolUse`) MUST be grouped dicts containing `matcher` (str) and non-empty `hooks`.
    """
    issues: list[str] = []
    if not isinstance(doc, dict) or not doc:
        return {"ok": False, "issue_count": 1, "issues": ["hooks_json_root_must_be_non_empty_object"]}
    known = FLAT_HOOK_EVENTS | GROUPED_HOOK_EVENTS
    for hook_name, spec in doc.items():
        if not isinstance(spec, dict):
            issues.append(f"{hook_name}: hook spec must be an object")
            continue
        for ev_name, entries in spec.items():
            if ev_name == "enabled":
                if not isinstance(entries, bool):
                    issues.append(f"{hook_name}.enabled: must be boolean")
                continue
            if ev_name not in known:
                continue
            if not isinstance(entries, list):
                issues.append(f"{hook_name}.{ev_name}: must be a list")
                continue
            if ev_name in FLAT_HOOK_EVENTS:
                for idx, item in enumerate(entries):
                    if not isinstance(item, dict):
                        issues.append(f"{hook_name}.{ev_name}[{idx}]: handler must be an object")
                        continue
                    if "matcher" in item or "hooks" in item:
                        issues.append(f"{hook_name}.{ev_name}[{idx}]: flat event must not wrap handlers in matcher/hooks group")
                    if not str(item.get("command") or "").strip():
                        issues.append(f"{hook_name}.{ev_name}[{idx}]: missing non-empty command")
            else:
                for idx, grp in enumerate(entries):
                    if not isinstance(grp, dict):
                        issues.append(f"{hook_name}.{ev_name}[{idx}]: group must be an object")
                        continue
                    if not isinstance(grp.get("matcher"), str):
                        issues.append(f"{hook_name}.{ev_name}[{idx}]: grouped event requires string matcher")
                    sub_hooks = grp.get("hooks")
                    if not isinstance(sub_hooks, list) or not sub_hooks:
                        issues.append(f"{hook_name}.{ev_name}[{idx}]: grouped event requires non-empty hooks list")
                        continue
                    for h_i, h in enumerate(sub_hooks):
                        if not isinstance(h, dict) or not str(h.get("command") or "").strip():
                            issues.append(f"{hook_name}.{ev_name}[{idx}].hooks[{h_i}]: missing non-empty command")
    return {"ok": len(issues) == 0, "issue_count": len(issues), "issues": issues}


_HOOK_MANIFEST_REL_PATHS: tuple[tuple[str, ...], ...] = (
    (".agents", "hooks.json"),
    (".agents", "hooks", "hooks.json"),
    (".gemini", "hooks.json"),
    (".claude", "settings.json"),
)


def _paths_overlap(path_a: str, path_b: str) -> bool:
    a = os.path.normpath(path_a)
    b = os.path.normpath(path_b)
    if a == b:
        return True
    try:
        common = os.path.commonpath([a, b])
    except ValueError:
        return False
    return common == a or common == b


def audit_launch_args_for_hook_bleed(
    launch_argv: list[str] | tuple[str, ...],
    *,
    own_workspace: str | pathlib.Path,
    peer_workspaces: list[str | pathlib.Path] | tuple[str | pathlib.Path, ...] = (),
) -> dict[str, Any]:
    """
    Fails closed when a seat's CLI launch arguments mount a sibling workspace or external
    hook-bearing directory via `--add-dir` / `--additional-dir`, preventing cross-workspace
    `PreToolUse` hook bleed across independent agent seats.
    """
    real_own = os.path.realpath(os.path.expanduser(str(own_workspace)))
    real_peers = [
        os.path.realpath(os.path.expanduser(str(p)))
        for p in (peer_workspaces or ())
        if str(p or "").strip()
    ]
    real_peers = [p for p in real_peers if p != real_own]

    argv_list = [str(tok) for tok in (launch_argv or ())]
    mounted_dirs: list[str] = []
    violations: list[dict[str, str]] = []

    i = 0
    while i < len(argv_list):
        tok = argv_list[i]
        raw_val: str | None = None
        if tok in ("--add-dir", "--additional-dir"):
            if i + 1 >= len(argv_list) or not argv_list[i + 1].strip() or argv_list[i + 1].startswith("-"):
                violations.append({"code": "missing_add_dir_value", "path": "", "detail": f"{tok} missing directory value"})
                i += 1
                continue
            raw_val = argv_list[i + 1]
            i += 2
        elif tok.startswith("--add-dir=") or tok.startswith("--additional-dir="):
            raw_val = tok.split("=", 1)[1]
            if not raw_val.strip():
                violations.append({"code": "missing_add_dir_value", "path": "", "detail": f"{tok} empty directory value"})
                i += 1
                continue
            i += 1
        else:
            i += 1
            continue

        real_dir = os.path.realpath(os.path.expanduser(raw_val))
        mounted_dirs.append(real_dir)
        if real_dir == real_own:
            continue

        matched_peer = False
        for peer in real_peers:
            if _paths_overlap(real_dir, peer):
                violations.append(
                    {
                        "code": "cross_workspace_peer_mount",
                        "path": real_dir,
                        "detail": f"mounts peer workspace {peer}",
                    }
                )
                matched_peer = True
                break
        if matched_peer:
            continue

        dir_path = pathlib.Path(real_dir)
        for rel_parts in _HOOK_MANIFEST_REL_PATHS:
            manifest = dir_path.joinpath(*rel_parts)
            if manifest.exists():
                violations.append(
                    {
                        "code": "external_hook_bearing_dir",
                        "path": real_dir,
                        "detail": f"external directory carries {'/'.join(rel_parts)}",
                    }
                )
                break

    return {
        "ok": len(violations) == 0,
        "own_workspace": real_own,
        "mounted_dirs": mounted_dirs,
        "violation_count": len(violations),
        "violations": violations,
    }


_FORBIDDEN_GLOBAL_PRETOOL_TOOLS: tuple[str, ...] = ("write_file", "edit_file", "run_command")
VALID_SEAT_HOOK_ROLE_PROFILES: tuple[str, ...] = (
    "platform_hub",
    "isolated_guard",
    "multidir_global_hook",
    "cleanroom_line",
)


def _matcher_matches_tool_name(matcher: str, tool_name: str) -> bool:
    pat = str(matcher or "").strip()
    if not pat:
        return False
    try:
        return bool(re.fullmatch(pat, tool_name))
    except re.error:
        return tool_name in pat.split("|")


def has_send_message_pretool_hook(
    hooks_doc: Any,
    *,
    command_markers: tuple[str, ...] = ("pending-hook.py",),
) -> bool:
    """
    Verifies a global `hooks.json` document wires a lightweight `PreToolUse` `send_message`
    audit hook while NEVER matching/intercepting `write_file`, `edit_file`, or `run_command`.
    """
    if not isinstance(hooks_doc, dict) or not validate_hooks_json_schema(hooks_doc).get("ok"):
        return False
    found_send_msg = False
    markers = tuple(m for m in (command_markers or ()) if str(m).strip())
    for spec in hooks_doc.values():
        if not isinstance(spec, dict) or spec.get("enabled") is False:
            continue
        for grp in spec.get("PreToolUse") or []:
            if not isinstance(grp, dict):
                continue
            matcher = str(grp.get("matcher") or "").strip()
            if not matcher:
                continue
            if any(_matcher_matches_tool_name(matcher, bad) for bad in _FORBIDDEN_GLOBAL_PRETOOL_TOOLS):
                return False
            if _matcher_matches_tool_name(matcher, "send_message"):
                for h in grp.get("hooks") or []:
                    cmd = str((h or {}).get("command") or "") if isinstance(h, dict) else ""
                    if cmd and (not markers or any(m in cmd for m in markers)):
                        found_send_msg = True
    return found_send_msg


def _extract_enabled_hook_commands(hooks_doc: Any) -> list[str]:
    if not isinstance(hooks_doc, dict):
        return []
    cmds: list[str] = []
    for spec in hooks_doc.values():
        if not isinstance(spec, dict) or spec.get("enabled") is False:
            continue
        for ev in FLAT_HOOK_EVENTS:
            for item in spec.get(ev) or []:
                if isinstance(item, dict):
                    c = str(item.get("command") or "").strip()
                    if c:
                        cmds.append(c)
        for ev in GROUPED_HOOK_EVENTS:
            for grp in spec.get(ev) or []:
                if not isinstance(grp, dict):
                    continue
                for h in grp.get("hooks") or []:
                    if isinstance(h, dict):
                        c = str(h.get("command") or "").strip()
                        if c:
                            cmds.append(c)
    return cmds


def has_enabled_pretool_send_message(
    hooks_doc: Any,
    *,
    command_markers: tuple[str, ...] = (),
) -> bool:
    """Returns True only when an enabled `PreToolUse` group matches `send_message` with a verified command."""
    if not isinstance(hooks_doc, dict) or not validate_hooks_json_schema(hooks_doc).get("ok"):
        return False
    markers = tuple(m for m in (command_markers or ()) if str(m).strip())
    for spec in hooks_doc.values():
        if not isinstance(spec, dict) or spec.get("enabled") is False:
            continue
        for grp in spec.get("PreToolUse") or []:
            if not isinstance(grp, dict):
                continue
            if not _matcher_matches_tool_name(str(grp.get("matcher") or ""), "send_message"):
                continue
            for h in grp.get("hooks") or []:
                if not isinstance(h, dict):
                    continue
                cmd = str(h.get("command") or "").strip()
                if cmd and (not markers or any(m in cmd for m in markers)):
                    return True
    return False


def audit_seat_hook_contract(
    *,
    role_profile: str,
    local_hooks_doc: Any,
    global_hooks_doc: Any,
    expected_local_markers: tuple[str, ...] = (),
    global_command_markers: tuple[str, ...] = ("pending-hook.py",),
) -> dict[str, Any]:
    """
    Role-aware hook & `send_message` audit contract across heterogeneous fleet seats:
      - `platform_hub`: valid local `hooks.json` + non-empty `expected_local_markers` in enabled hook commands + active `send_message` PreToolUse emitter (local or global).
      - `isolated_guard`: valid local `hooks.json` + non-empty `expected_local_markers` in enabled hook commands + global `PreToolUse(send_message)`.
      - `multidir_global_hook`: optional local `hooks.json` (must be schema-valid if present) + active global
        `PreInvocation` + `Stop` + `PreToolUse(send_message)` without global file/shell interception.
      - `cleanroom_line`: valid local `hooks.json` + non-empty `expected_local_markers` in enabled hook commands + active `send_message` PreToolUse emitter (local or global).
    """
    role = str(role_profile or "").strip().lower()
    if role not in VALID_SEAT_HOOK_ROLE_PROFILES:
        raise ValueError(f"Unsupported role_profile {role_profile!r}; expected one of {VALID_SEAT_HOOK_ROLE_PROFILES}")

    issues: list[str] = []
    gchk = validate_hooks_json_schema(global_hooks_doc) if isinstance(global_hooks_doc, dict) else {"ok": False, "issues": ["missing_global_hooks"]}
    has_global_pre_stop = isinstance(global_hooks_doc, dict) and any(
        isinstance(spec, dict)
        and spec.get("enabled") is not False
        and bool(spec.get("PreInvocation"))
        and bool(spec.get("Stop"))
        for spec in global_hooks_doc.values()
    )
    global_hooks_ok = bool(gchk.get("ok") and has_global_pre_stop)
    global_send_msg_ok = has_send_message_pretool_hook(global_hooks_doc, command_markers=global_command_markers)
    if not global_hooks_ok:
        issues.append("global_pre_stop_invalid")

    has_local = local_hooks_doc is not None
    local_schema_ok = False
    enabled_cmds: list[str] = []
    local_send_msg_ok = False
    if has_local:
        lchk = validate_hooks_json_schema(local_hooks_doc)
        local_schema_ok = bool(lchk.get("ok"))
        if not local_schema_ok:
            issues.extend(str(x) for x in lchk.get("issues") or [])
        else:
            enabled_cmds = _extract_enabled_hook_commands(local_hooks_doc)
            local_send_msg_ok = has_enabled_pretool_send_message(local_hooks_doc)

    req_markers = tuple(str(m).strip() for m in (expected_local_markers or ()) if str(m).strip())
    missing_markers = [m for m in req_markers if not any(m in c for c in enabled_cmds)]

    if role == "multidir_global_hook":
        if has_local and not local_schema_ok:
            issues.append("local_hooks_schema_invalid")
        if not global_send_msg_ok:
            issues.append("missing_global_send_message_hook")
        emitter_ready = global_send_msg_ok
    elif role == "isolated_guard":
        if not has_local:
            issues.append("missing_local_hooks")
        if not req_markers:
            issues.append("missing_expected_local_markers")
        elif missing_markers:
            issues.append(f"missing_local_markers:{','.join(missing_markers)}")
        if not global_send_msg_ok:
            issues.append("missing_global_send_message_hook")
        emitter_ready = global_send_msg_ok
    else:
        if not has_local:
            issues.append("missing_local_hooks")
        if not req_markers:
            issues.append("missing_expected_local_markers")
        elif missing_markers:
            issues.append(f"missing_local_markers:{','.join(missing_markers)}")
        emitter_ready = bool(local_send_msg_ok or global_send_msg_ok)
        if not emitter_ready:
            issues.append("missing_send_message_emitter")

    return {
        "ok": len(issues) == 0 and emitter_ready,
        "role_profile": role,
        "global_hooks_ok": global_hooks_ok,
        "global_send_message_hook": global_send_msg_ok,
        "has_local_hooks": has_local,
        "local_schema_ok": local_schema_ok,
        "local_send_message_emitter": local_send_msg_ok,
        "send_message_emitter_ready": emitter_ready,
        "issues": issues,
    }


STRICT_SEAT_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
DEFAULT_FORBIDDEN_BIND_IDENTITIES: tuple[str, ...] = ("guest-lab", "system-watcher", "unmapped")
DEFAULT_ONE_WAY_GUEST_SENDERS: tuple[str, ...] = ("guest-lab",)


def evaluate_unmapped_workspace_write_policy(
    *,
    seat: str,
    session_cwd: str,
    target_path: str,
    cwd_owner_seat: str,
    target_owner_seat: str,
    is_subagent: bool = False,
    sealed_seats: tuple[str, ...] | frozenset[str] = (),
    is_sensitive_cred: bool = False,
    is_bus_path: bool = False,
    is_sealed_path: bool = False,
) -> dict[str, Any]:
    """
    Single-UUID Guard Anti-Lockout Policy for unmapped sessions:
    Downgrades hard `deny` to explicit human `ask` (NEVER `allow`) ONLY when a top-level
    `unmapped` session carrying an explicit non-empty `session_cwd` inside a non-sealed
    workspace writes strictly inside that exact same workspace without touching credentials,
    shared-bus state, sealed vaults, or cross-seat directories.
    """
    if is_sealed_path or is_sensitive_cred or is_bus_path:
        return {
            "decision": "deny",
            "code": "protected_boundary_denied",
            "reason": "Blocked: sealed vault, host credential, or shared-bus write is strictly forbidden.",
        }
    clean_seat = str(seat or "").strip()
    c_own = str(cwd_owner_seat or "").strip()
    t_own = str(target_owner_seat or "").strip()
    if not clean_seat:
        return {
            "decision": "deny",
            "code": "missing_seat_identity",
            "reason": "Blocked: missing seat identity cannot use anti-lockout ask.",
        }
    if clean_seat != "unmapped":
        if t_own and t_own != clean_seat:
            return {
                "decision": "deny",
                "code": "cross_seat_write_denied",
                "reason": f"Blocked: mapped seat '{clean_seat}' cannot write inside '{t_own}'.",
            }
        return {"decision": "allow", "code": "mapped_own_workspace_allow", "reason": ""}
    if is_subagent:
        return {
            "decision": "deny",
            "code": "subagent_anti_lockout_denied",
            "reason": "Blocked: unmapped subagent cannot escalate write access via anti-lockout ask.",
        }
    if not str(session_cwd or "").strip() or not str(target_path or "").strip() or not c_own or not t_own:
        return {
            "decision": "deny",
            "code": "missing_explicit_workspace_ownership",
            "reason": "Blocked: unmapped session missing explicit workspace ownership cannot write.",
        }
    sealed_set = {str(s).strip().lower() for s in (sealed_seats or ()) if str(s).strip()}
    if c_own.lower() in sealed_set or t_own.lower() in sealed_set:
        return {
            "decision": "deny",
            "code": "sealed_workspace_denied",
            "reason": f"Blocked: sealed seat '{t_own}' is never eligible for unmapped anti-lockout ask.",
        }
    if c_own != t_own:
        return {
            "decision": "deny",
            "code": "cross_seat_write_denied",
            "reason": f"Blocked: unmapped session in '{c_own}' cannot write cross-seat into '{t_own}'.",
        }
    return {
        "decision": "ask",
        "code": "unmapped_own_workspace_ask",
        "reason": f"Anti-Lockout: unmapped top-level session inside '{c_own}' writing same workspace; requiring human confirmation.",
    }


def plan_atomic_seat_uuid_rebind(
    *,
    env_text: str,
    seat: str,
    new_uuid: str,
    seat_keys: tuple[str, ...] | list[str],
    key_to_seat: dict[str, str],
    forbidden_identities: tuple[str, ...] | frozenset[str] = DEFAULT_FORBIDDEN_BIND_IDENTITIES,
    force_reassign: bool = False,
) -> dict[str, Any]:
    """
    Pure atomic planner for rebinding a seat's primary and legacy compatibility UUID keys in an
    `.env` registry while preserving comments, sibling keys, and cross-seat uniqueness.
    Fails closed on guest/system identities, malformed UUIDs, or duplicate cross-seat UUIDs
    (unless `force_reassign=True`, which atomically clears conflicting keys on the previous seat).
    """
    clean_seat = str(seat or "").strip().lower()
    clean_uuid = str(new_uuid or "").strip().lower()
    forbidden = {str(x).strip().lower() for x in (forbidden_identities or ()) if str(x).strip()}
    if not clean_seat or clean_seat in forbidden:
        return {"ok": False, "error": f"forbidden_or_empty_seat:{clean_seat}"}
    if not STRICT_SEAT_UUID_RE.fullmatch(clean_uuid):
        return {"ok": False, "error": f"invalid_uuid:{new_uuid!r}"}
    ordered_keys = tuple(dict.fromkeys(str(k).strip() for k in (seat_keys or ()) if str(k).strip()))
    if not ordered_keys:
        return {"ok": False, "error": f"missing_seat_keys:{clean_seat}"}

    parsed: dict[str, str] = {}
    lines = str(env_text or "").splitlines()
    for line in lines:
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        k_s = k.strip()
        if k_s.startswith("export "):
            k_s = k_s[7:].strip()
        v_s = v.strip().strip('"').strip("'")
        if k_s:
            parsed[k_s] = v_s

    conflicts: list[dict[str, str]] = []
    conflict_key_set: set[str] = set()
    for k, v in parsed.items():
        if v.lower() != clean_uuid:
            continue
        owner = str(key_to_seat.get(k, "")).strip().lower()
        if owner and owner != clean_seat:
            conflicts.append({"seat": owner, "key": k, "uuid": v})
            conflict_key_set.add(k)
    if conflicts and not force_reassign:
        return {"ok": False, "error": "duplicate_cross_seat_uuid", "conflicts": conflicts}

    key_set = set(ordered_keys)
    clear_set = conflict_key_set - key_set if force_reassign else set()
    old_values = {k: parsed.get(k, "") for k in ordered_keys}
    seen_target: set[str] = set()
    seen_clear: set[str] = set()
    out_lines: list[str] = []
    for line in lines:
        s = line.strip()
        if s and not s.startswith("#") and "=" in s:
            raw_k = s.split("=", 1)[0].strip()
            k = raw_k[7:].strip() if raw_k.startswith("export ") else raw_k
            if k in key_set:
                if k not in seen_target:
                    out_lines.append(f"{k}={clean_uuid}")
                    seen_target.add(k)
                continue
            if k in clear_set:
                if k not in seen_clear:
                    out_lines.append(f"{k}=")
                    seen_clear.add(k)
                continue
        out_lines.append(line)
    for k in ordered_keys:
        if k not in seen_target:
            out_lines.append(f"{k}={clean_uuid}")
            seen_target.add(k)
    rendered = "\n".join(out_lines).rstrip("\n") + "\n"
    return {
        "ok": True,
        "seat": clean_seat,
        "new_uuid": clean_uuid,
        "updated_keys": list(ordered_keys),
        "cleared_conflict_keys": sorted(clear_set),
        "old_values": old_values,
        "conflicts_overridden": conflicts,
        "rendered_env": rendered,
    }


def evaluate_one_way_guest_dispatch(
    *,
    sender: str,
    priority: str,
    recent_dispatch_epochs: list[float] | tuple[float, ...],
    now_ts: float,
    has_approval_anchor: bool = False,
    allowed_guests: tuple[str, ...] | frozenset[str] = DEFAULT_ONE_WAY_GUEST_SENDERS,
    max_per_window: int = 3,
    window_sec: float = 300.0,
) -> dict[str, Any]:
    """
    Fail-closed policy gate for temporary one-way guest dispatchers:
      - Allowed strictly for non-P0 (`P1` / `P2`) dispatches without V2.3 approval anchors;
      - Enforces an atomic sliding-window anti-loop cap (`max_per_window` per `window_sec`);
      - Tags accepted dispatches `one_way_guest=True`, `from_conv_id=""`, `receipt_notified_to_sender=True`
        so the host watcher never bounces wakeups back to an unregistered guest terminal.
    """
    import math

    if (
        isinstance(now_ts, bool)
        or not isinstance(now_ts, (int, float))
        or not math.isfinite(float(now_ts))
        or isinstance(window_sec, bool)
        or not isinstance(window_sec, (int, float))
        or not math.isfinite(float(window_sec))
        or float(window_sec) <= 0.0
        or isinstance(max_per_window, bool)
        or not isinstance(max_per_window, int)
        or max_per_window < 1
    ):
        raise ValueError("Invalid numeric parameters for evaluate_one_way_guest_dispatch")

    clean_sender = str(sender or "").strip()
    guests = {str(g).strip() for g in (allowed_guests or ()) if str(g).strip()}
    if clean_sender not in guests:
        return {"ok": False, "code": "unrecognized_guest_sender", "reason": f"Sender {clean_sender!r} is not an allowed one-way guest."}
    if has_approval_anchor:
        return {"ok": False, "code": "guest_approval_anchor_forbidden", "reason": "One-way guest sender cannot attach V2.3 approval anchors."}
    prio = str(priority or "").strip().upper()
    if prio not in ("P1", "P2"):
        return {"ok": False, "code": "guest_priority_forbidden", "reason": f"One-way guest sender is restricted to P1/P2 (got {prio!r})."}

    now_f = float(now_ts)
    win_f = float(window_sec)
    recent = [
        float(ts)
        for ts in (recent_dispatch_epochs or ())
        if not isinstance(ts, bool)
        and isinstance(ts, (int, float))
        and math.isfinite(float(ts))
        and (now_f - float(ts)) <= win_f
        and float(ts) <= now_f + 5.0
    ]
    if len(recent) >= max_per_window:
        return {
            "ok": False,
            "code": "GUEST_DISPATCH_RATE_LIMITED",
            "recent_count": len(recent),
            "max_per_window": max_per_window,
            "window_sec": win_f,
            "reason": f"Guest sender '{clean_sender}' hit rate limit ({len(recent)}/{max_per_window} within {int(win_f)}s).",
        }
    return {
        "ok": True,
        "code": "GUEST_DISPATCH_ALLOWED",
        "sender": clean_sender,
        "priority": prio,
        "recent_count": len(recent),
        "remaining_in_window": max_per_window - len(recent) - 1,
        "one_way_guest": True,
        "from_conv_id": "",
        "receipt_notified_to_sender": True,
    }
