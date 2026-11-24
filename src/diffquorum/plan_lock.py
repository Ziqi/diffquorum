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


def open_pending_plan(
    plans_path: str | pathlib.Path,
    *,
    seat: str,
    scope: str,
    title: str,
    owner_seat: str = "lead",
) -> dict[str, Any]:
    """Opens a `WAITING_APPROVE` plan or reports `collision: True` if another seat holds `scope`."""
    p_file = pathlib.Path(plans_path).expanduser().resolve()
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
    p_file = pathlib.Path(plans_path).expanduser().resolve()
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
    p_file = pathlib.Path(plans_path).expanduser().resolve()
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
    p_file = pathlib.Path(plans_path).expanduser().resolve()
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
