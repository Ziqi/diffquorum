#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarCouncil Contributors
# SPDX-License-Identifier: MIT
"""Pointer-Over-Blackboard IPC, 5 Live Archives, nofollow I/O, flock locks, and hop<=1 bridge."""

from __future__ import annotations

import ast
import datetime as dt
import fcntl
import json
import os
import pathlib
import re
import shlex
import stat
import subprocess
import time
from typing import Any

MAX_BOARD_BYTES = 3072
MAX_ENVELOPE_BYTES = 400
MAX_STDIN_BYTES = 65536
IDEMPOTENCY_TTL_SECONDS = 7 * 86400
ACK_SILENCE_SECONDS = 60.0
FAST_BURST_WINDOW_SECONDS = 120.0
FAST_BURST_LIMIT = 4
SLOW_BURST_WINDOW_SECONDS = 900.0
SLOW_BURST_LIMIT = 6
MAX_HOP = 1

SEAT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")
HOST_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,79}$")
RESOURCE_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
VALID_KINDS = ("TASK_DISPATCH", "UPWARD_REPORT", "PEER_SYNC", "MILESTONE_PASS", "ACK")
VALID_PRIORITIES = ("P0", "P1", "P2")


def utc_iso(ts: float | None = None) -> str:
    val = time.time() if ts is None else ts
    return dt.datetime.fromtimestamp(val, tz=dt.timezone.utc).isoformat(timespec="seconds")


def parse_toml_text(text: str) -> dict[str, Any]:
    """Parses TOML via stdlib tomllib (3.11+) or a lightweight stdlib subset parser (3.10)."""
    try:
        import tomllib  # type: ignore[import-not-found]

        return tomllib.loads(text)
    except ImportError:
        pass

    root: dict[str, Any] = {}
    cur: dict[str, Any] = root
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[[") and line.endswith("]]"):
            sec = line[2:-2].strip()
            arr = root.setdefault(sec, [])
            item: dict[str, Any] = {}
            arr.append(item)
            cur = item
        elif line.startswith("[") and line.endswith("]"):
            sec = line[1:-1].strip()
            cur = root.setdefault(sec, {})
        elif "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if v in ("true", "false"):
                cur[k] = v == "true"
            elif re.fullmatch(r"-?\d+", v):
                cur[k] = int(v)
            else:
                cur[k] = ast.literal_eval(v)
    return root


def ensure_safe_dir(path: pathlib.Path) -> pathlib.Path:
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"Symlink directory blocked: {path}")
    return path


def open_regular_nofollow(path: pathlib.Path, flags: int, mode: int = 0o600) -> tuple[int, os.stat_result]:
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags | nofollow, mode)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Non-regular file blocked: {path}")
        return fd, st
    except Exception:
        os.close(fd)
        raise


def atomic_write_text(path: pathlib.Path, text: str, mode: int = 0o600) -> None:
    ensure_safe_dir(path.parent)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd, _ = open_regular_nofollow(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, mode)
    try:
        data = text.encode("utf-8")
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def atomic_write_json(path: pathlib.Path, payload: Any) -> None:
    atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")


def read_json_nofollow(path: pathlib.Path, max_bytes: int = 4 * 1024 * 1024) -> Any:
    if os.path.lexists(path) and path.is_symlink():
        raise ValueError(f"Symlink file blocked: {path}")
    fd, st = open_regular_nofollow(path, os.O_RDONLY)
    try:
        if st.st_size > max_bytes:
            raise ValueError(f"File exceeds {max_bytes} bytes: {path}")
        raw = os.read(fd, max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"File exceeds {max_bytes} bytes: {path}")
        return json.loads(raw.decode("utf-8"))
    finally:
        os.close(fd)


class BusLock:
    """Exclusive fcntl.flock mutex under `.starcouncil/locks/`."""

    def __init__(self, lock_path: pathlib.Path, non_blocking: bool = False) -> None:
        self.lock_path = lock_path
        self.non_blocking = non_blocking
        self._fd: int | None = None

    def __enter__(self) -> "BusLock":
        ensure_safe_dir(self.lock_path.parent)
        fd, _ = open_regular_nofollow(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        self._fd = fd
        op = fcntl.LOCK_EX | (fcntl.LOCK_NB if self.non_blocking else 0)
        try:
            fcntl.flock(fd, op)
        except Exception:
            os.close(fd)
            self._fd = None
            raise
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        if self._fd is not None:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None


def sc_dir(root: pathlib.Path) -> pathlib.Path:
    return root / ".starcouncil"


def append_jsonl_nofollow(path: pathlib.Path, line_str: str) -> None:
    ensure_safe_dir(path.parent)
    fd, _ = open_regular_nofollow(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        data = (line_str + "\n").encode("utf-8")
        view = memoryview(data)
        written = 0
        while written < len(view):
            written += os.write(fd, view[written:])
        os.fsync(fd)
    finally:
        os.close(fd)


def append_event_log(
    root: pathlib.Path,
    *,
    action: str,
    actor: str = "cli",
    status: str = "ok",
    detail: dict[str, Any] | None = None,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Appends an immutable structured record to `.starcouncil/logs/events.jsonl` under `events.lock`."""
    base = sc_dir(root)
    entry = {
        "ts": utc_iso(now_ts),
        "action": str(action),
        "actor": str(actor),
        "status": str(status),
        "detail": detail or {},
    }
    line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
    with BusLock(base / "locks" / "events.lock"):
        append_jsonl_nofollow(base / "logs" / "events.jsonl", line)
    return entry


def default_council_toml(
    topology: str = "local-tmux",
    subscription: str = "single-sub",
    host_alias: str = "workstation",
    remote_bin: str = "starcouncil",
) -> str:
    max_conc = 1 if subscription == "single-sub" else 3
    return (
        'schema_version = "0.1.0"\n\n'
        "[cluster]\n"
        f'topology = "{topology}"\n'
        f'subscription = "{subscription}"\n'
        f"max_concurrent_agents = {max_conc}\n"
        "max_review_rounds = 2\n"
        "max_hop = 1\n"
        "cross_host_daily_reporting = false\n"
        'allowlisted_hosts = ["local", "' + host_alias + '"]\n\n'
        "[wakeup]\n"
        "client_idle_seconds = 15\n"
        "ignore_daemon_tasks = true\n"
        "max_attempts_before_human = 2\n\n"
        "[[seats]]\n"
        'id = "lead"\n'
        'role = "Local dispatcher and coordinator"\n'
        'host = "local"\n'
        'transport = "local_agy"\n'
        'attendance = "core"\n'
        'subscribe_tags = ["dispatch", "outreach", "general"]\n'
        'preferred_mode = "sync"\n\n'
        "[[seats]]\n"
        'id = "builder"\n'
        'role = "Primary implementation engineer"\n'
        'host = "local"\n'
        'transport = "local_agy"\n'
        'attendance = "on_tag"\n'
        'subscribe_tags = ["code", "github", "security", "arch", "skill", "general"]\n'
        'preferred_mode = "sync"\n\n'
        "[[seats]]\n"
        'id = "remote-hub"\n'
        'role = "Optional remote workstation (DO_NOT_DISTURB by default)"\n'
        'host = "remote"\n'
        f'ssh_host = "{host_alias}"\n'
        f'remote_bin = "{remote_bin}"\n'
        'transport = "ssh_peer_card"\n'
        'attendance = "on_tag"\n'
        'subscribe_tags = ["arch", "skill", "retro"]\n'
        'preferred_mode = "async_card"\n'
    )


def init_workspace(
    root: pathlib.Path,
    *,
    topology: str = "local-tmux",
    subscription: str = "single-sub",
    host_alias: str = "workstation",
    remote_bin: str = "starcouncil",
    force: bool = False,
) -> dict[str, Any]:
    if topology not in ("local-tmux", "ssh-federated"):
        raise ValueError(f"Unsupported topology: {topology}")
    if subscription not in ("single-sub", "multi-sub"):
        raise ValueError(f"Unsupported subscription: {subscription}")
    if not HOST_ALIAS_RE.fullmatch(host_alias):
        raise ValueError(f"Invalid host_alias: {host_alias}")

    base = sc_dir(root)
    ensure_safe_dir(base)
    for sub in ("inbox", "artifacts", "locks", "logs", "meetings"):
        ensure_safe_dir(base / sub)

    toml_path = base / "council.toml"
    if force or not toml_path.exists():
        atomic_write_text(toml_path, default_council_toml(topology, subscription, host_alias, remote_bin))

    board_path = base / "BOARD.md"
    if force or not board_path.exists():
        atomic_write_text(
            board_path,
            "# Shared Blackboard (<3KB)\n\n"
            "- Keep payloads in `artifacts/` and `<400B` pointers in `inbox/<seat>.jsonl`.\n"
            "- Locks: none held\n"
            "- Status: `IDLE`\n",
        )

    pitfalls_path = base / "pitfalls.md"
    if force or not pitfalls_path.exists():
        atomic_write_text(
            pitfalls_path,
            "# Shift-Left Pitfalls Ledger\n\n"
            "Append verified root-cause blockers and Andon cord escalations here.\n",
        )

    fixes_path = base / "fixes_log.md"
    if force or not fixes_path.exists():
        atomic_write_text(
            fixes_path,
            "# Verified Fixes Log\n\n"
            "Append root-cause fixes and validation proof here.\n",
        )

    events_path = base / "logs" / "events.jsonl"
    if force and events_path.exists():
        events_path.unlink()

    bridge_path = base / "bridge_state.json"
    if force or not bridge_path.exists():
        atomic_write_json(
            bridge_path,
            {
                "seen_event_ids": {},
                "ack_ts_by_peer": {},
                "peer_tx_timestamps": {},
                "acked_events": {},
            },
        )

    append_event_log(
        root,
        action="INIT",
        actor="cli",
        status="ok",
        detail={"topology": topology, "subscription": subscription},
    )

    return {
        "ok": True,
        "starcouncil_dir": str(base),
        "topology": topology,
        "subscription": subscription,
        "max_concurrent_agents": 1 if subscription == "single-sub" else 3,
        "archives": ["BOARD.md", "logs/events.jsonl", "pitfalls.md", "fixes_log.md", "meetings/", "inbox/", "artifacts/", "locks/"],
    }


def load_council_config(root: pathlib.Path) -> dict[str, Any]:
    cfg_path = sc_dir(root) / "council.toml"
    if not cfg_path.is_file() or cfg_path.is_symlink():
        raise FileNotFoundError(f"Missing or unsafe council.toml at {cfg_path}")
    return parse_toml_text(cfg_path.read_text(encoding="utf-8"))


def update_board(root: pathlib.Path, content: str, actor: str = "cli") -> dict[str, Any]:
    encoded = content.encode("utf-8")
    if len(encoded) >= MAX_BOARD_BYTES:
        raise ValueError(f"BOARD.md budget exceeded: {len(encoded)} bytes >= {MAX_BOARD_BYTES} bytes")
    board_path = sc_dir(root) / "BOARD.md"
    with BusLock(sc_dir(root) / "locks" / "bus.lock"):
        atomic_write_text(board_path, content)
    append_event_log(root, action="BOARD_UPDATE", actor=actor, status="ok", detail={"bytes": len(encoded)})
    return {"ok": True, "path": str(board_path), "bytes": len(encoded)}


def refresh_board_locks(root: pathlib.Path, actor: str = "cli") -> dict[str, Any]:
    """Updates the Locks status line in BOARD.md from current `locks/*.holder.json` metadata."""
    base = sc_dir(root)
    locks_dir = base / "locks"
    holders: list[str] = []
    if locks_dir.is_dir():
        for hp in sorted(locks_dir.glob("*.holder.json")):
            try:
                doc = read_json_nofollow(hp)
                res_name = hp.name.replace(".holder.json", "")
                holders.append(f"{res_name}({doc.get('seat', '?')})")
            except Exception:
                continue
    lock_line = f"- Locks: {', '.join(holders) if holders else 'none held'}"
    cur = read_board(root)
    lines = cur.splitlines()
    replaced = False
    for idx, ln in enumerate(lines):
        if ln.startswith("- Locks:"):
            lines[idx] = lock_line
            replaced = True
            break
    if not replaced:
        lines.append(lock_line)
    new_text = "\n".join(lines).rstrip() + "\n"
    return update_board(root, new_text, actor=actor)


def read_board(root: pathlib.Path) -> str:
    board_path = sc_dir(root) / "BOARD.md"
    fd, st = open_regular_nofollow(board_path, os.O_RDONLY)
    try:
        if st.st_size >= MAX_BOARD_BYTES:
            raise ValueError(f"BOARD.md exceeds <{MAX_BOARD_BYTES}B budget ({st.st_size} bytes)")
        return os.read(fd, MAX_BOARD_BYTES).decode("utf-8")
    finally:
        os.close(fd)


def _prune_bridge_state(state: dict[str, Any], now_ts: float) -> None:
    seen = state.setdefault("seen_event_ids", {})
    for eid in [k for k, ts in seen.items() if (now_ts - float(ts)) > IDEMPOTENCY_TTL_SECONDS]:
        seen.pop(eid, None)
    tx_map = state.setdefault("peer_tx_timestamps", {})
    for peer in list(tx_map.keys()):
        tx_map[peer] = [float(t) for t in tx_map[peer] if (now_ts - float(t)) <= SLOW_BURST_WINDOW_SECONDS]
    ack_map = state.setdefault("ack_ts_by_peer", {})
    for peer in [k for k, ts in ack_map.items() if (now_ts - float(ts)) > ACK_SILENCE_SECONDS * 2]:
        ack_map.pop(peer, None)


def dispatch_pointer(
    root: pathlib.Path,
    *,
    from_seat: str,
    to_seat: str,
    summary: str,
    artifact_text: str = "",
    kind: str = "TASK_DISPATCH",
    priority: str = "P1",
    hop: int = 0,
    event_id: str = "",
    in_reply_to: str = "",
    now_ts: float | None = None,
) -> dict[str, Any]:
    if not SEAT_NAME_RE.fullmatch(from_seat) or not SEAT_NAME_RE.fullmatch(to_seat):
        raise ValueError("Invalid seat identifier format")
    if kind not in VALID_KINDS:
        raise ValueError(f"Invalid kind '{kind}'; expected one of {VALID_KINDS}")
    if priority not in VALID_PRIORITIES:
        raise ValueError(f"Invalid priority '{priority}'; expected one of {VALID_PRIORITIES}")
    if isinstance(hop, bool) or not isinstance(hop, int) or hop < 0 or hop > MAX_HOP:
        raise ValueError(f"Hop limit exceeded: hop={hop!r} (must satisfy 0 <= hop <= {MAX_HOP})")

    now_ep = time.time() if now_ts is None else float(now_ts)
    eid = event_id.strip() or f"evt-{int(now_ep)}-{os.getpid()}"
    if not EVENT_ID_RE.fullmatch(eid):
        raise ValueError(f"Invalid event_id: {eid}")

    base = sc_dir(root)
    bridge_path = base / "bridge_state.json"

    with BusLock(base / "locks" / "bus.lock"):
        state = read_json_nofollow(bridge_path) if bridge_path.exists() else {}
        _prune_bridge_state(state, now_ep)

        if eid in state["seen_event_ids"]:
            append_event_log(root, action="DISPATCH", actor=from_seat, status="dedup_skipped", detail={"event_id": eid})
            return {"ok": True, "action": "DEDUP_SKIPPED", "event_id": eid}

        peer_key = f"{from_seat}->{to_seat}"
        if (kind == "ACK" or in_reply_to.startswith("ack:")) and priority != "P0":
            last_ack = float(state["ack_ts_by_peer"].get(peer_key, 0.0))
            if (now_ep - last_ack) < ACK_SILENCE_SECONDS:
                append_event_log(root, action="DISPATCH", actor=from_seat, status="blocked_ack_silence", detail={"peer": peer_key})
                raise ValueError(f"ACK_SILENCE_WINDOW_ACTIVE ({ACK_SILENCE_SECONDS:.0f}s) for {peer_key}")

        hist = state["peer_tx_timestamps"].setdefault(peer_key, [])
        fast_cnt = sum(1 for t in hist if (now_ep - t) <= FAST_BURST_WINDOW_SECONDS)
        slow_cnt = sum(1 for t in hist if (now_ep - t) <= SLOW_BURST_WINDOW_SECONDS)
        if fast_cnt >= FAST_BURST_LIMIT or slow_cnt > SLOW_BURST_LIMIT:
            append_event_log(root, action="DISPATCH", actor=from_seat, status="blocked_resonance", detail={"peer": peer_key})
            raise ValueError(
                f"RESONANCE_CIRCUIT_OPEN for {peer_key} (120s={fast_cnt}/{FAST_BURST_LIMIT}, 900s={slow_cnt}/{SLOW_BURST_LIMIT})"
            )

        rel_artifact = f"artifacts/{eid}.md"
        full_body = artifact_text.strip() or summary.strip()
        atomic_write_text(
            base / rel_artifact,
            f"# {eid} ({kind} | {from_seat} -> {to_seat})\n\n- Timestamp: {utc_iso(now_ep)}\n\n{full_body}\n",
        )

        envelope = {
            "id": eid,
            "ts": int(now_ep),
            "from": from_seat,
            "kind": kind,
            "prio": priority,
            "hop": hop,
            "ack_prohibited": kind == "ACK",
            "ref": rel_artifact,
            "sum": summary.strip()[:120],
        }
        line = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
        while len(line.encode("utf-8")) >= MAX_ENVELOPE_BYTES and len(envelope["sum"]) > 8:
            envelope["sum"] = envelope["sum"][:-8]
            line = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
        if len(line.encode("utf-8")) >= MAX_ENVELOPE_BYTES:
            raise ValueError(f"Pointer envelope exceeds {MAX_ENVELOPE_BYTES}B limit")

        append_jsonl_nofollow(base / "inbox" / f"{to_seat}.jsonl", line)
        state["seen_event_ids"][eid] = now_ep
        hist.append(now_ep)
        if kind == "ACK":
            state["ack_ts_by_peer"][peer_key] = now_ep
        atomic_write_json(bridge_path, state)

    append_event_log(
        root,
        action="DISPATCH",
        actor=from_seat,
        status="ok",
        detail={"event_id": eid, "to": to_seat, "kind": kind, "hop": hop},
        now_ts=now_ep,
    )
    return {
        "ok": True,
        "action": "DISPATCHED",
        "event_id": eid,
        "pointer_bytes": len(line.encode("utf-8")),
        "ref": rel_artifact,
        "inbox": f"inbox/{to_seat}.jsonl",
    }


def ack_pointer(
    root: pathlib.Path,
    *,
    seat: str,
    event_id: str,
    note: str = "ACK",
    priority: str = "P1",
    emit_reply_to: str = "",
    now_ts: float | None = None,
) -> dict[str, Any]:
    if not SEAT_NAME_RE.fullmatch(seat) or not EVENT_ID_RE.fullmatch(event_id):
        raise ValueError("Invalid seat or event_id")
    now_ep = time.time() if now_ts is None else float(now_ts)
    base = sc_dir(root)
    bridge_path = base / "bridge_state.json"

    with BusLock(base / "locks" / "bus.lock"):
        state = read_json_nofollow(bridge_path) if bridge_path.exists() else {}
        _prune_bridge_state(state, now_ep)
        acked = state.setdefault("acked_events", {})
        acked[event_id] = {"seat": seat, "ts": now_ep, "note": note[:120]}
        atomic_write_json(bridge_path, state)

    append_event_log(
        root,
        action="ACK",
        actor=seat,
        status="ok",
        detail={"event_id": event_id, "emit_reply_to": emit_reply_to},
        now_ts=now_ep,
    )

    res: dict[str, Any] = {"ok": True, "action": "ACKED", "event_id": event_id, "seat": seat}
    if emit_reply_to:
        if not SEAT_NAME_RE.fullmatch(emit_reply_to):
            raise ValueError(f"Invalid emit_reply_to seat: {emit_reply_to}")
        ack_eid = f"ack-{event_id}"[:79]
        out = dispatch_pointer(
            root,
            from_seat=seat,
            to_seat=emit_reply_to,
            summary=f"ACK {event_id}: {note}",
            kind="ACK",
            priority=priority,
            hop=0,
            event_id=ack_eid,
            now_ts=now_ep,
        )
        res["reply_ack"] = out
    return res


def build_ssh_peer_command(host_alias: str, remote_bin: str = "starcouncil") -> list[str]:
    """Builds a zero-shell-interpolation SSH argv carrying dynamic JSON exclusively over stdin."""
    if not HOST_ALIAS_RE.fullmatch(host_alias):
        raise ValueError(f"Unsafe ssh host alias: {host_alias}")
    if not remote_bin.strip() or "\n" in remote_bin or "\x00" in remote_bin:
        raise ValueError(f"Unsafe remote binary path: {remote_bin}")
    remote_cmd = f"{shlex.quote(remote_bin)} dispatch --ingest-stdin"
    return ["ssh", "-o", "BatchMode=yes", "-o", "ForwardAgent=no", host_alias, remote_cmd]


def ingest_peer_stdin(root: pathlib.Path, raw_bytes: bytes, now_ts: float | None = None) -> dict[str, Any]:
    if len(raw_bytes) > MAX_STDIN_BYTES:
        raise ValueError(f"STDIN_LIMIT_EXCEEDED ({len(raw_bytes)} > {MAX_STDIN_BYTES})")
    if not all(b < 128 for b in raw_bytes):
        raise ValueError("NON_ASCII_STDIN_REJECTED")
    env = json.loads(raw_bytes.decode("ascii"))
    if not isinstance(env, dict):
        raise ValueError("ENVELOPE_MUST_BE_JSON_OBJECT")

    cfg = load_council_config(root)
    allowed_hosts = set(cfg.get("cluster", {}).get("allowlisted_hosts", ["local"]))
    allowed_seats = {str(s.get("id", "")) for s in cfg.get("seats", []) if s.get("id")}

    from_host = str(env.get("from_host") or "").strip()
    from_seat = str(env.get("from_seat") or "").strip()
    to_seat = str(env.get("to_seat") or "").strip()
    if from_host not in allowed_hosts:
        raise ValueError(f"HOST_NOT_ALLOWLISTED: {from_host}")
    if from_seat not in allowed_seats or to_seat not in allowed_seats:
        raise ValueError(f"SEAT_NOT_ALLOWLISTED: {from_seat}->{to_seat}")

    return dispatch_pointer(
        root,
        from_seat=from_seat,
        to_seat=to_seat,
        summary=str(env.get("summary") or env.get("title") or ""),
        artifact_text=str(env.get("body") or env.get("summary") or ""),
        kind=str(env.get("kind") or "MILESTONE_PASS").upper(),
        priority=str(env.get("priority") or "P1").upper(),
        hop=env.get("hop", 1),
        event_id=str(env.get("event_id") or ""),
        now_ts=now_ts,
    )


def run_with_lock(root: pathlib.Path, resource: str, seat: str, cmd_argv: list[str]) -> int:
    if not RESOURCE_NAME_RE.fullmatch(resource):
        raise ValueError(f"Invalid lock resource name: {resource}")
    if not SEAT_NAME_RE.fullmatch(seat):
        raise ValueError(f"Invalid seat name: {seat}")
    if not cmd_argv:
        raise ValueError("Empty command for lock execution")
    base = sc_dir(root)
    lock_file = base / "locks" / f"{resource}.lock"
    holder_file = base / "locks" / f"{resource}.holder.json"
    with BusLock(lock_file, non_blocking=False):
        atomic_write_json(holder_file, {"seat": seat, "pid": os.getpid(), "acquired_at": utc_iso()})
        append_event_log(root, action="LOCK_ACQUIRE", actor=seat, status="ok", detail={"resource": resource})
        try:
            proc = subprocess.run(cmd_argv, shell=False, check=False)
            rc = int(proc.returncode)
        finally:
            if holder_file.exists():
                holder_file.unlink()
            append_event_log(root, action="LOCK_RELEASE", actor=seat, status="ok", detail={"resource": resource})
        return rc
