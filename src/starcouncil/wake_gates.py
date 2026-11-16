#!/usr/bin/env python3
"""Six-gate 0-Token idle wakeup state machine (`[BUS-WAKE]`) for tmux + AI CLI panes."""

from __future__ import annotations

import re
import time
from typing import Any

WAKE_TOKEN = "[BUS-WAKE]"
MIN_CLIENT_IDLE_SECONDS = 15.0
MAX_WAKE_ATTEMPTS_PER_MSG = 2
RATE_LIMIT_WINDOW_SECONDS = 120.0
RATE_LIMIT_MAX_WAKES = 2
RETRY_COOLDOWN_SECONDS = 30.0

SILENT_FIRST_LINE_PREFIXES = ("【TERMINAL-ACK】", "【INFO-SYNC")
BUSY_SPINNER_RE = re.compile(r"^\s*(?:[\u2800-\u28ff✦✻*•]\s+)?(?:Working|Thinking|Generating)\.{0,3}\s*$")
BUSY_UI_MARKERS = (
    "Working...",
    "Thinking...",
    "esc to interrupt",
    "esc to cancel",
    "Esc to cancel",
    "Allow once",
    "Always allow",
    "BypassSandbox",
    "[y/n]",
    "(y/n)",
)
# Supports bare `>` as well as fresh-session placeholder hints such as `>   Ask anything...`
IDLE_PROMPT_LINE_RE = re.compile(r"^\s*>\s*(?:$|Ask\b|Try\b|Type\b)")


def is_silent_sync_message(text: str) -> bool:
    """Matches terminal/info-sync prefixes ONLY on the first non-empty line to prevent body false-positives."""
    for line in str(text or "").splitlines():
        s = line.strip()
        if s:
            return any(tag in s for tag in SILENT_FIRST_LINE_PREFIXES)
    return False


def is_bare_idle_prompt(capture_lines: list[str], cursor_x: int | None = None) -> bool:
    tail = [ln.rstrip("\r") for ln in capture_lines if ln.strip()][-6:]
    if not tail:
        return False
    joined = "\n".join(tail)
    if any(m in joined for m in BUSY_UI_MARKERS):
        return False
    if any(BUSY_SPINNER_RE.match(ln) for ln in tail):
        return False
    if cursor_x is not None and cursor_x < 2:
        return False
    return any(IDLE_PROMPT_LINE_RE.match(ln) for ln in tail)


def _has_active_foreground_tasks(tasks: list[dict[str, Any]]) -> bool:
    for t in tasks:
        if not isinstance(t, dict):
            continue
        if t.get("isDaemon") is True:
            continue
        desc = str(t.get("description") or "").strip().lower()
        if desc.startswith("cron ("):
            continue
        if str(t.get("status") or "").lower() in ("running", "in_progress", "pending"):
            return True
    return False


def evaluate_six_gates(snapshot: dict[str, Any], now_ts: float | None = None) -> dict[str, Any]:
    """Evaluates all 6 fail-closed wakeup safety gates against a pane + transcript snapshot."""
    now_ep = time.time() if now_ts is None else float(now_ts)
    msg_text = str(snapshot.get("msg_text") or "")
    msg_status = str(snapshot.get("msg_status") or "PENDING").upper()

    if is_silent_sync_message(msg_text):
        return {"wake": False, "gate": "prefix", "reason": "SILENT_FIRST_LINE_PREFIX"}

    if msg_status == "SEEN_AWAITING_HUMAN":
        return {"wake": False, "gate": "human_wait", "reason": "SEEN_AWAITING_HUMAN"}

    # Gate 1: tmux not in copy-mode and foreground is live AI CLI
    if int(snapshot.get("pane_in_mode", 0)) != 0:
        return {"wake": False, "gate": "gate1", "reason": "PANE_IN_COPY_MODE"}
    if str(snapshot.get("pane_fg") or "") not in ("agy", "antigravity") and not snapshot.get("agy_in_tree"):
        return {"wake": False, "gate": "gate1", "reason": "NO_LIVE_AGENT_IN_PANE"}

    # Gate 2: Real human keyboard idle >= 15s (uses client_activity, protects CJK IME composition)
    client_act = float(snapshot.get("client_activity_ts") or 0.0)
    if (now_ep - client_act) < MIN_CLIENT_IDLE_SECONDS:
        return {"wake": False, "gate": "gate2", "reason": "CLIENT_TYPING_ACTIVE"}

    # Gate 3: Idle bare `>` prompt (cursor_x >= 2) and no busy/approval UI chrome
    cap_lines = list(snapshot.get("capture_lines") or [])
    cx = snapshot.get("cursor_x")
    if not is_bare_idle_prompt(cap_lines, cursor_x=int(cx) if cx is not None else None):
        return {"wake": False, "gate": "gate3", "reason": "PROMPT_BUSY_OR_MISSING"}

    # Gate 4: Transcript last step idle PLANNER_RESPONSE (no tool calls) & no non-daemon tasks
    if (
        str(snapshot.get("transcript_last_type") or "") != "PLANNER_RESPONSE"
        or str(snapshot.get("transcript_last_status") or "") != "DONE"
        or bool(snapshot.get("transcript_has_tool_calls"))
    ):
        return {"wake": False, "gate": "gate4", "reason": "TRANSCRIPT_NOT_IDLE"}
    if _has_active_foreground_tasks(list(snapshot.get("running_tasks") or [])):
        return {"wake": False, "gate": "gate4", "reason": "NON_DAEMON_TASK_RUNNING"}

    # Gate 5: Per-seat sliding 120s rate limit
    recent_wakes = [
        float(t) for t in (snapshot.get("recent_seat_wakes") or []) if (now_ep - float(t)) <= RATE_LIMIT_WINDOW_SECONDS
    ]
    if len(recent_wakes) >= RATE_LIMIT_MAX_WAKES:
        return {"wake": False, "gate": "gate5", "reason": "SEAT_RATE_LIMIT_REACHED"}

    # Gate 6: Per-message retry cap + cooldown; transition to SEEN_AWAITING_HUMAN after 2 attempts
    attempts = int(snapshot.get("msg_attempts") or 0)
    last_ts = float(snapshot.get("last_attempt_ts") or 0.0)
    if attempts >= MAX_WAKE_ATTEMPTS_PER_MSG:
        return {
            "wake": False,
            "gate": "gate6",
            "reason": "MAX_ATTEMPTS_SEEN_AWAITING_HUMAN",
            "next_msg_status": "SEEN_AWAITING_HUMAN",
        }
    if attempts >= 1 and (now_ep - last_ts) < RETRY_COOLDOWN_SECONDS:
        return {"wake": False, "gate": "gate6", "reason": "RETRY_COOLDOWN_ACTIVE"}

    return {
        "wake": True,
        "gate": "all_6_passed",
        "reason": "READY_FOR_SPLIT_FRAME_WAKE",
        "frames": [WAKE_TOKEN, "Enter"],
        "split_delay_ms": 90,
    }


def apply_wake_attempt(
    state: dict[str, Any],
    *,
    seat: str,
    msg_id: str,
    frame1_ok: bool,
    frame2_ok: bool,
    now_ts: float | None = None,
) -> dict[str, Any]:
    """Records wake outcome idempotently; emits exact BSpace rollback keys if Enter fails."""
    now_ep = time.time() if now_ts is None else float(now_ts)
    messages = state.setdefault("messages", {})
    seat_wakes = state.setdefault("seat_wakes", {})

    key = f"{seat}:{msg_id}"
    rec = messages.setdefault(key, {"attempts": 0, "last_ts": 0.0, "status": "PENDING"})

    cleanup_keys: list[str] = []
    if frame1_ok:
        rec["attempts"] = int(rec.get("attempts") or 0) + 1
        rec["last_ts"] = now_ep
        hist = [float(t) for t in seat_wakes.get(seat, []) if (now_ep - float(t)) <= RATE_LIMIT_WINDOW_SECONDS]
        hist.append(now_ep)
        seat_wakes[seat] = hist

        if not frame2_ok:
            cleanup_keys = ["BSpace"] * len(WAKE_TOKEN)
            rec["last_error"] = "FRAME2_ENTER_FAILED_BSPACE_CLEANUP"
        elif rec["attempts"] >= MAX_WAKE_ATTEMPTS_PER_MSG:
            rec["status"] = "SEEN_AWAITING_HUMAN"

    return {
        "key": key,
        "attempts": rec["attempts"],
        "status": rec["status"],
        "cooldown_until": (now_ep + RETRY_COOLDOWN_SECONDS) if frame1_ok else 0.0,
        "cleanup_keys": cleanup_keys,
    }
