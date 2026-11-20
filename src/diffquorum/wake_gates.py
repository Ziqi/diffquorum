#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
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
SUPPORTED_AGENT_COMMANDS = frozenset({"agy", "antigravity", "claude", "codex", "opencode"})

# Cursor-to-column-1 sequences mark real visual line breaks before CSI stripping
_LINE_START_CSI_RE = re.compile(r"\x1b\[(?:1?G|\d*A|\d*E|\d+;1H)")
_FORWARD_CURSOR_CSI_RE = re.compile(r"\x1b\[\d*[GC]")
_CSI_RE = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
_OSC_RE = re.compile("\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)")
_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f\x80-\x9a\x9c-\x9f]")

BUSY_SPINNER_RE = re.compile(
    r"^\s*(?:[\u2800-\u28ff✦✻*•✢✳]\s+)?(?:Working|Thinking|Generating|Running|Cultivating)(?:\.{1,3}|…)\s*$"
)
BUSY_UI_MARKERS = (
    "Working...",
    "Working…",
    "Thinking...",
    "Thinking…",
    "Generating...",
    "Generating…",
    "esc to interrupt",
    "esc to cancel",
    "Esc to cancel",
)
# Blocking interactive modals can render ABOVE `? for shortcuts`; check before idle prompts.
WAITING_MODAL_RE = re.compile(
    r"(?:Yes,\s*I trust this folder"
    r"|requires permission to read,\s*edit"
    r"|How'?s the CLI experience so far"
    r"|↑/↓\s*(?:to\s*)?[Nn]avigate"
    r"|enter\s+(?:Toggle|Confirm)"
    r"|Allow once|Always allow|Allow always|BypassSandbox"
    r"|Do you want to (?:allow|run|proceed)"
    r"|\[y/n\]|\(y/n\))",
    re.IGNORECASE,
)
# Supports bare `>`, Codex `›`, and fresh-session placeholder hints such as `>   Ask anything...`
IDLE_PROMPT_LINE_RE = re.compile(r"^\s*[>›]\s*(?:$|Ask\b|Try\b|Type\b)")

# PF-016: standing timers & cron schedules are background daemons and must not block idle wakeups.
SCHEDULE_TASK_DESC_RE = re.compile(
    r"(?:^cron\s*\(|\btimer\s+running\b|^timer\s*:|\bone-shot\s+timer\b|\bscheduled\s+timer\b)",
    re.IGNORECASE,
)

# PF-017: runtime trailing XML metadata wrappers appended after </USER_REQUEST>.
_USER_REQ_OPEN_RE = re.compile(r"<USER_REQUEST>", re.IGNORECASE)
_USER_REQ_CLOSE_RE = re.compile(r"</USER_REQUEST>", re.IGNORECASE)
_USER_REQ_BODY_RE = re.compile(r"<USER_REQUEST>(.*?)</USER_REQUEST>", re.IGNORECASE | re.DOTALL)
_TRAILING_META_RE = re.compile(
    r"<(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE)>.*?</(?:ADDITIONAL_METADATA|USER_SETTINGS_CHANGE)>",
    re.IGNORECASE | re.DOTALL,
)

# Gate 4 stale awaiting-human-approval markers (can be bypassed only by a strictly newer ready ticket).
AWAITING_APPROVE_MARKERS = (
    "请先审核上面的计划",
    "回复“approve”",
    '回复"approve"',
    "awaiting human approval",
    'reply "approve"',
)


def extract_user_request_text(raw: str) -> str:
    """Unwraps <USER_REQUEST> safely while stripping trailing runtime XML metadata and blocking nested tags (PF-017)."""
    text = str(raw or "")
    opens = len(_USER_REQ_OPEN_RE.findall(text))
    closes = len(_USER_REQ_CLOSE_RE.findall(text))
    if opens > 1 or closes > 1 or opens != closes:
        raise ValueError("NESTED_OR_UNBALANCED_USER_REQUEST_TAG")
    if opens == 1:
        match = _USER_REQ_BODY_RE.search(text)
        if not match:
            raise ValueError("NESTED_OR_UNBALANCED_USER_REQUEST_TAG")
        return match.group(1).strip()
    cleaned = _TRAILING_META_RE.sub("", text)
    return cleaned.strip()


def is_awaiting_human_approve(text: str) -> bool:
    """Detects whether a transcript tail is parked waiting for explicit human plan approval."""
    low = str(text or "").lower()
    return any(marker in low for marker in AWAITING_APPROVE_MARKERS)


def strip_terminal_escapes(text: str) -> str:
    """Strips ANSI CSI/OSC escapes and normalizes terminal cursor moves cleanly."""
    normalized = _LINE_START_CSI_RE.sub("\n", str(text or ""))
    normalized = _FORWARD_CURSOR_CSI_RE.sub(" ", normalized)
    normalized = _OSC_RE.sub("", normalized)
    normalized = _CSI_RE.sub("", normalized)
    normalized = _CTRL_CHARS_RE.sub("", normalized)
    return normalized.replace("\r\n", "\n").replace("\r", "\n")


def is_silent_sync_message(text: str) -> bool:
    """Matches terminal/info-sync prefixes ONLY on the first non-empty line to prevent body false-positives."""
    for line in str(text or "").splitlines():
        s = line.strip()
        if s:
            return any(tag in s for tag in SILENT_FIRST_LINE_PREFIXES)
    return False


def is_bare_idle_prompt(capture_lines: list[str], cursor_x: int | None = None) -> bool:
    cleaned = [strip_terminal_escapes(ln).rstrip() for ln in capture_lines]
    tail = [ln for ln in cleaned if ln.strip()][-10:]
    if not tail:
        return False
    joined = "\n".join(tail)
    if WAITING_MODAL_RE.search(joined):
        return False
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
        if str(t.get("kind") or "").strip().lower() in ("timer", "cron", "schedule"):
            continue
        desc = str(t.get("description") or "").strip()
        if SCHEDULE_TASK_DESC_RE.search(desc):
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
    pane_fg = str(snapshot.get("pane_fg") or "").strip().lower()
    agent_in_tree = bool(snapshot.get("agy_in_tree") or snapshot.get("agent_in_tree"))
    if pane_fg not in SUPPORTED_AGENT_COMMANDS and not agent_in_tree:
        return {"wake": False, "gate": "gate1", "reason": "NO_LIVE_AGENT_IN_PANE"}

    # Gate 2: Real human keyboard idle >= 15s (uses client_activity, protects CJK IME composition)
    client_act = float(snapshot.get("client_activity_ts") or 0.0)
    if (now_ep - client_act) < MIN_CLIENT_IDLE_SECONDS:
        return {"wake": False, "gate": "gate2", "reason": "CLIENT_TYPING_ACTIVE"}

    # Gate 3: Idle bare `>` prompt (cursor_x >= 2), no modals, no busy spinners
    cap_lines = list(snapshot.get("capture_lines") or [])
    cleaned_tail = "\n".join(strip_terminal_escapes(ln) for ln in cap_lines[-10:])
    if WAITING_MODAL_RE.search(cleaned_tail):
        return {"wake": False, "gate": "gate3", "reason": "WAITING_USER_ANSWER"}
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
    awaiting_approve = bool(snapshot.get("transcript_awaiting_human_approve")) or is_awaiting_human_approve(
        str(snapshot.get("transcript_last_text") or "")
    )
    if awaiting_approve:
        tx_mtime = float(snapshot.get("transcript_mtime_ts") or 0.0)
        newest_ticket_ts = float(snapshot.get("newest_ready_ticket_ts") or 0.0)
        if newest_ticket_ts <= 0.0 or newest_ticket_ts <= tx_mtime:
            return {"wake": False, "gate": "gate4", "reason": "AWAITING_HUMAN_APPROVE"}

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
