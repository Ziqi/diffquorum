#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Six-gate 0-Token idle wakeup state machine (`[BUS-WAKE]`) for tmux + AI CLI panes."""

from __future__ import annotations

import math
import re
import time
from typing import Any

WAKE_TOKEN = "[BUS-WAKE]"
MIN_CLIENT_IDLE_SECONDS = 15.0
MAX_WAKE_ATTEMPTS_PER_MSG = 2
RATE_LIMIT_WINDOW_SECONDS = 120.0
RATE_LIMIT_MAX_WAKES = 2
RETRY_COOLDOWN_SECONDS = 30.0
MAX_MESSAGE_WAKE_AGE_SECONDS = 7200.0   # PF-021: 2h cap for plain chat messages
MAX_TICKET_WAKE_AGE_SECONDS = 86400.0   # PF-021: 24h cap for blocked PENDING tickets
COLD_INTERRUPTED_QUIESCENCE_SECONDS = 30.0
STALE_BG_TASK_UNBLOCK_SECONDS = 180.0

SILENT_FIRST_LINE_PREFIXES = ("【TERMINAL-ACK】", "【INFO-SYNC")
SUPPORTED_AGENT_COMMANDS = frozenset({"agy", "antigravity", "claude", "codex", "opencode"})

# Cursor-to-column-1 sequences mark real visual line breaks before CSI stripping
_LINE_START_CSI_RE = re.compile(r"\x1b\[(?:1?G|\d*A|\d*E|\d+;1H)")
_FORWARD_CURSOR_CSI_RE = re.compile(r"\x1b\[\d*[GC]")
_CSI_RE = re.compile(r"(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]")
_OSC_RE = re.compile("\x1b\\][^\x07\x1b]*(?:\x07|\x1b\\\\)")
_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b-\x0c\x0e-\x1f\x7f\x80-\x9a\x9c-\x9f]")

BUSY_SPINNER_RE = re.compile(
    r"^\s*(?:[\u2800-\u28ff✦✻*•✢✳]\s+)?(?:Working|Thinking|Generating|Running|Cultivating)(?:\.{1,3}|…)?(?:\s*\(.*\))?\s*$"
)
PANE_BUSY_CHROME_RE = re.compile(
    r"(?:esc\s+to\s+(?:cancel|interrupt)|[\u2800-\u28ff]|(?:Working|Thinking|Generating|Cultivating)(?:\.{2,3}|…))",
    re.IGNORECASE,
)
# PF-018: narrow mobile terminal idle status bar when `? for shortcuts` is truncated on the left
NARROW_IDLE_FOOTER_RE = re.compile(
    r"^(?:"
    r"(?:auto|ask|plan|safe|default|fast)\s*[·•|]\s*(?:Gemini|Claude|Opus|Sonnet|GPT|Grok|Kimi|\S.*?\s*[·•|]\s*/tasks\b)"
    r"|(?:Gemini|Claude|Opus|Sonnet|GPT|Grok|Kimi)\b.*?[·•|]\s*/tasks\s*$"
    r")",
    re.IGNORECASE,
)
# PF-023: fail-closed conservative multilingual approval & cross-seat revocation scoping
EXPLICIT_APPROVAL_SENTENCE_RE = re.compile(
    r"^(?:(?:好(?:的|吧|嘞)?|行|可以|没问题|ok|okay)[\s,，:：—-]*)?"
    r"(?:"
    r"(?:按(?:照)?(?:你(?:的)?|上述|上面(?:的)?|这个|该|本)?(?:推荐|建议|方案|计划)(?:的)?[\s,，:：—-]*)?"
    r"(?:我(?:们)?[\s,，]*)?"
    r"(?:(?:一起|一并|一块|全部|全都|全|都)[\s,，:：—-]*)?"
    r"(?:approve(?:d)?|同意(?:执行|了)?|批准(?:执行|了)?|确认执行|通过|可以)"
    r"(?:[\s,，:：—-]+"
    r"(?:please|go\s+ahead|proceed|(?:请)?(?:按(?:照)?(?:你(?:的)?|上述|上面(?:的)?|这个|该|本)?(?:推荐|建议|方案|计划))?(?:一起|一并)?(?:开始|继续|直接|立即)?执行(?:吧)?|开始(?:执行)?(?:吧)?))?"
    r"|(?:请)?(?:按(?:照)?|照)(?:这个|该|本|上述|上面(?:的)?|你(?:的)?)(?:推荐|建议|方案|计划)?(?:一起|一并)?(?:直接|立即|开始)?执行(?:吧|了)?"
    r")"
    r"[~～]*$",
    re.IGNORECASE,
)
NEGATED_OR_QUESTION_APPROVAL_RE = re.compile(
    r"(?:\b(?:not|no|never|don'?t|do\s+not|cannot|can'?t|disapprov\w*|unapprov\w*|cancel\w*|abort\w*|revoke\w*|but|however|except|unless|only|wait|hold|stop|pause)\b"
    r"|不(?:同意|批准|准|予批准|通过|要|行|可以|能)|暂不(?:同意|批准|通过|执行)?|先不(?:批|同意|通过|执行)|拒绝|驳回|但是|但|不过|除非|除了|只改|只做|[?？])",
    re.IGNORECASE,
)
FOLLOWUP_RESTRICTION_RE = re.compile(
    r"(?:\b(?:not|no|never|don'?t|do\s+not|no\s+need|disapprov\w*|unapprov\w*|cancel\w*|abort\w*|revoke\w*|but|however|except|unless|only|wait|hold|stop|pause|instead|skip|exclude)\b"
    r"|不(?:同意|批准|准|予批准|(?:要|用|必|需)(?:再)?(?:执行|改|动|做|跑|继续|推进|弄|搞|了))|别|勿|免了|暂不|先不|暂缓|等等|等一下|慢着|算了|但是|不过|除非|除了|只改|只做|先改|先做|跳过|拒绝|驳回)",
    re.IGNORECASE,
)
REVOCATION_RE = re.compile(
    r"(?:\b(?:abort\w*|cancel\w*|revok\w*|rescind\w*|withdraw\w*|veto\w*|reject\w*|refus\w*|"
    r"disapprov\w*|unapprov\w*|stop\w*|halt\w*|paus\w*|hold|wait|never\s*mind|no\s+need(?:\s+to)?|"
    r"(?:do\s+not|don'?t|not|no|never)\s+(?:approve\w*|allow\w*|execut\w*|run\w*|proceed\w*|start\w*|continu\w*|do\b))\b"
    r"|(?:撤回|撤销|作废|收回)(?:批准|审批|授权|同意|决定|指令)?"
    r"|取消(?:执行|任务|计划|授权|审批|批准)?|停止(?:执行)?|停下"
    r"|(?:不用|不必|无需)(?:再)?(?:执行|做|跑|改|动|继续|推进|弄|搞|管|处理|操作|了)"
    r"|(?:不要|别|先别|勿)(?:再)?(?:执行|做|跑|改|动|继续|推进|弄|搞)"
    r"|暂不(?:同意|批准|执行)?|先不(?:批|同意|执行)|暂停(?:执行)?|中止(?:执行)?|终止(?:执行)?"
    r"|不(?:同意|批准|准|批|予批准)|拒绝|驳回|否决|叫停|暂缓|免了|等等|等一下|慢着|算了)",
    re.IGNORECASE,
)
GLOBAL_SCOPE_REVOCATION_RE = re.compile(
    r"(?:\b(?:all|every\w*|other\w*|both)\b|全部|所有|全线|全停|全体|其它|其他|别的|其余|剩下|剩余|全都|一起|统统|一律)",
    re.IGNORECASE,
)
UNIT_SUFFIX_GUARD = r"(?!\s*[%天个元秒分时年月日轮次条步行页批波列]|[-./_0-9a-zA-Z])"
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


def is_silent_sync_message(text: str, *, priority: str = "P2") -> bool:
    """Matches terminal/info-sync prefixes ONLY at start of first non-empty line; P0 is never silent (PF-036)."""
    if str(priority or "").strip().upper() == "P0":
        return False
    for line in str(text or "").splitlines():
        s = line.strip()
        if s:
            return bool(SILENT_LEADING_PREFIX_RE.match(s))
    return False


def is_idle_cli_footer(footer: str) -> bool:
    """Returns True for valid idle CLI footers including wide `? for shortcuts` and narrow mobile bars (PF-018)."""
    s = strip_terminal_escapes(footer).strip()
    if not s:
        return False
    if any(m in s for m in BUSY_UI_MARKERS) or WAITING_MODAL_RE.search(s):
        return False
    if "? for shortcuts" in s or PARTIAL_SHORTCUTS_FOOTER_RE.search(s):
        return True
    return bool(NARROW_IDLE_FOOTER_RE.match(s) or ULTRA_NARROW_FOOTER_RE.match(s))


def is_pane_tail_busy(capture_lines: list[str] | str) -> bool:
    """Detects live busy/deep-thinking CLI chrome in the last 8 non-empty lines without prose false positives (PF-025)."""
    raw_lines = capture_lines.splitlines() if isinstance(capture_lines, str) else list(capture_lines or [])
    tail = [strip_terminal_escapes(ln).rstrip() for ln in raw_lines if strip_terminal_escapes(ln).strip()][-8:]
    for ln in tail:
        if PANE_BUSY_CHROME_RE.search(ln) or BUSY_SPINNER_RE.match(ln):
            return True
    return False


def classify_seat_state(
    *,
    online: bool,
    is_daemon: bool = False,
    pane_busy: bool = False,
    awaiting_approve: bool = False,
    transcript_busy: bool = False,
    copy_mode: bool = False,
) -> str:
    """Returns an exact <=8-char seat state tag preserving dual copy-mode states (PF-022 & PF-025)."""
    if not online:
        return "OFFLINE"
    if is_daemon:
        return "DAEMON"
    if pane_busy:
        return "WORK+CPY" if copy_mode else "WORKING"
    if awaiting_approve:
        return "WAIT+CPY" if copy_mode else "WAIT_APP"
    if transcript_busy:
        return "WORK+CPY" if copy_mode else "WORKING"
    if copy_mode:
        return "COPY-MOD"
    return "IDLE"


def is_explicit_approval_text(text: str) -> bool:
    """Fail-closed check supporting both leading and multi-sentence trailing human approvals (PF-023 & PF-031)."""
    cleaned = str(text or "").replace("\r\n", "\n").replace("\r", "\n").strip().strip("\"'“”‘’`").strip()
    if not cleaned or len(cleaned) > 600:
        return False
    if REVOCATION_RE.search(cleaned):
        return False
    sentences = [
        s.strip().strip("\"'“”‘’`").strip()
        for s in re.findall(r"[^。.!！?？;；\n]+[?？]*", cleaned)
        if s.strip().strip("\"'“”‘’`").strip()
    ]
    if not sentences:
        return False
    approval_indices = [
        idx
        for idx, sent in enumerate(sentences)
        if not NEGATED_OR_QUESTION_APPROVAL_RE.search(sent) and EXPLICIT_APPROVAL_SENTENCE_RE.fullmatch(sent)
    ]
    if not approval_indices:
        return False
    first_idx = approval_indices[0]
    app_set = set(approval_indices)
    for idx, sent in enumerate(sentences):
        if idx in app_set:
            continue
        if FOLLOWUP_RESTRICTION_RE.search(sent):
            return False
        if idx < first_idx and NEGATED_OR_QUESTION_APPROVAL_RE.search(sent):
            return False
        if idx > first_idx and ("?" in sent or "？" in sent) and not POST_APPROVAL_CONFIRM_Q_RE.search(sent):
            return False
    return True


def _extract_clause_seats(clause: str, known_seats: dict[str, tuple[str, ...]]) -> set[str]:
    mentioned: set[str] = set()
    for canon, aliases in known_seats.items():
        for alias in aliases:
            tok = alias.strip()
            if not tok:
                continue
            if tok.isdigit():
                pat = re.compile(rf"(?<![0-9a-zA-Z./\-_第]){re.escape(tok)}{UNIT_SUFFIX_GUARD}")
            else:
                pat = re.compile(rf"(?<![0-9a-zA-Z_-]){re.escape(tok)}(?![0-9a-zA-Z_-])", re.IGNORECASE)
            if pat.search(clause):
                mentioned.add(canon)
                break
    return mentioned


def revocation_applies_to_scope(
    text: str,
    *,
    from_seat: str,
    to_seat: str,
    known_seats: dict[str, tuple[str, ...]],
) -> bool:
    """Fail-closed revocation check: revokes unless EVERY revocation clause explicitly names ONLY unrelated seats (PF-023)."""
    if not REVOCATION_RE.search(text):
        return False
    clauses = [c.strip() for c in re.split(r"[。.!！?？;\n；，,]+", text) if c.strip()]
    matched_any = False
    for clause in clauses:
        if not REVOCATION_RE.search(clause):
            continue
        matched_any = True
        if GLOBAL_SCOPE_REVOCATION_RE.search(clause):
            return True
        mentioned = _extract_clause_seats(clause, known_seats)
        if not mentioned or to_seat in mentioned or from_seat in mentioned:
            return True
    return not matched_any


def is_bare_idle_prompt(capture_lines: list[str], cursor_x: int | None = None) -> bool:
    cleaned = [strip_terminal_escapes(ln).rstrip() for ln in capture_lines]
    tail = [ln for ln in cleaned if ln.strip()][-10:]
    if not tail:
        return False
    joined = "\n".join(tail)
    if WAITING_MODAL_RE.search(joined):
        return False
    if any(m in joined for m in BUSY_UI_MARKERS) or is_pane_tail_busy(tail):
        return False
    if cursor_x is not None and cursor_x < 2:
        return False
    if any(IDLE_PROMPT_LINE_RE.match(ln) for ln in tail):
        return True
    return is_idle_cli_footer(tail[-1])


def _has_active_foreground_tasks(tasks: list[dict[str, Any]]) -> bool:
    for t in tasks:
        if not isinstance(t, dict):
            continue
        raw_daemon = t.get("isDaemon")
        if raw_daemon is True or str(raw_daemon or "").strip().lower() == "true":
            continue
        if str(t.get("kind") or "").strip().lower() in ("timer", "cron", "schedule", "daemon"):
            continue
        desc = str(t.get("description") or "").strip()
        out_tail = str(t.get("output_tail") or "")
        if SCHEDULE_TASK_DESC_RE.search(desc) or DAEMON_READY_OUTPUT_RE.search(out_tail):
            continue
        if str(t.get("status") or "").lower() in ("running", "in_progress", "pending"):
            return True
    return False


def is_stale_bg_quiescent_for_unblock(
    *,
    transcript_age_sec: float | None,
    task_log_ages_sec: list[float] | tuple[float, ...] = (),
    threshold_sec: float = STALE_BG_TASK_UNBLOCK_SECONDS,
) -> bool:
    """
    Exempts hung non-daemon background commands (e.g. a silent `ssh ... tail -f`) from
    permanently deadlocking Gate 3/4 wakeups ONLY when BOTH the transcript AND every
    background task log/metadata file have had zero writes for `>= threshold_sec` (default 180s).
    """
    if isinstance(threshold_sec, bool) or not isinstance(threshold_sec, (int, float)):
        return False
    try:
        thresh = float(threshold_sec)
    except OverflowError:
        return False
    if not math.isfinite(thresh) or thresh <= 0.0:
        return False
    if transcript_age_sec is None or isinstance(transcript_age_sec, bool) or not isinstance(transcript_age_sec, (int, float)):
        return False
    try:
        tx_a = float(transcript_age_sec)
    except OverflowError:
        return False
    if not math.isfinite(tx_a) or tx_a < thresh:
        return False
    if not isinstance(task_log_ages_sec, (list, tuple)):
        return False
    for raw_age in task_log_ages_sec:
        if isinstance(raw_age, bool) or not isinstance(raw_age, (int, float)):
            return False
        try:
            age_f = float(raw_age)
        except OverflowError:
            return False
        if not math.isfinite(age_f) or age_f < thresh:
            return False
    return True


def is_cold_interrupted_idle(
    last_type: str,
    last_status: str,
    transcript_age_sec: float | None,
) -> bool:
    """Allows safe auto-recovery when a stream disconnect (`ERROR_MESSAGE`) or cold restart settles >=30s."""
    if transcript_age_sec is None or float(transcript_age_sec) < COLD_INTERRUPTED_QUIESCENCE_SECONDS:
        return False
    t_up = str(last_type or "").strip().upper()
    s_up = str(last_status or "").strip().upper()
    if s_up in ("CANCELED", "CANCELLED", "INTERRUPTED", "ABORTED", "ERROR", "FAILED"):
        return True
    if t_up in ("GENERIC", "USER_INPUT", "SYSTEM_MESSAGE", "ERROR_MESSAGE") and s_up == "DONE":
        return True
    return False


def evaluate_six_gates(snapshot: dict[str, Any], now_ts: float | None = None) -> dict[str, Any]:
    """Evaluates all 6 fail-closed wakeup safety gates against a pane + transcript snapshot."""
    now_ep = time.time() if now_ts is None else float(now_ts)
    msg_text = str(snapshot.get("msg_text") or "")
    msg_status = str(snapshot.get("msg_status") or "PENDING").upper()
    priority = str(snapshot.get("priority") or "P2").strip().upper()
    item_kind = str(snapshot.get("item_kind") or "msg").strip().lower()

    if is_silent_sync_message(msg_text, priority=priority):
        return {"wake": False, "gate": "prefix", "reason": "SILENT_FIRST_LINE_PREFIX"}

    if msg_status == "SEEN_AWAITING_HUMAN":
        return {"wake": False, "gate": "human_wait", "reason": "SEEN_AWAITING_HUMAN"}

    # PF-021: decoupled wakeup TTL (2h for plain chat messages, 24h for blocked PENDING tickets)
    item_age_raw = snapshot.get("item_age_sec")
    if item_age_raw is not None:
        item_kind = str(snapshot.get("item_kind") or "msg").strip().lower()
        max_age = MAX_TICKET_WAKE_AGE_SECONDS if item_kind == "ticket" else MAX_MESSAGE_WAKE_AGE_SECONDS
        if float(item_age_raw) > max_age:
            reason = "TICKET_WAKE_TTL_EXPIRED" if item_kind == "ticket" else "MESSAGE_WAKE_TTL_EXPIRED"
            return {"wake": False, "gate": "ttl", "reason": reason}

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

    # Gate 4: Transcript last step idle PLANNER_RESPONSE (or quiescent interrupted/ERROR_MESSAGE) & no non-daemon tasks
    last_type = str(snapshot.get("transcript_last_type") or "")
    last_status = str(snapshot.get("transcript_last_status") or "")
    tx_mtime_val = snapshot.get("transcript_mtime_ts")
    tx_age = (now_ep - float(tx_mtime_val)) if tx_mtime_val is not None else snapshot.get("transcript_age_sec")
    normal_idle = (
        last_type == "PLANNER_RESPONSE"
        and last_status == "DONE"
        and not bool(snapshot.get("transcript_has_tool_calls"))
    )
    if not normal_idle and not is_cold_interrupted_idle(last_type, last_status, tx_age):
        return {"wake": False, "gate": "gate4", "reason": "TRANSCRIPT_NOT_IDLE"}
    if _has_active_foreground_tasks(list(snapshot.get("running_tasks") or [])):
        stale_unblock = False
        if snapshot.get("allow_stale_bg_unblock") is True and "task_log_ages_sec" in snapshot:
            thresh_val = snapshot.get("stale_bg_threshold_sec", STALE_BG_TASK_UNBLOCK_SECONDS)
            stale_unblock = is_stale_bg_quiescent_for_unblock(
                transcript_age_sec=tx_age,
                task_log_ages_sec=snapshot.get("task_log_ages_sec"),
                threshold_sec=thresh_val,
            )
        if not stale_unblock:
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

    # Gate 6: Per-message retry cap + P0/P1 ticket backoff + report-no-reply single-wake cap (PF-030 & PF-036)
    attempts = int(snapshot.get("msg_attempts") or 0)
    last_ts = float(snapshot.get("last_attempt_ts") or 0.0)
    is_high_prio_tkt = item_kind == "ticket" and priority in ("P0", "P1")
    max_attempts = 1 if (bool(snapshot.get("is_report_no_reply")) or is_report_no_reply_message(msg_text)) else MAX_WAKE_ATTEMPTS_PER_MSG
    if is_high_prio_tkt:
        cooldown_req = compute_high_prio_ticket_backoff(attempts)
        if attempts >= 1 and (now_ep - last_ts) < cooldown_req:
            return {"wake": False, "gate": "gate6", "reason": "RETRY_COOLDOWN_ACTIVE"}
    else:
        if attempts >= max_attempts:
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


# --- v0.3 Wave C: Anti-Stall, Orthogonal Report-No-Reply, Receipt Wake & Cache Guards ---
HIGH_PRIO_BACKOFF_SCHEDULE = (30.0, 60.0, 180.0)
STALE_COPY_MODE_AUTO_EXIT_SECONDS = 180.0
HUMAN_REPLY_SCROLL_GUARD_SECONDS = 300.0
HOST_APPROVAL_CACHE_MAX_AGE_SECONDS = 30.0

SILENT_LEADING_PREFIX_RE = re.compile(
    r"^\s*(?:【TERMINAL-ACK】|【INFO-SYNC\b|\[TERMINAL-ACK\]|\[INFO-SYNC\b)",
    re.IGNORECASE,
)
REPORT_NO_REPLY_PREFIX_RE = re.compile(
    r"^\s*(?:【交卷免回】|【REPORT-NO-REPLY】|\[REPORT-NO-REPLY\])",
    re.IGNORECASE,
)
PARTIAL_SHORTCUTS_FOOTER_RE = re.compile(
    r"(?:\?\s+for\s+short\w*|(?:…|\.{2,3})\s*for\s+shortcuts\b)",
    re.IGNORECASE,
)
ULTRA_NARROW_FOOTER_RE = re.compile(
    r"^(?:[⏵▸▶>]+\s*)?(?:"
    r"(?:auto|ask|plan|safe|default|fast)(?:\s+mode)?(?:\s*$|\s*(?:…|\.{2,3})\s*$|\s*[·•|—-]\s*\S.*$)"
    r"|(?:…|\.{2,3}|\S.*?)?\s*[·•|]\s*/tasks(?:\s*\(\d+\)|\s*(?:…|\.{2,3}))?\s*$"
    r")",
    re.IGNORECASE,
)
DAEMON_READY_OUTPUT_RE = re.compile(
    r"(?:Ready\s+on\s+https?://|Listening\s+on\s+https?://|serving\s+at\s+https?://)",
    re.IGNORECASE,
)
POST_APPROVAL_CONFIRM_Q_RE = re.compile(
    r"(?:对吧|是吧|好吧|行吧|没问题吧|可以吧|\bright\s*\?)[?？]*$",
    re.IGNORECASE,
)


def is_report_no_reply_message(text: str) -> bool:
    """Returns True when the first non-empty line carries orthogonal `【交卷免回】` / `【REPORT-NO-REPLY】`."""
    for line in str(text or "").splitlines():
        s = line.strip()
        if s:
            return bool(REPORT_NO_REPLY_PREFIX_RE.match(s))
    return False


def compute_high_prio_ticket_backoff(attempts: int) -> float:
    """Returns bounded exponential retry cooldown `(30s, 60s, 180s)` for `P0/P1` tickets without 2-attempt death."""
    if attempts <= 0:
        return 0.0
    idx = min(int(attempts) - 1, len(HIGH_PRIO_BACKOFF_SCHEDULE) - 1)
    return HIGH_PRIO_BACKOFF_SCHEDULE[idx]


def should_auto_exit_stale_copy_mode(
    *,
    pane_in_mode: bool,
    min_client_idle_sec: float,
    threshold_sec: float = STALE_COPY_MODE_AUTO_EXIT_SECONDS,
    protected_session: bool = False,
) -> bool:
    """Safely clears forgotten tmux `copy-mode` only when session is unprotected and all clients are idle >= threshold."""
    if not pane_in_mode or protected_session:
        return False
    return float(min_client_idle_sec) >= float(threshold_sec)


def classify_wake_block_code(reason: str) -> str:
    """Maps a low-level gate rejection reason string into a compact observable HUD diagnostic code."""
    r = str(reason or "").lower()
    if "copy_mode" in r or "copy-mode" in r:
        return "COPY_MODE"
    if "client" in r or "typing" in r:
        return "CLIENT_ACTIVE"
    if "modal" in r or "user_answer" in r:
        return "MODAL_WAIT"
    if "spinner" in r or "chrome_busy" in r:
        return "SPINNER_ACTIVE"
    if "footer" in r or "prompt" in r:
        return "PROMPT_OR_FOOTER"
    if "awaiting_human_approve" in r:
        return "WAIT_APPROVE"
    if "daemon" in r or "task_running" in r:
        return "FG_TASK_BUSY"
    if "transcript" in r:
        return "TRANSCRIPT_BUSY"
    if "rate_limit" in r:
        return "RATE_LIMIT"
    return "GATE_BLOCKED"


def should_defer_low_priority_wake(
    *,
    human_reply_age_sec: float | None,
    priority: str = "P2",
    approved_passthrough: bool = False,
    primary_seat_sender: bool = False,
    window_sec: float = HUMAN_REPLY_SCROLL_GUARD_SECONDS,
) -> bool:
    """Defers P2/P3 background wakes within `window_sec` of a fresh reply to the user to prevent scroll-off."""
    if human_reply_age_sec is None or float(human_reply_age_sec) < 0.0:
        return False
    prio = str(priority or "P2").strip().upper()
    if prio in ("P0", "P1") or approved_passthrough or primary_seat_sender:
        return False
    return float(human_reply_age_sec) < float(window_sec)


def collect_terminal_ticket_receipts(
    tickets: list[dict[str, Any]],
    woken_receipts: dict[str, float],
    *,
    watermark_ts: float = 0.0,
) -> list[dict[str, str]]:
    """Returns orthogonal single-shot receipt wakeups `(ticket_id, status)` for `WAITING_REVIEW | DONE | BLOCKED`."""
    ready: list[dict[str, str]] = []
    for tdoc in tickets:
        if not isinstance(tdoc, dict):
            continue
        tid = str(tdoc.get("ticket_id") or "").strip()
        status = str(tdoc.get("status") or "").strip().upper()
        from_seat = str(tdoc.get("from_seat") or "").strip()
        updated_ts = float(tdoc.get("updated_epoch") or 0.0)
        if not tid or not from_seat or status not in ("WAITING_REVIEW", "DONE", "BLOCKED"):
            continue
        if bool(tdoc.get("receipt_notified_to_sender")):
            continue
        if watermark_ts > 0.0 and updated_ts > 0.0 and updated_ts < watermark_ts:
            continue
        rkey = f"{tid}:{status}"
        if rkey in woken_receipts:
            continue
        ready.append({"receipt_key": rkey, "ticket_id": tid, "status": status, "to_seat": from_seat})
    return ready


def verify_cached_host_approval(
    cache_doc: dict[str, Any] | None,
    anchor: dict[str, Any] | None,
    *,
    now_ts: float,
    max_age_sec: float = HOST_APPROVAL_CACHE_MAX_AGE_SECONDS,
) -> tuple[bool, str]:
    """Fail-closed verifier for host-side pre-verified approval cache (protects sandboxed seats)."""
    if not isinstance(cache_doc, dict) or not isinstance(anchor, dict):
        return False, "MISSING_CACHE_OR_ANCHOR"
    if cache_doc.get("ok") is not True:
        return False, "CACHE_NOT_OK"
    verified_ep = float(cache_doc.get("verified_epoch") or 0.0)
    age = float(now_ts) - verified_ep
    if verified_ep <= 0.0 or age < -5.0 or age > float(max_age_sec):
        return False, "CACHE_STALE"
    for field in ("conv_id", "step_index", "content_sha256"):
        if cache_doc.get(field) != anchor.get(field):
            return False, f"ANCHOR_MISMATCH_{field.upper()}"
    return True, "VERIFIED_HOST_CACHE"
