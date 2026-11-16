#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Quorum verification, Stage-2 blind anonymization, pitfalls/fixes ledgers, review Andon cord & sanitize-lint."""

from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import os
import pathlib
import random
import re
import tarfile
from typing import Any

from .blackboard import (
    MAX_BOARD_BYTES,
    MAX_ENVELOPE_BYTES,
    SEAT_NAME_RE,
    append_event_log,
    atomic_write_json,
    atomic_write_text,
    dq_dir,
    ensure_safe_dir,
    load_council_config,
    read_board,
    read_json_nofollow,
    utc_iso,
)

TOPIC_TAG_KEYWORDS: dict[str, tuple[str, ...]] = {
    "arch": ("架构", "底座", "总线", "通信", "沙箱", "隔离", "守护", "architecture", "harness", "ipc", "bus"),
    "skill": ("skill", "技能", "工作流", "workflow", "starcouncil", "diffquorum", "圆桌", "联席"),
    "retro": ("经验", "复盘", "踩坑", "好招", "总结", "教训", "pitfall", "retro", "learn"),
    "outreach": ("发帖", "推广", "社区", "宣发", "outreach", "release", "blog"),
    "code": ("代码", "cli", "测试", "单测", "bug", "test", "refactor", "fix"),
    "security": ("安全", "权限", "漏洞", "注入", "锁", "凭证", "脱敏", "security", "sanitize"),
}

MEETING_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")
DIFF_HASH_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
MODEL_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{1,63}$")
VALID_SOURCE_KINDS = ("local_seat", "remote_node", "external_llm", "subagent")

HOME_PATH_RE = re.compile(r"/(?:Users|home)/([A-Za-z0-9_.-]+)")
VOLUME_PATH_RE = re.compile(r"/Volumes/([A-Za-z0-9_.\-\u4e00-\u9fff]+)")
PRIVATE_IP_RE = re.compile(
    r"\b(?:"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}|"
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}"
    r")\b"
)
REAL_UUID_RE = re.compile(
    r"\b(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)

ROBOTIC_JARGON_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"双向强绑定", "直接说“两边核对一致”"),
    (r"自适应(?:降级与)?扩容矩阵", "直接说“支持不同电脑和订阅组合”"),
    (r"全员陪会综合征", "直接说“不拉无关窗口陪跑”"),
    (r"【TERMINAL-ACK】|【INFO-SYNC", "内部防循环标记不要直接贴给用户看"),
    (r"\b[0-9a-f]{64}\b", "长串 SHA-256 指纹放台账里，给用户的总结不用贴"),
)

DEFAULT_CLEAN_PLACEHOLDER_USERS = frozenset({"example", "user", "dev", "tester", "demo"})
DEFAULT_FORBID_ENV_KEYS = ("DIFFQUORUM_FORBID_WORDS", "STARCOUNCIL_FORBID_WORDS")

RUNNER_PRESETS: dict[str, dict[str, Any]] = {
    "agy-hydrogen": {
        "description": "Optional headless Antigravity runner bypassing built-in Flash fallback via pointer slices.",
        "planner_model": "gemini-4-carbon-high",
        "default_model": "gemini-4-hydrogen-high",
        "escalate_model": "gemini-4-hydrogen-xhigh",
        "argv_template": ["agy", "--model", "{model}", "-p", "{prompt}", "--output-format", "json"],
        "preflight_cli": "agy",
        "notes": (
            "Optional Antigravity helper: High (~15.6s/33.6k tok) for <=5 files & <=400 LOC; "
            "escalate to XHigh (~34.4s/74.3k tok) only for multi-file coupling or post-High failure. "
            "Requires writable ~/.gemini/antigravity-cli state dir."
        ),
    },
    "claude-sub": {
        "description": "Isolated headless Claude CLI worker pinned explicitly to avoid explore Opus drain.",
        "planner_model": "claude-opus-4-6",
        "default_model": "claude-sonnet-4-5",
        "escalate_model": "claude-opus-4-6",
        "argv_template": ["claude", "-p", "{prompt}", "--model", "{model}", "--output-format", "json"],
        "preflight_cli": "claude",
        "notes": "Single-task isolated context via pointer spec; check exit code and output JSON model field.",
    },
    "codex": {
        "description": "Isolated headless Codex CLI runner driven from a <400B task pointer.",
        "planner_model": "gpt-5.3-codex",
        "default_model": "gpt-5.3-codex",
        "escalate_model": "gpt-5.3-codex",
        "argv_template": ["codex", "exec", "-m", "{model}", "{prompt}"],
        "preflight_cli": "codex",
        "notes": "Pair with diffquorum preflight --write-path before non-interactive execution.",
    },
    "generic-ptr": {
        "description": "Vendor-neutral pointer-first execution contract (<400B TaskSpec -> ResultReceipt).",
        "planner_model": "planner-high",
        "default_model": "executor-default",
        "escalate_model": "executor-heavy",
        "argv_template": ["diffquorum", "dispatch", "--summary", "{prompt}"],
        "preflight_cli": "",
        "notes": "Zero vendor lock-in: exchange <400B pointer paths instead of pasting multi-turn transcripts.",
    },
}


def infer_tags(topic: str, explicit_tags: str = "") -> list[str]:
    if explicit_tags.strip():
        tags = [t.strip().lower() for t in explicit_tags.split(",") if t.strip()]
        return sorted(dict.fromkeys(tags)) or ["general"]
    low = topic.lower()
    matched = [tag for tag, kws in TOPIC_TAG_KEYWORDS.items() if any(kw in low for kw in kws)]
    return matched or ["general"]


def read_recent_pitfalls(root: pathlib.Path, limit: int = 5) -> list[str]:
    p = dq_dir(root) / "pitfalls.md"
    if not p.is_file() or p.is_symlink():
        return []
    bullets = [ln.strip() for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip().startswith("- ")]
    return bullets[-limit:]


def log_pitfall(root: pathlib.Path, *, title: str, root_cause: str, guard: str = "", actor: str = "cli") -> dict[str, Any]:
    if not title.strip() or not root_cause.strip():
        raise ValueError("title and root_cause must be non-empty")
    base = dq_dir(root)
    p = base / "pitfalls.md"
    existing = p.read_text(encoding="utf-8") if p.is_file() else "# Shift-Left Pitfalls Ledger\n\n"
    guard_part = f" | guard: {guard.strip()}" if guard.strip() else ""
    bullet = f"- [{utc_iso()}] **{title.strip()}**: {root_cause.strip()}{guard_part}\n"
    atomic_write_text(p, existing.rstrip() + "\n" + bullet)
    append_event_log(root, action="LOG_PITFALL", actor=actor, status="ok", detail={"title": title.strip()[:80]})
    return {"ok": True, "path": str(p), "entry": bullet.strip()}


def log_fix(root: pathlib.Path, *, title: str, fix_summary: str, files: str = "", actor: str = "cli") -> dict[str, Any]:
    if not title.strip() or not fix_summary.strip():
        raise ValueError("title and fix_summary must be non-empty")
    base = dq_dir(root)
    p = base / "fixes_log.md"
    existing = p.read_text(encoding="utf-8") if p.is_file() else "# Verified Fixes Log\n\n"
    files_part = f" (`{files.strip()}`)" if files.strip() else ""
    bullet = f"- [{utc_iso()}] **{title.strip()}**: {fix_summary.strip()}{files_part}\n"
    atomic_write_text(p, existing.rstrip() + "\n" + bullet)
    append_event_log(root, action="LOG_FIX", actor=actor, status="ok", detail={"title": title.strip()[:80]})
    return {"ok": True, "path": str(p), "entry": bullet.strip()}


def quorum_submit(
    root: pathlib.Path,
    *,
    meeting_id: str,
    author: str,
    source_kind: str,
    content: str,
    diff_sha256: str = "",
) -> dict[str, Any]:
    """Stores an independent participant's raw submission, optional git diff hash, and SHA-256 fingerprint."""
    if not MEETING_ID_RE.fullmatch(meeting_id):
        raise ValueError(f"Invalid meeting_id: {meeting_id}")
    if not SEAT_NAME_RE.fullmatch(author):
        raise ValueError(f"Invalid author identifier: {author}")
    if source_kind not in VALID_SOURCE_KINDS:
        raise ValueError(f"Invalid source_kind '{source_kind}'; expected one of {VALID_SOURCE_KINDS}")
    clean_diff = diff_sha256.strip()
    if clean_diff and not DIFF_HASH_RE.fullmatch(clean_diff):
        raise ValueError(f"Invalid diff_sha256 format: {clean_diff}")
    body = content.strip()
    if not body:
        raise ValueError("Submission content must be non-empty")

    sub_dir = dq_dir(root) / "meetings" / meeting_id / "submissions"
    ensure_safe_dir(sub_dir)
    stem = f"{author}__{source_kind}"
    md_path = sub_dir / f"{stem}.md"
    meta_path = sub_dir / f"{stem}.json"

    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    atomic_write_text(md_path, body + "\n")
    meta = {
        "meeting_id": meeting_id,
        "author": author,
        "source_kind": source_kind,
        "submitted_at": utc_iso(),
        "content_sha256": digest,
        "diff_sha256": clean_diff,
        "rel_file": f"submissions/{stem}.md",
    }
    atomic_write_json(meta_path, meta)
    append_event_log(
        root,
        action="QUORUM_SUBMIT",
        actor=author,
        status="ok",
        detail={"meeting_id": meeting_id, "source_kind": source_kind, "sha256_12": digest[:12]},
    )
    return {
        "ok": True,
        "meeting_id": meeting_id,
        "author": author,
        "source_kind": source_kind,
        "content_sha256": digest,
        "diff_sha256": clean_diff,
    }


council_submit = quorum_submit


def quorum_verify(
    root: pathlib.Path,
    *,
    meeting_id: str,
    require_multi_seat: bool = True,
    resolution_summary: str = "",
) -> dict[str, Any]:
    """Verifies anti-fake-quorum integrity: >=2 distinct authors, source_kinds, and SHA-256 hashes."""
    if not MEETING_ID_RE.fullmatch(meeting_id):
        raise ValueError(f"Invalid meeting_id: {meeting_id}")
    meet_dir = dq_dir(root) / "meetings" / meeting_id
    sub_dir = meet_dir / "submissions"
    if not sub_dir.is_dir() or sub_dir.is_symlink():
        raise FileNotFoundError(f"Missing submissions directory for meeting {meeting_id}")

    verified_subs: list[dict[str, Any]] = []
    tampered: list[str] = []
    for meta_fp in sorted(sub_dir.glob("*.json")):
        rec = read_json_nofollow(meta_fp)
        md_rel = str(rec.get("rel_file") or "")
        md_fp = (meet_dir / md_rel).resolve()
        if not md_fp.is_file() or md_fp.is_symlink() or md_fp.parent != sub_dir.resolve():
            tampered.append(meta_fp.name)
            continue
        live_text = md_fp.read_text(encoding="utf-8").strip()
        live_hash = hashlib.sha256(live_text.encode("utf-8")).hexdigest()
        if live_hash != rec.get("content_sha256"):
            tampered.append(meta_fp.name)
            continue
        verified_subs.append(rec)

    if tampered:
        append_event_log(root, action="QUORUM_VERIFY", actor="cli", status="tampered", detail={"meeting_id": meeting_id})
        raise ValueError(f"TAMPERED_SUBMISSION_HASH_MISMATCH: {tampered}")

    authors = sorted({str(r["author"]) for r in verified_subs})
    sources = sorted({(str(r["author"]), str(r["source_kind"])) for r in verified_subs})
    hashes = sorted({str(r["content_sha256"]) for r in verified_subs})
    diff_hashes = sorted({str(r.get("diff_sha256") or "") for r in verified_subs if str(r.get("diff_sha256") or "").strip()})

    is_multi = len(authors) >= 2 and len(sources) >= 2 and len(hashes) >= 2
    decision_grade = "MULTI_SEAT_DECISION" if is_multi else "SOLO_SYNTHESIS"
    blocked = require_multi_seat and not is_multi

    resolution = {
        "meeting_id": meeting_id,
        "verified_at": utc_iso(),
        "decision_grade": decision_grade,
        "ok": not blocked,
        "blocked": blocked,
        "distinct_authors": authors,
        "distinct_content_hashes": len(hashes),
        "bound_diff_hashes": diff_hashes,
        "reason": "MULTI_SEAT_VERIFIED" if is_multi else "INSUFFICIENT_INDEPENDENT_SUBMISSIONS",
        "summary": resolution_summary.strip(),
    }
    atomic_write_json(meet_dir / "RESOLUTION.json", resolution)

    if blocked:
        log_pitfall(
            root,
            title=f"Fake-Quorum Guard Blocked ({meeting_id})",
            root_cause=f"authors={authors}, distinct_hashes={len(hashes)} (<2 independent submissions)",
            guard="Require >=2 distinct author/source_kind/SHA-256 submissions before MULTI_SEAT_DECISION",
            actor="quorum-verify",
        )
        append_event_log(
            root,
            action="QUORUM_VERIFY",
            actor="cli",
            status="blocked_fake_quorum",
            detail={"meeting_id": meeting_id, "grade": decision_grade},
        )
    else:
        append_event_log(
            root,
            action="QUORUM_VERIFY",
            actor="cli",
            status="ok",
            detail={"meeting_id": meeting_id, "grade": decision_grade, "authors": authors},
        )

    return resolution


council_verify = quorum_verify


def quorum_render_blind_packet(root: pathlib.Path, *, meeting_id: str, seed: int = 0) -> dict[str, Any]:
    """Builds an anonymized Stage-2 peer review bundle (`Peer A/B/C`) + local `reveal_map.json`."""
    if not MEETING_ID_RE.fullmatch(meeting_id):
        raise ValueError(f"Invalid meeting_id: {meeting_id}")
    meet_dir = dq_dir(root) / "meetings" / meeting_id
    sub_dir = meet_dir / "submissions"
    if not sub_dir.is_dir() or sub_dir.is_symlink():
        raise FileNotFoundError(f"Missing submissions directory for meeting {meeting_id}")

    records = [read_json_nofollow(fp) for fp in sorted(sub_dir.glob("*.json"))]
    if not records:
        raise ValueError(f"No submissions found for meeting {meeting_id}")
    if len(records) > 26:
        raise ValueError("Blind packet supports up to 26 submissions cleanly")

    ordered = list(records)
    if seed != 0:
        random.Random(seed).shuffle(ordered)

    reveal_map: dict[str, dict[str, str]] = {}
    sections = [
        f"# Blind Peer Review Packet (`{meeting_id}`)\n",
        "Author and model identities are hidden to prevent self-preference or brand bias.\n",
    ]
    for idx, rec in enumerate(ordered):
        label = f"Peer {chr(65 + idx)}"
        md_fp = (meet_dir / str(rec.get("rel_file") or "")).resolve()
        if not md_fp.is_file() or md_fp.is_symlink() or md_fp.parent != sub_dir.resolve():
            raise ValueError(f"Unsafe submission path for {label}")
        body = md_fp.read_text(encoding="utf-8").strip()
        diff_h = str(rec.get("diff_sha256") or "")
        reveal_map[label] = {
            "author": str(rec["author"]),
            "source_kind": str(rec["source_kind"]),
            "content_sha256": str(rec["content_sha256"]),
            "diff_sha256": diff_h,
        }
        diff_note = f" (diff `{diff_h[:12]}`)" if diff_h else ""
        sections.append(f"## {label}{diff_note}\n\n{body}\n")

    packet_path = meet_dir / "blind_packet.md"
    map_path = meet_dir / "reveal_map.json"
    atomic_write_text(packet_path, "\n".join(sections))
    atomic_write_json(map_path, reveal_map)
    append_event_log(
        root,
        action="QUORUM_BLIND_PACKET",
        actor="cli",
        status="ok",
        detail={"meeting_id": meeting_id, "peers": list(reveal_map.keys())},
    )
    return {
        "ok": True,
        "meeting_id": meeting_id,
        "labels": list(reveal_map.keys()),
        "blind_packet": str(packet_path),
        "reveal_map": str(map_path),
    }


def build_runner_preset(profile: str, *, task_pointer: str, model_override: str = "") -> dict[str, Any]:
    """Renders an optional, shell-free headless worker argv + <400B pointer spec for CLI dispatch."""
    if profile not in RUNNER_PRESETS:
        raise ValueError(f"Unsupported profile '{profile}'; expected one of {tuple(RUNNER_PRESETS.keys())}")
    ptr = task_pointer.strip()
    if not ptr:
        raise ValueError("task_pointer must be non-empty")
    spec = RUNNER_PRESETS[profile]
    chosen_model = model_override.strip() or str(spec["default_model"])
    if not MODEL_SLUG_RE.fullmatch(chosen_model):
        raise ValueError(f"Invalid model identifier: {chosen_model}")

    prompt_msg = f"Read pointer task card {ptr} carefully and apply scoped changes, returning diff + test status."
    argv = [tok.format(model=chosen_model, prompt=prompt_msg) for tok in spec["argv_template"]]
    cli_bin = str(spec["preflight_cli"])
    return {
        "ok": True,
        "profile": profile,
        "description": spec["description"],
        "planner_model": spec["planner_model"],
        "selected_model": chosen_model,
        "escalate_model": spec["escalate_model"],
        "argv": argv,
        "preflight_argv": ["diffquorum", "preflight", "--cli", cli_bin] if cli_bin else ["diffquorum", "preflight"],
        "notes": spec["notes"],
    }


def plan_council(
    root: pathlib.Path,
    *,
    topic: str,
    tags_csv: str = "",
    subscription: str = "",
) -> dict[str, Any]:
    cfg = load_council_config(root)
    cluster = cfg.get("cluster", {})
    sub_mode = subscription or str(cluster.get("subscription") or "single-sub")
    if sub_mode not in ("single-sub", "multi-sub"):
        raise ValueError(f"Invalid subscription mode: {sub_mode}")

    max_conc = 1 if sub_mode == "single-sub" else int(cluster.get("max_concurrent_agents") or 3)
    tags = infer_tags(topic, tags_csv)
    tag_set = set(tags)

    invited: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for seat in cfg.get("seats", []):
        sid = str(seat.get("id") or "")
        role = str(seat.get("role") or sid)
        host = str(seat.get("host") or "local")
        att = str(seat.get("attendance") or "on_tag")
        sub_tags = [str(t).lower() for t in (seat.get("subscribe_tags") or [])]
        overlap = [t for t in tags if t in sub_tags]

        if att == "core" or bool(tag_set.intersection(sub_tags)):
            invited.append(
                {
                    "id": sid,
                    "role": role,
                    "host": host,
                    "mode": str(seat.get("preferred_mode") or ("async_card" if host == "remote" else "sync")),
                    "matched_tags": overlap or ["coordinator"],
                }
            )
        else:
            skipped.append(
                {
                    "id": sid,
                    "reason": "远端节点默认免打扰（仅架构/Skill/经验分享特邀）" if host == "remote" else "与本议题无关，免陪跑",
                }
            )

    serial_lenses = [
        {"step": 1, "lens": "架构简化视角", "artifact": "lens_1_arch.md"},
        {"step": 2, "lens": "漏洞与边界挑错视角", "artifact": "lens_2_audit.md"},
        {"step": 3, "lens": "大白话汇总官", "artifact": "lens_3_summary.md"},
    ]

    recent = read_recent_pitfalls(root)
    append_event_log(root, action="QUORUM_PLAN", actor="cli", status="ok", detail={"topic": topic[:80], "tags": tags})
    return {
        "topology": str(cluster.get("topology") or "local-tmux"),
        "subscription": sub_mode,
        "max_concurrent_agents": max_conc,
        "execution_pattern": "serial_3_lens_single_session" if max_conc == 1 else "parallel_subagents",
        "serial_lenses": serial_lenses if max_conc == 1 else [],
        "cross_host_daily_reporting": False,
        "topic": topic,
        "inferred_tags": tags,
        "recent_pitfalls": recent,
        "invited_seats": invited,
        "skipped_seats": skipped,
    }


def render_council_workflow(topic: str, model_tier: str = "pro") -> str:
    """Renders an AST-valid top-level await parallel workflow with explicit model= binding."""
    return (
        "# Auto-generated by DiffQuorum (multi-sub parallel check)\n"
        "import json\n\n"
        f"TOPIC = {json.dumps(topic, ensure_ascii=False)}\n"
        f"MODEL_TIER = {json.dumps(model_tier, ensure_ascii=False)}\n"
        'PROMPT = "请只做一轮独立快查，指出真问题或简化点，用大白话分点答复：\\n" + TOPIC\n\n'
        "phase('DiffQuorum Parallel Check')\n"
        "views = await parallel(\n"
        "    [('egm-zoom-out', '极简架构'), ('egm-codebase-details', '细节挑错')],\n"
        "    lambda item: agent(\n"
        "        prompt=PROMPT,\n"
        "        role=item[1],\n"
        "        type_name=item[0],\n"
        "        workspace='inherit',\n"
        "        model=MODEL_TIER,\n"
        "    ),\n"
        ")\n"
        "print(json.dumps({'topic': TOPIC, 'views': [str(v) for v in views]}, ensure_ascii=False))\n"
    )


def pseudonymize_text(text: str, secret_key: str) -> str:
    """Session-scoped HMAC-SHA256 pseudonymization of local home/volume paths and private IPs before L3 export."""
    key_bytes = secret_key.encode("utf-8")

    def _tag(prefix: str, val: str) -> str:
        digest = hmac.new(key_bytes, val.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        return f"{prefix}_{digest}"

    out = HOME_PATH_RE.sub(lambda m: f"/home/{_tag('USER', m.group(1))}", text)
    out = VOLUME_PATH_RE.sub(lambda m: f"/Volumes/{_tag('VOL', m.group(1))}", out)
    out = PRIVATE_IP_RE.sub(lambda m: _tag("PRIV_IP", m.group(0)), out)
    return out


def evaluate_review_gate(
    root: pathlib.Path,
    *,
    level: int,
    content_tree_hash: str,
    rule_version: str = "1",
    round_num: int = 1,
    blockers: list[str] | None = None,
    nits_only: bool = False,
    external_status: str = "ok",
    requires_local_sampling: bool = False,
    gpu_locked: bool = False,
    record_fix: str = "",
) -> dict[str, Any]:
    if level not in (0, 1, 2):
        raise ValueError(f"Unsupported review level: {level} (allowed: 0, 1, 2)")

    blocker_list = [b.strip() for b in (blockers or []) if b.strip()]
    recent = read_recent_pitfalls(root)

    if level == 0:
        append_event_log(root, action="REVIEW", actor="cli", status="pass_local_only", detail={"level": 0})
        return {
            "status": "PASS_LOCAL_ONLY",
            "level": 0,
            "max_rounds": 0,
            "external_called": False,
            "recent_pitfalls": recent,
            "summary": format_plain_3line("0档日常通过，直接按本地测试结果交活", "常规小改免拉跨窗口审稿", "无"),
        }

    if requires_local_sampling and gpu_locked:
        append_event_log(root, action="REVIEW", actor="cli", status="deferred_resource_busy", detail={"level": level})
        return {
            "status": "DEFERRED_RESOURCE_BUSY",
            "level": level,
            "external_called": False,
            "recent_pitfalls": recent,
            "summary": format_plain_3line("本机采样重审暂缓等待算力释放", "当前有重算力互斥锁占用（纯代码审稿不受影响）", "等待重任务结束"),
        }

    if nits_only:
        log_pitfall(
            root,
            title=f"Nit ({content_tree_hash[:12]})",
            root_cause="Local style/naming note logged without external CLI call",
            actor="review",
        )
        return {
            "status": "NITS_LOGGED_LOCALLY",
            "level": level,
            "external_called": False,
            "recent_pitfalls": read_recent_pitfalls(root),
            "summary": format_plain_3line("纯风格小建议已记到本地台账", "不占用外部模型额度，不阻塞当前进度", "无"),
        }

    if external_status.lower() in ("timeout", "5xx", "outage", "error"):
        append_event_log(root, action="REVIEW", actor="cli", status="outage_fail_closed", detail={"ext": external_status})
        return {
            "status": "OUTAGE_FAIL_CLOSED",
            "level": level,
            "external_called": True,
            "blocked": True,
            "recent_pitfalls": recent,
            "summary": format_plain_3line("外部审稿超时或断网，已按安全策略暂停放行", f"外部接口状态={external_status}（绝不在断网时静默放过）", "检查网络/接口后重试一次"),
        }

    max_rounds = 1 if level == 1 else 2
    if blocker_list:
        if round_num >= max_rounds:
            log_pitfall(
                root,
                title=f"PITFALL_HALT ({content_tree_hash[:12]} r{round_num})",
                root_cause="; ".join(blocker_list),
                guard=f"rule={rule_version}; stop blind retries & write deterministic check",
                actor="review",
            )
            append_event_log(
                root,
                action="REVIEW",
                actor="cli",
                status="pitfall_halt",
                detail={"hash": content_tree_hash[:12], "round": round_num},
            )
            return {
                "status": "PITFALL_HALT",
                "level": level,
                "round": round_num,
                "max_rounds": max_rounds,
                "blocked": True,
                "blockers": blocker_list,
                "recent_pitfalls": read_recent_pitfalls(root),
                "summary": format_plain_3line(
                    f"已达第 {round_num} 轮上限，仍有阻塞问题，安灯拉闸停刷！",
                    f"未清零缺陷：{'; '.join(blocker_list)}（绝不允许带病放行或继续空刷轮次）",
                    "先排查根因并补成自动检查脚本，再开洁净新会话复核",
                ),
            }
        append_event_log(root, action="REVIEW", actor="cli", status="fix_defect_family", detail={"round": round_num})
        return {
            "status": "FIX_DEFECT_FAMILY",
            "level": level,
            "round": round_num,
            "max_rounds": max_rounds,
            "blocked": True,
            "blockers": blocker_list,
            "recent_pitfalls": recent,
            "summary": format_plain_3line(
                f"第 {round_num} 轮发现 {len(blocker_list)} 个待修问题",
                f"请按同一类问题一次修干净后再复核（剩余 {max_rounds - round_num} 轮）",
                "修完对应缺陷族后跑一次本地单测",
            ),
        }

    if record_fix.strip() or round_num >= 2:
        log_fix(
            root,
            title=f"Review Closure ({content_tree_hash[:12]} r{round_num})",
            fix_summary=record_fix.strip() or "Zero blockers confirmed after defect-family fix",
            actor="review",
        )
    append_event_log(root, action="REVIEW", actor="cli", status="pass", detail={"level": level, "round": round_num})
    return {
        "status": "PASS",
        "level": level,
        "round": round_num,
        "max_rounds": max_rounds,
        "blocked": False,
        "recent_pitfalls": recent,
        "summary": format_plain_3line("本轮核查全部通过（0 个阻塞缺陷）", f"内容指纹 `{content_tree_hash[:12]}` 已达成零缺陷闭环", "无"),
    }


def run_doctor(
    root: pathlib.Path,
    *,
    settings_path: pathlib.Path | None = None,
    transcript_steps: int | None = None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    base = dq_dir(root)

    def _add(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    try:
        cfg = load_council_config(root)
        _add("council_toml", True, "valid TOML")
    except Exception as exc:
        _add("council_toml", False, str(exc))
        cfg = {}

    try:
        board = read_board(root)
        _add("board_budget", True, f"{len(board.encode('utf-8'))} / {MAX_BOARD_BYTES} bytes")
    except Exception as exc:
        _add("board_budget", False, str(exc))

    live_archives_ok = all(
        [
            (base / "logs" / "events.jsonl").is_file(),
            (base / "pitfalls.md").is_file(),
            (base / "fixes_log.md").is_file(),
            (base / "meetings").is_dir(),
        ]
    )
    _add("five_live_archives", live_archives_ok, "BOARD.md + logs/events.jsonl + pitfalls.md/fixes_log.md + meetings/ + inbox/locks")

    inbox_dir = base / "inbox"
    oversized: list[str] = []
    checked_ptrs = 0
    if inbox_dir.is_dir():
        for fp in sorted(inbox_dir.glob("*.jsonl")):
            if fp.is_symlink():
                oversized.append(f"symlink:{fp.name}")
                continue
            for idx, ln in enumerate(fp.read_text(encoding="utf-8").splitlines(), start=1):
                if not ln.strip():
                    continue
                checked_ptrs += 1
                if len(ln.encode("utf-8")) >= MAX_ENVELOPE_BYTES:
                    oversized.append(f"{fp.name}:{idx}")
    _add("inbox_pointer_size", not oversized, f"checked={checked_ptrs}, violations={oversized}")

    cluster = cfg.get("cluster", {})
    sub = cluster.get("subscription", "single-sub")
    mca = int(cluster.get("max_concurrent_agents", 1))
    _add("single_sub_serial_cap", (sub != "single-sub") or (mca == 1), f"subscription={sub}, max_concurrent_agents={mca}")

    sp = settings_path or (pathlib.Path.home() / ".gemini" / "antigravity-cli" / "settings.json")
    if sp.is_file():
        try:
            sdoc = json.loads(sp.read_text(encoding="utf-8"))
            extra = sdoc.get("additionalDirectories") or []
            _add("settings_additional_dirs", len(extra) == 0, f"additionalDirectories={extra}")
        except Exception as exc:
            _add("settings_additional_dirs", False, f"read error: {exc}")
    else:
        _add("settings_additional_dirs", True, "settings.json absent (clean isolation)")

    if transcript_steps is not None:
        _add("session_bloat_check", transcript_steps <= 3500, f"steps={transcript_steps} (rotate above 3500)")

    all_ok = all(c["ok"] for c in checks)
    return {"ok": all_ok, "checks": checks}


def run_sanitize_lint(target: pathlib.Path, *, extra_forbid: tuple[str, ...] = ()) -> dict[str, Any]:
    """Scans target tree for host paths, private/Tailscale IPs, real UUIDs, or forbidden terms."""
    forbid = [w.strip().lower() for w in extra_forbid if w.strip()]
    for env_key in DEFAULT_FORBID_ENV_KEYS:
        env_forbid = os.environ.get(env_key, "")
        if env_forbid.strip():
            forbid.extend(w.strip().lower() for w in env_forbid.split(",") if w.strip())
    forbid = list(dict.fromkeys(forbid))

    findings: list[dict[str, Any]] = []
    skip_dirs = {".git", "__pycache__", ".diffquorum", ".starcouncil"}

    files: list[pathlib.Path] = []
    if target.is_file():
        files = [target]
    elif target.is_dir():
        for r, dirs, fns in os.walk(target, followlinks=False):
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            for fn in sorted(fns):
                fp = pathlib.Path(r) / fn
                if fp.suffix in (".pyc", ".pyo", ".png", ".jpg", ".zip", ".gz"):
                    continue
                files.append(fp)

    for fp in files:
        if fp.is_symlink():
            continue
        try:
            text = fp.read_text(encoding="utf-8")
        except Exception:
            continue
        rel = str(fp.relative_to(target)) if target.is_dir() else fp.name
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in HOME_PATH_RE.finditer(line):
                user = m.group(1)
                if user.startswith("USER_") or user.lower() in DEFAULT_CLEAN_PLACEHOLDER_USERS:
                    continue
                findings.append({"file": rel, "line": lineno, "rule": "HOME_ABS_PATH", "match": m.group(0)})
            for m in VOLUME_PATH_RE.finditer(line):
                if not m.group(1).startswith("VOL_"):
                    findings.append({"file": rel, "line": lineno, "rule": "VOLUME_ABS_PATH", "match": m.group(0)})
            for m in PRIVATE_IP_RE.finditer(line):
                findings.append({"file": rel, "line": lineno, "rule": "PRIVATE_OR_TAILSCALE_IP", "match": m.group(0)})
            for m in REAL_UUID_RE.finditer(line):
                findings.append({"file": rel, "line": lineno, "rule": "REAL_SESSION_UUID", "match": m.group(0)})
            low = line.lower()
            for term in forbid:
                if term in low:
                    findings.append({"file": rel, "line": lineno, "rule": "FORBIDDEN_TERM", "match": term})

    return {"ok": len(findings) == 0, "scanned_files": len(files), "finding_count": len(findings), "findings": findings[:50]}


def format_plain_3line(result: str, reason: str, user_action: str = "无") -> str:
    return f"【结果】{result}\n【原因】{reason}\n【需您操作】{user_action}"


def lint_plain_summary(text: str) -> dict[str, Any]:
    warnings = [f"命中机器腔模式 `{pat}`：建议{advice}" for pat, advice in ROBOTIC_JARGON_PATTERNS if re.search(pat, text)]
    return {"ok": len(warnings) == 0, "warning_count": len(warnings), "warnings": warnings}


def build_reproducible_tarball_bytes(repo_root: pathlib.Path, prefix: str = "diffquorum") -> tuple[bytes, int]:
    """Builds a bit-for-bit reproducible source `.tar.gz` (mtime=0, uid/gid=0, sorted PAX headers)."""
    skip_dirs = {".git", "__pycache__", ".diffquorum", ".starcouncil", "artifacts", "dist", "build", ".pytest_cache"}
    entries: list[tuple[str, pathlib.Path]] = []
    for root, dirs, files in os.walk(repo_root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info"))
        rp = pathlib.Path(root)
        for name in sorted(files):
            if name.endswith((".pyc", ".pyo")) or name.startswith("._") or name == ".DS_Store":
                continue
            fp = rp / name
            entries.append((fp.relative_to(repo_root).as_posix(), fp))
        for dname in list(dirs):
            dp = rp / dname
            if dp.is_symlink():
                entries.append((dp.relative_to(repo_root).as_posix(), dp))
                dirs.remove(dname)

    entries.sort(key=lambda item: item[0])
    clean_prefix = prefix.strip("/") or "diffquorum"
    raw_buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw_buf, compresslevel=9, mtime=0) as gz:
        with tarfile.open(mode="w", fileobj=gz, format=tarfile.PAX_FORMAT) as tf:
            for rel, fp in entries:
                ti = tarfile.TarInfo(name=f"{clean_prefix}/{rel}")
                ti.mtime = 0
                ti.uid = 0
                ti.gid = 0
                ti.uname = ""
                ti.gname = ""
                ti.pax_headers = {}
                if fp.is_symlink():
                    ti.type = tarfile.SYMTYPE
                    ti.linkname = os.readlink(fp)
                    ti.mode = 0o777
                    tf.addfile(ti)
                elif fp.is_file():
                    data = fp.read_bytes()
                    ti.type = tarfile.REGTYPE
                    ti.size = len(data)
                    ti.mode = 0o755 if os.access(fp, os.X_OK) else 0o644
                    tf.addfile(ti, io.BytesIO(data))
    return raw_buf.getvalue(), len(entries)


def run_archive(
    repo_root: pathlib.Path,
    *,
    output: pathlib.Path | None = None,
    prefix: str = "diffquorum",
    verify: bool = False,
    verify_file: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Creates and optionally verifies a deterministic tarball from `repo_root`."""
    bytes_a, file_count = build_reproducible_tarball_bytes(repo_root, prefix=prefix)
    sha_a = hashlib.sha256(bytes_a).hexdigest()

    if verify_file is not None:
        if not verify_file.is_file():
            raise FileNotFoundError(f"Archive not found: {verify_file}")
        actual = hashlib.sha256(verify_file.read_bytes()).hexdigest()
        if actual != sha_a:
            raise ValueError(f"REPRODUCIBLE_BUILD_MISMATCH: expected={sha_a}, got={actual}")
        return {"ok": True, "verified_file": str(verify_file), "sha256": sha_a, "files": file_count}

    if verify:
        bytes_b, _ = build_reproducible_tarball_bytes(repo_root, prefix=prefix)
        sha_b = hashlib.sha256(bytes_b).hexdigest()
        if bytes_a != bytes_b or sha_a != sha_b:
            raise ValueError("NON_DETERMINISTIC_ARCHIVE_DETECTED")

    if output is not None:
        out_path = output.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(bytes_a)
        return {"ok": True, "output": str(out_path), "sha256": sha_a, "files": file_count, "verified": verify}

    return {"ok": True, "sha256": sha_a, "files": file_count, "verified": verify}
