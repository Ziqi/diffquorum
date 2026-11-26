#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Quorum verification, Stage-2 blind anonymization, pitfalls/fixes ledgers, review Andon cord & sanitize-lint."""

from __future__ import annotations

import ast
import gzip
import hashlib
import hmac
import io
import json
import math
import os
import pathlib
import random
import re
import tarfile
import tokenize
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

OBJECTIVE_BLOCKER_CLASSES: tuple[str, ...] = (
    "install_or_packaging",
    "test_or_runtime_or_security",
    "ci_workflow",
    "doc_truth_or_secret_leak",
)
DEFAULT_FORBIDDEN_TEST_CODENAMES: tuple[str, ...] = ("kimi", "opus", "grok", "egm")
_REL_SEMVER_RE = re.compile(r"^v?(\d+\.\d+\.\d+(?:\.(?:dev|post)\d+|(?:a|b|rc)\d+)?)$")
_REL_PYPROJ_VER_RE = re.compile(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']\s*$')
_REL_CFF_VER_RE = re.compile(r'(?m)^version:\s*["\']?([^"\'\s#]+)["\']?\s*$')
_REL_INIT_VER_RE = re.compile(r'(?m)^\s*__version__\s*=\s*["\']([^"\']+)["\']\s*$')
_REL_WF_VER_RE = re.compile(r'(?:--version\s+|RELEASE_VERSION\s*[:=]\s*)["\']?v?(\d+\.\d+\.\d+)["\']?(?![.\d])')
_REL_PKGINFO_UNK_RE = re.compile(r"(?m)^(?:Name|Version|Summary|Home-page|Author|License):\s*UNKNOWN\s*$")
_REL_PKGINFO_VER_RE = re.compile(r"(?m)^Version:\s*(\S+)\s*$")
_WALL_CLOCK_NAMES = frozenset(
    {"elapsed", "elapsed_s", "elapsed_sec", "dt", "dt_s", "dur", "duration", "took", "wall", "wall_s", "latency", "latency_s"}
)
_WALL_CLOCK_ATTRS = frozenset({"monotonic", "perf_counter", "process_time", "time"})

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


def verify_model_identity(
    expected_model: str,
    observed_model: str,
    *,
    root: pathlib.Path | None = None,
    actor: str = "model-probe",
) -> dict[str, Any]:
    """Fail-closed guard against silent router model downgrade or missing observed model identity."""
    exp_raw = expected_model.strip()
    obs_raw = (observed_model or "").strip()
    if not exp_raw or not MODEL_SLUG_RE.fullmatch(exp_raw):
        raise ValueError(f"Invalid expected_model identifier: {expected_model}")

    if not obs_raw:
        res: dict[str, Any] = {
            "ok": False,
            "blocked": True,
            "status": "MODEL_IDENTITY_MISSING",
            "expected_model": exp_raw,
            "observed_model": "",
            "reason": "OBSERVED_MODEL_EMPTY",
        }
    elif not MODEL_SLUG_RE.fullmatch(obs_raw):
        res = {
            "ok": False,
            "blocked": True,
            "status": "MODEL_IDENTITY_INVALID",
            "expected_model": exp_raw,
            "observed_model": obs_raw,
            "reason": "OBSERVED_MODEL_INVALID_SLUG",
        }
    elif obs_raw.lower() != exp_raw.lower():
        res = {
            "ok": False,
            "blocked": True,
            "status": "MODEL_DOWNGRADE_DETECTED",
            "expected_model": exp_raw,
            "observed_model": obs_raw,
            "reason": "EXPECTED_OBSERVED_MISMATCH",
        }
    else:
        res = {
            "ok": True,
            "blocked": False,
            "status": "MODEL_IDENTITY_VERIFIED",
            "expected_model": exp_raw,
            "observed_model": obs_raw,
            "reason": "EXACT_MATCH",
        }

    if root is not None:
        if res["blocked"]:
            log_pitfall(
                root,
                title=f"Model Identity Guard Blocked ({exp_raw})",
                root_cause=f"expected={exp_raw}, observed={obs_raw or '<empty>'} ({res['status']})",
                guard="Fail closed on silent router model downgrade or missing model receipt",
                actor=actor,
            )
            append_event_log(
                root,
                action="MODEL_PROBE",
                actor=actor,
                status="blocked",
                detail={"expected": exp_raw, "observed": obs_raw, "reason": res["status"]},
            )
        else:
            append_event_log(
                root,
                action="MODEL_PROBE",
                actor=actor,
                status="ok",
                detail={"expected": exp_raw, "observed": obs_raw},
            )
    return res


def probe_model_receipt(
    receipt_path: pathlib.Path,
    *,
    expected_model: str,
    root: pathlib.Path | None = None,
    actor: str = "model-probe",
) -> dict[str, Any]:
    """Reads a runner JSON receipt safely (no symlinks) and enforces exact expected==observed model identity."""
    doc = read_json_nofollow(receipt_path)
    usage = doc.get("usage") if isinstance(doc.get("usage"), dict) else {}
    observed = str(doc.get("observed_model") or doc.get("model") or usage.get("model") or "")
    res = verify_model_identity(expected_model, observed, root=root, actor=actor)
    res["receipt_path"] = str(receipt_path)
    return res


def quorum_submit(
    root: pathlib.Path,
    *,
    meeting_id: str,
    author: str,
    source_kind: str,
    content: str,
    diff_sha256: str = "",
    expected_model: str = "",
    observed_model: str = "",
) -> dict[str, Any]:
    """Stores an independent participant's raw submission, optional git diff hash, model verification, and SHA-256."""
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

    exp_model = expected_model.strip()
    obs_model = observed_model.strip()
    model_verified = False
    if exp_model:
        probe = verify_model_identity(exp_model, obs_model, root=root, actor=author)
        if probe["blocked"]:
            raise ValueError(f"{probe['status']}: expected={exp_model}, observed={obs_model or '<empty>'}")
        model_verified = True
    elif obs_model and not MODEL_SLUG_RE.fullmatch(obs_model):
        raise ValueError(f"Invalid observed_model identifier: {obs_model}")

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
        "expected_model": exp_model,
        "observed_model": obs_model,
        "model_verified": model_verified,
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
        "expected_model": exp_model,
        "observed_model": obs_model,
        "model_verified": model_verified,
    }


council_submit = quorum_submit


def quorum_verify(
    root: pathlib.Path,
    *,
    meeting_id: str,
    require_multi_seat: bool = True,
    require_model_match: bool = False,
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
    model_mismatches: list[str] = []
    for rec in verified_subs:
        exp_m = str(rec.get("expected_model") or "").strip()
        obs_m = str(rec.get("observed_model") or "").strip()
        if exp_m and obs_m.lower() != exp_m.lower():
            model_mismatches.append(f"{rec['author']}:expected={exp_m},observed={obs_m or '<empty>'}")
        elif require_model_match and (not exp_m or not obs_m or not bool(rec.get("model_verified"))):
            model_mismatches.append(f"{rec['author']}:unverified_model")

    decision_grade = "MULTI_SEAT_DECISION" if is_multi else "SOLO_SYNTHESIS"
    blocked = (require_multi_seat and not is_multi) or bool(model_mismatches)
    if model_mismatches:
        reason = "MODEL_DOWNGRADE_BLOCKED"
    elif is_multi:
        reason = "MULTI_SEAT_VERIFIED"
    else:
        reason = "INSUFFICIENT_INDEPENDENT_SUBMISSIONS"

    resolution = {
        "meeting_id": meeting_id,
        "verified_at": utc_iso(),
        "decision_grade": decision_grade,
        "ok": not blocked,
        "blocked": blocked,
        "distinct_authors": authors,
        "distinct_content_hashes": len(hashes),
        "bound_diff_hashes": diff_hashes,
        "model_mismatches": model_mismatches,
        "reason": reason,
        "summary": resolution_summary.strip(),
    }
    atomic_write_json(meet_dir / "RESOLUTION.json", resolution)

    if blocked:
        pitfall_title = (
            f"Model-Identity Guard Blocked ({meeting_id})"
            if model_mismatches
            else f"Fake-Quorum Guard Blocked ({meeting_id})"
        )
        pitfall_cause = (
            f"model_mismatches={model_mismatches}"
            if model_mismatches
            else f"authors={authors}, distinct_hashes={len(hashes)} (<2 independent submissions)"
        )
        log_pitfall(
            root,
            title=pitfall_title,
            root_cause=pitfall_cause,
            guard="Require >=2 distinct author/source_kind/SHA-256 submissions and exact expected==observed model match",
            actor="quorum-verify",
        )
        append_event_log(
            root,
            action="QUORUM_VERIFY",
            actor="cli",
            status="blocked_model_mismatch" if model_mismatches else "blocked_fake_quorum",
            detail={"meeting_id": meeting_id, "grade": decision_grade, "reason": reason},
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
    blocker_classes: list[str] | None = None,
    nits_only: bool = False,
    external_status: str = "ok",
    requires_local_sampling: bool = False,
    gpu_locked: bool = False,
    record_fix: str = "",
) -> dict[str, Any]:
    if level not in (0, 1, 2):
        raise ValueError(f"Unsupported review level: {level} (allowed: 0, 1, 2)")
    if isinstance(round_num, bool) or not isinstance(round_num, int) or round_num < 1:
        raise ValueError(f"Invalid round_num: {round_num!r} (must be integer >= 1)")

    raw_blockers = [b.strip() for b in (blockers or []) if b.strip()]
    demoted_notes: list[str] = []
    if blocker_classes is not None and raw_blockers:
        objective_only: list[str] = []
        for idx, b_txt in enumerate(raw_blockers):
            cls_name = blocker_classes[idx].strip().lower() if idx < len(blocker_classes) else ""
            if cls_name in OBJECTIVE_BLOCKER_CLASSES:
                objective_only.append(b_txt)
            else:
                demoted_notes.append(f"[{cls_name or 'subjective'}] {b_txt}")
        blocker_list = objective_only
    else:
        blocker_list = raw_blockers
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
    if round_num > max_rounds:
        log_pitfall(
            root,
            title=f"ROUND_CAP_HALT ({content_tree_hash[:12]} r{round_num})",
            root_cause=f"round={round_num} exceeded hard cap max_rounds={max_rounds} (level={level})",
            guard=f"rule={rule_version}; enforce <=2 review rounds hard stop (1+1 cap)",
            actor="review",
        )
        append_event_log(
            root,
            action="REVIEW",
            actor="cli",
            status="round_cap_halt",
            detail={"hash": content_tree_hash[:12], "round": round_num, "max_rounds": max_rounds},
        )
        return {
            "status": "ROUND_CAP_HALT",
            "level": level,
            "round": round_num,
            "max_rounds": max_rounds,
            "blocked": True,
            "blockers": blocker_list,
            "recent_pitfalls": read_recent_pitfalls(root),
            "summary": format_plain_3line(
                f"第 {round_num} 轮已超出硬封顶上限（最多 {max_rounds} 轮），系统直接拉闸拦截",
                f"同一改动严禁无限空转审稿（level={level}, max_rounds={max_rounds}）",
                "汇总未闭环问题并交由人工拍板，勿再加开新轮次",
            ),
        }
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
        "non_blocking_notes": demoted_notes,
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


def _expr_uses_wall_clock(expr: ast.AST) -> bool:
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Name) and sub.id.lower() in _WALL_CLOCK_NAMES:
            return True
        if isinstance(sub, ast.Attribute) and sub.attr.lower() in _WALL_CLOCK_ATTRS:
            return True
    return False


def _narrow_clock_bound(node: ast.AST, min_sec: float) -> float | None:
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        op, rhs = node.ops[0], node.comparators[0]
        if (
            isinstance(op, (ast.Lt, ast.LtE))
            and _expr_uses_wall_clock(node.left)
            and isinstance(rhs, ast.Constant)
            and isinstance(rhs.value, (int, float))
            and not isinstance(rhs.value, bool)
            and 0 < float(rhs.value) < min_sec
        ):
            return float(rhs.value)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("assertLess", "assertLessEqual")
        and len(node.args) >= 2
        and _expr_uses_wall_clock(node.args[0])
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, (int, float))
        and not isinstance(node.args[1].value, bool)
        and 0 < float(node.args[1].value) < min_sec
    ):
        return float(node.args[1].value)
    return None


def run_release_preflight(
    repo_root: pathlib.Path,
    *,
    expected_version: str = "",
    min_clock_assert_sec: float = 0.5,
    forbidden_test_codenames: tuple[str, ...] = DEFAULT_FORBIDDEN_TEST_CODENAMES,
    sdist_tar: pathlib.Path | None = None,
) -> dict[str, Any]:
    """Static 0-Token release preflight: cross-file version alignment, PKG-INFO/sdist closure & test hygiene."""
    issues: list[str] = []
    m_sem = _REL_SEMVER_RE.match((expected_version or "").strip())
    norm_ver = m_sem.group(1) if m_sem else ""

    pyproj = repo_root / "pyproject.toml"
    pyproj_txt = pyproj.read_text(encoding="utf-8") if pyproj.is_file() else ""
    if pyproj_txt:
        m_pv = _REL_PYPROJ_VER_RE.search(pyproj_txt)
        if m_pv:
            pv = m_pv.group(1).lstrip("v")
            if not norm_ver:
                norm_ver = pv
            elif pv != norm_ver:
                issues.append(f"pyproject.toml: version={pv!r} != expected {norm_ver!r}")

    if norm_ver:
        cff = repo_root / "CITATION.cff"
        if cff.is_file():
            m_cff = _REL_CFF_VER_RE.search(cff.read_text(encoding="utf-8"))
            if not m_cff or m_cff.group(1).lstrip("v") != norm_ver:
                issues.append(f"CITATION.cff: version={(m_cff.group(1) if m_cff else '<missing>')!r} != expected {norm_ver!r}")

        src_dir = repo_root / "src"
        if src_dir.is_dir():
            for child in sorted(src_dir.iterdir()):
                init_fp = child / "__init__.py"
                if child.is_dir() and init_fp.is_file():
                    m_iv = _REL_INIT_VER_RE.search(init_fp.read_text(encoding="utf-8"))
                    if m_iv and m_iv.group(1).lstrip("v") != norm_ver:
                        issues.append(f"{init_fp.relative_to(repo_root)}: __version__={m_iv.group(1)!r} != expected {norm_ver!r}")

        wf_dir = repo_root / ".github" / "workflows"
        if wf_dir.is_dir():
            for wf in sorted(wf_dir.iterdir()):
                if wf.suffix in {".yml", ".yaml"} and wf.is_file():
                    for lineno, ln in enumerate(wf.read_text(encoding="utf-8").splitlines(), start=1):
                        for m_wv in _REL_WF_VER_RE.finditer(ln):
                            if m_wv.group(1) != norm_ver:
                                issues.append(f".github/workflows/{wf.name}:{lineno}: hardcoded version {m_wv.group(1)!r} != {norm_ver!r}")

    clean_tokens = [re.escape(t.strip()) for t in forbidden_test_codenames if t.strip()]
    ident_re = re.compile(rf"(?:^|_)(?:{'|'.join(clean_tokens)})(?:_|$|[0-9])", re.IGNORECASE) if clean_tokens else None
    cmt_re = re.compile(rf"\b(?:{'|'.join(clean_tokens)})\b", re.IGNORECASE) if clean_tokens else None

    tests_dir = repo_root / "tests"
    tests_need_samples = False
    if tests_dir.is_dir():
        for r_t, dirs_t, files_t in os.walk(tests_dir, followlinks=False):
            dirs_t[:] = [d for d in dirs_t if d != "__pycache__"]
            for fn_t in sorted(files_t):
                if not fn_t.endswith(".py"):
                    continue
                tfp = pathlib.Path(r_t) / fn_t
                rel_tf = tfp.relative_to(repo_root).as_posix()
                src_t = tfp.read_text(encoding="utf-8")
                if re.search(r'["\']samples/|/\s*["\']samples["\']', src_t):
                    tests_need_samples = True
                tree_t = ast.parse(src_t, filename=str(tfp))
                for node in ast.walk(tree_t):
                    if ident_re and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        if ident_re.search(node.name):
                            issues.append(f"{rel_tf}:{node.lineno}: test identifier {node.name!r} leaks reviewer codename")
                    bound = _narrow_clock_bound(node, min_clock_assert_sec)
                    if bound is not None:
                        issues.append(f"{rel_tf}:{getattr(node, 'lineno', 0)}: narrow wall-clock bound (<{bound}s < {min_clock_assert_sec}s)")
                if cmt_re:
                    for tok in tokenize.generate_tokens(io.StringIO(src_t).readline):
                        if tok.type == tokenize.COMMENT and cmt_re.search(tok.string):
                            issues.append(f"{rel_tf}:{tok.start[0]}: test comment leaks reviewer codename")

    if pyproj_txt and (repo_root / "samples").is_dir() and tests_need_samples and sdist_tar is None:
        manifest_txt = (repo_root / "MANIFEST.in").read_text(encoding="utf-8") if (repo_root / "MANIFEST.in").is_file() else ""
        if "samples" not in manifest_txt and "samples" not in pyproj_txt:
            issues.append("MANIFEST.in/pyproject.toml: tests reference 'samples/' but manifest omits 'samples/'")

    if sdist_tar is not None:
        with tarfile.open(sdist_tar, "r:*") as tf_arc:
            pkg_members = [m for m in tf_arc.getmembers() if m.name.endswith("/PKG-INFO") or m.name == "PKG-INFO"]
            if not pkg_members:
                issues.append(f"sdist ({sdist_tar.name}): missing PKG-INFO")
            else:
                f_pkg = tf_arc.extractfile(pkg_members[0])
                pkg_txt = f_pkg.read().decode("utf-8", errors="replace") if f_pkg else ""
                if _REL_PKGINFO_UNK_RE.search(pkg_txt):
                    issues.append(f"sdist ({sdist_tar.name}): PKG-INFO contains UNKNOWN metadata")
                if norm_ver:
                    m_pv = _REL_PKGINFO_VER_RE.search(pkg_txt)
                    if not m_pv or m_pv.group(1).lstrip("v") != norm_ver:
                        issues.append(f"sdist ({sdist_tar.name}): PKG-INFO Version mismatch vs {norm_ver!r}")

    return {"ok": len(issues) == 0, "version": norm_ver, "issue_count": len(issues), "issues": issues}


SERVER_SIDE_SOCIAL_SEARCH_TOOLS: tuple[str, ...] = (
    "x_keyword_search",
    "x_user_search",
    "x_semantic_search",
)
DEFAULT_HEADLESS_DISALLOWED_TOOLS: tuple[str, ...] = (
    "Bash",
    "Edit",
    "Write",
    "NotebookEdit",
    "WebFetch",
    "WebSearch",
    "TodoWrite",
    *SERVER_SIDE_SOCIAL_SEARCH_TOOLS,
)
HEADLESS_SEARCH_TRIGGER_RE = re.compile(
    r"(?:\b(?:web_search|websearch|search\s+the\s+web|google\s+search|browse\s+the\s+internet|x_search|x_keyword_search|x_user_search|x_semantic_search|search\s+twitter)\b|联网检索|搜索网络|上网查|查推特|搜推特|检索\s*X\s*平台)",
    re.IGNORECASE,
)


def build_headless_review_argv(
    cli_bin: str,
    *,
    model: str,
    prompt: str,
    disallowed_tools: tuple[str, ...] = DEFAULT_HEADLESS_DISALLOWED_TOOLS,
    disable_all_tools: bool = False,
    system_prompt_override: str = "",
    extra_args: tuple[str, ...] = (),
) -> list[str]:
    """
    Constructs a tool-stripped headless blind-review CLI invocation so external reviewers never stall
    inside built-in file, web-search, or server-side social/X-search tool loops.
    """
    clean_bin = str(cli_bin or "").strip()
    clean_model = str(model or "").strip()
    if not clean_bin or not clean_model:
        raise ValueError("cli_bin and model must be non-empty")
    argv = [clean_bin, "--print", "--model", clean_model]
    if disable_all_tools:
        argv.extend(["--tools", ""])
    else:
        stripped = [t.strip() for t in disallowed_tools if t and t.strip()]
        if not stripped:
            raise ValueError("disallowed_tools must explicitly strip built-in tools for headless blind reviews")
        argv.extend(["--disallowed-tools", ",".join(stripped)])
    if str(system_prompt_override or "").strip():
        argv.extend(["--system-prompt-override", str(system_prompt_override).strip()])
    argv.extend([*extra_args, prompt])
    return argv


def validate_headless_review_spec(
    *,
    argv: list[str],
    prompt: str,
    timeout_sec: float,
    max_timeout_sec: float = 300.0,
    max_prompt_chars: int = 120_000,
) -> dict[str, Any]:
    """
    Fail-closed guard preventing headless blind-review CLI deadlocks & wall-clock timeouts:
      1. Requires explicit tool stripping (`--disallowed-tools`, `--tools ""`, or `--no-tools`);
      2. Rejects `--disable-web-search` alone when server-side social/X search tools (`x_keyword_search`,
         `x_user_search`, `x_semantic_search`) are not also stripped via `--tools ""` / `--no-tools` / `--disallowed-tools`;
      3. Rejects prompts containing live web or social/X search trigger phrases;
      4. Enforces finite `0 < timeout_sec < max_timeout_sec` (<300s) and bounded prompt size per chunk.
    """
    issues: list[str] = []
    tokens = [str(t) for t in argv]
    has_all_tools_off = False
    disallowed_set: set[str] = set()
    has_disable_web_search = False
    for idx, tok in enumerate(tokens):
        if tok == "--no-tools" or tok == "--tools=":
            has_all_tools_off = True
        elif tok == "--tools" and idx + 1 < len(tokens) and tokens[idx + 1] == "":
            has_all_tools_off = True
        elif tok.startswith("--disallowed-tools=") and tok.split("=", 1)[1].strip():
            for item in tok.split("=", 1)[1].split(","):
                if item.strip():
                    disallowed_set.add(item.strip().lower())
        elif tok == "--disallowed-tools" and idx + 1 < len(tokens) and tokens[idx + 1].strip():
            for item in tokens[idx + 1].split(","):
                if item.strip():
                    disallowed_set.add(item.strip().lower())
        elif tok == "--disable-web-search":
            has_disable_web_search = True
    has_tool_strip = has_all_tools_off or bool(disallowed_set)
    if not has_tool_strip:
        issues.append("missing_tool_strip: headless reviewer argv must explicitly pass --disallowed-tools (or --tools '' / --no-tools)")
    if has_disable_web_search and not has_all_tools_off:
        missing_social = [t for t in SERVER_SIDE_SOCIAL_SEARCH_TOOLS if t not in disallowed_set]
        if missing_social:
            issues.append(
                f"incomplete_web_only_strip: --disable-web-search alone leaves server-side social/X search tools active ({missing_social}); pass --tools '' / --no-tools or disable them in --disallowed-tools"
            )

    text = str(prompt or "")
    if not text.strip():
        issues.append("empty_prompt: headless reviewer prompt must be non-empty")
    if len(text) > int(max_prompt_chars):
        issues.append(f"prompt_too_large: {len(text)} chars exceeds per-chunk limit {int(max_prompt_chars)}")
    m_search = HEADLESS_SEARCH_TRIGGER_RE.search(text)
    if m_search:
        issues.append(f"search_trigger_in_prompt: phrase {m_search.group(0)!r} may trigger server-side web/social search stalls")

    if isinstance(timeout_sec, bool) or not isinstance(timeout_sec, (int, float)):
        issues.append(f"invalid_timeout: timeout_sec={timeout_sec!r} must be positive")
    else:
        try:
            t_val = float(timeout_sec)
        except OverflowError:
            t_val = float("inf")
        if not math.isfinite(t_val) or t_val <= 0.0:
            issues.append(f"invalid_timeout: timeout_sec={timeout_sec!r} must be finite and positive")
        elif t_val >= float(max_timeout_sec):
            issues.append(f"timeout_exceeds_deadline: timeout_sec={timeout_sec} >= max_timeout_sec={max_timeout_sec}")

    return {"ok": len(issues) == 0, "issue_count": len(issues), "issues": issues}
