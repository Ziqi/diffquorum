#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""
Clean-room multi-agent governance policies (`policy.py`):
  1. Front-Door Discussion Cap (`D0..D2`) & Multi-Model Specialty Routing
  2. Blast-Radius 4-Tier Review Routing (`R0..R3`) with Pure-Copy Fast Lane (`R1`)
     and `commercial_flagship_deliverable` Non-Code `R3` Domain
  3. Post-Launch Zero-Context Blind Evaluation (`B0..B2`) for Live Products & Commercial Deliverables
  4. Negative-Experiment Double-Blind `Fold-A / Fold-B` M&M Autopsy Verifier
  5. Machine-Readable Master Dictionary Cross-Repo Drift & Typography Guard
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import pathlib
import re
import stat
import urllib.parse
from typing import Any

DISCUSSION_TIERS: dict[str, dict[str, Any]] = {
    "D0": {
        "label": "direct_execution",
        "max_external_advisors": 0,
        "max_rounds": 0,
        "requires_strawman": False,
        "description": "Clear requirements or routine fixes: 0 external advisors, 0 discussion rounds.",
    },
    "D1": {
        "label": "single_specialist",
        "max_external_advisors": 1,
        "max_rounds": 1,
        "requires_strawman": False,
        "description": "Single-dimension design trade-off: 1 matched specialist advisor, capped at 1 round.",
    },
    "D2": {
        "label": "dual_blind_strategic",
        "max_external_advisors": 2,
        "max_rounds": 1,
        "requires_strawman": True,
        "description": "Cross-cutting strategic change: concrete strawman first, then <=2 blind advisors for 1 round (optional tie-breaker only on direct conflict).",
    },
}

DEFAULT_SPECIALTY_ROLES: dict[str, str] = {
    "orchestration_and_build": "primary_builder",
    "pricing_and_product_pruning": "product_strategist",
    "copy_ux_and_compliance": "architecture_compliance_reviewer",
    "code_math_concurrency_and_locks": "stateless_code_auditor",
    "negative_experiment_autopsy": "dual_blind_diagnosticians",
}

LIGHTWEIGHT_MODEL_RE = re.compile(
    r"(?:^|[-_/.:@])(?:flash|lite|mini|nano|haiku|small|tiny)(?:$|[-_/.:@0-9])",
    re.IGNORECASE,
)

BLAST_RADIUS_ORDER: dict[str, int] = {"R0": 0, "R1": 1, "R2": 2, "R3": 3}

R1_FAST_LANE_INVARIANTS: tuple[str, ...] = (
    "zero_logic_math_changes",
    "zero_storage_io_changes",
    "zero_auth_permission_changes",
    "zero_route_removals",
    "zero_custom_style_bloat",
)

R3_CRITICAL_DOMAINS: frozenset[str] = frozenset(
    {
        "billing_or_redemption",
        "auth_or_multitenant_privacy",
        "core_scoring_or_ledger_math",
        "state_schema_or_migration",
        "commercial_flagship_deliverable",
    }
)

BLIND_EVAL_TIERS: dict[str, dict[str, Any]] = {
    "B0": {
        "label": "skip_blind_eval",
        "min_evaluators": 0,
        "max_evaluators": 0,
        "max_rounds": 0,
        "description": "Internal maintenance or non-user-facing change: skip post-launch blind evaluation.",
    },
    "B1": {
        "label": "single_release_or_commercial_deliverable",
        "min_evaluators": 1,
        "max_evaluators": 2,
        "max_rounds": 1,
        "description": "Single feature launch or external commercial deliverable: 1..2 zero-context cross-family blind evaluators, 1 round into next-version backlog.",
    },
    "B2": {
        "label": "flagship_launch_cold_start",
        "min_evaluators": 2,
        "max_evaluators": 3,
        "max_rounds": 1,
        "description": "Flagship product cold-start launch: 2..3 distinct cross-family blind evaluators with optional user personas, 1 round into next-version backlog.",
    },
}

CGNAT_NETWORK = ipaddress.IPv4Network((0x64400000, 10))
FAKE_IP_NETWORK = ipaddress.IPv4Network((0xC6120000, 15))
PUBLIC_ARTIFACT_URI_RE = re.compile(r"^public-artifact:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
LOCAL_PATH_PREFIX_RE = re.compile(r"^(?:/|~[/\\]|\.{1,2}[/\\]|[A-Za-z]:[/\\]|file://)", re.IGNORECASE)
INTERNAL_HOST_SUFFIXES: tuple[str, ...] = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".corp", ".intranet")
NUMERIC_OR_HEX_LABEL_RE = re.compile(r"^(?:\d+|0x[0-9a-f]+)$", re.IGNORECASE)

MM_TRIGGER_STATUSES: frozenset[str] = frozenset({"REJECTED", "HOLD", "UNPROMOTED", "ANOMALY"})
MM_VALID_DIRECTIONS: frozenset[str] = frozenset({"up", "down", "threshold", "nonzero"})
MM_VALID_CORRECTIONS: frozenset[str] = frozenset({"holm", "bonferroni", "bh_fdr"})
SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")

EMOJI_RE = re.compile(
    "["
    "\U0001F170-\U0001F251"
    "\U0001F1E6-\U0001F1FF"
    "\U0001F300-\U0001FAFF"
    "\u231A-\u231B"
    "\u23E9-\u23F3"
    "\u23F8-\u23FA"
    "\u2600-\u27BF"
    "\u2B50\u2B55"
    "]|\u20E3"
)

MAX_JSON_DOC_BYTES = 2 * 1024 * 1024
MAX_SCAN_FILE_BYTES = 4 * 1024 * 1024
SKIP_SCAN_DIRS: frozenset[str] = frozenset({".git", "__pycache__", "node_modules", ".next", "dist", ".venv", "venv"})
BINARY_EXTS: frozenset[str] = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".pdf", ".zip", ".gz", ".tgz", ".tar", ".zst", ".woff", ".woff2", ".ttf", ".pyc", ".so"}
)


def _norm_token(value: str) -> str:
    return re.sub(r"\s+", "_", str(value or "").strip().lower())


def _safe_finite_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        num = float(value)
    except OverflowError:
        return None
    return num if math.isfinite(num) else None


def _read_regular_bytes_nofollow_bounded(
    path: pathlib.Path,
    *,
    max_bytes: int,
    allow_empty: bool,
) -> bytes:
    """Opens a regular file non-blocking with O_NOFOLLOW and reads at most `max_bytes`."""
    if path.is_symlink():
        raise ValueError(f"Symlinked path rejected: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(str(path), flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"Non-regular file rejected: {path}")
        if (not allow_empty and st.st_size <= 0) or st.st_size > max_bytes:
            raise ValueError(f"File size out of bounds ({0 if allow_empty else 1}..{max_bytes}B): {st.st_size}")
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if (not allow_empty and len(raw) == 0) or len(raw) > max_bytes:
        raise ValueError(f"File exceeded bounded read limit ({max_bytes}B): {path}")
    return raw


def _read_json_nofollow_bounded(path: str | pathlib.Path, *, max_bytes: int = MAX_JSON_DOC_BYTES) -> tuple[dict[str, Any], str]:
    p = pathlib.Path(os.path.abspath(os.path.expanduser(str(path))))
    raw = _read_regular_bytes_nofollow_bounded(p, max_bytes=max_bytes, allow_empty=False)
    doc = json.loads(raw.decode("utf-8"))
    if not isinstance(doc, dict):
        raise ValueError("Top-level JSON document must be an object")
    return doc, hashlib.sha256(raw).hexdigest()[:16]


def evaluate_discussion_plan(
    *,
    tier: str,
    rounds_requested: int,
    author_family: str,
    advisor_models: list[str] | tuple[str, ...] = (),
    advisor_families: list[str] | tuple[str, ...] = (),
    has_strawman: bool = False,
    tie_breaker_conflict: bool = False,
    specialty_domain: str = "",
) -> dict[str, Any]:
    """
    Validates front-door multi-model exploration (`D0..D2`) against single-round caps,
    strawman-first discipline, lightweight-model exclusion, and cross-family independence.
    """
    t = str(tier or "").strip().upper()
    if t not in DISCUSSION_TIERS:
        raise ValueError(f"Unsupported discussion tier {tier!r}; expected one of {tuple(DISCUSSION_TIERS)}")
    spec = DISCUSSION_TIERS[t]
    issues: list[str] = []

    if isinstance(rounds_requested, bool) or not isinstance(rounds_requested, int) or rounds_requested < 0:
        issues.append(f"invalid_rounds: rounds_requested={rounds_requested!r} must be a non-negative integer")
    elif rounds_requested > int(spec["max_rounds"]):
        issues.append(
            f"discussion_round_cap_exceeded: tier {t} caps upfront discussion at <= {spec['max_rounds']} round(s), got {rounds_requested}"
        )

    raw_models = list(advisor_models)
    raw_families = list(advisor_families)
    if any(not str(m).strip() for m in raw_models):
        issues.append("blank_advisor_model: advisor_models contains empty entry")
    if any(not _norm_token(f) for f in raw_families):
        issues.append("blank_advisor_family: advisor_families contains empty entry")

    models = [str(m).strip() for m in raw_models if str(m).strip()]
    families = [_norm_token(f) for f in raw_families if _norm_token(f)]
    auth_fam = _norm_token(author_family)
    if not auth_fam:
        issues.append("missing_author_family: author_family must be non-empty")

    max_adv = int(spec["max_external_advisors"])
    effective_max = max_adv + (1 if (t == "D2" and tie_breaker_conflict) else 0)
    if len(models) > effective_max or len(families) > effective_max:
        issues.append(
            f"too_many_advisors: tier {t} allows <= {effective_max} external advisor(s), got models={len(models)}, families={len(families)}"
        )
    if t in ("D1", "D2") and not models:
        issues.append(f"missing_advisors: tier {t} requires at least 1 matched external specialist advisor")
    if t == "D2" and not has_strawman:
        issues.append("missing_strawman: tier D2 requires a concrete numbered strawman proposal before inviting blind advisors")

    for mdl in models:
        if LIGHTWEIGHT_MODEL_RE.search(mdl):
            issues.append(f"lightweight_model_forbidden: {mdl!r} is restricted to mechanical checks, not {t} decision tables")

    if (models or families) and len(families) != len(models):
        issues.append(f"family_count_mismatch: {len(models)} advisor_models != {len(families)} advisor_families")
    if t in ("D1", "D2") and not families:
        issues.append(f"missing_advisor_families: tier {t} must declare advisor_families to verify cross-family independence")
    for fam in families:
        if auth_fam and fam == auth_fam:
            issues.append(f"same_family_self_review: advisor family {fam!r} matches author_family {auth_fam!r}")
    if t == "D2" and len(families) >= 2 and len(set(families)) < len(families):
        issues.append("duplicate_advisor_family: D2 blind advisors must come from distinct model families")

    recommended_role = DEFAULT_SPECIALTY_ROLES.get(_norm_token(specialty_domain), "matched_specialist")
    return {
        "ok": len(issues) == 0,
        "tier": t,
        "label": spec["label"],
        "max_rounds": spec["max_rounds"],
        "max_external_advisors": effective_max,
        "recommended_role": recommended_role,
        "issue_count": len(issues),
        "issues": issues,
    }


def evaluate_blast_radius_route(
    *,
    offline_or_readonly: bool = False,
    pure_copy_candidate: bool = False,
    r1_invariants: dict[str, bool] | None = None,
    critical_domains_touched: list[str] | tuple[str, ...] = (),
    claimed_tier: str = "",
    author_family: str = "",
    reviewer_families: list[str] | tuple[str, ...] = (),
    has_written_spec: bool = False,
    independent_verification_passed: bool = False,
    review_round: int = 1,
) -> dict[str, Any]:
    """
    Computes the minimum mandatory review tier (`R0..R3`) from blast-radius signals and
    verifies Fail-Closed that reviewers, invariants, and round caps satisfy the computed tier.
    """
    if r1_invariants is not None and not isinstance(r1_invariants, dict):
        raise ValueError("r1_invariants must be a dict or None")

    issues: list[str] = []
    normalized_domains: list[str] = []
    unknown_domains: list[str] = []
    for raw_dom in critical_domains_touched:
        d = _norm_token(raw_dom)
        if not d:
            continue
        if d not in R3_CRITICAL_DOMAINS:
            unknown_domains.append(str(raw_dom))
            issues.append(f"unknown_critical_domain:{raw_dom!r}")
        else:
            normalized_domains.append(d)

    inv_map = dict(r1_invariants or {})
    r1_all_hold = bool(pure_copy_candidate) and all(inv_map.get(k) is True for k in R1_FAST_LANE_INVARIANTS)

    if normalized_domains or unknown_domains:
        required_tier = "R3"
        rationale = (
            f"Critical blast-radius domain(s) touched: {sorted(set(normalized_domains))}"
            if normalized_domains
            else f"Fail-closed escalation on unrecognized critical domain(s): {unknown_domains}"
        )
    elif offline_or_readonly:
        required_tier = "R0"
        rationale = "Offline / read-only maintenance path (no live runtime or core logic touched)"
    elif r1_all_hold:
        required_tier = "R1"
        rationale = "Pure copy / label / dictionary sync satisfying all 5 R1 fast-lane invariants"
    else:
        required_tier = "R2"
        if pure_copy_candidate:
            missing_inv = [k for k in R1_FAST_LANE_INVARIANTS if inv_map.get(k) is not True]
            rationale = f"Escalated from R1 candidate to R2 because fast-lane invariant(s) failed: {missing_inv}"
        else:
            rationale = "Standard feature / UI / non-critical logic change"

    c_tier = str(claimed_tier or required_tier).strip().upper()
    if c_tier not in BLAST_RADIUS_ORDER:
        raise ValueError(f"Unsupported claimed_tier {claimed_tier!r}; expected one of {tuple(BLAST_RADIUS_ORDER)}")
    if BLAST_RADIUS_ORDER[c_tier] < BLAST_RADIUS_ORDER[required_tier]:
        issues.append(
            f"tier_under_classified: claimed {c_tier} < mandatory {required_tier} ({rationale})"
        )

    effective_tier = required_tier if BLAST_RADIUS_ORDER[required_tier] >= BLAST_RADIUS_ORDER[c_tier] else c_tier

    if isinstance(review_round, bool) or not isinstance(review_round, int) or review_round < 0:
        issues.append(f"invalid_review_round:{review_round!r}")
    elif effective_tier in ("R2", "R3") and review_round > 2:
        issues.append(f"andon_cord_round_cap_exceeded: {effective_tier} caps blind review at <= 2 rounds (1+1), got {review_round}")

    auth_fam = _norm_token(author_family)
    rev_fams = [_norm_token(f) for f in reviewer_families if _norm_token(f)]
    distinct_external = {f for f in rev_fams if f != auth_fam} if auth_fam else set(rev_fams)

    if effective_tier == "R2":
        if not has_written_spec:
            issues.append("missing_written_spec: R2 requires a concise pre-change specification")
        if not auth_fam:
            issues.append("missing_author_family: R2 requires author_family to verify cross-family blind review")
        if len(distinct_external) < 1:
            issues.append("insufficient_blind_reviewers: R2 requires >= 1 cross-family stateless blind reviewer")
        if auth_fam and auth_fam in rev_fams:
            issues.append(f"same_family_reviewer_forbidden: {auth_fam!r} cannot blind-review its own R2 change")
    elif effective_tier == "R3":
        if not has_written_spec:
            issues.append("missing_written_spec: R3 requires an explicit written specification")
        if not auth_fam:
            issues.append("missing_author_family: R3 requires author_family to enforce dual cross-family blind review")
        if auth_fam and auth_fam in rev_fams:
            issues.append(f"same_family_reviewer_forbidden: {auth_fam!r} cannot participate in R3 blind review")
        if len(distinct_external) < 2:
            issues.append(
                f"insufficient_heterogeneous_reviewers: R3 requires >= 2 distinct cross-family blind reviewers in parallel, got {len(distinct_external)}"
            )
        if not independent_verification_passed:
            issues.append(
                "missing_independent_verification: R3 requires independent recomputation / negative-security tests to pass"
            )

    required_blind_reviewers = {"R0": 0, "R1": 0, "R2": 1, "R3": 2}[effective_tier]
    return {
        "ok": len(issues) == 0,
        "required_tier": required_tier,
        "effective_tier": effective_tier,
        "required_blind_reviewers": required_blind_reviewers,
        "fast_lane_eligible": effective_tier in ("R0", "R1"),
        "rationale": rationale,
        "issue_count": len(issues),
        "issues": issues,
    }


def _is_valid_external_entrypoint(entrypoint: str) -> bool:
    """Returns True only for genuine external HTTP(S) URLs or sanitized `public-artifact:` URIs."""
    ep = str(entrypoint or "").strip()
    if not ep or any(ch.isspace() for ch in ep) or LOCAL_PATH_PREFIX_RE.match(ep):
        return False
    if PUBLIC_ARTIFACT_URI_RE.fullmatch(ep):
        return True
    try:
        parsed = urllib.parse.urlparse(ep)
        host = (parsed.hostname or "").strip().lower().rstrip(".")
    except ValueError:
        return False
    if parsed.scheme.lower() not in ("http", "https"):
        return False
    if not host or host == "localhost" or any(host.endswith(sfx) for sfx in INTERNAL_HOST_SUFFIXES):
        return False
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        if "." not in host:
            return False
        labels = host.split(".")
        if any(not lbl for lbl in labels) or all(NUMERIC_OR_HEX_LABEL_RE.fullmatch(lbl) for lbl in labels):
            return False
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if not addr.is_global:
        return False
    if isinstance(addr, ipaddress.IPv4Address) and (addr in CGNAT_NETWORK or addr in FAKE_IP_NETWORK):
        return False
    return True


def evaluate_post_launch_blind_eval(
    *,
    tier: str,
    author_family: str,
    external_entrypoint: str = "",
    leaked_internal_context: bool = False,
    evaluator_models: list[str] | tuple[str, ...] = (),
    evaluator_families: list[str] | tuple[str, ...] = (),
    evaluator_personas: list[str] | tuple[str, ...] = (),
    is_blocking_live_service: bool = False,
    eval_round: int = 1,
) -> dict[str, Any]:
    """
    Validates Stage-3 post-launch zero-context blind evaluation (`B0..B2`) for launched products
    and external commercial deliverables: strictly non-blocking (`is_blocking_live_service=False`),
    single-round backlog capture, genuine external entrypoint only, and distinct cross-family evaluators.
    """
    t = str(tier or "").strip().upper()
    if t not in BLIND_EVAL_TIERS:
        raise ValueError(f"Unsupported blind eval tier {tier!r}; expected one of {tuple(BLIND_EVAL_TIERS)}")
    spec = BLIND_EVAL_TIERS[t]
    issues: list[str] = []

    if is_blocking_live_service is not False:
        issues.append("blind_eval_must_not_block_live_service: Stage-3 blind evaluation feeds backlog only and must never block live service")
    if isinstance(eval_round, bool) or not isinstance(eval_round, int) or eval_round < 0:
        issues.append(f"invalid_eval_round: eval_round={eval_round!r} must be a non-negative integer")
    elif t == "B0" and eval_round > 0:
        issues.append(f"blind_eval_round_cap_exceeded: tier B0 requires eval_round == 0, got {eval_round}")
    elif t in ("B1", "B2") and eval_round != 1:
        issues.append(
            f"blind_eval_round_cap_exceeded: tier {t} caps blind eval at 1 round into next-version backlog, got {eval_round}"
            if eval_round > 1
            else f"invalid_eval_round: tier {t} requires eval_round == 1, got {eval_round}"
        )

    auth_fam = _norm_token(author_family)
    if not auth_fam:
        issues.append("missing_author_family: author_family must be non-empty")

    raw_models = list(evaluator_models)
    raw_families = list(evaluator_families)
    raw_personas = list(evaluator_personas)
    if any(not str(m).strip() for m in raw_models):
        issues.append("blank_evaluator_model: evaluator_models contains empty entry")
    if any(not _norm_token(f) for f in raw_families):
        issues.append("blank_evaluator_family: evaluator_families contains empty entry")
    if any(not _norm_token(p) for p in raw_personas):
        issues.append("blank_evaluator_persona: evaluator_personas contains empty entry")

    models = [str(m).strip() for m in raw_models if str(m).strip()]
    families = [_norm_token(f) for f in raw_families if _norm_token(f)]
    personas = [_norm_token(p) for p in raw_personas if _norm_token(p)]

    for mdl in models:
        if LIGHTWEIGHT_MODEL_RE.search(mdl):
            issues.append(f"lightweight_model_forbidden: {mdl!r} is forbidden for Stage-3 blind evaluation")
    if (models or families) and len(families) != len(models):
        issues.append(f"family_count_mismatch: {len(models)} evaluator_models != {len(families)} evaluator_families")
    if auth_fam and auth_fam in families:
        issues.append(f"same_family_self_eval: evaluator family matches author_family {auth_fam!r}")
    if len(families) >= 2 and len(set(families)) < len(families):
        issues.append("duplicate_evaluator_family: Stage-3 blind evaluators must belong to distinct model families")

    distinct_ext = {f for f in families if f != auth_fam} if auth_fam else set(families)
    if t == "B0":
        if models or families:
            issues.append("unexpected_evaluators_for_b0: tier B0 skips blind evaluation (0 evaluators)")
    else:
        if leaked_internal_context is not False:
            issues.append("internal_context_leaked: Stage-3 evaluators must receive zero internal docs, code, or chat history")
        if not _is_valid_external_entrypoint(external_entrypoint):
            issues.append(
                f"invalid_or_internal_external_entrypoint: {external_entrypoint!r} must be a public HTTP(S) URL or public-artifact:<slug>"
            )
        if len(models) < int(spec["min_evaluators"]) or len(distinct_ext) < int(spec["min_evaluators"]):
            issues.append(
                f"insufficient_blind_evaluators: tier {t} requires >= {spec['min_evaluators']} distinct cross-family blind evaluator(s)"
            )
        if len(models) > int(spec["max_evaluators"]) or len(families) > int(spec["max_evaluators"]):
            issues.append(
                f"too_many_blind_evaluators: tier {t} caps blind evaluators at <= {spec['max_evaluators']}"
            )
        if personas:
            if len(personas) != len(models):
                issues.append(f"persona_count_mismatch: {len(personas)} evaluator_personas != {len(models)} evaluator_models")
            elif len(personas) >= 2 and len(set(personas)) < len(personas):
                issues.append("duplicate_evaluator_persona: evaluator_personas must be distinct across evaluators")

    return {
        "ok": len(issues) == 0,
        "tier": t,
        "label": spec["label"],
        "max_rounds": spec["max_rounds"],
        "min_evaluators": spec["min_evaluators"],
        "max_evaluators": spec["max_evaluators"],
        "distinct_evaluator_families": sorted(distinct_ext),
        "backlog_only": True,
        "issue_count": len(issues),
        "issues": issues,
    }


def partition_ab_folds(
    block_ids: list[str] | tuple[str, ...],
    *,
    embargo_blocks: int = 0,
    holdout_blocks: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """
    Deterministically splits ordered diagnostic blocks into disjoint odd `Fold-A`
    (exposed to blind diagnosticians) and even `Fold-B` (sealed for zero-retrain probe verification),
    optionally enforcing an embargo buffer between adjacent blocks and rejecting any holdout overlap.
    """
    if isinstance(embargo_blocks, bool) or not isinstance(embargo_blocks, int) or embargo_blocks < 0:
        raise ValueError(f"embargo_blocks must be a non-negative integer, got {embargo_blocks!r}")
    ordered = [str(b).strip() for b in block_ids if str(b).strip()]
    if len(ordered) != len(set(ordered)):
        raise ValueError("block_ids must contain unique identifiers")
    holdout_set = {str(b).strip() for b in holdout_blocks if str(b).strip()}
    overlap = sorted(set(ordered) & holdout_set)
    if overlap:
        raise ValueError(f"Holdout zone leakage: diagnostic blocks overlap sealed holdout: {overlap}")

    step = 1 + embargo_blocks
    retained = [ordered[i] for i in range(0, len(ordered), step)]
    fold_a = [b for idx, b in enumerate(retained) if idx % 2 == 0]
    fold_b = [b for idx, b in enumerate(retained) if idx % 2 == 1]
    embargoed = [b for b in ordered if b not in set(retained)]
    if not fold_a or not fold_b:
        raise ValueError(f"Insufficient blocks after embargo={embargo_blocks} to form non-empty Fold-A and Fold-B")
    return {
        "ok": True,
        "fold_a": fold_a,
        "fold_b": fold_b,
        "embargoed": embargoed,
        "exposed_to_diagnosticians": "fold_a_only",
        "sealed_for_verification": "fold_b",
    }


def validate_mm_autopsy_packet(packet: dict[str, Any]) -> dict[str, Any]:
    """
    Validates a Negative-Experiment Double-Blind M&M (Morbidity & Mortality) Autopsy packet:
      1. Triggered only on failed/anomalous experiments, capped at 1 autopsy round, never a release gate;
      2. Disjoint non-empty `Fold-A` (exposed) and `Fold-B` (sealed), zero holdout overlap, zero author hints;
      3. Non-empty `author_family` + >= 2 distinct cross-family blind diagnosticians with unique SHA-256 receipts & 1..3 falsifiable hypotheses each;
      4. Converged zero-retrain `Fold-B` probes (1..3 probes, <=300s each, strictly pre-registered in Fold-A hypotheses, Holm/Bonferroni/BH-FDR with alpha <= 0.05).
    """
    if not isinstance(packet, dict):
        raise ValueError("M&M autopsy packet must be a JSON object")
    issues: list[str] = []

    status = str(packet.get("experiment_status") or "").strip().upper()
    if status not in MM_TRIGGER_STATUSES:
        issues.append(f"invalid_trigger_status: {status!r} not in {sorted(MM_TRIGGER_STATUSES)}")
    if packet.get("is_release_gate") is not False:
        issues.append("mm_must_not_be_release_gate: M&M autopsy is an offline research retrospective (set is_release_gate=false)")
    autopsy_round = packet.get("autopsy_round", 1)
    if isinstance(autopsy_round, bool) or not isinstance(autopsy_round, int) or autopsy_round != 1:
        issues.append(f"no_recursive_autopsy: autopsy_round must equal 1 (got {autopsy_round!r})")

    raw_fa = packet.get("fold_a_blocks")
    raw_fb = packet.get("fold_b_blocks")
    raw_ho = packet.get("holdout_blocks", [])
    fold_a = [str(x).strip() for x in raw_fa if str(x).strip()] if isinstance(raw_fa, list) else []
    fold_b = [str(x).strip() for x in raw_fb if str(x).strip()] if isinstance(raw_fb, list) else []
    if raw_ho is None:
        raw_ho = []
    if not isinstance(raw_ho, list):
        issues.append("invalid_holdout_blocks: holdout_blocks must be a list")
        holdout: set[str] = set()
    else:
        holdout = {str(x).strip() for x in raw_ho if str(x).strip()}
    if not isinstance(raw_fa, list) or not isinstance(raw_fb, list) or not fold_a or not fold_b:
        issues.append("missing_ab_folds: both fold_a_blocks and fold_b_blocks must be non-empty lists")
    overlap_ab = sorted(set(fold_a) & set(fold_b))
    if overlap_ab:
        issues.append(f"self_confirmation_leak: fold_a_blocks and fold_b_blocks overlap on {overlap_ab}")
    holdout_leak = sorted((set(fold_a) | set(fold_b)) & holdout)
    if holdout_leak:
        issues.append(f"holdout_zone_leak: autopsy touches sealed holdout blocks {holdout_leak}")

    if str(packet.get("exposed_to_diagnosticians") or "").strip().lower() != "fold_a_only":
        issues.append("fold_b_exposed: exposed_to_diagnosticians must strictly be 'fold_a_only'")
    if packet.get("contains_author_hypotheses") is not False:
        issues.append("author_bias_leak: Fold-A fact pack must set contains_author_hypotheses=false")

    author_fam = _norm_token(str(packet.get("author_family") or ""))
    if not author_fam:
        issues.append("missing_author_family: author_family must be non-empty to enforce non-author blind diagnosis")

    diags = packet.get("diagnosticians")
    if not isinstance(diags, list) or len(diags) < 2:
        issues.append("insufficient_diagnosticians: M&M requires >= 2 independent blind diagnosticians")
        diags = []

    diag_families: set[str] = set()
    diag_hashes: set[str] = set()
    valid_hash_count = 0
    registered_metrics: set[str] = set()
    for idx, d in enumerate(diags):
        if not isinstance(d, dict):
            issues.append(f"malformed_diagnostician[{idx}]")
            continue
        fam = _norm_token(str(d.get("model_family") or ""))
        if not fam:
            issues.append(f"diagnostician[{idx}]: missing model_family")
        else:
            diag_families.add(fam)
        if d.get("saw_fold_b") is not False:
            issues.append(f"diagnostician[{idx}]: saw_fold_b must be false before probe verification")
        rhash = str(d.get("report_sha256") or "").strip()
        if not SHA256_HEX_RE.fullmatch(rhash):
            issues.append(f"diagnostician[{idx}]: invalid or missing 64-hex report_sha256")
        else:
            valid_hash_count += 1
            diag_hashes.add(rhash.lower())
        hyps = d.get("hypotheses")
        if not isinstance(hyps, list) or not (1 <= len(hyps) <= 3):
            issues.append(f"diagnostician[{idx}]: must propose 1..3 hypotheses (got {len(hyps) if isinstance(hyps, list) else 'invalid'})")
            continue
        for h_i, h in enumerate(hyps):
            if not isinstance(h, dict):
                issues.append(f"diagnostician[{idx}].hypotheses[{h_i}]: must be an object")
                continue
            for req_field in ("mechanism", "fold_b_metric", "single_variable_change"):
                if not str(h.get(req_field) or "").strip():
                    issues.append(f"diagnostician[{idx}].hypotheses[{h_i}]: missing {req_field}")
            metric_norm = _norm_token(str(h.get("fold_b_metric") or ""))
            if metric_norm:
                registered_metrics.add(metric_norm)
            direction = str(h.get("expected_direction") or "").strip().lower()
            if direction not in MM_VALID_DIRECTIONS:
                issues.append(
                    f"diagnostician[{idx}].hypotheses[{h_i}]: expected_direction={direction!r} not in {sorted(MM_VALID_DIRECTIONS)}"
                )

    if len(diag_families) < 2:
        issues.append(f"single_family_blindspot: M&M requires >= 2 distinct diagnostician model families, got {len(diag_families)}")
    if author_fam and author_fam in diag_families:
        issues.append(f"author_family_in_diagnosticians: diagnosticians must be independent from author_family {author_fam!r}")
    if (len(diags) >= 2 and len(diag_hashes) < 2) or len(diag_hashes) < valid_hash_count:
        issues.append("duplicate_diagnosis_hashes: every independent blind diagnostician must produce a unique report_sha256 artifact")

    probes = packet.get("converged_probes")
    if not isinstance(probes, list) or not (1 <= len(probes) <= 3):
        issues.append("invalid_probe_count: converged_probes must contain 1..3 zero-retrain probes")
    else:
        for p_i, pr in enumerate(probes):
            if not isinstance(pr, dict):
                issues.append(f"converged_probes[{p_i}]: must be an object")
                continue
            if pr.get("zero_retrain") is not True:
                issues.append(f"converged_probes[{p_i}]: zero_retrain must be true")
            max_sec = _safe_finite_float(pr.get("max_runtime_sec"))
            if max_sec is None or max_sec <= 0.0 or max_sec > 300.0:
                issues.append(f"converged_probes[{p_i}]: max_runtime_sec must be finite in (0, 300], got {pr.get('max_runtime_sec')!r}")
            probe_metric = _norm_token(str(pr.get("fold_b_metric") or ""))
            if not probe_metric:
                issues.append(f"converged_probes[{p_i}]: missing fold_b_metric")
            elif registered_metrics and probe_metric not in registered_metrics:
                issues.append(
                    f"unregistered_fold_b_probe_metric: converged_probes[{p_i}].fold_b_metric={pr.get('fold_b_metric')!r} was not pre-registered in Fold-A hypotheses"
                )

    correction = str(packet.get("multiple_testing_correction") or "").strip().lower()
    if correction not in MM_VALID_CORRECTIONS:
        issues.append(f"invalid_multiple_testing_correction: {correction!r} not in {sorted(MM_VALID_CORRECTIONS)}")
    alpha = _safe_finite_float(packet.get("alpha"))
    if alpha is None or not (0.0 < alpha <= 0.05):
        issues.append(f"invalid_alpha: alpha must be finite in (0, 0.05], got {packet.get('alpha')!r}")

    return {
        "ok": len(issues) == 0,
        "fold_a_count": len(fold_a),
        "fold_b_count": len(fold_b),
        "distinct_diagnostician_families": sorted(diag_families),
        "probe_count": len(probes) if isinstance(probes, list) else 0,
        "issue_count": len(issues),
        "issues": issues,
    }


def _strip_dot_slash(raw: str) -> str:
    s = str(raw or "").strip()
    while s.startswith("./"):
        s = s[2:]
    return s


def _collect_scan_files(target_path: pathlib.Path, *, exclude_rels: set[str], dict_abs: pathlib.Path) -> list[pathlib.Path]:
    if target_path.is_symlink():
        raise ValueError(f"Symlinked scan target rejected: {target_path}")
    if target_path.is_file():
        return [] if target_path == dict_abs else [target_path]
    if not target_path.is_dir():
        raise FileNotFoundError(f"Scan target does not exist: {target_path}")

    found: list[pathlib.Path] = []
    for root, dirs, files in os.walk(target_path, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_SCAN_DIRS and not (pathlib.Path(root) / d).is_symlink())
        rp = pathlib.Path(root)
        for fn in sorted(files):
            fp = rp / fn
            if fp.is_symlink() or fp == dict_abs:
                continue
            if fp.suffix.lower() in BINARY_EXTS:
                continue
            rel = fp.relative_to(target_path).as_posix()
            if rel in exclude_rels:
                continue
            found.append(fp)
    return found


def _read_text_for_scan(fp: pathlib.Path, *, max_bytes: int = MAX_SCAN_FILE_BYTES) -> tuple[str | None, str]:
    """
    Safely opens and reads a text file non-blocking with O_NOFOLLOW and bounded size.
    Returns `(text, status)` where status is `"ok"`, `"non_regular"`, `"symlink"`, or `"too_large"`.
    """
    if fp.is_symlink():
        return None, "symlink"
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(str(fp), flags)
    except OSError:
        return None, "non_regular"
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, "non_regular"
        if st.st_size > max_bytes:
            return None, "too_large"
        chunks: list[bytes] = []
        total = 0
        while total <= max_bytes:
            chunk = os.read(fd, min(65536, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        os.close(fd)
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        return None, "too_large"
    return raw.decode("utf-8", errors="replace"), "ok"


def audit_master_dictionary_drift(
    dict_path: str | pathlib.Path,
    target_path: str | pathlib.Path,
    *,
    exclude_paths: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    """
    Zero-Token machine-readable Master Dictionary cross-repo drift & forbidden-jargon auditor.

    Verifies:
      1. Dictionary schema integrity & zero dual-SSOT overlap with `single_authority_domains`;
      2. Every matching `canonical_tokens[*].required_in` file contains the exact canonical `value` (directory & single-file targets);
      3. Zero occurrences of `canonical_terms[*].forbidden` or `retired_phrases` across scanned files (O_NOFOLLOW + O_NONBLOCK + bounded);
      4. `typography_invariants.emoji_count == 0` when configured (strictly excluding bool-is-int).
    """
    dict_abs = pathlib.Path(os.path.abspath(os.path.expanduser(str(dict_path))))
    target_abs = pathlib.Path(os.path.abspath(os.path.expanduser(str(target_path))))
    doc, dict_sha = _read_json_nofollow_bounded(dict_abs)
    findings: list[str] = []

    if not str(doc.get("schema_version") or "").strip():
        findings.append("dictionary_schema: missing non-empty schema_version")
    if not str(doc.get("version") or "").strip():
        findings.append("dictionary_schema: missing non-empty version")

    terms_raw = doc.get("canonical_terms", {})
    tokens_raw = doc.get("canonical_tokens", {})
    if terms_raw is not None and not isinstance(terms_raw, dict):
        findings.append("dictionary_schema: canonical_terms must be an object")
        terms: dict[str, Any] = {}
    else:
        terms = terms_raw or {}
    if tokens_raw is not None and not isinstance(tokens_raw, dict):
        findings.append("dictionary_schema: canonical_tokens must be an object")
        canonical_tokens: dict[str, Any] = {}
    else:
        canonical_tokens = tokens_raw or {}

    # Guard against dual-SSOT collisions across top-level, canonical_terms, and canonical_tokens
    delegated_raw = doc.get("single_authority_domains", {})
    if delegated_raw is not None and not isinstance(delegated_raw, dict):
        findings.append("dictionary_schema: single_authority_domains must be an object")
        delegated: dict[str, Any] = {}
    else:
        delegated = delegated_raw or {}
    for dom_key, authority_std in delegated.items():
        if dom_key == "single_authority_domains":
            continue
        if dom_key in doc or dom_key in terms or dom_key in canonical_tokens:
            findings.append(
                f"dual_ssot_violation: key {dom_key!r} is delegated to {authority_std!r} but also defined locally"
            )

    forbidden_terms: list[tuple[str, str]] = []
    for term_key, meta in terms.items():
        if not isinstance(meta, dict):
            findings.append(f"dictionary_schema: canonical_terms.{term_key} must be an object")
            continue
        bad_list = meta.get("forbidden", [])
        if bad_list is not None and not isinstance(bad_list, list):
            findings.append(f"dictionary_schema: canonical_terms.{term_key}.forbidden must be a list")
            continue
        for bad in bad_list or []:
            b = str(bad).strip()
            if b:
                forbidden_terms.append((f"canonical_terms.{term_key}", b))

    retired_raw = doc.get("retired_phrases", [])
    if retired_raw is not None and not isinstance(retired_raw, list):
        findings.append("dictionary_schema: retired_phrases must be a list")
    else:
        for phrase in retired_raw or []:
            p_str = str(phrase).strip()
            if p_str:
                forbidden_terms.append(("retired_phrases", p_str))

    typo = doc.get("typography_invariants") or {}
    emoji_lim = typo.get("emoji_count") if isinstance(typo, dict) else None
    forbid_emoji = isinstance(typo, dict) and not isinstance(emoji_lim, bool) and emoji_lim == 0

    exclude_set = {_strip_dot_slash(x) for x in exclude_paths if _strip_dot_slash(x)}
    files = _collect_scan_files(target_abs, exclude_rels=exclude_set, dict_abs=dict_abs)
    is_single_file = target_abs.is_file()
    single_file_body: str | None = None
    single_file_status = ""
    if is_single_file and target_abs != dict_abs:
        single_file_body, single_file_status = _read_text_for_scan(target_abs)

    # 1. Verify required canonical token presence across declared files (directory & single-file targets)
    for tok_key, meta in canonical_tokens.items():
        if not isinstance(meta, dict):
            findings.append(f"dictionary_schema: canonical_tokens.{tok_key} must be an object")
            continue
        expected_val = str(meta.get("value") or "")
        if not expected_val:
            continue
        req_list = meta.get("required_in", [])
        if req_list is not None and not isinstance(req_list, list):
            findings.append(f"dictionary_schema: canonical_tokens.{tok_key}.required_in must be a list")
            continue
        for rel_req in req_list or []:
            req_norm = _strip_dot_slash(rel_req)
            req_parts = pathlib.PurePosixPath(req_norm).parts
            if not req_norm or req_norm.startswith("/") or ".." in req_parts:
                findings.append(f"canonical_tokens.{tok_key}: unsafe required_in path {rel_req!r}")
                continue
            if is_single_file:
                if req_norm != target_abs.name and not target_abs.as_posix().endswith("/" + req_norm):
                    continue
                if single_file_status != "ok" or single_file_body is None:
                    findings.append(f"canonical_tokens.{tok_key}: unreadable required target ({single_file_status}): {req_norm}")
                elif expected_val not in single_file_body:
                    findings.append(
                        f"canonical_token_drift: {req_norm} missing canonical {tok_key}={expected_val!r}"
                    )
                continue

            cur = target_abs
            symlink_component = False
            for part in req_parts:
                cur = cur / part
                if cur.is_symlink():
                    symlink_component = True
                    break
            if symlink_component or not cur.is_file():
                findings.append(f"canonical_tokens.{tok_key}: required file missing or symlinked: {req_norm}")
                continue
            body, st_read = _read_text_for_scan(cur)
            if st_read != "ok" or body is None:
                findings.append(f"canonical_tokens.{tok_key}: required file rejected ({st_read}): {req_norm}")
                continue
            if expected_val not in body:
                findings.append(
                    f"canonical_token_drift: {req_norm} missing canonical {tok_key}={expected_val!r}"
                )

    # 2. Scan all target files for forbidden jargon, retired phrases & emoji violations
    for fp in files:
        rel_label = fp.name if is_single_file else fp.relative_to(target_abs).as_posix()
        if is_single_file and fp == target_abs:
            text, st_read = single_file_body, single_file_status
        else:
            text, st_read = _read_text_for_scan(fp)
        if st_read == "too_large":
            findings.append(f"{rel_label}: file exceeds {MAX_SCAN_FILE_BYTES}B scan cap (cannot bypass dictionary audit)")
            continue
        if st_read != "ok" or text is None:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for src_key, bad_tok in forbidden_terms:
                if bad_tok in line:
                    findings.append(f"{rel_label}:{lineno}: forbidden phrase {bad_tok!r} ({src_key})")
            if forbid_emoji and EMOJI_RE.search(line):
                findings.append(f"{rel_label}:{lineno}: emoji violation (typography_invariants.emoji_count == 0)")

    return {
        "ok": len(findings) == 0,
        "dictionary_version": str(doc.get("version") or ""),
        "dictionary_sha256_prefix": dict_sha,
        "scanned_files": len(files),
        "finding_count": len(findings),
        "findings": findings,
    }
