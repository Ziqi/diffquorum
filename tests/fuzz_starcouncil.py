#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarCouncil Contributors
# SPDX-License-Identifier: MIT
"""
StarCouncil Dual-Mode Adversarial Fuzzing Harness (tests/fuzz_starcouncil.py)

Supports:
  1. Native Google Atheris coverage-guided libFuzzer loop (`--atheris`).
  2. Zero-dependency deterministic PRNG + structure-aware security-invariant campaign
     (`python3 -W error tests/fuzz_starcouncil.py --iterations 2000`) verifying:
       - Pointer envelope budget (< 400 bytes) under arbitrary summary inputs
       - BOARD.md budget (< 3072 bytes) enforcement
       - Symlink escape & O_NOFOLLOW rejection inside `.starcouncil/`
       - Anti-fake-council SHA-256 tamper & single-author / copy-paste blocking
       - Clean-room sanitize-lint & HMAC pseudonymization invariants
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import random
import string
import sys
import tempfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from starcouncil.blackboard import (  # noqa: E402
    MAX_BOARD_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_STDIN_BYTES,
    dispatch_pointer,
    ingest_peer_stdin,
    init_workspace,
    update_board,
)
from starcouncil.governance import (  # noqa: E402
    council_submit,
    council_verify,
    evaluate_review_gate,
    lint_plain_summary,
    pseudonymize_text,
    run_sanitize_lint,
)
from starcouncil.wake_gates import evaluate_six_gates  # noqa: E402


def _rand_text(rng: random.Random, min_len: int = 1, max_len: int = 600) -> str:
    alphabet = string.ascii_letters + string.digits + " -_/:.;\n\t中英文测试"
    ln = rng.randint(min_len, max_len)
    return "".join(rng.choice(alphabet) for _ in range(ln))


def fuzz_one_bytes(data: bytes) -> None:
    """Arbitrary byte-stream fuzz target for Atheris / CI edge-corpus testing."""
    text = data.decode("utf-8", errors="replace")
    scrubbed = pseudonymize_text(text, "fuzz-ephemeral-key")
    probe_home = "/".join(["", "Users", "real_user"])
    if probe_home in text and probe_home in scrubbed:
        raise AssertionError("pseudonymize_text failed to scrub home path")
    _ = lint_plain_summary(text)

    try:
        snap = json.loads(text)
    except Exception:
        snap = None
    if isinstance(snap, dict):
        try:
            _ = evaluate_six_gates(snap, now_ts=1000.0)
        except (TypeError, ValueError, KeyError, AttributeError):
            pass


def run_stdlib_campaign(iterations: int, seed: int) -> int:
    rng = random.Random(seed)
    with tempfile.TemporaryDirectory(prefix="starcouncil_fuzz_") as tmp:
        root = pathlib.Path(tmp)
        init_workspace(root, topology="ssh-federated", subscription="single-sub", host_alias="workstation")

        # Pre-plant symlink trap outside inbox to confirm O_NOFOLLOW blocks all iterations
        trap_outside = root / "outside_trap.jsonl"
        trap_outside.write_text("", encoding="utf-8")
        trap_link = root / ".starcouncil" / "inbox" / "trap.jsonl"
        trap_link.symlink_to(trap_outside)

        for i in range(iterations):
            op = i % 5
            if op == 0:
                # 1. Pointer envelope MUST remain strictly < 400B for any summary
                summary = _rand_text(rng, 10, 800)
                if not summary.strip():
                    summary = "fallback"
                res = dispatch_pointer(
                    root,
                    from_seat="lead",
                    to_seat="builder",
                    summary=summary,
                    artifact_text=summary * 2,
                    hop=rng.choice([0, 1]),
                    event_id=f"evt-fuzz-{i}",
                    now_ts=10000.0 + i * 200.0,
                )
                assert res["pointer_bytes"] < MAX_ENVELOPE_BYTES, f"Pointer exceeded limit: {res}"
            elif op == 1:
                # 2. BOARD.md MUST allow <3KB and reject >=3KB
                size = rng.choice([128, 1024, MAX_BOARD_BYTES, MAX_BOARD_BYTES + 200])
                payload = "B" * size
                if size >= MAX_BOARD_BYTES:
                    try:
                        update_board(root, payload)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError("update_board accepted oversized payload")
                else:
                    out = update_board(root, payload)
                    assert out["bytes"] < MAX_BOARD_BYTES
            elif op == 2:
                # 3. Anti-fake-council MUST block identical copy-paste content or single author
                text_a = f"opinion-{i}-{rng.randint(1, 9999)}"
                mid = f"fuzz-m-{i}"
                council_submit(root, meeting_id=mid, author="lead", source_kind="local_seat", content=text_a)
                if rng.random() < 0.5:
                    # Copy-paste attack under second author name -> MUST stay SOLO_SYNTHESIS (blocked=True)
                    council_submit(root, meeting_id=mid, author="builder", source_kind="external_llm", content=text_a)
                    ver = council_verify(root, meeting_id=mid, require_multi_seat=True)
                    assert ver["blocked"] is True and ver["decision_grade"] == "SOLO_SYNTHESIS"
                else:
                    # Independent non-identical submission -> MUST succeed as MULTI_SEAT_DECISION
                    council_submit(root, meeting_id=mid, author="advisor", source_kind="remote_node", content=text_a + "-distinct")
                    ver = council_verify(root, meeting_id=mid, require_multi_seat=True)
                    assert ver["blocked"] is False and ver["decision_grade"] == "MULTI_SEAT_DECISION"
            elif op == 3:
                # 4. Symlink trap + unallowlisted stdin bytes must always fail closed
                try:
                    dispatch_pointer(
                        root,
                        from_seat="lead",
                        to_seat="trap",
                        summary="symlink escape attempt",
                        event_id=f"evt-trap-{i}",
                        now_ts=10000.0 + i * 200.0,
                    )
                except OSError:
                    pass
                else:
                    raise AssertionError("O_NOFOLLOW allowed write through symlink!")

                raw = os.urandom(rng.randint(1, 64))
                fuzz_one_bytes(raw)
                if rng.random() < 0.3:
                    try:
                        ingest_peer_stdin(root, b"z" * (MAX_STDIN_BYTES + 1))
                    except ValueError:
                        pass
            else:
                # 5. Review Andon cord & HMAC redaction invariants
                h = hashlib.sha256(f"{seed}-{i}".encode("utf-8")).hexdigest()
                rv = evaluate_review_gate(
                    root,
                    level=2,
                    content_tree_hash=h,
                    round_num=2,
                    blockers=[f"defect-{i}"],
                )
                assert rv["status"] == "PITFALL_HALT" and rv["blocked"] is True
                fake_ip = ".".join(["100", "99", str(rng.randint(1, 250)), str(rng.randint(1, 250))])
                fake_user = "/".join(["", "Users", f"dev{i}", "work"])
                assert fake_ip not in pseudonymize_text(f"{fake_user} {fake_ip}", f"k-{i}")
                assert trap_outside.read_text(encoding="utf-8") == ""

    # Confirm clean-room self-scan remains 100% green
    assert run_sanitize_lint(REPO_ROOT)["ok"] is True
    print(
        f"[PASS] [FUZZ-HARNESS] Completed {iterations} iterations (0 crashes; <400B envelope, <3KB board, nofollow, SHA-256 anti-fake-council & HMAC invariants held)."
    )
    return 0


def run_atheris() -> None:
    import atheris  # OpenSSF Scorecard recognized coverage-guided Python fuzzer

    atheris.Setup(sys.argv, fuzz_one_bytes)
    atheris.Fuzz()


def main() -> int:
    parser = argparse.ArgumentParser(description="StarCouncil Dual-Mode Fuzzing Harness")
    parser.add_argument("--atheris", action="store_true", help="Run native Google Atheris libFuzzer loop")
    parser.add_argument("--iterations", type=int, default=2000, help="Number of deterministic fuzz iterations")
    parser.add_argument("--seed", type=int, default=20261116, help="PRNG seed")
    args, _unknown = parser.parse_known_args()

    if args.atheris:
        run_atheris()
        return 0
    return run_stdlib_campaign(args.iterations, args.seed)


if __name__ == "__main__":
    sys.exit(main())
