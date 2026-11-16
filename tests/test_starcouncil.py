#!/usr/bin/env python3
"""Deterministic clean-room unit tests for StarCouncil v0.1.0 (5 live archives + anti-fake-council + 6 gates)."""

from __future__ import annotations

import ast
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

PKG_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_DIR = PKG_ROOT / "src"
SCRIPT = PKG_ROOT / "scripts" / "starcouncil.py"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from starcouncil.blackboard import (  # noqa: E402
    MAX_ENVELOPE_BYTES,
    MAX_STDIN_BYTES,
    ack_pointer,
    build_ssh_peer_command,
    dispatch_pointer,
    ingest_peer_stdin,
    init_workspace,
    read_board,
    refresh_board_locks,
    run_with_lock,
    update_board,
)
from starcouncil.governance import (  # noqa: E402
    council_submit,
    council_verify,
    evaluate_review_gate,
    format_plain_3line,
    lint_plain_summary,
    log_fix,
    log_pitfall,
    plan_council,
    pseudonymize_text,
    render_council_workflow,
    run_doctor,
    run_sanitize_lint,
)
from starcouncil.wake_gates import apply_wake_attempt, evaluate_six_gates  # noqa: E402


class StarCouncilCleanRoomTests(unittest.TestCase):
    def run_cli(self, *args: str, check: bool = True, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            input=input_bytes,
            capture_output=True,
            check=check,
        )

    def test_01_init_five_archives_board_budget_and_doctor_purity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            res = init_workspace(root, topology="local-tmux", subscription="single-sub")
            self.assertTrue(res["ok"])
            self.assertEqual(res["max_concurrent_agents"], 1)
            self.assertTrue((root / ".starcouncil" / "logs" / "events.jsonl").is_file())
            self.assertTrue((root / ".starcouncil" / "fixes_log.md").is_file())
            self.assertTrue((root / ".starcouncil" / "meetings").is_dir())

            ok_board = update_board(root, "# Board\n\nAll good.\n")
            self.assertLess(ok_board["bytes"], 3072)
            self.assertIn("All good.", read_board(root))
            refreshed = refresh_board_locks(root)
            self.assertTrue(refreshed["ok"])
            with self.assertRaises(ValueError):
                update_board(root, "x" * 3072)

            clean_settings = root / "clean_settings.json"
            clean_settings.write_text(json.dumps({"additionalDirectories": []}), encoding="utf-8")
            doc_ok = run_doctor(root, settings_path=clean_settings, transcript_steps=120)
            self.assertTrue(doc_ok["ok"], doc_ok)

            dirty_settings = root / "dirty_settings.json"
            dirty_settings.write_text(json.dumps({"additionalDirectories": ["/tmp/other"]}), encoding="utf-8")
            doc_bad = run_doctor(root, settings_path=dirty_settings, transcript_steps=3800)
            self.assertFalse(doc_bad["ok"])
            failed_names = {c["check"] for c in doc_bad["checks"] if not c["ok"]}
            self.assertIn("settings_additional_dirs", failed_names)
            self.assertIn("session_bloat_check", failed_names)

    def test_02_dispatch_pointer_envelope_limit_and_symlink_nofollow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)
            long_summary = "A" * 500
            res = dispatch_pointer(
                root,
                from_seat="lead",
                to_seat="builder",
                summary=long_summary,
                artifact_text="Full detailed spec saved to disk.",
                event_id="evt-ptr-001",
                now_ts=1000.0,
            )
            self.assertEqual(res["action"], "DISPATCHED")
            self.assertLess(res["pointer_bytes"], MAX_ENVELOPE_BYTES)
            inbox_file = root / ".starcouncil" / "inbox" / "builder.jsonl"
            lines = inbox_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertLess(len(lines[0].encode("utf-8")), MAX_ENVELOPE_BYTES)

            evil_target = root / "outside.jsonl"
            evil_target.write_text("", encoding="utf-8")
            sym_inbox = root / ".starcouncil" / "inbox" / "reviewer.jsonl"
            sym_inbox.symlink_to(evil_target)
            with self.assertRaises(OSError):
                dispatch_pointer(
                    root,
                    from_seat="lead",
                    to_seat="reviewer",
                    summary="symlink probe",
                    event_id="evt-ptr-002",
                    now_ts=1001.0,
                )

    def test_03_idempotency_hop_cap_ack_silence_and_resonance_circuit_breaker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)

            with self.assertRaises(ValueError):
                dispatch_pointer(root, from_seat="lead", to_seat="builder", summary="hop2", hop=2, event_id="evt-h2", now_ts=1000.0)

            first = dispatch_pointer(root, from_seat="lead", to_seat="builder", summary="once", event_id="evt-dedup-1", now_ts=2000.0)
            dup = dispatch_pointer(root, from_seat="lead", to_seat="builder", summary="twice", event_id="evt-dedup-1", now_ts=2100.0)
            self.assertEqual(first["action"], "DISPATCHED")
            self.assertEqual(dup["action"], "DEDUP_SKIPPED")

            ack_pointer(root, seat="builder", event_id="evt-dedup-1", emit_reply_to="lead", priority="P1", now_ts=3000.0)
            with self.assertRaises(ValueError):
                dispatch_pointer(
                    root,
                    from_seat="builder",
                    to_seat="lead",
                    summary="ack echo",
                    kind="ACK",
                    priority="P1",
                    event_id="evt-ack-echo",
                    now_ts=3020.0,
                )
            p0_ack = dispatch_pointer(
                root,
                from_seat="builder",
                to_seat="lead",
                summary="p0 alert",
                kind="ACK",
                priority="P0",
                event_id="evt-ack-p0",
                now_ts=3025.0,
            )
            self.assertEqual(p0_ack["action"], "DISPATCHED")

            for idx in range(4):
                dispatch_pointer(
                    root,
                    from_seat="lead",
                    to_seat="builder",
                    summary=f"burst {idx}",
                    event_id=f"evt-fast-{idx}",
                    now_ts=10000.0 + idx * 10,
                )
            with self.assertRaises(ValueError) as ctx_fast:
                dispatch_pointer(
                    root,
                    from_seat="lead",
                    to_seat="builder",
                    summary="burst overflow",
                    event_id="evt-fast-overflow",
                    now_ts=10040.0,
                )
            self.assertIn("RESONANCE_CIRCUIT_OPEN", str(ctx_fast.exception))

            for idx in range(7):
                dispatch_pointer(
                    root,
                    from_seat="builder",
                    to_seat="lead",
                    summary=f"slow {idx}",
                    event_id=f"evt-slow-{idx}",
                    now_ts=20000.0 + idx * 125,
                )
            with self.assertRaises(ValueError) as ctx_slow:
                dispatch_pointer(
                    root,
                    from_seat="builder",
                    to_seat="lead",
                    summary="slow overflow",
                    event_id="evt-slow-overflow",
                    now_ts=20875.0,
                )
            self.assertIn("RESONANCE_CIRCUIT_OPEN", str(ctx_slow.exception))

    def test_04_ssh_federated_shlex_quote_and_ascii_stdin_limits(self) -> None:
        argv = build_ssh_peer_command("workstation", "/opt/bin/starcouncil;rm -rf /")
        self.assertEqual(argv[:6], ["ssh", "-o", "BatchMode=yes", "-o", "ForwardAgent=no", "workstation"])
        self.assertIn("'/opt/bin/starcouncil;rm -rf /'", argv[6])

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root, topology="ssh-federated", host_alias="workstation")

            with self.assertRaises(ValueError):
                ingest_peer_stdin(root, b"a" * (MAX_STDIN_BYTES + 1))

            with self.assertRaises(ValueError):
                ingest_peer_stdin(root, "非ASCII".encode("utf-8"))

            bad_host = json.dumps(
                {
                    "from_host": "rogue-box",
                    "from_seat": "remote-hub",
                    "to_seat": "lead",
                    "summary": "hello",
                    "hop": 1,
                    "event_id": "evt-ssh-bad",
                }
            ).encode("ascii")
            with self.assertRaises(ValueError):
                ingest_peer_stdin(root, bad_host, now_ts=5000.0)

            good = json.dumps(
                {
                    "from_host": "workstation",
                    "from_seat": "remote-hub",
                    "to_seat": "lead",
                    "summary": "RFC review feedback attached",
                    "hop": 1,
                    "event_id": "evt-ssh-ok",
                }
            ).encode("ascii")
            ok_res = ingest_peer_stdin(root, good, now_ts=5000.0)
            self.assertEqual(ok_res["action"], "DISPATCHED")

    def test_05_flock_resource_mutex_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)
            rc = run_with_lock(root, "browser", "lead", [sys.executable, "-c", "import sys; sys.exit(0)"])
            self.assertEqual(rc, 0)
            self.assertFalse((root / ".starcouncil" / "locks" / "browser.holder.json").exists())
            ev_actions = [
                json.loads(ln)["action"]
                for ln in (root / ".starcouncil" / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertIn("LOCK_ACQUIRE", ev_actions)
            self.assertIn("LOCK_RELEASE", ev_actions)

    def test_06_six_gate_wakeup_client_activity_daemon_human_wait_and_bspace_rollback(self) -> None:
        base_snap = {
            "msg_id": "msg-001",
            "msg_text": "Please inspect evt-001",
            "msg_status": "PENDING",
            "msg_attempts": 0,
            "last_attempt_ts": 0.0,
            "pane_in_mode": 0,
            "pane_fg": "agy",
            "agy_in_tree": True,
            "client_activity_ts": 900.0,
            "capture_lines": ["──────", ">   Ask anything...", "──────"],
            "cursor_x": 4,
            "transcript_last_type": "PLANNER_RESPONSE",
            "transcript_last_status": "DONE",
            "transcript_has_tool_calls": False,
            "running_tasks": [{"description": "cron (daily-watch)", "status": "running", "isDaemon": True}],
            "recent_seat_wakes": [],
        }
        now = 1000.0
        ok_res = evaluate_six_gates(base_snap, now_ts=now)
        self.assertTrue(ok_res["wake"], ok_res)

        body_mention = dict(base_snap, msg_text="Please handle follow-up\nNote: ignore 【TERMINAL-ACK】 in body")
        self.assertTrue(evaluate_six_gates(body_mention, now_ts=now)["wake"])
        head_silent = dict(base_snap, msg_text="【TERMINAL-ACK】All done")
        self.assertFalse(evaluate_six_gates(head_silent, now_ts=now)["wake"])

        typing_snap = dict(base_snap, client_activity_ts=990.0)
        self.assertEqual(evaluate_six_gates(typing_snap, now_ts=now)["reason"], "CLIENT_TYPING_ACTIVE")

        human_wait = dict(base_snap, msg_status="SEEN_AWAITING_HUMAN")
        self.assertEqual(evaluate_six_gates(human_wait, now_ts=now)["reason"], "SEEN_AWAITING_HUMAN")

        wstate: dict = {}
        r1 = apply_wake_attempt(wstate, seat="lead", msg_id="msg-001", frame1_ok=True, frame2_ok=False, now_ts=1000.0)
        self.assertEqual(r1["attempts"], 1)
        self.assertEqual(r1["cleanup_keys"], ["BSpace"] * len("[BUS-WAKE]"))
        self.assertEqual(r1["status"], "PENDING")
        r2 = apply_wake_attempt(wstate, seat="lead", msg_id="msg-001", frame1_ok=True, frame2_ok=True, now_ts=1040.0)
        self.assertEqual(r2["attempts"], 2)
        self.assertEqual(r2["status"], "SEEN_AWAITING_HUMAN")

    def test_07_council_single_sub_serial_remote_dnd_and_workflow_ast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root, topology="ssh-federated", subscription="single-sub", host_alias="workstation")

            daily = plan_council(root, topic="安排社区发帖时间", tags_csv="outreach")
            self.assertEqual(daily["max_concurrent_agents"], 1)
            self.assertEqual(daily["execution_pattern"], "serial_3_lens_single_session")
            self.assertEqual(len(daily["serial_lenses"]), 3)
            self.assertNotIn("remote-hub", [s["id"] for s in daily["invited_seats"]])

            arch = plan_council(root, topic="优化跨机 Skill 架构", tags_csv="skill")
            rem = [s for s in arch["invited_seats"] if s["id"] == "remote-hub"]
            self.assertEqual(len(rem), 1)
            self.assertEqual(rem[0]["mode"], "async_card")

            wf_src = render_council_workflow("检查边界条件", model_tier="pro")
            tree = compile(wf_src, "wf.py", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT | ast.PyCF_ONLY_AST)
            compile(wf_src, "wf.py", "exec", flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT)
            agent_calls = [
                n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "agent"
            ]
            self.assertGreaterEqual(len(agent_calls), 1)
            for c in agent_calls:
                self.assertIn("model", [kw.arg for kw in c.keywords])

    def test_08_review_two_round_andon_cord_fail_closed_hmac_and_plain_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)

            r0 = evaluate_review_gate(root, level=0, content_tree_hash="deadbeef0001")
            self.assertEqual(r0["status"], "PASS_LOCAL_ONLY")

            r_gpu = evaluate_review_gate(root, level=1, content_tree_hash="deadbeef0002", requires_local_sampling=True, gpu_locked=True)
            self.assertEqual(r_gpu["status"], "DEFERRED_RESOURCE_BUSY")
            r_code = evaluate_review_gate(root, level=1, content_tree_hash="deadbeef0002", requires_local_sampling=False, gpu_locked=True)
            self.assertEqual(r_code["status"], "PASS")

            r_outage = evaluate_review_gate(root, level=2, content_tree_hash="deadbeef0003", external_status="timeout")
            self.assertEqual(r_outage["status"], "OUTAGE_FAIL_CLOSED")
            self.assertTrue(r_outage["blocked"])

            r_halt = evaluate_review_gate(
                root,
                level=2,
                content_tree_hash="deadbeef0004",
                round_num=2,
                blockers=["uncaught symlink traversal"],
            )
            self.assertEqual(r_halt["status"], "PITFALL_HALT")
            self.assertTrue(r_halt["blocked"])
            self.assertIn("PITFALL_HALT", (root / ".starcouncil" / "pitfalls.md").read_text(encoding="utf-8"))

            secret = "ephemeral-secret-2026"
            sample_home = "/".join(["", "Users", "alice_dev", "project"])
            sample_ip = ".".join(["100", "88", "77", "66"])
            scrubbed = pseudonymize_text(f"path={sample_home} host={sample_ip}", secret)
            self.assertNotIn("alice_dev", scrubbed)
            self.assertNotIn(sample_ip, scrubbed)
            self.assertEqual(scrubbed, pseudonymize_text(f"path={sample_home} host={sample_ip}", secret))

            msg = format_plain_3line("已完成修改", "全套单测通过", "无")
            self.assertTrue(lint_plain_summary(msg)["ok"])
            self.assertFalse(lint_plain_summary("已完成双向强绑定 【TERMINAL-ACK】")["ok"])

    def test_09_clean_room_tree_passes_sanitize_lint_and_skill_length_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            bad_dir = pathlib.Path(tmp)
            p_home = "/".join(["", "Users", "alice_private", "secret.py"])
            p_ip = ".".join(["192", "168", "10", "55"])
            p_uuid = "-".join(["12345678", "9abc", "4def", "8123", "abcdef012345"])
            (bad_dir / "leak.txt").write_text(f"{p_home}\n{p_ip}\n{p_uuid}\n", encoding="utf-8")
            bad_rep = run_sanitize_lint(bad_dir)
            self.assertFalse(bad_rep["ok"])
            rules = {f["rule"] for f in bad_rep["findings"]}
            self.assertEqual(rules, {"HOME_ABS_PATH", "PRIVATE_OR_TAILSCALE_IP", "REAL_SESSION_UUID"})

        for skill in ("starcouncil-teamwork", "starcouncil-review", "starcouncil-council"):
            sf = PKG_ROOT / "skills" / skill / "SKILL.md"
            self.assertTrue(sf.is_file(), f"Missing {sf}")
            self.assertLess(len(sf.read_text(encoding="utf-8").splitlines()), 120)

        clean_rep = run_sanitize_lint(PKG_ROOT)
        self.assertTrue(clean_rep["ok"], f"Clean-room leak detected: {clean_rep['findings']}")
        r_cli = self.run_cli("sanitize-lint", "--target", str(PKG_ROOT))
        self.assertEqual(r_cli.returncode, 0)

    def test_10_live_events_jsonl_pitfalls_and_fixes_log_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)
            log_pitfall(root, title="Quote leak bug", root_cause="Used unquoted string", guard="Use shlex.quote")
            log_fix(root, title="Quote fix", fix_summary="Switched to shlex.quote", files="src/starcouncil/blackboard.py")

            cn = plan_council(root, topic="Check security hardening")
            self.assertTrue(any("Quote leak bug" in p for p in cn["recent_pitfalls"]))

            rv = evaluate_review_gate(
                root,
                level=2,
                content_tree_hash="deadbeef0099",
                round_num=2,
                blockers=[],
                record_fix="Added nofollow guard",
            )
            self.assertEqual(rv["status"], "PASS")
            self.assertIn("Added nofollow guard", (root / ".starcouncil" / "fixes_log.md").read_text(encoding="utf-8"))

            events = [
                json.loads(ln)["action"]
                for ln in (root / ".starcouncil" / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            for expected in ("INIT", "LOG_PITFALL", "LOG_FIX", "COUNCIL_PLAN", "REVIEW"):
                self.assertIn(expected, events)

    def test_11_anti_fake_council_blocks_solo_or_duplicate_and_allows_verified_multi_seat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)

            # 1) Single-author submission cannot pass as MULTI_SEAT_DECISION
            council_submit(root, meeting_id="rfc-solo", author="lead", source_kind="local_seat", content="Only one view.")
            solo_blocked = council_verify(root, meeting_id="rfc-solo", require_multi_seat=True)
            self.assertTrue(solo_blocked["blocked"])
            self.assertEqual(solo_blocked["decision_grade"], "SOLO_SYNTHESIS")
            self.assertIn("Fake-Council Guard Blocked", (root / ".starcouncil" / "pitfalls.md").read_text(encoding="utf-8"))

            # With --allow-solo (require_multi_seat=False), allowed ONLY with SOLO_SYNTHESIS watermark
            solo_allowed = council_verify(root, meeting_id="rfc-solo", require_multi_seat=False)
            self.assertFalse(solo_allowed["blocked"])
            self.assertEqual(solo_allowed["decision_grade"], "SOLO_SYNTHESIS")

            # CLI council-verify exit code 2 when blocked
            r_blk = self.run_cli("council-verify", "--root", str(root), "--meeting-id", "rfc-solo", check=False)
            self.assertEqual(r_blk.returncode, 2)

            # 2) Two authors submitting byte-for-byte identical copy-paste content must NOT pass!
            council_submit(root, meeting_id="rfc-dup", author="lead", source_kind="local_seat", content="Same copied opinion")
            council_submit(root, meeting_id="rfc-dup", author="builder", source_kind="external_llm", content="Same copied opinion")
            dup_res = council_verify(root, meeting_id="rfc-dup", require_multi_seat=True)
            self.assertTrue(dup_res["blocked"])
            self.assertEqual(dup_res["decision_grade"], "SOLO_SYNTHESIS")

            # 3) Distinct authors, source kinds & distinct content hashes -> MULTI_SEAT_DECISION
            council_submit(root, meeting_id="rfc-real", author="lead", source_kind="local_seat", content="Keep interfaces minimal.")
            council_submit(root, meeting_id="rfc-real", author="advisor", source_kind="external_llm", content="Verified hash checks prevent tampering.")
            ok_res = council_verify(root, meeting_id="rfc-real", require_multi_seat=True, resolution_summary="Adopt hash check.")
            self.assertFalse(ok_res["blocked"])
            self.assertEqual(ok_res["decision_grade"], "MULTI_SEAT_DECISION")
            self.assertEqual(ok_res["distinct_authors"], ["advisor", "lead"])

            # 4) Tampering with a raw .md file after submission raises tamper error
            (root / ".starcouncil" / "meetings" / "rfc-real" / "submissions" / "lead__local_seat.md").write_text("Tampered!", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx_tamp:
                council_verify(root, meeting_id="rfc-real", require_multi_seat=True)
            self.assertIn("TAMPERED_SUBMISSION_HASH_MISMATCH", str(ctx_tamp.exception))


if __name__ == "__main__":
    unittest.main()
