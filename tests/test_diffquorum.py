#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Deterministic clean-room unit tests for DiffQuorum (5 live archives, blind quorum, 6 gates, preflight & presets)."""

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
SCRIPT = PKG_ROOT / "scripts" / "diffquorum.py"
LEGACY_SCRIPT = PKG_ROOT / "scripts" / "starcouncil.py"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from diffquorum.blackboard import (  # noqa: E402
    MAX_ENVELOPE_BYTES,
    MAX_STDIN_BYTES,
    ack_pointer,
    build_ssh_peer_command,
    dispatch_pointer,
    dq_dir,
    ingest_peer_stdin,
    init_workspace,
    read_board,
    refresh_board_locks,
    run_preflight,
    run_with_lock,
    update_board,
    verify_pointer_envelope,
)
from diffquorum.governance import (  # noqa: E402
    build_runner_preset,
    evaluate_review_gate,
    format_plain_3line,
    lint_plain_summary,
    log_fix,
    log_pitfall,
    plan_council,
    probe_model_receipt,
    pseudonymize_text,
    quorum_render_blind_packet,
    quorum_submit,
    quorum_verify,
    render_council_workflow,
    run_doctor,
    run_release_preflight,
    run_sanitize_lint,
    verify_model_identity,
)
from diffquorum.ops import (  # noqa: E402
    _disp_width,
    collect_ast_imports,
    curate_ledger,
    render_dual_hud,
    run_readonly_probe,
    scrub_probe_env,
)
from diffquorum.wake_gates import (  # noqa: E402
    apply_wake_attempt,
    classify_seat_state,
    evaluate_six_gates,
    extract_user_request_text,
    is_awaiting_human_approve,
    is_bare_idle_prompt,
    is_explicit_approval_text,
    is_idle_cli_footer,
    is_pane_tail_busy,
    revocation_applies_to_scope,
    strip_terminal_escapes,
)


class DiffQuorumCleanRoomTests(unittest.TestCase):
    def run_cli(
        self,
        *args: str,
        check: bool = True,
        input_bytes: bytes | None = None,
        script_path: pathlib.Path = SCRIPT,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(script_path), *args],
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
            self.assertTrue((root / ".diffquorum" / "logs" / "events.jsonl").is_file())
            self.assertTrue((root / ".diffquorum" / "fixes_log.md").is_file())
            self.assertTrue((root / ".diffquorum" / "meetings").is_dir())

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
            inbox_file = root / ".diffquorum" / "inbox" / "builder.jsonl"
            lines = inbox_file.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            self.assertLess(len(lines[0].encode("utf-8")), MAX_ENVELOPE_BYTES)

            evil_target = root / "outside.jsonl"
            evil_target.write_text("", encoding="utf-8")
            sym_inbox = root / ".diffquorum" / "inbox" / "reviewer.jsonl"
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
        argv = build_ssh_peer_command("workstation", "/opt/bin/diffquorum;rm -rf /")
        self.assertEqual(argv[:6], ["ssh", "-o", "BatchMode=yes", "-o", "ForwardAgent=no", "workstation"])
        self.assertIn("'/opt/bin/diffquorum;rm -rf /'", argv[6])

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
            self.assertFalse((root / ".diffquorum" / "locks" / "browser.holder.json").exists())
            ev_actions = [
                json.loads(ln)["action"]
                for ln in (root / ".diffquorum" / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()
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

    def test_07_quorum_single_sub_serial_remote_dnd_and_workflow_ast(self) -> None:
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
            self.assertIn("PITFALL_HALT", (root / ".diffquorum" / "pitfalls.md").read_text(encoding="utf-8"))

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

        for skill in ("diffquorum-coord", "diffquorum-quorum", "diffquorum-gate"):
            sf = PKG_ROOT / "skills" / skill / "SKILL.md"
            self.assertTrue(sf.is_file(), f"Missing {sf}")
            txt = sf.read_text(encoding="utf-8")
            self.assertLess(len(txt.splitlines()), 100)
            self.assertIn("<SUBAGENT-STOP>", txt)

        clean_rep = run_sanitize_lint(PKG_ROOT)
        self.assertTrue(clean_rep["ok"], f"Clean-room leak detected: {clean_rep['findings']}")
        r_cli = self.run_cli("sanitize-lint", "--target", str(PKG_ROOT))
        self.assertEqual(r_cli.returncode, 0)

    def test_10_live_events_jsonl_pitfalls_and_fixes_log_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)
            log_pitfall(root, title="Quote leak bug", root_cause="Used unquoted string", guard="Use shlex.quote")
            log_fix(root, title="Quote fix", fix_summary="Switched to shlex.quote", files="src/diffquorum/blackboard.py")

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
            self.assertIn("Added nofollow guard", (root / ".diffquorum" / "fixes_log.md").read_text(encoding="utf-8"))

            events = [
                json.loads(ln)["action"]
                for ln in (root / ".diffquorum" / "logs" / "events.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            for expected in ("INIT", "LOG_PITFALL", "LOG_FIX", "QUORUM_PLAN", "REVIEW"):
                self.assertIn(expected, events)

    def test_11_anti_fake_quorum_blocks_solo_or_duplicate_and_allows_verified_multi_seat(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)

            quorum_submit(root, meeting_id="rfc-solo", author="lead", source_kind="local_seat", content="Only one view.")
            solo_blocked = quorum_verify(root, meeting_id="rfc-solo", require_multi_seat=True)
            self.assertTrue(solo_blocked["blocked"])
            self.assertEqual(solo_blocked["decision_grade"], "SOLO_SYNTHESIS")
            self.assertIn("Fake-Quorum Guard Blocked", (root / ".diffquorum" / "pitfalls.md").read_text(encoding="utf-8"))

            solo_allowed = quorum_verify(root, meeting_id="rfc-solo", require_multi_seat=False)
            self.assertFalse(solo_allowed["blocked"])
            self.assertEqual(solo_allowed["decision_grade"], "SOLO_SYNTHESIS")

            r_blk = self.run_cli("quorum-verify", "--root", str(root), "--meeting-id", "rfc-solo", check=False)
            self.assertEqual(r_blk.returncode, 2)

            quorum_submit(root, meeting_id="rfc-dup", author="lead", source_kind="local_seat", content="Same copied opinion")
            quorum_submit(root, meeting_id="rfc-dup", author="builder", source_kind="external_llm", content="Same copied opinion")
            dup_res = quorum_verify(root, meeting_id="rfc-dup", require_multi_seat=True)
            self.assertTrue(dup_res["blocked"])
            self.assertEqual(dup_res["decision_grade"], "SOLO_SYNTHESIS")

            quorum_submit(root, meeting_id="rfc-real", author="lead", source_kind="local_seat", content="Keep interfaces minimal.")
            quorum_submit(root, meeting_id="rfc-real", author="advisor", source_kind="external_llm", content="Verified hash checks prevent tampering.")
            ok_res = quorum_verify(root, meeting_id="rfc-real", require_multi_seat=True, resolution_summary="Adopt hash check.")
            self.assertFalse(ok_res["blocked"])
            self.assertEqual(ok_res["decision_grade"], "MULTI_SEAT_DECISION")
            self.assertEqual(ok_res["distinct_authors"], ["advisor", "lead"])

            (root / ".diffquorum" / "meetings" / "rfc-real" / "submissions" / "lead__local_seat.md").write_text("Tampered!", encoding="utf-8")
            with self.assertRaises(ValueError) as ctx_tamp:
                quorum_verify(root, meeting_id="rfc-real", require_multi_seat=True)
            self.assertIn("TAMPERED_SUBMISSION_HASH_MISMATCH", str(ctx_tamp.exception))

    def test_12_preflight_zero_token_readiness_and_legacy_starcouncil_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)
            fake_agy_dir = root / "agy_state"
            fake_agy_dir.mkdir()

            ok_pf = run_preflight(root, write_paths=[str(root)], cli_tools=["python3"], agy_state_dir=fake_agy_dir)
            self.assertTrue(ok_pf["ok"], ok_pf)
            self.assertFalse(ok_pf["blocked"])

            r_bad_cli = self.run_cli("preflight", "--root", str(root), "--cli", "nonexistent_dq_tool_xyz", check=False)
            self.assertEqual(r_bad_cli.returncode, 2)
            self.assertFalse(json.loads(r_bad_cli.stdout.decode("utf-8"))["ok"])

            bad_agy_sym = root / "sym_agy"
            bad_agy_sym.symlink_to(fake_agy_dir)
            bad_pf = run_preflight(root, cli_tools=["agy"], agy_state_dir=bad_agy_sym)
            self.assertFalse(bad_pf["ok"])
            self.assertTrue(any(c["check"] == "agy_state_dir" and not c["ok"] for c in bad_pf["checks"]))

            # Legacy .starcouncil/ fallback + scripts/starcouncil.py shim
            legacy_ws = root / "legacy_ws"
            legacy_dir = legacy_ws / ".starcouncil"
            legacy_dir.mkdir(parents=True)
            (legacy_dir / "BOARD.md").write_text("# Legacy Board\n", encoding="utf-8")
            self.assertEqual(dq_dir(legacy_ws), legacy_dir)
            self.assertIn("Legacy Board", read_board(legacy_ws))

            import diffquorum

            shim_ver = self.run_cli("--version", script_path=LEGACY_SCRIPT)
            self.assertEqual(shim_ver.returncode, 0)
            self.assertIn(diffquorum.__version__, shim_ver.stdout.decode("utf-8"))

    def test_13_wake_gates_ansi_strip_unicode_ellipsis_and_modal_blocking(self) -> None:
        colored_prompt = "\x1b[32m>\x1b[0m\x1b[3CAsk anything..."
        self.assertEqual(strip_terminal_escapes(colored_prompt), "> Ask anything...")
        self.assertTrue(is_bare_idle_prompt([colored_prompt], cursor_x=4))
        self.assertFalse(is_bare_idle_prompt(["⠋ Thinking…"], cursor_x=4))
        self.assertFalse(is_bare_idle_prompt(["Allow once [Y/n]", ">   Ask anything..."], cursor_x=4))

        base_snap = {
            "msg_id": "msg-ansi",
            "msg_text": "check",
            "msg_status": "PENDING",
            "msg_attempts": 0,
            "last_attempt_ts": 0.0,
            "pane_in_mode": 0,
            "pane_fg": "claude",
            "agy_in_tree": False,
            "client_activity_ts": 100.0,
            "capture_lines": [colored_prompt],
            "cursor_x": 4,
            "transcript_last_type": "PLANNER_RESPONSE",
            "transcript_last_status": "DONE",
            "transcript_has_tool_calls": False,
            "running_tasks": [],
            "recent_seat_wakes": [],
        }
        self.assertTrue(evaluate_six_gates(base_snap, now_ts=1000.0)["wake"])
        self.assertTrue(evaluate_six_gates(dict(base_snap, pane_fg="codex", capture_lines=["›"]), now_ts=1000.0)["wake"])

        modal_snap = dict(
            base_snap,
            capture_lines=["Approve plan? ↑/↓ to navigate • enter Toggle", ">   Ask anything..."],
        )
        modal_res = evaluate_six_gates(modal_snap, now_ts=1000.0)
        self.assertFalse(modal_res["wake"])
        self.assertEqual(modal_res["reason"], "WAITING_USER_ANSWER")

        ellipsis_snap = dict(base_snap, capture_lines=["Working…"])
        ellipsis_res = evaluate_six_gates(ellipsis_snap, now_ts=1000.0)
        self.assertFalse(ellipsis_res["wake"])
        self.assertEqual(ellipsis_res["reason"], "PROMPT_BUSY_OR_MISSING")

    def test_14_quorum_diff_sha256_and_stage2_blind_peer_anonymization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)

            quorum_submit(
                root,
                meeting_id="m-blind",
                author="seat-kimi",
                source_kind="external_llm",
                content="Check symlink guard first.",
                diff_sha256="abc123def456",
            )
            quorum_submit(
                root,
                meeting_id="m-blind",
                author="seat-grok",
                source_kind="remote_node",
                content="Narrow matcher to mutating tools.",
                diff_sha256="abc123def456",
            )
            quorum_submit(
                root,
                meeting_id="m-blind",
                author="seat-lead",
                source_kind="local_seat",
                content="Ensure coverage remains >= 90%.",
                diff_sha256="abc123def456",
            )

            blind_res = quorum_render_blind_packet(root, meeting_id="m-blind", seed=42)
            self.assertTrue(blind_res["ok"])
            self.assertEqual(blind_res["labels"], ["Peer A", "Peer B", "Peer C"])

            packet_txt = pathlib.Path(blind_res["blind_packet"]).read_text(encoding="utf-8")
            self.assertIn("Peer A", packet_txt)
            self.assertIn("Peer B", packet_txt)
            self.assertIn("Peer C", packet_txt)
            self.assertNotIn("seat-kimi", packet_txt)
            self.assertNotIn("seat-grok", packet_txt)
            self.assertNotIn("seat-lead", packet_txt)

            reveal = json.loads(pathlib.Path(blind_res["reveal_map"]).read_text(encoding="utf-8"))
            authors_mapped = {v["author"] for v in reveal.values()}
            self.assertEqual(authors_mapped, {"seat-kimi", "seat-grok", "seat-lead"})
            self.assertTrue(all(v["diff_sha256"] == "abc123def456" for v in reveal.values()))

            cli_ver = self.run_cli("quorum-verify", "--root", str(root), "--meeting-id", "m-blind", "--resolution", "Ship Stage-2 fix")
            self.assertEqual(cli_ver.returncode, 0)
            out_json = json.loads(cli_ver.stdout.decode("utf-8"))
            self.assertEqual(out_json["decision_grade"], "MULTI_SEAT_DECISION")
            self.assertEqual(out_json["bound_diff_hashes"], ["abc123def456"])

    def test_15_optional_runner_presets_including_agy_hydrogen(self) -> None:
        for prof in ("agy-hydrogen", "claude-sub", "codex", "generic-ptr"):
            res = build_runner_preset(prof, task_pointer="artifacts/task-01.md")
            self.assertTrue(res["ok"])
            self.assertEqual(res["profile"], prof)
            self.assertIn("artifacts/task-01.md", " ".join(res["argv"]))

        hydro = build_runner_preset("agy-hydrogen", task_pointer="artifacts/task-01.md", model_override="gemini-4-hydrogen-xhigh")
        self.assertEqual(hydro["selected_model"], "gemini-4-hydrogen-xhigh")
        self.assertIn("Optional", hydro["notes"])
        self.assertEqual(hydro["preflight_argv"], ["diffquorum", "preflight", "--cli", "agy"])

        with self.assertRaises(ValueError):
            build_runner_preset("unknown-profile", task_pointer="artifacts/task-01.md")

        bad_cli = self.run_cli("preset", "--profile", "unknown-profile", "--task-pointer", "artifacts/x.md", check=False)
        self.assertEqual(bad_cli.returncode, 2)

    def test_16_model_downgrade_fail_closed_probe_and_quorum_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)

            ok = verify_model_identity("claude-opus-5-5-high", "claude-opus-5-5-high", root=root)
            self.assertTrue(ok["ok"])
            self.assertFalse(ok["blocked"])

            down = verify_model_identity("claude-opus-5-5-high", "gemini-flash-lite", root=root)
            self.assertFalse(down["ok"])
            self.assertTrue(down["blocked"])
            self.assertEqual(down["status"], "MODEL_DOWNGRADE_DETECTED")

            miss = verify_model_identity("kimi-k3.1-pro", "", root=root)
            self.assertTrue(miss["blocked"])
            self.assertEqual(miss["status"], "MODEL_IDENTITY_MISSING")

            bad_obs = verify_model_identity("kimi-k3.1-pro", "bad model!", root=root)
            self.assertTrue(bad_obs["blocked"])
            self.assertEqual(bad_obs["status"], "MODEL_IDENTITY_INVALID")

            with self.assertRaises(ValueError):
                verify_model_identity("bad slug!", "kimi-k3.1-pro")

            # Receipt probe (top-level & nested usage.model)
            rec_ok = root / "receipt_ok.json"
            rec_ok.write_text(json.dumps({"usage": {"model": "kimi-k3.1-pro"}}), encoding="utf-8")
            p_ok = probe_model_receipt(rec_ok, expected_model="kimi-k3.1-pro", root=root)
            self.assertTrue(p_ok["ok"])

            rec_bad = root / "receipt_bad.json"
            rec_bad.write_text(json.dumps({"model": "cheap-mini"}), encoding="utf-8")
            cli_bad = self.run_cli(
                "model-probe",
                "--root",
                str(root),
                "--expected",
                "kimi-k3.1-pro",
                "--receipt",
                str(rec_bad),
                check=False,
            )
            self.assertEqual(cli_bad.returncode, 2)
            self.assertEqual(json.loads(cli_bad.stdout.decode("utf-8"))["status"], "MODEL_DOWNGRADE_DETECTED")

            cli_ok = self.run_cli(
                "model-probe",
                "--expected",
                "kimi-k3.1-pro",
                "--observed",
                "kimi-k3.1-pro",
            )
            self.assertEqual(cli_ok.returncode, 0)

            # Quorum submit rejects silent downgrade fail-closed
            with self.assertRaises(ValueError) as ctx_down:
                quorum_submit(
                    root,
                    meeting_id="m-model",
                    author="seat-a",
                    source_kind="external_llm",
                    content="Review findings A",
                    expected_model="claude-opus-5-5-high",
                    observed_model="cheap-flash",
                )
            self.assertIn("MODEL_DOWNGRADE_DETECTED", str(ctx_down.exception))

            # Quorum verify with --require-model-match blocks unverified submissions
            quorum_submit(root, meeting_id="m-strict", author="seat-a", source_kind="local_seat", content="Alpha view.")
            quorum_submit(root, meeting_id="m-strict", author="seat-b", source_kind="external_llm", content="Beta view.")
            unv = quorum_verify(root, meeting_id="m-strict", require_multi_seat=True, require_model_match=True)
            self.assertTrue(unv["blocked"])
            self.assertEqual(unv["reason"], "MODEL_DOWNGRADE_BLOCKED")

            # Verified matching models pass strict quorum-verify
            quorum_submit(
                root,
                meeting_id="m-verified",
                author="seat-a",
                source_kind="local_seat",
                content="Verified alpha.",
                expected_model="claude-opus-5-5-high",
                observed_model="claude-opus-5-5-high",
            )
            quorum_submit(
                root,
                meeting_id="m-verified",
                author="seat-b",
                source_kind="external_llm",
                content="Verified beta.",
                expected_model="kimi-k3.1-pro",
                observed_model="kimi-k3.1-pro",
            )
            cli_ver = self.run_cli(
                "quorum-verify",
                "--root",
                str(root),
                "--meeting-id",
                "m-verified",
                "--require-model-match",
            )
            self.assertEqual(cli_ver.returncode, 0)
            self.assertEqual(json.loads(cli_ver.stdout.decode("utf-8"))["decision_grade"], "MULTI_SEAT_DECISION")

            # Post-submission tampered metadata model mismatch fails closed
            meta_fp = root / ".diffquorum" / "meetings" / "m-verified" / "submissions" / "seat-b__external_llm.json"
            doc = json.loads(meta_fp.read_text(encoding="utf-8"))
            doc["observed_model"] = "silent-flash"
            meta_fp.write_text(json.dumps(doc), encoding="utf-8")
            tampered_m = quorum_verify(root, meeting_id="m-verified", require_multi_seat=True)
            self.assertTrue(tampered_m["blocked"])
            self.assertEqual(tampered_m["reason"], "MODEL_DOWNGRADE_BLOCKED")

    def test_17_pf016_timer_filter_pf017_xml_unwrap_and_gate4_newer_ticket_unblock(self) -> None:
        # PF-017: Unwrap <USER_REQUEST> ignoring trailing XML wrappers & block nested tag smuggling
        wrapped = (
            "<USER_REQUEST>\nApprove\n</USER_REQUEST>"
            "<ADDITIONAL_METADATA>timezone=UTC</ADDITIONAL_METADATA>"
            "<USER_SETTINGS_CHANGE>theme=dark</USER_SETTINGS_CHANGE>"
        )
        self.assertEqual(extract_user_request_text(wrapped), "Approve")
        plain_meta = "Ship it<ADDITIONAL_METADATA>x=1</ADDITIONAL_METADATA>"
        self.assertEqual(extract_user_request_text(plain_meta), "Ship it")
        with self.assertRaises(ValueError):
            extract_user_request_text("<USER_REQUEST>hi <USER_REQUEST>nested</USER_REQUEST></USER_REQUEST>")
        with self.assertRaises(ValueError):
            extract_user_request_text("<USER_REQUEST>unclosed")

        base_snap = {
            "msg_id": "msg-v03",
            "msg_text": "check",
            "msg_status": "PENDING",
            "msg_attempts": 0,
            "last_attempt_ts": 0.0,
            "pane_in_mode": 0,
            "pane_fg": "agy",
            "agy_in_tree": True,
            "client_activity_ts": 100.0,
            "capture_lines": [">   Ask anything..."],
            "cursor_x": 4,
            "transcript_last_type": "PLANNER_RESPONSE",
            "transcript_last_status": "DONE",
            "transcript_has_tool_calls": False,
            "running_tasks": [],
            "recent_seat_wakes": [],
        }

        # PF-016: Standing timers must NOT block idle wakeup, while foreground tasks still block
        timer_snap = dict(
            base_snap,
            running_tasks=[
                {"description": "1d 19h timer running", "status": "running", "isDaemon": False},
                {"description": "Timer: periodic patrol", "status": "running", "isDaemon": False},
                {"description": "background watch", "kind": "timer", "status": "running", "isDaemon": False},
            ],
        )
        self.assertTrue(evaluate_six_gates(timer_snap, now_ts=1000.0)["wake"])

        fg_snap = dict(
            base_snap,
            running_tasks=[{"description": "pytest unit suite", "status": "running", "isDaemon": False}],
        )
        fg_res = evaluate_six_gates(fg_snap, now_ts=1000.0)
        self.assertFalse(fg_res["wake"])
        self.assertEqual(fg_res["reason"], "NON_DAEMON_TASK_RUNNING")

        # Gate 4: Stale awaiting-Approve blocks older/equal tickets, but newer ready ticket unblocks
        self.assertTrue(is_awaiting_human_approve("请先审核上面的计划。回复“Approve”后执行"))
        stale_blocked = dict(
            base_snap,
            transcript_last_text="请先审核上面的计划。回复“Approve”后我再开始执行",
            transcript_mtime_ts=500.0,
            newest_ready_ticket_ts=450.0,
        )
        r_blk = evaluate_six_gates(stale_blocked, now_ts=1000.0)
        self.assertFalse(r_blk["wake"])
        self.assertEqual(r_blk["reason"], "AWAITING_HUMAN_APPROVE")

        newer_unblocked = dict(stale_blocked, newest_ready_ticket_ts=520.0)
        r_ok = evaluate_six_gates(newer_unblocked, now_ts=1000.0)
        self.assertTrue(r_ok["wake"])

    def test_18_review_two_round_hard_cap_and_strict_400b_pointer_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root)

            # <= 2 review round hard cap triggers ROUND_CAP_HALT even with zero blockers
            r3 = evaluate_review_gate(root, level=2, content_tree_hash="deadbeef1234", round_num=3, blockers=[])
            self.assertEqual(r3["status"], "ROUND_CAP_HALT")
            self.assertTrue(r3["blocked"])

            r2_l1 = evaluate_review_gate(root, level=1, content_tree_hash="deadbeef1234", round_num=2, blockers=[])
            self.assertEqual(r2_l1["status"], "ROUND_CAP_HALT")
            self.assertTrue(r2_l1["blocked"])

            with self.assertRaises(ValueError):
                evaluate_review_gate(root, level=2, content_tree_hash="deadbeef1234", round_num=0)

            # Strict <400B pointer envelope verification
            ok_ptr = dispatch_pointer(
                root,
                from_seat="lead",
                to_seat="builder",
                summary="Short pointer summary",
                event_id="evt-strict-ok",
                strict_envelope=True,
                now_ts=1000.0,
            )
            self.assertTrue(ok_ptr["ok"])
            self.assertLess(ok_ptr["pointer_bytes"], MAX_ENVELOPE_BYTES)

            with self.assertRaises(ValueError) as ctx_big:
                dispatch_pointer(
                    root,
                    from_seat="lead",
                    to_seat="builder",
                    summary="X" * 380,
                    event_id="evt-strict-big",
                    strict_envelope=True,
                    now_ts=1001.0,
                )
            self.assertIn("POINTER_ENVELOPE_OVERSIZED", str(ctx_big.exception))

            with self.assertRaises(ValueError):
                verify_pointer_envelope("line1\nline2")
            with self.assertRaises(ValueError):
                verify_pointer_envelope("[]")
            with self.assertRaises(ValueError):
                verify_pointer_envelope(json.dumps({"id": "e1"}))

    def test_19_wave_b_wake_gates_narrow_footer_deep_thinking_ttl_and_fail_closed_approval(self) -> None:
        # PF-018: narrow mobile idle footer allowed; busy/modal footers blocked
        self.assertTrue(is_idle_cli_footer("? for shortcuts"))
        self.assertTrue(is_idle_cli_footer("auto · Gemini 4 ... · /tasks"))
        self.assertFalse(is_idle_cli_footer("auto · Gemini 4 ... · esc to interrupt"))
        self.assertFalse(is_idle_cli_footer("Allow once (y/n)"))
        self.assertFalse(is_idle_cli_footer("Random prose line"))

        # PF-025: deep-thinking pane tail busy detection without prose false positives
        self.assertTrue(is_pane_tail_busy(["line", "⡿ Thinking…", "auto · esc to cancel"]))
        self.assertTrue(is_pane_tail_busy("Generating…"))
        self.assertFalse(is_pane_tail_busy(["Summary: WORKING / IDLE verified.", ">", "? for shortcuts"]))

        # PF-022: exact <=8-char dual-state classifier (WAIT+CPY / WORK+CPY / DAEMON / OFFLINE)
        self.assertEqual(classify_seat_state(online=False), "OFFLINE")
        self.assertEqual(classify_seat_state(online=True, is_daemon=True), "DAEMON")
        self.assertEqual(classify_seat_state(online=True, pane_busy=True, copy_mode=True), "WORK+CPY")
        self.assertEqual(classify_seat_state(online=True, pane_busy=True, awaiting_approve=True), "WORKING")
        self.assertEqual(classify_seat_state(online=True, awaiting_approve=True, copy_mode=True), "WAIT+CPY")
        self.assertEqual(classify_seat_state(online=True, awaiting_approve=True, copy_mode=False), "WAIT_APP")
        self.assertEqual(classify_seat_state(online=True, transcript_busy=True, copy_mode=True), "WORK+CPY")
        self.assertEqual(classify_seat_state(online=True, copy_mode=True), "COPY-MOD")
        self.assertEqual(classify_seat_state(online=True), "IDLE")

        # PF-021: decoupled wakeup TTL (2h plain message vs 24h blocked PENDING ticket)
        base_snap = {
            "msg_id": "m-ttl",
            "msg_text": "check",
            "msg_status": "PENDING",
            "msg_attempts": 0,
            "last_attempt_ts": 0.0,
            "pane_in_mode": 0,
            "pane_fg": "agy",
            "agy_in_tree": True,
            "client_activity_ts": 100.0,
            "capture_lines": ["auto · Gemini 4 ... · /tasks"],
            "cursor_x": 3,
            "transcript_last_type": "PLANNER_RESPONSE",
            "transcript_last_status": "DONE",
            "transcript_has_tool_calls": False,
            "running_tasks": [],
            "recent_seat_wakes": [],
        }
        r_msg_old = evaluate_six_gates(dict(base_snap, item_kind="msg", item_age_sec=10800.0), now_ts=1000.0)
        self.assertFalse(r_msg_old["wake"])
        self.assertEqual(r_msg_old["reason"], "MESSAGE_WAKE_TTL_EXPIRED")

        r_tkt_6h = evaluate_six_gates(dict(base_snap, item_kind="ticket", item_age_sec=21600.0), now_ts=1000.0)
        self.assertTrue(r_tkt_6h["wake"])

        r_tkt_25h = evaluate_six_gates(dict(base_snap, item_kind="ticket", item_age_sec=90000.0), now_ts=1000.0)
        self.assertFalse(r_tkt_25h["wake"])
        self.assertEqual(r_tkt_25h["reason"], "TICKET_WAKE_TTL_EXPIRED")

        # PF-023: conservative multilingual approvals + fail-closed cross-seat revocation scoping
        for ok_txt in ("approve", "我都同意", "都同意", "全同意", "好嘞，我都同意", "按这个执行"):
            self.assertTrue(is_explicit_approval_text(ok_txt), ok_txt)
        for bad_txt in (
            "我都同意？",
            "我都同意，但是先别改",
            "不要按这个执行",
            "我不同意",
            "全同意，只改第一个",
            "qapprove",
            "approve. cancel it later",
        ):
            self.assertFalse(is_explicit_approval_text(bad_txt), bad_txt)

        seats = {
            "coord": ("coord", "00"),
            "builder": ("builder", "02"),
            "audit": ("audit", "99"),
        }
        self.assertFalse(
            revocation_applies_to_scope("这个99 的就先不用管了", from_seat="coord", to_seat="builder", known_seats=seats)
        )
        self.assertTrue(
            revocation_applies_to_scope("这个99 的就先不用管了", from_seat="coord", to_seat="audit", known_seats=seats)
        )
        for must_revoke in ("不用执行了", "02 先不用管了", "99 和全部都不用管了", "99% 不用管了", "99 不用管了，算了"):
            self.assertTrue(
                revocation_applies_to_scope(must_revoke, from_seat="coord", to_seat="builder", known_seats=seats),
                must_revoke,
            )

        seats_json = json.dumps(seats)
        cli_ok = self.run_cli(
            "approve-check",
            "--text", "我都同意",
            "--later-text", "99 不用管了",
            "--from", "coord", "--to", "builder",
            "--seats-json", seats_json,
        )
        self.assertEqual(cli_ok.returncode, 0)
        cli_rev = self.run_cli(
            "approve-check",
            "--text", "我都同意",
            "--later-text", "99 不用管了，算了",
            "--from", "coord", "--to", "builder",
            "--seats-json", seats_json,
            check=False,
        )
        self.assertEqual(cli_rev.returncode, 2)

    def test_20_wave_b_ops_hud_curate_routine_and_ast_bundler(self) -> None:
        ops_path = SRC_DIR / "diffquorum" / "ops.py"
        ops_tree = ast.parse(ops_path.read_text(encoding="utf-8"))
        # Zero delete paths & zero tmux mutating strings inside ops.py
        for stmt in ops_tree.body[1:]:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Attribute):
                    self.assertNotIn(node.attr, ("unlink", "rmtree", "remove"))
                if isinstance(node, ast.Constant) and isinstance(node.value, str):
                    self.assertNotIn("send-keys", node.value)
                    self.assertNotIn("switch-client", node.value)

        # 1) Dual-table 50-col HUD (WAIT+CPY, WORK+CPY, DAEMON, active tasks, OFFLINE fallback)
        hud_snap = {
            "clock": "15:40:00",
            "watcher_tag": "WD:OK(2s)",
            "lock_tag": "LOCK:FREE",
            "local_hw": "memF:25% dsk:48G",
            "local_seats": [
                {"short": "00-coord", "state": "IDLE", "tkt": 0, "size": "50x40"},
                {"short": "01-build", "pane_busy": True, "copy_mode": True, "tkt": 1, "size": "80x55"},
                {"short": "02-audit", "awaiting_approve": True, "copy_mode": True, "wait_sec": 180, "snippet": "Plan waiting", "tkt": 1, "size": "80x55"},
            ],
            "remote": {
                "online": True,
                "rtt_ms": 22,
                "health": "px/wd:OK",
                "cache_age_sec": 15,
                "hw": "mem:40/96G dsk:18% ld:1.4",
                "seats": [
                    {"short": "00-hub 总控", "awaiting_approve": True, "wait_sec": 60, "snippet": "Remote plan", "tkt": None, "size": "50x40"},
                    {"short": "04-gw 网关", "is_daemon": True, "tkt": None, "size": "120x40"},
                ],
            },
            "active_tasks": [
                {"status": "IN_PROGRESS", "seat": "01", "num": "#020", "updated_ts": 200, "title": "【Approved】Refactor pipeline"},
                {"status": "PENDING", "seat": "02", "num": "#021", "updated_ts": 300, "title": "Review audit bundle"},
            ],
        }
        rendered = render_dual_hud(hud_snap, width=50, color=False)
        self.assertIn("[!] WAIT APPROVE (2)", rendered)
        self.assertIn("LOC 02-audit 3m [CPY] Plan waiting", rendered)
        self.assertIn("REM 00-hub 总控 1m Remote plan", rendered)
        self.assertIn("01-build     WORK+CPY t:1  80x55", rendered)
        self.assertIn("02-audit     WAIT+CPY t:1  80x55   <--!", rendered)
        self.assertIn("04-gw 网关   DAEMON   t:-  120x40", rendered)
        self.assertIn("[ACTIVE TASKS] (2)", rendered)
        self.assertIn("RUN 01 #020 Refactor pipeline", rendered)
        self.assertLess(rendered.index("#020"), rendered.index("#021"))
        for ln in rendered.splitlines():
            self.assertLessEqual(_disp_width(ln), 50, f"HUD line overflowed 50 cols: {ln!r}")

        off_hud = render_dual_hud(
            {"local_seats": [], "remote": {"online": False, "consecutive_failures": 2, "error": "timeout>8s"}},
            width=50,
            color=False,
        )
        self.assertIn("[REMOTE] OFFLINE fail=2 (timeout>8s)", off_hud)
        self.assertNotIn("WAIT APPROVE", off_hud)
        self.assertNotIn("[ACTIVE TASKS]", off_hud)

        # 2) Routine probe: secret scrubbing, timeout fail-closed, healthy JSON, symlink rejection
        clean_env = scrub_probe_env({"PATH": "/usr/bin", "OPENAI_API_KEY": "sk-1", "KIMI_TOKEN": "tok", "XDG_CONFIG_HOME": "/tmp"})
        self.assertIn("PATH", clean_env)
        self.assertNotIn("OPENAI_API_KEY", clean_env)
        self.assertNotIn("KIMI_TOKEN", clean_env)

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            out_p = root / "probe.json"
            r_to = run_readonly_probe([sys.executable, "-c", "import time; time.sleep(5)"], output_path=out_p, timeout_sec=0.2)
            self.assertFalse(r_to["online"])
            self.assertEqual(r_to["consecutive_failures"], 1)
            r_ok = run_readonly_probe([sys.executable, "-c", 'print(\'{"host":"node-a","ok":true}\')'], output_path=out_p, timeout_sec=2.0)
            self.assertTrue(r_ok["online"])
            self.assertEqual(r_ok["consecutive_failures"], 0)
            sym_p = root / "sym.json"
            sym_p.symlink_to(out_p)
            with self.assertRaises(ValueError):
                run_readonly_probe([sys.executable, "-c", "print('{}')"], output_path=sym_p)

            # 3) Zero-delete ledger curator: PIN preserved + whole-file SHA-256 snapshot + MANIFEST.tsv
            ledger = root / "PROJECT_LEDGER.md"
            entries = [f"## [2026-11-{day:02d}] Entry {day}\n\n" + ("detail " * 80) for day in range(20, 5, -1)]
            ledger.write_text("# Ledger\n\n<!-- PIN -->\nPinned invariant\n<!-- /PIN -->\n\n" + "\n\n".join(entries) + "\n", encoding="utf-8")
            orig_bytes = ledger.read_bytes()
            dry = curate_ledger(ledger, max_bytes=2000, keep_entries=3, dry_run=True)
            self.assertEqual(dry["action"], "DRY_RUN")
            self.assertEqual(ledger.read_bytes(), orig_bytes)
            cur = curate_ledger(ledger, max_bytes=2000, keep_entries=3, dry_run=False)
            self.assertEqual(cur["action"], "CURATED")
            self.assertLessEqual(cur["hot_bytes"], 2000)
            self.assertIn("Pinned invariant", ledger.read_text(encoding="utf-8"))
            snap_file = root / cur["snapshot"]
            self.assertEqual(snap_file.read_bytes(), orig_bytes)
            self.assertIn(cur["orig_sha256"], (root / "archive" / "MANIFEST.tsv").read_text(encoding="utf-8"))

            # 3b) Compiled Truth + <!-- timeline --> split: upper truth preserved byte-for-byte (ignores fenced demo sentinel)
            tl_ledger = root / "STATE_TIMELINE.md"
            compiled_head = (
                "# Project Compiled Truth\n\n"
                "## [2026-11-22] Active Architecture State\n"
                "| Claim | valid_from | valid_until |\n"
                "| :--- | :--- | :--- |\n"
                "| Pointer envelope <=400B | 2026-11-01 | null |\n\n"
                "```markdown\n"
                "<!-- timeline -->\n"
                "```\n\n"
                "<!-- timeline -->"
            )
            tl_orig = (compiled_head + "\n\n" + "\n\n".join(entries) + "\n").encode("utf-8")
            tl_ledger.write_bytes(tl_orig)
            tl_cur = curate_ledger(tl_ledger, max_bytes=2400, keep_entries=3, dry_run=False)
            self.assertEqual(tl_cur["action"], "CURATED")
            self.assertEqual(tl_cur["mode"], "compiled_truth_timeline")
            tl_hot_txt = tl_ledger.read_text(encoding="utf-8")
            self.assertTrue(tl_hot_txt.startswith(compiled_head + "\n\n> **Lossless Snapshot**:"))
            self.assertIn("Entry 20", tl_hot_txt)
            self.assertNotIn("Entry 6", tl_hot_txt)
            self.assertEqual((root / tl_cur["snapshot"]).read_bytes(), tl_orig)

            for bad_l in ("", ".", "..", "/"):
                with self.assertRaises(ValueError):
                    curate_ledger(bad_l)

            # 4) AST import bundler: traces local relative imports & rejects symlink/path escapes
            pkg = root / "demo_repo" / "pkg"
            pkg.mkdir(parents=True)
            (pkg / "__init__.py").write_text("", encoding="utf-8")
            (pkg / "helper.py").write_text("def val():\n    return 42\n", encoding="utf-8")
            (pkg / "app.py").write_text("from .helper import val\nimport json\n", encoding="utf-8")
            bundled = collect_ast_imports(["pkg/app.py"], repo_root=root / "demo_repo", max_depth=2)
            self.assertTrue(bundled["ok"])
            paths = {f["path"] for f in bundled["files"]}
            self.assertEqual(paths, {"pkg/app.py", "pkg/helper.py"})
            self.assertEqual(bundled["edges"], [{"from": "pkg/app.py", "to": "pkg/helper.py"}])

            outside = root / "outside.py"
            outside.write_text("x = 1\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                collect_ast_imports([str(outside)], repo_root=root / "demo_repo")

            # 5) CLI smoke check on hud / curate / routine / bundle-ast
            self.assertEqual(self.run_cli("hud", "--snapshot-json", json.dumps(hud_snap), "--width", "50").returncode, 0)
            self.assertEqual(self.run_cli("curate", str(ledger), "--max-bytes", "999999").returncode, 0)
            self.assertEqual(
                self.run_cli("routine", "--output", str(out_p), "--", sys.executable, "-c", 'print(\'{"ok":true}\')').returncode,
                0,
            )
            self.assertEqual(self.run_cli("bundle-ast", "--repo-root", str(root / "demo_repo"), "--entry", "pkg/app.py").returncode, 0)

    def test_21_release_preflight_and_objective_blocker_convergence(self) -> None:
        import io
        import tarfile

        import diffquorum

        # 1) DiffQuorum repo itself passes release-preflight cleanly
        self_rep = run_release_preflight(PKG_ROOT, expected_version=diffquorum.__version__)
        self.assertTrue(self_rep["ok"], self_rep["issues"])

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            init_workspace(root / "ws")

            # 2) Subjective style / wishlist findings demoted to non_blocking_notes -> PASS
            r_demote = evaluate_review_gate(
                root / "ws",
                level=2,
                content_tree_hash="abc123456789",
                round_num=1,
                blockers=["Prefer punchier intro tone", "Add optional graph export plugin"],
                blocker_classes=["prose_style", "scope_wishlist"],
            )
            self.assertEqual(r_demote["status"], "PASS")
            self.assertFalse(r_demote["blocked"])
            self.assertEqual(len(r_demote["non_blocking_notes"]), 2)

            # Objective defect class continues to block cleanly
            r_obj = evaluate_review_gate(
                root / "ws",
                level=2,
                content_tree_hash="abc123456789",
                round_num=1,
                blockers=["sdist omits sample fixture", "Optional wording tweak"],
                blocker_classes=["install_or_packaging", "prose_style"],
            )
            self.assertEqual(r_obj["status"], "FIX_DEFECT_FAMILY")
            self.assertTrue(r_obj["blocked"])
            self.assertEqual(r_obj["blockers"], ["sdist omits sample fixture"])

            # 3) Synthetic repo with version mismatch, narrow clock assertion, reviewer codename & UNKNOWN PKG-INFO
            bad_repo = root / "bad_repo"
            (bad_repo / "src" / "demo").mkdir(parents=True)
            (bad_repo / ".github" / "workflows").mkdir(parents=True)
            (bad_repo / "tests").mkdir(parents=True)
            (bad_repo / "samples").mkdir(parents=True)
            (bad_repo / "samples" / "case.json").write_text("{}", encoding="utf-8")
            (bad_repo / "pyproject.toml").write_text('[project]\nname = "demo"\nversion = "0.3.8"\n', encoding="utf-8")
            (bad_repo / "CITATION.cff").write_text("cff-version: 1.2.0\nversion: 0.3.8\n", encoding="utf-8")
            (bad_repo / "src" / "demo" / "__init__.py").write_text('__version__ = "0.3.8"\n', encoding="utf-8")
            (bad_repo / ".github" / "workflows" / "ci.yml").write_text("run: gen-sbom --version 0.3.8\n", encoding="utf-8")
            tok_reviewer = "ki" + "mi"
            (bad_repo / "tests" / "test_app.py").write_text(
                f"# Regression from {tok_reviewer} round 2\n"
                f"def test_{tok_reviewer}_round(self):\n"
                "    p = 'samples/case.json'\n"
                "    assert elapsed < 0.2\n",
                encoding="utf-8",
            )
            rep_bad = run_release_preflight(bad_repo, expected_version="0.3.9")
            self.assertFalse(rep_bad["ok"])
            joined = "\n".join(rep_bad["issues"])
            self.assertIn("pyproject.toml", joined)
            self.assertIn("CITATION.cff", joined)
            self.assertIn("__init__.py", joined)
            self.assertIn("ci.yml", joined)
            self.assertIn("narrow wall-clock", joined)
            self.assertIn("test identifier", joined)
            self.assertIn("test comment", joined)
            self.assertIn("MANIFEST.in", joined)

            sdist_bad = root / "demo-0.3.9.tar.gz"
            with tarfile.open(sdist_bad, "w:gz") as tf:
                pkg_bytes = b"Metadata-Version: 2.1\nName: UNKNOWN\nVersion: 0.3.8\n"
                ti = tarfile.TarInfo("demo-0.3.9/PKG-INFO")
                ti.size = len(pkg_bytes)
                tf.addfile(ti, io.BytesIO(pkg_bytes))
            rep_sdist = run_release_preflight(bad_repo, expected_version="0.3.9", sdist_tar=sdist_bad)
            self.assertIn("UNKNOWN", "\n".join(rep_sdist["issues"]))

            self.assertEqual(
                self.run_cli("release-preflight", "--repo-root", str(PKG_ROOT), "--expected-version", diffquorum.__version__).returncode,
                0,
            )
            self.assertEqual(self.run_cli("release-preflight", "--repo-root", str(bad_repo), "--expected-version", "0.3.9", check=False).returncode, 2)

    def test_cold_interrupted_error_message_recovery(self) -> None:
        from diffquorum.wake_gates import evaluate_six_gates
        base = {
            "msg_text": "TKT-20261124-001 ready",
            "msg_status": "PENDING",
            "pane_in_mode": 0,
            "pane_fg": "agy",
            "client_activity_ts": 100.0,
            "capture_lines": [">   Ask anything..."],
            "cursor_x": 2,
            "transcript_last_type": "ERROR_MESSAGE",
            "transcript_last_status": "DONE",
            "transcript_has_tool_calls": False,
            "running_tasks": [],
        }
        fresh = evaluate_six_gates({**base, "transcript_mtime_ts": 190.0}, now_ts=200.0)
        self.assertFalse(fresh["wake"])
        self.assertEqual(fresh["reason"], "TRANSCRIPT_NOT_IDLE")
        settled = evaluate_six_gates({**base, "transcript_mtime_ts": 150.0}, now_ts=200.0)
        self.assertTrue(settled["wake"])
        self.assertEqual(settled["gate"], "all_6_passed")

    def test_wave_c_plan_lock_anti_stall_and_receipts(self) -> None:
        import os
        from diffquorum.ops import evaluate_two_cap_alert_latch, list_meetings, record_meeting, summarize_qa_directory
        from diffquorum.plan_lock import close_pending_plan, list_pending_plans, open_pending_plan, supersede_plans_for_scope
        from diffquorum.wake_gates import (
            classify_wake_block_code,
            collect_terminal_ticket_receipts,
            evaluate_six_gates,
            is_explicit_approval_text,
            is_idle_cli_footer,
            is_report_no_reply_message,
            is_silent_sync_message,
            should_auto_exit_stale_copy_mode,
            should_defer_low_priority_wake,
            verify_cached_host_approval,
        )

        with tempfile.TemporaryDirectory() as tmp:
            pfile = pathlib.Path(tmp) / "pending_plans.json"
            r1 = open_pending_plan(pfile, seat="lead", scope="Core Bus", title="Initial draft")
            self.assertTrue(r1["ok"])
            self.assertFalse(r1["collision"])
            self.assertEqual(os.stat(pfile).st_mode & 0o777, 0o600)

            r_col = open_pending_plan(pfile, seat="worker", scope="core-bus", title="Competing draft")
            self.assertFalse(r_col["ok"])
            self.assertTrue(r_col["collision"])
            self.assertEqual(len(r_col["conflicts"]), 1)

            r_close = close_pending_plan(pfile, seat="lead", plan_id=r1["plan"]["plan_id"], status="APPROVED")
            self.assertEqual(r_close["plan"]["status"], "APPROVED")
            self.assertEqual(list_pending_plans(pfile)["count"], 0)

            r2 = open_pending_plan(pfile, seat="worker", scope="core-bus", title="Follow-up draft")
            self.assertFalse(r2["collision"])
            self.assertEqual(supersede_plans_for_scope(pfile, "core-bus", superseded_by="TKT-900"), [r2["plan"]["plan_id"]])

            # Leading-only silent tag + P0 never silent + orthogonal report-no-reply single-wake
            self.assertTrue(is_silent_sync_message("【TERMINAL-ACK】 finished", priority="P1"))
            self.assertFalse(is_silent_sync_message("【TERMINAL-ACK】 emergency", priority="P0"))
            self.assertFalse(is_silent_sync_message("Reply with 【TERMINAL-ACK】 after check", priority="P2"))
            self.assertTrue(is_report_no_reply_message("【交卷免回】 summary ready"))

            base_snap = {
                "msg_text": "【交卷免回】 summary ready",
                "msg_status": "PENDING",
                "pane_in_mode": 0,
                "pane_fg": "agy",
                "client_activity_ts": 100.0,
                "capture_lines": [">", "⏵⏵ auto mode"],
                "cursor_x": 2,
                "transcript_last_type": "PLANNER_RESPONSE",
                "transcript_last_status": "DONE",
                "transcript_has_tool_calls": False,
                "running_tasks": [{"status": "running", "isDaemon": "true", "description": "Dev server"}],
            }
            w_first = evaluate_six_gates({**base_snap, "msg_attempts": 0}, now_ts=200.0)
            self.assertTrue(w_first["wake"])
            w_second = evaluate_six_gates({**base_snap, "msg_attempts": 1, "last_attempt_ts": 120.0}, now_ts=200.0)
            self.assertFalse(w_second["wake"])
            self.assertEqual(w_second["reason"], "MAX_ATTEMPTS_SEEN_AWAITING_HUMAN")

            # P0/P1 ticket backoff survives past 2 attempts instead of dying
            hi_snap = {
                **base_snap,
                "msg_text": "TKT-100 urgent",
                "item_kind": "ticket",
                "priority": "P1",
                "msg_attempts": 3,
                "last_attempt_ts": 10.0,
            }
            self.assertTrue(evaluate_six_gates(hi_snap, now_ts=300.0)["wake"])

            # Trailing multi-sentence approval & standalone Chinese words
            self.assertTrue(is_explicit_approval_text("好嘞我先去休息了。approve"))
            self.assertTrue(is_explicit_approval_text("通过"))
            self.assertFalse(is_explicit_approval_text("先不通过"))
            self.assertTrue(is_idle_cli_footer("? for short…"))
            self.assertTrue(should_auto_exit_stale_copy_mode(pane_in_mode=True, min_client_idle_sec=190.0))
            self.assertEqual(classify_wake_block_code("gate1_copy_mode"), "COPY_MODE")
            self.assertTrue(should_defer_low_priority_wake(human_reply_age_sec=45.0, priority="P2"))

            # Terminal ticket receipt wake & host approval cache verification
            receipts = collect_terminal_ticket_receipts(
                [{"ticket_id": "TKT-77", "status": "DONE", "from_seat": "lead", "updated_epoch": 500.0}],
                {},
                watermark_ts=100.0,
            )
            self.assertEqual(len(receipts), 1)
            ok_cache, _ = verify_cached_host_approval(
                {"ok": True, "verified_epoch": 195.0, "conv_id": "u1", "step_index": 3, "content_sha256": "abc"},
                {"conv_id": "u1", "step_index": 3, "content_sha256": "abc"},
                now_ts=200.0,
            )
            self.assertTrue(ok_cache)

            # Read-only Q&A directory, 0600 meeting ledger & 2-cap alert latch
            qa = summarize_qa_directory([{"seat": "lead", "user_inputs": ["[BUS-WAKE]", "Status?"], "last_reply": "Ready"}])
            self.assertEqual(qa[0]["last_question"], "Status?")
            mpath = pathlib.Path(tmp) / "meetings.jsonl"
            self.assertEqual(list_meetings(mpath, digest_only=True)["digest"], "")
            record_meeting(mpath, title="Arch Sync", topic="Plan Lock", participants=["lead", "worker"], decision="Approved")
            self.assertEqual(os.stat(mpath).st_mode & 0o777, 0o600)
            self.assertIn("Arch Sync", list_meetings(mpath, digest_only=True)["digest"])
            latch = evaluate_two_cap_alert_latch({"s1": 2}, ["s1"], hour_local=14)
            self.assertEqual(latch["notify_keys"], [])

    def test_pre_invocation_pending_banner_own_vs_peer_split_auto_collapse_and_redaction(self) -> None:
        from diffquorum.plan_lock import (
            build_pre_invocation_pending_banner,
            close_pending_plan,
            format_pending_plans_bar,
            open_pending_plan,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            primary = root / "primary_plans.json"
            mirror = root / "mirror_plans.json"

            self.assertEqual(build_pre_invocation_pending_banner("builder", primary, mirror_path=mirror), "")
            self.assertEqual(format_pending_plans_bar(primary, mirror_path=mirror, width=60), "")

            r1 = open_pending_plan(primary, seat="lead", scope="router-arch", title="[Step 1] Router Plan <script>x</script>")
            r2 = open_pending_plan(primary, seat="builder", scope="ci-matrix", title="Packaging Matrix")
            r3 = open_pending_plan(primary, seat="vault", scope="sensitive-audit", title="CONFIDENTIAL_AUDIT_TITLE")
            self.assertFalse(r1["collision"])
            self.assertFalse(r2["collision"])
            self.assertFalse(r3["collision"])

            mirror.write_text('{"schema_version":"1.0","rev":1,"plans":[]}', encoding="utf-8")

            banner = build_pre_invocation_pending_banner(
                "builder",
                primary,
                mirror_path=mirror,
                redacted_seats={"vault"},
            )
            self.assertIn("own:1 | peers:2 | total:3", banner)
            self.assertIn("lead(", banner)
            self.assertIn("builder(", banner)
            self.assertIn("vault(1 pending)", banner)
            self.assertNotIn("CONFIDENTIAL_AUDIT_TITLE", banner)
            self.assertNotIn("sensitive-audit", banner)
            self.assertNotIn("<script>", banner)

            bar_wide = format_pending_plans_bar(primary, mirror_path=mirror, width=90, redacted_seats={"vault"})
            self.assertTrue(bar_wide.startswith("[APR:3] "))
            self.assertIn("vault(1 pending)", bar_wide)
            self.assertNotIn("CONFIDENTIAL_AUDIT_TITLE", bar_wide)

            bar_narrow = format_pending_plans_bar(primary, mirror_path=mirror, width=40, redacted_seats={"vault"})
            self.assertLessEqual(len(bar_narrow), 40)

            for pid, owner in (
                (r1["plan"]["plan_id"], "lead"),
                (r2["plan"]["plan_id"], "builder"),
                (r3["plan"]["plan_id"], "vault"),
            ):
                close_pending_plan(primary, seat=owner, plan_id=pid, status="APPROVED")
            self.assertEqual(build_pre_invocation_pending_banner("builder", primary), "")
            self.assertEqual(format_pending_plans_bar(primary), "")

            sym = root / "sym.json"
            sym.symlink_to(primary)
            self.assertEqual(build_pre_invocation_pending_banner("builder", sym), "")
            big = root / "big.json"
            big.write_text(
                '{"rev":99,"plans":[{"seat":"lead","status":"WAITING_APPROVE","title":"' + ("A" * 530000) + '"}]}',
                encoding="utf-8",
            )
            self.assertEqual(build_pre_invocation_pending_banner("builder", big), "")

    def test_plan_hook_allowlist_symmetry_and_headless_review_guards(self) -> None:
        from diffquorum.governance import build_headless_review_argv, validate_headless_review_spec
        from diffquorum.plan_lock import validate_plan_hook_command

        # 1) Multi-seat PreToolUse hook symmetry for plan open/list/close
        self.assertEqual(validate_plan_hook_command("diffquorum plan list")["mode"], "allow_readonly")
        self.assertEqual(validate_plan_hook_command("python3 /usr/local/bin/star-bus.py plan open --seat s1 --scope demo --title T")["mode"], "allow_mutate")
        self.assertEqual(validate_plan_hook_command("star-bus plan close --seat s1 --plan-id PLN-1 --status APPROVED")["mode"], "allow_mutate")
        for bad_cmd in (
            "",
            "diffquorum plan list; id",
            "diffquorum plan list --plans-file /tmp/evil.json",
            "diffquorum plan list '--plans-file' /tmp/evil.json",
            'diffquorum plan list "--plans-file=/tmp/evil.json"',
            "diffquorum plan open --root /tmp/x --seat s1 --scope a --title b",
            "diffquorum plan open '--root' /tmp/escape --seat s1 --scope a --title b",
            'diffquorum plan open "--root=/tmp/escape" --seat s1 --scope a --title b',
            "/tmp/attacker/diffquorum plan list",
            "./diffquorum plan list",
            "python3 diffquorum plan list",
            "python3 star-bus.py plan open --seat s1 --scope a --title b",
            "/tmp/attacker/python3 /usr/local/bin/star-bus.py plan list",
            "diffquorum plan delete --seat s1",
            "curl plan list",
            "diffquorum dispatch --summary hi",
            "diffquorum plan 'unterminated",
        ):
            res = validate_plan_hook_command(bad_cmd)
            self.assertFalse(res["allowed"], f"Expected deny for {bad_cmd!r}: {res}")

        # 1b) Symlinked plans_path leaf or parent must be rejected before dereferencing (O_NOFOLLOW parity)
        from diffquorum.plan_lock import close_pending_plan, list_pending_plans, open_pending_plan, supersede_plans_for_scope

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            real_target = root / "real_plans.json"
            leaf_link = root / "link_plans.json"
            leaf_link.symlink_to(real_target)
            with self.assertRaises(ValueError):
                open_pending_plan(leaf_link, seat="lead", scope="sym-test", title="No")
            with self.assertRaises(ValueError):
                list_pending_plans(leaf_link)
            with self.assertRaises(ValueError):
                close_pending_plan(leaf_link, seat="lead", scope="sym-test")
            with self.assertRaises(ValueError):
                supersede_plans_for_scope(leaf_link, "sym-test", superseded_by="TKT-1")
            self.assertFalse(real_target.exists())

        # 2) Headless blind-review CLI tool-stripping, X/social search blocking & <300s timeout guard
        clean_prompt = "Audit the provided unified diff for objective defects only."
        argv = build_headless_review_argv("reviewer-cli", model="frontier-reasoner", prompt=clean_prompt)
        self.assertIn("--disallowed-tools", argv)
        self.assertIn("x_keyword_search", argv[argv.index("--disallowed-tools") + 1])
        ok_spec = validate_headless_review_spec(argv=argv, prompt=clean_prompt, timeout_sec=180)
        self.assertTrue(ok_spec["ok"], ok_spec)

        argv_all_off = build_headless_review_argv(
            "reviewer-cli",
            model="frontier-reasoner",
            prompt=clean_prompt,
            disable_all_tools=True,
            system_prompt_override="Static diff review only. Do not invoke any search tools.",
        )
        self.assertIn("--tools", argv_all_off)
        self.assertIn("--system-prompt-override", argv_all_off)
        self.assertTrue(validate_headless_review_spec(argv=argv_all_off, prompt=clean_prompt, timeout_sec=180)["ok"])

        # Partial --disable-web-search without stripping server-side X/social search must fail closed
        partial_web_only = validate_headless_review_spec(
            argv=["reviewer-cli", "--disable-web-search", "--disallowed-tools", "Bash,WebSearch", clean_prompt],
            prompt=clean_prompt,
            timeout_sec=120,
        )
        self.assertFalse(partial_web_only["ok"])
        self.assertIn("incomplete_web_only_strip", "\n".join(partial_web_only["issues"]))
        # Pairing --disable-web-search with --tools "" passes cleanly
        self.assertTrue(
            validate_headless_review_spec(
                argv=["reviewer-cli", "--disable-web-search", "--tools", "", clean_prompt],
                prompt=clean_prompt,
                timeout_sec=120,
            )["ok"]
        )

        bad_spec = validate_headless_review_spec(
            argv=["reviewer-cli", "--print", clean_prompt],
            prompt="Please web_search and x_keyword_search the latest docs and audit this diff.",
            timeout_sec=360,
        )
        self.assertFalse(bad_spec["ok"])
        joined = "\n".join(bad_spec["issues"])
        self.assertIn("missing_tool_strip", joined)
        self.assertIn("search_trigger_in_prompt", joined)
        self.assertIn("timeout_exceeds_deadline", joined)
        self.assertFalse(validate_headless_review_spec(argv=argv, prompt=clean_prompt, timeout_sec=float("nan"))["ok"])

        with self.assertRaises(ValueError):
            build_headless_review_argv("reviewer-cli", model="m1", prompt="p", disallowed_tools=())

        # 3) Stale non-daemon background drawer task deadlock exemption (>=180s transcript + task log quiescence)
        from diffquorum.wake_gates import is_stale_bg_quiescent_for_unblock

        self.assertTrue(is_stale_bg_quiescent_for_unblock(transcript_age_sec=240.0, task_log_ages_sec=[210.0, 190.0]))
        self.assertFalse(is_stale_bg_quiescent_for_unblock(transcript_age_sec=240.0, task_log_ages_sec=[45.0]))
        self.assertFalse(is_stale_bg_quiescent_for_unblock(transcript_age_sec=90.0, task_log_ages_sec=[300.0]))
        self.assertFalse(is_stale_bg_quiescent_for_unblock(transcript_age_sec=float("nan"), task_log_ages_sec=[300.0]))

        base_snap = {
            "pane_in_mode": 0,
            "pane_fg": "agy",
            "client_activity_ts": 900.0,
            "capture_lines": [">", "? for shortcuts"],
            "cursor_x": 2,
            "transcript_last_type": "PLANNER_RESPONSE",
            "transcript_last_status": "DONE",
            "transcript_has_tool_calls": False,
            "transcript_mtime_ts": 700.0,
            "running_tasks": [{"isDaemon": False, "status": "running", "description": "ssh remote tail -f"}],
            "allow_stale_bg_unblock": True,
        }
        # Active task log (<180s) stays protected on Gate 4
        blocked_snap = evaluate_six_gates({**base_snap, "task_log_ages_sec": [30.0]}, now_ts=1000.0)
        self.assertFalse(blocked_snap["wake"])
        self.assertEqual(blocked_snap["reason"], "NON_DAEMON_TASK_RUNNING")
        # Both transcript (300s) and task logs (220s) silent >=180s -> deadlock unblocked
        unblocked_snap = evaluate_six_gates({**base_snap, "task_log_ages_sec": [220.0]}, now_ts=1000.0)
        self.assertTrue(unblocked_snap["wake"], unblocked_snap)

    def test_governance_policy_suite_discussion_blast_radius_mm_and_master_dict(self) -> None:
        from diffquorum.policy import (
            R1_FAST_LANE_INVARIANTS,
            audit_master_dictionary_drift,
            evaluate_blast_radius_route,
            evaluate_discussion_plan,
            partition_ab_folds,
            validate_mm_autopsy_packet,
        )

        # 1) D0..D2 front-door discussion cap & specialty routing
        self.assertTrue(evaluate_discussion_plan(tier="D0", rounds_requested=0, author_family="family_a")["ok"])
        self.assertFalse(
            evaluate_discussion_plan(
                tier="D0", rounds_requested=1, author_family="family_a", advisor_models=["m1"], advisor_families=["family_b"]
            )["ok"]
        )
        self.assertTrue(
            evaluate_discussion_plan(
                tier="D1",
                rounds_requested=1,
                author_family="family_a",
                advisor_models=["frontier-b"],
                advisor_families=["family_b"],
                specialty_domain="pricing_and_product_pruning",
            )["ok"]
        )
        d2_ok = evaluate_discussion_plan(
            tier="D2",
            rounds_requested=1,
            author_family="family_a",
            advisor_models=["frontier-b", "frontier-c"],
            advisor_families=["family_b", "family_c"],
            has_strawman=True,
        )
        self.assertTrue(d2_ok["ok"], d2_ok)
        d2_bad = evaluate_discussion_plan(
            tier="D2",
            rounds_requested=2,
            author_family="family_a",
            advisor_models=["fast-mini-1", "frontier-a"],
            advisor_families=["family_b", "family_a"],
            has_strawman=False,
        )
        self.assertFalse(d2_bad["ok"])
        joined_d2 = "\n".join(d2_bad["issues"])
        self.assertIn("discussion_round_cap_exceeded", joined_d2)
        self.assertIn("missing_strawman", joined_d2)
        self.assertIn("lightweight_model_forbidden", joined_d2)
        self.assertIn("same_family_self_review", joined_d2)

        # 1b) Lightweight model delimiter checks (`:` / `@`) and D0 stray advisor_families
        self.assertFalse(
            evaluate_discussion_plan(
                tier="D1",
                rounds_requested=1,
                author_family="family_a",
                advisor_models=["phi4-mini:latest"],
                advisor_families=["family_b"],
            )["ok"]
        )
        self.assertFalse(
            evaluate_discussion_plan(
                tier="D0",
                rounds_requested=0,
                author_family="family_a",
                advisor_families=["family_b"],
            )["ok"]
        )

        # 2) R0..R3 blast-radius 4-tier routing including R1 pure-copy fast lane
        self.assertTrue(evaluate_blast_radius_route(offline_or_readonly=True, claimed_tier="R0")["ok"])
        all_r1 = {k: True for k in R1_FAST_LANE_INVARIANTS}
        r1_ok = evaluate_blast_radius_route(pure_copy_candidate=True, r1_invariants=all_r1, claimed_tier="R1")
        self.assertTrue(r1_ok["ok"] and r1_ok["fast_lane_eligible"])

        # Violating or omitting R1 invariants must auto-escalate to R2 and reject claimed R1
        r1_escalated = evaluate_blast_radius_route(
            pure_copy_candidate=True,
            r1_invariants={**all_r1, "zero_logic_math_changes": False},
            claimed_tier="R1",
        )
        self.assertFalse(r1_escalated["ok"])
        self.assertEqual(r1_escalated["required_tier"], "R2")

        # Unknown critical domain must fail closed to R3 (never fast_lane_eligible)
        r_unk = evaluate_blast_radius_route(
            offline_or_readonly=True,
            critical_domains_touched=["unlisted_critical_surface"],
            claimed_tier="R0",
        )
        self.assertFalse(r_unk["ok"])
        self.assertEqual(r_unk["required_tier"], "R3")
        self.assertFalse(r_unk["fast_lane_eligible"])

        # Critical domain auto-escalates to R3 requiring 2 distinct cross-family reviewers + independent tests
        r3_bad = evaluate_blast_radius_route(
            critical_domains_touched=["auth_or_multitenant_privacy"],
            claimed_tier="R2",
            author_family="family_a",
            reviewer_families=["family_b"],
            has_written_spec=True,
        )
        self.assertFalse(r3_bad["ok"])
        self.assertEqual(r3_bad["required_tier"], "R3")
        r3_ok = evaluate_blast_radius_route(
            critical_domains_touched=["billing_or_redemption", "auth_or_multitenant_privacy"],
            claimed_tier="R3",
            author_family="family_a",
            reviewer_families=["family_b", "family_c"],
            has_written_spec=True,
            independent_verification_passed=True,
            review_round=2,
        )
        self.assertTrue(r3_ok["ok"], r3_ok)

        # 3) Fold-A / Fold-B anti-self-confirmation double-blind M&M autopsy
        folds = partition_ab_folds(["W01", "W02", "W03", "W04", "W05", "W06"], embargo_blocks=1, holdout_blocks=["W07"])
        self.assertEqual(folds["fold_a"], ["W01", "W05"])
        self.assertEqual(folds["fold_b"], ["W03"])
        self.assertEqual(folds["embargoed"], ["W02", "W04", "W06"])
        with self.assertRaises(ValueError):
            partition_ab_folds(["W01", "W07"], holdout_blocks=["W07"])

        valid_mm = {
            "experiment_status": "REJECTED",
            "is_release_gate": False,
            "autopsy_round": 1,
            "author_family": "family_a",
            "fold_a_blocks": folds["fold_a"],
            "fold_b_blocks": folds["fold_b"],
            "holdout_blocks": ["W07"],
            "exposed_to_diagnosticians": "fold_a_only",
            "contains_author_hypotheses": False,
            "diagnosticians": [
                {
                    "model_family": "family_b",
                    "saw_fold_b": False,
                    "report_sha256": "a" * 64,
                    "hypotheses": [
                        {
                            "mechanism": "feature distribution shift in bucket 3",
                            "fold_b_metric": "rank_corr_delta",
                            "expected_direction": "up",
                            "single_variable_change": "drop unstable feature group",
                        }
                    ],
                },
                {
                    "model_family": "family_c",
                    "saw_fold_b": False,
                    "report_sha256": "b" * 64,
                    "hypotheses": [
                        {
                            "mechanism": "cache eviction overhead under burst load",
                            "fold_b_metric": "p99_latency_delta",
                            "expected_direction": "threshold",
                            "single_variable_change": "increase cache ttl window",
                        }
                    ],
                },
            ],
            "converged_probes": [
                {"fold_b_metric": "rank_corr_delta", "zero_retrain": True, "max_runtime_sec": 180},
            ],
            "multiple_testing_correction": "holm",
            "alpha": 0.05,
        }
        self.assertTrue(validate_mm_autopsy_packet(valid_mm)["ok"])

        # Hardening regressions: omitted author_family, unregistered Fold-B probe metric, 3-diag duplicate hash, huge int alpha
        no_auth = {**valid_mm, "author_family": ""}
        self.assertIn("missing_author_family", "\n".join(validate_mm_autopsy_packet(no_auth)["issues"]))
        unreg_probe = {
            **valid_mm,
            "converged_probes": [{"fold_b_metric": "post_hoc_unlisted_metric", "zero_retrain": True, "max_runtime_sec": 60}],
        }
        self.assertIn("unregistered_fold_b_probe_metric", "\n".join(validate_mm_autopsy_packet(unreg_probe)["issues"]))
        dup3 = {
            **valid_mm,
            "diagnosticians": [
                *valid_mm["diagnosticians"],
                {**valid_mm["diagnosticians"][0], "model_family": "family_d"},
            ],
        }
        self.assertIn("duplicate_diagnosis_hashes", "\n".join(validate_mm_autopsy_packet(dup3)["issues"]))
        huge_int = {**valid_mm, "alpha": 10**400}
        self.assertIn("invalid_alpha", "\n".join(validate_mm_autopsy_packet(huge_int)["issues"]))

        bad_mm = {
            **valid_mm,
            "is_release_gate": True,
            "autopsy_round": 2,
            "fold_b_blocks": ["W01", "W03"],
            "exposed_to_diagnosticians": "full",
            "contains_author_hypotheses": True,
            "alpha": 0.25,
        }
        res_bad_mm = validate_mm_autopsy_packet(bad_mm)
        self.assertFalse(res_bad_mm["ok"])
        joined_mm = "\n".join(res_bad_mm["issues"])
        self.assertIn("mm_must_not_be_release_gate", joined_mm)
        self.assertIn("self_confirmation_leak", joined_mm)
        self.assertIn("fold_b_exposed", joined_mm)

        # 4) Machine-readable Master Dictionary cross-repo drift & emoji guard (+ CLI)
        with tempfile.TemporaryDirectory() as tmp:
            troot = pathlib.Path(tmp)
            dict_p = troot / "master_dict.json"
            dict_p.write_text(
                json.dumps(
                    {
                        "schema_version": "diffquorum_master_dict/v1",
                        "version": "1.0.0",
                        "single_authority_domains": {"primary_nav": "NAMING_V1"},
                        "canonical_tokens": {
                            "platform_version": {"value": "v2.0", "required_in": ["README.md", "README.zh-CN.md"]}
                        },
                        "canonical_terms": {
                            "workspace": {"zh": "工作区", "en": "Workspace", "forbidden": ["legacy-box"]}
                        },
                        "retired_phrases": ["Old Brand v0"],
                        "typography_invariants": {"emoji_count": 0},
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            (troot / "README.md").write_text("# Demo v2.0\nWorkspace docs.\n", encoding="utf-8")
            (troot / "README.zh-CN.md").write_text("# 示例 v2.0\n工作区文档。\n", encoding="utf-8")
            clean_rep = audit_master_dictionary_drift(dict_p, troot)
            self.assertTrue(clean_rep["ok"], clean_rep)

            # Single-file dict-check must STILL enforce canonical_tokens required_in + colored status emoji + invalid UTF-8 byte cannot bypass
            (troot / "README.md").write_bytes(b"# Demo v1.9\nStatus: \xf0\x9f\x9f\xa2\xff legacy-box\n")
            sf_rep = audit_master_dictionary_drift(dict_p, troot / "README.md")
            self.assertFalse(sf_rep["ok"])
            joined_sf = "\n".join(sf_rep["findings"])
            self.assertIn("canonical_token_drift", joined_sf)
            self.assertIn("legacy-box", joined_sf)
            self.assertIn("emoji violation", joined_sf)

            # FIFO in directory must not hang or crash scanner
            import os as _os

            if hasattr(_os, "mkfifo"):
                _os.mkfifo(str(troot / "dummy.fifo"))

            # Introduce drift, forbidden phrase, and emoji -> Fail-Closed
            (troot / "README.md").write_text("# Demo v1.9\nUses legacy-box and Old Brand v0 \U0001f680\n", encoding="utf-8")
            drift_rep = audit_master_dictionary_drift(dict_p, troot)
            self.assertFalse(drift_rep["ok"])
            joined_dr = "\n".join(drift_rep["findings"])
            self.assertIn("canonical_token_drift", joined_dr)
            self.assertIn("legacy-box", joined_dr)
            self.assertIn("Old Brand v0", joined_dr)
            self.assertIn("emoji violation", joined_dr)

            # CLI exit codes: 0 on pass, 2 on fail (including Fail-Closed R1 without explicit invariants JSON)
            mm_file = troot / "mm_valid.json"
            mm_file.write_text(json.dumps(valid_mm), encoding="utf-8")
            self.assertEqual(self.run_cli("mm-verify", "--packet", str(mm_file)).returncode, 0)
            self.assertEqual(
                self.run_cli("discuss-check", "--tier", "D0", "--rounds", "0", "--author-family", "family_a").returncode,
                0,
            )
            self.assertEqual(
                self.run_cli("route-risk", "--offline-or-readonly", "--claimed-tier", "R0").returncode,
                0,
            )
            self.assertEqual(
                self.run_cli("route-risk", "--pure-copy-candidate", "--claimed-tier", "R1", check=False).returncode,
                2,
            )
            self.assertEqual(
                self.run_cli(
                    "route-risk",
                    "--pure-copy-candidate",
                    "--r1-invariants-json",
                    json.dumps(all_r1),
                    "--claimed-tier",
                    "R1",
                ).returncode,
                0,
            )
            self.assertEqual(
                self.run_cli("dict-check", "--dict", str(dict_p), "--target", str(troot), check=False).returncode,
                2,
            )

    def test_pending_kinds_reopen_stop_consistency_gate_and_hooks_json_schema(self) -> None:
        from diffquorum.plan_lock import (
            PLAN_MAX_CLOSED_RETAIN,
            build_pre_invocation_pending_banner,
            close_pending_plan,
            evaluate_stop_consistency_gate,
            format_pending_plans_bar,
            list_pending_plans,
            open_pending_plan,
            reopen_pending_plan,
            validate_hooks_json_schema,
            validate_plan_hook_command,
        )
        from diffquorum.wake_gates import evaluate_six_gates

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            pfile = root / "pending_plans.json"

            # 1) All 4 kinds (PLAN / DECISION / CIRCUIT_BREAKER / INPUT_REQUIRED) + badges + 512KB tolerance
            r_dec = open_pending_plan(pfile, seat="lead", scope="route-choice", title="Pick option A or B", kind="DECISION")
            r_cb = open_pending_plan(pfile, seat="worker", scope="billing-gate", title="Quota circuit breaker", kind="CIRCUIT_BREAKER")
            r_inp = open_pending_plan(pfile, seat="vault", scope="secret-input", title="CONFIDENTIAL_INPUT", kind="INPUT_REQUIRED")
            self.assertEqual(r_dec["plan"]["kind"], "DECISION")
            self.assertEqual(r_cb["plan"]["kind"], "CIRCUIT_BREAKER")
            self.assertEqual(r_inp["plan"]["kind"], "INPUT_REQUIRED")
            self.assertEqual(list_pending_plans(pfile, kind="DECISION")["count"], 1)

            banner_peer = build_pre_invocation_pending_banner("lead", pfile, redacted_seats={"vault"})
            self.assertIn("lead[DEC](", banner_peer)
            self.assertIn("worker[CB](", banner_peer)
            self.assertIn("vault(1 pending)", banner_peer)
            self.assertNotIn("CONFIDENTIAL_INPUT", banner_peer)

            # Sensitive seat can view its own pending item when allow_self_view=True
            banner_self = build_pre_invocation_pending_banner("vault", pfile, redacted_seats={"vault"}, allow_self_view=True)
            self.assertIn("vault[INP](", banner_self)
            self.assertIn("CONFIDENTIAL_INPUT", banner_self)

            bar = format_pending_plans_bar(pfile, width=120, redacted_seats={"vault"})
            self.assertIn("lead[DEC]:", bar)
            self.assertIn("worker[CB]:", bar)
            self.assertIn("vault(1 pending)", bar)
            self.assertNotIn("CONFIDENTIAL_INPUT", bar)

            # 2) Close then reopen in place (zero gap + collision check + auth check)
            close_pending_plan(pfile, seat="lead", plan_id=r_dec["plan"]["plan_id"], status="APPROVED")
            self.assertEqual(list_pending_plans(pfile, kind="DECISION")["count"], 0)
            with self.assertRaises(PermissionError):
                reopen_pending_plan(pfile, seat="outsider", plan_id=r_dec["plan"]["plan_id"])
            re_ok = reopen_pending_plan(
                pfile,
                seat="lead",
                plan_id=r_dec["plan"]["plan_id"],
                kind="CIRCUIT_BREAKER",
                title="Reopened on mid-flight gate",
                note="Need confirmation",
            )
            self.assertTrue(re_ok["ok"] and not re_ok["collision"])
            self.assertEqual(re_ok["plan"]["status"], "WAITING_APPROVE")
            self.assertEqual(re_ok["plan"]["kind"], "CIRCUIT_BREAKER")
            self.assertEqual(re_ok["plan"]["reopen_count"], 1)

            # Cross-seat collision when reopening a closed scope already claimed by another seat
            close_pending_plan(pfile, seat="lead", plan_id=r_dec["plan"]["plan_id"], status="CANCELLED")
            open_pending_plan(pfile, seat="worker", scope="route-choice", title="Worker took scope", kind="PLAN")
            re_col = reopen_pending_plan(pfile, seat="lead", plan_id=r_dec["plan"]["plan_id"])
            self.assertFalse(re_col["ok"])
            self.assertTrue(re_col["collision"])

            # 3) CLI plan open --kind / list --kind / reopen
            cli_p = root / "cli_plans.json"
            self.assertEqual(
                self.run_cli(
                    "plan", "open", "--plans-file", str(cli_p),
                    "--seat", "lead", "--scope", "cli-dec", "--title", "CLI Decision", "--kind", "DECISION",
                ).returncode,
                0,
            )
            self.assertEqual(
                self.run_cli("plan", "list", "--plans-file", str(cli_p), "--kind", "DECISION").returncode,
                0,
            )
            self.assertEqual(
                self.run_cli(
                    "plan", "close", "--plans-file", str(cli_p),
                    "--seat", "lead", "--scope", "cli-dec", "--status", "APPROVED",
                ).returncode,
                0,
            )
            self.assertEqual(
                self.run_cli(
                    "plan", "reopen", "--plans-file", str(cli_p),
                    "--seat", "lead", "--scope", "cli-dec", "--kind", "INPUT_REQUIRED", "--note", "Need key",
                ).returncode,
                0,
            )
            self.assertEqual(list_pending_plans(cli_p, kind="INPUT_REQUIRED")["count"], 1)

            # 4) Hook allowlist permits `plan reopen` and `~/bin/`
            self.assertEqual(
                validate_plan_hook_command("~/bin/star-bus plan reopen --seat lead --scope cli-dec")["mode"],
                "allow_mutate",
            )

            # 5) Stop consistency gate: Intercept A/B, code-block stripping, readonly_auto_register, 1-retry anti-loop
            # Ignored when termination_reason != NO_TOOL_CALL or not fully_idle
            self.assertEqual(
                evaluate_stop_consistency_gate(
                    response_text="请先审核上面的计划，回复 Approve 后我再开始执行。",
                    own_waiting_count=0,
                    peer_waiting_count=0,
                    termination_reason="TOOL_CALL",
                )["decision"],
                "allow",
            )
            # Quoted inside fenced or inline code block -> NOT a false positive
            self.assertEqual(
                evaluate_stop_consistency_gate(
                    response_text="Updated regex for `请先审核上面的计划`.\n```\nReply Approve to proceed\n```\nDone.",
                    own_waiting_count=0,
                    peer_waiting_count=0,
                )["decision"],
                "allow",
            )
            # Intercept A: unregistered DECISION while own_waiting == 0 -> continue
            stop_a = evaluate_stop_consistency_gate(
                response_text="目前有两套架构方案，请你拍板选定方案 A 还是方案 B。",
                own_waiting_count=0,
                peer_waiting_count=0,
            )
            self.assertEqual(stop_a["decision"], "continue")
            self.assertEqual(stop_a["inferred_kind"], "DECISION")
            # Shell-less readonly seat OR continuation_active=True -> auto_register + allow (never infinite loop!)
            stop_ro = evaluate_stop_consistency_gate(
                response_text="目前有两套架构方案，请你拍板选定方案 A 还是方案 B。",
                own_waiting_count=0,
                peer_waiting_count=0,
                readonly_auto_register=True,
            )
            self.assertEqual(stop_ro["decision"], "allow")
            self.assertEqual(stop_ro["action"], "auto_register")
            stop_loop = evaluate_stop_consistency_gate(
                response_text="目前有两套架构方案，请你拍板选定方案 A 还是方案 B。",
                own_waiting_count=0,
                peer_waiting_count=0,
                continuation_active=True,
            )
            self.assertEqual(stop_loop["decision"], "allow")
            self.assertEqual(stop_loop["action"], "auto_register")
            # Intercept B: false-zero peer footer while peer_waiting == 2 -> continue on first pass, allow on continuation
            stop_b = evaluate_stop_consistency_gate(
                response_text="已完成检查。\n\n**当前待你拍板清单（本席 0 项 | 全机他席 0 项）：无**",
                own_waiting_count=0,
                peer_waiting_count=2,
            )
            self.assertEqual(stop_b["decision"], "continue")
            self.assertEqual(
                evaluate_stop_consistency_gate(
                    response_text="已完成检查。\n\n**当前待你拍板清单（本席 0 项 | 全机他席 0 项）：无**",
                    own_waiting_count=0,
                    peer_waiting_count=2,
                    continuation_active=True,
                )["decision"],
                "allow",
            )

            # 6) hooks.json flat vs grouped schema validator
            good_hooks = {
                "sync": {
                    "enabled": True,
                    "PreInvocation": [{"command": "python3 hook.py"}],
                    "Stop": [{"command": "python3 hook.py"}],
                    "PreToolUse": [{"matcher": "run_command", "hooks": [{"command": "python3 guard.py"}]}],
                }
            }
            self.assertTrue(validate_hooks_json_schema(good_hooks)["ok"])
            bad_hooks = {
                "broken": {
                    "PreInvocation": [{"matcher": "*", "hooks": [{"command": "python3 hook.py"}]}],
                    "Stop": [{"matcher": "*", "hooks": [{"command": "python3 hook.py"}]}],
                }
            }
            bad_res = validate_hooks_json_schema(bad_hooks)
            self.assertFalse(bad_res["ok"])
            self.assertIn("flat event must not wrap", "\n".join(bad_res["issues"]))

            # 7) Gate 4 pending_plans wakeup protection (protects any open WAITING_APPROVE kind unless strictly newer ticket)
            snap_pending = {
                "pane_in_mode": 0,
                "pane_fg": "agy",
                "client_activity_ts": 100.0,
                "capture_lines": [">", "? for shortcuts"],
                "cursor_x": 2,
                "transcript_last_type": "PLANNER_RESPONSE",
                "transcript_last_status": "DONE",
                "transcript_has_tool_calls": False,
                "has_waiting_pending_plan": True,
                "pending_plan_updated_ts": 500.0,
                "newest_ready_ticket_ts": 400.0,
            }
            g_blk = evaluate_six_gates(snap_pending, now_ts=1000.0)
            self.assertFalse(g_blk["wake"])
            self.assertEqual(g_blk["reason"], "AWAITING_HUMAN_APPROVE")
            g_ok = evaluate_six_gates({**snap_pending, "newest_ready_ticket_ts": 600.0}, now_ts=1000.0)
            self.assertTrue(g_ok["wake"], g_ok)
            g_nan = evaluate_six_gates({**snap_pending, "pending_plan_updated_ts": float("nan"), "newest_ready_ticket_ts": 600.0}, now_ts=1000.0)
            self.assertFalse(g_nan["wake"])
            self.assertEqual(g_nan["reason"], "AWAITING_HUMAN_APPROVE")

            # 8) Retention cap retains all WAITING_APPROVE + bounded latest closed entries
            self.assertEqual(PLAN_MAX_CLOSED_RETAIN, 200)

    def test_29_three_stage_blind_eval_commercial_r3_and_space_approval(self) -> None:
        from diffquorum.policy import evaluate_blast_radius_route, evaluate_post_launch_blind_eval
        from diffquorum.wake_gates import is_explicit_approval_text

        # 1) Non-code commercial_flagship_deliverable auto-escalates to R3 dual-blind review
        r3_under = evaluate_blast_radius_route(
            critical_domains_touched=["commercial_flagship_deliverable"],
            claimed_tier="R2",
            author_family="family_a",
            reviewer_families=["family_b"],
            has_written_spec=True,
        )
        self.assertFalse(r3_under["ok"])
        self.assertEqual(r3_under["required_tier"], "R3")
        r3_ok = evaluate_blast_radius_route(
            critical_domains_touched=["commercial_flagship_deliverable"],
            claimed_tier="R3",
            author_family="family_a",
            reviewer_families=["family_b", "family_c"],
            has_written_spec=True,
            independent_verification_passed=True,
        )
        self.assertTrue(r3_ok["ok"], r3_ok["issues"])

        # 2) Stage-3 post-launch zero-context blind evaluation (B0..B2)
        self.assertTrue(evaluate_post_launch_blind_eval(tier="B0", author_family="family_a", eval_round=0)["ok"])
        self.assertFalse(evaluate_post_launch_blind_eval(tier="B0", author_family="family_a", eval_round=1)["ok"])
        self.assertFalse(
            evaluate_post_launch_blind_eval(
                tier="B0",
                author_family="family_a",
                eval_round=0,
                evaluator_models=["frontier-model-b"],
                evaluator_families=["family_b"],
            )["ok"]
        )
        self.assertTrue(
            evaluate_post_launch_blind_eval(
                tier="B1",
                author_family="family_a",
                external_entrypoint="public-artifact:executive-deck-v1.pdf",
                evaluator_models=["frontier-model-b"],
                evaluator_families=["family_b"],
            )["ok"]
        )
        self.assertTrue(
            evaluate_post_launch_blind_eval(
                tier="B2",
                author_family="family_a",
                external_entrypoint="https://app.example.com/start",
                evaluator_models=["frontier-model-b", "frontier-model-c"],
                evaluator_families=["family_b", "family_c"],
                evaluator_personas=["first_time_user", "enterprise_buyer"],
            )["ok"]
        )

        # Reject internal/private/CGNAT/fake-IP/file/local entrypoints & context leaks
        cgnat_host = ".".join(("100", "64", "2", "9"))
        fake_host = ".".join(("198", "18", "0", "25"))
        rfc1918_host = ".".join(("192", "168", "1", "20"))
        for bad_ep in (
            "",
            "http://localhost:3000",
            "http://127.0.0.1:8000",
            f"http://{rfc1918_host}:8080",
            f"http://{cgnat_host}/demo",
            f"http://{fake_host}/demo",
            f"http://[::ffff:{fake_host}]/demo",
            f"http://[::ffff:{cgnat_host}]/demo",
            "http://[invalid",
            "http://intranet/portal",
            "http://2130706433/",
            "file:///etc/hosts",
            "/tmp/internal-draft.pdf",
            "~/private/spec.md",
        ):
            r_ep = evaluate_post_launch_blind_eval(
                tier="B1",
                author_family="family_a",
                external_entrypoint=bad_ep,
                evaluator_models=["frontier-model-b"],
                evaluator_families=["family_b"],
            )
            self.assertFalse(r_ep["ok"], f"Expected rejection for internal entrypoint {bad_ep!r}")
            self.assertTrue(any("invalid_or_internal_external_entrypoint" in x for x in r_ep["issues"]))

        r_fail = evaluate_post_launch_blind_eval(
            tier="B2",
            author_family="family_a",
            external_entrypoint="https://app.example.com",
            leaked_internal_context=True,
            is_blocking_live_service=True,
            eval_round=2,
            evaluator_models=["small-fast-model", "frontier-model-a"],
            evaluator_families=["family_b", "family_a"],
            evaluator_personas=["buyer", "buyer"],
        )
        self.assertFalse(r_fail["ok"])
        joined = "\n".join(r_fail["issues"])
        for expected_code in (
            "blind_eval_must_not_block_live_service",
            "blind_eval_round_cap_exceeded",
            "internal_context_leaked",
            "lightweight_model_forbidden",
            "same_family_self_eval",
            "duplicate_evaluator_persona",
        ):
            self.assertIn(expected_code, joined)

        # CLI blind-eval-check returns exit 0 on valid B2 and exit 2 on internal entrypoint
        r_cli_ok = self.run_cli(
            "blind-eval-check",
            "--tier", "B2",
            "--author-family", "family_a",
            "--external-entrypoint", "https://app.example.com/demo",
            "--evaluator-model", "frontier-model-b",
            "--evaluator-family", "family_b",
            "--evaluator-model", "frontier-model-c",
            "--evaluator-family", "family_c",
            "--evaluator-persona", "buyer",
            "--evaluator-persona", "auditor",
        )
        self.assertEqual(r_cli_ok.returncode, 0, r_cli_ok.stdout + r_cli_ok.stderr)
        r_cli_bad = self.run_cli(
            "blind-eval-check",
            "--tier", "B1",
            "--author-family", "family_a",
            "--external-entrypoint", "http://localhost:8080",
            "--evaluator-model", "frontier-model-b",
            "--evaluator-family", "family_b",
            check=False,
        )
        self.assertEqual(r_cli_bad.returncode, 2)

        # 3) Space- & comma-separated '<selection> 其他/其余 approve' (Fail-Closed on negations/restrictions)
        self.assertTrue(is_explicit_approval_text("方案A比较好 其他 approve"))
        self.assertTrue(is_explicit_approval_text("选项一不错，其余同意"))
        self.assertTrue(is_explicit_approval_text("选方案二 剩下的都批准"))
        for bad_txt in (
            "方案A不好 其他 approve",
            "方案A不好。其他 approve",
            "方案A不好\n其他 approve",
            "方案A未通过 其他 approve",
            "只选方案A 其他 approve",
            "方案A暂缓 其他 approve",
            "别选方案A 其他 approve",
            "除了方案B 其他 approve",
            "只做方案A 其他 approve",
            "先别改A 其他 approve",
            "方案A行吗？其他 approve",
            "不要用方案A 其他 approve",
        ):
            self.assertFalse(is_explicit_approval_text(bad_txt), f"Must reject {bad_txt!r}")


if __name__ == "__main__":
    unittest.main()
