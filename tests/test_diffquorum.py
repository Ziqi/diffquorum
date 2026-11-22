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

            shim_ver = self.run_cli("--version", script_path=LEGACY_SCRIPT)
            self.assertEqual(shim_ver.returncode, 0)
            self.assertIn("0.3.0.dev0", shim_ver.stdout.decode("utf-8"))

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


if __name__ == "__main__":
    unittest.main()
