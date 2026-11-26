#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""
Zero-dependency executable statement coverage gate for DiffQuorum
(satisfies OpenSSF Best Practices Silver `test_statement_coverage80`, targeting >=90%).

Measures Python stdlib `dis` + `trace` statement coverage across
`src/diffquorum/{blackboard,governance,wake_gates,cli}.py`.
"""

from __future__ import annotations

import argparse
import dis
import io
import json
import pathlib
import shutil
import sys
import tempfile
import trace
import types
from contextlib import redirect_stderr, redirect_stdout

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
TARGET_FILES = (
    (SRC_DIR / "diffquorum" / "blackboard.py").resolve(),
    (SRC_DIR / "diffquorum" / "governance.py").resolve(),
    (SRC_DIR / "diffquorum" / "wake_gates.py").resolve(),
    (SRC_DIR / "diffquorum" / "ops.py").resolve(),
    (SRC_DIR / "diffquorum" / "plan_lock.py").resolve(),
    (SRC_DIR / "diffquorum" / "cli.py").resolve(),
)


def collect_executable_lines(py_file: pathlib.Path) -> set[int]:
    source = py_file.read_text(encoding="utf-8")
    code_obj = compile(source, str(py_file), "exec")
    lines: set[int] = set()

    def _walk(co: types.CodeType) -> None:
        for _offset, lineno in dis.findlinestarts(co):
            if lineno is not None and lineno > 0:
                lines.add(lineno)
        for const in co.co_consts:
            if isinstance(const, types.CodeType):
                _walk(const)

    _walk(code_obj)
    for idx, text in enumerate(source.splitlines(), start=1):
        if "sys.exit(main())" in text or "TYPE_CHECKING" in text:
            lines.discard(idx)
    return lines


def exercise_suite(temp_root: pathlib.Path) -> None:
    if str(SRC_DIR) not in sys.path:
        sys.path.insert(0, str(SRC_DIR))

    import diffquorum.blackboard as bb
    import diffquorum.cli as cli
    import diffquorum.governance as gov
    import diffquorum.ops as ops
    import diffquorum.plan_lock as plk
    import diffquorum.wake_gates as wg

    # 1. Init, TOML error branches, and board refresh / overflow branches
    for kwargs in ({"topology": "invalid"}, {"subscription": "invalid"}, {"host_alias": "bad host!"}):
        try:
            bb.init_workspace(temp_root / "bad", **kwargs)
        except ValueError:
            pass

    ws = temp_root / "ws"
    bb.init_workspace(ws, topology="ssh-federated", subscription="single-sub", host_alias="workstation", force=True)
    bb.update_board(ws, "# Clean Board\n\n- Status: ACTIVE\n")
    bb.refresh_board_locks(ws)
    assert "Clean Board" in bb.read_board(ws)
    try:
        bb.update_board(ws, "X" * 3100)
    except ValueError:
        pass

    parsed_toml = bb.parse_toml_text('# c\nflag = true\ncount = 3\n[s]\nk = "v"\n[[arr]]\nx = 1\n')
    assert parsed_toml["flag"] is True and parsed_toml["count"] == 3

    # 2. Dispatch, dedup, hop limit, ack silence, resonance circuit breaker & SSH bridge
    bb.dispatch_pointer(
        ws, from_seat="lead", to_seat="builder", summary="D" * 500, artifact_text="spec", event_id="evt-cov-1", now_ts=1000.0
    )
    bb.dispatch_pointer(
        ws, from_seat="lead", to_seat="builder", summary="strict ok", event_id="evt-cov-strict", strict_envelope=True, now_ts=1001.0
    )
    for bad_env in ("a\nb", "[]", json.dumps({"id": "x"}), json.dumps({"id": "x", "from": "a", "kind": "K", "ref": "r", "sum": "Z" * 400})):
        try:
            bb.verify_pointer_envelope(bad_env)
        except ValueError:
            pass
    try:
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="Z" * 380, event_id="evt-cov-big", strict_envelope=True, now_ts=1002.0)
    except ValueError:
        pass
    bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="dup", event_id="evt-cov-1", now_ts=1005.0)
    bb.ack_pointer(ws, seat="builder", event_id="evt-cov-1", emit_reply_to="lead", priority="P1", now_ts=2000.0)
    for call_kw in (
        {"from_seat": "builder", "to_seat": "lead", "summary": "echo", "kind": "ACK", "event_id": "evt-cov-ack2", "now_ts": 2010.0},
        {"from_seat": "bad seat!", "to_seat": "builder", "summary": "x", "event_id": "evt-x", "now_ts": 1000.0},
        {"from_seat": "lead", "to_seat": "builder", "summary": "x", "kind": "NOPE", "event_id": "evt-x", "now_ts": 1000.0},
        {"from_seat": "lead", "to_seat": "builder", "summary": "x", "priority": "P9", "event_id": "evt-x", "now_ts": 1000.0},
        {"from_seat": "lead", "to_seat": "builder", "summary": "x", "hop": 2, "event_id": "evt-x", "now_ts": 1000.0},
        {"from_seat": "lead", "to_seat": "builder", "summary": "x", "event_id": "bad!", "now_ts": 1000.0},
    ):
        try:
            bb.dispatch_pointer(ws, **call_kw)
        except ValueError:
            pass

    for i in range(4):
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary=f"b{i}", event_id=f"evt-b-{i}", now_ts=9000.0 + i * 5)
    try:
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="over", event_id="evt-b-over", now_ts=9030.0)
    except ValueError:
        pass

    _ = bb.build_ssh_peer_command("workstation", "/usr/local/bin/diffquorum")
    good_in = json.dumps(
        {
            "from_host": "workstation",
            "from_seat": "remote-hub",
            "to_seat": "lead",
            "summary": "remote ok",
            "hop": 1,
            "event_id": "evt-rem-1",
        }
    ).encode("ascii")
    bb.ingest_peer_stdin(ws, good_in, now_ts=15000.0)
    for bad_payload in (
        b"x" * (bb.MAX_STDIN_BYTES + 1),
        "中文".encode("utf-8"),
        b"[]",
        b'{"from_host":"rogue","from_seat":"remote-hub","to_seat":"lead"}',
        b'{"from_host":"workstation","from_seat":"unknown","to_seat":"lead"}',
    ):
        try:
            bb.ingest_peer_stdin(ws, bad_payload, now_ts=15005.0)
        except ValueError:
            pass

    assert bb.run_with_lock(ws, "build", "lead", [sys.executable, "-c", "pass"]) == 0

    # Preflight paths (writable, lock busy, missing CLI, symlink agy_state_dir)
    agy_dir = temp_root / "agy_ok"
    agy_dir.mkdir()
    assert bb.run_preflight(ws, write_paths=[str(ws)], resource="build", cli_tools=["python3", ""], agy_state_dir=agy_dir)["ok"]
    (ws / ".diffquorum" / "locks" / "build.holder.json").write_text('{"seat":"lead","pid":1}', encoding="utf-8")
    assert not bb.run_preflight(ws, resource="bad!res", cli_tools=["bad cli!", "missing_dq_bin"])["ok"]
    assert not bb.run_preflight(ws, resource="build")["ok"]
    (ws / ".diffquorum" / "locks" / "build.holder.json").unlink(missing_ok=True)
    agy_sym = temp_root / "agy_sym"
    agy_sym.symlink_to(agy_dir)
    assert not bb.run_preflight(ws, cli_tools=["agy"], agy_state_dir=agy_sym)["ok"]

    # 3. Quorum plan, submit, blind packet, verify & pitfalls/fixes + runner presets
    gov.log_pitfall(ws, title="Cov pitfall", root_cause="edge race", guard="add lock")
    gov.log_fix(ws, title="Cov fix", fix_summary="locked", files="blackboard.py")
    gov.plan_council(ws, topic="优化 Skill 架构", tags_csv="", subscription="single-sub")
    gov.plan_council(ws, topic="Daily outreach", tags_csv="outreach", subscription="multi-sub")
    _ = gov.render_council_workflow("Check invariants", model_tier="pro")

    gov.quorum_submit(ws, meeting_id="m-cov", author="lead", source_kind="local_seat", content="Option A", diff_sha256="deadbeef01")
    assert gov.quorum_verify(ws, meeting_id="m-cov", require_multi_seat=True)["blocked"] is True
    gov.quorum_submit(ws, meeting_id="m-cov", author="builder", source_kind="subagent", content="Option B verified", diff_sha256="deadbeef01")
    assert gov.quorum_verify(ws, meeting_id="m-cov", require_multi_seat=True, resolution_summary="Agreed")["blocked"] is False
    blind = gov.quorum_render_blind_packet(ws, meeting_id="m-cov", seed=7)
    assert blind["labels"] == ["Peer A", "Peer B"]

    tamper_md = ws / ".diffquorum" / "meetings" / "m-cov" / "submissions" / "lead__local_seat.md"
    tamper_md.write_text("tampered", encoding="utf-8")
    try:
        gov.quorum_verify(ws, meeting_id="m-cov", require_multi_seat=True)
    except ValueError:
        pass

    # 3b. v0.3 Model-identity fail-closed probe + strict quorum model matching
    assert gov.verify_model_identity("kimi-k3.1-pro", "kimi-k3.1-pro", root=ws)["ok"] is True
    assert gov.verify_model_identity("kimi-k3.1-pro", "cheap-flash", root=ws)["blocked"] is True
    assert gov.verify_model_identity("kimi-k3.1-pro", "", root=ws)["blocked"] is True
    assert gov.verify_model_identity("kimi-k3.1-pro", "bad slug!", root=ws)["blocked"] is True
    try:
        gov.verify_model_identity("bad slug!", "kimi-k3.1-pro")
    except ValueError:
        pass
    rec_cov = temp_root / "rec_cov.json"
    rec_cov.write_text(json.dumps({"model": "kimi-k3.1-pro"}), encoding="utf-8")
    assert gov.probe_model_receipt(rec_cov, expected_model="kimi-k3.1-pro", root=ws)["ok"] is True

    try:
        gov.quorum_submit(ws, meeting_id="m-cov-m", author="lead", source_kind="local_seat", content="M", expected_model="kimi-k3.1-pro", observed_model="mini")
    except ValueError:
        pass
    try:
        gov.quorum_submit(ws, meeting_id="m-cov-m", author="lead", source_kind="local_seat", content="M", observed_model="bad model!")
    except ValueError:
        pass
    gov.quorum_submit(ws, meeting_id="m-cov-m", author="lead", source_kind="local_seat", content="M1", expected_model="kimi-k3.1-pro", observed_model="kimi-k3.1-pro")
    gov.quorum_submit(ws, meeting_id="m-cov-m", author="builder", source_kind="external_llm", content="M2")
    assert gov.quorum_verify(ws, meeting_id="m-cov-m", require_multi_seat=True, require_model_match=True)["blocked"] is True
    meta_m = ws / ".diffquorum" / "meetings" / "m-cov-m" / "submissions" / "lead__local_seat.json"
    mdoc = json.loads(meta_m.read_text(encoding="utf-8"))
    mdoc["observed_model"] = "downgraded-mini"
    meta_m.write_text(json.dumps(mdoc), encoding="utf-8")
    assert gov.quorum_verify(ws, meeting_id="m-cov-m", require_multi_seat=True)["blocked"] is True

    for prof in ("agy-hydrogen", "claude-sub", "codex", "generic-ptr"):
        assert gov.build_runner_preset(prof, task_pointer="artifacts/p.md")["ok"]
    for bad_kw in ({"profile": "nope", "task_pointer": "p"}, {"profile": "codex", "task_pointer": " "}, {"profile": "codex", "task_pointer": "p", "model_override": "bad model!"}):
        try:
            gov.build_runner_preset(**bad_kw)
        except ValueError:
            pass

    # 4. Review gates, HMAC pseudonymization, plain-3line lint, doctor & archive
    gov.evaluate_review_gate(ws, level=0, content_tree_hash="abc12345")
    gov.evaluate_review_gate(ws, level=1, content_tree_hash="abc12345", requires_local_sampling=True, gpu_locked=True)
    gov.evaluate_review_gate(ws, level=1, content_tree_hash="abc12345", nits_only=True)
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", external_status="timeout")
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=1, blockers=["race"])
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=2, blockers=["race"])
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=3, blockers=[])
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=2, blockers=[], record_fix="Fixed")
    try:
        gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=0)
    except ValueError:
        pass
    probe_home = "/".join(["", "Users", "alice", "x"])
    probe_ip = ".".join(["192", "168", "1", "50"])
    probe_vol = "/".join(["", "Volumes", "Disk", "y"])
    _ = gov.pseudonymize_text(f"{probe_home} {probe_ip} {probe_vol}", "k1")
    _ = gov.lint_plain_summary("已完成修复")
    _ = gov.lint_plain_summary("已完成双向强绑定")

    settings_p = temp_root / "settings.json"
    settings_p.write_text(json.dumps({"additionalDirectories": []}), encoding="utf-8")
    gov.run_doctor(ws, settings_path=settings_p, transcript_steps=200)

    mini_repo = temp_root / "mini_repo"
    mini_repo.mkdir()
    (mini_repo / "hello.txt").write_text("hello diffquorum\n", encoding="utf-8")
    tgz_out = temp_root / "mini.tar.gz"
    ar_res = gov.run_archive(mini_repo, output=tgz_out, prefix="diffquorum-test", verify=True)
    assert ar_res["ok"] and tgz_out.is_file()
    ar_chk = gov.run_archive(mini_repo, prefix="diffquorum-test", verify_file=tgz_out)
    assert ar_chk["ok"]
    gov.run_sanitize_lint(mini_repo, extra_forbid=("forbiddenword",))

    # 5. Wake gates branches (including ANSI escapes, Unicode ellipsis, approval modals)
    base_snap = {
        "msg_id": "m1",
        "msg_text": "check",
        "msg_status": "PENDING",
        "msg_attempts": 0,
        "last_attempt_ts": 0.0,
        "pane_in_mode": 0,
        "pane_fg": "agy",
        "agy_in_tree": True,
        "client_activity_ts": 100.0,
        "capture_lines": ["\x1b[32m>\x1b[0m   Ask anything..."],
        "cursor_x": 3,
        "transcript_last_type": "PLANNER_RESPONSE",
        "transcript_last_status": "DONE",
        "transcript_has_tool_calls": False,
        "running_tasks": [{"description": "cron (ok)", "isDaemon": True}, {"description": "fg", "status": "completed"}],
        "recent_seat_wakes": [],
    }
    assert wg.evaluate_six_gates(base_snap, now_ts=1000.0)["wake"] is True
    for mut in (
        {"msg_text": "【TERMINAL-ACK】ok"},
        {"msg_status": "SEEN_AWAITING_HUMAN"},
        {"pane_in_mode": 1},
        {"pane_fg": "bash", "agy_in_tree": False},
        {"client_activity_ts": 995.0},
        {"capture_lines": ["Working…"]},
        {"capture_lines": ["Yes, I trust this folder", ">   Ask anything..."]},
        {"transcript_last_status": "RUNNING"},
        {"running_tasks": [{"description": "job", "status": "running", "isDaemon": False}]},
        {"recent_seat_wakes": [980.0, 990.0]},
        {"msg_attempts": 2},
        {"msg_attempts": 1, "last_attempt_ts": 990.0},
    ):
        snap = dict(base_snap, **mut)
        assert wg.evaluate_six_gates(snap, now_ts=1000.0)["wake"] is False
    assert wg.extract_user_request_text("<USER_REQUEST>Approve</USER_REQUEST><ADDITIONAL_METADATA>x</ADDITIONAL_METADATA>") == "Approve"
    assert wg.extract_user_request_text("Ok<USER_SETTINGS_CHANGE>k</USER_SETTINGS_CHANGE>") == "Ok"
    for bad_xml in ("<USER_REQUEST><USER_REQUEST>x</USER_REQUEST></USER_REQUEST>", "<USER_REQUEST>open", "</USER_REQUEST><USER_REQUEST>"):
        try:
            wg.extract_user_request_text(bad_xml)
        except ValueError:
            pass
    assert wg.evaluate_six_gates(
        dict(base_snap, running_tasks=[{"description": "1d 19h timer running", "status": "running", "isDaemon": False}, {"kind": "timer", "status": "running"}]),
        now_ts=1000.0,
    )["wake"] is True
    assert wg.evaluate_six_gates(
        dict(base_snap, transcript_last_text="请先审核上面的计划", transcript_mtime_ts=500.0, newest_ready_ticket_ts=400.0),
        now_ts=1000.0,
    )["wake"] is False
    assert wg.evaluate_six_gates(
        dict(base_snap, transcript_last_text="请先审核上面的计划", transcript_mtime_ts=500.0, newest_ready_ticket_ts=600.0),
        now_ts=1000.0,
    )["wake"] is True
    wstate: dict = {}
    wg.apply_wake_attempt(wstate, seat="lead", msg_id="m1", frame1_ok=True, frame2_ok=False, now_ts=1000.0)
    wg.apply_wake_attempt(wstate, seat="lead", msg_id="m1", frame1_ok=True, frame2_ok=True, now_ts=1040.0)

    # 5b. Wave B wake_gates & ops coverage (narrow footer, deep-thinking busy, dual-state, TTL, approval scoping, HUD, curate, routine, AST bundler)
    assert wg.is_idle_cli_footer("? for shortcuts") and wg.is_idle_cli_footer("auto · Gemini 4 ... · /tasks")
    assert not wg.is_idle_cli_footer("") and not wg.is_idle_cli_footer("esc to cancel")
    assert wg.is_pane_tail_busy("⡿ Thinking…") and not wg.is_pane_tail_busy("normal prose")
    for kw in (
        {"online": False},
        {"online": True, "is_daemon": True},
        {"online": True, "pane_busy": True, "copy_mode": True},
        {"online": True, "awaiting_approve": True, "copy_mode": True},
        {"online": True, "transcript_busy": True},
        {"online": True, "copy_mode": True},
        {"online": True},
    ):
        _ = wg.classify_seat_state(**kw)
    assert not wg.evaluate_six_gates(dict(base_snap, item_kind="msg", item_age_sec=9000.0), now_ts=1000.0)["wake"]
    assert wg.evaluate_six_gates(dict(base_snap, item_kind="ticket", item_age_sec=9000.0), now_ts=1000.0)["wake"]
    assert not wg.evaluate_six_gates(dict(base_snap, item_kind="ticket", item_age_sec=90000.0), now_ts=1000.0)["wake"]
    assert wg.is_explicit_approval_text("我都同意") and not wg.is_explicit_approval_text("我都同意？")
    assert not wg.is_explicit_approval_text("") and not wg.is_explicit_approval_text("approve。但是先别改")
    cov_seats = {"coord": ("coord", "00"), "builder": ("builder", "02"), "audit": ("audit", "99")}
    assert not wg.revocation_applies_to_scope("99 不用管了", from_seat="coord", to_seat="builder", known_seats=cov_seats)
    assert wg.revocation_applies_to_scope("99 和全部都不用管了", from_seat="coord", to_seat="builder", known_seats=cov_seats)
    assert wg.revocation_applies_to_scope("不用执行了", from_seat="coord", to_seat="builder", known_seats=cov_seats)
    assert not wg.revocation_applies_to_scope("一切正常", from_seat="coord", to_seat="builder", known_seats=cov_seats)

    cov_hud_snap = {
        "clock": "12:00:00",
        "local_hw": "memF:30% dsk:50G",
        "local_seats": [
            {"short": "00-lead", "state": "IDLE", "tkt": 0, "size": "50x40"},
            {"short": "01-work", "pane_busy": True, "copy_mode": True, "tkt": 1, "size": "80x55"},
            {"short": "02-wait", "awaiting_approve": True, "copy_mode": True, "wait_sec": 3700, "snippet": "A very long approval plan snippet to exercise CJK width truncation 很长的中文计划标题", "tkt": 2, "size": "80x55"},
            {"short": "03-run", "state": "WORKING", "tkt": 0, "size": "80x55"},
            {"short": "04-off", "online": False, "tkt": 0, "size": "-"},
        ],
        "remote": {
            "online": True, "rtt_ms": 15, "hw": "mem:40/96G",
            "seats": [
                {"short": "00-hub 总控", "awaiting_approve": True, "wait_sec": 45, "snippet": "Rem plan", "tkt": None, "size": "50x40"},
                {"short": "04-gw", "is_daemon": True, "tkt": None, "size": "120x40"},
            ],
        },
        "active_tasks": [
            {"status": "IN_PROGRESS", "seat": "01", "num": "#01", "updated_ts": 10, "title": "【Tag】Active task"},
            {"status": "PENDING", "seat": "02", "num": "#02", "updated_ts": 9, "title": "Pending task"},
        ],
    }
    _ = ops.render_dual_hud(cov_hud_snap, width=50, color=True)
    _ = ops.render_dual_hud({"local_seats": [], "remote": {"online": False, "error": "down"}}, width=50, color=False)
    _ = ops.render_dual_hud({"local_seats": [], "remote": {}}, width=50, color=False)

    cov_probe_out = temp_root / "cov_probe.json"
    _ = ops.scrub_probe_env({"PATH": "/usr/bin", "API_KEY": "secret", "XDG_CACHE_HOME": "/tmp"})
    ops.run_readonly_probe([sys.executable, "-c", "import sys; sys.exit(1)"], output_path=cov_probe_out, timeout_sec=1.0)
    ops.run_readonly_probe([sys.executable, "-c", "import time; time.sleep(2)"], output_path=cov_probe_out, timeout_sec=0.15)
    ops.run_readonly_probe([sys.executable, "-c", "print('[]')"], output_path=cov_probe_out, timeout_sec=1.0)
    ops.run_readonly_probe([sys.executable, "-c", 'print(\'{"host":"h1"}\')'], output_path=cov_probe_out, timeout_sec=1.0)

    cov_ledger = temp_root / "LEDGER.md"
    cov_ledger.write_text("# L\n\n<!-- PIN -->\nKeep\n<!-- /PIN -->\n\n" + "\n\n".join(f"## 2026-11-{d:02d} E{d}\n" + ("word " * 70) for d in range(15, 5, -1)), encoding="utf-8")
    ops.curate_ledger(cov_ledger, max_bytes=1200, keep_entries=3, dry_run=True)
    ops.curate_ledger(cov_ledger, max_bytes=1200, keep_entries=3, dry_run=False)
    ops.curate_ledger(cov_ledger, max_bytes=999999)
    cov_tl = temp_root / "TIMELINE.md"
    cov_tl.write_text("# Truth\n```markdown\n<!-- timeline -->\n```\n<!-- timeline -->\n\n" + "\n\n".join(f"## 2026-11-{d:02d} T{d}\n" + ("item " * 70) for d in range(15, 5, -1)), encoding="utf-8")
    ops.curate_ledger(cov_tl, max_bytes=1200, keep_entries=2, dry_run=False)

    cov_ast_repo = temp_root / "ast_repo"
    (cov_ast_repo / "pkg").mkdir(parents=True)
    (cov_ast_repo / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (cov_ast_repo / "pkg" / "b.py").write_text("X = 1\n", encoding="utf-8")
    (cov_ast_repo / "pkg" / "a.py").write_text("from . import b\nimport pkg.b\n", encoding="utf-8")
    ops.collect_ast_imports(["pkg/a.py"], repo_root=cov_ast_repo, max_depth=2)

    # 5b. Release preflight & objective blocker class convergence
    gov.evaluate_review_gate(
        ws,
        level=2,
        content_tree_hash="covhash01",
        round_num=1,
        blockers=["Style preference", "Missing PKG-INFO"],
        blocker_classes=["prose_style", "install_or_packaging"],
    )
    gov.run_release_preflight(REPO_ROOT)
    cov_rel_bad = temp_root / "rel_bad"
    (cov_rel_bad / "src" / "p").mkdir(parents=True)
    (cov_rel_bad / ".github" / "workflows").mkdir(parents=True)
    (cov_rel_bad / "tests").mkdir(parents=True)
    (cov_rel_bad / "samples").mkdir(parents=True)
    (cov_rel_bad / "pyproject.toml").write_text('version = "0.1.0"\n', encoding="utf-8")
    (cov_rel_bad / "CITATION.cff").write_text("version: 0.1.0\n", encoding="utf-8")
    (cov_rel_bad / "src" / "p" / "__init__.py").write_text('__version__ = "0.1.0"\n', encoding="utf-8")
    (cov_rel_bad / ".github" / "workflows" / "w.yml").write_text("run: x --version 0.1.0\n", encoding="utf-8")
    rev_tok = "ki" + "mi"
    (cov_rel_bad / "tests" / "test_x.py").write_text(
        f"# {rev_tok}\ndef test_{rev_tok}(self):\n    x = 'samples/a'\n    self.assertLess(dt.monotonic(), 0.2)\n    assert elapsed < 0.2\n",
        encoding="utf-8",
    )
    gov.run_release_preflight(cov_rel_bad, expected_version="0.2.0")
    import tarfile as _tf
    cov_sdist = temp_root / "bad.tar.gz"
    with _tf.open(cov_sdist, "w:gz") as _t:
        _b = b"Metadata-Version: 2.1\nName: UNKNOWN\nVersion: 0.1.0\n"
        _ti = _tf.TarInfo("p-0.2.0/PKG-INFO")
        _ti.size = len(_b)
        _t.addfile(_ti, io.BytesIO(_b))
    gov.run_release_preflight(cov_rel_bad, expected_version="0.2.0", sdist_tar=cov_sdist)

    # 6. Exercise CLI subcommands cleanly
    cli_ws = temp_root / "cli_ws"
    buf_out, buf_err = io.StringIO(), io.StringIO()
    sample_file = temp_root / "sample_trace.txt"
    sample_file.write_text("/".join(["", "Users", "bob", "app"]) + "\n", encoding="utf-8")
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        for cmd_argv in (
            ["init", "--root", str(cli_ws)],
            ["preflight", "--root", str(cli_ws), "--write-path", str(cli_ws), "--cli", "python3"],
            ["preset", "--profile", "agy-hydrogen", "--task-pointer", "artifacts/p.md"],
            ["board", "--root", str(cli_ws), "--set", "# CLI Board\n"],
            ["board", "--root", str(cli_ws), "--refresh"],
            ["board", "--root", str(cli_ws)],
            ["dispatch", "--root", str(cli_ws), "--from", "lead", "--to", "builder", "--summary", "task1", "--event-id", "evt-cli-1"],
            ["dispatch", "--print-ssh-cmd", "workstation:/opt/bin/diffquorum"],
            ["ack", "--root", str(cli_ws), "--seat", "builder", "--event-id", "evt-cli-1", "--reply-to", "lead"],
            ["lock", "--root", str(cli_ws), "--resource", "repo", "--seat", "lead", "--", sys.executable, "-c", "pass"],
            ["log-pitfall", "--root", str(cli_ws), "--title", "t1", "--root-cause", "rc1", "--guard", "g1"],
            ["log-fix", "--root", str(cli_ws), "--title", "f1", "--fix", "fx1", "--files", "cli.py"],
            ["doctor", "--root", str(cli_ws), "--settings-path", str(settings_p), "--transcript-steps", "100"],
            ["sanitize-lint", "--target", str(mini_repo)],
            ["quorum", "--root", str(cli_ws), "--topic", "Test topic"],
            ["quorum", "--topic", "Test topic", "--emit-workflow"],
            ["quorum-submit", "--root", str(cli_ws), "--meeting-id", "mc-1", "--author", "lead", "--source-kind", "local_seat", "--content", "A"],
            ["quorum-submit", "--root", str(cli_ws), "--meeting-id", "mc-1", "--author", "builder", "--source-kind", "subagent", "--content", "B"],
            ["quorum-blind", "--root", str(cli_ws), "--meeting-id", "mc-1", "--seed", "3"],
            ["quorum-verify", "--root", str(cli_ws), "--meeting-id", "mc-1"],
            ["model-probe", "--expected", "kimi-k3.1-pro", "--observed", "kimi-k3.1-pro"],
            ["model-probe", "--root", str(cli_ws), "--expected", "kimi-k3.1-pro", "--receipt", str(rec_cov)],
            ["review", "--root", str(cli_ws), "--level", "0", "--tree-hash", "deadbeef01"],
            ["review", "--tree-hash", "deadbeef01", "--lint-text", "已完成任务"],
            ["review", "--tree-hash", "deadbeef01", "--pseudonymize-file", str(sample_file)],
            ["wake-check", "--snapshot-json", json.dumps(base_snap)],
            ["hud", "--snapshot-json", json.dumps(cov_hud_snap), "--width", "50"],
            ["curate", str(cov_ledger), "--max-bytes", "999999"],
            ["routine", "--output", str(cov_probe_out), "--", sys.executable, "-c", 'print(\'{"host":"h1"}\')'],
            ["bundle-ast", "--repo-root", str(cov_ast_repo), "--entry", "pkg/a.py"],
            ["approve-check", "--text", "我都同意", "--later-text", "99 不用管了", "--from", "coord", "--to", "builder", "--seats-json", json.dumps(cov_seats)],
            ["release-preflight", "--repo-root", str(REPO_ROOT)],
            ["review", "--root", str(cli_ws), "--level", "2", "--tree-hash", "deadbeef02", "--blocker", "Tone nit", "--blocker-class", "style"],
            ["archive", "--repo-root", str(mini_repo), "--verify"],
            ["plan", "open", "--plans-file", str(temp_root / "cov_plans.json"), "--seat", "lead", "--scope", "router-v1", "--title", "Draft A"],
            ["plan", "open", "--plans-file", str(temp_root / "cov_plans.json"), "--seat", "lead", "--scope", "router-v1", "--title", "Draft A2"],
            ["plan", "open", "--plans-file", str(temp_root / "cov_plans.json"), "--seat", "worker", "--scope", "router-v1", "--title", "Competing"],
            ["plan", "list", "--plans-file", str(temp_root / "cov_plans.json"), "--scope", "router-v1"],
            ["plan", "close", "--plans-file", str(temp_root / "cov_plans.json"), "--seat", "lead", "--scope", "router-v1", "--status", "APPROVED", "--note", "ship"],
            ["plan", "list", "--plans-file", str(temp_root / "cov_plans.json"), "--all"],
            ["qa", "--records-json", json.dumps([{"seat": "lead", "user_inputs": ["[BUS-WAKE]", "Check deploy status"], "last_reply": "All green"}])],
            ["meetings", "list", "--ledger", str(temp_root / "cov_meetings.jsonl"), "--digest"],
            ["meetings", "record", "--ledger", str(temp_root / "cov_meetings.jsonl"), "--title", "Sync", "--topic", "Schema", "--participant", "lead", "--decision", "Go"],
            ["meetings", "list", "--ledger", str(temp_root / "cov_meetings.jsonl"), "--digest"],
        ):
            assert cli.main(cmd_argv) == 0, f"CLI failed on {cmd_argv}"
        assert cli.main(["dispatch", "--root", str(cli_ws)]) == 2

    # Exercise Wave C plan_lock, wake_gates, and ops edge branches
    p_cov = temp_root / "direct_plans.json"
    r_p1 = plk.open_pending_plan(p_cov, seat="worker", scope="db-mig", title="Step 1")
    assert r_p1["ok"] is True
    assert plk.supersede_plans_for_scope(p_cov, "db-mig", superseded_by="TKT-1") == [r_p1["plan"]["plan_id"]]
    for bad_call in (
        lambda: plk.normalize_plan_scope("!!!"),
        lambda: plk.open_pending_plan(p_cov, seat="", scope="x", title="y"),
        lambda: plk.list_pending_plans(p_cov, status="INVALID"),
        lambda: plk.close_pending_plan(p_cov, seat="lead", status="BAD"),
        lambda: plk.close_pending_plan(p_cov, seat="lead"),
        lambda: plk.close_pending_plan(p_cov, seat="lead", plan_id="PLN-MISSING"),
    ):
        try:
            bad_call()
        except (ValueError, KeyError):
            pass
    r_p2 = plk.open_pending_plan(p_cov, seat="worker", scope="auth-v2", title="Auth plan", owner_seat="lead")
    try:
        plk.close_pending_plan(p_cov, seat="stranger", plan_id=r_p2["plan"]["plan_id"])
    except PermissionError:
        pass

    assert wg.is_silent_sync_message("【TERMINAL-ACK】 done", priority="P2") is True
    assert wg.is_silent_sync_message("【TERMINAL-ACK】 urgent", priority="P0") is False
    assert wg.is_silent_sync_message("Please send 【TERMINAL-ACK】 when done", priority="P2") is False
    assert wg.is_report_no_reply_message("【交卷免回】 Task complete") is True
    assert wg.is_idle_cli_footer("⏵⏵ auto mode") is True
    assert wg.is_idle_cli_footer("? for short…") is True
    assert wg.is_explicit_approval_text("好嘞先睡了。approve") is True
    assert wg.is_explicit_approval_text("不通过") is False
    assert wg.is_explicit_approval_text("通过") is True
    assert wg.should_auto_exit_stale_copy_mode(pane_in_mode=True, min_client_idle_sec=200.0) is True
    assert wg.should_auto_exit_stale_copy_mode(pane_in_mode=True, min_client_idle_sec=200.0, protected_session=True) is False
    assert wg.compute_high_prio_ticket_backoff(0) == 0.0
    assert wg.compute_high_prio_ticket_backoff(2) == 60.0
    for r_str in ("copy_mode", "client_typing", "modal", "spinner", "footer", "awaiting_human_approve", "task_running", "transcript", "rate_limit", "other"):
        assert wg.classify_wake_block_code(r_str)
    assert wg.should_defer_low_priority_wake(human_reply_age_sec=60.0, priority="P2") is True
    assert wg.should_defer_low_priority_wake(human_reply_age_sec=60.0, priority="P1") is False
    recs = wg.collect_terminal_ticket_receipts(
        [{"ticket_id": "TKT-1", "status": "DONE", "from_seat": "lead", "updated_epoch": 500.0}],
        {},
        watermark_ts=100.0,
    )
    assert len(recs) == 1
    ok_c, _ = wg.verify_cached_host_approval(
        {"ok": True, "verified_epoch": 990.0, "conv_id": "c1", "step_index": 5, "content_sha256": "h1"},
        {"conv_id": "c1", "step_index": 5, "content_sha256": "h1"},
        now_ts=1000.0,
    )
    assert ok_c is True
    assert wg.verify_cached_host_approval(None, None, now_ts=1000.0)[0] is False
    assert wg.verify_cached_host_approval({"ok": True, "verified_epoch": 900.0}, {}, now_ts=1000.0)[0] is False

    latch1 = ops.evaluate_two_cap_alert_latch({}, ["seat-a"], hour_local=14)
    latch2 = ops.evaluate_two_cap_alert_latch(latch1["counts"], ["seat-a"], hour_local=15)
    latch3 = ops.evaluate_two_cap_alert_latch(latch2["counts"], ["seat-a"], hour_local=16)
    assert latch1["notify_keys"] == ["seat-a"] and latch3["notify_keys"] == []
    assert ops.evaluate_two_cap_alert_latch({}, ["seat-a"], hour_local=3)["in_quiet_hours"] is True

    # Exercise PreInvocation pending-plans banner, HUD bar, symmetric hook validator & headless review guard
    p_ban = temp_root / "banner_plans.json"
    p_mir = temp_root / "mirror_plans.json"
    assert plk.build_pre_invocation_pending_banner("builder", p_ban, mirror_path=p_mir) == ""
    assert plk.format_pending_plans_bar(p_ban, mirror_path=p_mir, width=60) == ""
    bp1 = plk.open_pending_plan(p_ban, seat="lead", scope="router-arch", title="Router Plan")
    bp2 = plk.open_pending_plan(p_ban, seat="builder", scope="ci-job", title="CI Job")
    bp3 = plk.open_pending_plan(p_ban, seat="vault", scope="sec-audit", title="PRIVATE_TITLE")
    p_mir.write_text('{"schema_version":"1.0","rev":1,"plans":[]}', encoding="utf-8")
    ban_txt = plk.build_pre_invocation_pending_banner("builder", p_ban, mirror_path=p_mir, redacted_seats={"vault"})
    assert "own:1 | peers:2 | total:3" in ban_txt and "PRIVATE_TITLE" not in ban_txt
    assert plk.format_pending_plans_bar(p_ban, mirror_path=p_mir, width=90, redacted_seats={"vault"}).startswith("[APR:3]")
    assert len(plk.format_pending_plans_bar(p_ban, mirror_path=p_mir, width=30, redacted_seats={"vault"})) <= 30
    for pid, owner in ((bp1["plan"]["plan_id"], "lead"), (bp2["plan"]["plan_id"], "builder"), (bp3["plan"]["plan_id"], "vault")):
        plk.close_pending_plan(p_ban, seat=owner, plan_id=pid, status="APPROVED")
    assert plk.build_pre_invocation_pending_banner("builder", p_ban) == ""
    sym_p = temp_root / "sym_plans.json"
    sym_p.symlink_to(p_ban)
    assert plk.build_pre_invocation_pending_banner("builder", sym_p) == ""
    big_p = temp_root / "big_plans.json"
    big_p.write_text('{"rev":9,"plans":[{"seat":"lead","status":"WAITING_APPROVE","title":"' + ("Z" * 17000) + '"}]}', encoding="utf-8")
    assert plk.build_pre_invocation_pending_banner("builder", big_p) == ""

    assert plk.validate_plan_hook_command("diffquorum plan list")["allowed"] is True
    assert plk.validate_plan_hook_command("python3 /usr/local/bin/star-bus.py plan open --seat s1 --scope x --title t")["allowed"] is True
    for bad_hk in (
        "",
        "diffquorum plan list; id",
        "diffquorum plan list --plans-file /tmp/a",
        "diffquorum plan open '--root' /tmp/a --seat s1 --scope x --title t",
        "/tmp/attacker/diffquorum plan list",
        "python3 star-bus.py plan list",
        "/tmp/attacker/python3 /usr/local/bin/star-bus.py plan list",
        "diffquorum plan 'bad",
        "diffquorum plan",
        "unknown plan list",
        "diffquorum inbox list",
        "diffquorum plan wipe",
    ):
        assert plk.validate_plan_hook_command(bad_hk)["allowed"] is False
    try:
        plk.open_pending_plan(sym_p, seat="lead", scope="sym-block", title="Denied")
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for symlinked plans_path")

    h_argv = gov.build_headless_review_argv("reviewer-cli", model="m1", prompt="Static diff check")
    assert gov.validate_headless_review_spec(argv=h_argv, prompt="Static diff check", timeout_sec=180)["ok"] is True
    assert gov.validate_headless_review_spec(argv=["reviewer-cli", "--no-tools"], prompt="Static diff check", timeout_sec=120)["ok"] is True
    assert gov.validate_headless_review_spec(argv=["reviewer-cli", "--tools", ""], prompt="Static diff check", timeout_sec=120)["ok"] is True
    assert gov.validate_headless_review_spec(argv=["reviewer-cli", "--tools="], prompt="Static diff check", timeout_sec=120)["ok"] is True
    assert gov.validate_headless_review_spec(argv=["reviewer-cli", "--disallowed-tools=Bash"], prompt="Static diff check", timeout_sec=120)["ok"] is True
    assert gov.validate_headless_review_spec(argv=["reviewer-cli"], prompt="", timeout_sec=0)["ok"] is False
    assert gov.validate_headless_review_spec(argv=["reviewer-cli"], prompt="web_search " + ("x" * 120), timeout_sec=400, max_prompt_chars=50)["ok"] is False
    for bad_argv_call in (
        lambda: gov.build_headless_review_argv("", model="m1", prompt="p"),
        lambda: gov.build_headless_review_argv("cli", model="m1", prompt="p", disallowed_tools=()),
    ):
        try:
            bad_argv_call()
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError from invalid build_headless_review_argv call")

    shutil.rmtree(ws, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="DiffQuorum >=90% Statement Coverage Gate")
    parser.add_argument("--min-coverage", type=float, default=90.0)
    args = parser.parse_args()

    exec_by_file = {p: collect_executable_lines(p) for p in TARGET_FILES}
    tracer = trace.Trace(count=True, trace=False)

    with tempfile.TemporaryDirectory(prefix="diffquorum_cov_") as tmp:
        tracer.runfunc(exercise_suite, pathlib.Path(tmp))

    results = tracer.results()
    hits_by_file: dict[pathlib.Path, set[int]] = {p: set() for p in TARGET_FILES}
    target_map = {str(p): p for p in TARGET_FILES}
    for (filename, lineno), count in results.counts.items():
        if count > 0:
            resolved = str(pathlib.Path(filename).resolve())
            if resolved in target_map:
                p = target_map[resolved]
                if lineno in exec_by_file[p]:
                    hits_by_file[p].add(lineno)

    total_exec = sum(len(v) for v in exec_by_file.values())
    total_hits = sum(len(v) for v in hits_by_file.values())
    pct = (total_hits / total_exec * 100.0) if total_exec else 100.0
    for p in TARGET_FILES:
        rel = p.relative_to(REPO_ROOT).as_posix()
        f_exec = len(exec_by_file[p])
        f_hit = len(hits_by_file[p])
        fpct = (f_hit / f_exec * 100.0) if f_exec else 100.0
        missed = sorted(exec_by_file[p] - hits_by_file[p])
        print(f"[INFO] [COVERAGE] {rel}: {f_hit}/{f_exec} ({fpct:.2f}%) | missed={missed[:15]}")

    print(
        f"[INFO] [COVERAGE] Total src/diffquorum statement coverage: {total_hits}/{total_exec} ({pct:.2f}%, threshold >= {args.min_coverage:.1f}%)"
    )
    if pct < args.min_coverage:
        print(f"[FAIL] [COVERAGE] Below {args.min_coverage:.1f}% threshold!", file=sys.stderr)
        return 1
    print(f"[PASS] [COVERAGE] Statement coverage gate satisfied ({pct:.2f}% >= {args.min_coverage:.1f}%).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
