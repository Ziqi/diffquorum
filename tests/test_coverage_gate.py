#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 StarCouncil Contributors
# SPDX-License-Identifier: MIT
"""
Zero-dependency executable statement coverage gate for StarCouncil
(satisfies OpenSSF Best Practices Silver `test_statement_coverage80`, targeting >=90%).

Measures Python stdlib `dis` + `trace` statement coverage across
`src/starcouncil/{blackboard,governance,wake_gates,cli}.py`.
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
    (SRC_DIR / "starcouncil" / "blackboard.py").resolve(),
    (SRC_DIR / "starcouncil" / "governance.py").resolve(),
    (SRC_DIR / "starcouncil" / "wake_gates.py").resolve(),
    (SRC_DIR / "starcouncil" / "cli.py").resolve(),
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

    import starcouncil.blackboard as bb
    import starcouncil.cli as cli
    import starcouncil.governance as gov
    import starcouncil.wake_gates as wg

    # 1. Init, TOML error branches, and board refresh / overflow branches
    try:
        bb.init_workspace(temp_root / "bad", topology="invalid")
    except ValueError:
        pass
    try:
        bb.init_workspace(temp_root / "bad", subscription="invalid")
    except ValueError:
        pass
    try:
        bb.init_workspace(temp_root / "bad", host_alias="bad host!")
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

    # Exercise TOML fallback parser explicitly
    parsed_toml = bb.parse_toml_text('# c\nflag = true\ncount = 3\n[s]\nk = "v"\n[[arr]]\nx = 1\n')
    assert parsed_toml["flag"] is True and parsed_toml["count"] == 3

    # 2. Dispatch, dedup, hop limit, ack silence, resonance circuit breaker & SSH bridge
    bb.dispatch_pointer(
        ws, from_seat="lead", to_seat="builder", summary="D" * 500, artifact_text="spec", event_id="evt-cov-1", now_ts=1000.0
    )
    bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="dup", event_id="evt-cov-1", now_ts=1005.0)
    bb.ack_pointer(ws, seat="builder", event_id="evt-cov-1", emit_reply_to="lead", priority="P1", now_ts=2000.0)
    try:
        bb.dispatch_pointer(ws, from_seat="builder", to_seat="lead", summary="echo", kind="ACK", event_id="evt-cov-ack2", now_ts=2010.0)
    except ValueError:
        pass
    try:
        bb.dispatch_pointer(ws, from_seat="bad seat!", to_seat="builder", summary="x", event_id="evt-x", now_ts=1000.0)
    except ValueError:
        pass
    try:
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="x", kind="NOPE", event_id="evt-x", now_ts=1000.0)
    except ValueError:
        pass
    try:
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="x", priority="P9", event_id="evt-x", now_ts=1000.0)
    except ValueError:
        pass
    try:
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="x", hop=2, event_id="evt-x", now_ts=1000.0)
    except ValueError:
        pass
    try:
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="x", event_id="bad!", now_ts=1000.0)
    except ValueError:
        pass

    for i in range(4):
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary=f"b{i}", event_id=f"evt-b-{i}", now_ts=9000.0 + i * 5)
    try:
        bb.dispatch_pointer(ws, from_seat="lead", to_seat="builder", summary="over", event_id="evt-b-over", now_ts=9030.0)
    except ValueError:
        pass

    _ = bb.build_ssh_peer_command("workstation", "/usr/local/bin/starcouncil")
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

    # 3. Council plan, submit, verify (solo, duplicate, multi-seat, tamper) & pitfalls/fixes
    gov.log_pitfall(ws, title="Cov pitfall", root_cause="edge race", guard="add lock")
    gov.log_fix(ws, title="Cov fix", fix_summary="locked", files="blackboard.py")
    gov.plan_council(ws, topic="优化 Skill 架构", tags_csv="", subscription="single-sub")
    gov.plan_council(ws, topic="Daily outreach", tags_csv="outreach", subscription="multi-sub")
    _ = gov.render_council_workflow("Check invariants", model_tier="pro")

    gov.council_submit(ws, meeting_id="m-cov", author="lead", source_kind="local_seat", content="Option A")
    assert gov.council_verify(ws, meeting_id="m-cov", require_multi_seat=True)["blocked"] is True
    gov.council_submit(ws, meeting_id="m-cov", author="builder", source_kind="subagent", content="Option B verified")
    assert gov.council_verify(ws, meeting_id="m-cov", require_multi_seat=True, resolution_summary="Agreed")["blocked"] is False

    tamper_md = ws / ".starcouncil" / "meetings" / "m-cov" / "submissions" / "lead__local_seat.md"
    tamper_md.write_text("tampered", encoding="utf-8")
    try:
        gov.council_verify(ws, meeting_id="m-cov", require_multi_seat=True)
    except ValueError:
        pass

    # 4. Review gates, HMAC pseudonymization, plain-3line lint, doctor & archive
    gov.evaluate_review_gate(ws, level=0, content_tree_hash="abc12345")
    gov.evaluate_review_gate(ws, level=1, content_tree_hash="abc12345", requires_local_sampling=True, gpu_locked=True)
    gov.evaluate_review_gate(ws, level=1, content_tree_hash="abc12345", nits_only=True)
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", external_status="timeout")
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=1, blockers=["race"])
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=2, blockers=["race"])
    gov.evaluate_review_gate(ws, level=2, content_tree_hash="abc12345", round_num=2, blockers=[], record_fix="Fixed")
    probe_home = "/".join(["", "Users", "alice", "x"])
    probe_ip = ".".join(["192", "168", "1", "50"])
    probe_vol = "/".join(["", "Volumes", "Disk", "y"])
    _ = gov.pseudonymize_text(f"{probe_home} {probe_ip} {probe_vol}", "k1")
    _ = gov.lint_plain_summary("已完成修复")
    _ = gov.lint_plain_summary("已完成双向强绑定")

    settings_p = temp_root / "settings.json"
    settings_p.write_text(json.dumps({"additionalDirectories": []}), encoding="utf-8")
    gov.run_doctor(ws, settings_path=settings_p, transcript_steps=200)

    # Archive copy & verify in isolated clean mini repo
    mini_repo = temp_root / "mini_repo"
    mini_repo.mkdir()
    (mini_repo / "hello.txt").write_text("hello starcouncil\n", encoding="utf-8")
    tgz_out = temp_root / "mini.tar.gz"
    ar_res = gov.run_archive(mini_repo, output=tgz_out, prefix="starcouncil-test", verify=True)
    assert ar_res["ok"] and tgz_out.is_file()
    ar_chk = gov.run_archive(mini_repo, prefix="starcouncil-test", verify_file=tgz_out)
    assert ar_chk["ok"]
    gov.run_sanitize_lint(mini_repo, extra_forbid=("forbiddenword",))

    # 5. Wake gates branches
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
        "capture_lines": [">   Ask anything..."],
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
        {"capture_lines": ["Working..."]},
        {"transcript_last_status": "RUNNING"},
        {"running_tasks": [{"description": "job", "status": "running", "isDaemon": False}]},
        {"recent_seat_wakes": [980.0, 990.0]},
        {"msg_attempts": 2},
        {"msg_attempts": 1, "last_attempt_ts": 990.0},
    ):
        snap = dict(base_snap, **mut)
        assert wg.evaluate_six_gates(snap, now_ts=1000.0)["wake"] is False
    wstate: dict = {}
    wg.apply_wake_attempt(wstate, seat="lead", msg_id="m1", frame1_ok=True, frame2_ok=False, now_ts=1000.0)
    wg.apply_wake_attempt(wstate, seat="lead", msg_id="m1", frame1_ok=True, frame2_ok=True, now_ts=1040.0)

    # 6. Exercise CLI subcommands cleanly
    cli_ws = temp_root / "cli_ws"
    buf_out, buf_err = io.StringIO(), io.StringIO()
    sample_file = temp_root / "sample_trace.txt"
    sample_file.write_text("/".join(["", "Users", "bob", "app"]) + "\n", encoding="utf-8")
    with redirect_stdout(buf_out), redirect_stderr(buf_err):
        for cmd_argv in (
            ["init", "--root", str(cli_ws)],
            ["board", "--root", str(cli_ws), "--set", "# CLI Board\n"],
            ["board", "--root", str(cli_ws), "--refresh"],
            ["board", "--root", str(cli_ws)],
            ["dispatch", "--root", str(cli_ws), "--from", "lead", "--to", "builder", "--summary", "task1", "--event-id", "evt-cli-1"],
            ["dispatch", "--print-ssh-cmd", "workstation:/opt/bin/starcouncil"],
            ["ack", "--root", str(cli_ws), "--seat", "builder", "--event-id", "evt-cli-1", "--reply-to", "lead"],
            ["lock", "--root", str(cli_ws), "--resource", "repo", "--seat", "lead", "--", sys.executable, "-c", "pass"],
            ["log-pitfall", "--root", str(cli_ws), "--title", "t1", "--root-cause", "rc1", "--guard", "g1"],
            ["log-fix", "--root", str(cli_ws), "--title", "f1", "--fix", "fx1", "--files", "cli.py"],
            ["doctor", "--root", str(cli_ws), "--settings-path", str(settings_p), "--transcript-steps", "100"],
            ["sanitize-lint", "--target", str(mini_repo)],
            ["council", "--root", str(cli_ws), "--topic", "Test topic"],
            ["council", "--topic", "Test topic", "--emit-workflow"],
            ["council-submit", "--root", str(cli_ws), "--meeting-id", "mc-1", "--author", "lead", "--source-kind", "local_seat", "--content", "A"],
            ["council-submit", "--root", str(cli_ws), "--meeting-id", "mc-1", "--author", "builder", "--source-kind", "subagent", "--content", "B"],
            ["council-verify", "--root", str(cli_ws), "--meeting-id", "mc-1"],
            ["review", "--root", str(cli_ws), "--level", "0", "--tree-hash", "deadbeef01"],
            ["review", "--tree-hash", "deadbeef01", "--lint-text", "已完成任务"],
            ["review", "--tree-hash", "deadbeef01", "--pseudonymize-file", str(sample_file)],
            ["wake-check", "--snapshot-json", json.dumps(base_snap)],
            ["archive", "--repo-root", str(mini_repo), "--verify"],
        ):
            assert cli.main(cmd_argv) == 0, f"CLI failed on {cmd_argv}"
        # Error path in CLI main()
        assert cli.main(["dispatch", "--root", str(cli_ws)]) == 2

    shutil.rmtree(ws, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="StarCouncil >=90% Statement Coverage Gate")
    parser.add_argument("--min-coverage", type=float, default=90.0)
    args = parser.parse_args()

    exec_by_file = {p: collect_executable_lines(p) for p in TARGET_FILES}
    tracer = trace.Trace(count=True, trace=False)

    with tempfile.TemporaryDirectory(prefix="starcouncil_cov_") as tmp:
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
        f"[INFO] [COVERAGE] Total src/starcouncil statement coverage: {total_hits}/{total_exec} ({pct:.2f}%, threshold >= {args.min_coverage:.1f}%)"
    )
    if pct < args.min_coverage:
        print(f"[FAIL] [COVERAGE] Below {args.min_coverage:.1f}% threshold!", file=sys.stderr)
        return 1
    print(f"[PASS] [COVERAGE] Statement coverage gate satisfied ({pct:.2f}% >= {args.min_coverage:.1f}%).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
