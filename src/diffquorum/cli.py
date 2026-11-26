#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 DiffQuorum Contributors
# SPDX-License-Identifier: MIT
"""Zero-dependency DiffQuorum microkernel CLI."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any

from . import __version__
from .blackboard import (
    MAX_STDIN_BYTES,
    ack_pointer,
    build_ssh_peer_command,
    dispatch_pointer,
    ingest_peer_stdin,
    init_workspace,
    read_board,
    refresh_board_locks,
    run_preflight,
    run_with_lock,
    update_board,
)
from .governance import (
    RUNNER_PRESETS,
    build_runner_preset,
    evaluate_review_gate,
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
    run_archive,
    run_doctor,
    run_release_preflight,
    run_sanitize_lint,
    verify_model_identity,
)
from .ops import collect_ast_imports, curate_ledger, list_meetings, record_meeting, render_dual_hud, run_readonly_probe, summarize_qa_directory
from .plan_lock import close_pending_plan, list_pending_plans, open_pending_plan, reopen_pending_plan
from .policy import (
    _read_json_nofollow_bounded,
    audit_master_dictionary_drift,
    evaluate_blast_radius_route,
    evaluate_discussion_plan,
    validate_mm_autopsy_packet,
)
from .wake_gates import evaluate_six_gates, is_explicit_approval_text, revocation_applies_to_scope


def _out(obj: Any) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="diffquorum",
        description=f"DiffQuorum v{__version__} — 零依赖多智能体指针协调、匿名防假会、六门禁唤醒与预检工具",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # 1. init
    p_init = sub.add_parser("init", help="初始化 .diffquorum/ 五类活档案工作区", allow_abbrev=False)
    p_init.add_argument("--root", default=".")
    p_init.add_argument("--topology", choices=("local-tmux", "ssh-federated"), default="local-tmux")
    p_init.add_argument("--subscription", choices=("single-sub", "multi-sub"), default="single-sub")
    p_init.add_argument("--host-alias", default="workstation")
    p_init.add_argument("--remote-bin", default="diffquorum")
    p_init.add_argument("--force", action="store_true")

    # 2. board
    p_board = sub.add_parser("board", help="读取、更新或刷新锁状态到 BOARD.md (<3KB 硬限)", allow_abbrev=False)
    p_board.add_argument("--root", default=".")
    p_board.add_argument("--set", dest="set_text", default="")
    p_board.add_argument("--refresh", action="store_true")

    # 3. dispatch / post
    for name in ("dispatch", "post"):
        p_dp = sub.add_parser(name, help="写入 <400B 指针信封或从 stdin 接收跨机入站信封", allow_abbrev=False)
        p_dp.add_argument("--root", default=".")
        p_dp.add_argument("--ingest-stdin", action="store_true")
        p_dp.add_argument("--from", dest="from_seat", default="lead")
        p_dp.add_argument("--to", dest="to_seat", default="builder")
        p_dp.add_argument("--summary", default="")
        p_dp.add_argument("--artifact", default="")
        p_dp.add_argument("--kind", default="TASK_DISPATCH")
        p_dp.add_argument("--priority", default="P1")
        p_dp.add_argument("--hop", type=int, default=0)
        p_dp.add_argument("--event-id", default="")
        p_dp.add_argument("--in-reply-to", default="")
        p_dp.add_argument("--strict-envelope", action="store_true")
        p_dp.add_argument("--print-ssh-cmd", default="")

    # 4. ack
    p_ack = sub.add_parser("ack", help="核销指针事件并遵循 60s 对称静默窗", allow_abbrev=False)
    p_ack.add_argument("--root", default=".")
    p_ack.add_argument("--seat", required=True)
    p_ack.add_argument("--event-id", required=True)
    p_ack.add_argument("--note", default="ACK")
    p_ack.add_argument("--priority", default="P1")
    p_ack.add_argument("--reply-to", default="")

    # 5. lock
    p_lk = sub.add_parser("lock", help="持 flock 独占锁运行外部命令 (零 shell=True)", allow_abbrev=False)
    p_lk.add_argument("--root", default=".")
    p_lk.add_argument("--resource", required=True)
    p_lk.add_argument("--seat", required=True)
    p_lk.add_argument("cmd_args", nargs=argparse.REMAINDER)

    # 6. preflight (<1s zero-token environment check)
    p_pf = sub.add_parser("preflight", help="派活前 <1s 零消耗预检：目录可写性、资源锁与 CLI 可用性", allow_abbrev=False)
    p_pf.add_argument("--root", default=".")
    p_pf.add_argument("--write-path", action="append", default=[])
    p_pf.add_argument("--resource", default="")
    p_pf.add_argument("--cli", action="append", default=[])
    p_pf.add_argument("--agy-state-dir", default="")

    # 7. preset (optional vendor-neutral & Hydrogen runner preset helper)
    p_pr = sub.add_parser("preset", help="可选无头执行器命令模板生成器 (含可选 agy-hydrogen 预设)", allow_abbrev=False)
    p_pr.add_argument("--profile", choices=tuple(RUNNER_PRESETS.keys()), default="generic-ptr")
    p_pr.add_argument("--task-pointer", required=True)
    p_pr.add_argument("--model", default="")

    # 8. log-pitfall & log-fix
    p_lp = sub.add_parser("log-pitfall", help="记录踩坑根因到 pitfalls.md 并写入事件流水", allow_abbrev=False)
    p_lp.add_argument("--root", default=".")
    p_lp.add_argument("--title", required=True)
    p_lp.add_argument("--root-cause", required=True)
    p_lp.add_argument("--guard", default="")
    p_lp.add_argument("--actor", default="cli")

    p_lf = sub.add_parser("log-fix", help="记录根因修复到 fixes_log.md 并写入事件流水", allow_abbrev=False)
    p_lf.add_argument("--root", default=".")
    p_lf.add_argument("--title", required=True)
    p_lf.add_argument("--fix", required=True)
    p_lf.add_argument("--files", default="")
    p_lf.add_argument("--actor", default="cli")

    # 9. doctor & sanitize-lint
    p_doc = sub.add_parser("doctor", help="校验五类活档案、指针上限、单订阅锁与 settings.json 纯净度", allow_abbrev=False)
    p_doc.add_argument("--root", default=".")
    p_doc.add_argument("--settings-path", default="")
    p_doc.add_argument("--transcript-steps", type=int, default=None)

    p_san = sub.add_parser("sanitize-lint", help="扫描私密路径、内网/Tailscale IP、真实 UUID 与禁用词", allow_abbrev=False)
    p_san.add_argument("--target", default=".")
    p_san.add_argument("--forbid", default="")

    # 10. quorum / council planning, submission, anonymization, and verification
    for name in ("quorum", "council"):
        p_cn = sub.add_parser(name, help="按话题标签摇人规划或输出单轮并行工作流", allow_abbrev=False)
        p_cn.add_argument("--root", default=".")
        p_cn.add_argument("--topic", required=True)
        p_cn.add_argument("--tags", default="")
        p_cn.add_argument("--subscription", choices=("", "single-sub", "multi-sub"), default="")
        p_cn.add_argument("--emit-workflow", action="store_true")
        p_cn.add_argument("--model", default="pro")

    for name in ("quorum-submit", "council-submit"):
        p_cs = sub.add_parser(name, help="保存参会席位独立原始发言、可选 diff 哈希与 SHA-256 指纹", allow_abbrev=False)
        p_cs.add_argument("--root", default=".")
        p_cs.add_argument("--meeting-id", required=True)
        p_cs.add_argument("--author", required=True)
        p_cs.add_argument("--source-kind", required=True, choices=("local_seat", "remote_node", "external_llm", "subagent"))
        p_cs.add_argument("--diff-sha256", default="")
        p_cs.add_argument("--expected-model", default="")
        p_cs.add_argument("--observed-model", default="")
        p_cs.add_argument("--content", default="")
        p_cs.add_argument("--file", default="")

    for name in ("quorum-verify", "council-verify"):
        p_cv = sub.add_parser(name, help="防假会哈希校验：>=2 个独立来源才准出具 MULTI_SEAT_DECISION", allow_abbrev=False)
        p_cv.add_argument("--root", default=".")
        p_cv.add_argument("--meeting-id", required=True)
        p_cv.add_argument("--allow-solo", action="store_true")
        p_cv.add_argument("--require-model-match", action="store_true")
        p_cv.add_argument("--resolution", default="")

    p_mp = sub.add_parser("model-probe", help="Fail-Closed 模型身份与静默降级探针（核验 expected == observed）", allow_abbrev=False)
    p_mp.add_argument("--root", default="")
    p_mp.add_argument("--expected", required=True)
    p_mp.add_argument("--observed", default="")
    p_mp.add_argument("--receipt", default="")
    p_mp.add_argument("--actor", default="model-probe")

    p_qb = sub.add_parser("quorum-blind", help="导出 Peer A/B/C 匿名盲审数据包并生成解盲映射", allow_abbrev=False)
    p_qb.add_argument("--root", default=".")
    p_qb.add_argument("--meeting-id", required=True)
    p_qb.add_argument("--seed", type=int, default=0)

    # 11. review, wake-check, archive
    p_rv = sub.add_parser("review", help="0/1/2 级轻量审稿、两轮安灯拉闸与 Fail-Closed 门禁", allow_abbrev=False)
    p_rv.add_argument("--root", default=".")
    p_rv.add_argument("--level", type=int, choices=(0, 1, 2), default=0)
    p_rv.add_argument("--tree-hash", required=True)
    p_rv.add_argument("--rule-version", default="1")
    p_rv.add_argument("--round", dest="round_num", type=int, default=1)
    p_rv.add_argument("--blocker", action="append", default=[])
    p_rv.add_argument("--blocker-class", dest="blocker_class", action="append", default=[])
    p_rv.add_argument("--nits-only", action="store_true")
    p_rv.add_argument("--external-status", default="ok")
    p_rv.add_argument("--requires-local-sampling", action="store_true")
    p_rv.add_argument("--gpu-locked", action="store_true")
    p_rv.add_argument("--record-fix", default="")
    p_rv.add_argument("--pseudonymize-file", default="")
    p_rv.add_argument("--hmac-key", default="session-ephemeral-key")
    p_rv.add_argument("--lint-text", default="")

    p_wk = sub.add_parser("wake-check", help="从 stdin JSON 校验 [BUS-WAKE] 六道空闲门禁", allow_abbrev=False)
    p_wk.add_argument("--snapshot-json", default="")

    p_ar = sub.add_parser("archive", help="构建或校验位级可重现的源码发行包 (.tar.gz)", allow_abbrev=False)
    p_ar.add_argument("--repo-root", default=".")
    p_ar.add_argument("--output", default="")
    p_ar.add_argument("--prefix", default="diffquorum")
    p_ar.add_argument("--verify", action="store_true")
    p_ar.add_argument("--verify-file", default="")

    # 12. Wave B 0-Token operational primitives: hud, curate, routine, bundle-ast, approve-check
    p_hud = sub.add_parser("hud", help="渲染纯只读 50 列窄屏双机统一战情看板", allow_abbrev=False)
    p_hud.add_argument("--snapshot-json", default="")
    p_hud.add_argument("--width", type=int, default=50)
    p_hud.add_argument("--color", action="store_true")

    p_cur = sub.add_parser("curate", help="零删除整文件 SHA-256 快照长账本折叠器", allow_abbrev=False)
    p_cur.add_argument("ledger")
    p_cur.add_argument("--max-bytes", type=int, default=15360)
    p_cur.add_argument("--keep-entries", type=int, default=5)
    p_cur.add_argument("--dry-run", action="store_true")

    p_rtn = sub.add_parser("routine", help="剥离密钥的单向只读定时探针 (0-Token)", allow_abbrev=False)
    p_rtn.add_argument("--output", required=True)
    p_rtn.add_argument("--host-label", default="remote")
    p_rtn.add_argument("--timeout", type=float, default=8.0)
    p_rtn.add_argument("cmd_args", nargs=argparse.REMAINDER)

    p_ast = sub.add_parser("bundle-ast", help="基于 Python AST 静态追踪本地依赖生成盲审文件清单", allow_abbrev=False)
    p_ast.add_argument("--repo-root", default=".")
    p_ast.add_argument("--entry", action="append", required=True)
    p_ast.add_argument("--max-depth", type=int, default=2)
    p_ast.add_argument("--max-files", type=int, default=32)

    p_app = sub.add_parser("approve-check", help="Fail-Closed 审批短语与跨席撤回作用域核验", allow_abbrev=False)
    p_app.add_argument("--text", required=True)
    p_app.add_argument("--later-text", default="")
    p_app.add_argument("--from", dest="from_seat", default="coord")
    p_app.add_argument("--to", dest="to_seat", default="worker")
    p_app.add_argument("--seats-json", default="")

    p_rpf = sub.add_parser("release-preflight", help="发版前 0-Token 跨文件版本号、sdist PKG-INFO 与单测卫生检查", allow_abbrev=False)
    p_rpf.add_argument("--repo-root", default=".")
    p_rpf.add_argument("--expected-version", default="")
    p_rpf.add_argument("--sdist-tar", default="")

    # 13. Wave C: Single-approval pending-plan collision lock (`plan`), read-only `qa`, and `meetings` ledger
    p_pln = sub.add_parser("plan", help="0-Token 待批方案撞车锁 (open | list | close)", allow_abbrev=False)
    pln_sub = p_pln.add_subparsers(dest="plan_action", required=True)

    p_pln_open = pln_sub.add_parser("open", help="登记待批/待决方案并在同 scope 已存在他席草稿时返回 collision:true", allow_abbrev=False)
    p_pln_open.add_argument("--plans-file", required=True)
    p_pln_open.add_argument("--seat", required=True)
    p_pln_open.add_argument("--scope", required=True)
    p_pln_open.add_argument("--title", required=True)
    p_pln_open.add_argument("--kind", default="PLAN", choices=("PLAN", "DECISION", "CIRCUIT_BREAKER", "INPUT_REQUIRED"))
    p_pln_open.add_argument("--owner-seat", default="lead")

    p_pln_list = pln_sub.add_parser("list", help="查询当前 WAITING_APPROVE 待批/待决清单", allow_abbrev=False)
    p_pln_list.add_argument("--plans-file", required=True)
    p_pln_list.add_argument("--scope", default="")
    p_pln_list.add_argument("--seat", default="")
    p_pln_list.add_argument("--status", default="")
    p_pln_list.add_argument("--kind", default="")
    p_pln_list.add_argument("--all", action="store_true")

    p_pln_reopen = pln_sub.add_parser("reopen", help="中途遇熔断或路径二选一时原位重开已关单为 WAITING_APPROVE", allow_abbrev=False)
    p_pln_reopen.add_argument("--plans-file", required=True)
    p_pln_reopen.add_argument("--seat", required=True)
    p_pln_reopen.add_argument("--plan-id", default="")
    p_pln_reopen.add_argument("--scope", default="")
    p_pln_reopen.add_argument("--kind", default="", choices=("", "PLAN", "DECISION", "CIRCUIT_BREAKER", "INPUT_REQUIRED"))
    p_pln_reopen.add_argument("--title", default="")
    p_pln_reopen.add_argument("--note", default="")

    p_pln_close = pln_sub.add_parser("close", help="关闭待批方案 (APPROVED | SUPERSEDED | CANCELLED)", allow_abbrev=False)
    p_pln_close.add_argument("--plans-file", required=True)
    p_pln_close.add_argument("--seat", required=True)
    p_pln_close.add_argument("--plan-id", default="")
    p_pln_close.add_argument("--scope", default="")
    p_pln_close.add_argument("--status", default="APPROVED", choices=("APPROVED", "SUPERSEDED", "CANCELLED"))
    p_pln_close.add_argument("--note", default="")

    p_qa = sub.add_parser("qa", help="纯只读席位最近一问一答目录摘要 (过滤 BUS-WAKE 与自检杂讯)", allow_abbrev=False)
    p_qa.add_argument("--records-json", required=True)
    p_qa.add_argument("--max-chars", type=int, default=80)

    p_mtg = sub.add_parser("meetings", help="0600 权限跨席会议结论 JSONL 台账 (record | list)", allow_abbrev=False)
    mtg_sub = p_mtg.add_subparsers(dest="mtg_action", required=True)

    p_mtg_rec = mtg_sub.add_parser("record", help="追加记录一次会议结论", allow_abbrev=False)
    p_mtg_rec.add_argument("--ledger", required=True)
    p_mtg_rec.add_argument("--title", required=True)
    p_mtg_rec.add_argument("--topic", required=True)
    p_mtg_rec.add_argument("--participant", action="append", default=[])
    p_mtg_rec.add_argument("--decision", default="")
    p_mtg_rec.add_argument("--status", default="CLOSED")

    p_mtg_ls = mtg_sub.add_parser("list", help="查询最近会议记录或输出单行摘要", allow_abbrev=False)
    p_mtg_ls.add_argument("--ledger", required=True)
    p_mtg_ls.add_argument("--limit", type=int, default=20)
    p_mtg_ls.add_argument("--digest", action="store_true")

    # 14. Governance Policy Suite (D0-D2 discussion cap, R0-R3 blast-radius routing, Fold-A/B M&M autopsy, Master Dict drift)
    p_disc = sub.add_parser("discuss-check", help="校验前门探讨 D0-D2 单轮封顶、靶子底稿与异构专长派工", allow_abbrev=False)
    p_disc.add_argument("--tier", required=True, choices=("D0", "D1", "D2"))
    p_disc.add_argument("--rounds", type=int, default=0)
    p_disc.add_argument("--author-family", required=True)
    p_disc.add_argument("--advisor-model", action="append", default=[])
    p_disc.add_argument("--advisor-family", action="append", default=[])
    p_disc.add_argument("--has-strawman", action="store_true")
    p_disc.add_argument("--tie-breaker-conflict", action="store_true")
    p_disc.add_argument("--specialty-domain", default="")

    p_risk = sub.add_parser("route-risk", help="按爆炸半径校验 R0-R3 四档审查路由 (含 R1 纯文案快检直通车)", allow_abbrev=False)
    p_risk.add_argument("--offline-or-readonly", action="store_true")
    p_risk.add_argument("--pure-copy-candidate", action="store_true")
    p_risk.add_argument("--r1-invariants-json", default="")
    p_risk.add_argument("--critical-domain", action="append", default=[])
    p_risk.add_argument("--claimed-tier", default="")
    p_risk.add_argument("--author-family", default="")
    p_risk.add_argument("--reviewer-family", action="append", default=[])
    p_risk.add_argument("--has-written-spec", action="store_true")
    p_risk.add_argument("--independent-verification-passed", action="store_true")
    p_risk.add_argument("--review-round", type=int, default=1)

    p_mm = sub.add_parser("mm-verify", help="校验负结果实验 Fold-A/Fold-B 隔离双盲 M&M 尸检数据包", allow_abbrev=False)
    p_mm.add_argument("--packet", required=True)

    p_dict = sub.add_parser("dict-check", help="基于机器可读 Master Dict 主词典执行跨仓口径漂移与禁词扫描", allow_abbrev=False)
    p_dict.add_argument("--dict", dest="dict_path", required=True)
    p_dict.add_argument("--target", required=True)
    p_dict.add_argument("--exclude", action="append", default=[])

    args = parser.parse_args(argv)
    try:
        if args.cmd == "init":
            _out(
                init_workspace(
                    pathlib.Path(args.root).resolve(),
                    topology=args.topology,
                    subscription=args.subscription,
                    host_alias=args.host_alias,
                    remote_bin=args.remote_bin,
                    force=args.force,
                )
            )
            return 0

        if args.cmd == "board":
            root = pathlib.Path(args.root).resolve()
            if args.refresh:
                _out(refresh_board_locks(root))
            elif args.set_text:
                _out(update_board(root, args.set_text))
            else:
                sys.stdout.write(read_board(root))
            return 0

        if args.cmd in ("dispatch", "post"):
            root = pathlib.Path(args.root).resolve()
            if args.print_ssh_cmd:
                host, _, rbin = args.print_ssh_cmd.partition(":")
                _out({"argv": build_ssh_peer_command(host, rbin or "diffquorum")})
                return 0
            if args.ingest_stdin:
                raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
                _out(ingest_peer_stdin(root, raw))
                return 0
            if not args.summary.strip():
                raise ValueError("--summary is required unless --ingest-stdin or --print-ssh-cmd is used")
            _out(
                dispatch_pointer(
                    root,
                    from_seat=args.from_seat,
                    to_seat=args.to_seat,
                    summary=args.summary,
                    artifact_text=args.artifact,
                    kind=args.kind,
                    priority=args.priority,
                    hop=args.hop,
                    event_id=args.event_id,
                    in_reply_to=args.in_reply_to,
                    strict_envelope=args.strict_envelope,
                )
            )
            return 0

        if args.cmd == "ack":
            _out(
                ack_pointer(
                    pathlib.Path(args.root).resolve(),
                    seat=args.seat,
                    event_id=args.event_id,
                    note=args.note,
                    priority=args.priority,
                    emit_reply_to=args.reply_to,
                )
            )
            return 0

        if args.cmd == "lock":
            cmd_argv = list(args.cmd_args)
            if cmd_argv and cmd_argv[0] == "--":
                cmd_argv = cmd_argv[1:]
            return run_with_lock(pathlib.Path(args.root).resolve(), args.resource, args.seat, cmd_argv)

        if args.cmd == "preflight":
            agy_dir = pathlib.Path(args.agy_state_dir).expanduser().resolve() if args.agy_state_dir else None
            rep = run_preflight(
                pathlib.Path(args.root).resolve(),
                write_paths=args.write_path,
                resource=args.resource,
                cli_tools=args.cli,
                agy_state_dir=agy_dir,
            )
            _out(rep)
            return 0 if rep["ok"] else 2

        if args.cmd == "preset":
            _out(build_runner_preset(args.profile, task_pointer=args.task_pointer, model_override=args.model))
            return 0

        if args.cmd == "log-pitfall":
            _out(
                log_pitfall(
                    pathlib.Path(args.root).resolve(),
                    title=args.title,
                    root_cause=args.root_cause,
                    guard=args.guard,
                    actor=args.actor,
                )
            )
            return 0

        if args.cmd == "log-fix":
            _out(
                log_fix(
                    pathlib.Path(args.root).resolve(),
                    title=args.title,
                    fix_summary=args.fix,
                    files=args.files,
                    actor=args.actor,
                )
            )
            return 0

        if args.cmd == "doctor":
            sp = pathlib.Path(args.settings_path).expanduser().resolve() if args.settings_path else None
            rep = run_doctor(pathlib.Path(args.root).resolve(), settings_path=sp, transcript_steps=args.transcript_steps)
            _out(rep)
            return 0 if rep["ok"] else 1

        if args.cmd == "sanitize-lint":
            forbid = tuple(w.strip() for w in args.forbid.split(",") if w.strip())
            rep = run_sanitize_lint(pathlib.Path(args.target).resolve(), extra_forbid=forbid)
            _out(rep)
            return 0 if rep["ok"] else 1

        if args.cmd in ("quorum", "council"):
            if args.emit_workflow:
                sys.stdout.write(render_council_workflow(args.topic, model_tier=args.model))
                return 0
            _out(
                plan_council(
                    pathlib.Path(args.root).resolve(),
                    topic=args.topic,
                    tags_csv=args.tags,
                    subscription=args.subscription,
                )
            )
            return 0

        if args.cmd in ("quorum-submit", "council-submit"):
            body = args.content or (pathlib.Path(args.file).read_text(encoding="utf-8") if args.file else "")
            _out(
                quorum_submit(
                    pathlib.Path(args.root).resolve(),
                    meeting_id=args.meeting_id,
                    author=args.author,
                    source_kind=args.source_kind,
                    content=body,
                    diff_sha256=args.diff_sha256,
                    expected_model=args.expected_model,
                    observed_model=args.observed_model,
                )
            )
            return 0

        if args.cmd in ("quorum-verify", "council-verify"):
            rep = quorum_verify(
                pathlib.Path(args.root).resolve(),
                meeting_id=args.meeting_id,
                require_multi_seat=not args.allow_solo,
                require_model_match=args.require_model_match,
                resolution_summary=args.resolution,
            )
            _out(rep)
            return 2 if rep.get("blocked") else 0

        if args.cmd == "model-probe":
            root_opt = pathlib.Path(args.root).resolve() if args.root else None
            if args.receipt:
                rep = probe_model_receipt(
                    pathlib.Path(args.receipt).resolve(),
                    expected_model=args.expected,
                    root=root_opt,
                    actor=args.actor,
                )
            else:
                rep = verify_model_identity(
                    args.expected,
                    args.observed,
                    root=root_opt,
                    actor=args.actor,
                )
            _out(rep)
            return 2 if rep.get("blocked") else 0

        if args.cmd == "quorum-blind":
            _out(
                quorum_render_blind_packet(
                    pathlib.Path(args.root).resolve(),
                    meeting_id=args.meeting_id,
                    seed=args.seed,
                )
            )
            return 0

        if args.cmd == "review":
            if args.lint_text:
                rep = lint_plain_summary(args.lint_text)
                _out(rep)
                return 0 if rep["ok"] else 1
            if args.pseudonymize_file:
                raw_txt = pathlib.Path(args.pseudonymize_file).read_text(encoding="utf-8")
                sys.stdout.write(pseudonymize_text(raw_txt, args.hmac_key))
                return 0
            rep = evaluate_review_gate(
                pathlib.Path(args.root).resolve(),
                level=args.level,
                content_tree_hash=args.tree_hash,
                rule_version=args.rule_version,
                round_num=args.round_num,
                blockers=args.blocker,
                blocker_classes=args.blocker_class if args.blocker_class else None,
                nits_only=args.nits_only,
                external_status=args.external_status,
                requires_local_sampling=args.requires_local_sampling,
                gpu_locked=args.gpu_locked,
                record_fix=args.record_fix,
            )
            _out(rep)
            return 2 if rep.get("blocked") else 0

        if args.cmd == "wake-check":
            snap_raw = args.snapshot_json or sys.stdin.read()
            snap = json.loads(snap_raw)
            _out(evaluate_six_gates(snap))
            return 0

        if args.cmd == "archive":
            _out(
                run_archive(
                    pathlib.Path(args.repo_root).resolve(),
                    output=pathlib.Path(args.output) if args.output else None,
                    prefix=args.prefix,
                    verify=args.verify,
                    verify_file=pathlib.Path(args.verify_file) if args.verify_file else None,
                )
            )
            return 0

        if args.cmd == "hud":
            snap_raw = args.snapshot_json or sys.stdin.read()
            snap = json.loads(snap_raw)
            sys.stdout.write(render_dual_hud(snap, width=args.width, color=args.color))
            return 0

        if args.cmd == "curate":
            _out(
                curate_ledger(
                    args.ledger,
                    max_bytes=args.max_bytes,
                    keep_entries=args.keep_entries,
                    dry_run=args.dry_run,
                )
            )
            return 0

        if args.cmd == "routine":
            cmd_argv = list(args.cmd_args)
            if cmd_argv and cmd_argv[0] == "--":
                cmd_argv = cmd_argv[1:]
            res = run_readonly_probe(
                cmd_argv,
                output_path=pathlib.Path(args.output),
                timeout_sec=args.timeout,
                host_label=args.host_label,
            )
            _out(res)
            return 0 if res.get("online") else 1

        if args.cmd == "bundle-ast":
            _out(
                collect_ast_imports(
                    args.entry,
                    repo_root=args.repo_root,
                    max_depth=args.max_depth,
                    max_files=args.max_files,
                )
            )
            return 0

        if args.cmd == "approve-check":
            approved = is_explicit_approval_text(args.text)
            revoked = False
            if args.later_text:
                raw_seats = json.loads(args.seats_json) if args.seats_json else {}
                known = {str(k): tuple(str(x) for x in v) for k, v in raw_seats.items()}
                revoked = revocation_applies_to_scope(
                    args.later_text,
                    from_seat=args.from_seat,
                    to_seat=args.to_seat,
                    known_seats=known,
                )
            ok = approved and not revoked
            _out({"ok": ok, "approved": approved, "revoked": revoked})
            return 0 if ok else 2

        if args.cmd == "release-preflight":
            s_tar = pathlib.Path(args.sdist_tar).resolve() if args.sdist_tar else None
            rep = run_release_preflight(
                pathlib.Path(args.repo_root).resolve(),
                expected_version=args.expected_version,
                sdist_tar=s_tar,
            )
            _out(rep)
            return 0 if rep["ok"] else 2

        if args.cmd == "plan":
            if args.plan_action == "open":
                _out(
                    open_pending_plan(
                        args.plans_file,
                        seat=args.seat,
                        scope=args.scope,
                        title=args.title,
                        owner_seat=args.owner_seat,
                        kind=args.kind,
                    )
                )
                return 0
            if args.plan_action == "list":
                _out(
                    list_pending_plans(
                        args.plans_file,
                        scope=args.scope,
                        seat=args.seat,
                        status=args.status,
                        kind=args.kind,
                        include_all=args.all,
                    )
                )
                return 0
            if args.plan_action == "reopen":
                _out(
                    reopen_pending_plan(
                        args.plans_file,
                        seat=args.seat,
                        plan_id=args.plan_id,
                        scope=args.scope,
                        kind=args.kind,
                        title=args.title,
                        note=args.note,
                    )
                )
                return 0
            if args.plan_action == "close":
                _out(
                    close_pending_plan(
                        args.plans_file,
                        seat=args.seat,
                        plan_id=args.plan_id,
                        scope=args.scope,
                        status=args.status,
                        note=args.note,
                    )
                )
                return 0

        if args.cmd == "qa":
            rows = json.loads(args.records_json)
            _out({"ok": True, "directory": summarize_qa_directory(rows, max_chars=args.max_chars)})
            return 0

        if args.cmd == "meetings":
            if args.mtg_action == "record":
                _out(
                    record_meeting(
                        args.ledger,
                        title=args.title,
                        topic=args.topic,
                        participants=args.participant,
                        decision=args.decision,
                        status=args.status,
                    )
                )
                return 0
            if args.mtg_action == "list":
                _out(list_meetings(args.ledger, limit=args.limit, digest_only=args.digest))
                return 0

        if args.cmd == "discuss-check":
            rep = evaluate_discussion_plan(
                tier=args.tier,
                rounds_requested=args.rounds,
                author_family=args.author_family,
                advisor_models=args.advisor_model,
                advisor_families=args.advisor_family,
                has_strawman=args.has_strawman,
                tie_breaker_conflict=args.tie_breaker_conflict,
                specialty_domain=args.specialty_domain,
            )
            _out(rep)
            return 0 if rep["ok"] else 2

        if args.cmd == "route-risk":
            inv_map = json.loads(args.r1_invariants_json) if args.r1_invariants_json.strip() else None
            if inv_map is not None and not isinstance(inv_map, dict):
                raise ValueError("--r1-invariants-json must decode to a JSON object")
            rep = evaluate_blast_radius_route(
                offline_or_readonly=args.offline_or_readonly,
                pure_copy_candidate=args.pure_copy_candidate,
                r1_invariants=inv_map,
                critical_domains_touched=args.critical_domain,
                claimed_tier=args.claimed_tier,
                author_family=args.author_family,
                reviewer_families=args.reviewer_family,
                has_written_spec=args.has_written_spec,
                independent_verification_passed=args.independent_verification_passed,
                review_round=args.review_round,
            )
            _out(rep)
            return 0 if rep["ok"] else 2

        if args.cmd == "mm-verify":
            pkt, _sha = _read_json_nofollow_bounded(args.packet)
            rep = validate_mm_autopsy_packet(pkt)
            _out(rep)
            return 0 if rep["ok"] else 2

        if args.cmd == "dict-check":
            rep = audit_master_dictionary_drift(args.dict_path, args.target, exclude_paths=args.exclude)
            _out(rep)
            return 0 if rep["ok"] else 2
    except Exception as exc:
        _out({"ok": False, "error": str(exc)})
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
