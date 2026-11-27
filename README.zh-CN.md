# DiffQuorum（多智能体轻量协作、盲审防假会与防膨胀门禁套件）

[![CI](https://github.com/Ziqi/diffquorum/actions/workflows/ci.yml/badge.svg)](https://github.com/Ziqi/diffquorum/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Ziqi/diffquorum/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ziqi/diffquorum/actions/workflows/codeql.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16755/badge)](https://www.bestpractices.dev/projects/16755)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Ziqi/diffquorum/badge)](https://scorecard.dev/viewer/?uri=github.com/Ziqi/diffquorum)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/diffquorum/attestations)
[![REUSE 3.3](https://img.shields.io/badge/REUSE-3.3%20Compliant-brightgreen)](./REUSE.toml)
[![Coverage](https://img.shields.io/badge/Coverage-93.63%25-brightgreen)](./tests/test_coverage_gate.py)
[![Fuzzing](https://img.shields.io/badge/Fuzzing-10%2F10%20%282%2C000%20iters%29-brightgreen)](./tests/fuzz_diffquorum.py)
[![Homebrew](https://img.shields.io/badge/Homebrew-Ziqi%2Ftap%2Fdiffquorum-FBB040?logo=homebrew&logoColor=white)](https://github.com/Ziqi/homebrew-tap)
[![SWHID](https://img.shields.io/badge/SWHID-swh%3A1%3Asnp%3A8ebe52ea-e20026.svg)](https://archive.softwareheritage.org/swh:1:snp:8ebe52eac91444368f75eeb4aa75324c40bb21f5)

**零第三方依赖（纯 Python 3.10+ 标准库）的跨会话指针黑板协作、Stage-2 匿名盲审防假会、六门禁防误触唤醒与 `<1s` 派活前零消耗预检工具。**（原名 `StarCouncil`，向下兼容 `.starcouncil/` 工作区与 `starcouncil` CLI 入口。）

语言：[English](./README.md) | **简体中文** | [实战踩坑与修复实录（23 大核心经验）](./docs/PITFALLS_AND_FIXES.md)

---

## 为什么做 DiffQuorum？（保留多席真协作，砍掉官僚套娃审核）

很多多智能体方案喜欢在各个窗口里互灌几万字长文、把不同模型凑一起却让模型认出自家品牌互相吹捧，或者动不动拉起连环跨窗口审稿把整套机器拖慢。**DiffQuorum（1 个微内核 CLI + 3 个不到 100 行的薄 Skill）**只保留实战中真正救过命的机制：

- **跨会话指针黑板与单跳联邦（`.diffquorum/`）**：重正文落 `artifacts/`，`BOARD.md < 3KB`，`inbox/<seat>.jsonl` 严格限制 `< 400B` 短指针，配齐 `O_NOFOLLOW`、`fcntl.flock` 互斥锁、7 天去重、`60s` 对称静默窗与高频熔断；多机平时**默认互不打扰**，仅按话题标签触发轻量 `async_card`。
- **防误触六门禁空闲唤醒与原生事件游标桥（`wake-check` / `wake_gates.py`）**：剥离 ANSI 终端转义序列、识别 Unicode 省略号忙碌动画，并抢在 `> Ask anything...` 前截停“信任文件夹/审批选择”弹窗（`WAITING_MODAL_RE`）；死守 `#{client_activity} >= 15s`（保护中文输入法），忽略 `isDaemon` 守护任务，内置顶层会话 `NATIVE_SEND_MESSAGE` 持久化 `5.5s` 防抖 + `24h` 存活游标桥（`scan_native_message_events_cursor`），支持断流 `ERROR_MESSAGE` 自动恢复、`P0/P1` 指数退避与结单回执必达，兼容 `agy`/`claude`/`codex`/`opencode`。
- **全口径待决撞车锁、角色分层 `PreInvocation`、`Stop` 一致性兜底与跨区钩子串味审查（`plan` / `plan_lock.py`）**：原子 `0600` + `flock` `diffquorum plan open --kind {PLAN,DECISION,CIRCUIT_BREAKER,INPUT_REQUIRED} | list | reopen | close` 杜绝双头方案冲突与中途反问漏记（同席安全共存 + 显式 `--supersede` + 实时 `live_footer_markdown`）；回合启动 `PreInvocation` 支持 `fleet`/`line`/`self` 三层角色视角（全局总控看全机、业务线总控仅看本线、执行席只看本席且 0 项占 0 字节，彻底消除跨窗口陈旧抄报，并保留 `<=512KB` 读取上限与敏感席位硬脱敏）；回合结束 `Stop` 钩子自动拦截未登账暂停与角色内假报 0 项尾注（`evaluate_stop_consistency_gate`），内置 `hooks.json` 扁平/分组结构校验（`validate_hooks_json_schema`）、跨工作区 `--add-dir` 钩子串味审查（`audit_launch_args_for_hook_bleed`）与多席 `PreToolUse` 对称放行校验（`validate_plan_hook_command`）。
- **Stage-2 匿名盲评防假开会与无头盲审防死锁（`quorum-*` / `governance.py`）**：单模型自导自演永远只能拿 `SOLO_SYNTHESIS`；至少 `>= 2` 份不同作者、不同来源且 SHA-256 哈希独立的原件（可选 `--diff-sha256` 绑定代码树）才准出 `MULTI_SEAT_DECISION`；无头外审强锁 `--disallowed-tools` 剥离内置工具、拦截联网检索触发词与 `<300s` 超时硬界（`build_headless_review_argv` / `validate_headless_review_spec`），配套 4 类客观硬伤收敛与 `release-preflight`。
- **三阶段协同治理引擎（`discuss-check` / `route-risk` / `blind-eval-check` / `mm-verify` / `dict-check`）**：固化一阶段前门探讨 `D0–D2` 单轮封顶与异构专长派工（`D2` 必先立靶子、禁轻量模型上决策桌）、二阶段上线前按爆炸半径 `R0–R3` 四档路由（含 5 不变量 `R1` 纯文案快检直通车，以及触碰钱/权/数/库或外部旗舰商业交付物 `commercial_flagship_deliverable` 自动升 `R3` 双盲审）、三阶段上线后零上下文盲测 `B0–B2`（非阻塞、仅公开入口、单轮进下版清单）、负结果实验 `Fold-A / Fold-B` 半区隔离防自证双盲 M&M 尸检协议，以及基于机器可读 `Master Dict` 主词典的跨仓口径漂移、禁词与零表情符扫描。
- **`<1s` 零消耗派活预检（`preflight`）、无损折叠（`curate`）与两轮安灯拉闸**：派活前先验目录可写性（提前拦截只读沙箱）、资源锁及目标 CLI 状态目录；内置零删除 SHA-256 账本折叠（`curate`）与 `0600` 会议/问答台账（`meetings` / `qa`）；平时小改动 `--level 0` 直接跑本地单测放行，外审最多两轮不过即触发 `PITFALL_HALT` 并记入 `pitfalls.md`，另附可选无头预设模板。

## `.diffquorum/` 五类后台活档案

| 档案路径 | 职责与核心限制 |
| :--- | :--- |
| **`BOARD.md`** | 共享黑板，实时展现各席任务与当前持锁状态（严控 `< 3KB`） |
| **`logs/events.jsonl`** | 全自动追加的运行流水日志（记录每次 `init`、`dispatch`、`ack`、`lock`、`review`、`quorum`） |
| **`pitfalls.md` 与 `fixes_log.md`** | 踩坑错题本与修复日志（`log-pitfall` / `log-fix`，开会与把关时自动带出近期踩坑提醒） |
| **`meetings/<id>/`** | 独立发言原件、`--diff-sha256` 指纹、`blind_packet.md`、`reveal_map.json` 与 `RESOLUTION.json` |
| **`inbox/<seat>.jsonl` + `artifacts/` + `locks/`** | `< 400B` 短指针信封、完整磁盘正文与 `fcntl.flock` 互斥锁 |

## 30 秒本地开箱体验

```bash
# 方式 A：通过官方 Homebrew 源一键安装（macOS / Linuxbrew）
brew install Ziqi/tap/diffquorum
diffquorum init --root /tmp/dq-demo && diffquorum preflight --root /tmp/dq-demo --cli python3
diffquorum doctor --root /tmp/dq-demo

# 方式 B：克隆即用（纯 Python 3.10+ 标准库，零 pip 依赖；国内读者可用 AtomGit 免代理镜像）
# 国内镜像：git clone https://atomgit.com/sinoziqi/diffquorum.git && cd diffquorum
git clone https://github.com/Ziqi/diffquorum.git && cd diffquorum
python3 scripts/diffquorum.py init --root /tmp/dq-demo
python3 scripts/diffquorum.py preflight --root /tmp/dq-demo --write-path /tmp/dq-demo
python3 scripts/diffquorum.py quorum --root /tmp/dq-demo --topic "设计盲审防假会机制"
python3 -W error -m unittest discover -s tests -v
python3 -W error tests/test_coverage_gate.py --min-coverage 90.0
python3 -W error tests/fuzz_diffquorum.py --iterations 2000
python3 -W error scripts/diffquorum.py sanitize-lint --target .
```

## 三个模块化薄 Skill（均 `< 100` 行，内置 `<SUBAGENT-STOP>` 防越界护栏）

- [`skills/diffquorum-coord/SKILL.md`](./skills/diffquorum-coord/SKILL.md)：`<1s` 派活前 `preflight`、指针黑板、`flock` 互斥锁、弹窗安全唤醒与可选预设模板
- [`skills/diffquorum-quorum/SKILL.md`](./skills/diffquorum-quorum/SKILL.md)：Stage-2 `Peer A/B/C` 盲评脱敏、SHA-256 防假开会核验与单订阅防 `429` 护栏
- [`skills/diffquorum-gate/SKILL.md`](./skills/diffquorum-gate/SKILL.md)：日常 `--level 0` 快通（防流程臃肿）、两轮安灯拉闸与大白话三行总结
