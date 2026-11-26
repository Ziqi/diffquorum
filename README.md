# DiffQuorum

[![CI](https://github.com/Ziqi/diffquorum/actions/workflows/ci.yml/badge.svg)](https://github.com/Ziqi/diffquorum/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Ziqi/diffquorum/actions/workflows/codeql.yml/badge.svg)](https://github.com/Ziqi/diffquorum/actions/workflows/codeql.yml)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16755/badge)](https://www.bestpractices.dev/projects/16755)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Ziqi/diffquorum/badge)](https://scorecard.dev/viewer/?uri=github.com/Ziqi/diffquorum)
[![SLSA 3](https://slsa.dev/images/gh-badge-level3.svg)](https://github.com/Ziqi/diffquorum/attestations)
[![REUSE 3.3](https://img.shields.io/badge/REUSE-3.3%20Compliant-brightgreen)](./REUSE.toml)
[![Coverage](https://img.shields.io/badge/Coverage-91.81%25-brightgreen)](./tests/test_coverage_gate.py)
[![Fuzzing](https://img.shields.io/badge/Fuzzing-10%2F10%20%282%2C000%20iters%29-brightgreen)](./tests/fuzz_diffquorum.py)
[![Homebrew](https://img.shields.io/badge/Homebrew-Ziqi%2Ftap%2Fdiffquorum-FBB040?logo=homebrew&logoColor=white)](https://github.com/Ziqi/homebrew-tap)
[![SWHID](https://img.shields.io/badge/SWHID-swh%3A1%3Asnp%3A8ebe52ea-e20026.svg)](https://archive.softwareheritage.org/swh:1:snp:8ebe52eac91444368f75eeb4aa75324c40bb21f5)

**Zero-dependency multi-agent session coordination (`<400B` pointer blackboard, 6-gate modal-aware idle wakeup), Stage-2 blind anti-fake-quorum verifier & 0-token pitfall ratchet for AI coding agents.** *(Formerly `StarCouncil`; seamlessly supports `.starcouncil/` workspaces and `starcouncil` CLI shims.)*

Language: **English** | [简体中文 (Simplified Chinese)](./README.zh-CN.md) | [13 Production Pitfalls & Fixes](./docs/PITFALLS_AND_FIXES.md)

---

## Why DiffQuorum?

Most multi-agent setups copy-paste walls of text across panes, wake busy/approval-blocked TUIs blindly, or trap daily engineering edits inside recursive multi-window audit queues. **DiffQuorum (`1 microkernel CLI + 3 <100-line Skills`)** solves those exact production failures while staying fast:

- **Cross-Session Pointer-Over-Blackboard (`.diffquorum/`)**: Keep `BOARD.md < 3KB`, write specs to `artifacts/`, serialize `inbox/<seat>.jsonl` with `<400B` pointer envelopes, `os.O_NOFOLLOW`, `fcntl.flock`, `7d` idempotency, `60s` ACK silence, burst circuit breakers, and `hop <= 1` SSH `stdin` (`<=64KB` ASCII) federation — zero cross-host daily chatter (`cross_host_daily_reporting = false`).
- **6-Gate ANSI- & Modal-Aware Idle Wakeup (`wake-check`)**: Strips ANSI CSI/OSC escapes before prompt matching, detects interactive approval modals (`WAITING_MODAL_RE`) even above `> Ask anything...`, requires `#{client_activity} >= 15s` keyboard idle, ignores background `isDaemon` watchers, recovers cold-interrupted `ERROR_MESSAGE` streams, guards `P0/P1` tickets with bounded backoff + terminal receipt guarantees, and emits exact `BSpace` rollbacks across `agy`, `claude`, `codex`, and `opencode`.
- **Pending-Plan Collision Lock & 0-Token `PreInvocation` Visibility (`plan` / `plan_lock.py`)**: Atomic `0600` + `flock` `diffquorum plan open | list | close` prevents competing drafts on the same logical scope, reconciles `own:X | peers:Y` turn-start banners (`0` bytes when idle, hard redaction for sensitive seats), and enforces symmetric multi-seat `PreToolUse` hook validation (`validate_plan_hook_command`).
- **Stage-2 Blind `Peer A/B/C` Anti-Fake-Quorum Verifier & Headless CLI Guard (`quorum-*` / `governance.py`)**: Blocks single-model roleplay (`SOLO_SYNTHESIS`) unless `>= 2` independent authors, source kinds, and non-identical SHA-256 submissions exist on disk (optionally bound via `--diff-sha256`); exports anonymized `Peer A/B/C` packets (`blind_packet.md` + local `reveal_map.json`); and enforces tool-stripped `<300s` headless blind reviews (`build_headless_review_argv` / `validate_headless_review_spec`) plus 4-class objective `BLOCK` convergence & `release-preflight`.
- **`<1s` Zero-Token `preflight`, Lossless `curate` & Two-Round Andon Cord (`PITFALL_HALT`)**: Checks target writeability (catching read-only sandboxes / symlink traps), resource locks, and worker CLIs/state dirs before spending tokens; provides zero-delete SHA-256 ledger folding (`curate`), `0600` meeting/Q&A ledgers (`meetings` / `qa`), caps external review at `<= 2` rounds, and ships optional headless runner presets (`diffquorum preset --profile generic-ptr|claude-sub|codex|agy-hydrogen`).

## `.diffquorum/` 5 Live Archives

| Archive | Purpose & Hard Guardrail |
| :--- | :--- |
| **`BOARD.md`** | Live shared status & held locks (`< 3KB` hard limit) |
| **`logs/events.jsonl`** | Auto-appended timeline of every `init`, `dispatch`, `ack`, `lock`, `review`, `quorum` event |
| **`pitfalls.md` & `fixes_log.md`** | `log-pitfall` / `log-fix` mistake & fix ledgers surfaced into `quorum` & `review` runs |
| **`meetings/<id>/`** | Hash-verified submissions (`--diff-sha256`), `blind_packet.md`, `reveal_map.json` & `RESOLUTION.json` |
| **`inbox/<seat>.jsonl` + `artifacts/` + `locks/`** | `< 400B` inbox pointer envelopes, full disk payloads, and `fcntl.flock` mutexes |

## 30-Second Quickstart

```bash
# Option A: Official Homebrew Tap (macOS & Linuxbrew)
brew install Ziqi/tap/diffquorum
diffquorum init --root /tmp/dq-demo && diffquorum preflight --root /tmp/dq-demo --cli python3
diffquorum doctor --root /tmp/dq-demo

# Option B: Zero-install from Git (Python 3.10+ stdlib only)
git clone https://github.com/Ziqi/diffquorum.git && cd diffquorum
python3 scripts/diffquorum.py init --root /tmp/dq-demo
python3 scripts/diffquorum.py preflight --root /tmp/dq-demo --write-path /tmp/dq-demo
python3 scripts/diffquorum.py quorum --root /tmp/dq-demo --topic "Design blind peer verification"
python3 -W error -m unittest discover -s tests -v
python3 -W error tests/test_coverage_gate.py --min-coverage 90.0
python3 -W error tests/fuzz_diffquorum.py --iterations 2000
python3 -W error scripts/diffquorum.py sanitize-lint --target .
```

## Included Modular Skills (`< 100` lines each, with `<SUBAGENT-STOP>`)

- [`skills/diffquorum-coord/SKILL.md`](./skills/diffquorum-coord/SKILL.md) — `<1s` `preflight`, Pointer-Over-Blackboard coordination, `flock` locks, modal-safe wakeups & optional presets
- [`skills/diffquorum-quorum/SKILL.md`](./skills/diffquorum-quorum/SKILL.md) — Stage-2 `Peer A/B/C` blind anonymization, SHA-256 anti-fake-quorum verification & single-sub `429` guard
- [`skills/diffquorum-gate/SKILL.md`](./skills/diffquorum-gate/SKILL.md) — Daily `--level 0` fast lane, 2-round Andon cord (`PITFALL_HALT`), `HMAC-SHA256` scrubbing & plain-language summaries
