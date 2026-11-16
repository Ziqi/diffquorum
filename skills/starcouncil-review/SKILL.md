---
name: starcouncil-review
description: Optional tiered code review skill with Level 0 (instant local fast-path), Level 1 (single-round sanity check), and Level 2 (two-round Andon cord PITFALL_HALT + L3 Fail-Closed). Reads recent pitfalls, auto-logs fixes to fixes_log.md, scrubs host secrets via HMAC-SHA256, and outputs plain 3-line human summaries.
---

# StarCouncil Review (<120 lines)

## Optional Tiers (No Multi-Window Audit Bloat)

- **Level 0 (Default daily work)**: Pass local tests and ship directly — zero extra cross-pane review queues.
- **Level 1 (Single-round quick check)**: One independent pass returning actionable blockers only; stop cleanly after 1 round.
- **Level 2 (Release / security gate — Two-Round Andon Cord)**:
  1. Run local tests & syntax checks first (**Round-0**), fix entire defect families in one batch, then freeze `tree-hash`.
  2. Cap external blind review at **2 rounds**. If round 2 still hits blockers, trigger **`PITFALL_HALT`** (stop burning quota, log root cause to `pitfalls.md`, never rubber-stamp!). Once fixed cleanly on round 2+, auto-log closure into `fixes_log.md`.
  3. Route style nits locally (`--nits-only` -> `pitfalls.md`) and halt **`OUTAGE_FAIL_CLOSED`** on external timeouts/5xx.

## Mandatory Live-Archive Hygiene & Plain 3-Line Output

- `review` automatically surfaces `recent_pitfalls` from `.starcouncil/pitfalls.md` and appends every run to `.starcouncil/logs/events.jsonl`.
- Always scrub local paths/IPs (`review --pseudonymize-file`) before sending context to external models, and summarize via [governance.py](../../src/starcouncil/governance.py) 3-line template:

```text
【结果】一句话直说通过了没 / 改好了啥
【原因】一句大白话讲清依据或卡点
【需您操作】明确点哪里（不用点就写“无”）
```

## Quick Commands

- Instant daily pass: `python3 scripts/starcouncil.py review --root . --level 0 --tree-hash deadbeef1234`
- Two-round Andon check: `python3 scripts/starcouncil.py review --root . --level 2 --tree-hash deadbeef1234 --round 2 --blocker "missing guard"`
- Record root-cause fix: `python3 scripts/starcouncil.py log-fix --root . --title "Guard edge" --fix "Validated path prefix" --files "src/guard.py"`
