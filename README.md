# StarCouncil

**Lightweight, zero-dependency Pointer-Over-Blackboard orchestration, anti-fake-council verification, 6-gate idle wakeup, and tiered review skills for AI coding agents.**

Language: **English** | [简体中文 (Simplified Chinese)](./README.zh-CN.md) | [6 Production Pitfalls & Fixes](./docs/PITFALLS_AND_FIXES.md)

---

## Why StarCouncil?

Most multi-agent frameworks broadcast walls of text into every pane and burn tokens on multi-tmux serial audits or endless retry loops. **StarCouncil (`1 microkernel CLI + 3 <120-line Skills`)** solves the real operational failure modes while keeping daily work fast:

- **Works across `[Local ↔ Federated] × [Single-Sub ↔ Multi-Sub]`**: Single-subscription users get `max_concurrent_agents = 1` serial 3-lens reviews (zero `429` storms); multi-machine clusters keep remote nodes quiet by default (`cross_host_daily_reporting = false`) and send lightweight `async_card` invites only on shared `arch` / `skill` / `retro` topics.
- **Anti-Fake-Council Verifier (`meetings/<id>/`)**: Blocks single-model "roleplay theater" (`SOLO_SYNTHESIS`) unless `>= 2` distinct authors, source kinds, and non-identical SHA-256 submissions exist on disk (`MULTI_SEAT_DECISION`).
- **Two-Round Andon Cord (`PITFALL_HALT`)**: Round-0 local checks fix defect families up front; external blind review stops hard at round 2 if blockers remain — **never** rubber-stamping broken code.
- **Zero-dependency Python 3.10+ stdlib**: Pure stdlib (`fcntl.flock`, `os.O_NOFOLLOW`, `shlex.quote`, `hmac`), zero third-party packages.

## `.starcouncil/` 5 Live Archives

| Archive | Purpose & Hard Guardrail |
| :--- | :--- |
| **`BOARD.md`** | Live shared status & held locks (`< 3KB` hard limit) |
| **`logs/events.jsonl`** | Auto-appended timeline of every `init`, `dispatch`, `ack`, `lock`, `review`, `council` event |
| **`pitfalls.md` & `fixes_log.md`** | `log-pitfall` / `log-fix` mistake & fix ledgers surfaced into every `council` & `review` run |
| **`meetings/<id>/`** | Hash-verified participant submissions blocking fake multi-seat roleplay |
| **`inbox/<seat>.jsonl` + `artifacts/` + `locks/`** | `< 400B` inbox pointer envelopes, full disk payloads, and `fcntl.flock` mutexes |

## 30-Second Quickstart

```bash
git clone https://github.com/Ziqi/starcouncil.git && cd starcouncil
python3 scripts/starcouncil.py init --root /tmp/sc-demo
python3 scripts/starcouncil.py doctor --root /tmp/sc-demo
python3 scripts/starcouncil.py council --root /tmp/sc-demo --topic "Design modular skill architecture"
python3 -m unittest discover -s tests -v
python3 scripts/starcouncil.py sanitize-lint --target .
```

## Included Modular Skills (`< 120` lines each)

- [`skills/starcouncil-teamwork/SKILL.md`](./skills/starcouncil-teamwork/SKILL.md) — Pointer-Over-Blackboard coordination, `flock` resource locks & `hop <= 1` federation
- [`skills/starcouncil-review/SKILL.md`](./skills/starcouncil-review/SKILL.md) — Optional `0/1/2` review tiers, 2-round Andon cord, `HMAC-SHA256` scrubbing & 3-line human summaries
- [`skills/starcouncil-council/SKILL.md`](./skills/starcouncil-council/SKILL.md) — Selective topic-tag quorum, serial 3-lens anti-429 mode & anti-fake-council hash verification
