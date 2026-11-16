---
name: diffquorum-coord
description: Use when coordinating 2+ independent AI agent sessions, locking shared resources, or checking target directory/CLI readiness before dispatching workers — keeps daily work isolated and replaces transcript dumps with <400B disk pointers.
---

# DiffQuorum Coordination (<100 lines)

<SUBAGENT-STOP>
If you are a worker subagent executing a narrow slice, do NOT trigger cross-session coordination unless writing to your assigned pointer inbox.
</SUBAGENT-STOP>

## Daily Speed & Anti-Bloat Rules

1. **Keep independent seats decoupled**: Sessions work autonomously without routine cross-reporting; share pointers **only** when touching shared boundaries or locks.
2. **Run `<1s` `preflight` BEFORE dispatching workers**: Verify target paths are writable (catching read-only sandbox / `.gitignore` traps early), locks are free, and required CLIs exist.
3. **Pointer-Over-Blackboard (`.diffquorum/`)**: Write payloads under `artifacts/`, keep `BOARD.md < 3KB`, and pass `<400B` JSONL pointers via `inbox/<seat>.jsonl` using `O_NOFOLLOW` + `fcntl.flock`.
4. **Safe idle wakeups (`wake-check`)**: Never interrupt active typing (`#{client_activity} < 15s`), interactive modals (`Yes, I trust this folder` / `↑/↓ to navigate`), non-daemon tasks, or `SEEN_AWAITING_HUMAN`; ignore first-line `【TERMINAL-ACK】`/`【INFO-SYNC` tags.
5. **Single-hop federation (`hop <= 1`)**: Wrap remote SSH with `shlex.quote`, `<= 64KB` ASCII stdin, `60s` ACK silence, and burst circuit breakers.
6. **Optional worker presets (`preset`)**: Use `generic-ptr`, `claude-sub`, `codex`, or optional `agy-hydrogen` only when isolating execution models.

## Commands

- Preflight check: `python3 scripts/diffquorum.py preflight --root . --write-path ./out --cli git`
- Dispatch pointer: `python3 scripts/diffquorum.py dispatch --root . --from lead --to builder --summary "Contract synced"`
- Lock shared resource: `python3 scripts/diffquorum.py lock --root . --resource browser --seat lead -- python3 task.py`
- Optional runner preset: `python3 scripts/diffquorum.py preset --profile agy-hydrogen --task-pointer artifacts/evt-1.md`
