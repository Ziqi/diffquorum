---
name: starcouncil-teamwork
description: Lightweight multi-agent Pointer-Over-Blackboard coordination skill. Manages .starcouncil/ 5 live archives (BOARD.md, logs/events.jsonl, pitfalls.md & fixes_log.md, meetings/, inbox/artifacts/locks), exclusive flock locks, and hop<=1 peer dispatch while preventing cross-host chatter bloat.
---

# StarCouncil Teamwork (<120 lines)

## 5 Live Archives Under `.starcouncil/`

1. **`BOARD.md` (`<3KB`)**: Live status & currently held resource locks (`starcouncil board --refresh`).
2. **`logs/events.jsonl`**: Auto-appended timeline of every `init`, `dispatch`, `ack`, `lock`, `review`, and `council` action for fast debugging.
3. **`pitfalls.md` & `fixes_log.md`**: Shift-Left mistake ledger & fix log (`log-pitfall` / `log-fix`), surfaced automatically during `council` and `review`.
4. **`meetings/<id>/`**: Raw independent statements + SHA-256 verification preventing single-model fake multi-seat roleplay.
5. **`inbox/<seat>.jsonl` (`<400B` pointers) + `artifacts/` + `locks/`**: Payloads live on disk in `artifacts/`; panes only receive tiny `<400B` pointers with `O_NOFOLLOW` + `fcntl.flock`.

## Golden Rules

- **Keep daily work fast and independent**: Local sessions only ping peers when a real shared boundary needs alignment; remote hosts keep `cross_host_daily_reporting = false`.
- **Single-hop SSH transport**: Never interpolate dynamic strings over SSH; use `shlex.quote` + `stdin <= 64KB` pure ASCII JSON (`hop <= 1`), `60s` ACK silence, and `120s >= 4` / `900s > 6` burst circuit breakers.
- **Native Antigravity reuse**: Keep routine sessions on lightweight `Orchestrator`, use `swarm(workspace="share")` only for parallel edits inside the same repo, and pass `-` to [cli.py](../../src/starcouncil/cli.py).

## Quick Commands

- Initialize workspace: `python3 scripts/starcouncil.py init --root .`
- Send `<400B` pointer: `python3 scripts/starcouncil.py dispatch --root . --from lead --to builder --summary "Interface synced"`
- Lock shared resource: `python3 scripts/starcouncil.py lock --root . --resource browser --seat lead -- python3 task.py`
- Run 30-second health check: `python3 scripts/starcouncil.py doctor --root .`
