---
name: starcouncil-council
description: Selective 3-phase multi-perspective council skill with cryptographic anti-fake-council verification. Keeps remote nodes silent by default, switches single-subscription users to serial 3-lens mode to avoid 429 deadlocks, reads recent pitfalls, and blocks fake single-model roleplay via meetings/ SHA-256 verification.
---

# StarCouncil Council (<120 lines)

## Core Anti-Fake-Council Guardrail

- **NEVER fake a multi-agent meeting in one model turn**: An LLM inventing 4 imaginary speakers inside one reply is `SOLO_SYNTHESIS`, **not** a multi-seat council decision!
- Whenever calling a real multi-seat / multi-model council under `.starcouncil/meetings/<meeting_id>/`:
  1. Each real participant (`local_seat`, `remote_node`, `external_llm`, `subagent`) MUST independently submit its raw opinion via `council-submit`.
  2. Run `council-verify --meeting-id <id>`: only **`>= 2` distinct authors, source kinds, and non-identical SHA-256 hashes** earn `MULTI_SEAT_DECISION`; single-source or copy-pasted submissions are blocked (`exit 2`, logged to `pitfalls.md`) unless explicitly watermarked `--allow-solo` as `SOLO_SYNTHESIS`.

## Topic-Tag Routing & `2x2` Mode Adaptation

- **Single-subscription (`single-sub`)**: Locks `max_concurrent_agents = 1` and runs a crisp serial 3-lens pass (`Architect -> Bug Auditor -> Plain Summarizer`) via disk artifacts so users never hit `429 RESOURCE_EXHAUSTED`.
- **Multi-node (`remote-hub`)**: Keeps remote workstations quiet by default; invites them asynchronously only when tags match `arch`, `skill`, or `retro`.
- **Always read `recent_pitfalls`**: `council` automatically surfaces recent entries from `.starcouncil/pitfalls.md` and records history in `.starcouncil/logs/events.jsonl` (see [cli.py](../../src/starcouncil/cli.py)).

## Quick Commands

- Plan selective quorum: `python3 scripts/starcouncil.py council --root . --topic "Design modular workflow" --subscription single-sub`
- Record independent submission: `python3 scripts/starcouncil.py council-submit --root . --meeting-id rfc-001 --author builder --source-kind local_seat --content "..."`
- Verify authenticity before decision: `python3 scripts/starcouncil.py council-verify --root . --meeting-id rfc-001`
