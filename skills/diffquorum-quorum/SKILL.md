---
name: diffquorum-quorum
description: Use when making high-stakes architecture, naming, or design calls across multiple seats/models — prevents single-model fake roleplay with SHA-256 verification and Stage-2 Peer A/B/C anonymization.
---

# DiffQuorum Blind Quorum (<100 lines)

<SUBAGENT-STOP>
Submit only your own independent view when invited; do NOT synthesize or sign on behalf of other peers.
</SUBAGENT-STOP>

## Anti-Fake-Quorum & Blind Review Rules

1. **NEVER fake multi-seat consensus in one model turn**: One model inventing 4 speakers is `SOLO_SYNTHESIS`, **not** a verified quorum.
2. **Real independent submissions**: Each participant writes its raw file via `quorum-submit` (optionally binding `--diff-sha256` to a git tree/commit hash).
3. **Anonymize before peer ranking (`quorum-blind`)**: Export `blind_packet.md` (`Peer A`, `Peer B`, `Peer C`) hiding model/seat names before cross-critique so reviewers cannot play brand favorites (`reveal_map.json` stays local).
4. **Verify before deciding (`quorum-verify`)**: `MULTI_SEAT_DECISION` requires `>= 2` distinct authors, source kinds, and non-identical SHA-256 hashes (tampering raises an error); single-source outputs stay `SOLO_SYNTHESIS`.
5. **Anti-429 single-subscription cap**: Under `single-sub`, enforce `max_concurrent_agents = 1` serial 3-lens execution; keep remote nodes `DO_NOT_DISTURB` unless tags match `arch`, `skill`, or `retro`.

## Commands

- Record peer submission: `python3 scripts/diffquorum.py quorum-submit --root . --meeting-id rfc-001 --author peer1 --source-kind external_llm --file peer1.md`
- Render blind packet: `python3 scripts/diffquorum.py quorum-blind --root . --meeting-id rfc-001 --seed 42`
- Verify quorum: `python3 scripts/diffquorum.py quorum-verify --root . --meeting-id rfc-001 --resolution "Ship option B"`
