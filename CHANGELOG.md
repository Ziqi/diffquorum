# Changelog

## v0.2.0 (2026-11-16)

Rebranded to **DiffQuorum** (`Ziqi/diffquorum`, preserving `.starcouncil/` workspace & `starcouncil` CLI backward compatibility) and integrated four code-level upgrades benchmarked from top open-source agent orchestrators:

- **Stage-2 Blind Anonymization & Diff Binding (`quorum-blind` / `--diff-sha256`)**: Added `quorum_submit(..., diff_sha256=...)` and `quorum_render_blind_packet` generating anonymized `Peer A/B/C` review bundles (`blind_packet.md`) paired with local `reveal_map.json` so peer reviewers cannot play model-brand favorites. Kept `council` / `council-submit` / `council-verify` as aliases.
- **ANSI- & Modal-Aware 6-Gate Wakeup (`wake_gates.py`)**: Added `strip_terminal_escapes()` (normalizing CSI cursor moves and OSC sequences), Unicode ellipsis (`Working…` / `Thinking…`) busy detection, `WAITING_MODAL_RE` interactive approval modal blocking above `> Ask anything...`, and native support for `claude`, `codex`, and `opencode` panes alongside `agy`.
- **Zero-Token `<1s` Worker Preflight (`diffquorum preflight`)**: Checks writeability of target directories via `O_NOFOLLOW` probe files (catching read-only sandboxes before wasting tokens), lock contention under `.diffquorum/locks/`, CLI binary existence, and `~/.gemini/antigravity-cli` state writability when `--cli agy` is requested.
- **Optional Runner Presets & Leaner `<100`-Line Skills**: Replaced bloated skills with 3 `<100`-line skills (`diffquorum-coord`, `diffquorum-quorum`, `diffquorum-gate`) carrying `<SUBAGENT-STOP>` subagent containment guards, and added `diffquorum preset --profile generic-ptr|claude-sub|codex|agy-hydrogen` as an optional vendor-neutral command generator (`coverage = 91.81%`, `15` unit tests + `2,000` fuzz iterations).

## v0.1.1 (2026-11-16)

Supply-chain assurance, reproducible release packaging, and verification gate upgrade (under initial name `StarCouncil`):

- **>= 90% Statement Coverage & 2,000-Iteration Fuzzing**: Added stdlib `dis` + `trace` statement coverage gate (`tests/test_coverage_gate.py`, achieving `91.06%`) and dual-mode Google Atheris / property-invariant fuzzer (`tests/fuzz_starcouncil.py`, `2,000` iterations).
- **Reproducible Packaging & `SPDX-2.3` SBOM**: Added deterministic `archive --verify`, executable launcher, `scripts/generate-sbom.py`, detached Ed25519 signatures (`.sig`), and signed in-toto DSSE bundles (`.intoto.jsonl`).
- **GitHub Supply-Chain Hardening**: Pinned all workflow actions (`CI`, `CodeQL`, `OpenSSF Scorecard`, `SLSA Build Level 3 & SBOM Attestation`) to full 40-char commit SHAs with least-privilege permissions, enabled Private Vulnerability Reporting, `Dependabot`, `FSFE REUSE 3.3`, `CITATION.cff`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, and `SECURITY_ASSURANCE_CASE.md`.
- **Permanent Archival & Distribution**: Archived in UNESCO Software Heritage (`swh:1:snp:8ebe52eac91444368f75eeb4aa75324c40bb21f5`) and packaged for official Homebrew distribution.

## v0.1.0 (2026-11-16)

Initial public clean-room release (under initial name `StarCouncil`):

- **Zero-dependency Python 3.10+ microkernel** maintaining `.starcouncil/` **5 Live Archives**: `BOARD.md` (`< 3KB`), `logs/events.jsonl`, `pitfalls.md` & `fixes_log.md`, `meetings/<meeting_id>/` SHA-256 anti-fake-council verifier, and `< 400B` pointer `inbox/<seat>.jsonl` + `artifacts/` + `locks/` (`fcntl.flock`).
- **Anti-resonance & safety hardening**: `O_NOFOLLOW`, `shlex.quote` + `<= 64KB` ASCII stdin SSH transport, `7d` idempotency, `hop <= 1`, `60s` ACK silence, `4/120s` & `6/900s` burst circuit breakers, `6-gate` idle wakeup, two-round Andon cord (`PITFALL_HALT`), `OUTAGE_FAIL_CLOSED`, `HMAC-SHA256` scrubbing, and `sanitize-lint`.
