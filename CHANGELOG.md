# Changelog

## [Unreleased]

Merged the full multi-seat operational hardening wave into `main` (zero third-party dependencies, Python 3.10+ stdlib only):

- **Governance Policy Suite (`policy.py`: `discuss-check`, `route-risk`, `mm-verify`, `dict-check`)**: Added 4 zero-dependency universal multi-agent governance validators: (1) front-door `D0–D2` single-round discussion cap & cross-family specialty routing (blocking lightweight models & strawman-less `D2` debates); (2) back-door `R0–R3` blast-radius 4-tier routing with 5-invariant `R1` pure-copy fast lane and automatic `R3` dual-blind escalation on billing/auth-IDOR/core-math/schema changes; (3) negative-experiment double-blind `Fold-A / Fold-B` M&M autopsy verifier (`partition_ab_folds` + `validate_mm_autopsy_packet`, enforcing zero holdout overlap, `<= 300s` zero-retrain `Fold-B` probes & multiple-testing correction); and (4) machine-readable `Master Dict` cross-repo drift, forbidden-jargon, dual-SSOT & `emoji_count == 0` scanner.
- **Pending-Plan Collision Lock & 0-Token `PreInvocation` Visibility (`plan_lock.py`)**: Added atomic `0600` + `fcntl.flock` `diffquorum plan open | list | close` collision lock with automatic `SUPERSEDED` cleanup on `APPROVED`, `rev`-reconciled read-only `O_NOFOLLOW` (`<=16KB`) `format_pending_plans_bar` and `build_pre_invocation_pending_banner` (`own:X | peers:Y | total:Z` with seat-level redaction), plus symmetric `PreToolUse` hook validator `validate_plan_hook_command`.
- **Headless Blind-Review Deadlock Guard & Objective 4-Class Gate (`governance.py`)**: Added `build_headless_review_argv` and `validate_headless_review_spec` enforcing explicit `--disallowed-tools` tool stripping, zero web-search trigger phrases, and `<300s` wall-clock deadlines; added `OBJECTIVE_BLOCKER_CLASSES` anti-bikeshedding gate and `diffquorum release-preflight` (cross-file semver, `PKG-INFO`, `samples/` sdist closure, and test-hygiene AST checks).
- **Anti-Stall Wake Gates & Operations Micro-Modules (`wake_gates.py`, `ops.py`)**: Added `ERROR_MESSAGE` cold-interrupted stream recovery (`>=30s`), leading-prefix silent-tag matching with `P0` non-silence, single-wake orthogonal `REPORT-NO-REPLY` + terminal ticket receipt guarantee, `P0/P1` bounded backoff, stale `copy-mode` auto-exit, compound `WAIT+CPY`/`WORK+CPY` HUD states, zero-delete SHA-256 `curate` ledger folding, `0600` `meetings` ledger, `qa` directory summarizer, and 2-cap alert latch.

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
