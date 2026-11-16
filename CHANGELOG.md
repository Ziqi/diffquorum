# Changelog

## v0.1.1 (2026-11-16)

Supply-chain assurance, reproducible release packaging, and verification gate upgrade:

- **>= 90% Statement Coverage & 2,000-Iteration Fuzzing**: Added stdlib `dis` + `trace` statement coverage gate (`tests/test_coverage_gate.py`, achieving `91.06%` across `src/starcouncil/*.py`) and dual-mode Google Atheris / property-invariant fuzzer (`tests/fuzz_starcouncil.py`, `2,000` iterations).
- **Reproducible Packaging & `SPDX-2.3` SBOM**: Added `starcouncil archive --verify` (deterministic `mtime=0`, `uid/gid=0` `.tar.gz`), `bin/starcouncil` executable launcher, `scripts/generate-sbom.py`, detached Ed25519 signatures (`.sig`), and signed in-toto DSSE bundles (`.intoto.jsonl`).
- **GitHub Supply-Chain Hardening**: Pinned all workflow actions (`CI`, `CodeQL`, `OpenSSF Scorecard`, `SLSA Build Level 3 & SBOM Attestation`) to full 40-char commit SHAs with least-privilege permissions, enabled Private Vulnerability Reporting, `Dependabot`, `FSFE REUSE 3.3` (`REUSE.toml` + `LICENSES/MIT.txt`), `CITATION.cff`, `GOVERNANCE.md`, `CODE_OF_CONDUCT.md`, and `SECURITY_ASSURANCE_CASE.md`.
- **Permanent Archival & Distribution**: Archived in UNESCO Software Heritage (`swh:1:snp:8ebe52eac91444368f75eeb4aa75324c40bb21f5`) and packaged for official Homebrew distribution (`brew install Ziqi/tap/starcouncil`).

## v0.1.0 (2026-11-16)

Initial public clean-room release of **StarCouncil**:

- **Zero-dependency Python 3.10+ microkernel (`starcouncil` CLI)** maintaining `.starcouncil/` **5 Live Archives**:
  1. `BOARD.md` (`< 3KB` shared live blackboard with lock visibility);
  2. `logs/events.jsonl` (automatic append-only event stream across `init`, `dispatch`, `ack`, `lock`, `review`, `council`, `council-submit`, `council-verify`, `log-pitfall`, `log-fix`);
  3. `pitfalls.md` & `fixes_log.md` (`log-pitfall` / `log-fix` Shift-Left ledgers surfaced automatically into `council` & `review`);
  4. `meetings/<meeting_id>/` (anti-fake-council verifier: `council-submit` + `council-verify` requiring `>= 2` independent authors, source kinds, and SHA-256 content hashes for `MULTI_SEAT_DECISION`, otherwise blocking or watermarking `SOLO_SYNTHESIS`);
  5. `inbox/<seat>.jsonl` (`< 400B` pointer envelopes) + `artifacts/` + `locks/` (`fcntl.flock` mutexes).
- **Anti-resonance & safety hardening**: `O_NOFOLLOW` symlink defense, `shlex.quote` + `<= 64KB` pure-ASCII stdin SSH transport, `7-day` `event_id` deduplication, `hop <= 1` limit, `60s` symmetric ACK silence, `120s >= 4` / `900s > 6` burst circuit breakers, `SEEN_AWAITING_HUMAN` & `#{client_activity} >= 15s` 6-gate idle wakeup state machine, two-round Andon cord (`PITFALL_HALT`), L3 `OUTAGE_FAIL_CLOSED`, session-scoped `HMAC-SHA256` pseudonymization, and `sanitize-lint`.
- **Three progressive-disclosure thin Skills (`< 120` lines each)**: `starcouncil-teamwork`, `starcouncil-review`, and `starcouncil-council`.
- **Production lessons (`docs/PITFALLS_AND_FIXES.md`)**: Clean-room engineering postmortem of 6 real multi-agent pitfalls and fixes.
