# DiffQuorum Security Assurance Case & Threat Model

> **Scope**: `Ziqi/diffquorum` (`src/diffquorum/`, `scripts/`, `skills/`, `.github/workflows/`)  
> **Standards Alignment**: OpenSSF Best Practices (`Silver`), OpenSSF OSPS Baseline (`Level 3`), Sigstore `SLSA Build Level 3`

---

## 1. Architecture Trust Boundaries & Threat Model

`DiffQuorum` is an offline-first, zero-dependency Python `>= 3.10` stdlib orchestration microkernel coordinating multiple AI agent panes locally (`tmux`) or over `ssh` peer cards. Its primary security threats arise from untrusted IPC payloads, symlink traversal inside shared `.diffquorum/` workspaces, prompt-injection context bloat, single-model "fake quorum" collusion, TUI modal hijack during idle wakeup, secret leakage during external review calls, and CI/CD release tampering:

| ID | Trust Boundary / Attack Vector | Security Failure Prevented | Deterministic Engineering Control & Verification |
| :--- | :--- | :--- | :--- |
| **TB-1** | **Prompt Bloat & Context-Flood DoS** (`inbox/<seat>.jsonl` & `BOARD.md`) | Unbounded payload injection causing agent context truncation, token exhaustion, or inbox denial of service. | Strict `<400B` hard envelope cap (`MAX_ENVELOPE_BYTES = 400`) and `<3KB` shared board cap (`MAX_BOARD_BYTES = 3072`), moving heavy content to disk `artifacts/<id>.md`. Verified across 2,000 adversarial inputs in `tests/fuzz_diffquorum.py`. |
| **TB-2** | **Shared `.diffquorum/` Symlink & Path Traversal** (`inbox/`, `meetings/`, `locks/`, `preflight`) | Compromised local participant plants a symlink in `.diffquorum/` to overwrite arbitrary files outside workspace root. | Every archive read/write/lock/preflight probe uses `os.O_NOFOLLOW`, `stat.S_ISREG` verification, atomic `.tmp` + `os.replace`, `os.walk(..., followlinks=False)`, and regex allowlists (`SEAT_NAME_RE`, `MEETING_ID_RE`, `EVENT_ID_RE`, `CLI_TOOL_RE`). |
| **TB-3** | **Concurrent IPC, Resource Races & Wakeup Modal Hijack** | Simultaneous `dispatch`, `ack`, `lock`, or `events.jsonl` writes corrupting JSONL envelopes; `[BUS-WAKE]` hitting an interactive approval dialog or active CJK IME buffer. | Exclusive `fcntl.flock` mutexes (`BusLock`) under `.diffquorum/locks/`, `7d` `event_id` deduplication, `60s` ACK silence, burst circuit breakers, `strip_terminal_escapes()` + `WAITING_MODAL_RE` check, `#{client_activity} >= 15s`, and `BSpace` rollback. |
| **TB-4** | **Cross-Host SSH Command Injection & Egress Escalation** (`dispatch --ingest-stdin`, `build_ssh_peer_command`) | Untrusted remote peer payload injecting shell metacharacters, forwarding SSH agents, or triggering unbounded multi-hop storms (`hop > 1`). | Zero `shell=True`, strict `shlex.quote(remote_bin)`, hardcoded `BatchMode=yes` + `ForwardAgent=no`, `<= 64KB` strictly 7-bit ASCII stdin (`MAX_STDIN_BYTES = 65536`), `MAX_HOP = 1`, and `allowlisted_hosts` / `seats` verification. |
| **TB-5** | **Single-Model "Fake Quorum" Roleplay & Model Bias** (`quorum-verify`, `quorum-blind`) | Orchestrator synthesizes fake multi-agent consensus in one turn, copies identical text under multiple names, tampers with `.md` minutes, or biases critique via model labels. | `quorum-submit` persists raw markdown + optional `diff_sha256` + `SHA-256`; `quorum-verify` recomputes live file hashes (`TAMPERED_SUBMISSION_HASH_MISMATCH`) and blocks `MULTI_SEAT_DECISION` (`exit 2`) unless `>= 2` distinct authors, source kinds, and non-identical SHA-256 digests exist; `quorum-blind` emits anonymized `Peer A/B/C`. |
| **TB-6** | **Outbox Secret/PII Leak & Fail-Open External Review** | Local file paths (`/Users/<real>`), Tailscale/RFC 1918 IPs, or session UUIDs leaking to external review CLIs or public commits; broken external model silently approving unsafe diffs. | Ephemeral-key `HMAC-SHA256` pseudonymization (`pseudonymize_text`), fail-closed `OUTAGE_FAIL_CLOSED` + two-round Andon cord (`PITFALL_HALT`), and `sanitize-lint` clean-room CI gate. |
| **TB-7** | **CI/CD & Artifact Supply-Chain Tampering** | Compromised upstream GitHub Action tag or non-deterministic release archive injection. | Full 40-char SHA pinning (`Pinned-Dependencies`), `permissions: {}` + `persist-credentials: false`, `CodeQL`, `OpenSSF Scorecard`, `SLSA Build Level 3` Sigstore OIDC (`actions/attest-build-provenance` + `actions/attest-sbom`), and bit-for-bit reproducible `archive --verify`. |

---

## 2. Continuous Verification Matrix

| Assurance Layer | Tool / Test Harness | Cadence | Target Evidence |
| :--- | :--- | :--- | :--- |
| **Unit & Integration** | `python3 -W error -m unittest discover -s tests -v` | Every push / PR | `tests/test_diffquorum.py` (15 suites) |
| **Coverage Gate (`>=90%`)** | `python3 -W error tests/test_coverage_gate.py --min-coverage 90.0` | Every push / PR | Stdlib `dis` + `trace` statement coverage across `src/diffquorum/*.py` |
| **Adversarial Fuzzing** | `python3 -W error tests/fuzz_diffquorum.py --iterations 2000` | Every push / PR | Optional `atheris` + 2,000-iteration security-invariant fuzzer |
| **Static SAST & Clean-Room** | `CodeQL` + `diffquorum sanitize-lint --target .` | Every push / PR + weekly | `.github/workflows/codeql.yml`, `.github/workflows/ci.yml` |
| **Provenance & SBOM** | Sigstore OIDC `SLSA L3` + `SPDX-2.3` + `REUSE 3.3` | Every push / tag / release | `.github/workflows/attestation.yml`, `REUSE.toml`, `scripts/generate-sbom.py` |
