# Security Policy & Supply-Chain Controls

## 1. Clean-Room & Zero-Dependency Guarantee

`StarCouncil` is strictly zero-dependency (Python `>= 3.10` standard library only — zero third-party `pip` packages) and enforces clean-room hygiene on every commit via CI (`starcouncil sanitize-lint --target .`), blocking host paths, internal/CGNAT IPs (`10.x`, `172.16-31.x`, `192.168.x`, `100.64-127.x`), real UUIDs, and operator-configured forbidden terms.

## 2. Defensive Architecture Controls

1. **Symlink & Traversal Safety**: All state writes use `os.O_NOFOLLOW`, regular-file `S_ISREG` verification, atomic `.tmp` + `os.fsync` + `os.replace`, and `followlinks=False` directory walks.
2. **IPC & Concurrency Mutexes**: `.starcouncil/BOARD.md` (`<3KB`) and `inbox/<seat>.jsonl` (`<400B` per pointer envelope) are serialized with `fcntl.flock` mutexes under `.starcouncil/locks/`, guarded by `event_id` deduplication, a `60s` ACK silence window, and sliding-window resonance circuit breakers.
3. **Remote SSH Hygiene**: Zero `shell=True`; remote commands wrap paths via `shlex.quote` (`BatchMode=yes`, `ForwardAgent=no`), strictly enforce `<= 64KB` 7-bit ASCII JSON over `stdin`, `MAX_HOP = 1`, and explicit TOML host/seat allowlists.
4. **Anti-Fake-Council Integrity**: `council-verify` validates live raw `.md` files against recorded `SHA-256` digests and blocks `MULTI_SEAT_DECISION` unless `>= 2` distinct authors, source kinds, and content hashes exist.
5. **Fail-Closed External Gate & HMAC Pseudonymization**: Outages/timeouts in external review CLIs return `OUTAGE_FAIL_CLOSED` and block approval. `starcouncil review --pseudonymize-file` applies ephemeral `HMAC-SHA256` redaction to host paths and private IPs before any external review export.

Full trust-boundary analysis is documented in [SECURITY_ASSURANCE_CASE.md](./SECURITY_ASSURANCE_CASE.md).

## 3. Supply-Chain Hardening & OpenSSF Alignment

- **Immutable GitHub Actions (`Pinned-Dependencies`)**: All workflows under `.github/workflows/` pin actions to full 40-character commit SHAs with least-privilege `permissions`, `persist-credentials: false`, and weekly `.github/dependabot.yml` monitoring.
- **Static Analysis, Coverage & Fuzzing**: Every push and pull request runs **CodeQL** Python SAST (`.github/workflows/codeql.yml`), **`>= 90%` statement coverage gate** (`tests/test_coverage_gate.py`), **2,000-iteration security-invariant fuzzing** (`tests/fuzz_starcouncil.py`, supporting Google `atheris`), and **OpenSSF Scorecard** (`.github/workflows/scorecard.yml`).
- **Sigstore `SLSA Build Level 3` Provenance & `SPDX-2.3` SBOM**: Automated GitHub OIDC provenance and `SPDX-2.3` SBOM attestations are published at [`github.com/Ziqi/starcouncil/attestations`](https://github.com/Ziqi/starcouncil/attestations), paired with bit-for-bit reproducible source tarballs (`starcouncil archive --verify`), detached Ed25519 signatures (`.sig`), and signed in-toto DSSE bundles (`.intoto.jsonl`). Verify release signatures with the official Ed25519 public key:
  ```pem
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VwAyEAxuIA6FCv17guUFZfrXZuTB+erFYRwrm2Lof3/hzm/HM=
  -----END PUBLIC KEY-----
  ```
  ```bash
  openssl pkeyutl -verify -pubin -inkey release_ed25519_pub.pem \
    -rawin -in starcouncil-v0.1.1.tar.gz -sigfile starcouncil-v0.1.1.tar.gz.sig
  ```
- **FSFE `REUSE 3.3` Licensing**: Repository-wide SPDX compliance declared via `REUSE.toml` and `LICENSES/MIT.txt`.

## 4. Reporting a Vulnerability (Coordinated Disclosure & SLA)

Please do **not** open public GitHub issues for security vulnerabilities (such as symlink bypasses, `sanitize-lint` evasions, or SSH command quoting flaws). Report privately via GitHub Private Security Advisories:

- **Channel**: [`https://github.com/Ziqi/starcouncil/security/advisories/new`](https://github.com/Ziqi/starcouncil/security/advisories/new)
- **Initial Acknowledgement SLA**: Within **48 hours**.
- **Triage & Remediation Target**: Within **14 days** for critical/high-severity issues (maximum coordinated embargo **90 days**).
- **Reporter Credit**: Verified reporters receive public credit in `CHANGELOG.md` and the published GitHub Security Advisory unless anonymity is requested.
