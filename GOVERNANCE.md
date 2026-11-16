# StarCouncil Project Governance & Continuity Charter

> **Version**: `v0.1.1` · **License**: [MIT](./LICENSE) · **Related Policies**: [CONTRIBUTING.md](./CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) · [SECURITY.md](./SECURITY.md)

## 1. Governance Model & Roles

`StarCouncil` follows a transparent **Benevolent Maintainer + Open Contributor** governance model engineered for deterministic multi-agent orchestration tooling:

| Role | Responsibilities & Privileges | Current Roster |
|---|---|---|
| **Lead Maintainer** | Architecture stewardship, security advisory triage, Repository Ruleset administration, cryptographic release signing, and SemVer roadmap (`v0.1.x` → `v0.2.x`). | `@Ziqi` (Ziqi Xiao) |
| **Reviewers / Co-Maintainers** | Reviewing pull requests against clean-room stdlib rules, Skill `<120`-line budgets, and anti-fake-council integrity. | Nominated from contributors with >=3 accepted high-quality PRs |
| **Contributors** | Submitting pull requests, bug reports, regression tests, and security disclosures under the MIT License & DCO. | Open to all community members |

## 2. Developer Certificate of Origin (DCO) & Legal Provenance

1. Every contribution is licensed under the repository's [MIT License](./LICENSE) (SPDX identifier `MIT`).
2. Contributors certify origin under the **Developer Certificate of Origin v1.1 (DCO)** (`https://developercertificate.org/`) by signing off commits (`git commit -s`, adding `Signed-off-by: Name <email>`).
3. Every file is covered by machine-readable SPDX licensing metadata via `REUSE.toml` and `LICENSES/MIT.txt` (`FSFE REUSE 3.3`).

## 3. Change Control & Mandatory Quality Gates

No functional change enters `main` unless all automated CI gates pass cleanly under `python3 -W error`:

1. **Regression & Unit Test Suite**: `python3 -W error -m unittest discover -s tests -v`.
2. **>= 90% Statement Coverage Gate**: `python3 -W error tests/test_coverage_gate.py --min-coverage 90.0` enforces `>= 90%` executable statement coverage across `src/starcouncil/*.py` (`blackboard.py`, `governance.py`, `wake_gates.py`, `cli.py`).
3. **2,000-Iteration Adversarial Fuzz Gate**: `python3 -W error tests/fuzz_starcouncil.py --iterations 2000` stress-tests `<400B` envelopes, `<3KB` board budgets, symlink blocking, SHA-256 anti-fake-council enforcement, and clean-room sanitization.
4. **Clean-Room Sanitize Lint**: `python3 -W error scripts/starcouncil.py sanitize-lint --target .` (`0` host paths, private IPs, or session UUIDs).
5. **Reproducible Build & CodeQL / Scorecard**: `archive --verify`, `generate-sbom.py`, `CodeQL SAST`, and `OpenSSF Scorecard`.

## 4. Access Continuity & Succession Plan (`Bus Factor` Resilience)

To guarantee uninterrupted maintenance, vulnerability patching, and release continuity within **7 days** even if the Lead Maintainer becomes unavailable:

1. **Zero Lock-In Pure-Stdlib Architecture**: `StarCouncil` requires zero external Python packages, zero cloud SaaS runtime dependencies, and uses keyless GitHub OIDC (`Sigstore` / `SLSA Build Level 3`) attestations that require no developer-laptop secret custody.
2. **Succession & Recovery Protocol**:
   - GitHub Account Recovery codes and hardware MFA backup keys are stored in an encrypted offline escrow vault with documented 72-hour handover instructions.
   - GitHub's native **Account Successor** feature is enabled for clean repository stewardship transfer without fork fragmentation.

## 5. Accessibility & Internationalization Standards

- **Bilingual Entrypoints**: Maintained in both **English** ([README.md](./README.md)) and **Simplified Chinese** ([README.zh-CN.md](./README.zh-CN.md)).
- **Accessible CLI Output**: Structured JSON and plain UTF-8 prefixed lines (`[PASS]` / `[FAIL]` / `[INFO]`) require no ANSI color perception and integrate cleanly with screen readers and monochrome CI logs.
