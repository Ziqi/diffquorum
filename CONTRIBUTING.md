# Contributing to StarCouncil

We welcome concise bug fixes, clean-room regression tests, security hardening, and ergonomic Skill improvements!

## Contribution Standards & DCO Sign-Off

1. **Zero third-party runtime dependencies**: Stick strictly to the Python `>= 3.10` standard library (`dependencies = []` in `pyproject.toml`).
2. **Coding style & strict warnings**: Follow PEP 8, add SPDX headers (`# SPDX-FileCopyrightText: 2026 StarCouncil Contributors` / `# SPDX-License-Identifier: MIT`), keep modules modular and small, and ensure all checks pass under `python3 -W error` (zero warnings treated as errors).
3. **Developer Certificate of Origin (DCO)**: Sign off all commits using `git commit -s` (`Signed-off-by: Name <email>`), certifying you have the right to submit the work under the [MIT License](./LICENSE).
4. **Keep Skills thin**: Each `skills/*/SKILL.md` file must stay under `120` lines.
5. **Mandatory regression tests**: Every bugfix or new behavior must include an automated unit or fuzz test under `tests/`. If you fix a subtle multi-agent race, prompt edge case, or security boundary, also append a short root-cause note to [`docs/PITFALLS_AND_FIXES.md`](./docs/PITFALLS_AND_FIXES.md).

## Local Verification Before Opening a PR

Run the full clean-room verification suite locally (`< 5` seconds):

```bash
python3 -W error -m unittest discover -s tests -v
python3 -W error tests/test_coverage_gate.py --min-coverage 90.0
python3 -W error tests/fuzz_starcouncil.py --iterations 2000
python3 -W error scripts/starcouncil.py sanitize-lint --target .
python3 -W error scripts/starcouncil.py archive --prefix starcouncil --verify
python3 -W error scripts/generate-sbom.py --version local --output /tmp/starcouncil.spdx.json
```
