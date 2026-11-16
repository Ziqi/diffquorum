# Contributing to StarCouncil

We welcome concise bug fixes, clean-room regression tests, and ergonomic Skill improvements!

## Rules Before Opening a PR

1. **Zero third-party Python dependencies**: Stick to Python 3.10+ standard library.
2. **Keep Skills thin**: Each `skills/*/SKILL.md` file must stay under `120` lines.
3. **Pass all deterministic checks**:
   ```bash
   python3 -m unittest discover -s tests -v
   python3 scripts/starcouncil.py sanitize-lint --target .
   ```
4. **Document real root causes**: If you fix a subtle multi-agent race or prompt edge case, add a regression test and a brief note to `docs/PITFALLS_AND_FIXES.md`.
