---
name: diffquorum-gate
description: Use before high-risk merges, security/hook changes, or releases, or after hitting any recurring pitfall — runs 0-token local checks first, enforces a hard 2-round Andon halt (no endless loops), and ratchets root fixes into pitfalls.md.
---

# DiffQuorum Gate & Pitfall Ratchet (<100 lines)

<SUBAGENT-STOP>
Fix blockers cleanly at the root cause; never weaken tests or rubber-stamp broken code to force a pass.
</SUBAGENT-STOP>

## Anti-Bureaucracy & Verification Rules

1. **Level 0 for daily work**: Routine local changes run local unit tests (`--level 0`) and ship immediately — zero multi-window audit ping-pong!
2. **Evidence before claims**: Never say "should pass"; run the verification command cleanly first.
3. **Level 1/2 Two-Round Andon Cord (`PITFALL_HALT`)**:
   - Fix an entire defect family locally before invoking external review (`tree-hash` locked).
   - Cap external review at `<= 2` rounds. If blockers remain at round 2, trigger **`PITFALL_HALT` (`exit 2`)**, log root cause into `.diffquorum/pitfalls.md`, and halt instead of burning rounds.
   - Network/5xx outages always return **`OUTAGE_FAIL_CLOSED`**.
4. **Scrub before export & speak plainly**: Run `review --pseudonymize-file` (`HMAC-SHA256`) before sharing paths/IPs externally, log root fixes with `log-fix`, and report via `【结果】/【原因】/【需您操作】`.

## Commands

- Daily local pass: `python3 scripts/diffquorum.py review --root . --level 0 --tree-hash deadbeef1234`
- Release 2-round gate: `python3 scripts/diffquorum.py review --root . --level 2 --tree-hash deadbeef1234 --round 2 --blocker "missing guard"`
- Ratchet fix: `python3 scripts/diffquorum.py log-fix --root . --title "Guard edge" --fix "Validated path prefix" --files "src/guard.py"`
