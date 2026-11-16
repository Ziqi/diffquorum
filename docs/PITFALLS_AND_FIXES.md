# Production Pitfalls & Engineering Fixes (`StarCouncil` Lessons Learned)

Every guardrail in `starcouncil` came from a real failure mode hit while running multi-agent clusters across laptops, headless workstations, and external LLM reviewers. Below are the **6 major pitfalls** and the deterministic fixes built into this toolkit.

---

## 1. The 11-Round Infinite Audit Loop vs. Rubber-Stamping Broken Code

- **What broke**: External reviewers sometimes raised brand-new minor or stylistic concerns every round (burning 11+ rounds of tokens), while capping rounds naively tempted agents to declare "passed at round 2" even when a real blocker remained.
- **Root-cause fix (Round-0 + Two-Round Andon Cord)**:
  1. **Round-0 deterministic check**: Run local unit tests, AST checks, and linters first; fix an entire defect family at once before calling external LLMs.
  2. **Hard 2-round Andon Cord (`PITFALL_HALT`)**: Cap external blind reviews at `<= 2` rounds per `content_tree_hash`. If round 2 still has a real blocker, **halt (`exit 2`), record the root cause to `.starcouncil/pitfalls.md`, never rubber-stamp**, and add a zero-token regression test before starting a clean verification session.
  3. **`OUTAGE_FAIL_CLOSED`**: Network timeouts or 5xx errors return `OUTAGE_FAIL_CLOSED` and block release — never silently pass on outage.

## 2. Single-Model "Fake Multi-Persona Council" Theater

- **What broke**: When asked for a multi-seat decision, a single model inside one session could write a script pretending "Seat A says X, Seat B says Y, consensus reached" without any real cross-seat or independent LLM files ever existing.
- **Root-cause fix (`meetings/<id>/` Anti-Fake-Council Verifier)**:
  - Implemented `council-submit` and `council-verify`: every participant writes an immutable `.md` statement plus `.json` metadata with its `author`, `source_kind`, and `SHA-256` hash.
  - `council-verify` inspects live file hashes on disk (`O_NOFOLLOW`, tamper-checked). `MULTI_SEAT_DECISION` is **only** granted when there are `>= 2` distinct authors, `>= 2` source kinds, and `>= 2` distinct content hashes. Single-source outputs are strictly watermarked `SOLO_SYNTHESIS` or blocked (`exit 2`).

## 3. Silent-ACK Keywords Inside Message Bodies Causing Dropped Wakeups

- **What broke**: Watchers used simple substring checks (`"【TERMINAL-ACK】" in content`) to skip non-actionable completion receipts. Whenever an actionable message quoted that marker inside its explanation paragraph, the watcher skipped it and left the receiving pane asleep indefinitely.
- **Root-cause fix (`is_silent_sync_message`)**:
  - Match silent-sync prefixes **strictly on the first non-empty line** of a message or title — never anywhere in the body prose.

## 4. Missed Fresh-Pane Wakeups vs. Interrupting Human Typing or Plan Approvals

- **What broke**:
  1. Fresh AI CLI panes display faint placeholder text next to the prompt (`>   Ask anything...`), so `line.strip() == ">"` never matched and new sessions stayed dormant.
  2. Injecting `[BUS-WAKE]` + `Enter` while the operator was composing CJK IME text, watching `window_activity` (noisy stdout!), or waiting on an interactive `Approve` plan corrupted user input or triggered unwanted execution.
- **Root-cause fix (`wake_gates.py` 6-Gate State Machine)**:
  - **Prompt tolerance**: Match bare `>` and known placeholder prompts with `cursor_x >= 2` and no busy spinner / approval chrome.
  - **Human typing protection**: Require `#{client_activity} >= 15s` (real keyboard idle, ignoring `window_activity`).
  - **State & daemon guards**: Ignore `isDaemon == True` / `cron (...)` tasks so background watchers don't block wakeups; halt immediately when `status == SEEN_AWAITING_HUMAN`; cap at 2 wake attempts and roll back partial Frame-1 injections using exact `BSpace` counts when Frame-2 `Enter` fails.

## 5. Full-Text Cross-Window Dumps Bloating Context & Workspace Bleed

- **What broke**: Pasting multi-thousand-line specs directly across panes rapidly inflated sessions to `6,000+` steps, triggering aggressive summarization loss. Worse, mounting shared workspaces in global `settings.json` (`additionalDirectories`) leaked unrelated session memory across projects.
- **Root-cause fix (Pointer-Over-Blackboard + `starcouncil doctor`)**:
  - Put full artifacts under `.starcouncil/artifacts/`, keep `BOARD.md < 3KB`, and enforce `< 400B` JSONL pointer envelopes in `inbox/<seat>.jsonl`.
  - `starcouncil doctor` verifies `BOARD.md` & `inbox/*.jsonl` size caps, checks `additionalDirectories == []` in `settings.json`, and flags bloated sessions above `3,500` steps.

## 6. Single-Subscription `429` Parallel Storms & Cross-Machine Daily Noise

- **What broke**:
  1. Spawning 3–4 concurrent subagents on a single consumer subscription triggered `429 RESOURCE_EXHAUSTED` mid-flight.
  2. Broadcasting daily progress between two separate workstations wasted quota and polluted unrelated session history.
- **Root-cause fix (`2x2` Selective Quorum & Serial 3-Lens Mode)**:
  - Under `single-sub`, lock `max_concurrent_agents = 1` and run a sequential 3-lens flow (`Architect -> Bug Auditor -> Plain Summarizer`) via disk artifacts.
  - Keep remote nodes `DO_NOT_DISTURB` for daily business (`cross_host_daily_reporting = false`), inviting them asynchronously (`async_card`, `hop <= 1`, `<= 64KB` ASCII stdin, `shlex.quote`, `60s` ACK silence, and `120s >= 4` / `900s > 6` circuit breakers) only when tags hit shared `arch`, `skill`, or `retro` topics.
