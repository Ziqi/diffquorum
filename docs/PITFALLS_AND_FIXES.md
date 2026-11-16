# Production Pitfalls & Engineering Fixes (`DiffQuorum` Lessons Learned)

Every guardrail in `diffquorum` came from a real failure mode hit while running multi-agent clusters across laptops, headless workstations, and external LLM reviewers. Below are the **8 major pitfalls** and the deterministic fixes built into this toolkit.

---

## 1. The 11-Round Infinite Audit Loop vs. Rubber-Stamping Broken Code

- **What broke**: External reviewers sometimes raised brand-new minor or stylistic concerns every round (burning 11+ rounds of tokens), while capping rounds naively tempted agents to declare "passed at round 2" even when a real blocker remained.
- **Root-cause fix (Round-0 + Two-Round Andon Cord)**:
  1. **Round-0 deterministic check**: Run local unit tests, AST checks, and linters first; fix an entire defect family at once before calling external LLMs.
  2. **Hard 2-round Andon Cord (`PITFALL_HALT`)**: Cap external blind reviews at `<= 2` rounds per `content_tree_hash`. If round 2 still has a real blocker, **halt (`exit 2`), record the root cause to `.diffquorum/pitfalls.md`, never rubber-stamp**, and add a zero-token regression test before starting a clean verification session.
  3. **`OUTAGE_FAIL_CLOSED`**: Network timeouts or 5xx errors return `OUTAGE_FAIL_CLOSED` and block release — never silently pass on outage.

## 2. Single-Model "Fake Multi-Persona Quorum" Theater

- **What broke**: When asked for a multi-seat decision, a single model inside one session could write a script pretending "Seat A says X, Seat B says Y, consensus reached" without any real cross-seat or independent LLM files ever existing.
- **Root-cause fix (`meetings/<id>/` Anti-Fake-Quorum Verifier)**:
  - Implemented `quorum-submit` and `quorum-verify`: every participant writes an immutable `.md` statement plus `.json` metadata with its `author`, `source_kind`, optional `--diff-sha256`, and `SHA-256` hash.
  - `quorum-verify` inspects live file hashes on disk (`O_NOFOLLOW`, tamper-checked). `MULTI_SEAT_DECISION` is **only** granted when there are `>= 2` distinct authors, `>= 2` source kinds, and `>= 2` distinct content hashes. Single-source outputs are strictly watermarked `SOLO_SYNTHESIS` or blocked (`exit 2`).

## 3. Silent-ACK Keywords Inside Message Bodies Causing Dropped Wakeups

- **What broke**: Watchers used simple substring checks (`"【TERMINAL-ACK】" in content`) to skip non-actionable completion receipts. Whenever an actionable message quoted that marker inside its explanation paragraph, the watcher skipped it and left the receiving pane asleep indefinitely.
- **Root-cause fix (`is_silent_sync_message`)**:
  - Match silent-sync prefixes **strictly on the first non-empty line** of a message or title — never anywhere in the body prose.

## 4. Missed Fresh-Pane Wakeups vs. Interrupting Human Typing or Plan Approvals

- **What broke**:
  1. Fresh AI CLI panes display faint placeholder text next to the prompt (`>   Ask anything...`), so `line.strip() == ">"` never matched and new sessions stayed dormant.
  2. Injecting `[BUS-WAKE]` + `Enter` while the operator was composing CJK IME text or watching `window_activity` corrupted user input.
- **Root-cause fix (`wake_gates.py` 6-Gate State Machine)**:
  - **Prompt tolerance**: Match bare `>`, Codex `›`, and placeholder hints with `cursor_x >= 2`.
  - **Human typing protection**: Require `#{client_activity} >= 15s` (real keyboard idle, ignoring `window_activity`).
  - **State & daemon guards**: Ignore `isDaemon == True` / `cron (...)` tasks so background watchers don't block wakeups; halt immediately when `status == SEEN_AWAITING_HUMAN`; cap at 2 wake attempts and roll back partial Frame-1 injections using exact `BSpace` counts when Frame-2 `Enter` fails.

## 5. Full-Text Cross-Window Dumps Bloating Context & Workspace Bleed

- **What broke**: Pasting multi-thousand-line specs directly across panes rapidly inflated sessions to `6,000+` steps, triggering aggressive summarization loss. Worse, mounting shared workspaces in global `settings.json` (`additionalDirectories`) leaked unrelated session memory across projects.
- **Root-cause fix (Pointer-Over-Blackboard + `diffquorum doctor`)**:
  - Put full artifacts under `.diffquorum/artifacts/`, keep `BOARD.md < 3KB`, and enforce `< 400B` JSONL pointer envelopes in `inbox/<seat>.jsonl`.
  - `diffquorum doctor` verifies `BOARD.md` & `inbox/*.jsonl` size caps, checks `additionalDirectories == []` in `settings.json`, and flags bloated sessions above `3,500` steps.

## 6. Single-Subscription `429` Parallel Storms & Cross-Machine Daily Noise

- **What broke**:
  1. Spawning 3–4 concurrent subagents on a single consumer subscription triggered `429 RESOURCE_EXHAUSTED` mid-flight.
  2. Broadcasting daily progress between two separate workstations wasted quota and polluted unrelated session history.
- **Root-cause fix (`2x2` Selective Quorum & Serial 3-Lens Mode)**:
  - Under `single-sub`, lock `max_concurrent_agents = 1` and run a sequential 3-lens flow (`Architect -> Bug Auditor -> Plain Summarizer`) via disk artifacts.
  - Keep remote nodes `DO_NOT_DISTURB` for daily business (`cross_host_daily_reporting = false`), inviting them asynchronously (`async_card`, `hop <= 1`, `<= 64KB` ASCII stdin, `shlex.quote`, `60s` ACK silence, and `120s >= 4` / `900s > 6` circuit breakers) only when tags hit shared `arch`, `skill`, or `retro` topics.

## 7. Read-Only Sandbox & Auth-State Traps Wasting Worker Launches (`preflight`)

- **What broke**: Dispatching headless CLI workers (`agy`, `claude`, `codex`) before verifying target-directory writeability or CLI state directories failed mid-run (`operation not permitted` writing `installation_id` or blocked repo writes) after burning planning tokens.
- **Root-cause fix (`diffquorum preflight`, `<1s` Zero-Token Check)**:
  - Run `O_NOFOLLOW` temp-file write probes on target paths, check `.diffquorum/locks/*.holder.json` contention, confirm CLI binaries via `shutil.which`, and verify writable `~/.gemini/antigravity-cli` when `--cli agy` is requested — failing fast (`exit 2`) before dispatching workers.

## 8. Stage-2 Model-Brand Bias & TUI Approval Modals Masking Idle Prompts

- **What broke**:
  1. Peer reviewers seeing raw author/model names favored their own family or rubber-stamped strong brands.
  2. Terminal UIs printed ANSI color/cursor escapes (`\x1b[32m`, `\x1b[3C`), Unicode `…` spinners (`Working…`), or interactive trust/permission modals (`Yes, I trust this folder`, `↑/↓ to navigate`) directly above an idle `>` line, tricking naive tail regexes.
- **Root-cause fix (`quorum-blind` + `strip_terminal_escapes` + `WAITING_MODAL_RE`)**:
  - `quorum-blind` anonymizes Stage-2 submissions into `Peer A / Peer B / Peer C` (`blind_packet.md`) while keeping `reveal_map.json` local until scoring finishes.
  - `wake_gates.py` runs `strip_terminal_escapes()`, matches Unicode `…` spinners, and scans the bottom 10 lines for `WAITING_MODAL_RE` **before** allowing any idle prompt match (`WAITING_USER_ANSWER`).
