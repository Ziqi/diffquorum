# Production Pitfalls & Engineering Fixes (`DiffQuorum` Lessons Learned)

Every guardrail in `diffquorum` came from a real failure mode hit while running multi-agent clusters across laptops, headless workstations, and external LLM reviewers. Below are the **15 major pitfalls** and the deterministic fixes built into this toolkit.

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

## 9. Mobile Narrow-Screen Status Bars & Deep-Thinking >30s False `IDLE` (`PF-018` / `PF-025`)

- **What broke**:
  1. On ~50–55 column mobile terminals, `? for shortcuts` was truncated from the left, leaving only `auto · Model ... · /tasks`, which caused idle-prompt gates to miss wakeups.
  2. Fleet dashboards relying solely on `transcript.jsonl` mtime `< 30s` mislabeled agents deep-thinking for >30s as `IDLE` even while the live TUI footer clearly displayed `esc to cancel` and braille spinners (`⡿`).
- **Root-cause fix (`is_idle_cli_footer` + `is_pane_tail_busy`)**:
  - Recognize structured narrow-screen CLI footers while still rejecting busy markers and interactive modals.
  - Inspect the last 8 non-empty stripped lines of active CLI panes (`capture-pane -p -S -8`) for live chrome (`esc to cancel`, `esc to interrupt`, braille spinners `U+2800..U+28FF`, or active status lines) without false-triggering on ordinary prose.

## 10. Copy-Mode Masking `WAIT_APP` & Blocked Pending Tickets Expiring After 2h (`PF-021` / `PF-022`)

- **What broke**:
  1. When a pane was parked on an approval prompt AND scrolled into tmux `copy-mode`, mutually exclusive state labels hid `copy-mode` behind `WAIT_APP`.
  2. Sharing a 2-hour wakeup TTL between transient chat messages and persistent `PENDING` tickets caused tickets blocked overnight by `copy-mode` or unsent prompt drafts to go permanently dormant once 2 hours elapsed.
- **Root-cause fix (`classify_seat_state` + Decoupled Wake TTLs)**:
  - Render strict 8-character compound states (`WAIT+CPY`, `WORK+CPY`) alongside `[CPY]` alert tags so mobile dashboards stay aligned at 50 columns without hiding lock causes.
  - Decouple `MAX_MESSAGE_WAKE_AGE_SECONDS = 7200` (2h) from `MAX_TICKET_WAKE_AGE_SECONDS = 86400` (24h), preserving `MAX_WAKE_ATTEMPTS_PER_MSG = 2` and zero-cost skips while blocked by Gate 1–3.

## 11. Secret-Scrubbed 0-Token Probes, Zero-Delete Ledger Folding & AST Blind Bundles (`PF-019` / `PF-020`)

- **What broke**:
  1. External CLI probes inheriting `*_API_KEY` / `*_TOKEN` or lacking `stdin=DEVNULL` + hard timeouts could stall agents or risk unintended paid calls.
  2. Unbounded append-only ledgers grew past `100KB+`, inflating every session's cache reads, while naive cleanup scripts risked empty-path deletion (`Path(".")`).
  3. Blind reviewers auditing a single modified file missed subtle bugs in local imported helpers.
- **Root-cause fix (`ops.py`: `routine`, `curate`, `hud`, `bundle-ast`)**:
  - `diffquorum routine` strips all secret/API-key env vars, enforces `stdin=DEVNULL` + strict timeout, and writes atomic `O_NOFOLLOW` `0600` JSON.
  - `diffquorum curate` contains **zero delete/unlink code paths** (AST-enforced), writes a SHA-256 read-back-verified whole-file `.snapshot.txt` + append-only `MANIFEST.tsv`, and preserves `<!-- PIN -->` blocks plus newest entries under budget.
  - `diffquorum hud` enforces zero `send-keys` / `switch-client` (eliminating mobile mis-taps), aligned dual-host tables, and auto-collapsing `[ACTIVE TASKS]` in `<=50` columns.
  - `diffquorum bundle-ast` statically resolves local Python imports via `ast.parse()` (zero code execution, symlink/escape blocked) so blind reviewers receive complete context.

## 12. Fail-Closed Spoken Approvals & Cross-Seat Revocation Scoping (`PF-023` / `PF-024`)

- **What broke**:
  1. Overly narrow English-only approval regexes missed unambiguous spoken confirmations, while global revocation regexes let a directive cancelling an unrelated seat (e.g., shelving seat `99`) falsely revoke an approved ticket targeting seat `02`.
  2. Restarting multi-account CLI sessions without checking the active OS Keychain account risked cross-account quota bleed, and remote headless nodes without independent Wi-Fi self-healing could drop offline for hours.
- **Root-cause fix (`is_explicit_approval_text` + `revocation_applies_to_scope` + Ops Guardrails)**:
  - Keep approval matching strictly Fail-Closed (blocking questions, negations, conditionals, hedges, and follow-up restrictions).
  - Evaluate later revocations clause-by-clause: **revoke by default** unless every revoking clause has zero global-scope words (`all`/`全部`/`其余`) AND explicitly names only unrelated seats (excluding unit-suffixed numbers like `99%`).
  - Isolate remote node Wi-Fi recovery in a Keychain-backed root watchdog (zero plaintext passwords) and always verify the active OS Keychain account before cold-restarting cross-account agent seats.

## Wave C Operational Safeguards (`v0.3.0-dev`)

- **Pending-Plan Collision Lock (`diffquorum plan`)**: Prevents competing approval drafts on the same logical `scope` via an atomic `0600` + `flock` ledger (`WAITING_APPROVE` -> `APPROVED | SUPERSEDED | CANCELLED`).
- **Leading-Prefix Silent Tags & Orthogonal `REPORT-NO-REPLY`**: Matches `TERMINAL-ACK` / `INFO-SYNC` strictly at the start of the first non-empty line (never mid-sentence), exempts `P0` emergencies from silence, and caps `REPORT-NO-REPLY` handoffs at a single wakeup while guaranteeing terminal ticket (`WAITING_REVIEW | DONE | BLOCKED`) receipt delivery.
- **Anti-Stall Mobile & Daemon Hardening**: Recognizes ultra-narrow mobile status footers (`⏵⏵ auto mode`, `? for short…`), string/bool `isDaemon` tasks, bounded `P0/P1` ticket backoff `(30s, 60s, 180s)`, stale `copy-mode` auto-exit (`>=180s` idle on unprotected sessions), and multi-sentence trailing approvals.
- **Zero-Token Pre-Invocation Pending-Plan Injection & Own/Peer Split**: Pure read-only `O_NOFOLLOW` (`<=16KB`) `rev`-reconciled reader (`build_pre_invocation_pending_banner` & `format_pending_plans_bar`) emits `0` bytes when idle and injects a single `own:X | peers:Y | total:Z` summary with optional seat-level title redaction when active, eliminating stale-memory '0 pending items' omissions across seats.

## 13. Asymmetric Multi-Seat Hook Allowlists & Headless Blind-Review Tool Deadlocks

- **What broke**:
  1. **Asymmetric `PreToolUse` Hook Allowlists**: When a new `0-Token` coordination subcommand (`plan open | list | close`) was rolled out across a fleet, any seat carrying a customized per-seat `PreToolUse` hook that did not symmetrically allow `plan` got blocked by its own guard and silently skipped pending-plan registration — blinding the fleet-wide approval board.
  2. **Headless Blind-Review Tool Loops & Server-Side Social/X-Search Stalls**: Invoking an external headless LLM CLI for independent diff review without explicitly stripping built-in file/web/social tools (`--disallowed-tools` or `--tools ""`), passing only `--disable-web-search` (which leaves server-side social/X search tools like `x_keyword_search` / `x_user_search` / `x_semantic_search` active!), or including live search trigger phrases in the review prompt caused headless runs to enter multi-minute tool loops and hit hard `300s` wall-clock timeouts.
- **Root-cause fix (`validate_plan_hook_command` + `build_headless_review_argv` / `validate_headless_review_spec`)**:
  - Share a single deterministic validator (`validate_plan_hook_command`) across every seat's `PreToolUse` hook so `plan list` (`allow_readonly`) and `plan open | close` (`allow_mutate`) are allowed symmetrically everywhere while failing closed on shell metacharacters or `--plans-file` / `--root` target-override flags.
  - Enforce explicit full tool stripping (`--tools ""` / `--no-tools`, optionally paired with `--system-prompt-override`, or `--disallowed-tools` explicitly covering `x_keyword_search,x_user_search,x_semantic_search`), fail closed when `--disable-web-search` is used without also stripping server-side social/X search tools, reject live web/social search trigger phrases in blind-review prompts, and bound per-chunk prompt size and finite timeout strictly below `300s`.

## 14. Multi-Model Talking-Shop Drift & Line-Count Review Misallocation (`D0–D2` + `R0–R3`)

- **What broke**:
  1. Inviting multiple LLMs to debate open-ended product/architecture topics without a concrete strawman or round cap degraded into multi-round talking shops, while routing lightweight models onto critical design tables caused shallow mistakes.
  2. Gating reviews by raw diff line count wasted tokens auditing 200-line copy/label syncs while under-auditing 5-line changes touching billing/coupons, authentication/multi-tenant privacy (IDOR), core ranking/accounting math, or persistent schema migrations.
- **Root-cause fix (`policy.py`: `discuss-check` & `route-risk`)**:
  - **Front-door `D0–D2` single-round cap**: `D0` (`0` external advisors), `D1` (`1` matched specialist, `<= 1` round), `D2` (concrete strawman first, `<= 2` distinct cross-family blind advisors for `1` round; optional tie-breaker only on direct conflict; lightweight models blocked from decision tables).
  - **Back-door `R0–R3` blast-radius routing**: `R0` (offline/read-only `<5s`), `R1` (pure-copy fast lane requiring all 5 zero-logic/storage/auth/route/CSS-bloat invariants -> auto-escalates to `R2` if any fails), `R2` (spec + `1` cross-family blind reviewer, `<= 2` rounds), `R3` (4 critical blast-radius domains -> `>= 2` distinct cross-family blind reviewers in parallel + independent recomputation/negative-security tests).

## 15. Post-Hoc Self-Confirmation on Failed Experiments & Cross-Repo Terminology Drift (`Fold-A/B` M&M + `Master Dict`)

- **What broke**:
  1. Asking a single model to explain why a pre-registered experiment failed on the full diagnostic dataset produced persuasive post-hoc stories that hypothesized and "validated" on the exact same data slice (confirmation bias & holdout leakage).
  2. Maintaining terminology, versions, and forbidden public jargon manually across multiple repositories and bilingual docs caused silent copy drift and dual-SSOT conflicts.
- **Root-cause fix (`policy.py`: `mm-verify`, `partition_ab_folds` & `dict-check`)**:
  - **Double-blind `Fold-A / Fold-B` M&M Autopsy**: Strictly offline research retrospective (`is_release_gate=false`, `autopsy_round=1`, zero holdout overlap). Splits diagnostic blocks into disjoint odd `Fold-A` (exposed to `>= 2` distinct cross-family blind diagnosticians with zero author bias) and sealed even `Fold-B`; requires `1..3` falsifiable hypotheses per diagnostician with fixed `SHA-256` receipts and `1..3` zero-retrain `Fold-B` probes (`<= 300s` each, Holm/Bonferroni/BH-FDR `alpha <= 0.05`).
  - **Machine-readable `Master Dict` drift guard (`diffquorum dict-check`)**: Validates a single JSON SSOT (`O_NOFOLLOW`, bounded read), rejects dual-SSOT delegation conflicts, verifies canonical token presence across declared files, and scans target trees (`followlinks=False`) for forbidden public jargon, retired phrases, and `emoji_count == 0` invariants.

## 16. Stale Non-Daemon Background Drawer Task Wakeup Deadlock (`is_stale_bg_quiescent_for_unblock`)

- **What broke**: A non-daemon shell command (such as an orphaned `ssh ... tail -f` monitor) hung silently inside an agent's background task drawer long after the agent's own turn (`PLANNER_RESPONSE:DONE`) had finished. Because Gate 3/4 treated every non-daemon `RUNNING` entry as active work, the seat stayed permanently deadlocked on `NON_DAEMON_TASK_RUNNING` (`code=BG`) for hours and ignored incoming high-priority `[BUS-WAKE]` tickets.
- **Root-cause fix (`wake_gates.py`: `is_stale_bg_quiescent_for_unblock`)**: Exempt a hung non-daemon background task from Gate 3/4 blocking **only** when BOTH the transcript AND every regular `.log`/`.json` background task artifact have had zero writes for `>= 180s` (`STALE_BG_TASK_UNBLOCK_SECONDS`, failing closed on symlinks, non-regular files, and any active log `< 180s`). Actively running jobs remain 100% protected while zombie background commands stop deadlocking cross-seat wakeups.

## 17. Silent Pending-Decision Drift, 16KB Read-Cap Cutoff & Flat vs Grouped `hooks.json` Schema (`plan_lock.py`)

- **What broke**: Across multi-seat fleets, pending human decisions silently disappeared from dashboards and turn-start banners for five compounding reasons:
  1. `plan open` only registered formal `PLAN` drafts, leaving `DECISION`, `CIRCUIT_BREAKER`, and `INPUT_REQUIRED` pauses invisible to the shared ledger and HUD.
  2. Closing a plan on `Approve` then pausing mid-execution on a follow-up question or circuit breaker had no atomic `plan reopen` transition.
  3. Read-only `PreInvocation` / HUD readers capped `pending_plans.json` at `16 KiB`, so as soon as historical closed plans pushed the file above `16 KiB` (e.g., ~30+ entries), every reader silently returned `None` (`0` pending items) with no warning.
  4. Lifecycle `hooks.json` files sometimes wrapped flat events (`SessionStart`, `PreInvocation`, `PostInvocation`, `Stop`) inside `{matcher, hooks}` groups meant only for `PreToolUse`/`PostToolUse`, silently disabling the hook on startup.
  5. Without a turn-end `Stop` consistency gate, an agent could still emit "awaiting your approval" with `own_waiting == 0` or a stale "0 pending" footer while open items existed.
- **Root-cause fix (`plan_lock.py`, `cli.py`, `wake_gates.py`)**:
  - Extended `plan open` / `plan list` with `--kind {PLAN,DECISION,CIRCUIT_BREAKER,INPUT_REQUIRED}` (`[DEC]/[CB]/[INP]` badges), added atomic in-place `plan reopen` (zero visibility gap + cross-seat collision check), and bounded retained closed history to the latest `200` items while never dropping any `WAITING_APPROVE` record.
  - Raised read-only `PENDING_PLANS_MAX_READ_BYTES` from `16 KiB` to `512 KiB` with bounded chunked reads, and allowed `plan reopen` + `~/bin/` in `validate_plan_hook_command`.
  - Added `evaluate_stop_consistency_gate` (fires ONLY on `NO_TOOL_CALL` + `fully_idle`, strips fenced/inline code before matching human-pause cues, catches false-zero own/peer footers, enforces a hard `continuation_active` 1-retry anti-loop guard, and supports `readonly_auto_register` for shell-less seats) plus `validate_hooks_json_schema` (enforcing flat vs grouped event schemas) and Gate 4 `has_waiting_pending_plan` wakeup protection.
