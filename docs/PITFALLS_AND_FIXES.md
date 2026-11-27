# Production Pitfalls & Engineering Fixes (`DiffQuorum` Lessons Learned)

Every guardrail in `diffquorum` came from a real failure mode hit while running multi-agent clusters across laptops, headless workstations, and external LLM reviewers. Below are the **24 major pitfalls** and the deterministic fixes built into this toolkit.

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
- **Zero-Token Pre-Invocation Pending-Plan Injection & Own/Peer Split**: Pure read-only `O_NOFOLLOW` (`<=512KB`) `rev`-reconciled reader (`build_pre_invocation_pending_banner` & `format_pending_plans_bar`) emits `0` bytes when idle and injects a single `own:X | peers:Y | total:Z` summary with optional seat-level title redaction when active, eliminating stale-memory '0 pending items' omissions across seats.

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

## 18. Post-Launch Blind Eval Context Leaks, Non-Code Flagship Drift & Space-Separated Approvals (`policy.py` & `wake_gates.py`)

- **What broke**:
  1. Teams either skipped post-launch cold-start user testing completely or handed internal source trees/localhost drafts to evaluators — leaking builder blind spots and turning post-launch UX checks into blocking release loops.
  2. Non-code flagship commercial deliverables (client proposals, pricing decks, executive launches) bypassed `R3` dual-blind rigor because blast-radius rules only listed code domains.
  3. Natural space-separated operator confirmations combining an affirmative selection with a trailing approval (e.g., `"Option A looks good, rest approve"` / `"方案A比较好 其他 approve"`) failed sentence-level regex matching when no period separated the two clauses.
- **Root-cause fix (`evaluate_post_launch_blind_eval` / `blind-eval-check`, `R3_CRITICAL_DOMAINS`, `is_explicit_approval_text`)**:
  - Extended `R3_CRITICAL_DOMAINS` with `commercial_flagship_deliverable` so flagship non-code proposals receive the same parallel dual-blind `R3` rigor as critical code.
  - Added Stage-3 `B0–B2` post-launch zero-context blind evaluation (`diffquorum blind-eval-check`): strictly non-blocking (`is_blocking_live_service=False`), capped at `1` round feeding directly into the next-version backlog, requiring `leaked_internal_context=False`, a genuine public HTTP(S) URL or `public-artifact:<slug>` entrypoint (rejecting `localhost`, loopback, RFC1918/CGNAT/link-local/Fake-IP ranges, `file://`, and local paths), distinct cross-family evaluators, and zero lightweight models.
  - Upgraded `is_explicit_approval_text` with a fail-closed space/comma clause splitter (`TRAILING_REST_APPROVAL_SPLIT_RE`) that accepts affirmative `<selection> 其他/其余 approve` phrasing while immediately rejecting any negation, restriction (`除了`/`只做`/`先别`), question, or revocation.

## 19. Stale Cross-Window Pending Snapshots & Cross-Workspace Hook Bleed (`plan_lock.py`)

- **What broke**:
  1. **Stale Cross-Window Pending-List Snapshots**: Printing the entire fleet's pending-approval list at the end of every worker seat's turn meant idle panes immediately displayed outdated counts whenever another seat got approved — creating conflicting pending tallies across windows and noisy token overhead.
  2. **Cross-Workspace `--add-dir` Hook Bleed**: Launching a worker session with a sibling workspace mounted via `--add-dir` loaded the sibling workspace's local `PreToolUse` hooks into the wrong seat and unexpectedly blocked legitimate own-workspace shell commands.
- **Root-cause fix (`build_pre_invocation_pending_banner` & `evaluate_stop_consistency_gate` `report_scope`)**:
  - Added role-scoped pending reporting (`report_scope="fleet" | "line" | "self"`, `line_seats`, `line_label`) while keeping the underlying `pending_plans.json` ledger and real-time terminal HUD 100% fleet-wide:
    - **`fleet`** (global coordinator): receives full `own` vs `peers` split and validates both own and peer false-zero footers;
    - **`line`** (domain lead): receives only its own `line_seats` rollup (appending `outside:N` only while `line_total > 0`, returning `""` 0 bytes when its own line has `0` open items) and validates false-zero footers only against `own` + `line_peer_waiting_count`;
    - **`self`** (execution workers): receives only its own open items (`""` 0 bytes when `own == 0`), omits peer lists from footers, and validates only own unregistered pauses (`Intercept A`) and own false-zero footers — eliminating cross-window snapshot drift.
  - Keep per-seat launch configurations strictly free of cross-workspace `--add-dir` mounts to peer hook-bearing directories; when renaming seats, preserve original physical birth directories via POSIX symlinks + session rename and hand any cross-boundary cutover command to the operator rather than weakening guards.

## 20. Silent Same-Seat `SUPERSEDED` Swallowing, Half-Turn Footer Drift & Colloquial Decision Misses (`plan_lock.py` & `cli.py`)

- **What broke**:
  1. **Silent Same-Seat Plan Swallowing**: Previously, `plan open` on a seat that already held a `WAITING_APPROVE` record on the same scope silently overwrote the earlier pending plan to `SUPERSEDED`. Whenever one seat legitimately submitted two related items under a broad scope, the first awaiting approval disappeared without operator sign-off.
  2. **Half-Turn `PreInvocation` Lag**: `PreInvocation` fires at the start of a turn before the agent calls `plan open` or `plan close` mid-turn. Relying solely on the turn-start banner caused agents to print stale counts in their trailing footer even right after mutating `pending_plans.json`.
  3. **Colloquial Decision Phrases Slipping Past `Stop`**: Operators and agents frequently pause with conversational phrasing (e.g., `"怎么来定"` / `"选哪个"` / `"是否可行"` / `"要不要一起"` / `"确认后推进"`) that bypassed formal-only decision regexes.
- **Root-cause fix (`open_pending_plan`, `reopen_pending_plan`, `render_live_pending_footer_markdown`, `_STOP_WAIT_DECISION_RE`)**:
  - **Coexistence by default + explicit `--supersede`**: Removed automatic same-seat `SUPERSEDED` overwriting in `plan open` and `plan reopen`. Colliding same-seat scopes automatically receive bounded suffixes (`<scope>-2`, `<scope>-3`, <= 120 chars) so multiple open items coexist safely; replacing an earlier item requires explicit `--supersede PLN-YYYYMMDD-NNN` validated atomically (format, existence, `WAITING_APPROVE` state, and seat/governance authorization) before any mutation occurs.
  - **Exact `live_footer_markdown` on every `plan` command**: `plan open | list | reopen | close` now compute and return a ready-to-paste role-scoped `live_footer_markdown` (`fleet` / `line` / `self`, honoring sensitive-seat redaction) directly from the post-write state, eliminating half-turn footer drift.
  - **Expanded colloquial `Stop` decision cues**: Extended `_STOP_WAIT_DECISION_RE` to catch everyday Chinese decision-pause phrasing while still stripping fenced/inline code blocks first so technical explanations never false-trigger.

## 21. Cross-Workspace `--add-dir` Hook Bleed & Multi-Line Onboarding Drift (`plan_lock.py`)

- **What broke**: When onboarding a new business-line cluster, mounting a sibling seat's workspace via `--add-dir <sibling-workspace>` caused the CLI runtime to inherit the sibling directory's local `PreToolUse` hooks — unexpectedly denying legitimate shell commands inside the new seat's own workspace. Meanwhile, ad-hoc manual setup across new seats easily drifted on symlink conventions, flat vs grouped `hooks.json` schemas, or missing shared helper binaries.
- **Root-cause fix (`audit_launch_args_for_hook_bleed` + `validate_hooks_json_schema`)**:
  - Added deterministic `audit_launch_args_for_hook_bleed(launch_argv, own_workspace=..., peer_workspaces=...)` to inspect `--add-dir` / `--additional-dir` arguments, failing closed on missing values, mounts overlapping any peer workspace, or external directories carrying local hook manifests (`.agents/hooks.json`, `.gemini/hooks.json`, `.claude/settings.json`).
  - Pair launch-arg auditing with `validate_hooks_json_schema` in a single-command read-only onboarding verifier so new business lines launch clean-room without cross-seat hook contamination.

## 22. Top-Level CLI Agent `send_message` Dormancy & Overnight 2h Modal Expiry (`wake_gates.py`)

- **What broke**:
  1. Native reactive wakeup inside an AI CLI runtime only wakes parent/child subagents sharing one process tree; independent top-level `tmux` CLI sessions communicating via `send_message` stayed dormant unless a host watcher injected `[BUS-WAKE]`.
  2. When a passive post-turn CLI survey modal (matched conservatively by `WAITING_MODAL_RE` to avoid corrupting unknown TUI prompts) stayed on screen overnight, peer completion notices (`【REPORT-NO-REPLY】` / `【交卷免回】`) aged past the 2-hour plain-chat wakeup TTL (`7200s`) and were silently dropped once the operator cleared the modal the next morning.
- **Root-cause fix (`scan_native_message_events_cursor`)**:
  - Added a persistent-cursor, 5.5s-debounced bridge (`scan_native_message_events_cursor`) over structured `NATIVE_SEND_MESSAGE` audit events carrying strictly boolean `is_silent` and orthogonal `is_report_no_reply` flags (zero message prose stored or echoed).
  - Grants actionable native peer events a `24h` (`86400s`) survival window (`MAX_NATIVE_EVENT_WAKE_AGE_SECONDS`) without relaxing the 2-hour plain-chat TTL, coalesces bursts (`<= 30s` cap), skips silent/self/unknown/already-woken/already-consumed events, and advances `next_cursor_seq` strictly across contiguous resolved sequence numbers so modal-blocked events wake cleanly the moment all 6 safety gates clear.

## 23. macOS Multi-Desktop Terminal Orchestration & `tmux` Window-Name Desync

- **What broke**:
  1. With macOS Mission Control's `"Automatically rearrange Spaces based on most recent use"` (`mru-spaces`) enabled, switching terminal desktops dynamically reshuffled Space indices and broke spatial muscle memory across multi-seat windows.
  2. Placing a terminal in native macOS Full-Screen mode skipped Desktop slots during Mission Control jumps, and running `tmux rename-session` without pairing `tmux rename-window` left retired legacy window names (`#W`) visible in terminal tabs and HUD headers.
- **Root-cause fix (Deterministic Multi-Desktop & Session Rename Hygiene)**:
  - Keep `com.apple.dock mru-spaces` disabled (`false`) and use maximized non-fullscreen windows per logical business line so Desktop indices remain strictly pinned.
  - Whenever renaming a live `tmux` seat session, always pair `tmux rename-session` with `tmux rename-window -t "=<session>:0" <short-name>` and keep the logical seat symlink path as the primary `cwd` on future spawns while preserving the underlying physical directory (`PF-001`) so active session transcripts never lose continuity.

## 24. Hookless Multi-Directory Seat Blind Spots & Cross-Hook `send_message` Duplication (`wake_gates.py` / `plan_lock.py`)

- **What broke**:
  1. Multi-directory seats (such as training or cross-repo engineering seats intentionally deployed without a restrictive workspace `.agents/hooks.json`) and custom-guard isolated seats did not invoke the central workspace `PreToolUse` guard, leaving their peer `send_message` calls absent from `events.jsonl` and excluded from the `24h` persistent-cursor wakeup bridge (`scan_native_message_events_cursor`).
  2. Naively adding a broad global `PreToolUse` hook (`"matcher": ".*"`) would intercept `write_file`/`edit_file`/`run_command` across hookless multi-directory seats, while adding a `send_message` global hook without cross-hook idempotency would write duplicate `#seq` entries on seats carrying both workspace and global hooks.
  3. Uniform fleet audits that demanded the exact same clean-room guard on hubs, isolated seats, and multi-directory seats produced false negatives on legitimate heterogeneous fleets.
- **Root-cause fix (`classify_native_message_flags` + `should_dedup_native_message_event` + `has_send_message_pretool_hook` + `audit_seat_hook_contract`)**:
  - **Strict `send_message`-Only Global `PreToolUse` Redline**: `has_send_message_pretool_hook` verifies an enabled global `PreToolUse` entry matches `send_message` while failing closed if ANY enabled global `PreToolUse` matcher intercepts `write_file`, `edit_file`, or `run_command`.
  - **Cross-Hook `2.0s` Atomic Dedup**: `should_dedup_native_message_event` deduplicates `(from_conv_id, recipient, msg_sha256_12, msg_len)` within `2.0s` under the shared event lock so dual-hook seats emit exactly one zero-prose `#seq` record (`is_silent` / `is_report_no_reply` from `classify_native_message_flags`).
  - **Role-Aware Contract Auditing**: `audit_seat_hook_contract` validates each seat against its actual role profile (`platform_hub`, `isolated_guard`, `multidir_global_hook`, `cleanroom_line`) and guarantees `send_message_emitter_ready` across 100% of the fleet.
