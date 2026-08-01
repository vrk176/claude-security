# claude-security

**A port of [`@openai/codex-security`](https://github.com/openai/codex-security) to Claude.**
CLI and TypeScript SDK for **finding and validating** security vulnerabilities in your
code. It drives the [Claude Agent SDK](https://code.claude.com/docs/en/agent-sdk) through a
bundled set of security-scanning skills, then seals the results into the same canonical
scan contract (JSON manifest + findings + coverage, SARIF, Markdown report).

This is a derivative work, not an independent tool. The model-agnostic scanning pipeline —
the Python finalizer, sealer, validators, JSON Schemas, and SQLite workbench — is reused
from codex-security under Apache-2.0; what was replaced is the runtime driver, Codex out
and Claude Agent SDK in. See
[Relationship to codex-security](#relationship-to-codex-security) for what is reused
verbatim, what changed, and what is not ported.

> **Status: the scan pipeline works end to end.** All 13 skills are present, and 9 of
> upstream's 11 commands are implemented. Standard, `--diff`, and `--resume` scans are
> verified against a real repository, including a paid scan sealed through the workbench
> with its cost and findings recorded in history.
>
> **Not implemented: `patch` and `validate`.** Upstream describes itself as a tool for
> finding, validating, *and fixing* vulnerabilities. This port finds and validates; it
> does not write fixes. `--deep` runs but is not yet cost-practical. See
> [Known limitations](#known-limitations).

> [!WARNING]
> **This tool does not sandbox the code it scans.** The scan agent runs with `Bash`
> pre-approved, so it executes shell commands with your privileges, your network access,
> and your credentials. Upstream Codex Security runs scans inside the Codex sandbox; this
> port has no equivalent. **Scan untrusted code only inside a disposable,
> network-restricted container.** See [SECURITY.md](SECURITY.md).

## Architecture

Three layers, mirroring codex-security:

1. **CLI / SDK** (`src/`) — argument parsing, target resolution, scan orchestration, usage/cost.
2. **Bundled plugin** (`plugin/`) — the scanning intelligence: 13 `SKILL.md` skills,
   shared reference docs, JSON Schemas, and the Python finalize/seal/validate scripts.
   **The Python pipeline and schemas are reused verbatim from codex-security** — they are
   model-agnostic.
3. **Runtime glue** (`src/runtime.ts`) — replaces the Codex CLI runtime with the Claude
   Agent SDK's `query()`. Loads `plugin/` as a local plugin, isolates the session from the
   user's `~/.claude` config (`settingSources: []`), scopes tools and writable directories,
   and streams usage.

## Requirements

Node.js 22+ and Python 3.10+ (the bundled finalize/seal/validate scripts use 3.10 syntax),
plus an Anthropic credential — see [Authentication](#authentication).

## Install

```bash
npm install -g claude-security      # or run ad hoc with: npx claude-security ...
```

From source:

```bash
git clone https://github.com/vrk176/claude-security.git
cd claude-security
npm install          # pulls @anthropic-ai/claude-agent-sdk
npm run build        # tsc -> dist/
```

## Authentication

```bash
claude-security login status          # which credential will a scan use?
printenv ANTHROPIC_API_KEY | claude-security login --with-api-key
claude-security logout
```

Credentials resolve in this order, and `login status` reports the winner without printing
any secret:

1. `ANTHROPIC_API_KEY` from the environment
2. `ANTHROPIC_AUTH_TOKEN` from the environment
3. an API key stored by `login --with-api-key`
4. an existing Claude Code sign-in (macOS keychain or `~/.claude`)

**An environment key outranks a stored one**, and `login status` says so when both exist —
otherwise "I stored a key but it's using a different account" is impossible to debug.
For the same reason `logout` lists what still authenticates you afterwards: removing the
stored key does not sign you out if `ANTHROPIC_API_KEY` is still exported.

The key is read from **stdin, never from a command-line argument** (argv is visible in
shell history and to anything that can read the process table), and stored as plain JSON
with mode `600` in a `700` directory under `CLAUDE_SECURITY_STATE_DIR`. Treat that file as
a secret; on a shared machine prefer an environment variable or a Claude Code sign-in.

There is no browser sign-in: third-party tools cannot offer claude.ai login, so
`claude-security login` with no flags explains the alternatives instead of attempting one.
For OAuth, sign in with Claude Code or `ant auth login` — the SDK picks those up on its own.

## Use

```bash
export ANTHROPIC_API_KEY=sk-...   # or: claude-security login --with-api-key

# whole repository
npx claude-security scan /path/to/repo --output-dir /path/outside/repo/results

# scoped paths, choose model / effort, cap spend, machine-readable output
npx claude-security scan /path/to/repo --path src --path lib \
  --model claude-opus-5 --effort xhigh --max-cost 25 --json

# validate inputs without starting the agent or loading credentials
npx claude-security scan /path/to/repo --dry-run
npx claude-security info --json
```

### Scan modes

```bash
claude-security scan REPO                    # standard single-pass repository scan
claude-security scan REPO --path src         # scoped to one or more paths
claude-security scan REPO --deep             # repeated discovery rounds until nothing new
claude-security scan REPO --diff origin/main # committed changes against a base
claude-security scan REPO --working-tree     # staged + unstaged changes
```

`--deep` and the diff modes are mutually exclusive, and the diff modes require a Git
repository.

### Bundled skills

All 13 upstream skills are bundled, but the CLI only drives the scanning ones. The rest
are usable by loading `plugin/` as a Claude Code plugin (see below) — they are shipped,
not wired to a command.

| Skill | Role | Reachable via |
|---|---|---|
| `security-scan` | Standard single-pass repository / scoped-path scan (default) | `scan` |
| `deep-security-scan` | Repeated discovery rounds, then one centralized validation tail | `scan --deep` |
| `security-diff-scan` | PR / commit / branch / working-tree change review | `scan --diff` / `--working-tree` |
| `threat-model` | Repository-scoped threat model (phase 1) | `scan` (all modes) |
| `finding-discovery` | Candidate discovery (phase 2) | `scan` |
| `validation` | Candidate validation (phase 3) | `scan` (all modes) |
| `attack-path-analysis` | Reachability and severity (phase 4) | `scan` (all modes) |
| `vulnerability-writeup` | Detailed per-finding reports | `scan --deep` / diff modes |
| `propose-security-hardening` | Structural hardening portfolio | `scan --deep` / diff modes |
| `fix-finding` | Fix and verify a validated finding | **plugin only** — no CLI command |
| `triage-finding` | Static repo-impact triage of externally supplied findings | **plugin only** |
| `track-findings` | File findings into Linear / Jira / GitHub (needs an MCP server) | **plugin only** |
| `define-security-policy` | Author or review a repository `SECURITY.md` | **plugin only** |

To use the plugin-only skills, load the bundled plugin in Claude Code and invoke the skill
by name. `plugin/.claude-plugin/plugin.json` declares it; point Claude Code at the
`plugin/` directory of an installed copy or a clone of this repository.

### Resuming an interrupted scan

A scan that stops early — budget cap, turn cap, cancellation — leaves its finished
phases on disk. Inspect them, then continue into the same directory:

```bash
npx claude-security status /path/outside/repo/results
# threat model    done
# file list       done (640 files)
# discovery       done (58 candidates)
# validation      pending (38/58)
# ...
# Next phase: validation. Resume with --output-dir ... --resume

npx claude-security scan /path/to/repo --path src \
  --output-dir /path/outside/repo/results --resume
```

Resume reads the phase artifacts and tells the agent exactly what is already done, so
completed phases are not paid for twice. Starting a *fresh* scan into a directory that
already holds artifacts is refused rather than silently overwriting them; `status`
exits 0 for a readable scan and 2 when the directory holds nothing.

### Scan history

Every fresh scan is recorded in a local SQLite workbench at
`~/.claude/state/plugins/claude-security/workbench.sqlite3` (override with
`CLAUDE_SECURITY_STATE_DIR`):

```bash
npx claude-security scans list                 # all recorded scans
npx claude-security scans list /path/to/repo   # filtered to one repository
npx claude-security scans show 880dee3e        # full id or a unique prefix
npx claude-security scans show 880dee3e --json
```

### Rerunning a recorded scan

```bash
npx claude-security scans rerun <scan-id> --output-dir /path/outside/repo/results2
# Rerunning 2f5d6dd4 against the current checkout
#   repository: /path/to/repo
#   mode:       standard
#   scope:      class/crontab.py, class/panelBackup.py
# ...
# Compare with the original:
#   claude-security scans match   2f5d6dd4 e2d3b388
#   claude-security scans compare 2f5d6dd4 e2d3b388
```

The scan's recorded launch recipe (repository, mode, scope, model) is replayed against the
current checkout, and the rerun is linked to the scan it repeats via `parentScanId`.
Flags given now override the recipe. `--dry-run` prints the reconstructed configuration
without scanning.

Diff scans cannot be rerun: replaying a diff against a moved checkout would compare
different revisions than the original, so the command refuses and points at `--diff`.

### Comparing scans over time

```bash
npx claude-security scans match   <before-id> <after-id>   # link findings by root cause
npx claude-security scans compare <before-id> <after-id>   # what changed
# resolved 4 / persisting 10 / new 0 / reopened 0 / unknown 0
```

**Run `match` before `compare`.** Compare reads *saved* matches; without them it cannot
tell a finding that persisted from one that was fixed and coincidentally re-found, and
reports the same finding as both resolved and new. (Measured: the same pair goes from
`{new: 10, resolved: 14}` unmatched to the correct `{persisting: 10, resolved: 4}` matched.)

Matching is deterministic and free — no model call. The scan contract's semantic
fingerprint is derived from target id, rule id, anchor, and instance, so it is stable
across scans of the same target; equal fingerprints are the same finding. Upstream this
step was semantic, and a model pass could still be layered on for renamed or refactored
code, where fingerprints legitimately drift.

A missing finding is only treated as resolved when the later scan's coverage is
`complete`; otherwise `comparable` is false and the report says so.

**A resume inherits the original scan's identity.** The runtime writes
`.runtime/scan-state.json` beside the artifacts, recording the workbench scan id, the
repository, its revision, the mode, and the scope. `--resume` reads it back, so the
resumed run finishes the scan history row it started instead of leaving it `running`
forever, and the workbench keeps ownership of sealing.

That record is also what makes a resume refuse the wrong directory. Resuming repository B
into repository A's bundle — or the same repository after HEAD moved, or with a different
scope — mixes two codebases into one result whose completed phases describe code that is
no longer there. Each mismatch is named:

```
error: Refusing to resume: this scan directory belongs to a different scan.
  - revision: recorded 929a3a5, got 7061dca — the checkout moved, so the finished
    phases describe different code
```

Registration happens at launch, not afterwards — the workbench tracks a scan while it
runs, and requires an empty scan directory, so `--resume` does not re-register.

**A failed registration stops the scan.** Without a workbench row there is no target
contract, so the agent authors its own manifest identity and seals its own result: the
finalizer can still check that bundle's structure, but nothing shows it describes this
repository at this revision. That provenance gap is invisible in the output, so the scan
is refused rather than produced. Pass `recordHistory: false` in the SDK when an
unrecorded scan is what you actually want — the difference between "history is off" and
"history broke" is the whole point.

**Scope is checked before the agent starts.** An absolute path, a missing path, or one
that escapes the repository — including through a symlink — exits 2 up front, under
`--dry-run` too. The workbench rejects a bad recipe as well, but only after the path has
reached the prompt, and content sent to a model cannot be recalled by failing the scan
afterwards.

**Sealing ownership follows history.** When a scan is recorded, the agent leaves an
unsealed canonical draft and the workbench finalizes it, stamping the timestamps,
producer, and artifact digests it owns. When history is off, the agent runs the finalizer
itself. Getting this backwards makes the workbench reject the scan at completion.

### CI severity policy

Scans are report-only by default. Add `--fail-on-severity` to make CI fail on findings at
or above a level, or check an already-sealed bundle offline with `policy`:

```bash
# fail the build on any high or critical finding
npx claude-security scan REPO --output-dir "$RESULTS" --fail-on-severity high

# re-check a sealed bundle later, without an agent or credentials
npx claude-security policy "$RESULTS" --fail-on-severity high
npx claude-security policy "$RESULTS" --fail-on-severity high --json
```

| Exit | Meaning |
|---|---|
| `0` | Report-only run, or the policy passed |
| `1` | Completed scan that violates the policy — **only** ever this |
| `2` | Invalid input, incomplete coverage, or a runtime/export error |

Severity order: `critical > high > medium > low > informational`.

A second, opt-in gate asks a different question — "how bad if it *were* reachable?" — see
[CI gating: severity vs impact](#ci-gating-severity-vs-impact).

**The seal is verified before any finding is trusted.** `policy` runs the bundle's
contract validator first, so an unsealed bundle — or one whose `findings.json` or
`coverage.json` was edited after sealing — exits 2 instead of reporting zero violations.
Emptying `findings.json` and setting coverage to `complete` used to pass a
`--fail-on-severity` gate; it now fails closed. There is deliberately no flag to skip this:
a gate with a bypass is the same gate with an extra step. This is why `policy` needs
Python, like `export` already did.

**Incomplete coverage outranks a passing policy.** A scan whose `coverage.completeness` is
not `complete` exits 2 even with zero violations: it did not finish, so it cannot prove the
absence of findings, and reporting it green would be worse than not running it. For the
same reason a scan that never sealed is never policy-checked — it exits 2.

### Token usage and cost

Every run writes `usage.json` into the scan directory — **including runs that fail**.
A run that hits the budget or turn cap can end by throwing rather than returning a
result, and the token accounting used to be lost with it; now whatever was accumulated
is persisted first.

```bash
npx claude-security usage /path/results
# $12.0041, 64 turns, in 8,123 / out 4,210 / cache-read 1,204,551

npx claude-security usage /path/results --json
```

Each completed scan also records its model, tokens, and cost into scan history, so
`scans list` and `scans show` show what a scan cost:

```
SCAN      MODE      STATE     STARTED           FINDINGS     COST       TARGET
797a6fda  standard  complete  2026-07-29 19:34  14 findings  $10.1133   /path/to/repo
```

`--max-cost` is rejected for a model with no entry in the price table: a cap the runtime
cannot price is a cap in name only.

`totalCostUsd`, `numTurns`, and `modelUsage` come from the SDK's result message and are
authoritative. **Prefer `modelUsage` over the top-level token counts**: subagent work is
billed into `totalCostUsd` and `modelUsage` but is *not* added to the top-level `usage`
totals, so a scan that delegates heavily will show roughly half its real token volume
there. (Measured on a real diff scan: top-level 46,842 output tokens vs 123,101 in
`modelUsage`.) When no result message arrived (the run threw), the file is marked
`"partial": true` and the token totals are the streamed approximation — assistant turns
are de-duplicated by message id, since parallel tool calls share one id.

### Scanning many repositories

```csv
id,repository,revision,scope,mode
service,https://github.com/acme/service.git,0123456789abcdef0123456789abcdef01234567,src,standard
gateway,https://github.com/acme/gateway.git,fedcba9876543210fedcba9876543210fedcba98,,deep
```

```bash
npx claude-security bulk-scan repositories.csv --output-dir /path/outside/repos/results \
  --workers 4 --max-attempts 2 --max-cost 15
npx claude-security bulk-scan repositories.csv --output-dir ... --dry-run   # validate the CSV
```

`id`, `repository`, and `revision` are required; `scope` and `mode` are optional.
**Revisions must be full 40-character SHAs** — a branch name would let the remote decide
what gets audited.

Each task writes its bundle to `<output>/artifacts/<id>/attempt-N` and appends a receipt
to `<output>/results.jsonl` carrying status, attempt, findings count, and cost. Rerunning
the same command **resumes**: tasks that already completed with a sealed report are
skipped, so an interrupted run does not pay twice. Exit is 2 if any task never sealed.

Checkouts are treated as untrusted: repository hooks are disabled
(`core.hooksPath=/dev/null`), ambient `GIT_*` variables are stripped, terminal auth
prompts are refused rather than hung on, LFS blobs are skipped, the checked-out HEAD is
verified against the pinned SHA, and the working copy is deleted after each scan.

> The interactive GitHub discovery wizard from the upstream tool is not ported — supply a
> CSV instead. Costs multiply here: budget `--max-cost` per task and start small.

### Dismissing false positives

```bash
npx claude-security findings list --scan <scan-id>
npx claude-security findings false-positive <occurrence-id> \
  --reason "Table names come from a fixed allowlist here; the identifier cannot contain a quote."
npx claude-security findings wont-fix <occurrence-id> --reason "..."
npx claude-security findings reopen <occurrence-id>
```

**A dismissal must carry a reason.** Later scans reuse the stated reason to decide whether
the dismissal still applies, so an unexplained one could never be re-evaluated and would
suppress the finding forever. The CLI refuses a dismissal without `--reason`.

Dismissals are keyed by the same semantic fingerprint used for `scans match`, and **a
later scan of the same target receives them in its prompt**: the scan skills are told to
re-check each stated reason against the current code, skip the finding when the reason
still holds, and report it when the code changed so the reason no longer does. A stale
dismissal is not allowed to hide a live bug, and a dismissal never extends to a different
finding that merely resembles it.

`findings reopen` withdraws a dismissal, and it stops appearing in later scans.

### Pre-commit hook

```bash
npx claude-security install-hook                    # current repo
npx claude-security install-hook /path/to/repo --fail-on-severity critical
npx claude-security install-hook --uninstall
```

The hook scans staged and unstaged changes before each commit and blocks the commit on
findings at or above the threshold (default `high`). Both exit 1 (policy violation) and
exit 2 (incomplete coverage or a runtime error) block: a scan that did not finish has not
shown the change is clean.

It respects `core.hooksPath`, and **refuses to replace or remove a `pre-commit` hook it
did not write** (use `--force` to override). If `claude-security` is not on `PATH` the
hook warns and lets the commit through, so a teammate without it installed is not blocked.

```bash
CLAUDE_SECURITY_SKIP=1 git commit ...   # skip one commit
```

> **Cost matters here.** Hook scans default to `--effort medium` and `--max-cost 5`
> because a commit hook runs often and interactively. Even so, a scan takes minutes and
> real money — a measured diff scan of 5 files cost $10 at `xhigh`. Tune
> `--effort`/`--max-cost` at install time, and expect this to be more practical on small,
> focused commits than on large ones.

### Exporting findings

```bash
# SARIF for code scanning (--source-root adds source-line fingerprints)
npx claude-security export /path/results --export-format sarif \
  --output /path/results.sarif --source-root /path/to/repo

# CSV / JSON; omit --output to write the in-bundle default, or use "-" for stdout
npx claude-security export /path/results --export-format csv
npx claude-security export /path/results --export-format json --output -
```

Export runs **offline** — no agent, no credentials, no network — and validates the seal
before writing. An unsealed bundle, or one whose findings were edited after sealing, is
refused (exit 2) instead of producing a plausible-looking export. Default in-bundle
paths are `exports/findings.csv`, `exports/findings.json`, and `exports/results.sarif`.

SDK:

```ts
import { ClaudeSecurity } from "claude-security";

const security = new ClaudeSecurity();
const result = await security.run("/path/to/repo", {
  outputDir: "/tmp/results",
});
console.log(result.reportPath, result.totalCostUsd);
```

The output directory must be outside the scanned repository.

## CI gating: severity vs impact

`--fail-on-severity` gates on final severity. Severity already discounts impact by
likelihood — the scan contract maps high impact with low likelihood down to `low` — so a
finding can carry a proven root-RCE primitive and still pass a `--fail-on-severity high`
gate because no caller reaches it in the tree scanned.

That mapping is upstream's, it is deliberate (the whole severity policy is written to
resist severity inflation), and this port does not change it. Instead there is a second,
opt-in gate that asks the other question:

```bash
claude-security policy ./scan --fail-on-impact high    # how bad if it *were* reachable?
```

Both gates can run together; a finding reports which one it tripped:

```
Policy:   fail at severity high or above, or impact high or above — 3 violation(s)
  [low] Command injection: unvalidated `path` ... (impact; impact high)
```

**The impact gate is fail-closed.** `attackPath.impact.level` is neither required nor
shape-constrained by the findings schema, so a finding that states no recognizable impact
counts as a violation, not a pass — a gate that cannot read the evidence must not certify
the code as clean. Only an explicit `ignore`, meaning impact was assessed and found nil,
clears the gate without a stated level. Expect the impact gate to be noisier than the
severity gate; that is the trade being made.

## Isolation caveat

The Agent SDK does not sandbox the filesystem. This runtime uses a scoped `allowedTools`
whitelist, `settingSources: []`, and instructs the agent to treat the repository as
read-only, but true read-only enforcement (and network isolation) requires running the CLI
inside a container. Scan untrusted code in a disposable, network-restricted container.

See [SECURITY.md](SECURITY.md) for the full posture, including prompt-injection exposure
and artifact handling.

## Relationship to codex-security

Upstream is [`openai/codex-security`](https://github.com/openai/codex-security)
(Copyright 2025 OpenAI, Apache-2.0). This port reuses its scanning pipeline and replaces
its runtime driver. [NOTICE](NOTICE) records the attribution and pins the exact upstream
commit the file-by-file comparison below was made against.

### Command coverage

| Upstream command | Here |
|---|---|
| `scan`, `scans`, `findings`, `export`, `bulk-scan`, `install-hook`, `login`, `logout`, `info` | implemented |
| `patch` | **not ported** — see [Known limitations](#known-limitations) |
| `validate` | **not ported** — see [Known limitations](#known-limitations) |
| — | `status`, `policy`, `usage` are additions, not upstream commands |

### Code

| Reused verbatim (model-agnostic) | Rewritten for Claude |
|---|---|
| `plugin/schemas/*` JSON Schemas | `src/runtime.ts` (Codex runtime → Agent SDK `query()`) |
| `plugin/scripts/*.py` finalize/seal/validate/normalize | `src/cli.ts`, `src/index.ts`, `src/paths.ts` |
| `plugin/references/*` scan contract & report semantics | `plugin/skills/security-scan/SKILL.md` (de-coupled from Codex desktop/MCP) |
| Canonical scan bundle format, SARIF, coverage model | auth (`ANTHROPIC_API_KEY`), model default (`claude-opus-5` / `xhigh`) |

## Contract identity

This port owns its own scan-contract identity, so bundles are not interchangeable with
`codex-security` in either direction:

| | Value |
|---|---|
| `documentType` | `claude-security.{scan-manifest,findings,coverage}` |
| Fingerprint algorithm | `claude-security/v1` |
| Snapshot digest prefix | `claude-security-snapshot/v1` (participates in the digest, so values differ) |
| SARIF driver / fingerprint key | `Claude Security` / `claudeSecurity/v1` |
| Env vars | `CLAUDE_SECURITY_{STARTED_AT,STATE_DIR}` |

The JSON Schema `$id` values still carry the upstream `openai.com/codex-security` URLs:
they identify the *schema definitions*, which are inherited from codex-security, and are
never resolved or used for loading (schemas load by filename).

## Design notes

### The manifest contract

A scan recorded in history does not author its own identity. The workbench pins the target
at registration and re-derives the same values when sealing, rejecting any manifest that
disagrees — so the runtime reads the contract back (`workbench_bridge.py contract`) and
puts the exact required values in the scan prompt. This matters because several fields are
not derivable by the agent: `kind` is `git_revision` for a clean checkout but
`git_worktree` for a dirty one, `targetId` is a workbench identity rather than a path, and
a diff scan's `baseRevision`/`headRevision`/`snapshotDigest` are resolved and pinned at
registration. A guess here fails sealing only *after* the whole scan has been paid for,
which is why the values are supplied rather than described.

For the same reason `runScan` returns a `warnings` array. A finalization that fails leaves
`ok: false`, and the reason has to travel in the result — routing it only through the
progress callback lost it entirely under `--json`, which is the mode CI uses.

### What changed in the deep scan

Upstream, `deep-security-scan`'s repeated-discovery phase was owned by a closed
orchestration service shipped as a compressed build artifact, so it could not be ported by
reading. The phase boundaries, merge discipline, and centralized validation tail are
preserved verbatim; the round scheduling is **reimplemented natively** in the skill using
ordinary subagents (independent rounds over a fixed file list, varying the search angle,
merging into one ledger, stopping when a round adds nothing new). Treat it as a
reimplementation of that phase, not a byte-for-byte port.

## Known limitations

**`--deep` is expensive and not yet cost-practical.** A live run over one 383-line file
cost $12.36 and still ran out of budget before finalizing — roughly 30x the per-line cost
of a standard scan. Two prompt-level fixes are needed before it is usable:

- Parallel discovery shards each invent their own `instance` labels, and the combiner's
  merge key includes `instance`, so overlapping findings never merge. One live round
  produced 56 candidates that later collapsed to 7 findings, after paying to carry all 56
  through the pipeline. Either share an instance convention across shards, or skip
  sharding when the scope is a single file.
- The skill requires validation records to be written back into the candidate ledger, but
  the model validated in-context and wrote straight to `findings.json`, leaving the ledger
  with zero validation records. A resume then re-validates work that was already done.

**`patch` and `validate` are not ported.** Upstream exposes two commands this port does
not have:

- `patch` runs the bundled `fix-finding` skill to write a fix. It is the only command that
  would modify your source, so it needs its own design — dry-run by default, explicit
  opt-in to write, and verification that the fix holds — plus live testing. Deferred
  rather than rushed into the first release.
- `validate` re-validates a single finding on demand. Scans already validate candidates as
  phase 3, so this was judged redundant; that judgement may be wrong for the workflow where
  you want to re-check one old finding against a new checkout.

Until then, `fix-finding` is reachable by loading `plugin/` as a Claude Code plugin.

**Not ported by design.** The interactive GitHub discovery wizard — supply a CSV to
`bulk-scan` instead, which is reproducible and reviewable.

## License

Apache-2.0 — see [LICENSE](LICENSE).

Derivative work of [Codex Security](https://github.com/openai/codex-security)
(Copyright 2025 OpenAI, Apache-2.0); see
[Relationship to codex-security](#relationship-to-codex-security) for the split, and
[NOTICE](NOTICE) for the attribution and the file-by-file accounting.

Not affiliated with, endorsed by, or supported by either OpenAI or Anthropic.
