import { mkdir } from "node:fs/promises";
import { execFileSync, spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { fileURLToPath } from "node:url";
import {
  basename,
  dirname,
  isAbsolute,
  join,
  resolve,
  relative as relativePath,
} from "node:path";

import {
  resolveTarget,
  defaultScanDir,
  canonicalize,
  type ResolvedTarget,
} from "./paths.js";
import {
  assertResumeMatches,
  readScanRecord,
  writeScanRecord,
  type ScanIdentity,
} from "./scanrecord.js";
import { inspectScanState, describeScanState, type ScanState } from "./state.js";
import { UsageAccumulator, writeUsage, type UsageSnapshot } from "./usage.js";
import type { ScanContract } from "./history.js";
import {
  registerScan,
  completeScan,
  getScanContract,
  scanFeedback,
  describeDismissals,
} from "./history.js";
import { scanCostFromUsage, costLimitSupported } from "./cost.js";
import { credentialEnv } from "./auth.js";

export interface ScanOptions {
  /** One or more repository-relative scope paths. Empty = whole repository. */
  paths?: string[];
  /**
   * Scan committed changes against this base (branch, tag, revision, or range).
   * Selects the diff-scan workflow instead of the repository scan.
   */
  diff?: string;
  /** Scan staged and unstaged working-tree changes. Selects the diff workflow. */
  workingTree?: boolean;
  /** Run repeated discovery rounds (deep scan) instead of a single pass. */
  deep?: boolean;
  /** Absolute output directory for the scan bundle. Defaults to a system-temp location. */
  outputDir?: string;
  /** Model id or alias. Defaults to claude-opus-5. */
  model?: string;
  /** Reasoning effort. Defaults to xhigh (best for agentic/security work). */
  effort?: "low" | "medium" | "high" | "xhigh" | "max";
  /** Python interpreter for the finalize/normalize scripts. Defaults to python3/python. */
  pythonPath?: string;
  /** Cap the agent's turns. Defaults to 120. */
  maxTurns?: number;
  /** Stop the scan when estimated cost exceeds this USD amount (SDK-enforced). */
  maxCostUsd?: number;
  /** Continue a scan that stopped early, reusing the phases already on disk. */
  resume?: boolean;
  /** Record the scan in the workbench history. Defaults to true. */
  recordHistory?: boolean;
  /** When rerunning a recorded scan, the scan id this run repeats. */
  parentScanId?: string;
  /** Cancel the scan. */
  signal?: AbortSignal;
  /** Called for each streamed message from the agent (for progress UIs). */
  onMessage?: (message: unknown) => void;
}

export interface ScanResult {
  /** Workbench scan id, when the run was recorded in history. */
  scanId?: string;
  scanDir: string;
  reportPath: string;
  findingsPath: string;
  manifestPath: string;
  coveragePath: string;
  /** Token/cost record, written even when the run fails. */
  usagePath: string;
  totalCostUsd?: number;
  numTurns?: number;
  durationMs?: number;
  usage?: UsageSnapshot;
  ok: boolean;
  /**
   * Non-fatal problems that still changed the outcome — a scan that could not be
   * recorded, or a finalization that failed. Returned in the result rather than
   * only streamed to `onMessage`, so `--json` consumers and CI see the reason
   * instead of a bare `ok: false`.
   */
  warnings: string[];
}

/** Locate the bundled plugin directory relative to this module. */
export function pluginDirectory(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  // dist/runtime.js -> ../plugin ; src/runtime.ts -> ../plugin
  const candidate = resolve(here, "..", "plugin");
  if (!existsSync(join(candidate, ".claude-plugin", "plugin.json"))) {
    throw new Error(`Bundled plugin not found at ${candidate}`);
  }
  return candidate;
}

export function resolvePython(explicit?: string): string {
  if (explicit) return explicit;
  if (process.env.PYTHON) return process.env.PYTHON;
  // The finalize scripts need Python >= 3.10; prefer the newest available
  // interpreter instead of trusting the bare `python3` (often an older system build).
  const candidates =
    process.platform === "win32"
      ? ["python"]
      : ["python3.14", "python3.13", "python3.12", "python3.11", "python3.10", "python3"];
  for (const candidate of candidates) {
    try {
      const out = execFileSync(candidate, ["--version"], {
        stdio: ["ignore", "pipe", "pipe"],
      })
        .toString()
        .trim();
      const match = /Python (\d+)\.(\d+)/.exec(out);
      if (match && (Number(match[1]) > 3 || Number(match[2]) >= 10)) {
        return candidate;
      }
    } catch {
      // candidate not installed — try the next one
    }
  }
  throw new Error(
    "No Python >= 3.10 found. Install one (e.g. `brew install python@3.13`) or pass --python / PYTHON.",
  );
}

function buildPrompt(args: {
  target: ResolvedTarget;
  scanDir: string;
  scope: string[];
  python: string;
  pluginDir: string;
  diff?: string;
  workingTree?: boolean;
  deep?: boolean;
  scanId?: string;
  contract?: ScanContract;
  dismissals?: string;
  resumeFrom?: ScanState;
}): string {
  const scopeLine =
    args.scope.length > 0
      ? args.scope.map((p) => `- ${p}`).join("\n")
      : "- (entire repository)";

  const isDiff = Boolean(args.diff) || Boolean(args.workingTree);
  const skill = isDiff
    ? "security-diff-scan"
    : args.deep
      ? "deep-security-scan"
      : "security-scan";
  const diffTarget = args.workingTree
    ? "working tree (staged and unstaged changes against HEAD)"
    : args.diff;

  return [
    isDiff
      ? "Run a security diff scan by following the `security-diff-scan` skill."
      : args.deep
        ? "Run a deep security scan by following the `deep-security-scan` skill."
        : "Run a standard security scan by following the `security-scan` skill.",
    "",
    "The runtime has resolved these values for you — use them verbatim wherever the",
    "skills reference `repo_root`, `scan_dir`, `scope`, `<python_command>`, or `<plugin_dir>`:",
    "",
    `- repo_root: ${args.target.repoRoot}`,
    `- scan_dir: ${args.scanDir}`,
    `- <python_command>: ${args.python}`,
    `- <plugin_dir>: ${args.pluginDir}`,
    ...(isDiff ? [`- diff target: ${diffTarget}`] : []),
    ...(args.scanId
      ? [
          `- scan id: ${args.scanId}`,
          "  Use this exact value as `scan.id` in scan-manifest.json.",
        ]
      : []),
    ...(args.contract
      ? [
          "- scan.target must be exactly these workbench-owned values:",
          `    kind: ${args.contract.target.allowedKinds[0]}`,
          `    targetId: ${args.contract.target.targetId}`,
          `    displayName: ${args.contract.target.displayName}`,
          ...(args.contract.target.requiredSnapshotDigest
            ? [`    snapshotDigest: ${args.contract.target.requiredSnapshotDigest}`]
            : []),
          // A diff scan's manifest target also carries the resolved change set,
          // and the workbench verifies every field of it. `working_tree` adds a
          // content digest pinning the exact uncommitted contents reviewed.
          ...(args.contract.diffTarget
            ? [
                `    baseRevision: ${args.contract.diffTarget.baseRevision}`,
                `    headRevision: ${args.contract.diffTarget.headRevision}`,
                ...(args.contract.diffTarget.contentDigest
                  ? [`    snapshotDigest: ${args.contract.diffTarget.contentDigest}`]
                  : []),
              ]
            : []),
          ...(args.contract.scope.requiredIncludePaths
            ? [
                `    scope.includePaths: ${JSON.stringify(
                  args.contract.scope.requiredIncludePaths,
                )}`,
              ]
            : []),
          "  Do not derive these yourself. The workbench verifies each one and rejects",
          "  the whole scan on any mismatch.",
        ]
      : []),
    "- scope:",
    scopeLine,
    "",
    "Rules for this headless run:",
    "- Only write inside scan_dir. Treat the target repository as read-only — never modify,",
    "  create, or delete files under repo_root.",
    `- The \`${skill}\` skill lives at \`<plugin_dir>/skills/${skill}/SKILL.md\` and its`,
    "  shared references at `<plugin_dir>/references/`. Read them to drive the phases.",
    ...(isDiff
      ? [
          "- Resolve the diff with git, review the changed files and the supporting files needed",
          "  to understand the changed behavior, then run the phases the skill defines.",
          "- Stay anchored to the change: do not broaden into a repository-wide scan.",
        ]
      : args.deep
        ? [
            "- Establish a threat model, then run repeated independent discovery rounds over the",
            "  in-scope files, varying the search angle each round and merging every round into",
            "  one candidate ledger. Stop when a round adds nothing new.",
            "- Then run validation and attack-path analysis ONCE, centrally, over the merged set.",
          ]
        : [
            "- Establish a threat model, review every in-scope file, validate candidates, analyze",
            "  attack paths, then continue.",
          ]),
    "- Write the canonical JSON (scan-manifest.json, findings.json, coverage.json) under",
    "  scan_dir.",
    ...(args.scanId
      ? [
          "- Author scan-manifest.json as an UNSEALED draft: omit `scan.sealedAt` and",
          "  `scan.artifacts`, and do NOT run finalize_scan_contract.py yourself. This scan is",
          "  registered in scan history, and the runtime finalizes it so the workbench can stamp",
          "  its own timestamps, producer, and artifact digests. Sealing it here would lock in",
          "  values the workbench must own and the scan could not be recorded.",
          "- Stop once the three canonical files are written and complete. Report the scan",
          "  directory and any coverage gaps; the readable report is generated after you finish.",
        ]
      : [
          "- Then finalize with the finalize_scan_contract.py script.",
          "- Do not stop until finalization succeeds and scan_dir/report.md exists.",
          "- When done, print the absolute report path and any coverage gaps.",
        ]),
    ...(args.dismissals
      ? ["", "## Previously dismissed findings", "", args.dismissals]
      : []),
    ...(args.resumeFrom
      ? ["", "## Resuming", "", describeScanState(args.resumeFrom)]
      : []),
  ].join("\n");
}

/**
 * Drive a Claude Agent SDK session that performs a security scan.
 * Returns the scan bundle paths and usage once the agent finishes.
 */
/**
 * Reject a scope path that is absent, absolute, or outside the repository.
 *
 * The workbench rejects a bad recipe at registration, but that is too late and
 * only happens when history is available: by then the path is already in the
 * prompt, and an agent with Read and Bash will have acted on it. Content that
 * has left the machine cannot be recalled by failing the scan afterwards, so
 * this runs before anything is spent — including under `--dry-run`, which is
 * meant to be the cheap way to find exactly this kind of mistake.
 */
export function assertScopeInsideRepository(repoRoot: string, scope: string[]): void {
  const repoReal = canonicalize(repoRoot);
  for (const entry of scope) {
    if (isAbsolute(entry)) {
      throw new Error(`Scope path must be repository-relative, not absolute: ${entry}`);
    }
    const resolved = resolve(repoReal, entry);
    if (!existsSync(resolved)) {
      throw new Error(`Scope path does not exist in the repository: ${entry}`);
    }
    // Compare canonical paths so a symlink pointing outside cannot smuggle the
    // scan out of the repository.
    const real = canonicalize(resolved);
    const rel = relativePath(repoReal, real);
    if (rel.startsWith("..") || isAbsolute(rel)) {
      throw new Error(`Scope path escapes the repository: ${entry} resolves to ${real}`);
    }
  }
}

/**
 * Rebuild the candidate ledger from every raw batch file.
 *
 * The skill asks the agent to do this after each batch, and a real run showed it
 * skipping the step: seven new raw files appeared and the ledger stayed at its
 * old row count, so a batch that had been paid for was invisible to validation.
 * The combiner is deterministic and reads only the raw rows, so the runtime can
 * simply redo it.
 *
 * Guarded, because it is destructive after discovery: enrichment records live in
 * the ledger, not in `raw/`, and the combiner rejects an enriched ledger as
 * input. Rebuilding once any row carries a validation record would throw that
 * work away, so this only runs while the ledger is still raw.
 */
/** Fields a raw candidate row may carry; mirrors references/scan-artifacts.md. */
const RAW_CANDIDATE_FIELDS = new Set([
  "cwe_ids",
  "locations",
  "summary",
  "evidence",
  "context",
  "instance",
]);

function rebuildCandidateLedger(
  scanDir: string,
  repoRoot: string,
  python: string,
): { rebuilt: boolean; reason?: string; stripped?: string } {
  const discovery = join(scanDir, "artifacts", "02_discovery");
  const rawDir = join(discovery, "raw");
  const ledger = join(discovery, "candidate_ledger.jsonl");
  const inScope = join(discovery, "in_scope_files.txt");
  if (!existsSync(rawDir) || !existsSync(inScope)) return { rebuilt: false };

  const inputs = readdirSync(rawDir)
    .filter((name) => name.endsWith(".jsonl"))
    .map((name) => join(rawDir, name));
  if (inputs.length === 0) return { rebuilt: false };

  if (existsSync(ledger)) {
    const enriched = readFileSync(ledger, "utf8")
      .split("\n")
      .some((line: string) => {
        if (!line.trim()) return false;
        try {
          const row = JSON.parse(line) as Record<string, unknown>;
          return row.validation !== undefined || row.attack_path !== undefined;
        } catch {
          return false;
        }
      });
    if (enriched) {
      return { rebuilt: false, reason: "ledger already carries enrichment records" };
    }
  }

  // Drop unknown top-level fields before combining.
  //
  // The combiner rejects the whole invocation on one unexpected key, which is
  // right for a contract check but wrong for a recovery step: on a real scan two
  // stray fields across 46 batch files blocked all 535 candidates. The contract
  // defines which fields carry meaning, so an extra one is noise — but dropping
  // it silently would hide the agent going off-spec, hence the warning below.
  const staged = join(scanDir, ".runtime", "raw-normalized");
  rmSync(staged, { recursive: true, force: true });
  mkdirSync(staged, { recursive: true });
  const dropped = new Map<string, number>();
  const stagedInputs: string[] = [];
  for (const input of inputs) {
    const out: string[] = [];
    for (const line of readFileSync(input, "utf8").split("\n")) {
      if (!line.trim()) continue;
      let row: Record<string, unknown>;
      try {
        row = JSON.parse(line) as Record<string, unknown>;
      } catch {
        // Leave a malformed row in place so the combiner reports it precisely.
        out.push(line);
        continue;
      }
      for (const key of Object.keys(row)) {
        if (!RAW_CANDIDATE_FIELDS.has(key)) {
          delete row[key];
          dropped.set(key, (dropped.get(key) ?? 0) + 1);
        }
      }
      out.push(JSON.stringify(row));
    }
    const target = join(staged, basename(input));
    writeFileSync(target, out.join("\n") + "\n", "utf8");
    stagedInputs.push(target);
  }

  const script = join(pluginDirectory(), "scripts", "normalize_candidates.py");
  const run = spawnSync(
    python,
    [script, "--input", ...stagedInputs, "--out", ledger, "--repo-root", repoRoot,
     "--in-scope-files", inScope],
    { encoding: "utf8", maxBuffer: 256 * 1024 * 1024 },
  );
  if (run.status !== 0) {
    const detail = run.stderr?.trim().split("\n").filter(Boolean).pop() ?? "unknown error";
    return { rebuilt: false, reason: detail };
  }
  const strippedNote =
    dropped.size > 0
      ? [...dropped.entries()].map(([k, n]) => `${k} (${n})`).join(", ")
      : undefined;
  return { rebuilt: true, stripped: strippedNote };
}

export async function runScan(
  rawPath: string,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const target = resolveTarget(rawPath);
  // Canonicalize: the finalize script rejects a scan dir reached via a symlink.
  const scanDir = options.outputDir
    ? canonicalize(options.outputDir)
    : defaultScanDir(target);
  const pluginDir = pluginDirectory();
  const python = resolvePython(options.pythonPath);
  const scope = options.paths ?? [];

  assertScopeInsideRepository(target.repoRoot, scope);

  // Guard rails on the target and the output directory.
  if (options.deep && (options.diff || options.workingTree)) {
    throw new Error(
      "Deep scans cover a repository or scoped path; they do not take a diff target.",
    );
  }
  if (options.diff && options.workingTree) {
    throw new Error("Use either diff/--diff or workingTree/--working-tree, not both.");
  }
  if ((options.diff || options.workingTree) && !target.git) {
    throw new Error(
      `A diff scan needs a Git repository, but ${target.repoRoot} is not one.`,
    );
  }
  if (scanDir === target.repoRoot || scanDir.startsWith(target.repoRoot + "/")) {
    throw new Error(
      "Output directory must be outside the scanned repository. Use --output-dir with a path outside the target.",
    );
  }

  await mkdir(scanDir, { recursive: true });

  // Refuse to start a fresh scan on top of an existing one: the phase artifacts
  // are the only durable record of a partial run, and overwriting them silently
  // throws away work that was already paid for.
  const existing = inspectScanState(scanDir);
  if (existing.hasArtifacts && !options.resume) {
    throw new Error(
      `Output directory already contains scan artifacts (${existing.completed.join(", ") || "partial work"}).\n` +
        "Pass resume/--resume to continue it, or choose an empty output directory.",
    );
  }
  // A directory that is merely non-empty is a different problem: there is
  // nothing to resume, and the workbench requires an empty directory to
  // register the scan. Saying "contains scan artifacts" here would be false,
  // and advising --resume would skip registration and lose the history record.
  if (!existing.empty && !existing.hasArtifacts && !options.resume) {
    throw new Error(
      `Output directory is not empty and holds no scan artifacts: ${scanDir}\n` +
        "A scan needs its own empty directory. Point --output-dir at a new path, " +
        "for example a fresh subdirectory.",
    );
  }
  if (options.resume && !existing.hasArtifacts) {
    throw new Error(
      `Nothing to resume: ${scanDir} contains no scan artifacts. Run without --resume to start a scan.`,
    );
  }
  if (options.resume && existing.sealed) {
    throw new Error(
      `Nothing to resume: ${scanDir} is already sealed (report.md exists).`,
    );
  }

  // Record the scan in the workbench before it starts. Registration requires an
  // empty scan directory, so it only applies to fresh runs — a resume is already
  // recorded. Failing to record must not block the scan itself.
  const warnings: string[] = [];
  const warn = (message: string): void => {
    warnings.push(message);
    options.onMessage?.({ type: "history_warning", message });
  };

  const identity: ScanIdentity = {
    repoRoot: target.repoRoot,
    targetId: target.targetId,
    mode: options.workingTree
      ? "working-tree"
      : options.diff
        ? "diff"
        : options.deep
          ? "deep"
          : "standard",
    scope,
    diffBase: options.diff ?? null,
  };

  let scanId: string | undefined;

  // A resume inherits the original scan's identity instead of starting a new
  // one. Without this the workbench row stays `running` forever, the agent is
  // told to seal a scan the workbench still owns, and nothing checks that the
  // directory being resumed belongs to this target at all.
  if (options.resume) {
    const record = readScanRecord(scanDir);
    if (record) {
      assertResumeMatches(record, identity);
      scanId = record.scanId ?? undefined;
    } else {
      warn(
        "no runtime scan record found, so this resume cannot restore the original " +
          "scan id or verify the target; it will not be recorded in scan history",
      );
    }
  }

  if (!options.resume && options.recordHistory !== false) {
    try {
      const registered = registerScan({
        target,
        scanDir,
        mode: options.deep ? "deep" : "standard",
        paths: scope,
        ...(options.workingTree
          ? { diff: { base: "HEAD", workingTree: true } }
          : options.diff
            ? { diff: { base: options.diff, workingTree: false } }
            : {}),
        model: options.model ?? "claude-opus-5",
        effort: options.effort ?? "xhigh",
        parentScanId: options.parentScanId,
        pythonPath: options.pythonPath,
      });
      scanId = registered.scanId;
    } catch (err) {
      // Registration failing is not the same as history being switched off.
      //
      // Without a workbench row there is no target contract, so the agent
      // authors its own manifest identity and seals its own scan. The finalizer
      // can check that bundle's structure but cannot show it describes this
      // repository at this revision — the provenance is the model's word. That
      // is a materially weaker result than the one asked for, so it is refused
      // rather than produced silently. Opt out deliberately with
      // `recordHistory: false` if an unrecorded scan is what you want.
      throw new Error(
        `Cannot record this scan in history: ${(err as Error).message}\n` +
          "Without a workbench record the scan would author its own provenance, " +
          "which cannot be verified. Fix the cause, or pass recordHistory: false " +
          "to run an explicitly unrecorded scan.",
      );
    }
  }

  // Persist identity for any later resume, including runs with history off:
  // knowing which target a directory belongs to matters even when the workbench
  // is not involved.
  if (!options.resume) {
    try {
      writeScanRecord(scanDir, {
        schemaVersion: 1,
        scanId: scanId ?? null,
        ...identity,
        createdAt: new Date().toISOString(),
      });
    } catch (err) {
      warn(`could not persist the scan record: ${(err as Error).message}`);
    }
  }

  // Tell the agent the exact target identity the workbench will verify its draft
  // manifest against. Without this the agent has to guess fields it cannot
  // derive — `allowedKinds` flips between git_revision and git_worktree on
  // whether the checkout is dirty — and a wrong guess fails sealing only after
  // the whole scan has been paid for.
  let contract: ScanContract | undefined;
  if (scanId) {
    try {
      contract = getScanContract(scanId, options.pythonPath);
    } catch (err) {
      warn(`could not read the manifest contract: ${(err as Error).message}`);
    }
  }

  // Carry prior dismissals into the run so a reviewed-and-rejected finding is not
  // re-reported. Best effort: unavailable history must not block a scan.
  let dismissals: string | undefined;
  if (scanId) {
    try {
      const { falsePositives } = scanFeedback(scanId, options.pythonPath);
      if (falsePositives.length > 0) dismissals = describeDismissals(falsePositives);
    } catch {
      // history unavailable — scan without the briefing
    }
  }

  const prompt = buildPrompt({
    target,
    scanDir,
    scope,
    python,
    pluginDir,
    diff: options.diff,
    workingTree: options.workingTree,
    deep: options.deep,
    scanId,
    contract,
    dismissals,
    resumeFrom: options.resume ? existing : undefined,
  });

  // Import the SDK lazily so `info`, `--dry-run`, and target resolution work
  // without the agent runtime or any credentials present.
  const { query } = await import("@anthropic-ai/claude-agent-sdk");
  type Options = NonNullable<Parameters<typeof query>[0]["options"]>;

  const queryOptions: Options = {
    cwd: target.repoRoot,
    model: options.model ?? "claude-opus-5",
    effort: options.effort ?? "xhigh",
    maxTurns: options.maxTurns ?? 120,
    maxBudgetUsd: options.maxCostUsd,
    // Fully isolate from the user's ~/.claude and project .claude config.
    settingSources: [],
    // Load our scan skills as a plugin.
    plugins: [{ type: "local", path: pluginDir }],
    // Non-interactive: pre-approved tools run, everything else is denied
    // (safer than bypassPermissions and needs no dangerous override).
    permissionMode: "dontAsk",
    allowedTools: [
      "Read",
      "Grep",
      "Glob",
      "Bash",
      "Write",
      "Edit",
      "Skill",
      "Task",
      "TodoWrite",
    ],
    // Permit writes to the scan bundle even though it lives outside cwd.
    additionalDirectories: [scanDir],
    // A key stored by `login --with-api-key` is not in the environment, so the
    // SDK cannot find it on its own; env keys and Claude Code logins it does.
    ...(credentialEnv() ? { env: { ...process.env, ...credentialEnv() } } : {}),
    abortController: options.signal ? toController(options.signal) : undefined,
  };

  const accumulator = new UsageAccumulator();
  let ok = false;

  // A run that hits the budget or turn cap can end by throwing rather than
  // emitting a result message. Persist whatever usage was accumulated either
  // way, so a paid run always leaves a record of what it cost.
  try {
    for await (const message of query({ prompt, options: queryOptions })) {
      accumulator.record(message);
      options.onMessage?.(message);
      const msg = message as { type?: string; subtype?: string };
      if (msg.type === "result") ok = msg.subtype === "success";
    }
  } catch (err) {
    const snapshot = accumulator.snapshot((err as Error).message);
    writeUsage(scanDir, snapshot);
    throw err;
  }

  const snapshot = accumulator.snapshot();
  writeUsage(scanDir, snapshot);

  // Fold in any raw batches the agent wrote but did not combine.
  const rebuild = rebuildCandidateLedger(scanDir, target.repoRoot, python);
  if (rebuild.reason) {
    warn(`candidate ledger not rebuilt: ${rebuild.reason}`);
  }
  if (rebuild.stripped) {
    warn(
      `raw candidates carried fields the contract does not define, dropped before ` +
        `combining: ${rebuild.stripped}`,
    );
  }

  // Sealing is owned by whoever the prompt said owns it. With history enabled the
  // agent leaves an unsealed draft and the workbench finalizes it here, stamping the
  // fields it owns and ingesting the findings. Without history the agent already ran
  // the finalizer itself.
  if (scanId && ok) {
    try {
      completeScan(scanId, {
        cost: scanCostFromUsage(snapshot) ?? undefined,
        pythonPath: options.pythonPath,
      });
    } catch (err) {
      // Finalization failure means no sealed report, so the scan is not ok.
      ok = false;
      warn(`finalization failed, scan not recorded: ${(err as Error).message}`);
    }
  }

  return {
    scanId,
    scanDir,
    reportPath: join(scanDir, "report.md"),
    findingsPath: join(scanDir, "findings.json"),
    manifestPath: join(scanDir, "scan-manifest.json"),
    coveragePath: join(scanDir, "coverage.json"),
    usagePath: join(scanDir, "usage.json"),
    totalCostUsd: snapshot.totalCostUsd,
    numTurns: snapshot.numTurns,
    durationMs: snapshot.durationMs,
    usage: snapshot,
    ok: ok && existsSync(join(scanDir, "report.md")),
    warnings,
  };
}

function toController(signal: AbortSignal): AbortController {
  const controller = new AbortController();
  if (signal.aborted) controller.abort();
  else signal.addEventListener("abort", () => controller.abort(), { once: true });
  return controller;
}
