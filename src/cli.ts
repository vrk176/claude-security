import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveTarget, defaultScanDir, canonicalize } from "./paths.js";
import { inspectScanState } from "./state.js";
import { exportFindings, EXPORT_FORMATS, type ExportFormat } from "./export.js";
import {
  evaluatePolicy,
  describePolicy,
  SEVERITY_LEVELS,
  type Severity,
} from "./policy.js";
import {
  assertScopeInsideRepository,
  pluginDirectory,
  runScan,
  type ScanOptions,
} from "./runtime.js";
import { describeUsage, type UsageSnapshot } from "./usage.js";
import { installHook, uninstallHook, hookLocation } from "./hook.js";
import {
  credentialStatus,
  describeCredentialStatus,
  storeApiKey,
  clearStoredKey,
  describeCredentialSource,
} from "./auth.js";
import { runBulkScan, summariseBulk, parseTasks } from "./bulk.js";
import { runScan as runScanDirect } from "./runtime.js";
import {
  listScans,
  getScan,
  describeScanRow,
  matchScans,
  compareScans,
  describeComparison,
  getScanRecipe,
  listFindings,
  triageFinding,
} from "./history.js";

/**
 * Read the version from package.json rather than hardcoding it.
 *
 * A hardcoded constant silently drifts from the published version the moment a
 * release bumps package.json alone, and `--version` is exactly what someone
 * reports in a bug. Resolved relative to this module so it works from `dist/`
 * whether the package is installed or run from a checkout.
 */
const VERSION: string = (() => {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      readFileSync(join(here, "..", "package.json"), "utf8"),
    ) as { version?: string };
    return pkg.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
})();

interface ParsedArgs {
  command: string;
  target?: string;
  paths: string[];
  outputDir?: string;
  model?: string;
  effort?: ScanOptions["effort"];
  pythonPath?: string;
  maxTurns?: number;
  maxCostUsd?: number;
  json: boolean;
  dryRun: boolean;
  resume: boolean;
  diff?: string;
  workingTree: boolean;
  deep: boolean;
  secondTarget?: string;
  uninstall: boolean;
  force: boolean;
  reason?: string;
  scanId?: string;
  withApiKey: boolean;
  workers?: number;
  maxAttempts?: number;
  failOnSeverity?: string;
  failOnImpact?: string;
  exportFormat?: string;
  output?: string;
  sourceRoot?: string;
}

/** A malformed command line. Always an exit-2 condition, never exit 1. */
class UsageError extends Error {}

/**
 * Every flag the parser accepts.
 *
 * Used for two things: rejecting unknown flags instead of dropping them, and
 * telling "the value is missing" apart from "the value happens to look odd".
 * A silently ignored `--max-cost` is a scan with no spending cap, and a typo'd
 * `--fail-on-severity` is a CI gate that quietly stops gating.
 */
const KNOWN_FLAGS = new Set([
  "--path", "--output-dir", "--model", "--effort", "--python",
  "--max-turns", "--max-cost", "--json", "--dry-run", "--resume",
  "--diff", "--working-tree", "--deep", "--uninstall", "--with-api-key",
  "--force", "--reason", "--scan", "--workers", "--max-attempts",
  "--fail-on-impact", "--fail-on-severity", "--export-format", "--output",
  "--source-root", "--help", "-h", "--version", "-v",
]);

const EFFORT_LEVELS = ["low", "medium", "high", "xhigh", "max"] as const;

function parse(argv: string[]): ParsedArgs {
  const args: ParsedArgs = {
    command: argv[0] ?? "help",
    paths: [],
    json: false,
    dryRun: false,
    resume: false,
    workingTree: false,
    deep: false,
    uninstall: false,
    force: false,
    withApiKey: false,
  };
  const rest = argv.slice(1);

  let i = 0;
  /** Consume the next token as a value, refusing another flag or nothing. */
  const value = (flag: string): string => {
    const next = rest[i + 1];
    if (next === undefined || KNOWN_FLAGS.has(next)) {
      throw new UsageError(`${flag} needs a value.`);
    }
    i += 1;
    return next;
  };
  const positiveNumber = (flag: string): number => {
    const raw = value(flag);
    const parsed = Number(raw);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new UsageError(`${flag} must be a positive number, not '${raw}'.`);
    }
    return parsed;
  };
  const positiveInteger = (flag: string): number => {
    const raw = value(flag);
    const parsed = Number(raw);
    if (!Number.isSafeInteger(parsed) || parsed <= 0) {
      throw new UsageError(`${flag} must be a positive whole number, not '${raw}'.`);
    }
    return parsed;
  };

  for (; i < rest.length; i++) {
    const a = rest[i];
    switch (a) {
      case "--path":
        args.paths.push(value("--path"));
        break;
      case "--output-dir":
        args.outputDir = value("--output-dir");
        break;
      case "--model":
        args.model = value("--model");
        break;
      case "--effort":
        {
          const raw = value("--effort");
          if (!(EFFORT_LEVELS as readonly string[]).includes(raw)) {
            throw new UsageError(
              `--effort must be one of: ${EFFORT_LEVELS.join(", ")} (got '${raw}').`,
            );
          }
          args.effort = raw as ScanOptions["effort"];
        }
        break;
      case "--python":
        args.pythonPath = value("--python");
        break;
      case "--max-turns":
        args.maxTurns = positiveInteger("--max-turns");
        break;
      case "--max-cost":
        args.maxCostUsd = positiveNumber("--max-cost");
        break;
      case "--json":
        args.json = true;
        break;
      case "--dry-run":
        args.dryRun = true;
        break;
      case "--resume":
        args.resume = true;
        break;
      case "--diff":
        args.diff = value("--diff");
        break;
      case "--working-tree":
        args.workingTree = true;
        break;
      case "--deep":
        args.deep = true;
        break;
      case "--uninstall":
        args.uninstall = true;
        break;
      case "--with-api-key":
        args.withApiKey = true;
        break;
      case "--force":
        args.force = true;
        break;
      case "--reason":
        args.reason = value("--reason");
        break;
      case "--scan":
        args.scanId = value("--scan");
        break;
      case "--workers":
        args.workers = positiveInteger("--workers");
        break;
      case "--max-attempts":
        args.maxAttempts = positiveInteger("--max-attempts");
        break;
      case "--fail-on-impact":
        args.failOnImpact = value("--fail-on-impact");
        break;
      case "--fail-on-severity":
        args.failOnSeverity = value("--fail-on-severity");
        break;
      case "--export-format":
        args.exportFormat = value("--export-format");
        break;
      case "--output":
        args.output = value("--output");
        break;
      case "--source-root":
        args.sourceRoot = value("--source-root");
        break;
      default:
        if (a.startsWith("--")) {
          throw new UsageError(`Unknown option '${a}'. Run --help for usage.`);
        }
        // Two positionals for `scans match|compare BEFORE AFTER`.
        if (args.target === undefined) args.target = a;
        else if (args.secondTarget === undefined) args.secondTarget = a;
        else throw new UsageError(`Unexpected extra argument '${a}'.`);
    }
  }
  return args;
}

function usage(): void {
  process.stdout.write(
    [
      "claude-security — Claude-powered security scanning",
      "",
      "Usage:",
      "  claude-security scan <path> [--path SUBPATH]... [--diff BASE|--working-tree|--deep]",
      "                        [--output-dir DIR]",
      "                        [--model ID] [--effort low|medium|high|xhigh|max]",
      "                        [--python PY] [--max-turns N] [--max-cost USD]",
      "                        [--resume] [--fail-on-severity LEVEL] [--fail-on-impact LEVEL]",
      "                        [--json] [--dry-run]",
      "  claude-security status <scan-dir> [--json]",
      "  claude-security policy <scan-dir> [--fail-on-severity LEVEL] [--fail-on-impact LEVEL]",
      "                        [--json]",
      "  claude-security usage <scan-dir> [--json]",
      "  claude-security scans list [REPO] [--json]",
      "  claude-security scans show <scan-id> [--json]",
      "  claude-security scans match <before-id> <after-id>",
      "  claude-security scans compare <before-id> <after-id> [--json]",
      "  claude-security scans rerun <scan-id> --output-dir DIR [--dry-run]",
      "  claude-security export <scan-dir> --export-format csv|json|sarif",
      "                        [--output PATH|-] [--source-root REPO]",
      "  claude-security bulk-scan <tasks.csv> --output-dir DIR [--workers N]",
      "                        [--max-attempts N] [--max-cost USD] [--json] [--dry-run]",
      "  claude-security findings list --scan <scan-id> [--json]",
      "  claude-security findings false-positive <occurrence-id> --reason TEXT",
      "  claude-security findings wont-fix <occurrence-id> --reason TEXT",
      "  claude-security findings reopen <occurrence-id>",
      "  claude-security install-hook [REPO] [--fail-on-severity LEVEL] [--max-cost USD]",
      "                        [--effort LEVEL] [--force] [--uninstall]",
      "  claude-security login --with-api-key   (reads the key from stdin)",
      "  claude-security login status [--json]",
      "  claude-security logout",
      "  claude-security info [--json]",
      "  claude-security --version",
      "",
      "Scans are report-only. The output directory must be outside the scanned repository.",
      "A scan that stops early (budget or turn cap) leaves its finished phases on disk;",
      "inspect them with `status` and continue with `scan ... --output-dir SAME --resume`.",
      "`export` and `policy` read a sealed scan offline: no agent, no credentials, no network.",
      "",
      "Exit codes: 0 pass or report-only, 1 policy violation, 2 invalid input or",
      "incomplete coverage. Severity levels: " + SEVERITY_LEVELS.join(" > ") + ".",
      "Authenticate with ANTHROPIC_API_KEY, `login --with-api-key`, or a Claude Code",
      "sign-in. `login status` shows which one a scan will actually use.",
      "",
    ].join("\n"),
  );
}

async function cmdScan(args: ParsedArgs): Promise<number> {
  if (!args.target) {
    process.stderr.write("error: scan requires a path\n");
    return 2;
  }
  // Validate the policy thresholds before spending anything on a scan.
  const threshold = parseThreshold(args.failOnSeverity);
  if (threshold === "invalid") {
    process.stderr.write(
      `error: invalid --fail-on-severity '${args.failOnSeverity}'. Use one of: ${SEVERITY_LEVELS.join(", ")}\n`,
    );
    return 2;
  }
  const impactThreshold = parseImpactThreshold(args.failOnImpact);
  if (impactThreshold === "invalid") {
    process.stderr.write(
      `error: invalid --fail-on-impact '${args.failOnImpact}'. Use one of: ${SEVERITY_LEVELS.join(", ")}\n`,
    );
    return 2;
  }
  const target = resolveTarget(args.target);
  // Check scope here too: --dry-run never reaches runScan, and validating input
  // is the whole point of a dry run.
  try {
    assertScopeInsideRepository(target.repoRoot, args.paths);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
  // Match what runScan will actually use, so --dry-run shows the real path.
  const scanDir = args.outputDir
    ? canonicalize(args.outputDir)
    : defaultScanDir(target);

  if (args.dryRun) {
    const plan = {
      repoRoot: target.repoRoot,
      repoName: target.repoName,
      targetId: target.targetId,
      git: target.git,
      scope: args.paths.length ? args.paths : ["(entire repository)"],
      mode: args.diff ? `diff:${args.diff}` : args.workingTree ? "working-tree" : args.deep ? "deep" : "repository",
      scanDir,
      model: args.model ?? "claude-opus-5",
      effort: args.effort ?? "xhigh",
      pluginDir: pluginDirectory(),
    };
    process.stdout.write(
      args.json
        ? JSON.stringify(plan, null, 2) + "\n"
        : `Dry run\n  target:   ${plan.repoRoot}\n  mode:     ${plan.mode}\n  scope:    ${plan.scope.join(", ")}\n  scanDir:  ${plan.scanDir}\n  model:    ${plan.model} (effort ${plan.effort})\n  plugin:   ${plan.pluginDir}\n`,
    );
    return 0;
  }

  // Credentials resolve the same way the Agent SDK resolves them: an env key,
  // an auth token, or an existing Claude Code login. Only warn when none of the
  // env vars are present — a stored login may still authenticate the run.
  if (!process.env.ANTHROPIC_API_KEY && !process.env.ANTHROPIC_AUTH_TOKEN) {
    process.stderr.write(
      "note: no ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN in the environment; relying on an existing Claude login.\n",
    );
  }

  const result = await runScan(args.target, {
    paths: args.paths,
    outputDir: args.outputDir,
    model: args.model,
    effort: args.effort,
    pythonPath: args.pythonPath,
    maxTurns: args.maxTurns,
    maxCostUsd: args.maxCostUsd,
    resume: args.resume,
    diff: args.diff,
    workingTree: args.workingTree,
    deep: args.deep,
    onMessage: args.json
      ? undefined
      : (m) => {
          const msg = m as { type?: string };
          if (msg.type === "assistant") process.stderr.write(".");
        },
  });

  // A scan that never sealed cannot be policy-checked: its findings are not
  // final. Report the runtime failure (exit 2) rather than an implied pass.
  const policy = result.ok
    ? evaluatePolicy(result.scanDir, threshold, impactThreshold, args.pythonPath)
    : null;

  if (args.json) {
    process.stdout.write(
      JSON.stringify({ ...result, policy }, null, 2) + "\n",
    );
  } else {
    process.stderr.write("\n");
    process.stdout.write(
      `${result.ok ? "Scan complete" : "Scan finished with gaps"}\n` +
        `  report:   ${result.reportPath}\n` +
        `  findings: ${result.findingsPath}\n` +
        "",
    );
    if (result.usage) {
      process.stdout.write(`  usage:    ${describeUsage(result.usage)}\n`);
    }
    if (policy) process.stdout.write("\n" + describePolicy(policy) + "\n");
  }

  if (!result.ok) return 2;
  return policy!.exitCode;
}

/** Validate a --fail-on-severity value, or null when the flag was omitted. */
function parseThreshold(raw: string | undefined): Severity | null | "invalid" {
  if (raw === undefined) return null;
  return SEVERITY_LEVELS.includes(raw as Severity) ? (raw as Severity) : "invalid";
}

/**
 * Validate --fail-on-impact. Returns null when omitted, "invalid" on a bad
 * value, so a typo is a config error rather than a silently disabled gate.
 */
function parseImpactThreshold(raw: string | undefined): Severity | null | "invalid" {
  return raw === undefined ? null : parseThreshold(raw);
}

function cmdPolicy(args: ParsedArgs): number {
  if (!args.target) {
    process.stderr.write("error: policy requires a scan directory\n");
    return 2;
  }
  const threshold = parseThreshold(args.failOnSeverity);
  if (threshold === "invalid") {
    process.stderr.write(
      `error: invalid --fail-on-severity '${args.failOnSeverity}'. Use one of: ${SEVERITY_LEVELS.join(", ")}\n`,
    );
    return 2;
  }
  const impactThreshold = parseImpactThreshold(args.failOnImpact);
  if (impactThreshold === "invalid") {
    process.stderr.write(
      `error: invalid --fail-on-impact '${args.failOnImpact}'. Use one of: ${SEVERITY_LEVELS.join(", ")}\n`,
    );
    return 2;
  }

  let result;
  try {
    result = evaluatePolicy(args.target, threshold, impactThreshold, args.pythonPath);
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
  if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    process.stdout.write(describePolicy(result) + "\n");
  }
  return result.exitCode;
}

async function cmdScans(args: ParsedArgs, sub: string | undefined): Promise<number> {
  try {
    if (sub === "list" || sub === undefined) {
      const scans = listScans({
        repository: args.target,
        scanRoot: args.outputDir,
        pythonPath: args.pythonPath,
      });
      if (args.json) {
        process.stdout.write(JSON.stringify(scans, null, 2) + "\n");
        return 0;
      }
      if (scans.length === 0) {
        process.stdout.write("No scans recorded.\n");
        return 0;
      }
      process.stdout.write(
        ["SCAN     ", "MODE     ", "STATE    ", "STARTED          ", "FINDINGS    ", "COST      ", "TARGET"].join(" ") + "\n",
      );
      for (const scan of scans) process.stdout.write(describeScanRow(scan) + "\n");
      return 0;
    }
    if (sub === "rerun") {
      if (!args.target) {
        process.stderr.write("error: scans rerun requires a scan id\n");
        return 2;
      }
      const { scanId, recipe } = getScanRecipe(args.target, args.pythonPath);
      const paths = recipe.target?.paths ?? [];

      if (recipe.target?.kind === "refs" || recipe.target?.kind === "working_tree") {
        process.stderr.write(
          "error: that scan was a diff scan. Rerunning a diff against a moved checkout\n" +
            "       would compare different revisions than the original; start a new\n" +
            "       scan with --diff or --working-tree instead.\n",
        );
        return 2;
      }
      if (!args.outputDir) {
        process.stderr.write("error: scans rerun requires --output-dir (it must be empty)\n");
        return 2;
      }

      // Flags given now override the recorded recipe; everything else is reused.
      const model = args.model ?? recipe.config?.model;
      const effort = args.effort ?? (recipe.config?.effort as ScanOptions["effort"]);
      process.stdout.write(
        `Rerunning ${scanId.slice(0, 8)} against the current checkout\n` +
          `  repository: ${recipe.repository}\n` +
          `  mode:       ${recipe.mode}\n` +
          `  scope:      ${paths.length > 0 ? paths.join(", ") : "(entire repository)"}\n` +
          `  model:      ${model ?? "claude-opus-5"}\n\n`,
      );
      if (args.dryRun) return 0;

      const result = await runScanDirect(recipe.repository, {
        paths,
        outputDir: args.outputDir,
        deep: recipe.mode === "deep",
        model,
        effort,
        maxCostUsd: args.maxCostUsd,
        maxTurns: args.maxTurns,
        pythonPath: args.pythonPath,
        parentScanId: scanId,
        onMessage: args.json
          ? undefined
          : (m) => {
              const msg = m as { type?: string; message?: string };
              if (msg.type === "assistant") process.stderr.write(".");
              else if (msg.type === "history_warning") {
                process.stderr.write(`\nwarning: ${msg.message}\n`);
              }
            },
      });
      if (args.json) {
        process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      } else {
        process.stderr.write("\n");
        process.stdout.write(
          `${result.ok ? "Rerun complete" : "Rerun finished with gaps"}\n` +
            `  report: ${result.reportPath}\n` +
            (result.scanId
              ? `\nCompare with the original:\n` +
                `  claude-security scans match   ${scanId.slice(0, 8)} ${result.scanId.slice(0, 8)}\n` +
                `  claude-security scans compare ${scanId.slice(0, 8)} ${result.scanId.slice(0, 8)}\n`
              : ""),
        );
      }
      return result.ok ? 0 : 2;
    }
    if (sub === "match" || sub === "compare") {
      const before = args.target;
      const after = args.paths[0] ?? args.secondTarget;
      if (!before || !after) {
        process.stderr.write(`error: scans ${sub} requires BEFORE and AFTER scan ids\n`);
        return 2;
      }
      if (sub === "match") {
        const result = matchScans(before, after, args.pythonPath);
        process.stdout.write(
          args.json
            ? JSON.stringify(result, null, 2) + "\n"
            : `Linked ${result.matched} finding(s); ${result.uncertain} uncertain.\n`,
        );
        return 0;
      }
      const result = compareScans(before, after, args.pythonPath);
      process.stdout.write(
        args.json
          ? JSON.stringify(result, null, 2) + "\n"
          : describeComparison(result) + "\n",
      );
      return 0;
    }
    if (sub === "show") {
      if (!args.target) {
        process.stderr.write("error: scans show requires a scan id\n");
        return 2;
      }
      const scan = getScan(args.target, args.pythonPath);
      if (args.json) {
        process.stdout.write(JSON.stringify(scan, null, 2) + "\n");
      } else {
        process.stdout.write(
          `Scan ${scan.scanId}\n` +
            `  target:   ${scan.targetPath}\n` +
            `  revision: ${scan.targetRevision ?? "(none)"}\n` +
            `  mode:     ${scan.mode}\n` +
            `  scope:    ${scan.scope ?? "."}\n` +
            `  dir:      ${scan.scanDir}\n` +
            `  started:  ${scan.startedAt ?? "?"}\n` +
            `  state:    ${scan.completedAt ? "complete" : "running"}\n` +
            `  findings: ${scan.findingCount ?? 0}\n` +
            (scan.cost
              ? `  cost:     ${scan.cost.estimatedUsd.toFixed(4)} USD (${scan.cost.model}, ` +
                `${scan.cost.outputTokens.toLocaleString()} out / ` +
                `${scan.cost.cachedInputTokens.toLocaleString()} cache-read)\n`
              : ""),
        );
      }
      return 0;
    }
    process.stderr.write(`error: unknown scans subcommand '${sub}'. Use list or show.\n`);
    return 2;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

async function cmdLogin(args: ParsedArgs, sub: string | undefined): Promise<number> {
  try {
    if (sub === "status" || args.target === "status") {
      const status = credentialStatus();
      process.stdout.write(
        args.json
          ? JSON.stringify(status, null, 2) + "\n"
          : describeCredentialStatus(status) + "\n",
      );
      return status.effective === "none" ? 2 : 0;
    }

    if (!args.withApiKey) {
      process.stderr.write(
        "claude-security does not implement its own browser sign-in: third-party tools\n" +
          "cannot offer claude.ai login. Use one of these instead:\n\n" +
          "  printenv ANTHROPIC_API_KEY | claude-security login --with-api-key\n" +
          "  export ANTHROPIC_API_KEY=sk-...\n" +
          "  sign in with Claude Code, or run `ant auth login`\n\n" +
          "Then check what will be used with `claude-security login status`.\n",
      );
      return 2;
    }

    if (process.stdin.isTTY) {
      process.stderr.write(
        "error: pipe the key on stdin so it does not land in your shell history:\n" +
          "  printenv ANTHROPIC_API_KEY | claude-security login --with-api-key\n",
      );
      return 2;
    }
    const { path } = storeApiKey(await readStdin());
    const status = credentialStatus();
    process.stdout.write(`Stored an API key at ${path} (mode 600).\n`);
    if (status.effective !== "stored-api-key") {
      process.stdout.write(
        `\nNote: scans will still use ${describeCredentialSource(status.effective)},\n` +
          "which outranks the stored key. Unset it to use what you just stored.\n",
      );
    }
    return 0;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
}

function cmdLogout(args: ParsedArgs): number {
  const { removed, remaining } = clearStoredKey();
  process.stdout.write(
    removed ? "Removed the stored API key.\n" : "No stored API key to remove.\n",
  );
  if (remaining.length > 0) {
    process.stdout.write(
      "\nYou are still authenticated by:\n" +
        remaining.map((s) => `  - ${describeCredentialSource(s)}`).join("\n") +
        "\n\nUnset those to be fully signed out.\n",
    );
  }
  return 0;
}

async function cmdBulkScan(args: ParsedArgs): Promise<number> {
  if (!args.target) {
    process.stderr.write("error: bulk-scan requires a task CSV path\n");
    return 2;
  }
  if (!args.outputDir) {
    process.stderr.write("error: bulk-scan requires --output-dir\n");
    return 2;
  }
  try {
    if (args.dryRun) {
      const tasks = parseTasks(readFileSync(canonicalize(args.target), "utf8"));
      if (args.json) {
        process.stdout.write(JSON.stringify(tasks, null, 2) + "\n");
      } else {
        process.stdout.write(`${tasks.length} task(s)\n`);
        for (const t of tasks) {
          process.stdout.write(
            `  ${t.id.padEnd(20)} ${(t.mode ?? "standard").padEnd(9)} ${t.revision.slice(0, 10)} ${t.scope ?? "."}  ${t.repository}\n`,
          );
        }
      }
      return 0;
    }

    const result = await runBulkScan({
      inputPath: args.target,
      outputDir: args.outputDir,
      workers: args.workers,
      maxAttempts: args.maxAttempts,
      maxCostUsd: args.maxCostUsd,
      model: args.model,
      effort: args.effort,
      pythonPath: args.pythonPath,
      onProgress: args.json
        ? undefined
        : (e) => {
            const suffix = e.error ? `: ${e.error}` : "";
            process.stderr.write(`  [${e.status}] ${e.id} (attempt ${e.attempt})${suffix}\n`);
          },
    });

    if (args.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      process.stdout.write(
        `\n${result.completed} completed, ${result.failed} failed, ${result.skipped} skipped ` +
          `of ${result.total}\n  receipts: ${result.resultsPath}\n\n` +
          summariseBulk(result.resultsPath) + "\n",
      );
    }
    // Any task that never produced a sealed scan is a failure of the run.
    return result.failed > 0 ? 2 : 0;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
}

function cmdFindings(args: ParsedArgs, sub: string | undefined): number {
  try {
    if (sub === "list") {
      if (!args.scanId) {
        process.stderr.write("error: findings list requires --scan <scan-id>\n");
        return 2;
      }
      const { findings, total } = listFindings(args.scanId, { pythonPath: args.pythonPath });
      if (args.json) {
        process.stdout.write(JSON.stringify(findings, null, 2) + "\n");
        return 0;
      }
      process.stdout.write(`${total} finding(s)\n`);
      for (const f of findings) {
        const state = f.status === "closed" ? `closed:${f.closeReason ?? "?"}` : "open";
        process.stdout.write(
          `  ${f.occurrenceId}  ${String(f.severity ?? "").padEnd(7)} ${state.padEnd(22)} ${f.title ?? ""}\n`,
        );
      }
      return 0;
    }
    if (sub === "false-positive" || sub === "wont-fix" || sub === "reopen") {
      if (!args.target) {
        process.stderr.write(`error: findings ${sub} requires an occurrence id\n`);
        return 2;
      }
      if (sub === "reopen") {
        triageFinding(args.target, { status: "open", pythonPath: args.pythonPath });
        process.stdout.write(`Reopened ${args.target}\n`);
        return 0;
      }
      if (!args.reason) {
        process.stderr.write(
          `error: findings ${sub} requires --reason "..." — a later scan reuses the\n` +
            "       stated reason to decide whether the dismissal still applies.\n",
        );
        return 2;
      }
      triageFinding(args.target, {
        status: "closed",
        closeReason: sub === "false-positive" ? "false_positive" : "wont_fix",
        note: args.reason,
        pythonPath: args.pythonPath,
      });
      process.stdout.write(`Marked ${args.target} as ${sub.replace("-", " ")}\n`);
      return 0;
    }
    process.stderr.write(
      `error: unknown findings subcommand '${sub ?? ""}'. Use list, false-positive, wont-fix, or reopen.\n`,
    );
    return 2;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
}

function cmdInstallHook(args: ParsedArgs): number {
  const repository = args.target ?? process.cwd();
  try {
    if (args.uninstall) {
      const result = uninstallHook(repository, args.force);
      process.stdout.write(
        result.removed
          ? `Removed pre-commit hook at ${result.hookPath}\n`
          : `No pre-commit hook at ${result.hookPath}\n`,
      );
      return 0;
    }
    const threshold = parseThreshold(args.failOnSeverity);
    if (threshold === "invalid") {
      process.stderr.write(
        `error: invalid --fail-on-severity '${args.failOnSeverity}'. Use one of: ${SEVERITY_LEVELS.join(", ")}\n`,
      );
      return 2;
    }
    const result = installHook(repository, {
      failOnSeverity: threshold ?? undefined,
      maxCostUsd: args.maxCostUsd,
      effort: args.effort,
      force: args.force,
    });
    process.stdout.write(
      `${result.action === "replaced" ? "Replaced" : "Installed"} pre-commit hook at ${result.hookPath}\n` +
        `  blocks at: ${threshold ?? "high"} or above\n` +
        `  max cost:  $${args.maxCostUsd ?? 5} per commit\n` +
        `  effort:    ${args.effort ?? "medium"}\n` +
        `\nSkip one commit with CLAUDE_SECURITY_SKIP=1 git commit ...\n`,
    );
    return 0;
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }
}

function cmdUsage(args: ParsedArgs): number {
  if (!args.target) {
    process.stderr.write("error: usage requires a scan directory\n");
    return 2;
  }
  const path = join(canonicalize(args.target), "usage.json");
  if (!existsSync(path)) {
    process.stderr.write(`error: no usage.json in ${canonicalize(args.target)}\n`);
    return 2;
  }
  const snapshot = JSON.parse(readFileSync(path, "utf8")) as UsageSnapshot;
  process.stdout.write(
    args.json
      ? JSON.stringify(snapshot, null, 2) + "\n"
      : describeUsage(snapshot) + "\n",
  );
  return 0;
}

function cmdExport(args: ParsedArgs): number {
  if (!args.target) {
    process.stderr.write("error: export requires a scan directory\n");
    return 2;
  }
  if (!args.exportFormat) {
    process.stderr.write(
      `error: export requires --export-format (${EXPORT_FORMATS.join("|")})\n`,
    );
    return 2;
  }
  if (!EXPORT_FORMATS.includes(args.exportFormat as ExportFormat)) {
    process.stderr.write(
      `error: unsupported export format '${args.exportFormat}'. Use one of: ${EXPORT_FORMATS.join(", ")}\n`,
    );
    return 2;
  }
  // CSV to stdout would interleave with JSON status output on the same stream.
  if (args.json && args.output === "-" && args.exportFormat === "csv") {
    process.stderr.write(
      "error: CSV cannot be written to stdout while --json is requested\n",
    );
    return 2;
  }

  let result;
  try {
    result = exportFindings(args.target, {
      format: args.exportFormat as ExportFormat,
      output: args.output,
      sourceRoot: args.sourceRoot,
      pythonPath: args.pythonPath,
    });
  } catch (err) {
    process.stderr.write(`error: ${(err as Error).message}\n`);
    return 2;
  }

  if (result.outputPath === null) return 0; // already streamed to stdout
  if (args.json) {
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    process.stdout.write(`Wrote ${result.format} export to ${result.outputPath}\n`);
  }
  return 0;
}

function cmdStatus(args: ParsedArgs): number {
  if (!args.target) {
    process.stderr.write("error: status requires a scan directory\n");
    return 2;
  }
  const scanDir = canonicalize(args.target);
  const state = inspectScanState(scanDir);

  if (args.json) {
    process.stdout.write(JSON.stringify(state, null, 2) + "\n");
    return state.empty ? 2 : 0;
  }

  if (state.empty) {
    process.stdout.write(`No scan artifacts in ${scanDir}\n`);
    return 2;
  }

  const mark = (done: boolean) => (done ? "done" : "pending");
  process.stdout.write(
    `Scan directory: ${scanDir}\n` +
      `  threat model    ${mark(state.completed.includes("threat_model"))}\n` +
      `  ${state.diffScan ? "changed files " : "file list     "}  ${mark(state.completed.includes("file_list"))}` +
      (state.inScopeFileCount !== undefined ? ` (${state.inScopeFileCount} files)` : "") +
      "\n" +
      `  discovery       ${mark(state.completed.includes("discovery"))}` +
      // File coverage is what closes discovery, so lead with it. Candidate
      // count alone told the reader nothing about how much was left to scan.
      (state.reviewedFileCount !== undefined && state.inScopeFileCount !== undefined
        ? ` (${state.reviewedFileCount}/${state.inScopeFileCount} files reviewed` +
          (state.ledgerRows !== undefined ? `, ${state.ledgerRows} candidates)` : ")")
        : state.ledgerRows !== undefined
          ? ` (${state.ledgerRows} candidates)`
          : "") +
      "\n" +
      `  validation      ${mark(state.completed.includes("validation"))}` +
      (state.ledgerRows ? ` (${state.ledgerValidated}/${state.ledgerRows})` : "") +
      "\n" +
      `  attack path     ${mark(state.completed.includes("attack_path"))}` +
      (state.ledgerRows
        ? ` (${state.ledgerAttackPath}/${state.attackPathEligible ?? state.ledgerRows} eligible)`
        : "") +
      "\n" +
      `  canonical JSON  ${mark(state.completed.includes("canonical_json"))}\n` +
      `  finalized       ${mark(state.sealed)}\n` +
      (state.nextPhase
        ? `\nNext phase: ${state.nextPhase}. Resume with --output-dir ${scanDir} --resume\n`
        : "\nScan is complete and sealed.\n"),
  );
  return 0;
}

function cmdInfo(args: ParsedArgs): number {
  const info = {
    name: "claude-security",
    version: VERSION,
    pluginDir: pluginDirectory(),
    defaultModel: "claude-opus-5",
    defaultEffort: "xhigh",
  };
  process.stdout.write(
    args.json ? JSON.stringify(info, null, 2) + "\n" : `claude-security ${VERSION}\n  plugin: ${info.pluginDir}\n  model:  ${info.defaultModel} (effort ${info.defaultEffort})\n`,
  );
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  // Asking for help is never a usage error. Handle it before parsing so
  // `findings false-positive --help` prints usage instead of complaining about a
  // missing occurrence id.
  if (argv.some((a) => a === "--help" || a === "-h")) {
    usage();
    return 0;
  }
  // Strip a subcommand before parsing. `scans compare A B` has two real
  // positionals; leaving "compare" in front would consume one of their slots
  // and make a valid command look like it had an extra argument.
  const subcommandOf = new Set(["scans", "findings", "login"]);
  const sub =
    subcommandOf.has(argv[0]) && argv[1] && !argv[1].startsWith("--")
      ? argv[1]
      : undefined;

  let args: ParsedArgs;
  try {
    args = parse(sub ? [argv[0], ...argv.slice(2)] : argv);
  } catch (err) {
    if (err instanceof UsageError) {
      // A malformed command line is invalid input, so exit 2. Exit 1 is
      // reserved for a completed scan that violates policy, and conflating the
      // two makes CI read a typo as a security finding.
      process.stderr.write(`error: ${err.message}\n`);
      return 2;
    }
    throw err;
  }
  if (args.command === "--version" || args.command === "-v") {
    process.stdout.write(VERSION + "\n");
    return 0;
  }
  switch (args.command) {
    case "scan":
      return cmdScan(args);
    case "status":
      return cmdStatus(args);
    case "export":
      return cmdExport(args);
    case "policy":
      return cmdPolicy(args);
    case "usage":
      return cmdUsage(args);
    case "install-hook":
      return cmdInstallHook(args);
    case "login":
      return cmdLogin(args, sub);
    case "logout":
      return cmdLogout(args);
    case "bulk-scan":
      return cmdBulkScan(args);
    case "findings":
      return cmdFindings(args, sub);
    case "scans":
      return await cmdScans(args, sub);
    case "info":
      return cmdInfo(args);
    case "help":
    case "--help":
    case "-h":
      usage();
      return 0;
    default:
      process.stderr.write(`error: unknown command '${args.command}'\n\n`);
      usage();
      return 2;
  }
}
