import { spawnSync } from "node:child_process";
import { join } from "node:path";

import { pluginDirectory, resolvePython } from "./runtime.js";
import type { ResolvedTarget } from "./paths.js";
import { formatUsd, type ScanCost } from "./cost.js";

export interface ScanRecord {
  scanId: string;
  targetId: string;
  targetPath: string;
  targetRevision?: string;
  scanDir: string;
  mode: string;
  scope?: string;
  startedAt?: string;
  completedAt?: string | null;
  findingCount?: number;
  cost?: ScanCost | null;
  progress?: unknown;
  [key: string]: unknown;
}

export interface ListScansOptions {
  limit?: number;
  offset?: number;
  repository?: string;
  mode?: string;
  scanRoot?: string;
  pythonPath?: string;
}

/**
 * Call the workbench bridge and parse its single JSON object.
 *
 * The workbench is SQLite plus plain Python — model-agnostic, so it is reused
 * from codex-security as-is. `workbench_cli.py` upstream only parses arguments
 * (the MCP server owned dispatch), so `workbench_bridge.py` supplies the
 * dispatch this CLI needs.
 */
function callBridge(
  command:
    | "register"
    | "list"
    | "get"
    | "complete"
    | "match"
    | "compare"
    | "triage"
    | "feedback"
    | "findings"
    | "recipe"
    | "contract",
  payload: Record<string, unknown>,
  pythonPath?: string,
): Record<string, unknown> {
  const python = resolvePython(pythonPath);
  const script = join(pluginDirectory(), "scripts", "workbench_bridge.py");
  const run = spawnSync(python, [script, command, JSON.stringify(payload)], {
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });

  if (run.error) {
    throw new Error(`Failed to run the workbench bridge: ${run.error.message}`);
  }
  const stdout = (run.stdout ?? "").trim();
  if (!stdout) {
    const stderr = (run.stderr ?? "").trim();
    throw new Error(`Workbench bridge produced no output${stderr ? `: ${stderr}` : ""}`);
  }

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(stdout) as Record<string, unknown>;
  } catch {
    throw new Error(`Workbench bridge returned invalid JSON: ${stdout.slice(0, 200)}`);
  }
  if (typeof parsed.error === "string") {
    throw new Error(parsed.error);
  }
  return parsed;
}

/**
 * Register a scan before it starts.
 *
 * The workbench requires an empty scan directory: a scan is registered at
 * launch so it can be tracked while running, not recorded after the fact.
 */
export function registerScan(args: {
  target: ResolvedTarget;
  scanDir: string;
  mode: "standard" | "deep";
  paths: string[];
  /**
   * The change set for a diff scan. The workbench resolves and pins this at
   * registration — it re-derives the same values when sealing and rejects a
   * manifest that disagrees — so a diff scan that omits it is recorded as an
   * ordinary scan and can never be sealed.
   */
  diff?: { base: string; workingTree: boolean };
  model: string;
  effort: string;
  /** Links a rerun to the scan it repeats. */
  parentScanId?: string;
  pythonPath?: string;
}): { scanId: string; targetId: string } {
  const recipe = {
    repository: args.target.repoRoot,
    mode: args.mode,
    config: { model: args.model, effort: args.effort },
    target: args.diff
      ? args.diff.workingTree
        ? { kind: "working_tree", base: "HEAD", head: "HEAD", paths: [] }
        : { kind: "refs", base: args.diff.base, head: "HEAD", paths: [] }
      : args.paths.length > 0
        ? { kind: "paths", paths: args.paths }
        : { kind: "repository", paths: [] },
  };
  const result = callBridge(
    "register",
    {
      scan_dir: args.scanDir,
      repository: args.target.repoRoot,
      recipe_json: JSON.stringify(recipe),
      parent_scan_id: args.parentScanId,
    },
    args.pythonPath,
  );
  return {
    scanId: String(result.scanId),
    targetId: String(result.targetId),
  };
}

export function listScans(options: ListScansOptions = {}): ScanRecord[] {
  const result = callBridge(
    "list",
    {
      limit: options.limit ?? 25,
      offset: options.offset ?? 0,
      repository: options.repository,
      mode: options.mode,
      scan_root: options.scanRoot,
    },
    options.pythonPath,
  );
  return (result.scans as ScanRecord[]) ?? [];
}

/** Look up one scan by full id or a unique id prefix. */
export function getScan(scanId: string, pythonPath?: string): ScanRecord {
  return callBridge("get", { scan_id: scanId }, pythonPath) as unknown as ScanRecord;
}

export interface ScanRecipe {
  repository: string;
  mode: "standard" | "deep";
  config?: { model?: string; effort?: string };
  target: { kind: string; paths: string[]; base?: string; head?: string };
}

/** The launch recipe a scan was registered with. */
export function getScanRecipe(
  scanId: string,
  pythonPath?: string,
): { scanId: string; recipe: ScanRecipe; parentScanId: string | null } {
  const result = callBridge("recipe", { scan_id: scanId }, pythonPath);
  return {
    scanId: String(result.scanId),
    recipe: result.recipe as ScanRecipe,
    parentScanId: (result.parentScanId as string | null) ?? null,
  };
}

export interface ScanContract {
  target: {
    allowedKinds: string[];
    displayName: string;
    targetId: string;
    requiredSnapshotDigest?: string;
  };
  scope: {
    requestedPath: string;
    requiredIncludePaths?: string[];
    requiredExcludePaths: string[];
  };
  diffTarget: Record<string, string> | null;
}

/**
 * The manifest contract a draft must satisfy to be sealable.
 *
 * `completeScan` re-derives this and refuses a draft that disagrees, so the
 * agent must be told it before it writes scan-manifest.json rather than after
 * the scan has already been paid for.
 */
export function getScanContract(scanId: string, pythonPath?: string): ScanContract {
  return callBridge("contract", { scan_id: scanId }, pythonPath) as unknown as ScanContract;
}

export interface CompareSummary {
  new: number;
  persisting: number;
  resolved: number;
  reopened: number;
  unknown: number;
}

export interface CompareResult {
  beforeScanId: string;
  afterScanId: string;
  comparable: boolean;
  summary: CompareSummary;
  findings: {
    title?: string;
    severity?: string;
    status?: string;
    path?: string;
    [key: string]: unknown;
  }[];
  [key: string]: unknown;
}

/** Seal a scan into the workbench so its findings become comparable. */
export function completeScan(
  scanId: string,
  options: { cost?: ScanCost; pythonPath?: string } = {},
): Record<string, unknown> {
  return callBridge(
    "complete",
    { scan_id: scanId, cost: options.cost },
    options.pythonPath,
  );
}

/**
 * Link findings that share a root cause across two sealed scans.
 *
 * Must run before `compareScans`: without saved matches, compare cannot tell a
 * finding that persisted from one that was fixed and separately re-found, and
 * reports every finding as both resolved and new.
 */
export function matchScans(
  beforeScanId: string,
  afterScanId: string,
  pythonPath?: string,
): { matched: number; uncertain: number } {
  const result = callBridge(
    "match",
    { before_scan_id: beforeScanId, after_scan_id: afterScanId },
    pythonPath,
  );
  return {
    matched: Number(result.matched ?? 0),
    uncertain: Number(result.uncertain ?? 0),
  };
}

/** Diff two sealed scans into new / persisting / resolved / reopened / unknown. */
export function compareScans(
  beforeScanId: string,
  afterScanId: string,
  pythonPath?: string,
): CompareResult {
  return callBridge(
    "compare",
    { before_scan_id: beforeScanId, after_scan_id: afterScanId },
    pythonPath,
  ) as unknown as CompareResult;
}

/** Human-readable rendering of a comparison. */
export function describeComparison(result: CompareResult): string {
  const s = result.summary;
  const lines = [
    `Comparing ${result.beforeScanId.slice(0, 8)} -> ${result.afterScanId.slice(0, 8)}`,
    "",
    `  resolved    ${s.resolved}`,
    `  persisting  ${s.persisting}`,
    `  new         ${s.new}`,
    `  reopened    ${s.reopened}`,
    `  unknown     ${s.unknown}`,
  ];
  const notable = result.findings.filter((f) => f.status !== "persisting");
  if (notable.length > 0) {
    lines.push("");
    for (const f of notable) {
      lines.push(`  [${String(f.status).padEnd(9)}] ${String(f.severity ?? "").padEnd(7)} ${f.title ?? ""}`);
    }
  }
  if (!result.comparable) {
    lines.push(
      "",
      "The later scan's coverage is not complete, so a missing finding cannot be",
      "treated as resolved.",
    );
  }
  return lines.join("\n");
}

export interface FindingRow {
  occurrenceId: string;
  title?: string;
  severity?: string;
  status?: string;
  closeReason?: string | null;
  note?: string | null;
}

/** List a scan's findings with their occurrence ids and triage state. */
export function listFindings(
  scanId: string,
  options: { limit?: number; pythonPath?: string } = {},
): { findings: FindingRow[]; total: number } {
  const result = callBridge(
    "findings",
    { scan_id: scanId, limit: options.limit ?? 100 },
    options.pythonPath,
  );
  return {
    findings: (result.findings as FindingRow[]) ?? [],
    total: Number(result.total ?? 0),
  };
}

/**
 * Record a human verdict on one finding.
 *
 * A dismissal must carry a reason: later scans reuse the stated reason to
 * decide whether the dismissal still applies, so an unexplained one cannot be
 * re-evaluated and would silently suppress the finding forever.
 */
export function triageFinding(
  occurrenceId: string,
  options: {
    status?: "open" | "closed";
    closeReason?: "false_positive" | "wont_fix" | "fixed";
    note?: string;
    pythonPath?: string;
  } = {},
): Record<string, unknown> {
  return callBridge(
    "triage",
    {
      occurrence_id: occurrenceId,
      status: options.status ?? "closed",
      close_reason: options.closeReason,
      note: options.note,
    },
    options.pythonPath,
  );
}

export interface DismissedFinding {
  fingerprint: string;
  ruleId?: string;
  title?: string;
  reason?: string;
  locations?: { path?: string; startLine?: number }[];
}

/** Prior dismissals that apply to this scan's target, keyed by fingerprint. */
export function scanFeedback(
  scanId: string,
  pythonPath?: string,
): { falsePositives: DismissedFinding[] } {
  const result = callBridge("feedback", { scan_id: scanId }, pythonPath);
  return { falsePositives: (result.falsePositives as DismissedFinding[]) ?? [] };
}

/**
 * Render prior dismissals as a briefing for the scanning agent.
 *
 * The reason is the load-bearing part: a dismissal is only valid while its
 * stated justification still holds, so the agent is asked to re-check the
 * reason against the current code rather than suppress on sight.
 */
export function describeDismissals(dismissed: DismissedFinding[]): string {
  const lines = [
    "A reviewer previously dismissed the findings below on this target.",
    "",
    "For each one, check whether the stated reason still holds in the code you are",
    "reviewing now. If it does, do not report the finding again. If the code changed",
    "so that the reason no longer holds, report it — a stale dismissal must not hide a",
    "live bug. Do not extend a dismissal to a different finding that merely looks similar.",
    "",
  ];
  for (const d of dismissed) {
    const where = d.locations?.[0]
      ? ` (${d.locations[0].path}:${d.locations[0].startLine})`
      : "";
    lines.push(`- ${d.title ?? d.ruleId ?? d.fingerprint}${where}`);
    lines.push(`  Dismissed because: ${d.reason ?? "(no reason recorded)"}`);
  }
  return lines.join("\n");
}

/** Compact one-line rendering for `scans list`. */
export function describeScanRow(scan: ScanRecord): string {
  const id = scan.scanId.slice(0, 8);
  const when = (scan.startedAt ?? "").slice(0, 16).replace("T", " ");
  const state = scan.completedAt ? "complete" : "running";
  const findings =
    typeof scan.findingCount === "number" ? `${scan.findingCount} findings` : "";
  const cost = scan.cost ? formatUsd(scan.cost.estimatedUsd) : "";
  return [
    id.padEnd(9),
    (scan.mode ?? "").padEnd(9),
    state.padEnd(9),
    when.padEnd(17),
    findings.padEnd(12),
    cost.padEnd(10),
    scan.targetPath ?? "",
  ].join(" ");
}
