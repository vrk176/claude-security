import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

/** Phases of a standard scan, in the order the skill runs them. */
export type ScanPhase =
  | "threat_model"
  | "file_list"
  | "discovery"
  | "validation"
  | "attack_path"
  | "canonical_json"
  | "sealed";

export interface ScanState {
  scanDir: string;
  /** True when the directory holds no scan artifacts at all. */
  empty: boolean;
  /** Phases already satisfied on disk. */
  completed: ScanPhase[];
  /** The first phase that still needs work, or null when the scan is sealed. */
  nextPhase: ScanPhase | null;
  threatModelPath?: string;
  inScopeFileCount?: number;
  ledgerRows?: number;
  ledgerValidated?: number;
  ledgerAttackPath?: number;
  /** Rows the attack-path phase is expected to touch (reportable + deferred). */
  attackPathEligible?: number;
  /** True when the artifacts are diff-scan shaped rather than standard-scan shaped. */
  diffScan?: boolean;
  /** Per-file completion rows, for diff scans. */
  workLedgerRows?: number;
  hasFindings: boolean;
  hasCoverage: boolean;
  hasManifest: boolean;
  sealed: boolean;
}

const PHASE_ORDER: ScanPhase[] = [
  "threat_model",
  "file_list",
  "discovery",
  "validation",
  "attack_path",
  "canonical_json",
  "sealed",
];

function countLines(path: string): number {
  try {
    const text = readFileSync(path, "utf8");
    return text.split("\n").filter((line) => line.trim().length > 0).length;
  } catch {
    return 0;
  }
}

interface LedgerRow {
  validation?: { disposition?: string };
  attack_path?: unknown;
}

function readLedger(path: string): LedgerRow[] {
  try {
    return readFileSync(path, "utf8")
      .split("\n")
      .filter((line) => line.trim().length > 0)
      .flatMap((line) => {
        try {
          return [JSON.parse(line) as LedgerRow];
        } catch {
          return [];
        }
      });
  } catch {
    return [];
  }
}

/**
 * Rows that the attack-path phase is expected to touch.
 *
 * The phase only runs over candidates whose validation disposition is
 * `reportable` or `deferred`; a `suppressed` or `not_applicable` row is closed
 * by validation and never gets an attack_path record. Counting those rows as
 * outstanding would leave a finished scan looking permanently incomplete.
 */
function attackPathEligible(rows: LedgerRow[]): number {
  return rows.filter((row) => {
    const disposition = row.validation?.disposition;
    return disposition === "reportable" || disposition === "deferred";
  }).length;
}

/**
 * Inspect a scan directory and work out which phases are already done.
 *
 * A scan can stop part-way for reasons outside our control (budget cap, turn
 * cap, cancellation), and the phase artifacts on disk are the durable record of
 * how far it got. Reading them lets a resume skip completed work instead of
 * paying for it twice.
 */
export function inspectScanState(scanDir: string): ScanState {
  const context = join(scanDir, "artifacts", "01_context");
  const discovery = join(scanDir, "artifacts", "02_discovery");
  const threatModel = join(context, "threat_model.md");
  // A standard scan enumerates scope into in_scope_files.txt; a diff scan builds
  // deep_review_input.jsonl from the changed files instead. Either one means the
  // scope is settled, so accept whichever the workflow produced.
  const inScope = join(discovery, "in_scope_files.txt");
  const diffWorklist = join(discovery, "deep_review_input.jsonl");
  const ledger = join(discovery, "candidate_ledger.jsonl");
  // Likewise, a diff scan records per-file completion in work_ledger.jsonl
  // rather than accumulating candidates in candidate_ledger.jsonl.
  const workLedger = join(discovery, "work_ledger.jsonl");

  const findings = join(scanDir, "findings.json");
  const coverage = join(scanDir, "coverage.json");
  const manifest = join(scanDir, "scan-manifest.json");
  const report = join(scanDir, "report.md");

  const state: ScanState = {
    scanDir,
    empty: true,
    completed: [],
    nextPhase: "threat_model",
    hasFindings: existsSync(findings),
    hasCoverage: existsSync(coverage),
    hasManifest: existsSync(manifest),
    sealed: existsSync(report),
  };

  try {
    state.empty = readdirSync(scanDir).length === 0;
  } catch {
    state.empty = true;
    return state;
  }

  if (existsSync(threatModel)) {
    state.completed.push("threat_model");
    state.threatModelPath = threatModel;
  }
  if (existsSync(inScope)) {
    state.completed.push("file_list");
    state.inScopeFileCount = countLines(inScope);
  } else if (existsSync(diffWorklist)) {
    state.completed.push("file_list");
    state.inScopeFileCount = countLines(diffWorklist);
    state.diffScan = true;
  }

  // Diff scans close discovery with a per-file work ledger instead of a
  // candidate ledger; treat a completed worklist as discovery done.
  if (!existsSync(ledger) && existsSync(workLedger)) {
    state.workLedgerRows = countLines(workLedger);
    if (state.workLedgerRows > 0) state.completed.push("discovery");
  }

  if (existsSync(ledger)) {
    const parsed = readLedger(ledger);
    const rows = parsed.length;
    state.ledgerRows = rows;
    state.ledgerValidated = parsed.filter((row) => row.validation !== undefined).length;
    state.ledgerAttackPath = parsed.filter((row) => row.attack_path !== undefined).length;
    state.attackPathEligible = attackPathEligible(parsed);
    if (rows > 0) state.completed.push("discovery");
    // Validation must touch every row; attack-path only the eligible ones.
    const validationDone = rows > 0 && state.ledgerValidated === rows;
    if (validationDone) state.completed.push("validation");
    // Eligibility is derived from validation dispositions, so an unvalidated
    // ledger yields 0 eligible rows — which would otherwise read as "0 of 0
    // done". Attack-path can only be complete once validation actually ran.
    if (validationDone && state.ledgerAttackPath >= state.attackPathEligible) {
      state.completed.push("attack_path");
    }
  }
  if (state.hasFindings && state.hasCoverage && state.hasManifest) {
    state.completed.push("canonical_json");
    // A diff scan folds validation and attack-path closure into its own
    // workflow rather than a nested-record ledger. Once the canonical JSON
    // exists, those phases are done by construction.
    if (state.diffScan) {
      for (const phase of ["validation", "attack_path"] as const) {
        if (!state.completed.includes(phase)) state.completed.push(phase);
      }
    }
  }
  if (state.sealed) state.completed.push("sealed");

  // A sealed scan is finished by definition — never advertise a next phase for
  // it, even if an intermediate artifact looks incomplete.
  state.nextPhase = state.sealed
    ? null
    : (PHASE_ORDER.find((phase) => !state.completed.includes(phase)) ?? null);
  return state;
}

/** Render the state as the resume briefing handed to the agent. */
export function describeScanState(state: ScanState): string {
  const lines: string[] = [];
  lines.push("A previous run of this scan stopped early. Work already on disk:");
  lines.push("");
  lines.push(
    state.completed.includes("threat_model")
      ? `- Threat model: DONE (${state.threatModelPath}). Reuse it as-is; do not regenerate.`
      : "- Threat model: NOT DONE.",
  );
  lines.push(
    state.inScopeFileCount !== undefined
      ? `- In-scope file list: DONE (${state.inScopeFileCount} files). Reuse it; do not rebuild.`
      : "- In-scope file list: NOT DONE.",
  );
  if (state.ledgerRows !== undefined && state.ledgerRows > 0) {
    lines.push(
      `- Candidate ledger: ${state.ledgerRows} rows, ` +
        `${state.ledgerValidated ?? 0} with a validation record, ` +
        `${state.ledgerAttackPath ?? 0} with an attack_path record.`,
    );
    if ((state.ledgerValidated ?? 0) < state.ledgerRows) {
      lines.push(
        "  Add validation records only to rows that lack one. Preserve every existing row and field.",
      );
    }
    if ((state.ledgerAttackPath ?? 0) < (state.attackPathEligible ?? state.ledgerRows)) {
      lines.push(
        `  ${state.attackPathEligible ?? state.ledgerRows} rows are reportable/deferred and need an attack_path record.`,
        "  Add attack_path records only to those rows; leave suppressed/not_applicable rows alone.",
      );
    }
  } else {
    lines.push("- Candidate ledger: NOT STARTED.");
  }
  lines.push(
    state.completed.includes("canonical_json")
      ? "- Canonical JSON: WRITTEN (scan-manifest.json, findings.json, coverage.json)."
      : "- Canonical JSON: NOT WRITTEN.",
  );
  lines.push(state.sealed ? "- Finalization: DONE." : "- Finalization: NOT DONE.");
  lines.push("");
  lines.push(
    `Resume at the '${state.nextPhase ?? "nothing — already sealed"}' phase. ` +
      "Do not redo completed phases: re-running them wastes budget and can overwrite good work.",
  );
  return lines.join("\n");
}
