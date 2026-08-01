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
  /** True when the directory has no entries at all. */
  empty: boolean;
  /**
   * True when the directory holds at least one recognizable scan artifact.
   *
   * Distinct from `empty`: a directory can be full of unrelated files and still
   * hold nothing to resume. Conflating the two makes a fresh scan into a
   * non-empty directory report artifacts that do not exist, and advise a resume
   * that would silently skip history registration.
   */
  hasArtifacts: boolean;
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
  /** In-scope files with a completion receipt. */
  reviewedFileCount?: number;
  /** In-scope files still lacking one. Zero means discovery is genuinely done. */
  unreviewedFileCount?: number;
  /** The actual files still to review, in scope order. */
  unreviewedFiles?: string[];
  hasFindings: boolean;
  hasCoverage: boolean;
  hasManifest: boolean;
  sealed: boolean;
}

/**
 * Files handed to the agent per discovery batch.
 *
 * Chosen from what actually worked: on a real 640-file scan the model's own
 * batches ran 11-33 files with a median of 20, and those resumed cleanly. The
 * one run that treated its whole remaining set (143 files) as a single batch
 * spent its entire budget and wrote nothing, because the receipts are only
 * written when a batch closes. Twenty bounds the loss from an interrupted batch
 * to a few dollars.
 */
const DISCOVERY_BATCH_SIZE = 20;

const PHASE_ORDER: ScanPhase[] = [
  "threat_model",
  "file_list",
  "discovery",
  "validation",
  "attack_path",
  "canonical_json",
  "sealed",
];

/** Read a newline-delimited path list into a set, ignoring blanks and comments. */
function readPathSet(path: string): Set<string> {
  const set = new Set<string>();
  try {
    for (const line of readFileSync(path, "utf8").split("\n")) {
      const value = line.trim();
      if (value && !value.startsWith("#")) set.add(value);
    }
  } catch {
    // An unreadable receipt file means no coverage evidence, not full coverage.
  }
  return set;
}

/**
 * Collect one field from every JSONL row that passes `accept`.
 *
 * A truncated final line is expected after an interrupted run, so a row that
 * fails to parse is skipped rather than throwing away the rows before it.
 */
function readJsonlField(
  path: string,
  field: string,
  accept: (row: Record<string, unknown>) => boolean = () => true,
): Set<string> {
  const set = new Set<string>();
  try {
    for (const line of readFileSync(path, "utf8").split("\n")) {
      if (!line.trim()) continue;
      try {
        const row = JSON.parse(line) as Record<string, unknown>;
        const value = row[field];
        if (typeof value === "string" && value && accept(row)) set.add(value);
      } catch {
        continue;
      }
    }
  } catch {
    // Same reasoning as readPathSet: absent evidence is not evidence of coverage.
  }
  return set;
}

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
  // Standard scans record per-file completion here; see references/scan-artifacts.md.
  const reviewedFiles = join(scanDir, "artifacts", "03_coverage", "reviewed_files.txt");

  const findings = join(scanDir, "findings.json");
  const coverage = join(scanDir, "coverage.json");
  const manifest = join(scanDir, "scan-manifest.json");
  const report = join(scanDir, "report.md");

  const state: ScanState = {
    scanDir,
    empty: true,
    hasArtifacts: false,
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

  // Discovery closes on file coverage, never on candidate count.
  //
  // Counting rows fails in both directions: one candidate found in the first of
  // 640 files would close discovery and silently skip the other 639, while a
  // genuinely clean repository produces zero candidates and could never finish
  // at all. Reconcile the reviewed set against the in-scope set instead, so the
  // question is "was every file looked at", which is what coverage means.
  const expected = existsSync(inScope)
    ? readPathSet(inScope)
    : existsSync(diffWorklist)
      // The diff worklist keys its rows on `path`; work_ledger.jsonl keys its
      // completion rows on `file`. Reconciling them requires both names.
      ? readJsonlField(diffWorklist, "path")
      : null;

  // A sealed scan had its coverage validated by the finalizer, so re-deriving a
  // count here would only produce a misleading "0/1 reviewed" next to "done".
  if (!state.sealed && expected !== null && expected.size > 0) {
    const reviewed = existsSync(workLedger)
      ? readJsonlField(workLedger, "file", (row) => row.status === "complete")
      : existsSync(reviewedFiles)
        ? readPathSet(reviewedFiles)
        : new Set<string>();

    const remaining: string[] = [];
    let covered = 0;
    for (const path of expected) {
      if (reviewed.has(path)) covered += 1;
      else remaining.push(path);
    }
    state.reviewedFileCount = covered;
    state.unreviewedFileCount = remaining.length;
    state.unreviewedFiles = remaining;
    if (existsSync(workLedger)) state.workLedgerRows = countLines(workLedger);
    if (state.unreviewedFileCount === 0) state.completed.push("discovery");
  }

  if (existsSync(ledger)) {
    const parsed = readLedger(ledger);
    const rows = parsed.length;
    state.ledgerRows = rows;
    state.ledgerValidated = parsed.filter((row) => row.validation !== undefined).length;
    state.ledgerAttackPath = parsed.filter((row) => row.attack_path !== undefined).length;
    state.attackPathEligible = attackPathEligible(parsed);
    // Validation must touch every row; attack-path only the eligible ones.
    const validationDone =
      state.completed.includes("discovery") && state.ledgerValidated === rows;
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
  if (state.sealed) {
    // Sealing runs the contract finalizer, which validates coverage against the
    // manifest. A sealed scan is therefore complete by definition, and
    // re-deriving phases from artifacts would report a finished scan as partial
    // whenever it predates a change in how those artifacts are recorded.
    for (const phase of PHASE_ORDER) {
      if (!state.completed.includes(phase)) state.completed.push(phase);
    }
  }

  // A sealed scan is finished by definition — never advertise a next phase for
  // it, even if an intermediate artifact looks incomplete.
  state.nextPhase = state.sealed
    ? null
    : (PHASE_ORDER.find((phase) => !state.completed.includes(phase)) ?? null);

  state.hasArtifacts =
    state.completed.length > 0 ||
    state.hasFindings ||
    state.hasCoverage ||
    state.hasManifest ||
    state.sealed;
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
  const remaining = state.unreviewedFiles ?? [];
  if (remaining.length > 0) {
    // Hand over one concrete batch rather than a way to compute one.
    //
    // Telling the agent to diff two files leaves both "which files" and "how
    // many at once" to it, and a resume that picked the whole remaining set as
    // one batch burned its entire budget without writing a single receipt.
    // Batch boundaries are a deterministic local computation, so the runtime
    // makes them instead of asking.
    const batch = remaining.slice(0, DISCOVERY_BATCH_SIZE);
    const batches = Math.ceil(remaining.length / DISCOVERY_BATCH_SIZE);
    lines.push(
      `- File coverage: ${state.reviewedFileCount}/${state.inScopeFileCount} reviewed, ` +
        `${remaining.length} still to review, in ${batches} batch(es) of ` +
        `${DISCOVERY_BATCH_SIZE}.`,
      "",
      `  Review exactly these ${batch.length} files now — this batch, nothing else:`,
      ...batch.map((path) => `    ${path}`),
      "",
      "  Then, before starting anything further:",
      "    1. append each reviewed path to `artifacts/03_coverage/reviewed_files.txt`",
      "    2. write this batch's candidates to `artifacts/02_discovery/raw/<batch>.jsonl`",
      "    3. rebuild `candidate_ledger.jsonl` from the whole `raw/` directory",
      "",
      "  Only then take the next batch, which is the first",
      `  ${DISCOVERY_BATCH_SIZE} files still missing from reviewed_files.txt:`,
      "",
      "    comm -23 <(sort artifacts/02_discovery/in_scope_files.txt) \\",
      `             <(sort artifacts/03_coverage/reviewed_files.txt) | head -${DISCOVERY_BATCH_SIZE}`,
      "",
      "  Do not widen a batch or defer the writes to the end. A batch that is",
      "  interrupted before its receipts are written costs everything it spent, and",
      "  the next resume repeats it from scratch.",
    );
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
