import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { canonicalize } from "./paths.js";

/** Severity levels, most severe first. */
export const SEVERITY_LEVELS = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;

export type Severity = (typeof SEVERITY_LEVELS)[number];

/** Rank: lower is more severe. */
function rank(level: string): number {
  const index = SEVERITY_LEVELS.indexOf(level as Severity);
  return index === -1 ? SEVERITY_LEVELS.length : index;
}

export interface PolicyViolation {
  title: string;
  severity: string;
  occurrenceId?: string;
  /** Which gate(s) this finding tripped. */
  gates: ("severity" | "impact")[];
  /** The finding's stated impact, or "not stated" when it declared none. */
  impact: string;
}

export interface PolicyResult {
  scanDir: string;
  /** The threshold that was applied, or null for report-only. */
  threshold: Severity | null;
  /** The impact threshold, or null when the impact gate is off. */
  impactThreshold: Severity | null;
  /** Findings that tripped either gate. */
  violations: PolicyViolation[];
  /** Every finding's severity, most severe first. */
  severityCounts: Record<string, number>;
  totalFindings: number;
  /** coverage.completeness: complete | partial | unknown. */
  completeness: string;
  /** True when coverage is anything other than "complete". */
  coverageIncomplete: boolean;
  /** Terminal verdict. */
  verdict: "pass" | "violation" | "incomplete";
  /** Exit code implied by the verdict. */
  exitCode: 0 | 1 | 2;
}

/**
 * Evaluate a sealed scan against a CI severity policy.
 *
 * Exit-code contract (matching the upstream tool so CI configs port over):
 *   0 — report-only run, or a policy that passed
 *   1 — a completed scan that violates the policy
 *   2 — incomplete coverage, or unreadable input
 *
 * Incomplete coverage outranks a passing policy: a scan that did not finish
 * cannot prove the absence of findings, so reporting it as a pass would be
 * worse than useless in CI.
 *
 * `impactThreshold` is a second, opt-in gate that asks a different question
 * than severity does. Severity already discounts impact by likelihood — the
 * scan contract maps high impact with low likelihood down to `low` — so a
 * proven root-RCE primitive with no caller in the tree passes a
 * `--fail-on-severity high` gate. That mapping is deliberate and stays
 * untouched; teams that want "no high-impact primitive merges, demonstrated
 * reachability or not" turn on the impact gate instead.
 *
 * The gate is fail-closed. `attackPath.impact.level` is neither required nor
 * shape-constrained by the findings schema, so a finding that states no
 * recognizable impact counts as a violation rather than a pass: a security gate
 * that cannot read the evidence must not certify the code as clean. Only an
 * explicit `ignore` — the contract's way of saying impact was assessed and
 * found nil — clears the gate without a stated level.
 */
export function evaluatePolicy(
  scanDirectory: string,
  threshold: Severity | null,
  impactThreshold: Severity | null = null,
): PolicyResult {
  const scanDir = canonicalize(scanDirectory);
  const findingsPath = join(scanDir, "findings.json");
  const coveragePath = join(scanDir, "coverage.json");

  if (!existsSync(findingsPath)) {
    throw new Error(`No findings.json in ${scanDir}`);
  }

  const findings = JSON.parse(readFileSync(findingsPath, "utf8")) as {
    findings?: {
      title?: string;
      occurrenceId?: string;
      severity?: { level?: string };
      attackPath?: { impact?: { level?: string } };
    }[];
  };
  const rows = findings.findings ?? [];

  let completeness = "unknown";
  if (existsSync(coveragePath)) {
    const coverage = JSON.parse(readFileSync(coveragePath, "utf8")) as {
      completeness?: string;
    };
    completeness = coverage.completeness ?? "unknown";
  }
  const coverageIncomplete = completeness !== "complete";

  const severityCounts: Record<string, number> = {};
  for (const row of rows) {
    const level = row.severity?.level ?? "unknown";
    severityCounts[level] = (severityCounts[level] ?? 0) + 1;
  }

  const violations: PolicyViolation[] = [];
  for (const row of rows) {
    const severity = row.severity?.level ?? "unknown";
    const stated = row.attackPath?.impact?.level;
    const gates: PolicyViolation["gates"] = [];

    if (threshold !== null && rank(severity) <= rank(threshold)) {
      gates.push("severity");
    }
    if (impactThreshold !== null && stated !== "ignore") {
      // An unrecognised or absent level ranks past the end of the scale, which
      // is exactly the fail-closed case: unreadable evidence is a violation.
      const unreadable = stated === undefined || rank(stated) === SEVERITY_LEVELS.length;
      if (unreadable || rank(stated) <= rank(impactThreshold)) {
        gates.push("impact");
      }
    }

    if (gates.length > 0) {
      violations.push({
        title: row.title ?? "(untitled)",
        severity,
        occurrenceId: row.occurrenceId,
        gates,
        impact: stated ?? "not stated",
      });
    }
  }
  violations.sort((a, b) => rank(a.severity) - rank(b.severity));

  let verdict: PolicyResult["verdict"];
  let exitCode: PolicyResult["exitCode"];
  if (coverageIncomplete) {
    // Report the violations we did find, but the run cannot be called a pass.
    verdict = "incomplete";
    exitCode = 2;
  } else if (violations.length > 0) {
    verdict = "violation";
    exitCode = 1;
  } else {
    verdict = "pass";
    exitCode = 0;
  }

  return {
    scanDir,
    threshold,
    impactThreshold,
    violations,
    severityCounts,
    totalFindings: rows.length,
    completeness,
    coverageIncomplete,
    verdict,
    exitCode,
  };
}

/** Human-readable one-screen summary. */
export function describePolicy(result: PolicyResult): string {
  const mix =
    SEVERITY_LEVELS.filter((level) => result.severityCounts[level])
      .map((level) => `${level}: ${result.severityCounts[level]}`)
      .join(", ") || "none";

  const lines = [
    `Findings: ${result.totalFindings} (${mix})`,
    `Coverage: ${result.completeness}`,
  ];

  if (result.threshold === null && result.impactThreshold === null) {
    lines.push("Policy:   report-only (no --fail-on-severity or --fail-on-impact)");
  } else {
    const gates = [
      result.threshold ? `severity ${result.threshold} or above` : null,
      result.impactThreshold ? `impact ${result.impactThreshold} or above` : null,
    ].filter(Boolean);
    lines.push(
      `Policy:   fail at ${gates.join(", or ")} — ${result.violations.length} violation(s)`,
    );
    for (const violation of result.violations) {
      // Name the gate when the impact one is active: "why did a low block CI?"
      // is otherwise unanswerable from the output alone.
      const why =
        result.impactThreshold === null
          ? ""
          : ` (${violation.gates.join("+")}; impact ${violation.impact})`;
      lines.push(`  [${violation.severity}] ${violation.title}${why}`);
    }
  }

  if (result.verdict === "incomplete") {
    lines.push(
      "",
      "Coverage is not complete, so this run cannot be reported as passing.",
    );
  }
  return lines.join("\n");
}
