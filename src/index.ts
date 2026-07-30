export { runScan, pluginDirectory } from "./runtime.js";
export type { ScanOptions, ScanResult } from "./runtime.js";
export { resolveTarget, defaultScanDir, canonicalize } from "./paths.js";
export type { ResolvedTarget } from "./paths.js";
export { inspectScanState, describeScanState } from "./state.js";
export type { ScanState, ScanPhase } from "./state.js";
export { exportFindings, EXPORT_FORMATS, DEFAULT_EXPORT_PATHS } from "./export.js";
export type { ExportFormat, ExportOptions, ExportResult } from "./export.js";
export { evaluatePolicy, describePolicy, SEVERITY_LEVELS } from "./policy.js";
export { UsageAccumulator, writeUsage, describeUsage } from "./usage.js";
export { estimateCost, scanCostFromUsage, costLimitSupported, formatUsd } from "./cost.js";
export type { ScanCost } from "./cost.js";
export { getScanRecipe } from "./history.js";
export type { ScanRecipe } from "./history.js";
export { listScans, getScan, registerScan, describeScanRow } from "./history.js";
export type { ScanRecord, ListScansOptions } from "./history.js";
export type { UsageSnapshot, TokenTotals } from "./usage.js";
export type { Severity, PolicyResult } from "./policy.js";

import { runScan, type ScanOptions, type ScanResult } from "./runtime.js";

/**
 * High-level client mirroring the codex-security `CodexSecurity` surface.
 *
 * ```ts
 * const security = new ClaudeSecurity();
 * const result = await security.run("/path/to/repo", { outputDir: "/tmp/results" });
 * console.log(result.reportPath);
 * ```
 */
export class ClaudeSecurity {
  constructor(private readonly defaults: Partial<ScanOptions> = {}) {}

  run(repository: string, options: ScanOptions = {}): Promise<ScanResult> {
    return runScan(repository, { ...this.defaults, ...options });
  }
}
