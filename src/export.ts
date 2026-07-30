import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";

import { canonicalize } from "./paths.js";
import { pluginDirectory, resolvePython } from "./runtime.js";

export type ExportFormat = "csv" | "json" | "sarif";

export const EXPORT_FORMATS: ExportFormat[] = ["csv", "json", "sarif"];

/** Default in-bundle location the finalizer uses for each format. */
export const DEFAULT_EXPORT_PATHS: Record<ExportFormat, string> = {
  csv: "exports/findings.csv",
  json: "exports/findings.json",
  sarif: "exports/results.sarif",
};

export interface ExportOptions {
  format: ExportFormat;
  /** Destination path, or "-" for stdout. Defaults to the in-bundle path. */
  output?: string;
  /** Repository root; lets SARIF add source-line fingerprints. */
  sourceRoot?: string;
  pythonPath?: string;
}

export interface ExportResult {
  format: ExportFormat;
  /** Absolute path written, or null when the export went to stdout. */
  outputPath: string | null;
  bytes: number;
}

/**
 * Export findings from a sealed scan bundle.
 *
 * This runs entirely offline: no agent, no credentials, no network. The Python
 * finalizer validates the seal before producing anything, so a tampered or
 * unsealed bundle fails here rather than yielding a plausible-looking export.
 */
export function exportFindings(
  scanDirectory: string,
  options: ExportOptions,
): ExportResult {
  const scanDir = canonicalize(scanDirectory);
  if (!existsSync(scanDir)) {
    throw new Error(`Scan directory does not exist: ${scanDir}`);
  }
  if (!existsSync(join(scanDir, "scan-manifest.json"))) {
    throw new Error(
      `Not a scan bundle (no scan-manifest.json): ${scanDir}`,
    );
  }
  if (!EXPORT_FORMATS.includes(options.format)) {
    throw new Error(
      `Unsupported export format '${options.format}'. Use one of: ${EXPORT_FORMATS.join(", ")}`,
    );
  }

  const python = resolvePython(options.pythonPath);
  const script = join(pluginDirectory(), "scripts", "finalize_scan_contract.py");
  const toStdout = options.output === "-";

  const argv = [script, "--scan-dir", scanDir, "--export-format", options.format];
  if (options.sourceRoot) {
    argv.push("--source-root", canonicalize(options.sourceRoot));
  }
  if (!toStdout) {
    const output = options.output
      ? canonicalize(options.output)
      : join(scanDir, DEFAULT_EXPORT_PATHS[options.format]);
    argv.push("--export-output", output);
  }

  const run = spawnSync(python, argv, {
    encoding: "buffer",
    maxBuffer: 512 * 1024 * 1024,
  });

  if (run.error) {
    throw new Error(`Failed to run ${python}: ${run.error.message}`);
  }
  if (run.status !== 0) {
    const stderr = run.stderr?.toString().trim();
    // argparse prints its usage block ahead of the real message; keep the last line.
    const detail = stderr?.split("\n").filter(Boolean).pop() ?? "unknown error";
    throw new Error(`Export failed: ${detail}`);
  }

  if (toStdout) {
    process.stdout.write(run.stdout);
    return { format: options.format, outputPath: null, bytes: run.stdout.length };
  }

  const written = options.output
    ? canonicalize(options.output)
    : join(scanDir, DEFAULT_EXPORT_PATHS[options.format]);
  return {
    format: options.format,
    outputPath: written,
    bytes: existsSync(written) ? Buffer.byteLength(run.stdout) : 0,
  };
}
