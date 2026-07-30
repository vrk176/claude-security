import { execFileSync } from "node:child_process";
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join, relative, resolve } from "node:path";

import { canonicalize } from "./paths.js";
import { runScan, type ScanOptions } from "./runtime.js";
import { scanCostFromUsage, type ScanCost } from "./cost.js";

export interface BulkTask {
  id: string;
  repository: string;
  revision: string;
  scope?: string;
  mode?: "standard" | "deep";
}

export interface BulkReceipt extends BulkTask {
  status: "completed" | "failed";
  attempt: number;
  outputDir: string;
  cost?: ScanCost;
  findings?: number;
  error?: string;
}

export interface BulkOptions {
  inputPath: string;
  outputDir: string;
  workers?: number;
  maxAttempts?: number;
  maxCostUsd?: number;
  model?: string;
  effort?: ScanOptions["effort"];
  pythonPath?: string;
  signal?: AbortSignal;
  onProgress?: (event: {
    id: string;
    status: "started" | "completed" | "failed" | "skipped";
    attempt: number;
    error?: string;
  }) => void;
}

export interface BulkResult {
  total: number;
  completed: number;
  failed: number;
  skipped: number;
  resultsPath: string;
}

/**
 * Parse the task CSV.
 *
 * Required columns: id, repository, revision. Optional: scope, mode.
 * Revisions must be full 40-character SHAs — a branch name would let the
 * remote decide what gets scanned, which defeats the point of a pinned audit.
 */
export function parseTasks(csv: string): BulkTask[] {
  const lines = csv
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
  if (lines.length === 0) throw new Error("The task CSV is empty.");

  const headers = lines[0].split(",").map((h) => h.trim().toLowerCase());
  for (const required of ["id", "repository", "revision"]) {
    if (!headers.includes(required)) {
      throw new Error("The task CSV requires id, repository, and revision columns.");
    }
  }

  const seen = new Set<string>();
  const tasks: BulkTask[] = [];
  for (const line of lines.slice(1)) {
    const cells = line.split(",").map((c) => c.trim());
    const row = Object.fromEntries(headers.map((h, i) => [h, cells[i] ?? ""]));
    const id = row.id;
    if (!id || !/^[A-Za-z0-9._-]+$/.test(id)) {
      throw new Error(
        `Invalid task id '${id}': use letters, digits, dot, dash, or underscore.`,
      );
    }
    if (seen.has(id.toLowerCase())) {
      throw new Error(`Duplicate task id '${id}'.`);
    }
    seen.add(id.toLowerCase());
    if (!/^[0-9a-f]{40}$/i.test(row.revision)) {
      throw new Error(
        `Task '${id}': revision must be a full 40-character commit SHA, not '${row.revision}'.`,
      );
    }
    if (row.mode && row.mode !== "standard" && row.mode !== "deep") {
      throw new Error(`Task '${id}': mode must be standard or deep.`);
    }
    tasks.push({
      id,
      repository: row.repository,
      revision: row.revision.toLowerCase(),
      scope: row.scope || undefined,
      mode: (row.mode as BulkTask["mode"]) || undefined,
    });
  }
  return tasks;
}

/**
 * Clone one pinned revision into an isolated checkout.
 *
 * The remote is untrusted, so: repository hooks are disabled, ambient GIT_*
 * variables are stripped, terminal auth prompts are refused rather than hung
 * on, LFS blobs are skipped, and the resulting HEAD is verified against the
 * pinned SHA — a remote that serves different content than requested is an
 * error, not a silently different scan.
 */
function checkoutRevision(task: BulkTask, path: string): void {
  const environment: NodeJS.ProcessEnv = { ...process.env };
  for (const name of [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  ]) {
    delete environment[name];
  }
  environment.GIT_TERMINAL_PROMPT = "0";
  environment.GIT_LFS_SKIP_SMUDGE = "1";

  const git = (...args: string[]): string =>
    execFileSync(
      "git",
      ["-c", "core.hooksPath=/dev/null", "-C", path, ...args],
      { env: environment, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    ).trim();

  git("init", "--quiet");
  git("fetch", "--quiet", "--no-tags", "--depth=1", "--", task.repository, task.revision);
  git("checkout", "--quiet", "--detach", "FETCH_HEAD");
  const head = git("rev-parse", "HEAD").toLowerCase();
  if (head !== task.revision) {
    throw new Error(
      `Checkout HEAD ${head} does not match the pinned revision ${task.revision}.`,
    );
  }
}

/** Read prior receipts so a rerun resumes instead of redoing finished work. */
function readReceipts(ledgerPath: string): Map<string, BulkReceipt> {
  const receipts = new Map<string, BulkReceipt>();
  if (!existsSync(ledgerPath)) return receipts;
  for (const line of readFileSync(ledgerPath, "utf8").split("\n")) {
    if (!line.trim()) continue;
    try {
      const receipt = JSON.parse(line) as BulkReceipt;
      receipts.set(receipt.id.toLowerCase(), receipt);
    } catch {
      // A truncated final line from an interrupted run is not fatal.
    }
  }
  return receipts;
}

/**
 * Scan many pinned repositories, resuming where a previous run left off.
 *
 * Each task gets its own scan bundle under `<output>/artifacts/<id>/attempt-N`,
 * and every outcome is appended to `<output>/results.jsonl`. Rerunning the same
 * command skips tasks that already completed with artifacts on disk.
 */
export async function runBulkScan(options: BulkOptions): Promise<BulkResult> {
  const output = canonicalize(options.outputDir);
  const workers = options.workers ?? 2;
  const maxAttempts = options.maxAttempts ?? 1;
  if (!Number.isSafeInteger(workers) || workers < 1) {
    throw new Error("workers must be a positive integer.");
  }
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1) {
    throw new Error("maxAttempts must be a positive integer.");
  }

  const tasks = parseTasks(readFileSync(canonicalize(options.inputPath), "utf8"));
  mkdirSync(join(output, "checkouts"), { recursive: true });
  mkdirSync(join(output, "artifacts"), { recursive: true });
  const ledger = join(output, "results.jsonl");

  const receipts = readReceipts(ledger);
  const pending: BulkTask[] = [];
  let skipped = 0;
  for (const task of tasks) {
    const prior = receipts.get(task.id.toLowerCase());
    const done =
      prior?.status === "completed" &&
      existsSync(join(prior.outputDir, "report.md"));
    if (done) {
      skipped += 1;
      options.onProgress?.({ id: task.id, status: "skipped", attempt: prior.attempt });
    } else {
      pending.push(task);
    }
  }

  let completed = 0;
  let failed = 0;
  let next = 0;

  const runOne = async (task: BulkTask): Promise<void> => {
    const checkout = join(output, "checkouts", task.id);
    let attempt = receipts.get(task.id.toLowerCase())?.attempt ?? 0;
    let lastError: string | undefined;

    while (attempt < maxAttempts) {
      options.signal?.throwIfAborted();
      attempt += 1;
      const scanDir = join(output, "artifacts", task.id, `attempt-${attempt}`);
      options.onProgress?.({ id: task.id, status: "started", attempt });

      let status: BulkReceipt["status"] = "failed";
      let cost: ScanCost | undefined;
      let findings: number | undefined;
      try {
        rmSync(checkout, { recursive: true, force: true });
        mkdirSync(checkout, { recursive: true, mode: 0o700 });
        checkoutRevision(task, checkout);

        if (task.scope) {
          // A scope that escapes the checkout would scan something the task
          // never named.
          const scoped = resolve(checkout, task.scope);
          const outside = relative(canonicalize(checkout), scoped);
          if (outside.startsWith("..") || resolve(outside) === outside) {
            throw new Error(`Task '${task.id}': scope escapes the checkout.`);
          }
        }

        const result = await runScan(checkout, {
          paths: task.scope ? [task.scope] : [],
          outputDir: scanDir,
          deep: task.mode === "deep",
          model: options.model,
          effort: options.effort,
          maxCostUsd: options.maxCostUsd,
          pythonPath: options.pythonPath,
          signal: options.signal,
          // Each checkout is a throwaway path, so a history row per attempt
          // would accumulate noise pointing at directories that no longer exist.
          recordHistory: false,
        });
        if (result.ok) {
          status = "completed";
          cost = result.usage ? (scanCostFromUsage(result.usage) ?? undefined) : undefined;
          try {
            findings = (
              JSON.parse(readFileSync(result.findingsPath, "utf8")) as {
                findings?: unknown[];
              }
            ).findings?.length;
          } catch {
            // A sealed scan always has findings.json; a read failure is not
            // worth failing an otherwise good scan over.
          }
        } else {
          // Prefer the runtime's own reason; a bare "no sealed report" tells a
          // bulk-run operator nothing about which of 200 tasks needs attention.
          lastError =
            result.warnings.length > 0
              ? result.warnings.join("; ")
              : "scan finished without a sealed report";
        }
      } catch (err) {
        lastError = (err as Error).message;
      } finally {
        // The checkout is untrusted source; do not leave it lying around.
        rmSync(checkout, { recursive: true, force: true });
      }

      const receipt: BulkReceipt = {
        ...task,
        status,
        attempt,
        outputDir: scanDir,
        ...(cost ? { cost } : {}),
        ...(findings !== undefined ? { findings } : {}),
        ...(status === "failed" && lastError ? { error: lastError } : {}),
      };
      appendFileSync(ledger, JSON.stringify(receipt) + "\n", "utf8");

      if (status === "completed") {
        completed += 1;
        options.onProgress?.({ id: task.id, status: "completed", attempt });
        return;
      }
      options.onProgress?.({ id: task.id, status: "failed", attempt, error: lastError });
    }
    failed += 1;
  };

  const worker = async (): Promise<void> => {
    while (next < pending.length) {
      const task = pending[next++];
      await runOne(task);
    }
  };

  await Promise.all(Array.from({ length: Math.min(workers, pending.length) }, worker));

  return {
    total: tasks.length,
    completed,
    failed,
    skipped,
    resultsPath: ledger,
  };
}

/** Summarise a finished bulk run from its ledger. */
export function summariseBulk(ledgerPath: string): string {
  const receipts = [...readReceipts(canonicalize(ledgerPath)).values()];
  if (receipts.length === 0) return "No bulk-scan receipts.";
  const totalCost = receipts.reduce((sum, r) => sum + (r.cost?.estimatedUsd ?? 0), 0);
  const lines = [
    `${receipts.length} task(s), $${totalCost.toFixed(4)} total`,
    "",
  ];
  for (const r of receipts.sort((a, b) => a.id.localeCompare(b.id))) {
    const cost = r.cost ? `$${r.cost.estimatedUsd.toFixed(2)}` : "";
    const detail =
      r.status === "completed"
        ? `${r.findings ?? "?"} findings`
        : (r.error ?? "failed").slice(0, 60);
    lines.push(
      `  ${r.id.padEnd(20)} ${r.status.padEnd(10)} ${cost.padEnd(9)} ${detail}`,
    );
  }
  return lines.join("\n");
}
