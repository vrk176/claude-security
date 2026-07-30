import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";

/**
 * Resolve a path to its canonical, symlink-free form.
 *
 * The finalize script rejects a scan directory reached through a symlink, and on
 * macOS both `/tmp` and the `/var/folders/...` value returned by `tmpdir()` are
 * symlinks into `/private`. Canonicalizing here keeps default scan directories
 * usable. Only the existing prefix can be resolved, so walk up to the nearest
 * existing ancestor and re-append the rest.
 */
export function canonicalize(path: string): string {
  const absolute = resolve(path);
  let head = absolute;
  const tail: string[] = [];
  while (!existsSync(head)) {
    const parent = dirname(head);
    if (parent === head) return absolute;
    tail.unshift(basename(head));
    head = parent;
  }
  try {
    return join(realpathSync(head), ...tail);
  } catch {
    return absolute;
  }
}

export interface ResolvedTarget {
  /** Absolute path to the repository (or directory) being scanned. */
  repoRoot: string;
  /** Short human name, used in scan-dir naming. */
  repoName: string;
  /** Stable-ish scan target identity: git HEAD short-sha when available, else a dir digest. */
  targetId: string;
  /** True when repoRoot is inside a git work tree. */
  git: boolean;
}

/** Resolve a scan target from a filesystem path. */
export function resolveTarget(rawPath: string): ResolvedTarget {
  const repoRoot = canonicalize(rawPath);
  if (!existsSync(repoRoot)) {
    throw new Error(`Scan target does not exist: ${repoRoot}`);
  }
  const repoName = basename(repoRoot) || "repo";

  let git = false;
  let revision: string | undefined;
  try {
    const out = execFileSync("git", ["rev-parse", "--short", "HEAD"], {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "ignore"],
    })
      .toString()
      .trim();
    if (out) {
      git = true;
      revision = out;
    }
  } catch {
    // not a git repo, or git unavailable — fall through to a directory digest
  }

  const targetId =
    revision ??
    createHash("sha256").update(repoRoot).digest("hex").slice(0, 12);

  return { repoRoot, repoName, targetId, git };
}

/** Compute the default scan directory (outside the repo, under the system temp dir). */
export function defaultScanDir(target: ResolvedTarget): string {
  const stamp = new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .replace("T", "_")
    .replace("Z", "");
  const scanId = `${target.targetId}_${stamp}`;
  return canonicalize(
    join(tmpdir(), "claude-security-scans", target.repoName, scanId),
  );
}
