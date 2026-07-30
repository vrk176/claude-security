import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { canonicalize } from "./paths.js";
import type { Severity } from "./policy.js";

/** Marker used to recognise a hook this tool wrote. */
const HOOK_MARKER = "# claude-security pre-commit hook";

export interface InstallHookOptions {
  /** Block the commit at this severity or above. Defaults to "high". */
  failOnSeverity?: Severity;
  /** Cap spend per commit. Defaults to 5 USD. */
  maxCostUsd?: number;
  /** Reasoning effort for hook scans. Defaults to "medium" for latency. */
  effort?: "low" | "medium" | "high" | "xhigh" | "max";
  /** Overwrite an existing hook. */
  force?: boolean;
}

export interface HookLocation {
  hooksDir: string;
  hookPath: string;
  /** True when a hook file already exists at that path. */
  exists: boolean;
  /** True when the existing hook was written by this tool. */
  ours: boolean;
}

/**
 * Resolve where the pre-commit hook belongs.
 *
 * `git rev-parse --git-path hooks` honours `core.hooksPath`, so a repository
 * that redirects its hooks is respected without special-casing.
 */
export function hookLocation(repository: string): HookLocation {
  const repoRoot = canonicalize(repository);
  let relative: string;
  try {
    relative = execFileSync("git", ["rev-parse", "--git-path", "hooks"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    }).trim();
  } catch {
    throw new Error(`Not a Git repository: ${repoRoot}`);
  }
  const hooksDir = relative.startsWith("/") ? relative : join(repoRoot, relative);
  const hookPath = join(hooksDir, "pre-commit");
  const exists = existsSync(hookPath);
  let ours = false;
  if (exists) {
    try {
      ours = readFileSync(hookPath, "utf8").includes(HOOK_MARKER);
    } catch {
      ours = false;
    }
  }
  return { hooksDir, hookPath, exists, ours };
}

function hookScript(options: Required<Omit<InstallHookOptions, "force">>): string {
  return `#!/bin/sh
${HOOK_MARKER}
# Scans staged and unstaged changes before each commit and blocks the commit on
# findings at or above the configured severity.
#
# Exit codes from claude-security: 0 pass/report-only, 1 policy violation,
# 2 invalid input, incomplete coverage, or a runtime error. Both 1 and 2 block
# the commit — an incomplete scan has not shown the code is clean.
#
# Skip a single commit with:  CLAUDE_SECURITY_SKIP=1 git commit ...
# Remove entirely with:       claude-security install-hook --uninstall

# Deliberately no 'set -e': the scan's non-zero exit is the signal this hook
# exists to report, and 'set -e' would abort before the guidance below is shown.

if [ -n "$CLAUDE_SECURITY_SKIP" ]; then
  echo "claude-security: skipped (CLAUDE_SECURITY_SKIP set)" >&2
  exit 0
fi

# Nothing staged means nothing to review — check this first so an ordinary
# no-op commit stays silent.
if git diff --cached --quiet; then
  exit 0
fi

if ! command -v claude-security >/dev/null 2>&1; then
  echo "claude-security: not on PATH; skipping pre-commit scan" >&2
  exit 0
fi

repo_root=$(git rev-parse --show-toplevel)

# The scan bundle must live outside the repository being scanned.
results_dir=$(mktemp -d "\${TMPDIR:-/tmp}/claude-security-precommit.XXXXXX")
trap 'rm -rf "$results_dir"' EXIT

echo "claude-security: scanning staged changes..." >&2
claude-security scan "$repo_root" \\
  --working-tree \\
  --output-dir "$results_dir/results" \\
  --effort ${options.effort} \\
  --max-cost ${options.maxCostUsd} \\
  --fail-on-severity ${options.failOnSeverity}
status=$?

if [ $status -ne 0 ]; then
  echo "" >&2
  echo "claude-security: commit blocked (exit $status)." >&2
  echo "  Review the findings above, or commit anyway with:" >&2
  echo "    CLAUDE_SECURITY_SKIP=1 git commit ..." >&2
  exit $status
fi

exit 0
`;
}

/** Write the pre-commit hook. Refuses to clobber a hook it did not write. */
export function installHook(
  repository: string,
  options: InstallHookOptions = {},
): HookLocation & { action: "installed" | "replaced" } {
  const location = hookLocation(repository);
  if (!existsSync(location.hooksDir)) {
    throw new Error(`Hooks directory does not exist: ${location.hooksDir}`);
  }
  if (location.exists && !location.ours && !options.force) {
    throw new Error(
      `A pre-commit hook already exists at ${location.hookPath}.\n` +
        "It was not written by claude-security; refusing to replace it. Use --force to overwrite.",
    );
  }

  writeFileSync(
    location.hookPath,
    hookScript({
      failOnSeverity: options.failOnSeverity ?? "high",
      maxCostUsd: options.maxCostUsd ?? 5,
      effort: options.effort ?? "medium",
    }),
    "utf8",
  );
  chmodSync(location.hookPath, 0o755);
  return {
    ...hookLocation(repository),
    action: location.exists ? "replaced" : "installed",
  };
}

/** Remove the hook, but only if this tool wrote it. */
export function uninstallHook(repository: string, force = false): { removed: boolean; hookPath: string } {
  const location = hookLocation(repository);
  if (!location.exists) return { removed: false, hookPath: location.hookPath };
  if (!location.ours && !force) {
    throw new Error(
      `The pre-commit hook at ${location.hookPath} was not written by claude-security; ` +
        "refusing to remove it. Use --force to remove it anyway.",
    );
  }
  unlinkSync(location.hookPath);
  return { removed: true, hookPath: location.hookPath };
}
