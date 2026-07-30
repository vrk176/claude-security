import { execFileSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/** Where a stored API key lives. Honours CLAUDE_SECURITY_STATE_DIR. */
export function stateDirectory(): string {
  const override = process.env.CLAUDE_SECURITY_STATE_DIR;
  if (override) return override;
  const home = process.env.CLAUDE_HOME ?? join(homedir(), ".claude");
  return join(home, "state", "plugins", "claude-security");
}

function keyPath(): string {
  return join(stateDirectory(), "credentials.json");
}

export type CredentialSource =
  | "env:ANTHROPIC_API_KEY"
  | "env:ANTHROPIC_AUTH_TOKEN"
  | "stored-api-key"
  | "claude-code-login"
  | "none";

export interface CredentialStatus {
  /** The source the SDK will actually authenticate with. */
  effective: CredentialSource;
  /** Every source detected, in precedence order. */
  available: CredentialSource[];
  /** Last four characters of the effective key, when it is one we can see. */
  hint?: string;
  storedKeyPath: string;
}

function readStoredKey(): string | undefined {
  const path = keyPath();
  if (!existsSync(path)) return undefined;
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { apiKey?: string };
    const key = parsed.apiKey?.trim();
    return key ? key : undefined;
  } catch {
    return undefined;
  }
}

/** True when Claude Code has a login this machine's SDK can reuse. */
function hasClaudeCodeLogin(): boolean {
  if (process.platform === "darwin") {
    try {
      execFileSync("security", ["find-generic-password", "-s", "Claude Code-credentials", "-w"], {
        stdio: ["ignore", "ignore", "ignore"],
      });
      return true;
    } catch {
      // fall through to the file-based check
    }
  }
  const home = process.env.CLAUDE_HOME ?? join(homedir(), ".claude");
  return existsSync(join(home, ".credentials.json"));
}

/**
 * Resolve which credential the SDK will use.
 *
 * Precedence matches the Agent SDK's own resolution order, and an environment
 * key deliberately outranks a stored one: a key exported in the current shell is
 * the more explicit, more local intent. Surfacing this order matters — a user
 * who runs `logout` while `ANTHROPIC_API_KEY` is exported is still
 * authenticated, and silently implying otherwise would be misleading.
 */
export function credentialStatus(): CredentialStatus {
  const available: CredentialSource[] = [];
  if (process.env.ANTHROPIC_API_KEY) available.push("env:ANTHROPIC_API_KEY");
  if (process.env.ANTHROPIC_AUTH_TOKEN) available.push("env:ANTHROPIC_AUTH_TOKEN");
  const stored = readStoredKey();
  if (stored) available.push("stored-api-key");
  if (hasClaudeCodeLogin()) available.push("claude-code-login");

  const effective = available[0] ?? "none";
  let hint: string | undefined;
  const visible =
    effective === "env:ANTHROPIC_API_KEY"
      ? process.env.ANTHROPIC_API_KEY
      : effective === "env:ANTHROPIC_AUTH_TOKEN"
        ? process.env.ANTHROPIC_AUTH_TOKEN
        : effective === "stored-api-key"
          ? stored
          : undefined;
  if (visible && visible.length >= 4) hint = visible.slice(-4);

  return { effective, available, hint, storedKeyPath: keyPath() };
}

/**
 * Store an API key for later scans.
 *
 * The key is read from stdin by the caller, never from argv: a command-line
 * argument is visible in shell history and to any process that can read the
 * process table. Stored 0600 in a 0700 directory.
 */
export function storeApiKey(apiKey: string): { path: string } {
  const key = apiKey.trim();
  if (!key) {
    throw new Error("No API key was provided on stdin.");
  }
  if (/\s/.test(key)) {
    throw new Error("An API key cannot contain whitespace.");
  }
  if (!key.startsWith("sk-")) {
    throw new Error(
      "That does not look like an Anthropic API key (expected it to start with 'sk-').",
    );
  }
  const dir = stateDirectory();
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    // A pre-existing directory we cannot chmod is not fatal; the file mode below
    // is the protection that matters.
  }
  const path = keyPath();
  writeFileSync(path, JSON.stringify({ apiKey: key }, null, 2) + "\n", {
    mode: 0o600,
  });
  chmodSync(path, 0o600);
  return { path };
}

/** Remove the stored API key. Reports what still authenticates afterwards. */
export function clearStoredKey(): { removed: boolean; remaining: CredentialSource[] } {
  const path = keyPath();
  const removed = existsSync(path);
  if (removed) rmSync(path, { force: true });
  const after = credentialStatus();
  return {
    removed,
    remaining: after.available,
  };
}

/**
 * Environment additions needed for the SDK to use a stored key.
 *
 * Returns nothing when the key would come from the environment or from a Claude
 * Code login, since the SDK finds those itself.
 */
export function credentialEnv(): Record<string, string> | undefined {
  const status = credentialStatus();
  if (status.effective !== "stored-api-key") return undefined;
  const key = readStoredKey();
  return key ? { ANTHROPIC_API_KEY: key } : undefined;
}

export function describeCredentialSource(source: CredentialSource): string {
  switch (source) {
    case "env:ANTHROPIC_API_KEY":
      return "ANTHROPIC_API_KEY from the environment";
    case "env:ANTHROPIC_AUTH_TOKEN":
      return "ANTHROPIC_AUTH_TOKEN from the environment";
    case "stored-api-key":
      return "an API key stored by `claude-security login --with-api-key`";
    case "claude-code-login":
      return "an existing Claude Code login";
    case "none":
      return "nothing — no credential found";
  }
}

/** Human-readable status, never printing a secret. */
export function describeCredentialStatus(status: CredentialStatus): string {
  const lines: string[] = [];
  if (status.effective === "none") {
    lines.push("Not authenticated.");
    lines.push("");
    lines.push("Set up one of:");
    lines.push("  export ANTHROPIC_API_KEY=sk-...");
    lines.push("  printenv ANTHROPIC_API_KEY | claude-security login --with-api-key");
    lines.push("  sign in with Claude Code, or `ant auth login`");
    return lines.join("\n");
  }

  lines.push(
    `Scans will use ${describeCredentialSource(status.effective)}` +
      (status.hint ? ` (…${status.hint})` : "") +
      ".",
  );

  if (status.available.length > 1) {
    lines.push("");
    lines.push("Other credentials are also present but will not be used:");
    for (const source of status.available.slice(1)) {
      lines.push(`  - ${describeCredentialSource(source)}`);
    }
    if (
      status.effective.startsWith("env:") &&
      status.available.includes("stored-api-key")
    ) {
      lines.push("");
      lines.push(
        "An environment key outranks the stored one. Unset it to use the stored key.",
      );
    }
  }
  return lines.join("\n");
}
