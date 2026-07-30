import { writeFileSync } from "node:fs";
import { join } from "node:path";

export interface TokenTotals {
  inputTokens: number;
  outputTokens: number;
  cacheReadInputTokens: number;
  cacheCreationInputTokens: number;
}

export interface UsageSnapshot extends TokenTotals {
  /** Assistant turns observed on the stream. */
  assistantMessages: number;
  /** Authoritative cost from the SDK result message, when one arrived. */
  totalCostUsd?: number;
  /** Authoritative turn count from the result message. */
  numTurns?: number;
  durationMs?: number;
  /** Per-model breakdown from the result message, when present. */
  modelUsage?: Record<string, unknown>;
  /** result subtype, e.g. success | error_max_budget_usd | error_max_turns. */
  resultSubtype?: string;
  /** Set when the run ended by throwing instead of returning a result. */
  endedWithError?: string;
  /**
   * True when no result message arrived, so the token totals are the streamed
   * approximation rather than the SDK's authoritative accounting.
   */
  partial: boolean;
}

/**
 * Accumulates token usage while a scan streams.
 *
 * The SDK reports authoritative totals in its `result` message — but a run that
 * hits the budget cap can end by *throwing* instead, and then nothing is
 * reported at all. Three paid runs during this port produced no usage data for
 * exactly that reason. So: tally every assistant turn as it arrives, and treat
 * the result message as an upgrade rather than the only source.
 */
export class UsageAccumulator {
  #seen = new Set<string>();
  #totals: TokenTotals = {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadInputTokens: 0,
    cacheCreationInputTokens: 0,
  };
  #assistantMessages = 0;
  #totalCostUsd?: number;
  #numTurns?: number;
  #durationMs?: number;
  #modelUsage?: Record<string, unknown>;
  #resultSubtype?: string;
  #sawResult = false;

  /** Feed one streamed SDK message. Unknown shapes are ignored. */
  record(message: unknown): void {
    const msg = message as {
      type?: string;
      subtype?: string;
      message?: { id?: string; usage?: Record<string, number> };
      total_cost_usd?: number;
      num_turns?: number;
      duration_ms?: number;
      usage?: Record<string, number>;
      modelUsage?: Record<string, unknown>;
    };

    if (msg.type === "assistant") {
      // Parallel tool calls can repeat one assistant message id; count it once.
      const id = msg.message?.id;
      if (id && this.#seen.has(id)) return;
      if (id) this.#seen.add(id);
      this.#assistantMessages += 1;
      this.#add(msg.message?.usage);
      return;
    }

    if (msg.type === "result") {
      this.#sawResult = true;
      this.#resultSubtype = msg.subtype;
      if (typeof msg.total_cost_usd === "number") this.#totalCostUsd = msg.total_cost_usd;
      if (typeof msg.num_turns === "number") this.#numTurns = msg.num_turns;
      if (typeof msg.duration_ms === "number") this.#durationMs = msg.duration_ms;
      if (msg.modelUsage) this.#modelUsage = msg.modelUsage;
      // The result's usage supersedes the streamed tally.
      if (msg.usage) {
        this.#totals = {
          inputTokens: msg.usage.input_tokens ?? this.#totals.inputTokens,
          outputTokens: msg.usage.output_tokens ?? this.#totals.outputTokens,
          cacheReadInputTokens:
            msg.usage.cache_read_input_tokens ?? this.#totals.cacheReadInputTokens,
          cacheCreationInputTokens:
            msg.usage.cache_creation_input_tokens ??
            this.#totals.cacheCreationInputTokens,
        };
      }
    }
  }

  #add(usage: Record<string, number> | undefined): void {
    if (!usage) return;
    this.#totals.inputTokens += usage.input_tokens ?? 0;
    this.#totals.outputTokens += usage.output_tokens ?? 0;
    this.#totals.cacheReadInputTokens += usage.cache_read_input_tokens ?? 0;
    this.#totals.cacheCreationInputTokens += usage.cache_creation_input_tokens ?? 0;
  }

  snapshot(endedWithError?: string): UsageSnapshot {
    return {
      ...this.#totals,
      assistantMessages: this.#assistantMessages,
      totalCostUsd: this.#totalCostUsd,
      numTurns: this.#numTurns,
      durationMs: this.#durationMs,
      modelUsage: this.#modelUsage,
      resultSubtype: this.#resultSubtype,
      endedWithError,
      partial: !this.#sawResult,
    };
  }
}

/**
 * Persist usage beside the scan bundle.
 *
 * Written on both the success and the failure path: a run you paid for should
 * leave a record of what it cost even when it produced nothing else. Never
 * throws — losing telemetry must not turn into losing the scan.
 */
export function writeUsage(scanDir: string, snapshot: UsageSnapshot): void {
  try {
    writeFileSync(
      join(scanDir, "usage.json"),
      JSON.stringify(snapshot, null, 2) + "\n",
      "utf8",
    );
  } catch {
    // best effort
  }
}

/** One-line human summary. */
export function describeUsage(snapshot: UsageSnapshot): string {
  const parts: string[] = [];
  if (snapshot.totalCostUsd !== undefined) {
    parts.push(`$${snapshot.totalCostUsd.toFixed(4)}`);
  }
  if (snapshot.numTurns !== undefined) parts.push(`${snapshot.numTurns} turns`);
  else parts.push(`${snapshot.assistantMessages} assistant turns`);
  parts.push(
    `in ${snapshot.inputTokens.toLocaleString()} / out ${snapshot.outputTokens.toLocaleString()} / cache-read ${snapshot.cacheReadInputTokens.toLocaleString()}`,
  );
  if (snapshot.partial) parts.push("(partial — no result message)");
  if (snapshot.endedWithError) parts.push(`ended: ${snapshot.endedWithError}`);
  return parts.join(", ");
}
