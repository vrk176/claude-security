import type { UsageSnapshot } from "./usage.js";

/**
 * Per-token prices in nanodollars, mirroring the upstream cost module's shape:
 * [input, cachedInput, cacheWriteInput, output].
 *
 * Integer nanodollars keep the arithmetic exact — floating-point dollars
 * accumulate error across millions of tokens, and the workbench rejects a
 * non-finite estimate.
 *
 * Cache reads bill at ~10% of base input; 5-minute cache writes at ~1.25x.
 */
const MODEL_PRICING_NANODOLLARS: Record<
  string,
  [input: number, cachedInput: number, cacheWriteInput: number, output: number]
> = {
  // $5 / $25 per MTok
  "claude-opus-5": [5000, 500, 6250, 25000],
  "claude-opus-4-8": [5000, 500, 6250, 25000],
  "claude-opus-4-7": [5000, 500, 6250, 25000],
  "claude-opus-4-6": [5000, 500, 6250, 25000],
  // $10 / $50 per MTok
  "claude-fable-5": [10000, 1000, 12500, 50000],
  "claude-mythos-5": [10000, 1000, 12500, 50000],
  // $3 / $15 per MTok
  "claude-sonnet-5": [3000, 300, 3750, 15000],
  "claude-sonnet-4-6": [3000, 300, 3750, 15000],
  // $1 / $5 per MTok
  "claude-haiku-4-5": [1000, 100, 1250, 5000],
  "claude-haiku-4-5-20251001": [1000, 100, 1250, 5000],
};

export interface ScanCost {
  model: string;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  outputTokens: number;
  estimatedUsd: number;
}

/**
 * Estimate cost for one model's token usage.
 *
 * Returns null for an unpriced model rather than guessing — a fabricated
 * estimate recorded in scan history is worse than no estimate.
 */
export function estimateCost(
  model: string,
  tokens: {
    inputTokens: number;
    cachedInputTokens: number;
    cacheWriteInputTokens: number;
    outputTokens: number;
  },
): ScanCost | null {
  const pricing = MODEL_PRICING_NANODOLLARS[model];
  if (pricing === undefined) return null;
  const [inputRate, cachedRate, cacheWriteRate, outputRate] = pricing;

  // The workbench requires cached + cacheWrite <= input, so bill the
  // uncached remainder at the full rate and never let it go negative.
  const uncached = Math.max(
    0,
    tokens.inputTokens - tokens.cachedInputTokens - tokens.cacheWriteInputTokens,
  );
  const nanodollars =
    uncached * inputRate +
    tokens.cachedInputTokens * cachedRate +
    tokens.cacheWriteInputTokens * cacheWriteRate +
    tokens.outputTokens * outputRate;
  if (!Number.isSafeInteger(nanodollars)) return null;

  return {
    model,
    inputTokens: tokens.inputTokens,
    cachedInputTokens: tokens.cachedInputTokens,
    cacheWriteInputTokens: tokens.cacheWriteInputTokens,
    outputTokens: tokens.outputTokens,
    estimatedUsd: nanodollars / 1_000_000_000,
  };
}

/**
 * Build the workbench cost record for a finished scan.
 *
 * Prefers `modelUsage`, which the SDK populates per model and which **includes
 * subagent work** — the top-level totals do not, and on a delegation-heavy scan
 * they understate real volume by roughly half. `totalCostUsd` from the result
 * message is authoritative when present; the price table is the fallback.
 */
export function scanCostFromUsage(snapshot: UsageSnapshot): ScanCost | null {
  const modelUsage = snapshot.modelUsage as
    | Record<
        string,
        {
          inputTokens?: number;
          outputTokens?: number;
          cacheReadInputTokens?: number;
          cacheCreationInputTokens?: number;
          costUSD?: number;
        }
      >
    | undefined;

  if (modelUsage && Object.keys(modelUsage).length > 0) {
    // Attribute the record to the model that did the most output work.
    const [model, usage] = Object.entries(modelUsage).sort(
      (a, b) => (b[1].outputTokens ?? 0) - (a[1].outputTokens ?? 0),
    )[0];

    const cached = usage.cacheReadInputTokens ?? 0;
    const cacheWrite = usage.cacheCreationInputTokens ?? 0;
    // The SDK reports uncached input separately from cache reads, but the
    // workbench treats inputTokens as the total. Fold them together.
    const inputTokens = (usage.inputTokens ?? 0) + cached + cacheWrite;

    const estimate = estimateCost(model, {
      inputTokens,
      cachedInputTokens: cached,
      cacheWriteInputTokens: cacheWrite,
      outputTokens: usage.outputTokens ?? 0,
    });

    const authoritative = snapshot.totalCostUsd ?? usage.costUSD;
    if (estimate === null) {
      if (authoritative === undefined) return null;
      return {
        model,
        inputTokens,
        cachedInputTokens: cached,
        cacheWriteInputTokens: cacheWrite,
        outputTokens: usage.outputTokens ?? 0,
        estimatedUsd: authoritative,
      };
    }
    return authoritative === undefined
      ? estimate
      : { ...estimate, estimatedUsd: authoritative };
  }

  // No per-model breakdown: fall back to the streamed totals.
  if (snapshot.totalCostUsd === undefined) return null;
  const cached = snapshot.cacheReadInputTokens;
  const cacheWrite = snapshot.cacheCreationInputTokens;
  return {
    model: "unknown",
    inputTokens: snapshot.inputTokens + cached + cacheWrite,
    cachedInputTokens: cached,
    cacheWriteInputTokens: cacheWrite,
    outputTokens: snapshot.outputTokens,
    estimatedUsd: snapshot.totalCostUsd,
  };
}

/** True when a cost cap can be enforced meaningfully for this model. */
export function costLimitSupported(model: string): boolean {
  return MODEL_PRICING_NANODOLLARS[model] !== undefined;
}

export function formatUsd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 4,
  }).format(value);
}
