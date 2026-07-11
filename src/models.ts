/**
 * Model ids + per-role fallback chains.
 *
 * Priority: brain + latency (not $).
 * Fast-mode family (this account): Sol / Terra / Luna only.
 * Classifier rule: best brain first → lower classifier → always end on Grok.
 */

export type ModelId = string;

export const MODELS = {
  sol: "gpt-5.6-sol-max-fast",
  terra: "gpt-5.6-terra-max-fast",
  luna: "gpt-5.6-luna-max-fast",
  gpt55: "gpt-5.5-extra-high",
  opus: "claude-opus-4-8-thinking-max",
  grok: "grok-4.5-xhigh",
} as const;

/** Sol-led coding/verify chain. */
export const SOL_LED_CHAIN = [
  MODELS.sol,
  MODELS.terra,
  MODELS.gpt55,
  MODELS.grok,
] as const;

/** Opus master/reviewer with Anthropic-classifier hedge through fast lane. */
export const OPUS_LED_CHAIN = [
  MODELS.opus,
  MODELS.sol,
  MODELS.terra,
  MODELS.gpt55,
  MODELS.grok,
] as const;

/** Scout / micro-unblock: Luna then no-classifier terminal. */
export const LUNA_LED_CHAIN = [MODELS.luna, MODELS.grok] as const;

export type RoleId =
  | "master"
  | "implementer"
  | "tester"
  | "executor"
  | "debugger"
  | "reviewer"
  | "scout"
  | "micro-unblock"
  | "watchdog";

export const ROLE_MODEL_CHAINS: Record<RoleId, readonly ModelId[]> = {
  master: OPUS_LED_CHAIN,
  reviewer: OPUS_LED_CHAIN,
  implementer: SOL_LED_CHAIN,
  tester: SOL_LED_CHAIN,
  executor: SOL_LED_CHAIN,
  debugger: SOL_LED_CHAIN,
  watchdog: SOL_LED_CHAIN,
  scout: LUNA_LED_CHAIN,
  "micro-unblock": LUNA_LED_CHAIN,
};

export function nextModel(
  chain: readonly ModelId[],
  current: ModelId,
): ModelId | undefined {
  const i = chain.indexOf(current);
  if (i < 0) return chain[0];
  return chain[i + 1];
}

/** Assert every configured chain ends on the no-classifier terminal. */
export function assertChainsEndOnGrok(
  chains: Record<string, readonly ModelId[]> = ROLE_MODEL_CHAINS,
): void {
  for (const [role, chain] of Object.entries(chains)) {
    const last = chain[chain.length - 1];
    if (last !== MODELS.grok) {
      throw new Error(
        `Role ${role} chain must end on ${MODELS.grok}, got ${last}`,
      );
    }
  }
}
