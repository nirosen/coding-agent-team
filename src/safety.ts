import type { RunResult } from "@cursor/sdk";

const SAFETY_PATTERNS: RegExp[] = [
  /safety[_\s-]?classifier/i,
  /cybersecurity[_\s-]?(classifier|policy|block)/i,
  /\bblocked by (an? )?(openai|anthropic|model|safety|content)/i,
  /\bcontent[_\s-]?policy\b/i,
  /\brefus(ed|al)\b.*\b(security|exploit|attack|malware)\b/i,
  /\bi (can'?t|cannot|won'?t) (help|assist).*(exploit|malware|attack|hack)/i,
  /\bmodel.*(unavailable|not available|blocked)\b/i,
  /\bpolicy violation\b/i,
];

export function textLooksLikeSafetyBlock(text: string): boolean {
  if (!text) return false;
  return SAFETY_PATTERNS.some((re) => re.test(text));
}

export function resultLooksLikeSafetyBlock(
  result: RunResult,
  streamedText = "",
): boolean {
  if (textLooksLikeSafetyBlock(streamedText)) return true;
  return textLooksLikeSafetyBlock(JSON.stringify(result));
}

export function errorLooksLikeSafetyBlock(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return textLooksLikeSafetyBlock(msg);
}
