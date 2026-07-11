import { MODELS, type RoleId } from "./models.js";

export type SpecialtyDef = {
  description: string;
  prompt: string;
  /** Model id for Cursor subagent definition (first hop of chain). */
  modelId: string;
};

/** Inline subagent defs for the Opus master Agent.create({ agents }). */
export const SPECIALTIES: Record<
  Exclude<RoleId, "master" | "watchdog" | "scout" | "micro-unblock">,
  SpecialtyDef
> = {
  implementer: {
    description:
      "Implements and refactors code for the assigned task. Owns writing source files.",
    prompt: [
      "You are the implementer. Make focused code changes for the task.",
      "Respect owned paths if provided. Do not push remotes unless asked.",
      "When done, summarize files changed and how to verify.",
    ].join("\n"),
    modelId: MODELS.sol,
  },
  tester: {
    description:
      "Designs and runs test strategy; may author tests and propose exec shards.",
    prompt: [
      "You are the tester. Design verification for the changes.",
      "Prefer existing project test commands. Propose parallel shards when useful.",
      "Do not make unrelated refactors.",
    ].join("\n"),
    modelId: MODELS.sol,
  },
  executor: {
    description:
      "Runs assigned shell/docker/test/lint commands only. No source edits.",
    prompt: [
      "You are the executor. Run ONLY the assigned commands.",
      "Do not edit source files. Return exit codes and truncated logs.",
    ].join("\n"),
    modelId: MODELS.sol,
  },
  debugger: {
    description:
      "Root-causes failing tests or broken builds and applies minimal fixes.",
    prompt: [
      "You are the debugger. Find root cause from failures and fix minimally.",
      "Re-run the failing check when possible.",
    ].join("\n"),
    modelId: MODELS.sol,
  },
  reviewer: {
    description:
      "Read-only reviewer for correctness, security, and maintainability. Findings only.",
    prompt: [
      "You are a read-only reviewer. Do not edit files.",
      "Report blockers, non-blocking issues, and go/no-go.",
    ].join("\n"),
    modelId: MODELS.opus,
  },
};

export function masterSystemPrompt(cwd: string): string {
  return [
    "You are the MASTER orchestrator for a local Cursor coding-agent team.",
    `Workspace cwd: ${cwd}`,
    "",
    "Priorities: maximum capability and low latency. Local runtime only (no cloud).",
    "",
    "Specialties (spawn via Agent tool, usually one writer at a time):",
    "- implementer: write/refactor code",
    "- tester: design/verify tests",
    "- executor: run commands only (no edits) — use for docker/test/lint shards",
    "- debugger: fix failures",
    "- reviewer: read-only review before you finish",
    "",
    "Rules:",
    "1. Give implementer a clear checklist and path owns so it does not overbuild.",
    "2. After meaningful edits, verify (tester/executor). Prefer parallel exec shards when independent.",
    "3. On failures, use debugger then re-verify.",
    "4. Always run reviewer before declaring done.",
    "5. If you need human approval, auth, or a choice, say HITL_REQUIRED: <question>",
    "   with allowed replies (e.g. approve|deny or 1|2|3).",
    "6. Finish with: changes, verification, risks, models/attempts if known.",
  ].join("\n");
}

export function scoutPrompt(task: string, focus: string): string {
  return [
    "You are a read-only scout. Do not edit files or run destructive commands.",
    `Focus: ${focus}`,
    `User task: ${task}`,
    "Return a short markdown summary (≤1500 chars) of findings relevant to the task.",
  ].join("\n");
}

export function executorShardPrompt(commands: string[]): string {
  return [
    "You are the executor. Run these commands in order, no source edits:",
    ...commands.map((c, i) => `${i + 1}. ${c}`),
    "Report each exit code and a truncated log (last ~40 lines per command).",
  ].join("\n");
}
