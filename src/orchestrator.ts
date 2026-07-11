import { MODELS, ROLE_MODEL_CHAINS } from "./models.js";
import { runJob, type JobOutcome } from "./run-job.js";
import { masterSystemPrompt, SPECIALTIES } from "./specialties.js";
import type { TeamStateStore } from "./state.js";
import type { SlackConfig } from "./slack-hitl.js";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import { askHitlAndWait, slackHitlEnabled } from "./slack-hitl.js";

async function askStdinHitl(question: string): Promise<string> {
  const rl = readline.createInterface({ input, output });
  try {
    console.log(`\n\x1b[33m⏸ HITL (terminal)\x1b[0m ${question}`);
    const answer = await rl.question("Your reply> ");
    return answer.trim();
  } finally {
    rl.close();
  }
}

export type OrchestratorOptions = {
  apiKey: string;
  cwd: string;
  task: string;
  scoutSummaries?: string[];
  execHint?: string;
  state?: TeamStateStore;
  slack?: SlackConfig;
  hitlTimeoutMs?: number;
  live?: boolean;
  verbose?: boolean;
  /** If Slack HITL off, prompt on this TTY for answers. */
  interactiveHitl?: boolean;
};

function buildMasterPrompt(opts: OrchestratorOptions): string {
  const parts = [
    masterSystemPrompt(opts.cwd),
    "",
    "## User task",
    opts.task,
  ];
  if (opts.scoutSummaries?.length) {
    parts.push("", "## Scout summaries (--fan-out)", ...opts.scoutSummaries);
  }
  if (opts.execHint) {
    parts.push("", "## Exec hint", opts.execHint);
  }
  return parts.join("\n");
}

function extractHitl(text: string): string | undefined {
  const m = text.match(/HITL_REQUIRED:\s*(.+)/i);
  return m?.[1]?.trim();
}

/**
 * Run Opus-led master with specialty subagents. On HITL_REQUIRED, park and
 * ask Slack when configured.
 */
export async function runOrchestrator(
  opts: OrchestratorOptions,
): Promise<JobOutcome> {
  const agents = Object.fromEntries(
    Object.entries(SPECIALTIES).map(([name, def]) => [
      name,
      {
        description: def.description,
        prompt: def.prompt,
        model: { id: def.modelId } as { id: string },
      },
    ]),
  );

  // Reviewer subagent should stay Opus-first in the definition; fallbacks
  // for the master itself are handled by runJob's OPUS_LED_CHAIN.
  agents.reviewer = {
    ...agents.reviewer!,
    model: { id: MODELS.opus },
  };

  const jobId = `master-${Date.now()}`;
  let prompt = buildMasterPrompt(opts);

  for (let round = 0; round < 3; round++) {
    const outcome = await runJob({
      role: "master",
      cwd: opts.cwd,
      apiKey: opts.apiKey,
      modelChain: ROLE_MODEL_CHAINS.master,
      prompt,
      agents,
      state: opts.state,
      jobId: round === 0 ? jobId : `${jobId}-r${round}`,
      live: opts.live,
      verbose: opts.verbose,
    });

    if (!outcome.ok) return outcome;

    const question = extractHitl(outcome.streamedText);
    if (!question) return outcome;

    opts.state?.markAwaitingHuman(jobId, question);
    let answer: string;
    if (opts.slack && slackHitlEnabled(opts.slack)) {
      console.log(`[master] awaiting Slack HITL: ${question}`);
      ({ answer } = await askHitlAndWait(opts.slack, {
        jobId,
        question,
        timeoutMs: opts.hitlTimeoutMs,
      }));
    } else if (opts.interactiveHitl !== false && process.stdin.isTTY) {
      answer = await askStdinHitl(question);
      if (!answer) {
        console.warn("[master] empty HITL reply; stopping");
        return outcome;
      }
    } else {
      console.warn(
        `[master] HITL_REQUIRED but no Slack/TTY: ${question}`,
      );
      return outcome;
    }
    opts.state?.resolveHuman(jobId, answer);
    prompt = [
      buildMasterPrompt(opts),
      "",
      "## Human reply (Slack HITL)",
      `Question: ${question}`,
      `Answer: ${answer}`,
      "",
      "Continue the task with this decision. Spawn specialties as needed.",
    ].join("\n");
  }

  return {
    ok: false,
    role: "master",
    attempts: [...ROLE_MODEL_CHAINS.master],
    lastError: "HITL rounds exhausted",
    streamedText: "",
  };
}
