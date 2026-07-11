import { ROLE_MODEL_CHAINS } from "./models.js";
import { runJob, type JobOutcome } from "./run-job.js";
import { scoutPrompt } from "./specialties.js";
import type { TeamStateStore } from "./state.js";
import type { ProcessRegistry } from "./process-registry.js";
import type { ProjectHookLease } from "./project-hook.js";

export type FanOutOptions = {
  apiKey: string;
  cwd: string;
  task: string;
  focuses: string[];
  max?: number;
  state?: TeamStateStore;
  live?: boolean;
  verbose?: boolean;
  processRegistry?: ProcessRegistry;
  projectHook?: ProjectHookLease;
};

/**
 * Read-only parallel scouts (Luna→Grok). Summaries returned for master context.
 */
export async function runFanOutScouts(
  opts: FanOutOptions,
): Promise<{ summaries: string[]; outcomes: JobOutcome[] }> {
  const max = opts.max ?? 3;
  const focuses = opts.focuses.slice(0, max);
  if (focuses.length === 0) {
    focuses.push("repo layout, entrypoints, and tests relevant to the task");
  }

  const outcomes = await Promise.all(
    focuses.map((focus, i) =>
      runJob({
        role: "scout",
        cwd: opts.cwd,
        apiKey: opts.apiKey,
        modelChain: ROLE_MODEL_CHAINS.scout,
        prompt: scoutPrompt(opts.task, focus),
        state: opts.state,
        jobId: `scout-${i}-${Date.now()}`,
        live: opts.live,
        verbose: opts.verbose,
        processRegistry: opts.processRegistry,
        projectHook: opts.projectHook,
      }),
    ),
  );

  const summaries = outcomes.map((o, i) => {
    const head = `### Scout ${i + 1}: ${focuses[i]}`;
    if (!o.ok) {
      return `${head}\n(failed: ${o.lastError ?? "unknown"}; attempts=${o.attempts.join("→")})`;
    }
    const body = o.streamedText.trim().slice(0, 2000);
    return `${head}\n${body}`;
  });

  return { summaries, outcomes };
}
