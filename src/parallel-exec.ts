import { ROLE_MODEL_CHAINS } from "./models.js";
import { runJob, type JobOutcome } from "./run-job.js";
import { executorShardPrompt } from "./specialties.js";
import type { TeamStateStore } from "./state.js";
import type { ProcessRegistry } from "./process-registry.js";
import type { ProjectHookLease } from "./project-hook.js";

export type ParallelExecOptions = {
  apiKey: string;
  cwd: string;
  /** Each inner array is one shard (commands in order). */
  shards: string[][];
  max?: number;
  state?: TeamStateStore;
  live?: boolean;
  verbose?: boolean;
  processRegistry?: ProcessRegistry;
  projectHook?: ProjectHookLease;
};

/**
 * Parallel executor jobs (Sol→Terra→GPT→Grok). No source edits by prompt.
 */
export async function runParallelExec(
  opts: ParallelExecOptions,
): Promise<JobOutcome[]> {
  const max = opts.max ?? 8;
  const shards = opts.shards.slice(0, max);
  return Promise.all(
    shards.map((commands, i) =>
      runJob({
        role: "executor",
        cwd: opts.cwd,
        apiKey: opts.apiKey,
        modelChain: ROLE_MODEL_CHAINS.executor,
        prompt: executorShardPrompt(commands),
        state: opts.state,
        jobId: `exec-${i}-${Date.now()}`,
        live: opts.live,
        verbose: opts.verbose,
        processRegistry: opts.processRegistry,
        projectHook: opts.projectHook,
      }),
    ),
  );
}
