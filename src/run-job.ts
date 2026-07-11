import { Agent, CursorAgentError, type RunResult } from "@cursor/sdk";
import { nextModel, type ModelId } from "./models.js";
import {
  errorLooksLikeSafetyBlock,
  resultLooksLikeSafetyBlock,
} from "./safety.js";
import {
  banner,
  renderJobDone,
  renderStreamEvent,
  type LiveSession,
} from "./session-view.js";
import type { TeamStateStore } from "./state.js";

export type JobOk = {
  ok: true;
  role: string;
  model: ModelId;
  result: RunResult;
  streamedText: string;
  attempts: ModelId[];
};

export type JobFail = {
  ok: false;
  role: string;
  attempts: ModelId[];
  lastError?: string;
  streamedText: string;
};

export type JobOutcome = JobOk | JobFail;

export type RunJobOptions = {
  role: string;
  cwd: string;
  apiKey: string;
  modelChain: readonly ModelId[];
  prompt: string;
  agents?: Record<
    string,
    { description: string; prompt: string; model: { id: string } | "inherit" }
  >;
  state?: TeamStateStore;
  jobId?: string;
  onText?: (text: string) => void;
  /** Live interactive terminal view (default true). */
  live?: boolean;
  verbose?: boolean;
};

/**
 * Local Agent.create + send/stream/wait, walking the model chain on
 * safety/classifier blocks. Every chain should end on Grok.
 */
export async function runJob(opts: RunJobOptions): Promise<JobOutcome> {
  const attempts: ModelId[] = [];
  let streamedText = "";
  let lastError: string | undefined;
  const jobId = opts.jobId ?? `${opts.role}-${Date.now()}`;
  const live = opts.live !== false;

  for (let i = 0; i < opts.modelChain.length; i++) {
    const model = opts.modelChain[i]!;
    attempts.push(model);
    if (live) {
      banner(opts.role, model, `cwd=${opts.cwd}`);
    } else {
      console.log(`[${opts.role}] trying model=${model} cwd=${opts.cwd}`);
    }
    opts.state?.upsert({
      jobId,
      role: opts.role,
      model,
      status: "running",
      attempts: [...attempts],
      lastEventAt: Date.now(),
    });

    const session: LiveSession = {
      role: opts.role,
      model,
      verbose: Boolean(opts.verbose),
    };

    try {
      await using agent = await Agent.create({
        apiKey: opts.apiKey,
        model: { id: model },
        local: { cwd: opts.cwd },
        ...(opts.agents ? { agents: opts.agents } : {}),
      });

      const run = await agent.send(opts.prompt);
      console.log(
        live
          ? `\x1b[2mrun.id=${run.id}  agentId=${agent.agentId}\x1b[0m\n`
          : `[${opts.role}] run.id=${run.id} agentId=${agent.agentId}`,
      );
      opts.state?.upsert({
        jobId,
        role: opts.role,
        model,
        status: "running",
        runId: run.id,
        agentId: agent.agentId,
        attempts: [...attempts],
        lastEventAt: Date.now(),
      });

      streamedText = "";
      for await (const event of run.stream()) {
        opts.state?.touch(jobId);
        if (live) {
          const delta = renderStreamEvent(session, event);
          if (delta) {
            streamedText += delta;
            opts.onText?.(delta);
          }
        } else if (event.type === "assistant") {
          for (const block of event.message.content) {
            if (block.type === "text") {
              streamedText += block.text;
              process.stdout.write(block.text);
              opts.onText?.(block.text);
            }
          }
        }
      }

      const result = await run.wait();
      if (resultLooksLikeSafetyBlock(result, streamedText)) {
        const fb = nextModel(opts.modelChain, model);
        console.warn(
          `\n[${opts.role}] safety-block on ${model}` +
            (fb ? ` → fallback ${fb}` : " (no more fallbacks)"),
        );
        lastError = `safety-block on ${model}`;
        opts.state?.upsert({
          jobId,
          role: opts.role,
          model,
          status: "blocked",
          attempts: [...attempts],
          lastError,
          lastEventAt: Date.now(),
        });
        continue;
      }

      if (result.status === "error") {
        lastError = `run status=error id=${result.id}`;
        if (resultLooksLikeSafetyBlock(result, streamedText)) {
          continue;
        }
        opts.state?.upsert({
          jobId,
          role: opts.role,
          model,
          status: "error",
          attempts: [...attempts],
          lastError,
          lastEventAt: Date.now(),
        });
        return {
          ok: false,
          role: opts.role,
          attempts,
          lastError,
          streamedText,
        };
      }

      if (live) {
        renderJobDone(opts.role, model, result.status, attempts);
      } else {
        console.log(
          `\n[${opts.role}] finished model=${model} status=${result.status} attempts=${attempts.join("→")}`,
        );
      }
      opts.state?.upsert({
        jobId,
        role: opts.role,
        model,
        status: "finished",
        attempts: [...attempts],
        lastEventAt: Date.now(),
      });
      return {
        ok: true,
        role: opts.role,
        model,
        result,
        streamedText,
        attempts,
      };
    } catch (err) {
      lastError = err instanceof Error ? err.message : String(err);
      if (err instanceof CursorAgentError || errorLooksLikeSafetyBlock(err)) {
        const fb = nextModel(opts.modelChain, model);
        console.warn(
          `\n[${opts.role}] startup/classifier failure on ${model}: ${lastError}` +
            (fb ? ` → fallback ${fb}` : ""),
        );
        opts.state?.upsert({
          jobId,
          role: opts.role,
          model,
          status: "blocked",
          attempts: [...attempts],
          lastError,
          lastEventAt: Date.now(),
        });
        if (fb) continue;
      }
      opts.state?.upsert({
        jobId,
        role: opts.role,
        model,
        status: "error",
        attempts: [...attempts],
        lastError,
        lastEventAt: Date.now(),
      });
      return { ok: false, role: opts.role, attempts, lastError, streamedText };
    }
  }

  return {
    ok: false,
    role: opts.role,
    attempts,
    lastError: lastError ?? "all models exhausted",
    streamedText,
  };
}
