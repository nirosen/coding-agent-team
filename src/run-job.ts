import { Agent, CursorAgentError, type RunResult } from "@cursor/sdk";
import { redactSecrets } from "./control.js";
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
import type { ProcessRegistry } from "./process-registry.js";
import type { PolicyRuntime } from "./policy-runtime.js";
import type { ProjectHookLease } from "./project-hook.js";
import {
  formatSteerFollowUp,
  type SteerHub,
  type SteerMessage,
} from "./steer.js";

const MAX_CONVERSATION_TURNS = 32;
const CANCEL_TIMEOUT_MS = 10_000;
const CANCEL_SETTLE_TIMEOUT_MS = 30_000;

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
  live?: boolean;
  verbose?: boolean;
  steer?: SteerHub;
  processRegistry?: ProcessRegistry;
  policy?: PolicyRuntime;
  projectHook?: ProjectHookLease;
};

type SDKRun = Awaited<
  ReturnType<Awaited<ReturnType<typeof Agent.create>>["send"]>
>;

type StreamOutcome =
  | { kind: "done" }
  | { kind: "steered"; steer: SteerMessage; delayed: boolean };

function abortableDelay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException("operation aborted", "AbortError"));
      return;
    }
    const timer = setTimeout(done, ms);
    function done(): void {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }
    function onAbort(): void {
      clearTimeout(timer);
      reject(new DOMException("operation aborted", "AbortError"));
    }
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

async function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(
      () => reject(new Error(`${label} timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function consumeRunStream(
  run: SDKRun,
  opts: {
    jobId: string;
    live: boolean;
    session: LiveSession;
    state?: TeamStateStore;
    onText?: (text: string) => void;
    onDelta: (delta: string) => void;
  },
): Promise<void> {
  for await (const event of run.stream()) {
    opts.state?.touch(opts.jobId);
    if (opts.live) {
      const delta = renderStreamEvent(opts.session, event);
      if (delta) {
        opts.onDelta(delta);
        opts.onText?.(delta);
      }
    } else if (event.type === "assistant") {
      for (const block of event.message.content) {
        if (block.type !== "text") continue;
        const text = redactSecrets(block.text);
        opts.onDelta(text);
        process.stdout.write(text);
        opts.onText?.(text);
      }
    }
  }
}

async function waitForSteer(
  hub: SteerHub,
  signal: AbortSignal,
): Promise<SteerMessage> {
  for (;;) {
    if (signal.aborted) {
      throw new DOMException("steer wait aborted", "AbortError");
    }
    await hub.poll();
    const steer = hub.take();
    if (steer) return steer;
    await abortableDelay(hub.intervalMs, signal);
  }
}

/**
 * Consume the SDK stream with exactly one iterator. A separate control waiter
 * races it; no repeated `iter.next()` calls are created on polling ticks.
 */
export async function streamUntilDoneOrSteer(
  run: SDKRun,
  opts: {
    jobId: string;
    live: boolean;
    session: LiveSession;
    state?: TeamStateStore;
    onText?: (text: string) => void;
    steer?: SteerHub;
    allowSteer: boolean;
    onDelta: (delta: string) => void;
  },
): Promise<StreamOutcome> {
  const streamPromise = consumeRunStream(run, opts);
  if (!opts.steer?.enabled || !opts.allowSteer) {
    await streamPromise;
    return { kind: "done" };
  }

  const abort = new AbortController();
  const steerPromise = waitForSteer(opts.steer, abort.signal);
  const winner = await Promise.race([
    streamPromise.then(
      () => ({ kind: "done" as const }),
      (error: unknown) => ({ kind: "stream-error" as const, error }),
    ),
    steerPromise.then(
      (steer) => ({ kind: "steered" as const, steer }),
      (error: unknown) => ({ kind: "steer-error" as const, error }),
    ),
  ]);

  if (winner.kind === "stream-error") {
    abort.abort();
    await steerPromise.catch(() => undefined);
    throw winner.error;
  }
  if (winner.kind === "steer-error") {
    const controlError =
      winner.error instanceof Error
        ? winner.error
        : new Error(String(winner.error));
    console.error(
      `[steer] control polling failed; failing closed: ${controlError.message}`,
    );
    if (run.supports("cancel")) {
      await withTimeout(
        run.cancel(),
        CANCEL_TIMEOUT_MS,
        "run.cancel after control failure",
      ).catch(() => undefined);
      await withTimeout(
        streamPromise,
        CANCEL_SETTLE_TIMEOUT_MS,
        "stream settlement after control failure",
      ).catch((error) => {
        if (
          error instanceof Error &&
          error.message.startsWith(
            "stream settlement after control failure timed out",
          )
        ) {
          throw error;
        }
        // Cancellation may terminate the stream with an expected error.
      });
    } else {
      await streamPromise.catch(() => undefined);
    }
    throw controlError;
  }
  if (winner.kind === "done") {
    abort.abort();
    // Observe the expected AbortError and avoid an unhandled rejection.
    await steerPromise.catch(() => undefined);
    return winner;
  }

  abort.abort();
  const steer = winner.steer;
  console.log(
    `\n\x1b[33m↪ steer (${steer.source})\x1b[0m ${steer.text.slice(0, 200)}${steer.text.length > 200 ? "…" : ""}`,
  );

  if (!run.supports("cancel")) {
    console.warn(
      `[steer] active run cannot be cancelled (${run.unsupportedReason("cancel")}); applying after this turn`,
    );
    await streamPromise;
    return { kind: "steered", steer, delayed: true };
  }

  try {
    await withTimeout(run.cancel(), CANCEL_TIMEOUT_MS, "run.cancel");
  } catch (error) {
    console.warn(
      `[steer] cancel failed; applying after this turn: ${error instanceof Error ? error.message : error}`,
    );
    await streamPromise;
    return { kind: "steered", steer, delayed: true };
  }

  try {
    await withTimeout(
      streamPromise,
      CANCEL_SETTLE_TIMEOUT_MS,
      "cancelled stream settlement",
    );
  } catch (error) {
    // Cancellation commonly ends the stream with an error. A timeout is not
    // safe to ignore because a second send could overlap the first run.
    if (
      error instanceof Error &&
      error.message.startsWith("cancelled stream settlement timed out")
    ) {
      throw error;
    }
  }
  return { kind: "steered", steer, delayed: false };
}

function promptWithSteerHistory(
  original: string,
  steers: readonly SteerMessage[],
): string {
  if (steers.length === 0) return original;
  return [
    original,
    "",
    "## Previously authenticated mid-run guidance",
    ...steers.map(
      (steer, index) =>
        `${index + 1}. [${steer.id}] ${steer.text}`,
    ),
    "",
    "Honor this guidance, but request authorization again at every named gate.",
  ].join("\n");
}

function allowsModelFallback(error: unknown): boolean {
  if (errorLooksLikeSafetyBlock(error)) return true;
  if (!(error instanceof CursorAgentError)) return false;
  const message = error.message.toLowerCase();
  if (
    /auth|api[ _-]?key|credential|permission|billing|quota|insufficient/.test(
      message,
    )
  ) {
    return false;
  }
  return (
    error.isRetryable ||
    /model|classifier|unsupported|not found|not available|capacity/.test(
      message,
    )
  );
}

/**
 * Local Agent.create + send/stream/wait with model fallback. Accepted steers
 * are replayed when a fallback creates a new model/agent.
 */
export async function runJob(opts: RunJobOptions): Promise<JobOutcome> {
  const attempts: ModelId[] = [];
  const acceptedSteers: SteerMessage[] = [];
  let pendingSteer: SteerMessage | undefined;
  let streamedText = "";
  let lastError: string | undefined;
  const jobId = opts.jobId ?? `${opts.role}-${Date.now()}`;
  const live = opts.live !== false;
  const stopOwnedProcesses = async (): Promise<void> => {
    if (!opts.processRegistry) return;
    await opts.processRegistry.stopOwner(jobId);
  };

  for (const model of opts.modelChain) {
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
      lastError: undefined,
      lastEventAt: Date.now(),
    });
    const session: LiveSession = {
      role: opts.role,
      model,
      verbose: Boolean(opts.verbose),
    };

    try {
      opts.projectHook?.verify();
      const customTools = opts.processRegistry
        ? {
            supervised_process: opts.processRegistry.customTool(jobId),
            ...(opts.policy && opts.role === "master"
              ? { request_phase_transition: opts.policy.phaseTool() }
              : {}),
          }
        : undefined;
      await using agent = await Agent.create({
        apiKey: opts.apiKey,
        model: { id: model },
        local: {
          cwd: opts.cwd,
          autoReview: true,
          ...(opts.projectHook
            ? {
                settingSources: ["project" as const],
                sandboxOptions: { enabled: true },
              }
            : {}),
          ...(customTools ? { customTools } : {}),
        },
        ...(opts.agents ? { agents: opts.agents } : {}),
      });

      let nextPrompt = promptWithSteerHistory(opts.prompt, acceptedSteers);
      let result: RunResult | undefined;

      for (let turn = 0; turn < MAX_CONVERSATION_TURNS; turn++) {
        opts.projectHook?.verify();
        const run = await agent.send(nextPrompt);
        if (pendingSteer) {
          opts.steer?.acknowledgeSteer(pendingSteer);
          acceptedSteers.push(pendingSteer);
          pendingSteer = undefined;
        }
        console.log(
          live
            ? `\x1b[2mrun.id=${run.id}  agentId=${agent.agentId}${turn ? `  turn=${turn}` : ""}\x1b[0m\n`
            : `[${opts.role}] run.id=${run.id} agentId=${agent.agentId} turn=${turn}`,
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
        if (turn === 0) streamedText = "";

        const streamOutcome = await streamUntilDoneOrSteer(run, {
          jobId,
          live,
          session,
          state: opts.state,
          onText: opts.onText,
          steer: opts.steer,
          allowSteer: turn < MAX_CONVERSATION_TURNS - 1,
          onDelta: (delta) => {
            streamedText += delta;
          },
        });

        if (streamOutcome.kind === "steered") {
          await stopOwnedProcesses();
          pendingSteer = streamOutcome.steer;
          // wait() must settle before a follow-up send on the same agent.
          let settled: RunResult | undefined;
          try {
            settled = await withTimeout(
              run.wait(),
              CANCEL_SETTLE_TIMEOUT_MS,
              "steered run settlement",
            );
          } catch (error) {
            if (streamOutcome.delayed) throw error;
            // A cancelled run may reject wait(); stream settlement already
            // confirmed the previous run is no longer active.
          }
          if (
            settled?.status === "error" ||
            (streamOutcome.delayed && settled?.status !== "finished")
          ) {
            throw new Error(
              `steered run did not settle safely: ${settled?.status ?? "unknown"}`,
            );
          }
          nextPrompt = formatSteerFollowUp(streamOutcome.steer);
          continue;
        }

        result = await run.wait();
        break;
      }

      if (!result) {
        await stopOwnedProcesses();
        lastError =
          "conversation turn limit reached; any unacknowledged steer remains queued";
        return { ok: false, role: opts.role, attempts, lastError, streamedText };
      }

      if (resultLooksLikeSafetyBlock(result, streamedText)) {
        await stopOwnedProcesses();
        const fallback = nextModel(opts.modelChain, model);
        console.warn(
          `\n[${opts.role}] safety-block on ${model}` +
            (fallback ? ` → fallback ${fallback}` : " (no more fallbacks)"),
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

      if (result.status !== "finished") {
        await stopOwnedProcesses();
        lastError = `run status=${result.status} id=${result.id}`;
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

      opts.processRegistry?.assertIdle(jobId);
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
        lastError: undefined,
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
    } catch (error) {
      if (pendingSteer) {
        opts.steer?.releaseSteer(pendingSteer);
        pendingSteer = undefined;
      }
      let caught = error instanceof Error ? error.message : String(error);
      try {
        await stopOwnedProcesses();
      } catch (cleanupError) {
        caught = `${caught}; supervised cleanup failed: ${
          cleanupError instanceof Error ? cleanupError.message : cleanupError
        }`;
      }
      lastError = caught;
      if (allowsModelFallback(error)) {
        const fallback = nextModel(opts.modelChain, model);
        console.warn(
          `\n[${opts.role}] startup/classifier failure on ${model}: ${lastError}` +
            (fallback ? ` → fallback ${fallback}` : ""),
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
        if (fallback) continue;
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
