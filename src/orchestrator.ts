import { MODELS, ROLE_MODEL_CHAINS } from "./models.js";
import { runJob, type JobFail, type JobOutcome } from "./run-job.js";
import { masterSystemPrompt, SPECIALTIES } from "./specialties.js";
import type { TeamStateStore } from "./state.js";
import type { ProcessRegistry } from "./process-registry.js";
import type { PolicyRuntime } from "./policy-runtime.js";
import type { ProjectHookLease } from "./project-hook.js";
import type { SlackConfig } from "./slack-hitl.js";
import readline from "node:readline/promises";
import { stdin as input, stdout as output } from "node:process";
import {
  askHitlAndWait,
  postSlackMessage,
  slackHitlEnabled,
  slackPostingEnabled,
} from "./slack-hitl.js";
import type {
  AuthorizationMessage,
  SteerHub,
} from "./steer.js";
import {
  isUnsafeAuthorizationValue,
  looksLikeSecret,
  questionSha256,
} from "./control.js";

type GateDecision = {
  decision: "approve" | "deny" | "cancel" | "choice";
  value?: string;
  answer: string;
  source: "control" | "slack" | "tty";
  authorizationId?: string;
  controlMessage?: AuthorizationMessage;
};

const MAX_HITL_GATES = 32;

async function askStdinHitl(question: string): Promise<GateDecision> {
  const rl = readline.createInterface({ input, output });
  try {
    console.log(`\n\x1b[33m⏸ HITL (terminal)\x1b[0m ${question}`);
    for (;;) {
      const raw = await rl.question(
        "Decision [approve | deny | cancel | choice:<value>]> ",
      );
      const parsed = parseGateDecision(raw, "tty");
      if (parsed) return parsed;
      console.warn(
        "Invalid decision. Secrets and free-form text are not accepted here; use a steer for guidance.",
      );
    }
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
  interactiveHitl?: boolean;
  /** Signed controller and mid-run steer channel. */
  steer?: SteerHub;
  processRegistry?: ProcessRegistry;
  policy?: PolicyRuntime;
  projectHook?: ProjectHookLease;
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
  if (opts.policy) {
    const phase = opts.policy.currentPhase();
    const phaseIndex = opts.policy.profile.phases.indexOf(phase);
    const nextPhase = opts.policy.profile.phases[phaseIndex + 1];
    const commands = opts.policy.commands.commands
      .filter((command) => command.phase === phase)
      .map(
        (command) =>
          `- ${command.id} (${command.kind}, expected exits ${command.expectedExitCodes.join(",")})`,
      );
    parts.push(
      "",
      "## Signed hard-policy run",
      `Current phase: ${phase}`,
      `Next phase: ${nextPhase ?? "none"}`,
      "Built-in Shell is denied. Run only signed commands through supervised_process.",
      ...(commands.length ? commands : ["- No commands are declared for this phase."]),
      nextPhase
        ? `After the required receipts exist, call request_phase_transition with targetPhase=${nextPhase}.`
        : "The terminal phase is sealed; do not execute more work.",
      "Never edit .cursor/hooks.json or .team-state. A steer cannot change the signed manifests or budget.",
    );
  }
  return parts.join("\n");
}

export function extractHitl(text: string): string | undefined {
  const matches = [
    ...text.matchAll(/^HITL_REQUIRED:\s*(\S[^\r\n]*)$/gim),
  ];
  const question = matches.at(-1)?.[1]?.trim();
  if (!question || question.length > 2_000) return undefined;
  return question;
}

export function parseGateDecision(
  raw: string,
  source: GateDecision["source"],
): GateDecision | undefined {
  const answer = raw.trim();
  if (looksLikeSecret(answer)) return undefined;
  if (/^approve$/i.test(answer)) {
    return { decision: "approve", answer: "approve", source };
  }
  const approveValue = answer.match(/^approve[-:]([A-Za-z0-9_.-]{1,128})$/i);
  if (
    approveValue?.[1] &&
    !isUnsafeAuthorizationValue(approveValue[1])
  ) {
    return {
      decision: "approve",
      value: approveValue[1],
      answer: `approve:${approveValue[1]}`,
      source,
    };
  }
  if (/^deny$/i.test(answer)) {
    return { decision: "deny", answer: "deny", source };
  }
  if (/^cancel$/i.test(answer)) {
    return { decision: "cancel", answer: "cancel", source };
  }
  const choice = answer.match(/^choice:([A-Za-z0-9_.-]{1,128})$/i);
  if (choice?.[1] && !isUnsafeAuthorizationValue(choice[1])) {
    return {
      decision: "choice",
      value: choice[1],
      answer: `choice:${choice[1]}`,
      source,
    };
  }
  if (/^[1-9][0-9]{0,2}$/.test(answer)) {
    return {
      decision: "choice",
      value: answer,
      answer: `choice:${answer}`,
      source,
    };
  }
  return undefined;
}

function failedGate(
  opts: OrchestratorOptions,
  prior: JobOutcome,
  jobId: string,
  error: string,
): JobFail {
  opts.state?.upsert({
    jobId,
    role: "master",
    status: "blocked",
    lastError: error,
    attempts: [...prior.attempts],
    lastEventAt: Date.now(),
  });
  return {
    ok: false,
    role: "master",
    attempts: [...prior.attempts],
    lastError: error,
    streamedText: prior.streamedText,
  };
}

async function waitForGateDecision(
  opts: OrchestratorOptions,
  jobId: string,
  question: string,
): Promise<GateDecision> {
  const timeoutMs = opts.hitlTimeoutMs ?? 30 * 60 * 1000;

  // Signed run-scoped control is authoritative when configured. Slack is only
  // a notification in this mode; Nir authorizes through the Codex controller.
  if (opts.steer?.enabled) {
    if (opts.slack && slackPostingEnabled(opts.slack)) {
      try {
        await postSlackMessage(
          opts.slack,
          [
            `*coding-agent-team authorization required*`,
            `run \`${opts.steer.teamRunId}\` · job \`${jobId}\``,
            question,
            "",
            `question_sha256: \`${questionSha256(question)}\``,
            "_Authorize through the signed Codex controller channel._",
          ].join("\n"),
        );
      } catch (error) {
        console.warn(
          `[master] Slack notification failed; signed control remains active: ${error instanceof Error ? error.message : error}`,
        );
      }
    }
    const control = await opts.steer.waitForAuthorization(
      {
        teamRunId: opts.steer.teamRunId,
        jobId,
        question,
      },
      { timeoutMs },
    );
    return {
      decision: control.decision,
      value: control.value,
      answer: control.answer,
      source: "control",
      authorizationId: control.id,
      controlMessage: control,
    };
  }

  if (opts.slack && slackHitlEnabled(opts.slack)) {
    const { reply } = await askHitlAndWait(opts.slack, {
      jobId,
      question,
      timeoutMs,
      allowedReplies: "approve | deny | cancel | choice:<value>",
      validateReply: (text) => Boolean(parseGateDecision(text, "slack")),
    });
    const parsed = parseGateDecision(reply.text, "slack");
    if (!parsed) {
      throw new Error(
        `invalid Slack authorization from allowlisted user ${reply.user}`,
      );
    }
    return parsed;
  }

  if (opts.interactiveHitl !== false && process.stdin.isTTY) {
    return askStdinHitl(question);
  }

  throw new Error("authorization required but no signed control, Slack, or TTY");
}

/**
 * Run Opus-led master with specialty subagents. HITL is a hard gate: failure,
 * timeout, deny, or cancel returns a failed outcome and can never print OK.
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
  agents.reviewer = {
    ...agents.reviewer!,
    model: { id: MODELS.opus },
  };

  const jobId = `master-${Date.now()}`;
  let prompt = buildMasterPrompt(opts);

  for (let round = 0; round <= MAX_HITL_GATES; round++) {
    const outcome = await runJob({
      role: "master",
      cwd: opts.cwd,
      apiKey: opts.apiKey,
      modelChain: ROLE_MODEL_CHAINS.master,
      prompt,
      agents,
      state: opts.state,
      jobId,
      live: opts.live,
      verbose: opts.verbose,
      steer: opts.steer,
      processRegistry: opts.processRegistry,
      policy: opts.policy,
      projectHook: opts.projectHook,
    });

    if (!outcome.ok) return outcome;
    const policyQuestion = opts.policy?.pendingQuestion();
    const question = policyQuestion ?? extractHitl(outcome.streamedText);
    if (!question) return outcome;
    if (!opts.state) {
      return failedGate(
        opts,
        outcome,
        jobId,
        "HITL requires TeamStateStore for exact audit binding",
      );
    }
    if (round === MAX_HITL_GATES) {
      return failedGate(
        opts,
        outcome,
        jobId,
        `HITL gate limit reached (${MAX_HITL_GATES})`,
      );
    }
    if (looksLikeSecret(question)) {
      return failedGate(
        opts,
        outcome,
        jobId,
        "refusing HITL question containing a secret-shaped value",
      );
    }

    opts.state?.markAwaitingHuman(jobId, question);
    let authorization: GateDecision;
    try {
      authorization = await waitForGateDecision(opts, jobId, question);
    } catch (error) {
      return failedGate(
        opts,
        outcome,
        jobId,
        `authorization unresolved: ${error instanceof Error ? error.message : error}`,
      );
    }

    try {
      opts.state?.resolveHuman(jobId, {
        decision: authorization.decision,
        source: authorization.source,
        authorizationId: authorization.authorizationId,
      });
      if (policyQuestion) {
        if (authorization.decision === "choice") {
          throw new Error("policy gates do not accept choice decisions");
        }
        opts.policy!.authorizePending({
          decision: authorization.decision,
          authorizationId: authorization.authorizationId,
          controlEnvelope:
            authorization.controlMessage?.pendingControl.envelope,
        });
      }
      if (authorization.controlMessage) {
        opts.steer!.acknowledgeAuthorization(authorization.controlMessage);
      }
    } catch (error) {
      return failedGate(
        opts,
        outcome,
        jobId,
        `authorization audit failed: ${error instanceof Error ? error.message : error}`,
      );
    }

    if (
      authorization.decision === "deny" ||
      authorization.decision === "cancel"
    ) {
      return failedGate(
        opts,
        outcome,
        jobId,
        `human decision: ${authorization.decision}`,
      );
    }

    prompt = [
      buildMasterPrompt(opts),
      "",
      "## Authorized gate decision",
      `Question: ${question}`,
      `Decision: ${authorization.answer}`,
      `Source: ${authorization.source}`,
      "",
      "Continue only within this authorization. Ask again at the next named gate.",
    ].join("\n");
  }

  return {
    ok: false,
    role: "master",
    attempts: [...ROLE_MODEL_CHAINS.master],
    lastError: "HITL gate loop exited unexpectedly",
    streamedText: "",
  };
}
