/**
 * Authenticated mid-run control for coding-agent-team.
 *
 * Primary channel: signed JSON envelopes in a run-scoped control spool.
 * Optional Slack steering is disabled unless an explicit user allowlist is
 * configured, and every Slack message must name the target team run.
 */

import type { SlackConfig } from "./slack-hitl.js";
import {
  acknowledgeControl,
  authorizationMatches,
  formatAuthorizationAnswer,
  looksLikeSecret,
  rejectControl,
  scanControlSpool,
  type AuthorizationQuery,
  type PendingControl,
} from "./control.js";

export type SteerSource = "control" | "slack";

export type SteerMessage = {
  id: string;
  text: string;
  source: SteerSource;
  at: number;
  /** Present for durable signed-control messages; ack after follow-up send. */
  pendingControl?: PendingControl;
};

export type AuthorizationMessage = {
  id: string;
  answer: string;
  decision: "approve" | "deny" | "cancel" | "choice";
  value?: string;
  source: "control";
  pendingControl: PendingControl;
};

export type SteerHubOptions = {
  controlDir: string;
  publicKeyPem: string | Buffer;
  teamRunId: string;
  slack?: SlackConfig;
  pollMs?: number;
  enabled?: boolean;
};

export class SteerHub {
  readonly controlDir: string;
  readonly teamRunId: string;
  readonly enabled: boolean;
  private readonly publicKeyPem: string | Buffer;
  private readonly slack?: SlackConfig;
  private readonly pollMs: number;
  private steerQueue: SteerMessage[] = [];
  private authorizationQueue: AuthorizationMessage[] = [];
  private queuedControlIds = new Set<string>();
  private slackOldest: string;
  private lastSlackPoll = 0;

  constructor(opts: SteerHubOptions) {
    this.controlDir = opts.controlDir;
    this.teamRunId = opts.teamRunId;
    this.publicKeyPem = opts.publicKeyPem;
    this.slack = opts.slack;
    this.pollMs = opts.pollMs ?? 2000;
    this.enabled = opts.enabled !== false;
    this.slackOldest = slackTimestampNow();
  }

  get intervalMs(): number {
    return this.pollMs;
  }

  async poll(): Promise<void> {
    if (!this.enabled) return;

    for (const pending of scanControlSpool(this.controlDir, {
      publicKeyPem: this.publicKeyPem,
      teamRunId: this.teamRunId,
    })) {
      const envelope = pending.envelope;
      if (this.queuedControlIds.has(envelope.id)) continue;
      this.queuedControlIds.add(envelope.id);
      if (envelope.kind === "steer") {
        this.steerQueue.push({
          id: envelope.id,
          text: envelope.text!,
          source: "control",
          at: envelope.createdAt,
          pendingControl: pending,
        });
      } else {
        this.authorizationQueue.push({
          id: envelope.id,
          answer: formatAuthorizationAnswer(envelope),
          decision: envelope.decision!,
          value: envelope.value,
          source: "control",
          pendingControl: pending,
        });
      }
    }

    // Never let optional Slack I/O delay a durable signed control.
    if (this.steerQueue.length || this.authorizationQueue.length) return;
    if (!slackSteerEnabled(this.slack)) return;
    const now = Date.now();
    if (now - this.lastSlackPoll < this.pollMs) return;
    this.lastSlackPoll = now;

    try {
      const messages = await pollSlackSteers(
        this.slack!,
        this.teamRunId,
        this.slackOldest,
      );
      if (messages.newestTs) this.slackOldest = messages.newestTs;
      this.steerQueue.push(...messages.steers);
    } catch (error) {
      console.warn(
        `[steer] Slack poll failed: ${error instanceof Error ? error.message : error}`,
      );
    }
  }

  take(): SteerMessage | undefined {
    while (this.steerQueue.length) {
      const steer = this.steerQueue.shift()!;
      if (
        steer.pendingControl &&
        steer.pendingControl.envelope.expiresAt <= Date.now()
      ) {
        this.queuedControlIds.delete(steer.pendingControl.envelope.id);
        rejectControl(this.controlDir, steer.pendingControl);
        continue;
      }
      return steer;
    }
    return undefined;
  }

  peek(): SteerMessage | undefined {
    return this.steerQueue[0];
  }

  /** Ack only after the follow-up `agent.send()` has been accepted. */
  acknowledgeSteer(steer: SteerMessage): void {
    if (steer.pendingControl) {
      acknowledgeControl(this.controlDir, steer.pendingControl);
      this.queuedControlIds.delete(steer.pendingControl.envelope.id);
    }
  }

  /** Return an undelivered steer to the queue/spool after send failure. */
  releaseSteer(steer: SteerMessage): void {
    if (steer.pendingControl) {
      this.queuedControlIds.delete(steer.pendingControl.envelope.id);
      return;
    }
    this.steerQueue.unshift(steer);
  }

  takeAuthorization(
    query: AuthorizationQuery,
    now = Date.now(),
  ): AuthorizationMessage | undefined {
    for (let i = this.authorizationQueue.length - 1; i >= 0; i--) {
      const message = this.authorizationQueue[i]!;
      if (message.pendingControl.envelope.expiresAt > now) continue;
      this.authorizationQueue.splice(i, 1);
      this.queuedControlIds.delete(message.pendingControl.envelope.id);
      rejectControl(this.controlDir, message.pendingControl);
    }
    const index = this.authorizationQueue.findIndex((item) =>
      authorizationMatches(item.pendingControl.envelope, query, now),
    );
    if (index < 0) return undefined;
    return this.authorizationQueue.splice(index, 1)[0];
  }

  acknowledgeAuthorization(message: AuthorizationMessage): void {
    acknowledgeControl(this.controlDir, message.pendingControl);
    this.queuedControlIds.delete(message.pendingControl.envelope.id);
  }

  async waitForAuthorization(
    query: AuthorizationQuery,
    opts: {
      timeoutMs?: number;
      signal?: AbortSignal;
    } = {},
  ): Promise<AuthorizationMessage> {
    const timeoutMs = opts.timeoutMs ?? 30 * 60 * 1000;
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (opts.signal?.aborted) {
        throw new DOMException("authorization wait aborted", "AbortError");
      }
      await this.poll();
      const authorization = this.takeAuthorization(query);
      if (authorization) return authorization;
      await abortableDelay(
        Math.min(this.pollMs, Math.max(1, deadline - Date.now())),
        opts.signal,
      );
    }
    throw new Error(`control authorization timeout after ${timeoutMs}ms`);
  }
}

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

function slackSteerEnabled(cfg?: SlackConfig): boolean {
  return Boolean(
    cfg?.botToken &&
      cfg.channelId &&
      cfg.steerEnabled &&
      cfg.allowedUserIds?.length,
  );
}

function slackTimestampNow(): string {
  return (Date.now() / 1000).toFixed(6);
}

function slackTimestampValue(ts: string): bigint {
  const [seconds = "0", fraction = ""] = ts.split(".");
  return (
    BigInt(seconds) * 1_000_000n +
    BigInt(fraction.padEnd(6, "0").slice(0, 6))
  );
}

function laterSlackTimestamp(a: string, b: string): string {
  return slackTimestampValue(a) >= slackTimestampValue(b) ? a : b;
}

export async function pollSlackSteers(
  cfg: SlackConfig,
  teamRunId: string,
  oldest: string,
): Promise<{ steers: SteerMessage[]; newestTs?: string }> {
  if (!slackSteerEnabled(cfg)) return { steers: [] };

  const steers: Array<SteerMessage & { ts: string }> = [];
  let cursor: string | undefined;
  let newestTs = oldest;
  const seenCursors = new Set<string>();
  const deadline = Date.now() + 30_000;
  let pages = 0;

  do {
    if (++pages > 20 || Date.now() >= deadline) {
      throw new Error("Slack steer pagination exceeded its bound");
    }
    if (cursor) {
      if (seenCursors.has(cursor)) {
        throw new Error("Slack steer pagination cursor repeated");
      }
      seenCursors.add(cursor);
    }
    const params = new URLSearchParams({
      channel: cfg.channelId!,
      limit: "200",
      oldest,
      inclusive: "false",
    });
    if (cursor) params.set("cursor", cursor);
    const response = await fetch(
      `https://slack.com/api/conversations.history?${params}`,
      {
        headers: { Authorization: `Bearer ${cfg.botToken}` },
        signal: AbortSignal.timeout(
          Math.max(1, Math.min(10_000, deadline - Date.now())),
        ),
      },
    );
    const json = (await response.json()) as {
      ok?: boolean;
      error?: string;
      messages?: Array<{
        text?: string;
        ts?: string;
        bot_id?: string;
        user?: string;
      }>;
      response_metadata?: { next_cursor?: string };
    };
    if (!json.ok) {
      throw new Error(json.error ?? "conversations.history failed");
    }

    for (const message of json.messages ?? []) {
      if (!message.ts) continue;
      if (slackTimestampValue(message.ts) <= slackTimestampValue(oldest)) {
        continue;
      }
      newestTs = laterSlackTimestamp(newestTs, message.ts);
      if (message.bot_id || !message.user) continue;
      if (!cfg.allowedUserIds!.includes(message.user)) continue;
      const text = (message.text ?? "").trim();
      const match = text.match(/^STEER\s+([^:]+):\s*([\s\S]+)$/i);
      if (!match?.[1] || !match[2]?.trim()) continue;
      if (match[1].trim() !== teamRunId) continue;
      if (looksLikeSecret(match[2])) continue;
      steers.push({
        id: `slack:${message.ts}:${message.user}`,
        text: match[2].trim(),
        source: "slack",
        at: Math.trunc(Number(message.ts) * 1000),
        ts: message.ts,
      });
    }
    cursor = json.response_metadata?.next_cursor?.trim() || undefined;
  } while (cursor);

  steers.sort((a, b) => {
    const left = slackTimestampValue(a.ts);
    const right = slackTimestampValue(b.ts);
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return {
    steers: steers.map(({ ts: _ts, ...steer }) => steer),
    newestTs,
  };
}

export function formatSteerFollowUp(steer: SteerMessage): string {
  return [
    "## Authenticated mid-run guidance",
    `Control id: ${steer.id}`,
    `Source: ${steer.source}`,
    "",
    steer.text,
    "",
    "Incorporate this guidance into the existing task.",
    "This guidance does not authorize crossing a named approval/spend/deploy gate.",
    "At every such gate, emit HITL_REQUIRED and wait for a matching authorization.",
  ].join("\n");
}
