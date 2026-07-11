import type { SlackConfig } from "./slack-hitl.js";
import {
  postSlackMessage,
  postWebhookAlert,
  slackPostingEnabled,
} from "./slack-hitl.js";
import type { TeamStateStore } from "./state.js";
import { redactSecrets } from "./control.js";

export type WatchdogOptions = {
  state: TeamStateStore;
  slack: SlackConfig;
  idleMs?: number;
  intervalMs?: number;
};

/**
 * Side loop: mark stale jobs and alert Slack. Does not replace hard
 * cancellation inside runJob; pairs with HITL for human unblocks.
 */
export function startWatchdog(opts: WatchdogOptions): () => void {
  const idleMs = opts.idleMs ?? 5 * 60 * 1000;
  const intervalMs = opts.intervalMs ?? 30_000;
  const alerted = new Set<string>();

  const timer = setInterval(() => {
    void tick(opts, idleMs, alerted);
  }, intervalMs);
  timer.unref?.();

  return () => clearInterval(timer);
}

async function tick(
  opts: WatchdogOptions,
  idleMs: number,
  alerted: Set<string>,
): Promise<void> {
  const stale = opts.state.listStale(idleMs);
  for (const job of stale) {
    const key = `${job.jobId}:${job.status}`;
    if (alerted.has(key)) continue;
    alerted.add(key);

    opts.state.upsert({
      jobId: job.jobId,
      role: job.role,
      status: job.status === "awaiting_human" ? "awaiting_human" : "stale",
      lastError: job.lastError ?? `idle > ${idleMs}ms`,
      lastEventAt: Date.now(),
    });

    const text = redactSecrets([
      `*watchdog*: job \`${job.jobId}\` looks ${job.status === "awaiting_human" ? "waiting on you" : "stale/idle"}`,
      `role=${job.role} model=${job.model ?? "?"} attempts=${(job.attempts ?? []).join("→") || "?"}`,
      job.hitlQuestion ? `HITL: ${job.hitlQuestion}` : "",
      job.lastError ? `error: ${job.lastError}` : "",
    ]
      .filter(Boolean)
      .join("\n"));

    try {
      if (slackPostingEnabled(opts.slack)) {
        // Alert only. Opening another HITL thread would compete with the
        // orchestrator's authoritative thread/control gate.
        await postSlackMessage(opts.slack, text);
      } else if (opts.slack.webhookUrl) {
        await postWebhookAlert(opts.slack.webhookUrl, text);
      } else {
        console.warn(`[watchdog] ${text}`);
      }
    } catch (err) {
      console.warn(
        `[watchdog] alert failed: ${err instanceof Error ? err.message : err}`,
      );
    }
  }
}
