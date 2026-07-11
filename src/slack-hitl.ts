/**
 * Slack HITL — env-only secrets. Never hardcode tokens.
 *
 * SLACK_BOT_TOKEN + SLACK_CHANNEL_ID: bidirectional Q&A / approvals
 * SLACK_WEBHOOK_URL: optional one-way alerts
 */

export type SlackConfig = {
  botToken?: string;
  channelId?: string;
  webhookUrl?: string;
};

export function loadSlackConfig(env: NodeJS.ProcessEnv = process.env): SlackConfig {
  return {
    botToken: env.SLACK_BOT_TOKEN?.trim() || undefined,
    channelId: env.SLACK_CHANNEL_ID?.trim() || undefined,
    webhookUrl: env.SLACK_WEBHOOK_URL?.trim() || undefined,
  };
}

export function slackHitlEnabled(cfg: SlackConfig): boolean {
  return Boolean(cfg.botToken && cfg.channelId);
}

async function slackApi(
  token: string,
  method: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const res = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(body),
  });
  const json = (await res.json()) as Record<string, unknown>;
  if (!json.ok) {
    throw new Error(`Slack ${method} failed: ${JSON.stringify(json)}`);
  }
  return json;
}

export async function postWebhookAlert(
  webhookUrl: string,
  text: string,
): Promise<void> {
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    throw new Error(`Slack webhook HTTP ${res.status}`);
  }
}

export type HitlThread = {
  channel: string;
  ts: string;
};

/** Post a HITL question; returns thread ts for polling replies. */
export async function postHitlQuestion(
  cfg: SlackConfig,
  opts: {
    jobId: string;
    question: string;
    allowedReplies?: string;
  },
): Promise<HitlThread> {
  if (!cfg.botToken || !cfg.channelId) {
    throw new Error("SLACK_BOT_TOKEN and SLACK_CHANNEL_ID required for HITL");
  }
  const allowed = opts.allowedReplies ?? "approve | deny | or free-text answer";
  const text = [
    `*coding-agent-team HITL* · job \`${opts.jobId}\``,
    opts.question,
    "",
    `_Reply in this thread:_ ${allowed}`,
  ].join("\n");

  const json = await slackApi(cfg.botToken, "chat.postMessage", {
    channel: cfg.channelId,
    text,
    unfurl_links: false,
  });
  const ts = String(json.ts);
  return { channel: cfg.channelId, ts };
}

export async function readThreadReplies(
  cfg: SlackConfig,
  thread: HitlThread,
): Promise<string[]> {
  if (!cfg.botToken) throw new Error("SLACK_BOT_TOKEN required");
  const json = await slackApi(cfg.botToken, "conversations.replies", {
    channel: thread.channel,
    ts: thread.ts,
    oldest: thread.ts,
  });
  const messages = (json.messages as Array<{ text?: string; bot_id?: string }>) ?? [];
  // Skip the root bot message; keep human (no bot_id) replies.
  return messages
    .slice(1)
    .filter((m) => !m.bot_id && m.text)
    .map((m) => String(m.text).trim());
}

/**
 * Post question and poll until a non-empty human reply or timeout.
 */
export async function askHitlAndWait(
  cfg: SlackConfig,
  opts: {
    jobId: string;
    question: string;
    allowedReplies?: string;
    timeoutMs?: number;
    pollMs?: number;
  },
): Promise<{ answer: string; thread: HitlThread }> {
  const timeoutMs = opts.timeoutMs ?? 30 * 60 * 1000;
  const pollMs = opts.pollMs ?? 5000;
  const thread = await postHitlQuestion(cfg, opts);
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollMs));
    const replies = await readThreadReplies(cfg, thread);
    const answer = replies[replies.length - 1];
    if (answer) return { answer, thread };
  }
  throw new Error(`HITL timeout after ${timeoutMs}ms for job ${opts.jobId}`);
}
