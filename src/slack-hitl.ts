/**
 * Slack notifications and allowlisted HITL replies.
 *
 * Secrets are env-only. Slack is never the only control path when a signed
 * controller is configured, and arbitrary channel members are not trusted.
 */

export type SlackConfig = {
  botToken?: string;
  channelId?: string;
  webhookUrl?: string;
  allowedUserIds: string[];
  steerEnabled: boolean;
};

const CHANNEL_ID_RE = /^[CGD][A-Z0-9]{8,}$/;
const USER_ID_RE = /^[UW][A-Z0-9]{8,}$/;
const SLACK_TIMEOUT_MS = 10_000;

export function loadSlackConfig(env: NodeJS.ProcessEnv = process.env): SlackConfig {
  const allowedUserIds = (env.SLACK_ALLOWED_USER_IDS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter((value) => USER_ID_RE.test(value));
  return {
    botToken: env.SLACK_BOT_TOKEN?.trim() || undefined,
    channelId: env.SLACK_CHANNEL_ID?.trim() || undefined,
    webhookUrl: env.SLACK_WEBHOOK_URL?.trim() || undefined,
    allowedUserIds,
    steerEnabled: /^(?:1|true|yes)$/i.test(
      env.SLACK_STEER_ENABLED?.trim() ?? "",
    ),
  };
}

export function slackPostingEnabled(cfg: SlackConfig): boolean {
  return Boolean(
    cfg.botToken &&
      cfg.channelId &&
      CHANNEL_ID_RE.test(cfg.channelId),
  );
}

export function slackHitlEnabled(cfg: SlackConfig): boolean {
  return slackPostingEnabled(cfg) && cfg.allowedUserIds.length > 0;
}

function assertSlackPostingConfig(
  cfg: SlackConfig,
): asserts cfg is SlackConfig & { botToken: string; channelId: string } {
  if (!cfg.botToken || !cfg.channelId) {
    throw new Error("SLACK_BOT_TOKEN and SLACK_CHANNEL_ID are required");
  }
  if (!CHANNEL_ID_RE.test(cfg.channelId)) {
    throw new Error(
      `SLACK_CHANNEL_ID must be an uppercase C…/G…/D… ID (got "${cfg.channelId}")`,
    );
  }
}

async function slackApi(
  token: string,
  method: string,
  body: Record<string, unknown>,
  encoding: "json" | "form" = "json",
  timeoutMs = SLACK_TIMEOUT_MS,
): Promise<Record<string, unknown>> {
  const headers: Record<string, string> = {
    Authorization: `Bearer ${token}`,
  };
  let payload: string;
  if (encoding === "form") {
    headers["Content-Type"] =
      "application/x-www-form-urlencoded; charset=utf-8";
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(body)) {
      if (value === undefined || value === null) continue;
      params.set(key, String(value));
    }
    payload = params.toString();
  } else {
    headers["Content-Type"] = "application/json; charset=utf-8";
    payload = JSON.stringify(body);
  }

  const response = await fetch(`https://slack.com/api/${method}`, {
    method: "POST",
    headers,
    body: payload,
    signal: AbortSignal.timeout(Math.max(1, timeoutMs)),
  });
  const json = (await response.json()) as Record<string, unknown>;
  if (!json.ok) {
    throw new Error(`Slack ${method} failed: ${JSON.stringify(json)}`);
  }
  return json;
}

export async function postWebhookAlert(
  webhookUrl: string,
  text: string,
): Promise<void> {
  const response = await fetch(webhookUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
    signal: AbortSignal.timeout(SLACK_TIMEOUT_MS),
  });
  if (!response.ok) {
    throw new Error(`Slack webhook HTTP ${response.status}`);
  }
}

export type HitlThread = {
  channel: string;
  ts: string;
};

export async function postSlackMessage(
  cfg: SlackConfig,
  text: string,
  threadTs?: string,
): Promise<HitlThread> {
  assertSlackPostingConfig(cfg);
  const json = await slackApi(cfg.botToken, "chat.postMessage", {
    channel: cfg.channelId,
    text,
    thread_ts: threadTs,
    unfurl_links: false,
  });
  const channel = String(json.channel ?? cfg.channelId);
  const ts = String(json.ts ?? "");
  if (!channel || !ts || ts === "undefined") {
    throw new Error(
      `Slack chat.postMessage returned no channel/ts: ${JSON.stringify(json)}`,
    );
  }
  return { channel, ts };
}

/** Post a HITL question; returns the exact thread to poll. */
export async function postHitlQuestion(
  cfg: SlackConfig,
  opts: {
    jobId: string;
    question: string;
    allowedReplies?: string;
  },
): Promise<HitlThread> {
  const allowed =
    opts.allowedReplies ?? "approve | deny | cancel | choice:<value>";
  const question =
    opts.question.length > 3500
      ? `${opts.question.slice(0, 3497)}...`
      : opts.question;
  return postSlackMessage(
    cfg,
    [
      `*coding-agent-team HITL* · job \`${opts.jobId}\``,
      question,
      "",
      `_Reply in this thread:_ ${allowed}`,
      "_Only configured allowlisted Slack users are accepted._",
    ].join("\n"),
  );
}

export type HitlReply = {
  text: string;
  user: string;
  ts: string;
};

export async function readThreadReplies(
  cfg: SlackConfig,
  thread: HitlThread,
  operationTimeoutMs = 30_000,
): Promise<HitlReply[]> {
  assertSlackPostingConfig(cfg);
  if (cfg.allowedUserIds.length === 0) {
    throw new Error("SLACK_ALLOWED_USER_IDS is required for Slack HITL replies");
  }
  if (!thread.channel || !thread.ts) {
    throw new Error(`Slack thread missing channel/ts: ${JSON.stringify(thread)}`);
  }

  const replies: HitlReply[] = [];
  let cursor: string | undefined;
  const seenCursors = new Set<string>();
  const deadline = Date.now() + Math.max(1, operationTimeoutMs);
  let pages = 0;
  do {
    if (++pages > 20 || Date.now() >= deadline) {
      throw new Error("Slack HITL pagination exceeded its bound");
    }
    if (cursor) {
      if (seenCursors.has(cursor)) {
        throw new Error("Slack HITL pagination cursor repeated");
      }
      seenCursors.add(cursor);
    }
    const json = await slackApi(
      cfg.botToken,
      "conversations.replies",
      {
        channel: thread.channel,
        ts: thread.ts,
        limit: 200,
        cursor,
      },
      "form",
      Math.min(SLACK_TIMEOUT_MS, deadline - Date.now()),
    );
    const messages =
      (json.messages as Array<{
        text?: string;
        ts?: string;
        user?: string;
        bot_id?: string;
      }>) ?? [];
    for (const message of messages) {
      if (
        !message.text ||
        !message.ts ||
        !message.user ||
        message.bot_id ||
        message.ts === thread.ts ||
        !cfg.allowedUserIds.includes(message.user)
      ) {
        continue;
      }
      replies.push({
        text: message.text.trim(),
        user: message.user,
        ts: message.ts,
      });
    }
    const metadata = json.response_metadata as
      | { next_cursor?: string }
      | undefined;
    cursor = metadata?.next_cursor?.trim() || undefined;
  } while (cursor);

  return replies.sort((a, b) => a.ts.localeCompare(b.ts));
}

export async function askHitlAndWait(
  cfg: SlackConfig,
  opts: {
    jobId: string;
    question: string;
    allowedReplies?: string;
    timeoutMs?: number;
    pollMs?: number;
    signal?: AbortSignal;
    validateReply?: (text: string) => boolean;
  },
): Promise<{ reply: HitlReply; thread: HitlThread }> {
  if (!slackHitlEnabled(cfg)) {
    throw new Error(
      "Slack HITL requires valid token/channel and SLACK_ALLOWED_USER_IDS",
    );
  }
  const timeoutMs = opts.timeoutMs ?? 30 * 60 * 1000;
  const pollMs = opts.pollMs ?? 5000;
  const thread = await postHitlQuestion(cfg, opts);
  const deadline = Date.now() + timeoutMs;
  const seen = new Set<string>();

  while (Date.now() < deadline) {
    if (opts.signal?.aborted) {
      throw new DOMException("Slack HITL aborted", "AbortError");
    }
    await abortableDelay(
      Math.min(pollMs, Math.max(1, deadline - Date.now())),
      opts.signal,
    );
    const replies = await readThreadReplies(
      cfg,
      thread,
      Math.min(30_000, Math.max(1, deadline - Date.now())),
    );
    for (const reply of replies) {
      if (seen.has(reply.ts)) continue;
      seen.add(reply.ts);
      if (!opts.validateReply || opts.validateReply(reply.text)) {
        return { reply, thread };
      }
      await postSlackMessage(
        cfg,
        "Invalid decision. Reply with the exact structured form shown above; do not include credentials.",
        thread.ts,
      );
    }
  }
  throw new Error(`HITL timeout after ${timeoutMs}ms for job ${opts.jobId}`);
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
