import assert from "node:assert/strict";
import { it } from "node:test";
import { askHitlAndWait, type SlackConfig } from "./slack-hitl.js";

it("ignores invalid allowlisted Slack replies and accepts a later valid one", async () => {
  const originalFetch = globalThis.fetch;
  let posts = 0;
  globalThis.fetch = (async (input: string | URL | Request) => {
    const url = String(input);
    if (url.endsWith("/chat.postMessage")) {
      posts++;
      return new Response(
        JSON.stringify({ ok: true, channel: "C123456789", ts: "100.1" }),
      );
    }
    if (url.endsWith("/conversations.replies")) {
      return new Response(
        JSON.stringify({
          ok: true,
          messages: [
            {
              ts: "100.2",
              user: "U123456789",
              text: "looks good",
            },
            {
              ts: "100.3",
              user: "U123456789",
              text: "approve",
            },
          ],
          response_metadata: { next_cursor: "" },
        }),
      );
    }
    throw new Error(`unexpected Slack URL: ${url}`);
  }) as typeof fetch;

  try {
    const config: SlackConfig = {
      botToken: "xoxb-test",
      channelId: "C123456789",
      allowedUserIds: ["U123456789"],
      steerEnabled: false,
    };
    const result = await askHitlAndWait(config, {
      jobId: "master-1",
      question: "Approve phase A?",
      pollMs: 1,
      timeoutMs: 1_000,
      validateReply: (text) => text === "approve",
    });
    assert.equal(result.reply.text, "approve");
    assert.equal(posts, 2, "question plus invalid-reply warning");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
