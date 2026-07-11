import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  CONTROL_SCHEMA,
  generateControllerKeyPair,
  questionSha256,
  signControlEnvelope,
  writeControlEnvelope,
} from "./control.js";
import {
  formatSteerFollowUp,
  pollSlackSteers,
  SteerHub,
} from "./steer.js";
import type { SlackConfig } from "./slack-hitl.js";

describe("SteerHub signed spool", () => {
  it("queues, preserves, and acknowledges signed steers", async () => {
    const controlDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "steer-hub-test-"),
    );
    const keys = generateControllerKeyPair();
    const now = Date.now();
    writeControlEnvelope(
      controlDir,
      signControlEnvelope(
        {
          schema: CONTROL_SCHEMA,
          id: "steer-1",
          kind: "steer",
          createdAt: now,
          expiresAt: now + 60_000,
          issuer: "controller",
          teamRunId: "team-1",
          text: "freeze accounting",
        },
        keys.privateKeyPem,
      ),
    );
    const hub = new SteerHub({
      controlDir,
      publicKeyPem: keys.publicKeyPem,
      teamRunId: "team-1",
    });
    await hub.poll();
    const firstAttempt = hub.take();
    assert.equal(firstAttempt?.text, "freeze accounting");
    assert.equal(
      fs.readdirSync(path.join(controlDir, "inbox")).length,
      1,
    );
    hub.releaseSteer(firstAttempt!);
    await hub.poll();
    const steer = hub.take();
    assert.equal(steer?.id, "steer-1");
    hub.acknowledgeSteer(steer!);
    assert.equal(
      fs.readdirSync(path.join(controlDir, "inbox")).length,
      0,
    );
    assert.equal(
      fs.readdirSync(path.join(controlDir, "processed")).length,
      1,
    );
  });

  it("binds authorizations to the exact question", async () => {
    const controlDir = fs.mkdtempSync(
      path.join(os.tmpdir(), "steer-auth-test-"),
    );
    const keys = generateControllerKeyPair();
    const question = "Approve phase A?";
    const now = Date.now();
    writeControlEnvelope(
      controlDir,
      signControlEnvelope(
        {
          schema: CONTROL_SCHEMA,
          id: "auth-1",
          kind: "authorization",
          createdAt: now,
          expiresAt: now + 60_000,
          issuer: "controller",
          teamRunId: "team-1",
          jobId: "master-1",
          questionSha256: questionSha256(question),
          decision: "approve",
          value: "phase-a",
        },
        keys.privateKeyPem,
      ),
    );
    const hub = new SteerHub({
      controlDir,
      publicKeyPem: keys.publicKeyPem,
      teamRunId: "team-1",
    });
    await hub.poll();
    assert.equal(
      hub.takeAuthorization({
        teamRunId: "team-1",
        jobId: "master-1",
        question: "different",
      }),
      undefined,
    );
    const authorization = hub.takeAuthorization({
      teamRunId: "team-1",
      jobId: "master-1",
      question,
    });
    assert.equal(authorization?.answer, "approve:phase-a");
    hub.acknowledgeAuthorization(authorization!);
  });
});

describe("Slack steer polling", () => {
  it("paginates, allowlists users, and requires an exact run target", async () => {
    const originalFetch = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: string | URL | Request) => {
      const url = String(input);
      calls.push(url);
      const secondPage = url.includes("cursor=next-page");
      return new Response(
        JSON.stringify(
          secondPage
            ? {
                ok: true,
                messages: [
                  {
                    ts: "1783740001.000001",
                    user: "U123456789",
                    text: "STEER team-1: accepted guidance",
                  },
                  {
                    ts: "1783740000.900000",
                    user: "U000000000",
                    text: "STEER team-1: wrong user",
                  },
                  {
                    ts: "1783740000.800000",
                    user: "U123456789",
                    text: "STEER team-1: use token xoxb-123456789",
                  },
                ],
                response_metadata: { next_cursor: "" },
              }
            : {
                ok: true,
                messages: [
                  {
                    ts: "1783740002.000001",
                    user: "U123456789",
                    text: "STEER team-other: wrong run",
                  },
                ],
                response_metadata: { next_cursor: "next-page" },
              },
        ),
        { headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    try {
      const config: SlackConfig = {
        botToken: "xoxb-test",
        channelId: "C123456789",
        allowedUserIds: ["U123456789"],
        steerEnabled: true,
      };
      const result = await pollSlackSteers(
        config,
        "team-1",
        "1783740000.000000",
      );
      assert.equal(calls.length, 2);
      assert.deepEqual(
        result.steers.map((steer) => steer.text),
        ["accepted guidance"],
      );
      assert.equal(result.newestTs, "1783740002.000001");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

it("steer follow-up explicitly preserves named authorization gates", () => {
  const prompt = formatSteerFollowUp({
    id: "steer-1",
    text: "focus on accounting",
    source: "control",
    at: Date.now(),
  });
  assert.match(prompt, /does not authorize crossing a named/i);
  assert.doesNotMatch(prompt, /do not re-ask for confirmation/i);
});
