import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  acknowledgeControl,
  authorizationMatches,
  CONTROL_SCHEMA,
  generateControllerKeyPair,
  questionSha256,
  redactSecrets,
  scanControlSpool,
  signControlEnvelope,
  type UnsignedControlEnvelope,
  writeControlEnvelope,
} from "./control.js";

function tempControlDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "team-control-test-"));
}

function unsignedSteer(
  now = Date.now(),
  teamRunId = "team-1",
): UnsignedControlEnvelope {
  return {
    schema: CONTROL_SCHEMA,
    id: "steer-1",
    kind: "steer",
    createdAt: now,
    expiresAt: now + 60_000,
    issuer: "controller",
    teamRunId,
    text: "freeze manifests before calls",
  };
}

describe("signed control spool", () => {
  it("keeps valid messages pending until acknowledged", () => {
    const controlDir = tempControlDir();
    const keys = generateControllerKeyPair();
    const signed = signControlEnvelope(unsignedSteer(), keys.privateKeyPem);
    writeControlEnvelope(controlDir, signed);

    const first = scanControlSpool(controlDir, {
      publicKeyPem: keys.publicKeyPem,
      teamRunId: "team-1",
    });
    assert.equal(first.length, 1);
    assert.deepEqual(first[0]!.envelope, signed);
    assert.equal(fs.readdirSync(path.join(controlDir, "processed")).length, 0);

    // A crash/restart before ack sees the same durable message.
    const replay = scanControlSpool(controlDir, {
      publicKeyPem: keys.publicKeyPem,
      teamRunId: "team-1",
    });
    assert.equal(replay.length, 1);

    acknowledgeControl(controlDir, first[0]!);
    assert.equal(
      fs.readdirSync(path.join(controlDir, "processed")).length,
      1,
    );
    fs.copyFileSync(
      path.join(controlDir, "processed", first[0]!.fileName),
      path.join(controlDir, "inbox", first[0]!.fileName),
    );
    assert.deepEqual(
      scanControlSpool(controlDir, {
        publicKeyPem: keys.publicKeyPem,
        teamRunId: "team-1",
      }),
      [],
    );
    assert.equal(fs.readdirSync(path.join(controlDir, "rejected")).length, 1);
  });

  it("rejects tampered and wrong-run envelopes", () => {
    const controlDir = tempControlDir();
    const keys = generateControllerKeyPair();
    const signed = signControlEnvelope(unsignedSteer(), keys.privateKeyPem);
    writeControlEnvelope(controlDir, { ...signed, text: "tampered" });
    const other = signControlEnvelope(
      unsignedSteer(Date.now() + 1, "team-other"),
      keys.privateKeyPem,
    );
    writeControlEnvelope(controlDir, other);

    assert.deepEqual(
      scanControlSpool(controlDir, {
        publicKeyPem: keys.publicKeyPem,
        teamRunId: "team-1",
      }),
      [],
    );
    assert.equal(fs.readdirSync(path.join(controlDir, "rejected")).length, 2);
  });

  it("rejects symlink messages without reading their target", () => {
    const controlDir = tempControlDir();
    const keys = generateControllerKeyPair();
    const inbox = path.join(controlDir, "inbox");
    fs.mkdirSync(inbox, { recursive: true });
    const secret = path.join(controlDir, "secret.txt");
    fs.writeFileSync(secret, "do-not-read");
    fs.symlinkSync(secret, path.join(inbox, "malicious.json"));

    assert.deepEqual(
      scanControlSpool(controlDir, {
        publicKeyPem: keys.publicKeyPem,
        teamRunId: "team-1",
      }),
      [],
    );
    assert.equal(fs.readFileSync(secret, "utf8"), "do-not-read");
    assert.equal(fs.readdirSync(path.join(controlDir, "rejected")).length, 1);
  });

  it("rejects credentials in control payloads", () => {
    const keys = generateControllerKeyPair();
    assert.throws(
      () =>
        signControlEnvelope(
          {
            ...unsignedSteer(),
            text: "use token xoxb-123456789",
          },
          keys.privateKeyPem,
        ),
      /secret-shaped/,
    );
    assert.equal(
      redactSecrets("token=xoxb-123456789"),
      "[REDACTED_CREDENTIAL]",
    );
    for (const credential of [
      "ghp_123456789012345678901234567890123456",
      "AKIA1234567890ABCDEF",
      "nvapi-123456789012345678901234",
    ]) {
      assert.equal(redactSecrets(credential), "[REDACTED_TOKEN]");
    }
  });
});

describe("authorization binding", () => {
  it("matches only exact run, job, question, and TTL", () => {
    const now = Date.now();
    const question = "Approve Phase B after reviewing Phase A evidence?";
    const keys = generateControllerKeyPair();
    const signed = signControlEnvelope(
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
        value: "phase-b",
      },
      keys.privateKeyPem,
    );
    const query = { teamRunId: "team-1", jobId: "master-1", question };
    assert.equal(authorizationMatches(signed, query, now + 1), true);
    assert.equal(
      authorizationMatches(signed, { ...query, teamRunId: "team-2" }, now + 1),
      false,
    );
    assert.equal(
      authorizationMatches(
        signed,
        { ...query, question: `${question} changed` },
        now + 1,
      ),
      false,
    );
    assert.equal(authorizationMatches(signed, query, now + 60_000), false);
  });
});
