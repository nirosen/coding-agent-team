import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { it } from "node:test";
import { TeamStateStore } from "./state.js";

it("writes private atomic state and clears prior gate metadata", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "team-state-test-"));
  const stateDir = path.join(root, ".team-state");
  const state = new TeamStateStore(stateDir, "team-1", root);
  state.upsert({ jobId: "master-1", role: "master", status: "running" });
  state.markAwaitingHuman("master-1", "Approve phase A?");
  state.resolveHuman("master-1", {
    decision: "approve",
    source: "control",
    authorizationId: "auth-1",
  });
  state.markAwaitingHuman("master-1", "Approve phase B?");

  const snapshot = state.snapshot();
  const job = snapshot.jobs["master-1"];
  assert.equal(job?.hitlDecision, undefined);
  assert.equal(job?.hitlAuthorizationId, undefined);
  assert.deepEqual(
    job?.hitlHistory?.map((event) => ({
      question: event.question,
      decision: event.decision,
      authorizationId: event.authorizationId,
      resolved: event.resolvedAt !== undefined,
    })),
    [
      {
        question: "Approve phase A?",
        decision: "approve",
        authorizationId: "auth-1",
        resolved: true,
      },
      {
        question: "Approve phase B?",
        decision: undefined,
        authorizationId: undefined,
        resolved: false,
      },
    ],
  );
  assert.throws(
    () =>
      state.resolveHuman("missing", {
        decision: "approve",
        source: "tty",
      }),
    /no unresolved HITL gate/,
  );
  assert.equal(fs.statSync(stateDir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(state.filePath).mode & 0o777, 0o600);
  assert.equal(
    fs.readdirSync(stateDir).some((name) => name.endsWith(".tmp")),
    false,
  );
  assert.throws(
    () => new TeamStateStore(stateDir, "team-1", root),
    /refusing replay\/overwrite/,
  );
});
