import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { it } from "node:test";
import { acquireTeamLock } from "./lock.js";

it("permits one writer and releases only its own lock", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "team-lock-test-"));
  const first = acquireTeamLock(dir, "team-1");
  assert.throws(
    () => acquireTeamLock(dir, "team-2"),
    /another team writer is active/,
  );
  first.release();
  const second = acquireTeamLock(dir, "team-2");
  assert.equal(second.record.teamRunId, "team-2");
  second.release();
});
