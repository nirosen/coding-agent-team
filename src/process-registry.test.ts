import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  ProcessRegistry,
  parseLinuxProcStat,
  type ExecutionReceipt,
  type ProcessRecord,
} from "./process-registry.js";
import {
  COMMAND_MANIFEST_SCHEMA,
  validateCommandManifest,
} from "./manifests.js";
import { sha256 } from "./policy.js";

describe("supervised process identity", () => {
  it("parses Linux start ticks when the command name contains spaces and parentheses", () => {
    const stat =
      "123 (worker (phase a)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 987654 20";
    assert.equal(parseLinuxProcStat(stat), "987654");
  });

  it("rejects malformed process stat records", () => {
    assert.throws(() => parseLinuxProcStat("123 worker S 1"), /terminator/);
    assert.throws(() => parseLinuxProcStat("123 (worker) S 1 2"), /start time/);
  });

  it(
    "durably runs exact manifest commands and refuses active completion",
    { skip: process.platform !== "linux" },
    async () => {
      const workspace = fs.mkdtempSync(
        path.join(os.tmpdir(), "process-registry-"),
      );
      const stateDirectory = path.join(workspace, ".team-state");
      fs.writeFileSync(path.join(workspace, "README.md"), "fixture\n");
      execFileSync("git", ["init", "-q"], { cwd: workspace });
      execFileSync("git", ["add", "README.md"], { cwd: workspace });
      execFileSync(
        "git",
        [
          "-c",
          "user.name=Fixture",
          "-c",
          "user.email=fixture@example.invalid",
          "commit",
          "-qm",
          "fixture",
        ],
        { cwd: workspace },
      );
      const records: ProcessRecord[] = [];
      const receipts: ExecutionReceipt[] = [];
      const manifest = validateCommandManifest({
        schema: COMMAND_MANIFEST_SCHEMA,
        commands: [
          {
            id: "exit-seven",
            phase: "execution",
            kind: "test",
            argv: [process.execPath, "-e", "process.exit(7)"],
            cwd: ".",
            timeoutMs: 10_000,
            envAllowlist: [],
            executableSha256: sha256(fs.readFileSync(process.execPath)),
            expectedExitCodes: [7],
          },
          {
            id: "mutating-test",
            phase: "execution",
            kind: "test",
            argv: [
              process.execPath,
              "-e",
              "require('node:fs').writeFileSync('test-output.tmp','changed')",
            ],
            cwd: ".",
            timeoutMs: 10_000,
            envAllowlist: [],
            executableSha256: sha256(fs.readFileSync(process.execPath)),
            expectedExitCodes: [0],
          },
          {
            id: "escape-group",
            phase: "execution",
            kind: "command",
            argv: [
              process.execPath,
              "-e",
              "const cp=require('node:child_process'),key='det'+'ached',child=cp.spawn(process.execPath,['-e',`setTimeout(()=>require('node:fs').writeFileSync('escaped.marker','yes'),500)`],{stdio:'ignore',[key]:true});child.unref()",
            ],
            cwd: ".",
            timeoutMs: 10_000,
            envAllowlist: [],
            executableSha256: sha256(fs.readFileSync(process.execPath)),
            expectedExitCodes: [0],
          },
          {
            id: "wait",
            phase: "execution",
            kind: "command",
            argv: [process.execPath, "-e", "setInterval(()=>{},1000)"],
            cwd: ".",
            timeoutMs: 60_000,
            envAllowlist: [],
            executableSha256: sha256(fs.readFileSync(process.execPath)),
            expectedExitCodes: [0],
          },
        ],
      });
      const registry = new ProcessRegistry({
        workspace,
        teamRunId: "team-registry",
        stateDirectory,
        manifest,
        currentPhase: () => "execution",
        onProcess: (record) => records.push(record),
        onReceipt: (receipt) => receipts.push(receipt),
      });
      const completed = await registry.start("master-1", "exit-seven");
      const result = await registry.wait(completed.processId);
      assert.equal(result.exitCode, 7);
      assert.equal(result.status, "exited");
      assert.equal(receipts[0]?.status, "passed");
      assert.equal(
        JSON.stringify(records).includes("process.exit(7)"),
        false,
      );

      const mutating = await registry.start("master-1", "mutating-test");
      const mutatingResult = await registry.wait(mutating.processId);
      assert.equal(mutatingResult.status, "failed");
      assert.equal(receipts[1]?.status, "failed");
      fs.unlinkSync(path.join(workspace, "test-output.tmp"));

      const escaped = await registry.start("master-1", "escape-group");
      const escapedResult = await registry.wait(escaped.processId);
      assert.equal(escapedResult.status, "exited");
      assert.equal(receipts[2]?.status, "passed");
      await new Promise((resolve) => setTimeout(resolve, 750));
      assert.equal(
        fs.existsSync(path.join(workspace, "escaped.marker")),
        false,
      );
      registry.assertIdle();

      const active = await registry.start("master-1", "wait");
      assert.throws(() => registry.assertIdle(), /still active/);
      await registry.stop(active.processId);
      await registry.wait(active.processId);
      registry.assertIdle();
      await registry.shutdown();
    },
  );
});
