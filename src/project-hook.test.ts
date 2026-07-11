import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { installDenyShellProjectHook } from "./project-hook.js";

const root = path.resolve(import.meta.dirname, "..");

describe("hard-policy project hook", () => {
  it("denies built-in Shell and restores a newly created .cursor directory", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "hook-workspace-"));
    const state = path.join(workspace, ".team-state");
    const lease = installDenyShellProjectHook({
      workspace,
      stateDirectory: state,
      teamRunId: "team-hook-test",
    });
    lease.verify();
    const manifest = JSON.parse(fs.readFileSync(lease.hookPath, "utf8"));
    assert.equal(
      manifest.hooks.beforeShellExecution[0].failClosed,
      true,
    );
    assert.equal(manifest.hooks.preToolUse[0].failClosed, true);
    const output = execFileSync(
      process.execPath,
      [path.join(root, "scripts", "deny-shell-hook.mjs")],
      {
        input: JSON.stringify({
          hook_event_name: "beforeShellExecution",
          command: "nohup evaluator &",
        }),
        encoding: "utf8",
      },
    );
    assert.equal(JSON.parse(output).permission, "deny");
    const editOutput = execFileSync(
      process.execPath,
      [
        path.join(root, "scripts", "protect-policy-files.mjs"),
        workspace,
      ],
      {
        input: JSON.stringify({
          hook_event_name: "preToolUse",
          tool_name: "Write",
          tool_input: { path: path.join(workspace, ".cursor", "hooks.json") },
        }),
        encoding: "utf8",
      },
    );
    assert.equal(JSON.parse(editOutput).permission, "deny");
    const stateAlias = path.join(workspace, "control-alias");
    fs.symlinkSync(".team-state", stateAlias);
    const aliasOutput = execFileSync(
      process.execPath,
      [
        path.join(root, "scripts", "protect-policy-files.mjs"),
        workspace,
      ],
      {
        input: JSON.stringify({
          hook_event_name: "preToolUse",
          tool_name: "Write",
          tool_input: { path: path.join(stateAlias, "forged.json") },
        }),
        encoding: "utf8",
      },
    );
    assert.equal(JSON.parse(aliasOutput).permission, "deny");
    fs.unlinkSync(stateAlias);
    const mcpPath = path.join(workspace, ".cursor", "mcp.json");
    fs.writeFileSync(mcpPath, '{"mcpServers":{}}\n');
    assert.throws(() => lease.verify(), /MCP\/plugin settings/);
    fs.unlinkSync(mcpPath);
    lease.verify();
    lease.release();
    assert.equal(fs.existsSync(path.join(workspace, ".cursor")), false);
  });

  it("refuses existing hooks and does not overwrite a changed lease", () => {
    const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "hook-existing-"));
    const cursor = path.join(workspace, ".cursor");
    fs.mkdirSync(cursor);
    fs.writeFileSync(path.join(cursor, "hooks.json"), '{"version":1}\n');
    assert.throws(
      () =>
        installDenyShellProjectHook({
          workspace,
          stateDirectory: path.join(workspace, ".team-state"),
          teamRunId: "team-existing",
        }),
      /refuses an existing/,
    );

    fs.unlinkSync(path.join(cursor, "hooks.json"));
    const lease = installDenyShellProjectHook({
      workspace,
      stateDirectory: path.join(workspace, ".team-state"),
      teamRunId: "team-mutation",
    });
    fs.writeFileSync(lease.hookPath, '{"version":1,"hooks":{}}\n');
    assert.throws(() => lease.verify(), /changed/);
    assert.throws(() => lease.release(), /changed/);
    assert.equal(fs.existsSync(lease.hookPath), true);
  });
});
