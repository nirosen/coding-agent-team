import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import {
  ACCOUNTING_CONFIG_SCHEMA,
  ACCOUNTING_EVENTS_SCHEMA,
} from "./accounting.js";
import {
  CONTROL_SCHEMA,
  generateControllerKeyPair,
  questionSha256,
  signControlEnvelope,
} from "./control.js";
import {
  COMMAND_MANIFEST_SCHEMA,
  TEST_MANIFEST_SCHEMA,
  commandDigest,
  validateCommandManifest,
  validateTestManifest,
} from "./manifests.js";
import {
  POLICY_PROFILE_SCHEMA,
  RUN_BINDING_SCHEMA,
  artifactSha256,
  canonicalJson,
  sha256,
  signRunBinding,
  type LoadedRunBundle,
  type PolicyProfile,
} from "./policy.js";
import {
  PolicyRuntime,
  verifyReadinessSeal,
} from "./policy-runtime.js";
import type { ProcessRegistry } from "./process-registry.js";
import { TeamStateStore } from "./state.js";
import { requireGitHead, workspaceSnapshotSha256 } from "./workspace.js";

describe("policy phase gates and readiness", () => {
  it("seals only an evidence-stable, signed, terminal transition", () => {
    const workspace = fs.realpathSync(
      fs.mkdtempSync(path.join(os.tmpdir(), "policy-runtime-")),
    );
    const stateDirectory = path.join(workspace, ".team-state");
    const ledger = path.join(workspace, "ledger.jsonl");
    fs.writeFileSync(ledger, "");
    const adapter = path.join(workspace, "adapter.mjs");
    fs.writeFileSync(
      adapter,
      [
        "#!/usr/bin/env node",
        `console.log(${JSON.stringify(
          JSON.stringify({
            schema: ACCOUNTING_EVENTS_SCHEMA,
            watermarks: { provider: "0" },
            events: [],
          }),
        )});`,
        "",
      ].join("\n"),
      { mode: 0o700 },
    );
    fs.writeFileSync(
      path.join(workspace, ".gitignore"),
      ".team-state/\n.cursor/\nignored-input\n",
    );
    execFileSync("git", ["init", "-q"], { cwd: workspace });
    execFileSync("git", ["add", "."], { cwd: workspace });
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
    const ignoredInput = path.join(workspace, "ignored-input");
    fs.writeFileSync(ignoredInput, "original\n");
    const gitHead = requireGitHead(workspace);
    const profile: PolicyProfile = {
      schema: POLICY_PROFILE_SCHEMA,
      profileId: "no-spend",
      profileVersion: "1",
      enforcement: "hard",
      phases: ["verification", "terminal"],
      terminalPhase: "terminal",
      transitions: [
        {
          from: "verification",
          to: "terminal",
          requires: [
            "commands",
            "tests",
            "receipts",
            "review",
            "accounting",
            "authorization",
            "idle",
          ],
        },
      ],
    };
    const commands = validateCommandManifest({
      schema: COMMAND_MANIFEST_SCHEMA,
      commands: [
        {
          id: "tests",
          phase: "verification",
          kind: "test",
          argv: [process.execPath, "-e", "process.exit(0)"],
          cwd: ".",
          timeoutMs: 10_000,
          envAllowlist: [],
          executableSha256: sha256(fs.readFileSync(process.execPath)),
          expectedExitCodes: [0],
        },
        {
          id: "review",
          phase: "verification",
          kind: "review",
          argv: [process.execPath, "-e", "process.exit(0)"],
          cwd: ".",
          timeoutMs: 10_000,
          envAllowlist: [],
          executableSha256: sha256(fs.readFileSync(process.execPath)),
          expectedExitCodes: [0],
        },
      ],
    });
    const tests = validateTestManifest(
      {
        schema: TEST_MANIFEST_SCHEMA,
        selections: [
          {
            id: "unit-tests",
            phase: "verification",
            commandId: "tests",
            tests: ["src/*.test.ts"],
            configPath: null,
            configSha256: null,
          },
        ],
      },
      commands,
    );
    const accounting = {
      schema: ACCOUNTING_CONFIG_SCHEMA,
      adapter: {
        argv: [adapter],
        cwd: ".",
        executableSha256: sha256(fs.readFileSync(adapter)),
        envAllowlist: [],
        timeoutMs: 10_000,
      },
      sources: [{ slot: "ledger", path: "ledger.jsonl" }],
      limits: { usd_micros: "0", external_calls: "0" },
    };
    const keys = generateControllerKeyPair();
    const now = Date.now();
    const binding = signRunBinding(
      {
        schema: RUN_BINDING_SCHEMA,
        teamRunId: "team-runtime",
        createdAt: now,
        expiresAt: now + 60_000,
        issuer: "controller",
        taskSha256: sha256("task"),
        profileSha256: artifactSha256(profile),
        commandManifestSha256: artifactSha256(commands),
        testManifestSha256: artifactSha256(tests),
        accountingConfigSha256: artifactSha256(accounting),
        workspace: { cwd: workspace, gitHead },
      },
      keys.privateKeyPem,
    );
    const bundle: LoadedRunBundle = {
      directory: workspace,
      task: "task",
      taskBytes: Buffer.from("task"),
      profile,
      commandManifest: commands,
      testManifest: tests,
      accountingConfig: accounting,
      binding,
      canonical: {
        profile: canonicalJson(profile),
        commandManifest: canonicalJson(commands),
        testManifest: canonicalJson(tests),
        accountingConfig: canonicalJson(accounting),
      },
    };
    const state = new TeamStateStore(
      stateDirectory,
      binding.teamRunId,
      workspace,
    );
    const runtime = new PolicyRuntime({
      bundle,
      state,
      stateDirectory,
      workspace,
    });
    runtime.attachRegistry({
      assertIdle: () => undefined,
    } as unknown as ProcessRegistry);
    for (const command of commands.commands) {
      state.recordReceipt({
        schema: "coding-agent-team-execution-receipt/v1",
        receiptId: `receipt-stale-${command.id}`,
        processId: `process-stale-${command.id}`,
        ownerJobId: "master-1",
        commandId: command.id,
        commandSha256: commandDigest(command),
        startedWorkspaceSha256: "0".repeat(64),
        workspaceSha256: "0".repeat(64),
        phase: command.phase,
        kind: command.kind,
        startedAt: now - 2,
        endedAt: now - 1,
        exitCode: 1,
        signal: null,
        expectedExit: false,
        status: "failed",
      });
      state.recordReceipt({
        schema: "coding-agent-team-execution-receipt/v1",
        receiptId: `receipt-${command.id}`,
        processId: `process-${command.id}`,
        ownerJobId: "master-1",
        commandId: command.id,
        commandSha256: commandDigest(command),
        startedWorkspaceSha256: workspaceSnapshotSha256(workspace),
        workspaceSha256: workspaceSnapshotSha256(workspace),
        phase: command.phase,
        kind: command.kind,
        startedAt: now,
        endedAt: now + 1,
        exitCode: 0,
        signal: null,
        expectedExit: true,
        status: "passed",
      });
    }
    const gate = runtime.requestTransition("terminal");
    assert.equal(runtime.pendingQuestion(), gate.question);
    const authorization = signControlEnvelope(
      {
        schema: CONTROL_SCHEMA,
        id: "auth-terminal",
        kind: "authorization",
        createdAt: now,
        expiresAt: now + 60_000,
        issuer: "controller",
        teamRunId: binding.teamRunId,
        jobId: "master-1",
        questionSha256: questionSha256(gate.question),
        decision: "approve",
      },
      keys.privateKeyPem,
    );
    fs.writeFileSync(ignoredInput, "changed while awaiting authorization\n");
    assert.throws(
      () =>
        runtime.authorizePending({
          decision: "approve",
          authorizationId: authorization.id,
          controlEnvelope: authorization,
        }),
      /evidence changed|workspace changed/,
    );
    fs.writeFileSync(ignoredInput, "original\n");
    runtime.authorizePending({
      decision: "approve",
      authorizationId: authorization.id,
      controlEnvelope: authorization,
    });
    runtime.assertReady();
    const snapshot = state.snapshot();
    assert.equal(snapshot.runStatus, "ready");
    assert.equal(snapshot.policy?.currentPhase, "terminal");
    const sealPath = snapshot.policy?.readinessSeal?.path;
    assert.ok(sealPath);
    const seal = verifyReadinessSeal(
      JSON.parse(fs.readFileSync(sealPath, "utf8")),
    );
    assert.equal(seal.finalAuthorizationId, authorization.id);
  });
});
