#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  ACCOUNTING_CONFIG_SCHEMA,
  ACCOUNTING_EVENTS_SCHEMA,
  validateAccountingConfig,
} from "./accounting.js";
import {
  CONTROL_SCHEMA,
  acknowledgeControl,
  generateControllerKeyPair,
  questionSha256,
  scanControlSpool,
  signControlEnvelope,
  verifyControlEnvelope,
  writeControlEnvelope,
} from "./control.js";
import {
  COMMAND_MANIFEST_SCHEMA,
  TEST_MANIFEST_SCHEMA,
  validateCommandManifest,
  validateTestManifest,
} from "./manifests.js";
import {
  POLICY_PROFILE_SCHEMA,
  RUN_BINDING_SCHEMA,
  artifactSha256,
  canonicalJson,
  loadRunBundle,
  sha256,
  signRunBinding,
  type PolicyProfile,
} from "./policy.js";
import {
  PolicyRuntime,
  readinessSealSha256,
  verifyReadinessSeal,
} from "./policy-runtime.js";
import { ProcessRegistry } from "./process-registry.js";
import { installDenyShellProjectHook } from "./project-hook.js";
import { TeamStateStore } from "./state.js";
import { requireGitHead } from "./workspace.js";

function writeJson(filePath: string, value: unknown): void {
  fs.writeFileSync(filePath, `${canonicalJson(value)}\n`, { mode: 0o600 });
}

function initializeGitWorkspace(workspace: string): string {
  fs.writeFileSync(
    path.join(workspace, ".gitignore"),
    ".team-state/\n.cursor/\n",
  );
  execFileSync("git", ["init", "-q"], { cwd: workspace });
  execFileSync("git", ["add", "."], { cwd: workspace });
  execFileSync(
    "git",
    [
      "-c",
      "user.name=No Spend Stage",
      "-c",
      "user.email=no-spend@example.invalid",
      "commit",
      "-qm",
      "fixture",
    ],
    { cwd: workspace },
  );
  return requireGitHead(workspace);
}

async function exerciseCancellation(root: string): Promise<void> {
  const workspace = fs.realpathSync(
    fs.mkdtempSync(path.join(root, "cancel-workspace-")),
  );
  initializeGitWorkspace(workspace);
  const manifest = validateCommandManifest({
    schema: COMMAND_MANIFEST_SCHEMA,
    commands: [
      {
        id: "long-running",
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
    teamRunId: "team-no-spend-cancel",
    stateDirectory: path.join(workspace, ".team-state"),
    manifest,
    currentPhase: () => "execution",
    onProcess: () => undefined,
    onReceipt: () => undefined,
  });
  const record = await registry.start("stage-cancel", "long-running");
  let activeRefused = false;
  try {
    registry.assertIdle();
  } catch {
    activeRefused = true;
  }
  if (!activeRefused) throw new Error("active process did not block completion");
  await registry.stop(record.processId);
  await registry.wait(record.processId);
  registry.assertIdle();
  await registry.shutdown();
}

async function stage(): Promise<void> {
  if (process.platform !== "linux") {
    throw new Error("no-spend supervision staging requires Linux");
  }
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "team-no-spend-stage-"));
  await exerciseCancellation(root);

  const workspace = fs.realpathSync(
    fs.mkdtempSync(path.join(root, "sealed-workspace-")),
  );
  const bundleDirectory = path.join(root, "bundle");
  fs.mkdirSync(bundleDirectory, { mode: 0o700 });
  const ledger = path.join(workspace, "ledger.jsonl");
  fs.writeFileSync(ledger, "", { mode: 0o600 });
  const adapter = path.join(workspace, "accounting-adapter.mjs");
  fs.writeFileSync(
    adapter,
    [
      "#!/usr/bin/env node",
      `console.log(${JSON.stringify(
        JSON.stringify({
          schema: ACCOUNTING_EVENTS_SCHEMA,
          watermarks: { fixture: "0" },
          events: [],
        }),
      )});`,
      "",
    ].join("\n"),
    { mode: 0o700 },
  );
  const executableSha256 = sha256(fs.readFileSync(process.execPath));
  const testConfigPath = path.join(workspace, "test-selection.json");
  fs.writeFileSync(
    testConfigPath,
    `${canonicalJson({ tests: ["no-provider-fixture"] })}\n`,
    { mode: 0o600 },
  );
  const gitHead = initializeGitWorkspace(workspace);
  const profile: PolicyProfile = {
    schema: POLICY_PROFILE_SCHEMA,
    profileId: "no-spend-mec-stage",
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
        id: "fixture-tests",
        phase: "verification",
        kind: "test",
        argv: [process.execPath, "-e", "process.exit(0)"],
        cwd: ".",
        timeoutMs: 10_000,
        envAllowlist: [],
        executableSha256,
        expectedExitCodes: [0],
      },
      {
        id: "fixture-review",
        phase: "verification",
        kind: "review",
        argv: [process.execPath, "-e", "process.exit(0)"],
        cwd: ".",
        timeoutMs: 10_000,
        envAllowlist: [],
        executableSha256,
        expectedExitCodes: [0],
      },
    ],
  });
  const tests = validateTestManifest(
    {
      schema: TEST_MANIFEST_SCHEMA,
      selections: [
        {
          id: "fixture-selection",
          phase: "verification",
          commandId: "fixture-tests",
          tests: ["no-provider-fixture"],
          configPath: "test-selection.json",
          configSha256: sha256(fs.readFileSync(testConfigPath)),
        },
      ],
    },
    commands,
  );
  const accounting = validateAccountingConfig({
    schema: ACCOUNTING_CONFIG_SCHEMA,
    adapter: {
      argv: [adapter],
      cwd: ".",
      executableSha256: sha256(fs.readFileSync(adapter)),
      envAllowlist: [],
      timeoutMs: 10_000,
    },
    sources: [{ slot: "fixture-ledger", path: "ledger.jsonl" }],
    limits: { usd_micros: "0", external_calls: "0" },
  });
  const task = Buffer.from("Execute the no-spend staging bundle.\n", "utf8");
  const keys = generateControllerKeyPair();
  const now = Date.now();
  const binding = signRunBinding(
    {
      schema: RUN_BINDING_SCHEMA,
      teamRunId: `team-no-spend-${now}`,
      createdAt: now,
      expiresAt: now + 60 * 60 * 1000,
      issuer: "no-spend-stage",
      taskSha256: sha256(task),
      profileSha256: artifactSha256(profile),
      commandManifestSha256: artifactSha256(commands),
      testManifestSha256: artifactSha256(tests),
      accountingConfigSha256: artifactSha256(accounting),
      workspace: { cwd: workspace, gitHead },
    },
    keys.privateKeyPem,
  );
  fs.writeFileSync(path.join(bundleDirectory, "task.md"), task);
  writeJson(path.join(bundleDirectory, "profile.json"), profile);
  writeJson(path.join(bundleDirectory, "commands.json"), commands);
  writeJson(path.join(bundleDirectory, "tests.json"), tests);
  writeJson(path.join(bundleDirectory, "accounting.json"), accounting);
  writeJson(path.join(bundleDirectory, "binding.json"), binding);

  const loaded = loadRunBundle(bundleDirectory, {
    publicKeyPem: keys.publicKeyPem,
    expectedCwd: workspace,
    expectedGitHead: gitHead,
  });
  const stateDirectory = path.join(workspace, ".team-state");
  const state = new TeamStateStore(
    stateDirectory,
    binding.teamRunId,
    workspace,
  );
  const runtime = new PolicyRuntime({
    bundle: loaded,
    state,
    stateDirectory,
    workspace,
  });
  const hook = installDenyShellProjectHook({
    workspace,
    stateDirectory,
    teamRunId: binding.teamRunId,
  });
  const hookOutput = execFileSync(
    process.execPath,
    [path.resolve(import.meta.dirname, "..", "scripts", "deny-shell-hook.mjs")],
    {
      input: JSON.stringify({
        hook_event_name: "beforeShellExecution",
        command: "nohup forbidden &",
      }),
      encoding: "utf8",
    },
  );
  if (JSON.parse(hookOutput).permission !== "deny") {
    throw new Error("hard-policy shell hook did not deny Shell");
  }
  const registry = new ProcessRegistry({
    workspace,
    teamRunId: binding.teamRunId,
    stateDirectory,
    manifest: runtime.commands,
    currentPhase: () => runtime.currentPhase(),
    beforeStart: () => runtime.assertExecutionOpen(),
    onProcess: (record) => state.recordProcess(record),
    onReceipt: (receipt) => state.recordReceipt(receipt),
  });
  runtime.attachRegistry(registry);
  state.setRunStatus("running");
  let unknownRejected = false;
  try {
    await registry.start("stage-master", "not-in-manifest");
  } catch {
    unknownRejected = true;
  }
  if (!unknownRejected) throw new Error("unlisted command was not rejected");
  for (const commandId of ["fixture-tests", "fixture-review"]) {
    const record = await registry.start("stage-master", commandId);
    const result = await registry.wait(record.processId);
    if (result.status !== "exited") {
      throw new Error(`fixture command failed: ${commandId}`);
    }
  }
  const gate = runtime.requestTransition("terminal");
  const authorization = signControlEnvelope(
    {
      schema: CONTROL_SCHEMA,
      id: "auth-no-spend-terminal",
      kind: "authorization",
      createdAt: Date.now(),
      expiresAt: Date.now() + 60_000,
      issuer: "no-spend-stage",
      teamRunId: binding.teamRunId,
      jobId: "stage-master",
      questionSha256: questionSha256(gate.question),
      decision: "approve",
    },
    keys.privateKeyPem,
  );
  if (!verifyControlEnvelope(authorization, keys.publicKeyPem)) {
    throw new Error("staging authorization signature is invalid");
  }
  const controlRoot = path.join(root, "control");
  const controlDirectory = path.join(controlRoot, binding.teamRunId);
  writeControlEnvelope(controlDirectory, authorization);
  const pending = scanControlSpool(controlDirectory, {
    publicKeyPem: keys.publicKeyPem,
    teamRunId: binding.teamRunId,
  });
  if (pending.length !== 1) {
    throw new Error("staging authorization did not enter the control spool");
  }
  acknowledgeControl(controlDirectory, pending[0]!);
  runtime.authorizePending({
    decision: "approve",
    authorizationId: authorization.id,
    controlEnvelope: authorization,
  });
  runtime.assertReady();
  const sealPath = state.snapshot().policy?.readinessSeal?.path;
  if (!sealPath) throw new Error("staging readiness seal is missing");
  const seal = verifyReadinessSeal(
    JSON.parse(fs.readFileSync(sealPath, "utf8")),
  );
  hook.verify();
  hook.release();
  await registry.shutdown();
  const fakeBin = path.join(root, "bin");
  fs.mkdirSync(fakeBin);
  fs.writeFileSync(
    path.join(fakeBin, "ssh"),
    [
      "#!/bin/sh",
      'while [ "$1" = "-o" ]; do shift 2; done',
      "shift",
      'exec /bin/sh -c "$1"',
      "",
    ].join("\n"),
    { mode: 0o755 },
  );
  fs.writeFileSync(
    path.join(fakeBin, "tmux"),
    "#!/bin/sh\nexit 1\n",
    { mode: 0o755 },
  );
  const controllerHome = path.join(root, "controller-home");
  const controllerKeyDirectory = path.join(
    controllerHome,
    ".coding-agent-team",
  );
  fs.mkdirSync(controllerKeyDirectory, { recursive: true, mode: 0o700 });
  const privateKeyPath = path.join(controllerKeyDirectory, "controller.key");
  const publicKeyPath = path.join(controllerKeyDirectory, "controller.pub");
  fs.writeFileSync(privateKeyPath, keys.privateKeyPem, { mode: 0o600 });
  fs.writeFileSync(publicKeyPath, keys.publicKeyPem, { mode: 0o600 });
  const configPath = path.join(root, "controller.json");
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      worker_host: "local-stage",
      team_cwd: workspace,
      harness_dir: path.resolve(import.meta.dirname, ".."),
      worker_tmux_session: "no-spend-stage",
      worker_control_root: controlRoot,
      worker_public_key_path: publicKeyPath,
      private_key_path: privateKeyPath,
      public_key_path: publicKeyPath,
      minimum_free_gb: 0,
      require_docker: false,
      require_policy_bundle: true,
    }),
    { mode: 0o600 },
  );
  const verifyOutput = execFileSync(
    path.resolve(
      import.meta.dirname,
      "..",
      "node_modules",
      ".bin",
      "tsx",
    ),
    [
      path.resolve(import.meta.dirname, "teamctl.ts"),
      "--config",
      configPath,
      "verify",
    ],
    {
      encoding: "utf8",
      env: {
        ...process.env,
        HOME: controllerHome,
        PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
      },
    },
  );
  const verified = JSON.parse(verifyOutput) as {
    verified?: boolean;
    sealSha256?: string;
  };
  if (
    verified.verified !== true ||
    verified.sealSha256 !== readinessSealSha256(seal)
  ) {
    throw new Error("teamctl did not verify the staging readiness seal");
  }
  process.stdout.write(
    `${JSON.stringify(
      {
        staged: true,
        teamRunId: binding.teamRunId,
        sealSha256: readinessSealSha256(seal),
        modelCalls: 0,
        providerCalls: 0,
      },
      null,
      2,
    )}\n`,
  );
}

stage().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
