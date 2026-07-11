#!/usr/bin/env node
/**
 * Local multi-model coding agent team (Cursor SDK).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { assertChainsEndOnGrok } from "./models.js";
import { runFanOutScouts } from "./fan-out.js";
import { runOrchestrator } from "./orchestrator.js";
import { runParallelExec } from "./parallel-exec.js";
import {
  loadSlackConfig,
  slackHitlEnabled,
  slackPostingEnabled,
} from "./slack-hitl.js";
import { TeamStateStore } from "./state.js";
import { startWatchdog } from "./watchdog.js";
import { SteerHub } from "./steer.js";
import {
  defaultControlDir,
  publicKeyFingerprint,
  writeControlCapability,
} from "./control.js";
import { acquireTeamLock } from "./lock.js";
import { runHostPreflight } from "./preflight.js";
import { loadRunBundle, type LoadedRunBundle } from "./policy.js";
import { PolicyRuntime } from "./policy-runtime.js";
import {
  ProcessRegistry,
  assertNoLiveManagedProcesses,
} from "./process-registry.js";
import {
  installDenyShellProjectHook,
  type ProjectHookLease,
} from "./project-hook.js";
import {
  validateCommandManifest,
  validateTestManifest,
} from "./manifests.js";
import { validateAccountingConfig } from "./accounting.js";

function usage(exitCode = 1): never {
  const text = `Usage:
  npm run team -- --cwd <repo> (--task "<prompt>" | --task-file <path> | --run-bundle <dir>) [options]

Options:
  --cwd <path>                 Local repo (required)
  --task <text>                Task prompt
  --task-file <path>           Read task prompt from a file
  --run-bundle <dir>           Signed hard-policy bundle (Linux, signed control)
  --fan-out                    Run Luna scouts before master
  --fan-out-max <n>            Max scouts (default 3)
  --fan-out-focus <text>       Repeatable scout focus
  --parallel-exec              Run explicit --exec-shard commands after master
  --exec-shard <cmd>           Repeatable command shard
  --parallel-exec-max <n>      Max shards (default 8)
  --watchdog                   Enable stale/idle alerts
  --no-watchdog                Disable watchdog
  --hitl-timeout-ms <n>        Authorization wait (default 1800000)
  --verbose                    Show thinking + extra stream events
  --quiet                      Text-only stream
  --steer                      Require signed controller/steering (default)
  --no-steer                   Explicitly run without mid-run control
  --controller-public-key <p>  Ed25519 public key PEM (required with --steer)
  --control-dir <path>         Run control spool (default ~/.coding-agent-team/control/<run>)
  --min-free-gb <n>            Workspace/Docker free-space floor (default 20)
  --require-docker             Fail if Docker or its capacity check is unavailable

Signed control:
  The controller private key stays off the worker. The worker receives only
  --controller-public-key and verifies run-scoped steer/authorization envelopes.

Env:
  CURSOR_API_KEY                  required
  CODING_AGENT_CONTROL_PUBLIC_KEY optional public-key path
  CODING_AGENT_CONTROL_ROOT       optional control-root override
  SLACK_BOT_TOKEN                 optional notifications / allowlisted HITL
  SLACK_CHANNEL_ID                uppercase C…/G…/D… channel ID
  SLACK_ALLOWED_USER_IDS          comma-separated IDs allowed to answer HITL
  SLACK_STEER_ENABLED=1           opt-in Slack STEER (also requires allowlist)
  SLACK_WEBHOOK_URL               optional one-way alerts
`;
  (exitCode === 0 ? console.log : console.error)(text);
  process.exit(exitCode);
}

type CliArgs = {
  cwd?: string;
  task?: string;
  taskFile?: string;
  runBundle?: string;
  fanOut: boolean;
  fanOutMax: number;
  fanOutFocus: string[];
  parallelExec: boolean;
  execShards: string[];
  parallelExecMax: number;
  watchdog: boolean | "auto";
  hitlTimeoutMs: number;
  verbose: boolean;
  quiet: boolean;
  steer: boolean;
  controllerPublicKey?: string;
  controlDir?: string;
  minimumFreeGb: number;
  requireDocker: boolean;
};

function parseArgs(argv: string[]): CliArgs {
  const out: CliArgs = {
    fanOut: false,
    fanOutMax: 3,
    fanOutFocus: [],
    parallelExec: false,
    execShards: [],
    parallelExecMax: 8,
    watchdog: "auto",
    hitlTimeoutMs: 30 * 60 * 1000,
    verbose: false,
    quiet: false,
    steer: true,
    minimumFreeGb: 20,
    requireDocker: false,
  };

  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index]!;
    const next = (): string => {
      const value = argv[++index];
      if (!value) usage();
      return value;
    };
    switch (arg) {
      case "--cwd":
        out.cwd = path.resolve(next());
        break;
      case "--task":
        out.task = next();
        break;
      case "--task-file":
        out.taskFile = path.resolve(next());
        break;
      case "--run-bundle":
        out.runBundle = path.resolve(next());
        break;
      case "--fan-out":
        out.fanOut = true;
        break;
      case "--fan-out-max":
        out.fanOutMax = Number(next());
        break;
      case "--fan-out-focus":
        out.fanOutFocus.push(next());
        break;
      case "--parallel-exec":
        out.parallelExec = true;
        break;
      case "--exec-shard":
        out.execShards.push(next());
        out.parallelExec = true;
        break;
      case "--parallel-exec-max":
        out.parallelExecMax = Number(next());
        break;
      case "--watchdog":
        out.watchdog = true;
        break;
      case "--no-watchdog":
        out.watchdog = false;
        break;
      case "--hitl-timeout-ms":
        out.hitlTimeoutMs = Number(next());
        break;
      case "--verbose":
        out.verbose = true;
        break;
      case "--quiet":
        out.quiet = true;
        break;
      case "--steer":
        out.steer = true;
        break;
      case "--no-steer":
        out.steer = false;
        break;
      case "--controller-public-key":
        out.controllerPublicKey = path.resolve(next());
        break;
      case "--control-dir":
        out.controlDir = path.resolve(next());
        break;
      case "--min-free-gb":
        out.minimumFreeGb = Number(next());
        break;
      case "--require-docker":
        out.requireDocker = true;
        break;
      case "--help":
      case "-h":
        usage(0);
        break;
      default:
        console.error(`Unknown arg: ${arg}`);
        usage();
    }
  }
  if (
    !Number.isSafeInteger(out.fanOutMax) ||
    out.fanOutMax < 1 ||
    out.fanOutMax > 16
  ) {
    throw new Error("--fan-out-max must be an integer in [1, 16]");
  }
  if (
    !Number.isSafeInteger(out.parallelExecMax) ||
    out.parallelExecMax < 1 ||
    out.parallelExecMax > 32
  ) {
    throw new Error("--parallel-exec-max must be an integer in [1, 32]");
  }
  if (
    !Number.isSafeInteger(out.hitlTimeoutMs) ||
    out.hitlTimeoutMs < 1_000 ||
    out.hitlTimeoutMs > 24 * 60 * 60 * 1000
  ) {
    throw new Error("--hitl-timeout-ms must be an integer in [1000, 86400000]");
  }
  if (!Number.isFinite(out.minimumFreeGb) || out.minimumFreeGb < 0) {
    throw new Error("--min-free-gb must be a non-negative number");
  }
  if (!out.steer && (out.controllerPublicKey || out.controlDir)) {
    throw new Error(
      "--no-steer cannot be combined with --controller-public-key or --control-dir",
    );
  }
  return out;
}

function readTask(args: CliArgs): string {
  const choices = [args.task, args.taskFile, args.runBundle].filter(Boolean);
  if (choices.length !== 1) usage();
  if (args.runBundle) {
    throw new Error("signed bundle task must be loaded through loadRunBundle");
  }
  if (args.task) {
    if (Buffer.byteLength(args.task, "utf8") > 1024 * 1024) {
      throw new Error("--task exceeds 1 MiB");
    }
    return args.task;
  }
  if (!args.taskFile || !fs.existsSync(args.taskFile)) {
    throw new Error(`task file not found: ${args.taskFile}`);
  }
  const task = readSmallRegularFile(
    path.resolve(args.taskFile),
    1024 * 1024,
    "task file",
  ).trim();
  if (!task) throw new Error(`task file is empty: ${args.taskFile}`);
  return task;
}

function readPublicKey(args: CliArgs): {
  path: string;
  pem: string;
} | undefined {
  if (!args.steer) return undefined;
  const keyPath =
    args.controllerPublicKey ??
    process.env.CODING_AGENT_CONTROL_PUBLIC_KEY?.trim();
  if (!keyPath) {
    throw new Error(
      "--steer requires --controller-public-key or CODING_AGENT_CONTROL_PUBLIC_KEY",
    );
  }
  const resolved = path.resolve(keyPath);
  return {
    path: resolved,
    pem: readSmallRegularFile(
      resolved,
      64 * 1024,
      "controller public key",
    ),
  };
}

function readSmallRegularFile(
  filePath: string,
  maximumBytes: number,
  label: string,
): string {
  let fd: number | undefined;
  try {
    const before = fs.lstatSync(filePath);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.size > maximumBytes
    ) {
      throw new Error(`${label} must be a small regular non-symlink file`);
    }
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== before.ino) {
      throw new Error(`${label} changed while opening`);
    }
    return fs.readFileSync(fd, "utf8");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function gitHead(cwd: string): string | null {
  const result = spawnSync("git", ["rev-parse", "--verify", "HEAD"], {
    cwd,
    encoding: "utf8",
    timeout: 10_000,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.status !== 0) return null;
  const head = result.stdout.trim();
  if (!/^[0-9a-f]{40,64}$/.test(head)) {
    throw new Error("workspace git HEAD is invalid");
  }
  return head;
}

function loadPolicyBundle(
  args: CliArgs,
  publicKey: { path: string; pem: string } | undefined,
): LoadedRunBundle | undefined {
  if (!args.runBundle) return undefined;
  if (!publicKey) {
    throw new Error("--run-bundle requires signed control and a controller key");
  }
  if (process.platform !== "linux") {
    throw new Error("--run-bundle hard-policy mode currently requires Linux");
  }
  if (args.fanOut || args.parallelExec || args.execShards.length > 0) {
    throw new Error(
      "--run-bundle owns execution; --fan-out and --parallel-exec are not allowed",
    );
  }
  return loadRunBundle(args.runBundle, {
    publicKeyPem: publicKey.pem,
    expectedCwd: args.cwd!,
    expectedGitHead: gitHead(args.cwd!),
  });
}

async function main(): Promise<number> {
  assertChainsEndOnGrok();
  const args = parseArgs(process.argv.slice(2));
  const apiKey = process.env.CURSOR_API_KEY?.trim();
  if (!apiKey) throw new Error("Set CURSOR_API_KEY (Dashboard → Integrations)");
  if (!args.cwd || !fs.existsSync(args.cwd)) {
    throw new Error(`cwd not found: ${args.cwd}`);
  }
  args.cwd = fs.realpathSync(args.cwd);
  if (!fs.statSync(args.cwd).isDirectory()) {
    throw new Error(`cwd is not a directory: ${args.cwd}`);
  }
  if (/[\u0000-\u001f\u007f]/.test(args.cwd)) {
    throw new Error("cwd must not contain control characters");
  }
  const cwd = args.cwd;
  const publicKey = readPublicKey(args);
  const bundle = loadPolicyBundle(args, publicKey);
  if (bundle) {
    const commands = validateCommandManifest(bundle.commandManifest);
    validateTestManifest(bundle.testManifest, commands);
    validateAccountingConfig(bundle.accountingConfig);
  }
  const task = bundle?.task ?? readTask(args);

  const checks = runHostPreflight({
    cwd: args.cwd,
    minimumFreeGb: args.minimumFreeGb,
    requireDocker: args.requireDocker,
  });
  for (const check of checks) {
    console.log(
      `[preflight] ${check.label}: ${check.availableGb.toFixed(1)}GB free (${check.path})`,
    );
  }

  const slack = loadSlackConfig();
  const teamRunId =
    bundle?.binding.teamRunId ?? `team-${Date.now()}-${crypto.randomUUID()}`;
  const stateDir = path.join(cwd, ".team-state");
  if (bundle) assertNoLiveManagedProcesses(stateDir, cwd);
  const writerLock = acquireTeamLock(stateDir, teamRunId);
  const setup = await (async () => {
    let projectHook: ProjectHookLease | undefined;
    let processRegistry: ProcessRegistry | undefined;
    try {
      const state = new TeamStateStore(stateDir, teamRunId, cwd);
      const controlDir = args.controlDir ?? defaultControlDir(teamRunId);
      const fingerprint = publicKey
        ? publicKeyFingerprint(publicKey.pem)
        : undefined;
      const steer = publicKey
        ? new SteerHub({
            controlDir,
            publicKeyPem: publicKey.pem,
            teamRunId,
            slack,
          })
        : undefined;
      const policy = bundle
        ? new PolicyRuntime({
            bundle,
            state,
            stateDirectory: stateDir,
            workspace: cwd,
          })
        : undefined;
      if (policy) {
        projectHook = installDenyShellProjectHook({
          workspace: cwd,
          stateDirectory: stateDir,
          teamRunId,
        });
        processRegistry = new ProcessRegistry({
          workspace: cwd,
          teamRunId,
          stateDirectory: stateDir,
          manifest: policy.commands,
          currentPhase: () => policy.currentPhase(),
          beforeStart: () => policy.assertExecutionOpen(),
          onProcess: (record) => state.recordProcess(record),
          onReceipt: (receipt) => state.recordReceipt(receipt),
        });
        policy.attachRegistry(processRegistry);
      }
      state.setRunStatus("running");
      const capability = publicKey
        ? {
            active: true,
            teamRunId,
            cwd,
            pid: process.pid,
            host: os.hostname(),
            startedAt: Date.now(),
            stateFile: state.filePath,
            publicKeyFingerprint: fingerprint!,
            policyProfileSha256: state.snapshot().policy?.profileSha256,
            runBindingSha256: state.snapshot().policy?.bindingSha256,
          }
        : undefined;
      if (capability) writeControlCapability(controlDir, capability);
      const wantWatchdog =
        args.watchdog === true ||
        (args.watchdog === "auto" &&
          (slackPostingEnabled(slack) || Boolean(slack.webhookUrl)));
      const stopWatchdog = wantWatchdog
        ? startWatchdog({ state, slack })
        : () => {};
      return {
        state,
        policy,
        projectHook,
        processRegistry,
        controlDir,
        fingerprint,
        steer,
        capability,
        wantWatchdog,
        stopWatchdog,
      };
    } catch (error) {
      if (processRegistry) {
        await processRegistry.shutdown().catch(() => undefined);
      }
      if (projectHook) {
        try {
          projectHook.release();
        } catch {
          // Preserve the original setup failure.
        }
      }
      writerLock.release();
      throw error;
    }
  })();
  const {
    state,
    policy,
    projectHook,
    processRegistry,
    controlDir,
    fingerprint,
    steer,
    capability,
    wantWatchdog,
    stopWatchdog,
  } = setup;
  let cleanupPromise: Promise<void> | undefined;
  const cleanup = (): Promise<void> => {
    if (cleanupPromise) return cleanupPromise;
    cleanupPromise = (async () => {
      const failures: unknown[] = [];
      const status = state.snapshot().runStatus;
      if (
        status === "running" ||
        status === "awaiting_human" ||
        status === "initializing"
      ) {
        state.setRunStatus("cleaning");
      }
      if (processRegistry) {
        try {
          await processRegistry.shutdown();
        } catch (error) {
          failures.push(error);
        }
      }
      if (projectHook) {
        try {
          projectHook.release();
        } catch (error) {
          failures.push(error);
        }
      }
      if (capability) {
        try {
          writeControlCapability(controlDir, {
            ...capability,
            active: false,
          });
        } catch (error) {
          failures.push(error);
        }
      }
      try {
        stopWatchdog();
      } catch (error) {
        failures.push(error);
      }
      try {
        writerLock.release();
      } catch (error) {
        failures.push(error);
      }
      if (failures.length > 0) {
        try {
          state.setRunStatus(
            "failed",
            failures
              .map((failure) =>
                failure instanceof Error ? failure.message : String(failure),
              )
              .join("; "),
          );
        } catch {
          // Preserve the original cleanup failures.
        }
        throw new AggregateError(failures, "team cleanup failed");
      }
    })();
    return cleanupPromise;
  };
  const signalHandler = (signal: NodeJS.Signals): void => {
    void cleanup().finally(() => {
      process.removeListener("SIGINT", signalHandler);
      process.removeListener("SIGTERM", signalHandler);
      process.kill(process.pid, signal);
    });
  };
  process.once("SIGINT", signalHandler);
  process.once("SIGTERM", signalHandler);

  try {
    console.log(`[team] run=${teamRunId} cwd=${args.cwd}`);
    console.log(
      `[team] live=${!args.quiet} slack-post=${slackPostingEnabled(slack)} slack-hitl=${slackHitlEnabled(slack)} watchdog=${wantWatchdog} signed-control=${Boolean(steer)}`,
    );
    if (policy) {
      console.log(
        `[team] hard-policy=${policy.profile.profileId}@${policy.profile.profileVersion} phase=${policy.currentPhase()}`,
      );
    }
    if (steer) {
      console.log(`[team] control dir: ${controlDir}`);
      console.log(`[team] controller key: SHA256:${fingerprint}`);
    }
    console.log(
      "[team] watch this SSH/tmux terminal; local SDK runs do not appear in Agents Window",
    );

    const live = !args.quiet;
    let scoutSummaries: string[] | undefined;
    if (args.fanOut) {
      console.log("\n=== Fan-out scouts (Luna→Grok) ===\n");
      const result = await runFanOutScouts({
        apiKey,
        cwd: args.cwd,
        task,
        focuses: args.fanOutFocus,
        max: args.fanOutMax,
        state,
        live,
        verbose: args.verbose,
        processRegistry,
        projectHook,
      });
      scoutSummaries = result.summaries;
      for (const summary of result.summaries) {
        console.log(`\n${summary}\n`);
      }
    }

    console.log("\n=== Master (Opus→Sol→Terra→GPT→Grok) ===\n");
    const master = await runOrchestrator({
      apiKey,
      cwd: args.cwd,
      task,
      scoutSummaries,
      state,
      slack,
      hitlTimeoutMs: args.hitlTimeoutMs,
      live,
      verbose: args.verbose,
      interactiveHitl: true,
      steer,
      processRegistry,
      policy,
      projectHook,
    });
    if (!master.ok) {
      state.setRunStatus("failed", master.lastError ?? "master failed");
      console.error(
        `[team] master FAILED attempts=${master.attempts.join("→")} err=${master.lastError}`,
      );
      return 2;
    }
    console.log(
      `\n[team] master OK model=${master.model} attempts=${master.attempts.join("→")}`,
    );
    processRegistry?.assertIdle();
    policy?.assertReady();

    if (args.parallelExec && args.execShards.length > 0) {
      console.log("\n=== Parallel exec shards ===\n");
      const outcomes = await runParallelExec({
        apiKey,
        cwd: args.cwd,
        shards: args.execShards.map((command) => [command]),
        max: args.parallelExecMax,
        state,
        live,
        verbose: args.verbose,
        processRegistry,
        projectHook,
      });
      for (const outcome of outcomes) {
        if (!outcome.ok) {
          state.setRunStatus("failed", outcome.lastError ?? "exec shard failed");
          console.error(
            `[exec] FAIL attempts=${outcome.attempts.join("→")} err=${outcome.lastError}`,
          );
          return 2;
        }
        console.log(
          `[exec] OK model=${outcome.model} attempts=${outcome.attempts.join("→")}`,
        );
      }
    }

    if (!policy) state.setRunStatus("ready");
    console.log(`\n[team] complete · state ${state.filePath}`);
    return 0;
  } catch (error) {
    if (state.snapshot().runStatus !== "ready") {
      state.setRunStatus(
        "failed",
        error instanceof Error ? error.message : String(error),
      );
    }
    throw error;
  } finally {
    process.removeListener("SIGINT", signalHandler);
    process.removeListener("SIGTERM", signalHandler);
    await cleanup();
  }
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
