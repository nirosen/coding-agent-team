#!/usr/bin/env node
/**
 * Local multi-model coding agent team (Cursor SDK).
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
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

function usage(exitCode = 1): never {
  const text = `Usage:
  npm run team -- --cwd <repo> (--task "<prompt>" | --task-file <path>) [options]

Options:
  --cwd <path>                 Local repo (required)
  --task <text>                Task prompt
  --task-file <path>           Read task prompt from a file
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
  return out;
}

function readTask(args: CliArgs): string {
  if (Boolean(args.task) === Boolean(args.taskFile)) usage();
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
  const task = readTask(args);
  const publicKey = readPublicKey(args);

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
  const teamRunId = `team-${Date.now()}-${crypto.randomUUID()}`;
  const stateDir = path.join(args.cwd, ".team-state");
  const writerLock = acquireTeamLock(stateDir, teamRunId);
  const setup = (() => {
    try {
      const state = new TeamStateStore(stateDir, teamRunId, args.cwd);
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
      const capability = publicKey
        ? {
            active: true,
            teamRunId,
            cwd: args.cwd,
            pid: process.pid,
            host: os.hostname(),
            startedAt: Date.now(),
            stateFile: state.filePath,
            publicKeyFingerprint: fingerprint!,
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
        controlDir,
        fingerprint,
        steer,
        capability,
        wantWatchdog,
        stopWatchdog,
      };
    } catch (error) {
      writerLock.release();
      throw error;
    }
  })();
  const {
    state,
    controlDir,
    fingerprint,
    steer,
    capability,
    wantWatchdog,
    stopWatchdog,
  } = setup;
  let cleanedUp = false;
  const cleanup = (): void => {
    if (cleanedUp) return;
    cleanedUp = true;
    if (capability) {
      try {
        writeControlCapability(controlDir, {
          ...capability,
          active: false,
        });
      } catch (error) {
        console.warn(
          `[control] could not mark inactive: ${error instanceof Error ? error.message : error}`,
        );
      }
    }
    try {
      stopWatchdog();
    } catch (error) {
      console.warn(
        `[watchdog] cleanup failed: ${error instanceof Error ? error.message : error}`,
      );
    }
    try {
      writerLock.release();
    } catch (error) {
      console.warn(
        `[lock] cleanup failed: ${error instanceof Error ? error.message : error}`,
      );
    }
  };
  const signalHandler = (signal: NodeJS.Signals): void => {
    cleanup();
    process.removeListener("SIGINT", signalHandler);
    process.removeListener("SIGTERM", signalHandler);
    process.kill(process.pid, signal);
  };
  process.once("SIGINT", signalHandler);
  process.once("SIGTERM", signalHandler);

  try {
    console.log(`[team] run=${teamRunId} cwd=${args.cwd}`);
  console.log(
    `[team] live=${!args.quiet} slack-post=${slackPostingEnabled(slack)} slack-hitl=${slackHitlEnabled(slack)} watchdog=${wantWatchdog} signed-control=${Boolean(steer)}`,
  );
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
    });
    if (!master.ok) {
      console.error(
        `[team] master FAILED attempts=${master.attempts.join("→")} err=${master.lastError}`,
      );
      return 2;
    }
    console.log(
      `\n[team] master OK model=${master.model} attempts=${master.attempts.join("→")}`,
    );

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
      });
      for (const outcome of outcomes) {
        if (!outcome.ok) {
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

    console.log(`\n[team] complete · state ${state.filePath}`);
    return 0;
  } finally {
    process.removeListener("SIGINT", signalHandler);
    process.removeListener("SIGTERM", signalHandler);
    cleanup();
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
