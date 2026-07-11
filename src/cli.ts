#!/usr/bin/env node
/**
 * Local multi-model coding agent team (Cursor SDK).
 *
 *   export CURSOR_API_KEY=...
 *   npm run team -- --cwd /path/to/repo --task "..."
 *
 * Optional: --fan-out, --parallel-exec, Slack HITL via env.
 */
import fs from "node:fs";
import path from "node:path";
import { assertChainsEndOnGrok } from "./models.js";
import { runFanOutScouts } from "./fan-out.js";
import { runOrchestrator } from "./orchestrator.js";
import { runParallelExec } from "./parallel-exec.js";
import { loadSlackConfig, slackHitlEnabled } from "./slack-hitl.js";
import { TeamStateStore } from "./state.js";
import { startWatchdog } from "./watchdog.js";

function usage(): never {
  console.error(`Usage:
  npm run team -- --cwd <repo> --task "<prompt>" [options]

Options:
  --cwd <path>              Local repo (required)
  --task <text>             Task prompt (required)
  --fan-out                 Run Luna scouts before master
  --fan-out-max <n>         Max scouts (default 3)
  --fan-out-focus <text>    Repeatable scout focus (else one default)
  --parallel-exec           After master, unused unless --exec-shard given
  --exec-shard <cmd>        Repeatable; each flag is one shard (one command)
  --parallel-exec-max <n>   Max shards (default 8)
  --watchdog                Enable stale/idle Slack/console alerts (default on if Slack)
  --no-watchdog             Disable watchdog
  --hitl-timeout-ms <n>     Slack HITL wait (default 1800000)
  --verbose                 Extra stream events
  --quiet                   Text-only stream (less interactive)

Live session: run on the remote over SSH in a real TTY — you see role banners,
assistant text, tool calls, and status live. HITL prompts appear in-terminal
when Slack is not configured. Cloud Agents Window does not show local SDK runs.

Env:
  CURSOR_API_KEY            required
  SLACK_BOT_TOKEN           bidirectional HITL
  SLACK_CHANNEL_ID          channel id for #nir-ccb-aisec (etc.)
  SLACK_WEBHOOK_URL         optional one-way alerts
`);
  process.exit(1);
}

function parseArgs(argv: string[]) {
  const out: {
    cwd?: string;
    task?: string;
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
  } = {
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
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    const next = () => {
      const v = argv[++i];
      if (!v) usage();
      return v;
    };
    switch (a) {
      case "--cwd":
        out.cwd = path.resolve(next());
        break;
      case "--task":
        out.task = next();
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
      case "--help":
      case "-h":
        usage();
        break;
      default:
        console.error(`Unknown arg: ${a}`);
        usage();
    }
  }
  return out;
}

async function main(): Promise<void> {
  assertChainsEndOnGrok();

  const args = parseArgs(process.argv.slice(2));
  const apiKey = process.env.CURSOR_API_KEY?.trim();
  if (!apiKey) {
    console.error("Set CURSOR_API_KEY (Dashboard → Integrations).");
    process.exit(1);
  }
  if (!args.cwd || !args.task) usage();
  if (!fs.existsSync(args.cwd)) {
    console.error(`cwd not found: ${args.cwd}`);
    process.exit(1);
  }

  const slack = loadSlackConfig();
  const teamRunId = `team-${Date.now()}`;
  const stateDir = path.join(args.cwd, ".team-state");
  const state = new TeamStateStore(stateDir, teamRunId, args.cwd);

  const wantWatchdog =
    args.watchdog === true ||
    (args.watchdog === "auto" &&
      (slackHitlEnabled(slack) || Boolean(slack.webhookUrl)));
  const stopWatchdog = wantWatchdog
    ? startWatchdog({ state, slack })
    : () => {};

  console.log(`[team] run=${teamRunId} cwd=${args.cwd}`);
  console.log(
    `[team] live=${!args.quiet} slack HITL=${slackHitlEnabled(slack) ? "on" : "off (TTY HITL if interactive)"} watchdog=${wantWatchdog}`,
  );
  console.log(
    `[team] watch this SSH terminal for the live session (local SDK ≠ Agents Window)`,
  );

  const live = !args.quiet;
  let scoutSummaries: string[] | undefined;
  try {
    if (args.fanOut) {
      console.log("\n=== Fan-out scouts (Luna→Grok) ===\n");
      const { summaries } = await runFanOutScouts({
        apiKey,
        cwd: args.cwd,
        task: args.task,
        focuses: args.fanOutFocus,
        max: args.fanOutMax,
        state,
        live,
        verbose: args.verbose,
      });
      scoutSummaries = summaries;
      for (const s of summaries) console.log(`\n${s}\n`);
    }

    console.log("\n=== Master (Opus→Sol→Terra→GPT→Grok) ===\n");
    const master = await runOrchestrator({
      apiKey,
      cwd: args.cwd,
      task: args.task,
      scoutSummaries,
      state,
      slack,
      hitlTimeoutMs: args.hitlTimeoutMs,
      live,
      verbose: args.verbose,
      interactiveHitl: true,
    });

    if (!master.ok) {
      console.error(
        `[team] master FAILED attempts=${master.attempts.join("→")} err=${master.lastError}`,
      );
      process.exit(2);
    }
    console.log(
      `\n[team] master OK model=${master.model} attempts=${master.attempts.join("→")}`,
    );

    if (args.parallelExec && args.execShards.length > 0) {
      console.log("\n=== Parallel exec shards ===\n");
      const outcomes = await runParallelExec({
        apiKey,
        cwd: args.cwd,
        shards: args.execShards.map((c) => [c]),
        max: args.parallelExecMax,
        state,
        live,
        verbose: args.verbose,
      });
      for (const o of outcomes) {
        if (!o.ok) {
          console.error(
            `[exec] FAIL attempts=${o.attempts.join("→")} err=${o.lastError}`,
          );
          process.exit(2);
        }
        console.log(`[exec] OK model=${o.model} attempts=${o.attempts.join("→")}`);
      }
    }

    console.log(`\n[team] complete · state ${state.filePath}`);
  } finally {
    stopWatchdog();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
