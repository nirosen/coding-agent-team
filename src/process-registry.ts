import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawn, type ChildProcess } from "node:child_process";
import type {
  SDKCustomTool,
  SDKCustomToolContext,
  SDKJsonValue,
} from "@cursor/sdk";
import { redactSecrets } from "./control.js";
import {
  commandDigest,
  receiptId,
  type CommandManifest,
  type ManifestCommand,
} from "./manifests.js";

const LOG_LIMIT_BYTES = 2 * 1024 * 1024;
const TOOL_TAIL_CHARS = 16_000;
const STOP_GRACE_MS = 5_000;
const BANNED_EXECUTABLES = new Set([
  "at",
  "batch",
  "daemon",
  "daemonize",
  "disown",
  "mosh",
  "nohup",
  "screen",
  "setsid",
  "ssh",
  "systemd-run",
  "tmux",
]);

export type ProcessStatus =
  | "starting"
  | "running"
  | "stopping"
  | "exited"
  | "failed"
  | "timed_out"
  | "orphaned"
  | "lost";

export type ProcessIdentity = {
  bootId: string;
  startTimeTicks: string;
};

export type ProcessRecord = {
  processId: string;
  ownerJobId: string;
  toolCallId?: string;
  commandId: string;
  commandSha256: string;
  executableSha256: string;
  pid: number;
  pgid: number;
  identity: ProcessIdentity;
  status: ProcessStatus;
  startedAt: number;
  updatedAt: number;
  endedAt?: number;
  exitCode?: number;
  signal?: NodeJS.Signals;
  logPath: string;
  lastError?: string;
};

export type ExecutionReceipt = {
  schema: "coding-agent-team-execution-receipt/v1";
  receiptId: string;
  processId: string;
  ownerJobId: string;
  commandId: string;
  commandSha256: string;
  phase: string;
  kind: ManifestCommand["kind"];
  startedAt: number;
  endedAt: number;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  expectedExit: boolean;
  status: "passed" | "failed";
};

export type ProcessRegistryOptions = {
  workspace: string;
  teamRunId: string;
  stateDirectory: string;
  manifest: CommandManifest;
  currentPhase: () => string;
  beforeStart?: () => void;
  onProcess: (record: ProcessRecord) => void;
  onReceipt: (receipt: ExecutionReceipt) => void;
  launcherPath?: string;
  platform?: NodeJS.Platform;
};

type Tracked = {
  command: ManifestCommand;
  child: ChildProcess;
  record: ProcessRecord;
  tail: string;
  logBytes: number;
  timeout?: NodeJS.Timeout;
  settle: Promise<ProcessRecord>;
  resolve: (record: ProcessRecord) => void;
  timedOut: boolean;
};

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function parseLinuxProcStat(stat: string): string {
  const close = stat.lastIndexOf(")");
  if (close < 0) throw new Error("invalid /proc stat: missing command terminator");
  const fields = stat.slice(close + 2).trim().split(/\s+/);
  const startTime = fields[19];
  if (!startTime || !/^[0-9]+$/.test(startTime)) {
    throw new Error("invalid /proc stat: missing start time");
  }
  return startTime;
}

export function readLinuxProcessIdentity(pid: number): ProcessIdentity {
  if (process.platform !== "linux") {
    throw new Error("hard process identity requires Linux /proc");
  }
  const bootId = fs
    .readFileSync("/proc/sys/kernel/random/boot_id", "utf8")
    .trim();
  if (!/^[0-9a-f-]{36}$/.test(bootId)) {
    throw new Error("Linux boot ID is invalid");
  }
  const stat = fs.readFileSync(`/proc/${pid}/stat`, "utf8");
  return { bootId, startTimeTicks: parseLinuxProcStat(stat) };
}

function processGroupAlive(pgid: number): boolean {
  try {
    process.kill(-pgid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

export function assertNoLiveManagedProcesses(
  stateDirectory: string,
  workspace: string,
): void {
  if (!fs.existsSync(stateDirectory)) return;
  const directory = fs.lstatSync(stateDirectory);
  if (!directory.isDirectory() || directory.isSymbolicLink()) {
    throw new Error("state directory must be a real directory");
  }
  const expectedWorkspace = fs.realpathSync(workspace);
  const live: string[] = [];
  for (const name of fs
    .readdirSync(stateDirectory)
    .filter((candidate) => candidate.startsWith("team-") && candidate.endsWith(".json"))) {
    const filePath = path.join(stateDirectory, name);
    try {
      const info = fs.lstatSync(filePath);
      if (!info.isFile() || info.isSymbolicLink() || info.size > 10 * 1024 * 1024) {
        continue;
      }
      const state = JSON.parse(fs.readFileSync(filePath, "utf8")) as {
        cwd?: unknown;
        processes?: Record<string, Partial<ProcessRecord>>;
      };
      if (state.cwd !== expectedWorkspace) continue;
      for (const record of Object.values(state.processes ?? {})) {
        if (
          typeof record.processId !== "string" ||
          typeof record.pid !== "number" ||
          typeof record.pgid !== "number" ||
          !record.identity ||
          typeof record.identity.bootId !== "string" ||
          typeof record.identity.startTimeTicks !== "string"
        ) {
          continue;
        }
        if (
          processGroupAlive(record.pgid) &&
          sameIdentity(record.pid, record.identity as ProcessIdentity)
        ) {
          live.push(record.processId);
        }
      }
    } catch {
      // Malformed historical state is not trusted as process identity.
    }
  }
  if (live.length > 0) {
    throw new Error(
      `prior harness state still owns live process groups: ${live.join(", ")}`,
    );
  }
}

function sameIdentity(pid: number, expected: ProcessIdentity): boolean {
  try {
    const current = readLinuxProcessIdentity(pid);
    return (
      current.bootId === expected.bootId &&
      current.startTimeTicks === expected.startTimeTicks
    );
  } catch {
    return false;
  }
}

function resolveExecutable(argv0: string, envPath: string | undefined): string {
  if (path.isAbsolute(argv0) || argv0.includes(path.sep)) {
    return fs.realpathSync(path.resolve(argv0));
  }
  for (const directory of (envPath ?? "").split(path.delimiter)) {
    if (!directory) continue;
    const candidate = path.join(directory, argv0);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return fs.realpathSync(candidate);
    } catch {
      // Keep searching PATH.
    }
  }
  throw new Error(`manifest executable is not on PATH: ${argv0}`);
}

function executableDigest(filePath: string): string {
  const info = fs.lstatSync(filePath);
  if (!info.isFile() || info.size > 512 * 1024 * 1024) {
    throw new Error(`manifest executable is not a regular file: ${filePath}`);
  }
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== info.ino) {
      throw new Error(`manifest executable changed while opening: ${filePath}`);
    }
    const hash = crypto.createHash("sha256");
    const buffer = Buffer.allocUnsafe(1024 * 1024);
    for (;;) {
      const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
    }
    const after = fs.fstatSync(fd);
    if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) {
      throw new Error(`manifest executable changed while hashing: ${filePath}`);
    }
    return hash.digest("hex");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function validateNoDetach(command: ManifestCommand): void {
  const base = path.basename(command.argv[0]!).toLowerCase();
  if (BANNED_EXECUTABLES.has(base)) {
    throw new Error(`detaching/remote launcher is forbidden: ${base}`);
  }
  if (base === "docker" || base === "podman") {
    const args = command.argv.slice(1);
    if (
      args.some(
        (argument) =>
          argument === "-d" ||
          argument === "--detach" ||
          argument.startsWith("-d=") ||
          argument.startsWith("--detach=") ||
          argument === "--restart" ||
          (argument.startsWith("--restart=") && argument !== "--restart=no"),
      ) ||
      args.includes("start")
    ) {
      throw new Error(`${base} detached/restart execution is forbidden`);
    }
  }
}

function safeWorkspaceCwd(workspace: string, relative: string): string {
  const root = fs.realpathSync(workspace);
  const candidate = fs.realpathSync(path.resolve(root, relative));
  if (candidate !== root && !candidate.startsWith(`${root}${path.sep}`)) {
    throw new Error(`manifest cwd escapes workspace: ${relative}`);
  }
  if (!fs.statSync(candidate).isDirectory()) {
    throw new Error(`manifest cwd is not a directory: ${relative}`);
  }
  return candidate;
}

function safeLogDirectory(stateDirectory: string, teamRunId: string): string {
  const runDir = path.join(stateDirectory, teamRunId);
  const logDir = path.join(runDir, "process-logs");
  for (const directory of [runDir, logDir]) {
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const info = fs.lstatSync(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error(`process log path must be a real directory: ${directory}`);
    }
    fs.chmodSync(directory, 0o700);
  }
  return logDir;
}

export class ProcessRegistry {
  readonly teamRunId: string;
  private readonly workspace: string;
  private readonly stateDirectory: string;
  private readonly commands: Map<string, ManifestCommand>;
  private readonly currentPhase: () => string;
  private readonly beforeStart?: () => void;
  private readonly onProcess: (record: ProcessRecord) => void;
  private readonly onReceipt: (receipt: ExecutionReceipt) => void;
  private readonly launcherPath: string;
  private readonly launcherSha256: string;
  private readonly tracked = new Map<string, Tracked>();
  private readonly fatalErrors: Error[] = [];
  private shuttingDown = false;

  constructor(opts: ProcessRegistryOptions) {
    if ((opts.platform ?? process.platform) !== "linux") {
      throw new Error("hard supervised execution currently requires Linux");
    }
    this.workspace = fs.realpathSync(opts.workspace);
    this.teamRunId = opts.teamRunId;
    this.stateDirectory = opts.stateDirectory;
    this.commands = new Map(
      opts.manifest.commands.map((command) => [command.id, command]),
    );
    this.currentPhase = opts.currentPhase;
    this.beforeStart = opts.beforeStart;
    this.onProcess = opts.onProcess;
    this.onReceipt = opts.onReceipt;
    this.launcherPath =
      opts.launcherPath ??
      path.resolve(import.meta.dirname, "..", "scripts", "supervised-launcher.mjs");
    const launcher = fs.lstatSync(this.launcherPath);
    if (!launcher.isFile() || launcher.isSymbolicLink()) {
      throw new Error("supervised launcher must be a regular non-symlink file");
    }
    this.launcherSha256 = executableDigest(this.launcherPath);
  }

  customTool(ownerJobId: string): SDKCustomTool {
    return {
      description:
        "Run, wait for, inspect, or stop an exact command from the signed run manifest. Built-in Shell is disabled in hard-policy runs.",
      inputSchema: {
        type: "object",
        properties: {
          action: {
            type: "string",
            enum: ["run", "start", "wait", "status", "stop"],
          },
          commandId: { type: "string" },
          processId: { type: "string" },
        },
        required: ["action"],
        additionalProperties: false,
      },
      execute: async (
        args: Record<string, SDKJsonValue>,
        context: SDKCustomToolContext,
      ) => this.executeTool(ownerJobId, args, context),
    };
  }

  private async executeTool(
    ownerJobId: string,
    args: Record<string, SDKJsonValue>,
    context: SDKCustomToolContext,
  ): Promise<SDKJsonValue> {
    const action = args.action;
    if (
      action !== "run" &&
      action !== "start" &&
      action !== "wait" &&
      action !== "status" &&
      action !== "stop"
    ) {
      throw new Error("supervised_process action is invalid");
    }
    if (action === "run" || action === "start") {
      if (typeof args.commandId !== "string") {
        throw new Error(`${action} requires commandId`);
      }
      const record = await this.start(
        ownerJobId,
        args.commandId,
        context.toolCallId,
      );
      if (action === "start") return this.publicRecord(record);
      return this.publicRecord(await this.wait(record.processId));
    }
    if (typeof args.processId !== "string") {
      throw new Error(`${action} requires processId`);
    }
    const tracked = this.tracked.get(args.processId);
    if (!tracked || tracked.record.ownerJobId !== ownerJobId) {
      throw new Error("process is not owned by this job");
    }
    if (action === "wait") return this.publicRecord(await this.wait(args.processId));
    if (action === "stop") {
      await this.stop(args.processId, "SIGTERM");
      return this.publicRecord(await this.wait(args.processId));
    }
    return this.publicRecord(tracked.record);
  }

  private publicRecord(record: ProcessRecord): SDKJsonValue {
    const tracked = this.tracked.get(record.processId);
    return {
      processId: record.processId,
      commandId: record.commandId,
      commandSha256: record.commandSha256,
      status: record.status,
      pid: record.pid,
      exitCode: record.exitCode ?? null,
      signal: record.signal ?? null,
      tail: redactSecrets(tracked?.tail ?? ""),
    };
  }

  async start(
    ownerJobId: string,
    commandId: string,
    toolCallId?: string,
  ): Promise<ProcessRecord> {
    if (this.shuttingDown) throw new Error("process registry is shutting down");
    this.beforeStart?.();
    const command = this.commands.get(commandId);
    if (!command) throw new Error(`command is not in signed manifest: ${commandId}`);
    if (command.phase !== this.currentPhase()) {
      throw new Error(
        `command ${commandId} belongs to phase ${command.phase}, current phase is ${this.currentPhase()}`,
      );
    }
    validateNoDetach(command);
    if (executableDigest(this.launcherPath) !== this.launcherSha256) {
      throw new Error("trusted supervised launcher changed");
    }
    const cwd = safeWorkspaceCwd(this.workspace, command.cwd);
    const executable = resolveExecutable(command.argv[0]!, process.env.PATH);
    const actualExecutableSha256 = executableDigest(executable);
    if (
      command.executableSha256 &&
      command.executableSha256 !== actualExecutableSha256
    ) {
      throw new Error(`executable digest changed for command ${commandId}`);
    }
    const env: NodeJS.ProcessEnv = {};
    for (const name of new Set([
      "HOME",
      "PATH",
      "TMPDIR",
      ...command.envAllowlist,
    ])) {
      if (process.env[name] !== undefined) env[name] = process.env[name];
    }
    env.CODING_AGENT_TEAM_RUN_ID = this.teamRunId;
    env.CODING_AGENT_COMMAND_ID = command.id;

    const processId = `process-${crypto.randomUUID()}`;
    const logDirectory = safeLogDirectory(this.stateDirectory, this.teamRunId);
    const logPath = path.join(logDirectory, `${processId}.log`);
    const logFd = fs.openSync(
      logPath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    const payload = Buffer.from(
      JSON.stringify({ argv: [executable, ...command.argv.slice(1)], cwd }),
      "utf8",
    ).toString("base64url");
    const child = spawn(process.execPath, [this.launcherPath, payload], {
      cwd: this.workspace,
      env,
      detached: true,
      shell: false,
      stdio: ["ignore", "pipe", "pipe", "pipe"],
    });
    if (!child.pid) {
      fs.closeSync(logFd);
      throw new Error(`could not launch command ${commandId}`);
    }
    let identity: ProcessIdentity | undefined;
    for (let attempt = 0; attempt < 20; attempt++) {
      try {
        identity = readLinuxProcessIdentity(child.pid);
        break;
      } catch {
        await delay(5);
      }
    }
    if (!identity) {
      child.kill("SIGKILL");
      fs.closeSync(logFd);
      throw new Error(`could not record Linux process identity for ${commandId}`);
    }

    let resolve!: (record: ProcessRecord) => void;
    const settle = new Promise<ProcessRecord>((done) => {
      resolve = done;
    });
    const now = Date.now();
    const record: ProcessRecord = {
      processId,
      ownerJobId,
      toolCallId,
      commandId,
      commandSha256: commandDigest(command),
      executableSha256: actualExecutableSha256,
      pid: child.pid,
      pgid: child.pid,
      identity,
      status: "starting",
      startedAt: now,
      updatedAt: now,
      logPath,
    };
    const tracked: Tracked = {
      command,
      child,
      record,
      tail: "",
      logBytes: 0,
      settle,
      resolve,
      timedOut: false,
    };
    this.tracked.set(processId, tracked);
    this.publish(tracked, "starting");
    const append = (chunk: Buffer): void => {
      const sanitized = Buffer.from(
        redactSecrets(chunk.toString("utf8")),
        "utf8",
      );
      const remaining = LOG_LIMIT_BYTES - tracked.logBytes;
      if (remaining > 0) {
        const write = sanitized.subarray(0, remaining);
        fs.writeSync(logFd, write);
        tracked.logBytes += write.length;
      }
      tracked.tail = `${tracked.tail}${sanitized.toString("utf8")}`.slice(
        -TOOL_TAIL_CHARS,
      );
    };
    child.stdout?.on("data", append);
    child.stderr?.on("data", append);
    child.once("error", (error) => {
      tracked.record.lastError = error.message;
      this.finish(tracked, null, null, "failed", logFd);
    });
    child.once("exit", (code, signal) => {
      setTimeout(() => {
        const groupRemains = processGroupAlive(tracked.record.pgid);
        const status: ProcessStatus = groupRemains
          ? "orphaned"
          : tracked.timedOut
            ? "timed_out"
            : code !== null &&
                tracked.command.expectedExitCodes.includes(code)
              ? "exited"
              : "failed";
        this.finish(tracked, code, signal, status, logFd);
      }, 25);
    });
    tracked.timeout = setTimeout(() => {
      tracked.timedOut = true;
      this.publish(tracked, "timed_out", "command timeout reached");
      void this.stop(processId, "SIGTERM");
    }, command.timeoutMs);

    this.publish(tracked, "running");
    const barrier = child.stdio[3];
    if (!barrier || !("write" in barrier)) {
      await this.stop(processId, "SIGKILL");
      throw new Error("supervised launcher startup barrier is unavailable");
    }
    barrier.write("1");
    barrier.end();
    return structuredClone(record);
  }

  private finish(
    tracked: Tracked,
    code: number | null,
    signal: NodeJS.Signals | null,
    status: ProcessStatus,
    logFd: number,
  ): void {
    if (
      tracked.record.endedAt !== undefined ||
      tracked.record.status === "orphaned"
    ) {
      return;
    }
    if (tracked.timeout) clearTimeout(tracked.timeout);
    try {
      fs.fsyncSync(logFd);
    } finally {
      try {
        fs.closeSync(logFd);
      } catch {
        // The error/exit events can race; only the first close matters.
      }
    }
    const endedAt = Date.now();
    tracked.record = {
      ...tracked.record,
      status,
      exitCode: code ?? undefined,
      signal: signal ?? undefined,
      endedAt,
      updatedAt: endedAt,
    };
    try {
      this.onProcess(structuredClone(tracked.record));
      const expectedExit =
        code !== null && tracked.command.expectedExitCodes.includes(code);
      this.onReceipt({
        schema: "coding-agent-team-execution-receipt/v1",
        receiptId: receiptId(tracked.command.id),
        processId: tracked.record.processId,
        ownerJobId: tracked.record.ownerJobId,
        commandId: tracked.command.id,
        commandSha256: tracked.record.commandSha256,
        phase: tracked.command.phase,
        kind: tracked.command.kind,
        startedAt: tracked.record.startedAt,
        endedAt,
        exitCode: code,
        signal,
        expectedExit,
        status: status === "exited" && expectedExit ? "passed" : "failed",
      });
      tracked.resolve(structuredClone(tracked.record));
    } catch (error) {
      const failure =
        error instanceof Error ? error : new Error(String(error));
      this.fatalErrors.push(failure);
      tracked.record = {
        ...tracked.record,
        status: "failed",
        lastError: `could not persist completion: ${failure.message}`,
      };
      tracked.resolve(structuredClone(tracked.record));
    }
  }

  private publish(
    tracked: Tracked,
    status: ProcessStatus,
    lastError?: string,
  ): void {
    tracked.record = {
      ...tracked.record,
      status,
      updatedAt: Date.now(),
      lastError,
    };
    this.onProcess(structuredClone(tracked.record));
  }

  async wait(processId: string): Promise<ProcessRecord> {
    const tracked = this.tracked.get(processId);
    if (!tracked) throw new Error(`unknown supervised process: ${processId}`);
    if (tracked.record.endedAt !== undefined) {
      return structuredClone(tracked.record);
    }
    return tracked.settle;
  }

  async stop(
    processId: string,
    firstSignal: NodeJS.Signals = "SIGTERM",
  ): Promise<void> {
    const tracked = this.tracked.get(processId);
    if (!tracked || tracked.record.endedAt !== undefined) return;
    if (!sameIdentity(tracked.record.pid, tracked.record.identity)) {
      this.publish(
        tracked,
        "lost",
        "process identity changed; refusing to signal a reused PID/group",
      );
      tracked.resolve(structuredClone(tracked.record));
      return;
    }
    this.publish(tracked, "stopping");
    try {
      process.kill(-tracked.record.pgid, firstSignal);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
    }
    const deadline = Date.now() + STOP_GRACE_MS;
    while (Date.now() < deadline && processGroupAlive(tracked.record.pgid)) {
      await delay(50);
    }
    if (
      processGroupAlive(tracked.record.pgid) &&
      sameIdentity(tracked.record.pid, tracked.record.identity)
    ) {
      try {
        process.kill(-tracked.record.pgid, "SIGKILL");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
      }
    }
  }

  active(ownerJobId?: string): ProcessRecord[] {
    return [...this.tracked.values()]
      .map(({ record }) => record)
      .filter(
        (record) =>
          (record.endedAt === undefined || record.status === "orphaned") &&
          (!ownerJobId || record.ownerJobId === ownerJobId),
      )
      .map((record) => structuredClone(record));
  }

  assertIdle(ownerJobId?: string): void {
    if (this.fatalErrors.length > 0) {
      throw new AggregateError(
        this.fatalErrors,
        "supervised process state/receipt persistence failed",
      );
    }
    const active = this.active(ownerJobId);
    if (active.length > 0) {
      throw new Error(
        `supervised work is still active: ${active
          .map((record) => `${record.processId}:${record.status}`)
          .join(", ")}`,
      );
    }
  }

  async shutdown(): Promise<void> {
    if (this.shuttingDown) return;
    this.shuttingDown = true;
    await Promise.all(
      this.active().map(async (record) => {
        try {
          await this.stop(record.processId);
          const tracked = this.tracked.get(record.processId);
          if (tracked && tracked.record.status !== "orphaned") {
            await Promise.race([tracked.settle, delay(STOP_GRACE_MS + 1_000)]);
          }
        } catch (error) {
          const tracked = this.tracked.get(record.processId);
          if (tracked) {
            this.publish(
              tracked,
              "lost",
              error instanceof Error ? error.message : String(error),
            );
          }
        }
      }),
    );
    const stillActive = this.active();
    if (stillActive.length > 0) {
      throw new Error(
        `could not stop all supervised work: ${stillActive
          .map((record) => record.processId)
          .join(", ")}`,
      );
    }
    this.assertIdle();
  }

  async stopOwner(ownerJobId: string): Promise<void> {
    await Promise.all(
      this.active(ownerJobId).map(async (record) => {
        await this.stop(record.processId);
        const tracked = this.tracked.get(record.processId);
        if (tracked && tracked.record.status !== "orphaned") {
          await Promise.race([tracked.settle, delay(STOP_GRACE_MS + 1_000)]);
        }
      }),
    );
    this.assertIdle(ownerJobId);
  }
}
