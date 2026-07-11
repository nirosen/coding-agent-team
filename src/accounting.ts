import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { canonicalJson, sha256 } from "./policy.js";

export const ACCOUNTING_CONFIG_SCHEMA =
  "coding-agent-team-accounting-config/v1";
export const ACCOUNTING_EVENTS_SCHEMA =
  "coding-agent-team-accounting-events/v1";
export const RECONCILIATION_SCHEMA =
  "coding-agent-team-spend-reconciliation/v1";

const IDENTIFIER = /^[A-Za-z0-9_.:@-]{1,128}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const INTEGER = /^(?:0|[1-9][0-9]{0,39})$/;

export type AccountingSource = {
  slot: string;
  path: string;
};

export type AccountingConfig = {
  schema: typeof ACCOUNTING_CONFIG_SCHEMA;
  adapter: {
    argv: string[];
    cwd: string;
    executableSha256: string;
    envAllowlist: string[];
    timeoutMs: number;
  };
  sources: AccountingSource[];
  limits: Record<string, string>;
};

export type AccountingEvent = {
  id: string;
  phase: string;
  units: Record<string, string>;
};

export type AccountingEvents = {
  schema: typeof ACCOUNTING_EVENTS_SCHEMA;
  watermarks: Record<string, string>;
  events: AccountingEvent[];
};

export type SpendReconciliation = {
  schema: typeof RECONCILIATION_SCHEMA;
  id: string;
  phase: string;
  createdAt: number;
  previousSha256: string | null;
  sourceSha256: Record<string, string>;
  watermarks: Record<string, string>;
  eventIds: string[];
  eventSha256: Record<string, string>;
  delta: Record<string, string>;
  totals: Record<string, string>;
  limits: Record<string, string>;
  verdict: "pass" | "over_budget";
};

function asObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exact(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
): void {
  const allowed = new Set(keys);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw new Error(`${label} contains unknown field: ${unknown}`);
  const missing = keys.find(
    (key) => !Object.prototype.hasOwnProperty.call(value, key),
  );
  if (missing) throw new Error(`${label} is missing field: ${missing}`);
}

function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function integer(value: unknown, label: string): string {
  if (typeof value !== "string" || !INTEGER.test(value)) {
    throw new Error(`${label} must be a non-negative canonical integer string`);
  }
  return value;
}

function integerMap(value: unknown, label: string): Record<string, string> {
  const raw = asObject(value, label);
  const entries = Object.entries(raw);
  if (entries.length === 0 || entries.length > 128) {
    throw new Error(`${label} must contain between 1 and 128 units`);
  }
  return Object.fromEntries(
    entries
      .map(([unit, amount]) => [
        identifier(unit, `${label} unit`),
        integer(amount, `${label}.${unit}`),
      ])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

function safePath(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${label} is invalid`);
  }
  if (!path.isAbsolute(value)) {
    const normalized = path.normalize(value);
    if (
      normalized !== value ||
      normalized === ".." ||
      normalized.startsWith(`..${path.sep}`)
    ) {
      throw new Error(`${label} must be normalized and cannot escape`);
    }
  }
  return value;
}

function argv(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) {
    throw new Error(`${label} must contain 1 to 256 arguments`);
  }
  return value.map((argument, index) => {
    if (
      typeof argument !== "string" ||
      argument.length === 0 ||
      /[\u0000\r\n]/.test(argument)
    ) {
      throw new Error(`${label}[${index}] is invalid`);
    }
    return argument;
  });
}

export function validateAccountingConfig(value: unknown): AccountingConfig {
  const config = asObject(value, "accounting config");
  exact(config, ["schema", "adapter", "sources", "limits"], "accounting config");
  if (config.schema !== ACCOUNTING_CONFIG_SCHEMA) {
    throw new Error(
      `unsupported accounting config schema: ${String(config.schema)}`,
    );
  }
  const adapter = asObject(config.adapter, "accounting adapter");
  exact(
    adapter,
    ["argv", "cwd", "executableSha256", "envAllowlist", "timeoutMs"],
    "accounting adapter",
  );
  const adapterArgv = argv(adapter.argv, "accounting adapter argv");
  if (!path.isAbsolute(adapterArgv[0]!)) {
    throw new Error("accounting adapter executable must be an absolute path");
  }
  if (
    typeof adapter.executableSha256 !== "string" ||
    !SHA256.test(adapter.executableSha256)
  ) {
    throw new Error("accounting adapter executableSha256 is invalid");
  }
  if (
    !Array.isArray(adapter.envAllowlist) ||
    adapter.envAllowlist.length > 128
  ) {
    throw new Error("accounting adapter envAllowlist is invalid");
  }
  const envAllowlist = adapter.envAllowlist.map((name, index) => {
    if (
      typeof name !== "string" ||
      !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)
    ) {
      throw new Error(`accounting adapter envAllowlist[${index}] is invalid`);
    }
    return name;
  });
  if (
    typeof adapter.timeoutMs !== "number" ||
    !Number.isSafeInteger(adapter.timeoutMs) ||
    adapter.timeoutMs < 1 ||
    adapter.timeoutMs > 5 * 60 * 1000
  ) {
    throw new Error("accounting adapter timeoutMs is invalid");
  }
  if (!Array.isArray(config.sources) || config.sources.length > 128) {
    throw new Error("accounting sources must contain at most 128 entries");
  }
  const sources = config.sources.map((raw, index): AccountingSource => {
    const source = asObject(raw, `accounting sources[${index}]`);
    exact(source, ["slot", "path"], `accounting sources[${index}]`);
    return {
      slot: identifier(source.slot, `accounting sources[${index}].slot`),
      path: safePath(source.path, `accounting sources[${index}].path`),
    };
  });
  if (new Set(sources.map((source) => source.slot)).size !== sources.length) {
    throw new Error("accounting source slots must be unique");
  }
  return {
    schema: ACCOUNTING_CONFIG_SCHEMA,
    adapter: {
      argv: adapterArgv,
      cwd: safePath(adapter.cwd, "accounting adapter cwd"),
      executableSha256: adapter.executableSha256,
      envAllowlist,
      timeoutMs: adapter.timeoutMs,
    },
    sources,
    limits: integerMap(config.limits, "accounting limits"),
  };
}

export function validateAccountingEvents(value: unknown): AccountingEvents {
  const output = asObject(value, "accounting adapter output");
  exact(
    output,
    ["schema", "watermarks", "events"],
    "accounting adapter output",
  );
  if (output.schema !== ACCOUNTING_EVENTS_SCHEMA) {
    throw new Error(
      `unsupported accounting event schema: ${String(output.schema)}`,
    );
  }
  const watermarks = integerMap(output.watermarks, "accounting watermarks");
  if (
    !Array.isArray(output.events) ||
    output.events.length > 100_000
  ) {
    throw new Error("accounting events must contain at most 100000 entries");
  }
  const events = output.events.map((raw, index): AccountingEvent => {
    const event = asObject(raw, `accounting events[${index}]`);
    exact(event, ["id", "phase", "units"], `accounting events[${index}]`);
    return {
      id: identifier(event.id, `accounting events[${index}].id`),
      phase: identifier(event.phase, `accounting events[${index}].phase`),
      units: integerMap(event.units, `accounting events[${index}].units`),
    };
  });
  const ids = events.map((event) => event.id);
  if (new Set(ids).size !== ids.length) {
    throw new Error("accounting output contains duplicate event ids");
  }
  return {
    schema: ACCOUNTING_EVENTS_SCHEMA,
    watermarks,
    events,
  };
}

function hashRegularFile(filePath: string, maximumBytes: number): string {
  const before = fs.lstatSync(filePath);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size > maximumBytes
  ) {
    throw new Error(`accounting input must be a regular file: ${filePath}`);
  }
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== before.ino) {
      throw new Error(`accounting input changed while opening: ${filePath}`);
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
      throw new Error(`accounting input changed while hashing: ${filePath}`);
    }
    return hash.digest("hex");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function resolveAgainst(workspace: string, candidate: string): string {
  const lexical = path.isAbsolute(candidate)
    ? path.resolve(candidate)
    : path.resolve(workspace, candidate);
  const lexicalInfo = fs.lstatSync(lexical);
  if (lexicalInfo.isSymbolicLink()) {
    throw new Error(`accounting path cannot be a symlink: ${candidate}`);
  }
  const resolved = fs.realpathSync(lexical);
  if (!path.isAbsolute(candidate)) {
    const workspaceRoot = fs.realpathSync(workspace);
    const root = `${workspaceRoot}${path.sep}`;
    if (resolved !== workspaceRoot && !resolved.startsWith(root)) {
      throw new Error(`accounting path escapes workspace: ${candidate}`);
    }
  }
  return resolved;
}

export function accountingSourceHashes(
  config: AccountingConfig,
  workspace: string,
): Record<string, string> {
  return Object.fromEntries(
    config.sources
      .map((source) => [
        source.slot,
        hashRegularFile(resolveAgainst(workspace, source.path), 256 * 1024 * 1024),
      ])
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

export function runAccountingAdapter(
  config: AccountingConfig,
  workspace: string,
): { output: AccountingEvents; sourceSha256: Record<string, string> } {
  const executable = path.resolve(config.adapter.argv[0]!);
  if (
    hashRegularFile(executable, 512 * 1024 * 1024) !==
    config.adapter.executableSha256
  ) {
    throw new Error("accounting adapter executable digest changed");
  }
  const sourceSha256 = accountingSourceHashes(config, workspace);
  const env: NodeJS.ProcessEnv = {};
  for (const name of new Set([
    "HOME",
    "PATH",
    "TMPDIR",
    ...config.adapter.envAllowlist,
  ])) {
    if (process.env[name] !== undefined) env[name] = process.env[name];
  }
  env.CODING_AGENT_ACCOUNTING_SOURCES = canonicalJson(
    Object.fromEntries(
      config.sources.map((source) => [
        source.slot,
        resolveAgainst(workspace, source.path),
      ]),
    ),
  );
  const cwd = resolveAgainst(workspace, config.adapter.cwd);
  const result = spawnSync(executable, config.adapter.argv.slice(1), {
    cwd,
    env,
    encoding: "utf8",
    timeout: config.adapter.timeoutMs,
    maxBuffer: 4 * 1024 * 1024,
    shell: false,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `accounting adapter exited ${String(result.status)}: ${(result.stderr ?? "").slice(-2000)}`,
    );
  }
  const afterSourceSha256 = accountingSourceHashes(config, workspace);
  if (canonicalJson(sourceSha256) !== canonicalJson(afterSourceSha256)) {
    throw new Error("accounting sources changed while the adapter was running");
  }
  return {
    output: validateAccountingEvents(JSON.parse(result.stdout)),
    sourceSha256,
  };
}

export function reconcileSpend(
  config: AccountingConfig,
  phase: string,
  adapter: { output: AccountingEvents; sourceSha256: Record<string, string> },
  previous?: SpendReconciliation,
  now = Date.now(),
): SpendReconciliation {
  identifier(phase, "reconciliation phase");
  const priorEvents = new Set(previous?.eventIds ?? []);
  const eventSha256: Record<string, string> = {
    ...(previous?.eventSha256 ?? {}),
  };
  const allIds = new Set(priorEvents);
  const delta = new Map<string, bigint>();
  for (const event of adapter.output.events) {
    if (allIds.has(event.id)) {
      if (!priorEvents.has(event.id)) {
        throw new Error(`duplicate accounting event: ${event.id}`);
      }
      if (eventSha256[event.id] !== sha256(canonicalJson(event))) {
        throw new Error(`accounting event changed after reconciliation: ${event.id}`);
      }
      continue;
    }
    allIds.add(event.id);
    eventSha256[event.id] = sha256(canonicalJson(event));
    for (const [unit, amount] of Object.entries(event.units)) {
      delta.set(unit, (delta.get(unit) ?? 0n) + BigInt(amount));
    }
  }
  if (previous) {
    for (const slot of Object.keys(previous.watermarks)) {
      if (adapter.output.watermarks[slot] === undefined) {
        throw new Error(`accounting watermark disappeared for ${slot}`);
      }
    }
    for (const [slot, watermark] of Object.entries(adapter.output.watermarks)) {
      const prior = previous.watermarks[slot];
      if (prior !== undefined && BigInt(watermark) < BigInt(prior)) {
        throw new Error(`accounting watermark regressed for ${slot}`);
      }
    }
  }
  const units = new Set([
    ...Object.keys(config.limits),
    ...Object.keys(previous?.totals ?? {}),
    ...delta.keys(),
  ]);
  const totals: Record<string, string> = {};
  const deltaRecord: Record<string, string> = {};
  let overBudget = false;
  for (const unit of [...units].sort()) {
    const increment = delta.get(unit) ?? 0n;
    const total = BigInt(previous?.totals[unit] ?? "0") + increment;
    deltaRecord[unit] = increment.toString();
    totals[unit] = total.toString();
    const limit = config.limits[unit];
    if (limit === undefined) {
      throw new Error(`accounting event uses unbudgeted unit: ${unit}`);
    }
    if (total > BigInt(limit)) overBudget = true;
  }
  const reconciliation: SpendReconciliation = {
    schema: RECONCILIATION_SCHEMA,
    id: `reconcile-${crypto.randomUUID()}`,
    phase,
    createdAt: now,
    previousSha256: previous ? sha256(canonicalJson(previous)) : null,
    sourceSha256: Object.fromEntries(
      Object.entries(adapter.sourceSha256).sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ),
    watermarks: adapter.output.watermarks,
    eventIds: [...allIds].sort(),
    eventSha256: Object.fromEntries(
      Object.entries(eventSha256).sort(([left], [right]) =>
        left.localeCompare(right),
      ),
    ),
    delta: deltaRecord,
    totals,
    limits: config.limits,
    verdict: overBudget ? "over_budget" : "pass",
  };
  return reconciliation;
}

export function reconciliationSha256(value: SpendReconciliation): string {
  return sha256(canonicalJson(value));
}
