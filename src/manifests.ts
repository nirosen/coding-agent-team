import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson, sha256 } from "./policy.js";

export const COMMAND_MANIFEST_SCHEMA =
  "coding-agent-team-command-manifest/v1";
export const TEST_MANIFEST_SCHEMA = "coding-agent-team-test-manifest/v1";

const IDENTIFIER = /^[A-Za-z0-9_.:@-]{1,128}$/;
const SHA256 = /^[0-9a-f]{64}$/;

export type ManifestCommandKind = "command" | "test" | "review";

export type ManifestCommand = {
  id: string;
  phase: string;
  kind: ManifestCommandKind;
  argv: string[];
  cwd: string;
  timeoutMs: number;
  envAllowlist: string[];
  executableSha256: string;
  expectedExitCodes: number[];
};

export type CommandManifest = {
  schema: typeof COMMAND_MANIFEST_SCHEMA;
  commands: ManifestCommand[];
};

export type TestSelection = {
  id: string;
  phase: string;
  commandId: string;
  tests: string[];
  configPath: string | null;
  configSha256: string | null;
};

export type TestManifest = {
  schema: typeof TEST_MANIFEST_SCHEMA;
  selections: TestSelection[];
};

export type FrozenArtifactRef = {
  path: string;
  sha256: string;
};

export type FrozenRunArtifacts = {
  task: FrozenArtifactRef;
  profile: FrozenArtifactRef;
  commands: FrozenArtifactRef;
  tests: FrozenArtifactRef;
  accounting: FrozenArtifactRef;
  binding: FrozenArtifactRef;
};

function object(value: unknown, label: string): Record<string, unknown> {
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

function digestOrNull(value: unknown, label: string): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be lowercase SHA-256 hex or null`);
  }
  return value;
}

function safeArgv(value: unknown, label: string): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 256) {
    throw new Error(`${label} must contain 1 to 256 arguments`);
  }
  let totalBytes = 0;
  return value.map((argument, index) => {
    if (
      typeof argument !== "string" ||
      argument.length === 0 ||
      /[\u0000\r\n]/.test(argument)
    ) {
      throw new Error(`${label}[${index}] is invalid`);
    }
    totalBytes += Buffer.byteLength(argument, "utf8");
    if (totalBytes > 256 * 1024) {
      throw new Error(`${label} exceeds 256 KiB`);
    }
    return argument;
  });
}

function relativeCwd(value: unknown, label: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    path.isAbsolute(value) ||
    /[\u0000-\u001f\u007f]/.test(value)
  ) {
    throw new Error(`${label} must be a safe relative path`);
  }
  const normalized = path.normalize(value);
  if (
    normalized === ".." ||
    normalized.startsWith(`..${path.sep}`) ||
    normalized !== value
  ) {
    throw new Error(`${label} must stay inside the workspace and be normalized`);
  }
  return value;
}

export function validateCommandManifest(value: unknown): CommandManifest {
  const manifest = object(value, "command manifest");
  exact(manifest, ["schema", "commands"], "command manifest");
  if (manifest.schema !== COMMAND_MANIFEST_SCHEMA) {
    throw new Error(
      `unsupported command manifest schema: ${String(manifest.schema)}`,
    );
  }
  if (
    !Array.isArray(manifest.commands) ||
    manifest.commands.length === 0 ||
    manifest.commands.length > 512
  ) {
    throw new Error("command manifest must contain 1 to 512 commands");
  }
  const commands = manifest.commands.map((raw, index): ManifestCommand => {
    const command = object(raw, `commands[${index}]`);
    exact(
      command,
      [
        "id",
        "phase",
        "kind",
        "argv",
        "cwd",
        "timeoutMs",
        "envAllowlist",
        "executableSha256",
        "expectedExitCodes",
      ],
      `commands[${index}]`,
    );
    const id = identifier(command.id, `commands[${index}].id`);
    const phase = identifier(command.phase, `commands[${index}].phase`);
    if (
      command.kind !== "command" &&
      command.kind !== "test" &&
      command.kind !== "review"
    ) {
      throw new Error(`commands[${index}].kind is invalid`);
    }
    if (
      typeof command.timeoutMs !== "number" ||
      !Number.isSafeInteger(command.timeoutMs) ||
      command.timeoutMs < 1 ||
      command.timeoutMs > 7 * 24 * 60 * 60 * 1000
    ) {
      throw new Error(`commands[${index}].timeoutMs is invalid`);
    }
    if (
      !Array.isArray(command.envAllowlist) ||
      command.envAllowlist.length > 128
    ) {
      throw new Error(`commands[${index}].envAllowlist is invalid`);
    }
    const envAllowlist = command.envAllowlist.map((name, envIndex) => {
      if (
        typeof name !== "string" ||
        !/^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(name)
      ) {
        throw new Error(
          `commands[${index}].envAllowlist[${envIndex}] is invalid`,
        );
      }
      return name;
    });
    if (new Set(envAllowlist).size !== envAllowlist.length) {
      throw new Error(`commands[${index}].envAllowlist contains duplicates`);
    }
    if (
      !Array.isArray(command.expectedExitCodes) ||
      command.expectedExitCodes.length === 0 ||
      command.expectedExitCodes.length > 32
    ) {
      throw new Error(`commands[${index}].expectedExitCodes is invalid`);
    }
    const expectedExitCodes = command.expectedExitCodes.map((code) => {
      if (
        typeof code !== "number" ||
        !Number.isSafeInteger(code) ||
        code < 0 ||
        code > 255
      ) {
        throw new Error(`commands[${index}] contains an invalid exit code`);
      }
      return code;
    });
    return {
      id,
      phase,
      kind: command.kind,
      argv: safeArgv(command.argv, `commands[${index}].argv`),
      cwd: relativeCwd(command.cwd, `commands[${index}].cwd`),
      timeoutMs: command.timeoutMs,
      envAllowlist,
      executableSha256:
        digestOrNull(
          command.executableSha256,
          `commands[${index}].executableSha256`,
        ) ??
        (() => {
          throw new Error(
            `commands[${index}].executableSha256 must be pinned`,
          );
        })(),
      expectedExitCodes,
    };
  });
  const ids = commands.map((command) => command.id);
  if (new Set(ids).size !== ids.length) {
    throw new Error("command manifest command ids must be unique");
  }
  return { schema: COMMAND_MANIFEST_SCHEMA, commands };
}

export function validateTestManifest(
  value: unknown,
  commands?: CommandManifest,
): TestManifest {
  const manifest = object(value, "test manifest");
  exact(manifest, ["schema", "selections"], "test manifest");
  if (manifest.schema !== TEST_MANIFEST_SCHEMA) {
    throw new Error(
      `unsupported test manifest schema: ${String(manifest.schema)}`,
    );
  }
  if (
    !Array.isArray(manifest.selections) ||
    manifest.selections.length > 512
  ) {
    throw new Error("test manifest selections must contain at most 512 entries");
  }
  const selections = manifest.selections.map((raw, index): TestSelection => {
    const selection = object(raw, `selections[${index}]`);
    exact(
      selection,
      [
        "id",
        "phase",
        "commandId",
        "tests",
        "configPath",
        "configSha256",
      ],
      `selections[${index}]`,
    );
    if (
      !Array.isArray(selection.tests) ||
      selection.tests.length === 0 ||
      selection.tests.length > 10_000
    ) {
      throw new Error(`selections[${index}].tests is invalid`);
    }
    const tests = selection.tests.map((test, testIndex) => {
      if (
        typeof test !== "string" ||
        test.length === 0 ||
        test.length > 4096 ||
        /[\u0000\r\n]/.test(test)
      ) {
        throw new Error(`selections[${index}].tests[${testIndex}] is invalid`);
      }
      return test;
    });
    if (new Set(tests).size !== tests.length) {
      throw new Error(`selections[${index}].tests contains duplicates`);
    }
    const configPath =
      selection.configPath === null
        ? null
        : relativeCwd(
            selection.configPath,
            `selections[${index}].configPath`,
          );
    const configSha256 = digestOrNull(
      selection.configSha256,
      `selections[${index}].configSha256`,
    );
    if ((configPath === null) !== (configSha256 === null)) {
      throw new Error(
        `selections[${index}] configPath and configSha256 must both be null or pinned`,
      );
    }
    return {
      id: identifier(selection.id, `selections[${index}].id`),
      phase: identifier(selection.phase, `selections[${index}].phase`),
      commandId: identifier(
        selection.commandId,
        `selections[${index}].commandId`,
      ),
      tests,
      configPath,
      configSha256,
    };
  });
  const ids = selections.map((selection) => selection.id);
  if (new Set(ids).size !== ids.length) {
    throw new Error("test selection ids must be unique");
  }
  if (commands) {
    const commandById = new Map(
      commands.commands.map((command) => [command.id, command]),
    );
    for (const selection of selections) {
      const command = commandById.get(selection.commandId);
      if (
        !command ||
        command.kind !== "test" ||
        command.phase !== selection.phase
      ) {
        throw new Error(
          `test selection ${selection.id} does not reference a matching test command`,
        );
      }
    }
  }
  return { schema: TEST_MANIFEST_SCHEMA, selections };
}

function privateDirectory(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(dir);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`artifact path must be a real directory: ${dir}`);
  }
  fs.chmodSync(dir, 0o700);
}

function syncDirectory(dir: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(dir, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "EINVAL" && code !== "ENOTSUP" && code !== "EISDIR") {
      throw error;
    }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function writeOnce(filePath: string, contents: string): FrozenArtifactRef {
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  syncDirectory(path.dirname(filePath));
  return { path: filePath, sha256: sha256(contents.trimEnd()) };
}

function writeRaw(filePath: string, contents: Buffer): FrozenArtifactRef {
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    fs.writeFileSync(fd, contents);
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  syncDirectory(path.dirname(filePath));
  return { path: filePath, sha256: sha256(contents) };
}

export function freezeRunArtifacts(
  stateDirectory: string,
  teamRunId: string,
  artifacts: {
    task: Buffer;
    profile: unknown;
    commands: CommandManifest;
    tests: TestManifest;
    accounting: unknown;
    binding: unknown;
  },
): FrozenRunArtifacts {
  const runDirectory = path.join(stateDirectory, teamRunId);
  const artifactDirectory = path.join(runDirectory, "artifacts");
  privateDirectory(runDirectory);
  privateDirectory(artifactDirectory);
  const writeJson = (name: string, value: unknown): FrozenArtifactRef =>
    writeOnce(
      path.join(artifactDirectory, name),
      `${canonicalJson(value)}\n`,
    );
  return {
    task: writeRaw(path.join(artifactDirectory, "task.md"), artifacts.task),
    profile: writeJson("profile.json", artifacts.profile),
    commands: writeJson("commands.json", artifacts.commands),
    tests: writeJson("tests.json", artifacts.tests),
    accounting: writeJson("accounting.json", artifacts.accounting),
    binding: writeJson("binding.json", artifacts.binding),
  };
}

export function commandDigest(command: ManifestCommand): string {
  return sha256(
    canonicalJson({
      argv: command.argv,
      cwd: command.cwd,
      envAllowlist: command.envAllowlist,
      executableSha256: command.executableSha256,
    }),
  );
}

export function receiptId(commandId: string): string {
  return `receipt-${commandId}-${crypto.randomUUID()}`;
}
