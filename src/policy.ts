import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const POLICY_PROFILE_SCHEMA = "coding-agent-team-policy-profile/v1";
export const RUN_BINDING_SCHEMA = "coding-agent-team-run-binding/v1";

const MAX_ARTIFACT_BYTES = 4 * 1024 * 1024;
const MAX_BINDING_TTL_MS = 24 * 60 * 60 * 1000;
const IDENTIFIER = /^[A-Za-z0-9_.:@-]{1,128}$/;
const SHA256 = /^[0-9a-f]{64}$/;

export type TransitionRequirement =
  | "commands"
  | "tests"
  | "receipts"
  | "review"
  | "accounting"
  | "authorization"
  | "idle";

export type PolicyTransition = {
  from: string;
  to: string;
  requires: TransitionRequirement[];
};

export type PolicyProfile = {
  schema: typeof POLICY_PROFILE_SCHEMA;
  profileId: string;
  profileVersion: string;
  enforcement: "hard";
  phases: string[];
  terminalPhase: string;
  transitions: PolicyTransition[];
};

export type RunBinding = {
  schema: typeof RUN_BINDING_SCHEMA;
  teamRunId: string;
  createdAt: number;
  expiresAt: number;
  issuer: string;
  taskSha256: string;
  profileSha256: string;
  commandManifestSha256: string;
  testManifestSha256: string;
  accountingConfigSha256: string;
  workspace: {
    cwd: string;
    gitHead: string | null;
  };
  signature: string;
};

export type UnsignedRunBinding = Omit<RunBinding, "signature">;

export type LoadedRunBundle = {
  directory: string;
  task: string;
  taskBytes: Buffer;
  profile: PolicyProfile;
  commandManifest: unknown;
  testManifest: unknown;
  accountingConfig: unknown;
  binding: RunBinding;
  canonical: {
    profile: string;
    commandManifest: string;
    testManifest: string;
    accountingConfig: string;
  };
};

function assertObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return value as Record<string, unknown>;
}

function assertExactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  required: readonly string[],
  label: string,
): void {
  const allowedSet = new Set(allowed);
  const unknown = Object.keys(value).find((key) => !allowedSet.has(key));
  if (unknown) throw new Error(`${label} contains unknown field: ${unknown}`);
  const missing = required.find(
    (key) => !Object.prototype.hasOwnProperty.call(value, key),
  );
  if (missing) throw new Error(`${label} is missing field: ${missing}`);
}

function assertIdentifier(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new Error(`${label} is invalid`);
  }
}

function assertSha256(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new Error(`${label} must be lowercase SHA-256 hex`);
  }
}

function assertEpoch(value: unknown, label: string): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    throw new Error(`${label} must be epoch milliseconds`);
  }
}

/**
 * Deterministic JSON used for content hashes and signatures. Only the JSON
 * value domain is accepted, and numbers must be safe integers so two runtimes
 * cannot disagree about serialization.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new Error("canonical JSON numbers must be safe integers");
    }
    return String(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const object = value as Record<string, unknown>;
    const entries = Object.keys(object)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new Error(`unsupported canonical JSON value: ${typeof value}`);
}

export function sha256(value: string | Buffer): string {
  return crypto.createHash("sha256").update(value).digest("hex");
}

export function artifactSha256(value: unknown): string {
  return sha256(canonicalJson(value));
}

export function validatePolicyProfile(value: unknown): PolicyProfile {
  const profile = assertObject(value, "policy profile");
  assertExactKeys(
    profile,
    [
      "schema",
      "profileId",
      "profileVersion",
      "enforcement",
      "phases",
      "terminalPhase",
      "transitions",
    ],
    [
      "schema",
      "profileId",
      "profileVersion",
      "enforcement",
      "phases",
      "terminalPhase",
      "transitions",
    ],
    "policy profile",
  );
  if (profile.schema !== POLICY_PROFILE_SCHEMA) {
    throw new Error(`unsupported policy profile schema: ${String(profile.schema)}`);
  }
  assertIdentifier(profile.profileId, "profileId");
  assertIdentifier(profile.profileVersion, "profileVersion");
  if (profile.enforcement !== "hard") {
    throw new Error("policy enforcement must be hard");
  }
  if (
    !Array.isArray(profile.phases) ||
    profile.phases.length < 2 ||
    profile.phases.length > 32
  ) {
    throw new Error("policy phases must contain between 2 and 32 entries");
  }
  const phases = profile.phases.map((phase, index) => {
    assertIdentifier(phase, `phases[${index}]`);
    return phase;
  });
  if (new Set(phases).size !== phases.length) {
    throw new Error("policy phases must be unique");
  }
  assertIdentifier(profile.terminalPhase, "terminalPhase");
  if (!phases.includes(profile.terminalPhase)) {
    throw new Error("terminalPhase must be listed in phases");
  }
  if (profile.terminalPhase !== phases.at(-1)) {
    throw new Error("terminalPhase must be the final declared phase");
  }
  if (!Array.isArray(profile.transitions) || profile.transitions.length < 1) {
    throw new Error("policy transitions are required");
  }
  const allowedRequirements = new Set<TransitionRequirement>([
    "commands",
    "tests",
    "receipts",
    "review",
    "accounting",
    "authorization",
    "idle",
  ]);
  const transitions = profile.transitions.map((raw, index): PolicyTransition => {
    const transition = assertObject(raw, `transitions[${index}]`);
    assertExactKeys(
      transition,
      ["from", "to", "requires"],
      ["from", "to", "requires"],
      `transitions[${index}]`,
    );
    assertIdentifier(transition.from, `transitions[${index}].from`);
    assertIdentifier(transition.to, `transitions[${index}].to`);
    if (
      !phases.includes(transition.from) ||
      !phases.includes(transition.to) ||
      transition.from === transition.to
    ) {
      throw new Error(`transitions[${index}] references invalid phases`);
    }
    if (
      !Array.isArray(transition.requires) ||
      transition.requires.length === 0
    ) {
      throw new Error(`transitions[${index}].requires cannot be empty`);
    }
    const requires = transition.requires.map((requirement) => {
      if (
        typeof requirement !== "string" ||
        !allowedRequirements.has(requirement as TransitionRequirement)
      ) {
        throw new Error(
          `transitions[${index}] has unsupported requirement: ${String(requirement)}`,
        );
      }
      return requirement as TransitionRequirement;
    });
    if (new Set(requires).size !== requires.length) {
      throw new Error(`transitions[${index}].requires contains duplicates`);
    }
    return {
      from: transition.from,
      to: transition.to,
      requires,
    };
  });
  const edges = transitions.map(({ from, to }) => `${from}->${to}`);
  if (new Set(edges).size !== edges.length) {
    throw new Error("policy transitions must be unique");
  }
  if (transitions.length !== phases.length - 1) {
    throw new Error("hard policy must define one transition between each phase");
  }
  for (let index = 0; index < transitions.length; index++) {
    const transition = transitions[index]!;
    if (
      transition.from !== phases[index] ||
      transition.to !== phases[index + 1]
    ) {
      throw new Error("hard policy transitions must follow declared phase order");
    }
    for (const required of ["accounting", "authorization", "idle"] as const) {
      if (!transition.requires.includes(required)) {
        throw new Error(`hard policy transition must require ${required}`);
      }
    }
  }
  return {
    schema: POLICY_PROFILE_SCHEMA,
    profileId: profile.profileId,
    profileVersion: profile.profileVersion,
    enforcement: "hard",
    phases,
    terminalPhase: profile.terminalPhase,
    transitions,
  };
}

export function validateRunBinding(value: unknown): RunBinding {
  const binding = assertObject(value, "run binding");
  assertExactKeys(
    binding,
    [
      "schema",
      "teamRunId",
      "createdAt",
      "expiresAt",
      "issuer",
      "taskSha256",
      "profileSha256",
      "commandManifestSha256",
      "testManifestSha256",
      "accountingConfigSha256",
      "workspace",
      "signature",
    ],
    [
      "schema",
      "teamRunId",
      "createdAt",
      "expiresAt",
      "issuer",
      "taskSha256",
      "profileSha256",
      "commandManifestSha256",
      "testManifestSha256",
      "accountingConfigSha256",
      "workspace",
      "signature",
    ],
    "run binding",
  );
  if (binding.schema !== RUN_BINDING_SCHEMA) {
    throw new Error(`unsupported run binding schema: ${String(binding.schema)}`);
  }
  assertIdentifier(binding.teamRunId, "run binding teamRunId");
  assertIdentifier(binding.issuer, "run binding issuer");
  assertEpoch(binding.createdAt, "run binding createdAt");
  assertEpoch(binding.expiresAt, "run binding expiresAt");
  if (
    binding.expiresAt <= binding.createdAt ||
    binding.expiresAt - binding.createdAt > MAX_BINDING_TTL_MS
  ) {
    throw new Error(`run binding TTL must be in (0, ${MAX_BINDING_TTL_MS}]ms`);
  }
  for (const field of [
    "taskSha256",
    "profileSha256",
    "commandManifestSha256",
    "testManifestSha256",
    "accountingConfigSha256",
  ] as const) {
    assertSha256(binding[field], `run binding ${field}`);
  }
  const workspace = assertObject(binding.workspace, "run binding workspace");
  assertExactKeys(
    workspace,
    ["cwd", "gitHead"],
    ["cwd", "gitHead"],
    "run binding workspace",
  );
  if (
    typeof workspace.cwd !== "string" ||
    !path.isAbsolute(workspace.cwd) ||
    /[\u0000-\u001f\u007f]/.test(workspace.cwd)
  ) {
    throw new Error("run binding workspace cwd must be an absolute safe path");
  }
  if (
    workspace.gitHead !== null &&
    (typeof workspace.gitHead !== "string" ||
      !/^[0-9a-f]{40,64}$/.test(workspace.gitHead))
  ) {
    throw new Error("run binding workspace gitHead is invalid");
  }
  if (
    typeof binding.signature !== "string" ||
    !/^[A-Za-z0-9+/]{86}==$/.test(binding.signature) ||
    Buffer.from(binding.signature, "base64").length !== 64
  ) {
    throw new Error("run binding signature is invalid");
  }
  return {
    schema: RUN_BINDING_SCHEMA,
    teamRunId: binding.teamRunId,
    createdAt: binding.createdAt,
    expiresAt: binding.expiresAt,
    issuer: binding.issuer,
    taskSha256: binding.taskSha256 as string,
    profileSha256: binding.profileSha256 as string,
    commandManifestSha256: binding.commandManifestSha256 as string,
    testManifestSha256: binding.testManifestSha256 as string,
    accountingConfigSha256: binding.accountingConfigSha256 as string,
    workspace: {
      cwd: workspace.cwd,
      gitHead: workspace.gitHead as string | null,
    },
    signature: binding.signature,
  };
}

export function canonicalRunBindingPayload(
  value: UnsignedRunBinding | RunBinding,
): Buffer {
  const { signature: _signature, ...unsigned } = value as RunBinding;
  return Buffer.from(canonicalJson(unsigned), "utf8");
}

export function signRunBinding(
  value: UnsignedRunBinding,
  privateKeyPem: string | Buffer,
): RunBinding {
  const key = crypto.createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("run-binding private key must be Ed25519");
  }
  return validateRunBinding({
    ...value,
    signature: crypto
      .sign(null, canonicalRunBindingPayload(value), key)
      .toString("base64"),
  });
}

export function verifyRunBinding(
  value: RunBinding,
  publicKeyPem: string | Buffer,
): boolean {
  try {
    const key = crypto.createPublicKey(publicKeyPem);
    return (
      key.asymmetricKeyType === "ed25519" &&
      crypto.verify(
        null,
        canonicalRunBindingPayload(value),
        key,
        Buffer.from(value.signature, "base64"),
      )
    );
  } catch {
    return false;
  }
}

function readBundleFile(
  directory: string,
  name: string,
  maximumBytes = MAX_ARTIFACT_BYTES,
): Buffer {
  const filePath = path.join(directory, name);
  const before = fs.lstatSync(filePath);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size > maximumBytes
  ) {
    throw new Error(`${name} must be a regular non-symlink file`);
  }
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== before.ino) {
      throw new Error(`${name} changed while opening`);
    }
    return fs.readFileSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function parseJsonArtifact(
  directory: string,
  name: string,
): { value: unknown; canonical: string } {
  const value = JSON.parse(readBundleFile(directory, name).toString("utf8"));
  return { value, canonical: canonicalJson(value) };
}

export function loadRunBundle(
  bundleDirectory: string,
  opts: {
    publicKeyPem: string | Buffer;
    expectedCwd: string;
    expectedGitHead?: string | null;
    now?: number;
  },
): LoadedRunBundle {
  const directory = fs.realpathSync(bundleDirectory);
  const dirInfo = fs.lstatSync(directory);
  if (!dirInfo.isDirectory() || dirInfo.isSymbolicLink()) {
    throw new Error("run bundle must be a real directory");
  }
  const taskBytes = readBundleFile(directory, "task.md", 1024 * 1024);
  const task = taskBytes.toString("utf8").trim();
  if (!task) throw new Error("run bundle task.md is empty");
  const profileArtifact = parseJsonArtifact(directory, "profile.json");
  const commandsArtifact = parseJsonArtifact(directory, "commands.json");
  const testsArtifact = parseJsonArtifact(directory, "tests.json");
  const accountingArtifact = parseJsonArtifact(directory, "accounting.json");
  const binding = validateRunBinding(
    JSON.parse(readBundleFile(directory, "binding.json", 128 * 1024).toString("utf8")),
  );
  const now = opts.now ?? Date.now();
  if (binding.createdAt > now + 5 * 60 * 1000 || binding.expiresAt <= now) {
    throw new Error("run binding is not currently valid");
  }
  if (!verifyRunBinding(binding, opts.publicKeyPem)) {
    throw new Error("run binding Ed25519 signature is invalid");
  }
  const expectedCwd = fs.realpathSync(opts.expectedCwd);
  if (path.resolve(binding.workspace.cwd) !== expectedCwd) {
    throw new Error("run binding workspace cwd does not match");
  }
  if (
    opts.expectedGitHead !== undefined &&
    binding.workspace.gitHead !== opts.expectedGitHead
  ) {
    throw new Error("run binding git HEAD does not match");
  }
  const actualHashes = {
    taskSha256: sha256(taskBytes),
    profileSha256: sha256(profileArtifact.canonical),
    commandManifestSha256: sha256(commandsArtifact.canonical),
    testManifestSha256: sha256(testsArtifact.canonical),
    accountingConfigSha256: sha256(accountingArtifact.canonical),
  };
  for (const [field, actual] of Object.entries(actualHashes)) {
    if (binding[field as keyof typeof actualHashes] !== actual) {
      throw new Error(`run bundle ${field} does not match signed binding`);
    }
  }
  return {
    directory,
    task,
    taskBytes,
    profile: validatePolicyProfile(profileArtifact.value),
    commandManifest: commandsArtifact.value,
    testManifest: testsArtifact.value,
    accountingConfig: accountingArtifact.value,
    binding,
    canonical: {
      profile: profileArtifact.canonical,
      commandManifest: commandsArtifact.canonical,
      testManifest: testsArtifact.canonical,
      accountingConfig: accountingArtifact.canonical,
    },
  };
}
