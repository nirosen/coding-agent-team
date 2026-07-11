import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const CONTROL_SCHEMA = "coding-agent-team-control/v1";
const MAX_CONTROL_BYTES = 64 * 1024;
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const MAX_TTL_MS = 60 * 60 * 1000;

export type ControlKind = "steer" | "authorization";
export type AuthorizationDecision = "approve" | "deny" | "cancel" | "choice";

export type ControlEnvelope = {
  schema: typeof CONTROL_SCHEMA;
  id: string;
  kind: ControlKind;
  createdAt: number;
  expiresAt: number;
  issuer: string;
  teamRunId: string;
  jobId?: string;
  text?: string;
  decision?: AuthorizationDecision;
  value?: string;
  questionSha256?: string;
  signature: string;
};

export type UnsignedControlEnvelope = Omit<ControlEnvelope, "signature">;

export type AuthorizationQuery = {
  teamRunId: string;
  jobId: string;
  question: string;
};

export type PendingControl = {
  envelope: ControlEnvelope;
  fileName: string;
};

export type ControlCapability = {
  schema: "coding-agent-team-capability/v1";
  active: boolean;
  teamRunId: string;
  cwd: string;
  pid: number;
  host: string;
  startedAt: number;
  stateFile: string;
  controlDir: string;
  publicKeyFingerprint: string;
};

export function defaultControlRoot(): string {
  return (
    process.env.CODING_AGENT_CONTROL_ROOT?.trim() ||
    path.join(os.homedir(), ".coding-agent-team", "control")
  );
}

export function defaultControlDir(teamRunId: string): string {
  return path.join(defaultControlRoot(), teamRunId);
}

export function normalizeQuestion(question: string): string {
  return question.replace(/\r\n/g, "\n").trim();
}

export function questionSha256(question: string): string {
  return crypto
    .createHash("sha256")
    .update(normalizeQuestion(question), "utf8")
    .digest("hex");
}

function isString(value: unknown, maxLength = 16_384): value is string {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    value.length <= maxLength
  );
}

export function redactSecrets(value: string): string {
  return value
    .replace(
      /\b(?:crsr_|cursor_|xox[baprs]-|sk-|ihub_)[A-Za-z0-9_.-]{8,}\b/gi,
      "[REDACTED_TOKEN]",
    )
    .replace(
      /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{16,}|nvapi-[A-Za-z0-9_-]{16,}|hf_[A-Za-z0-9]{20,}|npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{20,})\b/g,
      "[REDACTED_TOKEN]",
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
      "[REDACTED_JWT]",
    )
    .replace(
      /\bBearer\s+[A-Za-z0-9._~+/-]{12,}/gi,
      "Bearer [REDACTED_TOKEN]",
    )
    .replace(
      /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]+/gi,
      "[REDACTED_WEBHOOK]",
    )
    .replace(
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
      "[REDACTED_PRIVATE_KEY]",
    )
    .replace(
      /\b(?:api[_-]?key|token|secret)\s*[:=]\s*["']?[^\s"',;]+/gi,
      "[REDACTED_CREDENTIAL]",
    );
}

export function looksLikeSecret(value: string): boolean {
  return redactSecrets(value) !== value;
}

export function isUnsafeAuthorizationValue(value: string): boolean {
  return (
    looksLikeSecret(value) ||
    /^(?:all|anything|everything|future)$/i.test(value.trim())
  );
}

function assertSafeIdentifier(value: unknown, field: string): asserts value is string {
  if (!isString(value, 256) || !/^[A-Za-z0-9_.:@-]+$/.test(value)) {
    throw new Error(`${field} is invalid`);
  }
}

export function validateControlEnvelope(value: unknown): ControlEnvelope {
  if (!value || typeof value !== "object") {
    throw new Error("control message must be a JSON object");
  }
  const v = value as Record<string, unknown>;
  const allowedKeys = new Set([
    "schema",
    "id",
    "kind",
    "createdAt",
    "expiresAt",
    "issuer",
    "teamRunId",
    "jobId",
    "text",
    "decision",
    "value",
    "questionSha256",
    "signature",
  ]);
  const unknownKey = Object.keys(v).find((key) => !allowedKeys.has(key));
  if (unknownKey) throw new Error(`unknown control field: ${unknownKey}`);
  if (v.schema !== CONTROL_SCHEMA) {
    throw new Error(`unsupported control schema: ${String(v.schema)}`);
  }
  assertSafeIdentifier(v.id, "control id");
  assertSafeIdentifier(v.issuer, "control issuer");
  assertSafeIdentifier(v.teamRunId, "control teamRunId");
  if (v.kind !== "steer" && v.kind !== "authorization") {
    throw new Error(`unsupported control kind: ${String(v.kind)}`);
  }
  if (
    typeof v.createdAt !== "number" ||
    !Number.isSafeInteger(v.createdAt) ||
    v.createdAt < 0
  ) {
    throw new Error("control createdAt must be epoch milliseconds");
  }
  if (
    typeof v.expiresAt !== "number" ||
    !Number.isSafeInteger(v.expiresAt) ||
    v.expiresAt < 0
  ) {
    throw new Error("control expiresAt must be epoch milliseconds");
  }
  if (v.expiresAt <= v.createdAt || v.expiresAt - v.createdAt > MAX_TTL_MS) {
    throw new Error(`control TTL must be in (0, ${MAX_TTL_MS}]ms`);
  }
  if (
    !isString(v.signature, 1024) ||
    !/^[A-Za-z0-9+/]{86}==$/.test(v.signature) ||
    Buffer.from(v.signature, "base64").length !== 64
  ) {
    throw new Error("control signature is required");
  }

  if (v.kind === "steer") {
    if (!isString(v.text, 16_384)) throw new Error("steer text is required");
    if (looksLikeSecret(v.text)) {
      throw new Error("steer text contains a secret-shaped value");
    }
    if (v.jobId !== undefined) assertSafeIdentifier(v.jobId, "steer jobId");
    if (
      v.decision !== undefined ||
      v.value !== undefined ||
      v.questionSha256 !== undefined
    ) {
      throw new Error("steer contains authorization-only fields");
    }
  } else {
    if (v.text !== undefined) {
      throw new Error("authorization contains steer-only text");
    }
    assertSafeIdentifier(v.jobId, "authorization jobId");
    if (!/^[0-9a-f]{64}$/i.test(String(v.questionSha256))) {
      throw new Error("authorization questionSha256 must be SHA-256 hex");
    }
    if (
      v.decision !== "approve" &&
      v.decision !== "deny" &&
      v.decision !== "cancel" &&
      v.decision !== "choice"
    ) {
      throw new Error(`unsupported authorization decision: ${String(v.decision)}`);
    }
    if (
      v.decision === "choice" &&
      (!isString(v.value, 256) || isUnsafeAuthorizationValue(v.value))
    ) {
      throw new Error("choice authorization requires a value");
    }
    if (
      v.value !== undefined &&
      (!isString(v.value, 256) || isUnsafeAuthorizationValue(v.value))
    ) {
      throw new Error("authorization value is invalid");
    }
  }
  return v as ControlEnvelope;
}

/**
 * Stable payload serialization for Ed25519 signatures. Keep the explicit
 * field order: JSON object order from arbitrary callers is not canonical.
 */
export function canonicalControlPayload(
  value: UnsignedControlEnvelope | ControlEnvelope,
): Buffer {
  const payload = {
    schema: value.schema,
    id: value.id,
    kind: value.kind,
    createdAt: value.createdAt,
    expiresAt: value.expiresAt,
    issuer: value.issuer,
    teamRunId: value.teamRunId,
    jobId: value.jobId ?? null,
    text: value.text ?? null,
    decision: value.decision ?? null,
    value: value.value ?? null,
    questionSha256: value.questionSha256 ?? null,
  };
  return Buffer.from(JSON.stringify(payload), "utf8");
}

export function signControlEnvelope(
  envelope: UnsignedControlEnvelope,
  privateKeyPem: string | Buffer,
): ControlEnvelope {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("controller private key must be Ed25519");
  }
  const signature = crypto.sign(
    null,
    canonicalControlPayload(envelope),
    privateKey,
  );
  return validateControlEnvelope({
    ...envelope,
    signature: signature.toString("base64"),
  });
}

export function verifyControlEnvelope(
  envelope: ControlEnvelope,
  publicKeyPem: string | Buffer,
): boolean {
  let signature: Buffer;
  try {
    signature = Buffer.from(envelope.signature, "base64");
  } catch {
    return false;
  }
  const publicKey = crypto.createPublicKey(publicKeyPem);
  if (publicKey.asymmetricKeyType !== "ed25519") return false;
  return crypto.verify(
    null,
    canonicalControlPayload(envelope),
    publicKey,
    signature,
  );
}

export function publicKeyFingerprint(publicKeyPem: string | Buffer): string {
  const key = crypto.createPublicKey(publicKeyPem);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new Error("controller public key must be Ed25519");
  }
  const der = key.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex");
}

export function generateControllerKeyPair(): {
  publicKeyPem: string;
  privateKeyPem: string;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return {
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey
      .export({ type: "pkcs8", format: "pem" })
      .toString(),
  };
}

function mkdirPrivate(dir: string): boolean {
  const existed = fs.existsSync(dir);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(dir);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`control path must be a real directory: ${dir}`);
  }
  fs.chmodSync(dir, 0o700);
  return !existed;
}

function fsyncDirectory(dir: string): void {
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

function durableWriteNew(filePath: string, data: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL,
      0o600,
    );
    fs.writeFileSync(fd, data, "utf8");
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export function ensureControlDir(controlDir: string): void {
  let created = mkdirPrivate(controlDir);
  for (const child of ["inbox", "processed", "rejected"]) {
    created = mkdirPrivate(path.join(controlDir, child)) || created;
  }
  if (created) {
    fsyncDirectory(controlDir);
    fsyncDirectory(path.dirname(controlDir));
  }
}

function safeReadRegularFile(filePath: string): string {
  const before = fs.lstatSync(filePath);
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error("control message must be a regular non-symlink file");
  }
  if (before.size > MAX_CONTROL_BYTES) {
    throw new Error(`control message exceeds ${MAX_CONTROL_BYTES} bytes`);
  }

  const noFollow = fs.constants.O_NOFOLLOW ?? 0;
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | noFollow);
  try {
    const current = fs.fstatSync(fd);
    if (!current.isFile() || current.size > MAX_CONTROL_BYTES) {
      throw new Error("control message changed or is not a regular file");
    }
    return fs.readFileSync(fd, "utf8");
  } finally {
    fs.closeSync(fd);
  }
}

function archiveControlFile(
  controlDir: string,
  fileName: string,
  destination: "processed" | "rejected",
): void {
  const source = path.join(controlDir, "inbox", fileName);
  let target = path.join(controlDir, destination, fileName);
  if (fs.existsSync(target)) {
    target = path.join(
      controlDir,
      destination,
      `${Date.now()}-${crypto.randomUUID()}-${fileName}`,
    );
  }
  fs.renameSync(source, target);
  fsyncDirectory(path.join(controlDir, "inbox"));
  fsyncDirectory(path.join(controlDir, destination));
}

/**
 * Scan valid messages without consuming them. A message remains in inbox
 * until the harness acknowledges it after `agent.send()` accepts the steer,
 * or after an authorization is applied. This makes crash recovery replayable.
 */
export function scanControlSpool(
  controlDir: string,
  opts: {
    publicKeyPem: string | Buffer;
    teamRunId: string;
    now?: number;
  },
): PendingControl[] {
  ensureControlDir(controlDir);
  const now = opts.now ?? Date.now();
  const inbox = path.join(controlDir, "inbox");
  const out: PendingControl[] = [];

  for (const fileName of fs
    .readdirSync(inbox)
    .filter((name) => name.endsWith(".json"))
    .sort()) {
    const source = path.join(inbox, fileName);
    try {
      if (
        fs.existsSync(path.join(controlDir, "processed", fileName)) ||
        fs.existsSync(path.join(controlDir, "rejected", fileName))
      ) {
        throw new Error("replayed control message");
      }
      const parsed = JSON.parse(safeReadRegularFile(source));
      const envelope = validateControlEnvelope(parsed);
      if (fileName !== controlFileName(envelope)) {
        throw new Error("control filename does not match signed envelope");
      }
      if (envelope.teamRunId !== opts.teamRunId) {
        throw new Error(
          `message targets ${envelope.teamRunId}, expected ${opts.teamRunId}`,
        );
      }
      if (envelope.createdAt > now + MAX_CLOCK_SKEW_MS) {
        throw new Error("message createdAt is too far in the future");
      }
      if (envelope.expiresAt <= now) {
        throw new Error("message expired");
      }
      if (!verifyControlEnvelope(envelope, opts.publicKeyPem)) {
        throw new Error("invalid Ed25519 signature");
      }
      out.push({ envelope, fileName });
    } catch (error) {
      try {
        archiveControlFile(controlDir, fileName, "rejected");
      } catch {
        // A concurrent operator may have already moved it.
      }
      console.warn(
        `[control] rejected ${fileName}: ${error instanceof Error ? error.message : error}`,
      );
    }
  }
  return out;
}

export function acknowledgeControl(
  controlDir: string,
  pending: PendingControl,
): void {
  archiveControlFile(controlDir, pending.fileName, "processed");
}

export function rejectControl(
  controlDir: string,
  pending: PendingControl,
): void {
  archiveControlFile(controlDir, pending.fileName, "rejected");
}

/** Atomic writer used by teamctl and tests. */
export function writeControlEnvelope(
  controlDir: string,
  envelope: ControlEnvelope,
): string {
  validateControlEnvelope(envelope);
  ensureControlDir(controlDir);
  const inbox = path.join(controlDir, "inbox");
  const name = controlFileName(envelope);
  const destination = path.join(inbox, name);
  const temporary = path.join(
    controlDir,
    `.${name}.${process.pid}.${crypto.randomUUID()}.tmp`,
  );
  try {
    durableWriteNew(temporary, `${JSON.stringify(envelope, null, 2)}\n`);
    fs.linkSync(temporary, destination);
    fs.unlinkSync(temporary);
    fsyncDirectory(controlDir);
    fsyncDirectory(inbox);
    return destination;
  } finally {
    try {
      fs.unlinkSync(temporary);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}

function controlFileName(
  envelope: Pick<ControlEnvelope, "id" | "createdAt">,
): string {
  const safeId = envelope.id.replace(/[^A-Za-z0-9_.-]/g, "_");
  return `${String(envelope.createdAt).padStart(16, "0")}-${safeId}.json`;
}

export function authorizationMatches(
  envelope: ControlEnvelope,
  query: AuthorizationQuery,
  now = Date.now(),
): boolean {
  if (envelope.kind !== "authorization" || envelope.expiresAt <= now) {
    return false;
  }
  return (
    envelope.teamRunId === query.teamRunId &&
    envelope.jobId === query.jobId &&
    envelope.questionSha256 === questionSha256(query.question)
  );
}

export function formatAuthorizationAnswer(envelope: ControlEnvelope): string {
  if (envelope.kind !== "authorization" || !envelope.decision) {
    throw new Error("not an authorization envelope");
  }
  return envelope.value
    ? `${envelope.decision}:${envelope.value}`
    : envelope.decision;
}

export function writeControlCapability(
  controlDir: string,
  value: Omit<ControlCapability, "schema" | "controlDir">,
): void {
  ensureControlDir(controlDir);
  const capability: ControlCapability = {
    schema: "coding-agent-team-capability/v1",
    ...value,
    controlDir,
  };
  const destination = path.join(controlDir, "enabled.json");
  const temporary = `${destination}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    durableWriteNew(temporary, `${JSON.stringify(capability, null, 2)}\n`);
    fs.renameSync(temporary, destination);
    fsyncDirectory(controlDir);
  } finally {
    try {
      fs.unlinkSync(temporary);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
  }
}
