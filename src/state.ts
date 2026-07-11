import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { questionSha256 } from "./control.js";
import type { FrozenArtifactRef, FrozenRunArtifacts } from "./manifests.js";
import type {
  ExecutionReceipt,
  ProcessRecord,
} from "./process-registry.js";

export type JobStatus =
  | "pending"
  | "running"
  | "awaiting_human"
  | "blocked"
  | "finished"
  | "error"
  | "stale";

export type HitlEvent = {
  question: string;
  questionSha256: string;
  requestedAt: number;
  decision?: "approve" | "deny" | "cancel" | "choice";
  source?: "control" | "slack" | "tty";
  authorizationId?: string;
  resolvedAt?: number;
};

export type JobRecord = {
  jobId: string;
  role: string;
  model?: string;
  status: JobStatus;
  runId?: string;
  agentId?: string;
  attempts?: string[];
  lastError?: string;
  hitlQuestion?: string;
  hitlQuestionSha256?: string;
  hitlDecision?: "approve" | "deny" | "cancel" | "choice";
  hitlSource?: "control" | "slack" | "tty";
  hitlAuthorizationId?: string;
  hitlResolvedAt?: number;
  hitlHistory?: HitlEvent[];
  lastEventAt: number;
  createdAt: number;
};

export type RunStatus =
  | "initializing"
  | "running"
  | "awaiting_human"
  | "failed"
  | "cleaning"
  | "ready";

export type PolicyGateRecord = {
  gateId: string;
  from: string;
  to: string;
  evidenceSha256: string;
  workspaceSha256: string;
  question: string;
  questionSha256: string;
  requestedAt: number;
  decision?: "approve" | "deny" | "cancel";
  authorizationId?: string;
  resolvedAt?: number;
};

export type PolicyState = {
  profileId: string;
  profileVersion: string;
  profileSha256: string;
  bindingSha256: string;
  currentPhase: string;
  terminalPhase: string;
  artifacts: FrozenRunArtifacts;
  pendingGate?: PolicyGateRecord;
  gateHistory: PolicyGateRecord[];
  reconciliationRefs: FrozenArtifactRef[];
  readinessSeal?: FrozenArtifactRef;
};

export type TeamStateFile = {
  schema: "coding-agent-team-state/v2";
  teamRunId: string;
  cwd: string;
  updatedAt: number;
  runStatus: RunStatus;
  jobs: Record<string, JobRecord>;
  processes: Record<string, ProcessRecord>;
  receipts: ExecutionReceipt[];
  policy?: PolicyState;
  lastError?: string;
};

export class TeamStateStore {
  readonly filePath: string;
  private data: TeamStateFile;

  constructor(dir: string, teamRunId: string, cwd: string) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const info = fs.lstatSync(dir);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error(`state path must be a real directory: ${dir}`);
    }
    fs.chmodSync(dir, 0o700);
    this.filePath = path.join(dir, `${teamRunId}.json`);
    if (fs.existsSync(this.filePath)) {
      throw new Error(
        `state already exists for teamRunId ${teamRunId}; refusing replay/overwrite`,
      );
    }
    this.data = {
      schema: "coding-agent-team-state/v2",
      teamRunId,
      cwd,
      updatedAt: Date.now(),
      runStatus: "initializing",
      jobs: {},
      processes: {},
      receipts: [],
    };
    this.flush(true);
  }

  snapshot(): TeamStateFile {
    return structuredClone(this.data);
  }

  setRunStatus(status: RunStatus, lastError?: string): void {
    this.data.runStatus = status;
    this.data.lastError = lastError;
    this.data.updatedAt = Date.now();
    this.flush();
  }

  initializePolicy(policy: PolicyState): void {
    if (this.data.policy) {
      throw new Error("policy state is already initialized");
    }
    this.data.policy = structuredClone(policy);
    this.data.updatedAt = Date.now();
    this.flush();
  }

  setPolicyGate(gate: PolicyGateRecord): void {
    const policy = this.data.policy;
    if (!policy) throw new Error("policy state is not initialized");
    if (policy.pendingGate && policy.pendingGate.resolvedAt === undefined) {
      throw new Error("a policy gate is already pending");
    }
    policy.pendingGate = structuredClone(gate);
    policy.gateHistory = [...policy.gateHistory, structuredClone(gate)].slice(
      -128,
    );
    this.data.runStatus = "awaiting_human";
    this.data.updatedAt = Date.now();
    this.flush();
  }

  resolvePolicyGate(metadata: {
    decision: "approve" | "deny" | "cancel";
    authorizationId?: string;
    resolvedAt?: number;
  }): void {
    const policy = this.data.policy;
    const pending = policy?.pendingGate;
    if (!policy || !pending || pending.resolvedAt !== undefined) {
      throw new Error("no unresolved policy gate");
    }
    const resolved: PolicyGateRecord = {
      ...pending,
      decision: metadata.decision,
      authorizationId: metadata.authorizationId,
      resolvedAt: metadata.resolvedAt ?? Date.now(),
    };
    policy.pendingGate = resolved;
    const index = policy.gateHistory.findIndex(
      (gate) => gate.gateId === resolved.gateId,
    );
    if (index < 0) throw new Error("pending gate is missing from policy history");
    policy.gateHistory[index] = structuredClone(resolved);
    this.data.runStatus =
      metadata.decision === "approve" ? "running" : "failed";
    this.data.updatedAt = Date.now();
    this.flush();
  }

  advancePolicyPhase(nextPhase: string): void {
    const policy = this.data.policy;
    if (!policy) throw new Error("policy state is not initialized");
    const gate = policy.pendingGate;
    if (
      !gate ||
      gate.decision !== "approve" ||
      gate.to !== nextPhase ||
      gate.resolvedAt === undefined
    ) {
      throw new Error("phase advancement requires an approved matching gate");
    }
    policy.currentPhase = nextPhase;
    policy.pendingGate = undefined;
    this.data.updatedAt = Date.now();
    this.flush();
  }

  addReconciliationRef(ref: FrozenArtifactRef): void {
    const policy = this.data.policy;
    if (!policy) throw new Error("policy state is not initialized");
    policy.reconciliationRefs.push(structuredClone(ref));
    this.data.updatedAt = Date.now();
    this.flush();
  }

  setReadinessSeal(ref: FrozenArtifactRef): void {
    const policy = this.data.policy;
    if (!policy) throw new Error("policy state is not initialized");
    if (policy.readinessSeal) throw new Error("readiness seal is write-once");
    policy.readinessSeal = structuredClone(ref);
    this.data.runStatus = "ready";
    this.data.updatedAt = Date.now();
    this.flush();
  }

  recordProcess(record: ProcessRecord): void {
    this.data.processes[record.processId] = structuredClone(record);
    this.data.updatedAt = Date.now();
    this.flush();
  }

  recordReceipt(receipt: ExecutionReceipt): void {
    if (
      this.data.receipts.some(
        (existing) => existing.receiptId === receipt.receiptId,
      )
    ) {
      throw new Error(`duplicate execution receipt: ${receipt.receiptId}`);
    }
    if (this.data.receipts.length >= 10_000) {
      throw new Error("execution receipt limit reached");
    }
    this.data.receipts.push(structuredClone(receipt));
    this.data.updatedAt = Date.now();
    this.flush();
  }

  activeProcesses(ownerJobId?: string): ProcessRecord[] {
    return Object.values(this.data.processes)
      .filter(
        (record) =>
          (record.endedAt === undefined || record.status === "orphaned") &&
          (!ownerJobId || record.ownerJobId === ownerJobId),
      )
      .map((record) => structuredClone(record));
  }

  upsert(partial: Partial<JobRecord> & Pick<JobRecord, "jobId" | "role" | "status">): void {
    const prev = this.data.jobs[partial.jobId];
    const has = (key: keyof JobRecord): boolean =>
      Object.prototype.hasOwnProperty.call(partial, key);
    const merged: JobRecord = {
      jobId: partial.jobId,
      role: partial.role,
      status: partial.status,
      createdAt: prev?.createdAt ?? Date.now(),
      lastEventAt: Date.now(),
      model: has("model") ? partial.model : prev?.model,
      runId: has("runId") ? partial.runId : prev?.runId,
      agentId: has("agentId") ? partial.agentId : prev?.agentId,
      attempts: has("attempts") ? partial.attempts : prev?.attempts,
      lastError: has("lastError") ? partial.lastError : prev?.lastError,
      hitlQuestion: has("hitlQuestion")
        ? partial.hitlQuestion
        : prev?.hitlQuestion,
      hitlQuestionSha256: has("hitlQuestionSha256")
        ? partial.hitlQuestionSha256
        : prev?.hitlQuestionSha256,
      hitlDecision: has("hitlDecision")
        ? partial.hitlDecision
        : prev?.hitlDecision,
      hitlSource: has("hitlSource") ? partial.hitlSource : prev?.hitlSource,
      hitlAuthorizationId: has("hitlAuthorizationId")
        ? partial.hitlAuthorizationId
        : prev?.hitlAuthorizationId,
      hitlResolvedAt: has("hitlResolvedAt")
        ? partial.hitlResolvedAt
        : prev?.hitlResolvedAt,
      hitlHistory: has("hitlHistory")
        ? partial.hitlHistory
        : prev?.hitlHistory,
    };
    this.data.jobs[partial.jobId] = merged;
    this.data.updatedAt = Date.now();
    this.flush();
  }

  touch(jobId: string): void {
    const job = this.data.jobs[jobId];
    if (!job) return;
    job.lastEventAt = Date.now();
    this.data.updatedAt = Date.now();
    this.flush();
  }

  markAwaitingHuman(jobId: string, question: string): void {
    const requestedAt = Date.now();
    const hash = questionSha256(question);
    const history: HitlEvent[] = [
      ...(this.data.jobs[jobId]?.hitlHistory ?? []),
      { question, questionSha256: hash, requestedAt },
    ].slice(-64);
    this.upsert({
      jobId,
      role: this.data.jobs[jobId]?.role ?? "master",
      status: "awaiting_human",
      hitlQuestion: question,
      hitlQuestionSha256: hash,
      hitlDecision: undefined,
      hitlSource: undefined,
      hitlAuthorizationId: undefined,
      hitlResolvedAt: undefined,
      hitlHistory: history,
      lastError: undefined,
      lastEventAt: requestedAt,
    });
  }

  resolveHuman(
    jobId: string,
    metadata: {
      decision: NonNullable<JobRecord["hitlDecision"]>;
      source: NonNullable<JobRecord["hitlSource"]>;
      authorizationId?: string;
    },
  ): void {
    const resolvedAt = Date.now();
    const current = this.data.jobs[jobId];
    const history: HitlEvent[] = [...(current?.hitlHistory ?? [])];
    let historyIndex = -1;
    for (let index = history.length - 1; index >= 0; index--) {
      const event = history[index]!;
      if (
        event.questionSha256 === current?.hitlQuestionSha256 &&
        event.resolvedAt === undefined
      ) {
        historyIndex = index;
        break;
      }
    }
    if (historyIndex < 0) {
      throw new Error(`no unresolved HITL gate for job ${jobId}`);
    }
    history[historyIndex] = {
      ...history[historyIndex]!,
      decision: metadata.decision,
      source: metadata.source,
      authorizationId: metadata.authorizationId,
      resolvedAt,
    };
    this.upsert({
      jobId,
      role: this.data.jobs[jobId]?.role ?? "master",
      status: "running",
      hitlDecision: metadata.decision,
      hitlSource: metadata.source,
      hitlAuthorizationId: metadata.authorizationId,
      hitlResolvedAt: resolvedAt,
      hitlHistory: history,
      lastError: undefined,
      lastEventAt: resolvedAt,
    });
  }

  listStale(idleMs: number, now = Date.now()): JobRecord[] {
    return Object.values(this.data.jobs).filter(
      (j) =>
        (j.status === "running" || j.status === "awaiting_human") &&
        now - j.lastEventAt > idleMs,
    );
  }

  private flush(exclusive = false): void {
    const temporary = `${this.filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    let fd: number | undefined;
    try {
      fd = fs.openSync(
        temporary,
        fs.constants.O_WRONLY |
          fs.constants.O_CREAT |
          fs.constants.O_EXCL,
        0o600,
      );
      fs.writeFileSync(fd, `${JSON.stringify(this.data, null, 2)}\n`, "utf8");
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      if (exclusive) {
        fs.linkSync(temporary, this.filePath);
        fs.unlinkSync(temporary);
      } else {
        fs.renameSync(temporary, this.filePath);
      }
      fs.chmodSync(this.filePath, 0o600);
      fsyncDirectory(path.dirname(this.filePath));
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
      try {
        fs.unlinkSync(temporary);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  }
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
