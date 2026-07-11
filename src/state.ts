import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { questionSha256 } from "./control.js";

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

export type TeamStateFile = {
  teamRunId: string;
  cwd: string;
  updatedAt: number;
  jobs: Record<string, JobRecord>;
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
    this.data = {
      teamRunId,
      cwd,
      updatedAt: Date.now(),
      jobs: {},
    };
    this.flush();
  }

  snapshot(): TeamStateFile {
    return structuredClone(this.data);
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

  private flush(): void {
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
      fs.renameSync(temporary, this.filePath);
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
