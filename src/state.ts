import fs from "node:fs";
import path from "node:path";

export type JobStatus =
  | "pending"
  | "running"
  | "awaiting_human"
  | "blocked"
  | "finished"
  | "error"
  | "stale";

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
  hitlAnswer?: string;
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
    fs.mkdirSync(dir, { recursive: true });
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
    const merged: JobRecord = {
      jobId: partial.jobId,
      role: partial.role,
      status: partial.status,
      createdAt: prev?.createdAt ?? Date.now(),
      lastEventAt: Date.now(),
      model: partial.model ?? prev?.model,
      runId: partial.runId ?? prev?.runId,
      agentId: partial.agentId ?? prev?.agentId,
      attempts: partial.attempts ?? prev?.attempts,
      lastError: partial.lastError ?? prev?.lastError,
      hitlQuestion: partial.hitlQuestion ?? prev?.hitlQuestion,
      hitlAnswer: partial.hitlAnswer ?? prev?.hitlAnswer,
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
    this.upsert({
      jobId,
      role: this.data.jobs[jobId]?.role ?? "master",
      status: "awaiting_human",
      hitlQuestion: question,
      lastEventAt: Date.now(),
    });
  }

  resolveHuman(jobId: string, answer: string): void {
    this.upsert({
      jobId,
      role: this.data.jobs[jobId]?.role ?? "master",
      status: "running",
      hitlAnswer: answer,
      lastEventAt: Date.now(),
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
    fs.writeFileSync(this.filePath, JSON.stringify(this.data, null, 2));
  }
}
