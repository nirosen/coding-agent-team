import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

type LockRecord = {
  schema: "coding-agent-team-lock/v1";
  token: string;
  teamRunId: string;
  pid: number;
  host: string;
  startedAt: number;
};

export type TeamLock = {
  filePath: string;
  record: LockRecord;
  release(): void;
};

function processAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
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

function readLock(filePath: string): LockRecord | undefined {
  let fd: number | undefined;
  try {
    const info = fs.lstatSync(filePath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 8 * 1024) {
      return undefined;
    }
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const parsed = JSON.parse(fs.readFileSync(fd, "utf8")) as LockRecord;
    if (
      parsed.schema === "coding-agent-team-lock/v1" &&
      Number.isSafeInteger(parsed.pid) &&
      parsed.pid > 0 &&
      typeof parsed.host === "string" &&
      parsed.host.length <= 255 &&
      typeof parsed.teamRunId === "string" &&
      /^[A-Za-z0-9_.-]+$/.test(parsed.teamRunId) &&
      typeof parsed.token === "string" &&
      /^[0-9a-f-]{36}$/i.test(parsed.token) &&
      Number.isSafeInteger(parsed.startedAt)
    ) {
      return parsed;
    }
  } catch {
    // Malformed locks are treated as unsafe, not silently overwritten.
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  return undefined;
}

export function acquireTeamLock(
  stateDir: string,
  teamRunId: string,
): TeamLock {
  const stateDirExisted = fs.existsSync(stateDir);
  fs.mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  const stateInfo = fs.lstatSync(stateDir);
  if (!stateInfo.isDirectory() || stateInfo.isSymbolicLink()) {
    throw new Error(`state path must be a real directory: ${stateDir}`);
  }
  fs.chmodSync(stateDir, 0o700);
  if (!stateDirExisted) fsyncDirectory(path.dirname(stateDir));
  const filePath = path.join(stateDir, "writer.lock");
  const record: LockRecord = {
    schema: "coding-agent-team-lock/v1",
    token: crypto.randomUUID(),
    teamRunId,
    pid: process.pid,
    host: os.hostname(),
    startedAt: Date.now(),
  };

  for (;;) {
    let fd: number | undefined;
    try {
      fd = fs.openSync(
        filePath,
        fs.constants.O_WRONLY |
          fs.constants.O_CREAT |
          fs.constants.O_EXCL,
        0o600,
      );
      fs.writeFileSync(fd, `${JSON.stringify(record, null, 2)}\n`, "utf8");
      fs.fsyncSync(fd);
      fs.closeSync(fd);
      fd = undefined;
      fsyncDirectory(stateDir);
      break;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const existing = readLock(filePath);
      if (!existing) {
        throw new Error(
          `refusing to overwrite malformed writer lock: ${filePath}`,
        );
      }
      if (existing.host !== os.hostname()) {
        throw new Error(
          `writer lock belongs to host ${existing.host}; shared cwd cannot be safely auto-unlocked`,
        );
      }
      if (processAlive(existing.pid)) {
        throw new Error(
          `another team writer is active: run=${existing.teamRunId} pid=${existing.pid}`,
        );
      }
      const stale = `${filePath}.stale.${Date.now()}.${crypto.randomUUID()}`;
      fs.renameSync(filePath, stale);
      fsyncDirectory(stateDir);
    } finally {
      if (fd !== undefined) fs.closeSync(fd);
    }
  }

  return {
    filePath,
    record,
    release(): void {
      const current = readLock(filePath);
      if (current?.token !== record.token) return;
      try {
        fs.unlinkSync(filePath);
        fsyncDirectory(stateDir);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    },
  };
}
