import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { canonicalJson, sha256 } from "./policy.js";

export type ProjectHookLease = {
  hookPath: string;
  installedSha256: string;
  verify(): void;
  release(): void;
};

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function syncDirectory(directory: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(directory, fs.constants.O_RDONLY);
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

function safeRead(filePath: string): Buffer {
  const before = fs.lstatSync(filePath);
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.size > 1024 * 1024
  ) {
    throw new Error(`managed hook must be a small regular file: ${filePath}`);
  }
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== before.ino) {
      throw new Error("managed hook changed while opening");
    }
    return fs.readFileSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function writeNew(filePath: string, contents: Buffer): void {
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
}

/**
 * Hard-policy runs intentionally do not merge existing project hooks. Loading
 * an existing manifest would execute repository-controlled commands at the
 * same trust level as the enforcement hook.
 */
export function installDenyShellProjectHook(opts: {
  workspace: string;
  stateDirectory: string;
  teamRunId: string;
  hookScript?: string;
  protectScript?: string;
}): ProjectHookLease {
  const workspace = fs.realpathSync(opts.workspace);
  const cursorDirectory = path.join(workspace, ".cursor");
  const hookPath = path.join(cursorDirectory, "hooks.json");
  const cursorExisted = fs.existsSync(cursorDirectory);
  let cursorOriginalMode: number | undefined;
  if (cursorExisted) {
    const info = fs.lstatSync(cursorDirectory);
    if (!info.isDirectory() || info.isSymbolicLink()) {
      throw new Error("workspace .cursor must be a real directory");
    }
    cursorOriginalMode = info.mode & 0o777;
  } else {
    fs.mkdirSync(cursorDirectory, { mode: 0o700 });
    syncDirectory(workspace);
  }
  if (fs.existsSync(hookPath)) {
    throw new Error(
      "hard-policy mode refuses an existing .cursor/hooks.json; use a dedicated evaluation worktree",
    );
  }
  if (fs.readdirSync(cursorDirectory).length > 0) {
    throw new Error(
      "hard-policy mode requires an empty or absent .cursor directory so project MCP/plugins cannot bypass policy",
    );
  }
  fs.chmodSync(cursorDirectory, 0o700);
  const hookScript =
    opts.hookScript ??
    path.resolve(import.meta.dirname, "..", "scripts", "deny-shell-hook.mjs");
  const scriptInfo = fs.lstatSync(hookScript);
  if (!scriptInfo.isFile() || scriptInfo.isSymbolicLink()) {
    throw new Error("deny-shell hook script must be a regular non-symlink file");
  }
  const hookScriptSha256 = sha256(safeRead(hookScript));
  const protectScript =
    opts.protectScript ??
    path.resolve(
      import.meta.dirname,
      "..",
      "scripts",
      "protect-policy-files.mjs",
    );
  const protectInfo = fs.lstatSync(protectScript);
  if (!protectInfo.isFile() || protectInfo.isSymbolicLink()) {
    throw new Error(
      "policy-file hook script must be a regular non-symlink file",
    );
  }
  const protectScriptSha256 = sha256(safeRead(protectScript));
  const manifest = {
    version: 1,
    hooks: {
      preToolUse: [
        {
          type: "command",
          command: `${shellQuote(process.execPath)} ${shellQuote(protectScript)} ${shellQuote(workspace)}`,
          timeout: 5,
          failClosed: true,
        },
      ],
      beforeShellExecution: [
        {
          type: "command",
          command: `${shellQuote(process.execPath)} ${shellQuote(hookScript)}`,
          timeout: 5,
          failClosed: true,
        },
      ],
    },
  };
  const contents = Buffer.from(`${canonicalJson(manifest)}\n`, "utf8");
  const installedSha256 = sha256(contents);
  writeNew(hookPath, contents);
  syncDirectory(cursorDirectory);

  const journalDirectory = path.join(
    opts.stateDirectory,
    opts.teamRunId,
    "hook",
  );
  fs.mkdirSync(journalDirectory, { recursive: true, mode: 0o700 });
  const journalPath = path.join(journalDirectory, "installation.json");
  writeNew(
    journalPath,
    Buffer.from(
      `${canonicalJson({
        schema: "coding-agent-team-hook-installation/v1",
        hookPath,
        installedSha256,
        hookScript,
        hookScriptSha256,
        protectScript,
        protectScriptSha256,
        cursorDirectoryCreated: !cursorExisted,
        cursorOriginalMode: cursorOriginalMode ?? null,
      })}\n`,
      "utf8",
    ),
  );
  syncDirectory(journalDirectory);

  let released = false;
  const verify = (): void => {
    if (released) throw new Error("project hook lease is already released");
    if (sha256(safeRead(hookPath)) !== installedSha256) {
      throw new Error(
        "hard-policy project hook changed; refusing to create or continue an agent",
      );
    }
    if (
      sha256(safeRead(hookScript)) !== hookScriptSha256 ||
      sha256(safeRead(protectScript)) !== protectScriptSha256
    ) {
      throw new Error(
        "hard-policy hook executable changed; refusing to create or continue an agent",
      );
    }
  };
  return {
    hookPath,
    installedSha256,
    verify,
    release(): void {
      if (released) return;
      verify();
      const quarantine = `${hookPath}.remove.${process.pid}.${crypto.randomUUID()}`;
      fs.renameSync(hookPath, quarantine);
      syncDirectory(cursorDirectory);
      fs.unlinkSync(quarantine);
      syncDirectory(cursorDirectory);
      if (!cursorExisted && fs.readdirSync(cursorDirectory).length === 0) {
        fs.rmdirSync(cursorDirectory);
        syncDirectory(workspace);
      } else if (cursorOriginalMode !== undefined) {
        fs.chmodSync(cursorDirectory, cursorOriginalMode);
        syncDirectory(cursorDirectory);
      }
      released = true;
    },
  };
}
