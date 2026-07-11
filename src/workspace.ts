import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const EXCLUDED_PREFIXES = [".team-state", ".cursor"];

function gitOutput(cwd: string, args: string[], encoding?: BufferEncoding): Buffer | string {
  const result = spawnSync("git", args, {
    cwd,
    encoding,
    timeout: 60_000,
    maxBuffer: 64 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(
      `git ${args[0]} failed: ${String(result.stderr).slice(-2000)}`,
    );
  }
  return result.stdout;
}

export function requireGitHead(cwd: string): string {
  const head = String(
    gitOutput(cwd, ["rev-parse", "--verify", "HEAD"], "utf8"),
  ).trim();
  if (!/^[0-9a-f]{40,64}$/.test(head)) {
    throw new Error("hard-policy workspace requires a valid Git HEAD");
  }
  return head;
}

/**
 * Hash the visible working tree without mutating the index. Harness-owned
 * `.team-state`, temporary `.cursor` policy files, and Git internals are the
 * only exclusions. Ignored files are included because tests may consume them.
 */
export function workspaceSnapshotSha256(cwd: string): string {
  const workspace = fs.realpathSync(cwd);
  const head = requireGitHead(workspace);
  const listed = gitOutput(
    workspace,
    ["ls-files", "-co", "--exclude-standard", "-z", "--", "."],
  ) as Buffer;
  const ignored = gitOutput(
    workspace,
    ["ls-files", "-o", "-i", "--exclude-standard", "-z", "--", "."],
  ) as Buffer;
  const relativePaths = [
    ...new Set(
      Buffer.concat([listed, ignored])
        .toString("utf8")
        .split("\0")
        .filter(Boolean),
    ),
  ]
    .filter(
      (relative) =>
        !EXCLUDED_PREFIXES.some(
          (prefix) =>
            relative === prefix || relative.startsWith(`${prefix}/`),
        ),
    )
    .sort((left, right) =>
      Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8")),
    );
  const hash = crypto.createHash("sha256");
  hash.update("coding-agent-team-workspace/v1\0", "utf8");
  hash.update(head, "utf8");
  hash.update("\0", "utf8");
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  let totalBytes = 0;
  for (const relative of relativePaths) {
    if (
      path.isAbsolute(relative) ||
      relative === ".." ||
      relative.startsWith(`..${path.sep}`)
    ) {
      throw new Error(`git returned an unsafe workspace path: ${relative}`);
    }
    const candidate = path.join(workspace, relative);
    hash.update(relative, "utf8");
    hash.update("\0", "utf8");
    let info: fs.Stats;
    try {
      info = fs.lstatSync(candidate);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      hash.update("missing\0", "utf8");
      continue;
    }
    hash.update(`${info.mode & 0o777}\0`, "utf8");
    if (info.isSymbolicLink()) {
      const target = fs.readlinkSync(candidate, "utf8");
      hash.update(`symlink\0${Buffer.byteLength(target, "utf8")}\0`, "utf8");
      hash.update(target, "utf8");
      hash.update("\0", "utf8");
      continue;
    }
    if (!info.isFile()) {
      throw new Error(`workspace path is not a file or symlink: ${relative}`);
    }
    totalBytes += info.size;
    if (totalBytes > 1024 * 1024 * 1024) {
      throw new Error("workspace snapshot exceeds 1 GiB");
    }
    hash.update(`file\0${info.size}\0`, "utf8");
    const fd = fs.openSync(
      candidate,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    try {
      const opened = fs.fstatSync(fd);
      if (!opened.isFile() || opened.ino !== info.ino) {
        throw new Error(`workspace file changed while opening: ${relative}`);
      }
      for (;;) {
        const bytes = fs.readSync(fd, buffer, 0, buffer.length, null);
        if (bytes === 0) break;
        hash.update(buffer.subarray(0, bytes));
      }
      const after = fs.fstatSync(fd);
      if (after.size !== opened.size || after.mtimeMs !== opened.mtimeMs) {
        throw new Error(`workspace file changed while hashing: ${relative}`);
      }
    } finally {
      fs.closeSync(fd);
    }
    hash.update("\0", "utf8");
  }
  return hash.digest("hex");
}
