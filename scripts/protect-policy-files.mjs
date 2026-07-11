#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const workspace = process.argv[2]
  ? fs.realpathSync(path.resolve(process.argv[2]))
  : null;
const deny = (message) => {
  process.stdout.write(
    JSON.stringify({
      permission: "deny",
      user_message: message,
      agent_message:
        "Hard-policy control files are immutable for the duration of this run.",
    }),
  );
};

let input;
try {
  let body = "";
  for await (const chunk of process.stdin) {
    body += chunk;
    if (body.length > 1024 * 1024) throw new Error("hook input too large");
  }
  input = JSON.parse(body);
} catch {
  deny("Hard-policy file-protection hook received invalid input.");
  process.exit(0);
}

if (!workspace) {
  deny("Hard-policy workspace binding is unavailable.");
  process.exit(0);
}

const protectedCursor = path.join(workspace, ".cursor");
const protectedState = path.join(workspace, ".team-state");
const resolveExistingAliases = (candidate) => {
  const suffix = [];
  let probe = candidate;
  for (;;) {
    try {
      return path.resolve(fs.realpathSync(probe), ...suffix);
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
      const parent = path.dirname(probe);
      if (parent === probe) throw error;
      suffix.unshift(path.basename(probe));
      probe = parent;
    }
  }
};
const strings = [];
const visit = (value) => {
  if (typeof value === "string") strings.push(value);
  else if (Array.isArray(value)) value.forEach(visit);
  else if (value && typeof value === "object") Object.values(value).forEach(visit);
};
visit(input);

const targetsProtectedPath = strings.some((value) => {
  if (value.includes("\0")) return true;
  const slashValue = value.replaceAll("\\", "/");
  if (
    slashValue.includes(`${protectedCursor.replaceAll("\\", "/")}/`) ||
    slashValue.includes(`${protectedState.replaceAll("\\", "/")}/`) ||
    /(?:^|[\s:'"])\.cursor\//.test(slashValue) ||
    /(?:^|[\s:'"])\.team-state\//.test(slashValue)
  ) {
    return true;
  }
  try {
    const candidate = path.isAbsolute(value)
      ? path.resolve(value)
      : path.resolve(workspace, value);
    const dereferenced = resolveExistingAliases(candidate);
    return (
      candidate === protectedCursor ||
      candidate.startsWith(`${protectedCursor}${path.sep}`) ||
      candidate === protectedState ||
      candidate.startsWith(`${protectedState}${path.sep}`) ||
      dereferenced === protectedCursor ||
      dereferenced.startsWith(`${protectedCursor}${path.sep}`) ||
      dereferenced === protectedState ||
      dereferenced.startsWith(`${protectedState}${path.sep}`)
    );
  } catch {
    return true;
  }
});

if (targetsProtectedPath) {
  deny("This edit targets an active hard-policy control or state artifact.");
} else {
  process.stdout.write(JSON.stringify({ permission: "allow" }));
}
