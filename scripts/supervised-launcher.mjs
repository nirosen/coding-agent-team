#!/usr/bin/env node
import { spawn } from "node:child_process";

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(126);
}

const encoded = process.argv[2];
if (!encoded) fail("missing supervised command payload");

let payload;
try {
  payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8"));
} catch {
  fail("invalid supervised command payload");
}
if (
  !payload ||
  !Array.isArray(payload.argv) ||
  payload.argv.length === 0 ||
  payload.argv.some((value) => typeof value !== "string")
) {
  fail("invalid supervised command argv");
}

// The parent persists this launcher's PID/process identity before releasing
// the exact manifest command. stdin is a private one-byte startup barrier;
// the manifest command itself always receives stdin="ignore".
const barrier = process.stdin;
let released = false;
barrier.once("data", () => {
  released = true;
  const child = spawn(payload.argv[0], payload.argv.slice(1), {
    cwd: payload.cwd,
    env: process.env,
    shell: false,
    stdio: ["ignore", "inherit", "inherit"],
  });
  child.once("error", (error) => fail(`exec failed: ${error.message}`));
  child.once("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 125);
  });
});
barrier.once("end", () => {
  if (!released) fail("startup barrier closed without release");
});
barrier.once("error", (error) => fail(`startup barrier failed: ${error.message}`));
