#!/usr/bin/env node
let input;
try {
  input = JSON.parse(await new Promise((resolve, reject) => {
    let body = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1024 * 1024) reject(new Error("hook input too large"));
    });
    process.stdin.on("end", () => resolve(body));
    process.stdin.on("error", reject);
  }));
} catch {
  process.stdout.write(
    JSON.stringify({
      permission: "deny",
      user_message: "Hard-policy shell hook received invalid input.",
      agent_message:
        "Built-in Shell is disabled. Use the supervised_process custom tool.",
    }),
  );
  process.exit(0);
}

const isShell =
  input &&
  input.hook_event_name === "beforeShellExecution" &&
  typeof input.command === "string";

process.stdout.write(
  JSON.stringify({
    permission: "deny",
    user_message: isShell
      ? "Built-in shell execution is disabled for this supervised run."
      : "Hard-policy hook denied an unrecognized shell request.",
    agent_message:
      "Use supervised_process with a commandId from the signed command manifest. Unlisted commands require a new signed run bundle.",
  }),
);
