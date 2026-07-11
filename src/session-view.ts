import type { SDKMessage } from "@cursor/sdk";
import { redactSecrets } from "./control.js";

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const cyan = (s: string) => `\x1b[36m${s}\x1b[0m`;
const yellow = (s: string) => `\x1b[33m${s}\x1b[0m`;
const green = (s: string) => `\x1b[32m${s}\x1b[0m`;

export type LiveSession = {
  role: string;
  model: string;
  verbose: boolean;
  /** Track whether we are mid assistant text line. */
  _inText?: boolean;
  /** Track whether we are mid a verbose thinking stream. */
  _inThink?: boolean;
};

export function banner(role: string, model: string, extra?: string): void {
  const line = "─".repeat(60);
  console.log(`\n${cyan(line)}`);
  console.log(`${cyan("▶")} ${green(role)} ${dim(`model=${model}`)}${extra ? ` ${dim(extra)}` : ""}`);
  console.log(`${cyan(line)}\n`);
}

function summarizeToolArgs(name: string, args: unknown): string {
  if (!args || typeof args !== "object") return "";
  const r = args as Record<string, unknown>;
  const pick = (...keys: string[]) => {
    for (const k of keys) {
      const v = r[k];
      if (typeof v === "string" && v.trim()) {
        const t = v.replace(/\s+/g, " ").trim();
        const summarized = t.length > 100 ? `${t.slice(0, 97)}...` : t;
        return redactSecrets(summarized);
      }
    }
    return "";
  };
  const n = name.toLowerCase();
  if (n.includes("shell") || n.includes("command")) {
    return pick("command", "cmd") || "";
  }
  if (n.includes("read") || n.includes("write") || n.includes("edit")) {
    return pick("path", "target_file", "filePath", "file") || "";
  }
  if (n.includes("grep") || n.includes("search")) {
    return pick("pattern", "query") || "";
  }
  return pick("path", "pattern", "command", "query") || "";
}

function endTextIfNeeded(session: LiveSession): void {
  if (session._inThink) {
    process.stdout.write("\n");
    session._inThink = false;
  }
  if (session._inText) {
    process.stdout.write("\n");
    session._inText = false;
  }
}

/**
 * Render one SDK stream event to the terminal for an interactive live session.
 * Returns assistant text deltas (for transcript accumulation).
 */
export function renderStreamEvent(
  session: LiveSession,
  event: SDKMessage,
): string {
  let textDelta = "";

  switch (event.type) {
    case "system":
      if (session.verbose) {
        endTextIfNeeded(session);
        console.log(
          dim(`[system] ${redactSecrets(JSON.stringify(event).slice(0, 200))}`),
        );
      }
      break;

    case "thinking":
      // Default: hide model thinking (SDK often emits one word per event).
      // --verbose: stream dim text on one line, no per-word pink prefix.
      if (
        session.verbose &&
        "text" in event &&
        typeof event.text === "string" &&
        event.text
      ) {
        if (session._inText) {
          process.stdout.write("\n");
          session._inText = false;
        }
        if (!session._inThink) {
          process.stdout.write(`${dim("⋯ ")}`);
          session._inThink = true;
        }
        process.stdout.write(dim(redactSecrets(event.text)));
      }
      break;

    case "assistant":
      for (const block of event.message.content) {
        if (block.type === "text") {
          if (session._inThink) {
            process.stdout.write("\n");
            session._inThink = false;
          }
          const text = redactSecrets(block.text);
          process.stdout.write(text);
          session._inText = true;
          textDelta += text;
        } else if (block.type === "tool_use") {
          endTextIfNeeded(session);
          const detail = summarizeToolArgs(block.name, block.input);
          console.log(
            `${yellow("⚙ tool")} ${block.name}${detail ? dim(` ${detail}`) : ""}`,
          );
        }
      }
      break;

    case "tool_call":
      endTextIfNeeded(session);
      {
        const detail = summarizeToolArgs(
          event.name,
          "args" in event ? event.args : undefined,
        );
        const status = "status" in event ? String(event.status) : "";
        console.log(
          `${yellow("⚙")} ${event.name}${status ? dim(` [${status}]`) : ""}${detail ? dim(` ${detail}`) : ""}`,
        );
      }
      break;

    case "status":
      endTextIfNeeded(session);
      console.log(
        `${dim("● status")} ${event.status}${event.message ? dim(` — ${redactSecrets(event.message)}`) : ""}`,
      );
      break;

    case "task":
      endTextIfNeeded(session);
      console.log(
        `${cyan("▸ task")} ${event.status ?? ""}${event.text ? ` ${redactSecrets(event.text)}` : ""}`,
      );
      break;

    default:
      if (session.verbose) {
        endTextIfNeeded(session);
        console.log(dim(`[event] ${(event as { type: string }).type}`));
      }
      break;
  }

  return textDelta;
}

export function renderJobDone(
  role: string,
  model: string,
  status: string,
  attempts: string[],
): void {
  console.log(
    `\n${green("✔")} ${role} done · model=${model} · status=${status} · attempts=${attempts.join("→")}\n`,
  );
}
