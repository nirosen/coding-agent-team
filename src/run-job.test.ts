import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { streamUntilDoneOrSteer } from "./run-job.js";
import type { SteerHub, SteerMessage } from "./steer.js";

function oneSteerHub(steer: SteerMessage): SteerHub {
  let available = true;
  return {
    enabled: true,
    intervalMs: 1,
    async poll() {},
    take() {
      if (!available) return undefined;
      available = false;
      return steer;
    },
  } as unknown as SteerHub;
}

describe("streamUntilDoneOrSteer", () => {
  it("cancels a supported run and returns the steer", async () => {
    let release!: () => void;
    const settled = new Promise<void>((resolve) => {
      release = resolve;
    });
    let cancels = 0;
    const run = {
      stream() {
        return (async function* () {
          await settled;
        })();
      },
      supports(operation: string) {
        return operation === "cancel";
      },
      unsupportedReason() {
        return "";
      },
      async cancel() {
        cancels++;
        release();
      },
    };
    const steer = {
      id: "steer-1",
      text: "change focus",
      source: "control" as const,
      at: Date.now(),
    };
    const outcome = await streamUntilDoneOrSteer(run as never, {
      jobId: "job-1",
      live: false,
      session: { role: "master", model: "test", verbose: false },
      steer: oneSteerHub(steer),
      allowSteer: true,
      onDelta() {},
    });
    assert.equal(outcome.kind, "steered");
    assert.equal(cancels, 1);
    if (outcome.kind === "steered") {
      assert.equal(outcome.steer.id, "steer-1");
      assert.equal(outcome.delayed, false);
    }
  });

  it("waits for the turn when cancellation is unsupported", async () => {
    const run = {
      stream() {
        return (async function* () {
          await new Promise((resolve) => setTimeout(resolve, 10));
        })();
      },
      supports() {
        return false;
      },
      unsupportedReason() {
        return "local runtime does not support cancel";
      },
    };
    const outcome = await streamUntilDoneOrSteer(run as never, {
      jobId: "job-1",
      live: false,
      session: { role: "master", model: "test", verbose: false },
      steer: oneSteerHub({
        id: "steer-2",
        text: "apply later",
        source: "control",
        at: Date.now(),
      }),
      allowSteer: true,
      onDelta() {},
    });
    assert.equal(outcome.kind, "steered");
    if (outcome.kind === "steered") assert.equal(outcome.delayed, true);
  });

  it("aborts the control waiter when the SDK stream fails", async () => {
    const run = {
      stream() {
        return (async function* () {
          throw new Error("stream failed");
        })();
      },
    };
    const hub = {
      enabled: true,
      intervalMs: 60_000,
      async poll() {},
      take() {
        return undefined;
      },
    } as unknown as SteerHub;
    await assert.rejects(
      streamUntilDoneOrSteer(run as never, {
        jobId: "job-1",
        live: false,
        session: { role: "master", model: "test", verbose: false },
        steer: hub,
        allowSteer: true,
        onDelta() {},
      }),
      /stream failed/,
    );
  });

  it("lets the SDK run settle then fails closed if control polling fails", async () => {
    const run = {
      stream() {
        return (async function* () {
          await new Promise((resolve) => setTimeout(resolve, 5));
        })();
      },
      supports() {
        return false;
      },
    };
    const hub = {
      enabled: true,
      intervalMs: 1,
      async poll() {
        throw new Error("spool unavailable");
      },
      take() {
        return undefined;
      },
    } as unknown as SteerHub;
    await assert.rejects(
      streamUntilDoneOrSteer(run as never, {
        jobId: "job-1",
        live: false,
        session: { role: "master", model: "test", verbose: false },
        steer: hub,
        allowSteer: true,
        onDelta() {},
      }),
      /spool unavailable/,
    );
  });
});
