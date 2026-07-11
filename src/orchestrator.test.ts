import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { extractHitl, parseGateDecision } from "./orchestrator.js";

describe("parseGateDecision", () => {
  it("accepts structured gate decisions", () => {
    assert.deepEqual(parseGateDecision("approve", "tty"), {
      decision: "approve",
      answer: "approve",
      source: "tty",
    });
    assert.deepEqual(parseGateDecision("approve-phase-a", "slack"), {
      decision: "approve",
      value: "phase-a",
      answer: "approve:phase-a",
      source: "slack",
    });
    assert.equal(
      parseGateDecision("deny", "tty")?.decision,
      "deny",
    );
    assert.equal(
      parseGateDecision("choice:2", "tty")?.value,
      "2",
    );
  });

  it("rejects free text and secret-shaped values", () => {
    assert.equal(parseGateDecision("looks good", "tty"), undefined);
    assert.equal(
      parseGateDecision("choice:sk-secret-value", "tty"),
      undefined,
    );
    assert.equal(parseGateDecision("approve-all", "tty"), undefined);
  });
});

describe("extractHitl", () => {
  it("uses the final exact single-line marker", () => {
    assert.equal(
      extractHitl(
        "HITL_REQUIRED: old gate\nignored detail\nHITL_REQUIRED: Approve phase B? allowed=approve|deny",
      ),
      "Approve phase B? allowed=approve|deny",
    );
  });

  it("does not absorb trailing output or inline marker examples", () => {
    assert.equal(
      extractHitl("Use HITL_REQUIRED: <question> when needed."),
      undefined,
    );
    assert.equal(
      extractHitl("HITL_REQUIRED: Approve phase A?\nDo not include me."),
      "Approve phase A?",
    );
  });
});
