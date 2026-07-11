import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ACCOUNTING_CONFIG_SCHEMA,
  ACCOUNTING_EVENTS_SCHEMA,
  reconcileSpend,
  validateAccountingConfig,
  validateAccountingEvents,
} from "./accounting.js";

const config = validateAccountingConfig({
  schema: ACCOUNTING_CONFIG_SCHEMA,
  adapter: {
    argv: [process.execPath],
    cwd: ".",
    executableSha256: "0".repeat(64),
    envAllowlist: [],
    timeoutMs: 10_000,
  },
  sources: [],
  limits: {
    usd_micros: "1000000",
    external_calls: "4",
  },
});

function events(
  watermark: string,
  rows: Array<{
    id: string;
    phase?: string;
    usd: string;
    calls: string;
  }>,
) {
  return validateAccountingEvents({
    schema: ACCOUNTING_EVENTS_SCHEMA,
    watermarks: { provider: watermark },
    events: rows.map((row) => ({
      id: row.id,
      phase: row.phase ?? "execution",
      units: {
        usd_micros: row.usd,
        external_calls: row.calls,
      },
    })),
  });
}

describe("canonical accounting reconciliation", () => {
  it("uses exact integer arithmetic and deduplicates prior events", () => {
    const first = reconcileSpend(
      config,
      "execution",
      {
        output: events("2", [
          { id: "call-1", usd: "300000", calls: "1" },
          { id: "call-2", usd: "200000", calls: "1" },
        ]),
        sourceSha256: { ledger: "1".repeat(64) },
      },
      undefined,
      10,
    );
    assert.deepEqual(first.totals, {
      external_calls: "2",
      usd_micros: "500000",
    });
    assert.equal(first.verdict, "pass");

    const second = reconcileSpend(
      config,
      "verification",
      {
        output: events("3", [
          { id: "call-2", usd: "200000", calls: "1" },
          { id: "call-3", usd: "250000", calls: "1" },
        ]),
        sourceSha256: { ledger: "2".repeat(64) },
      },
      first,
      20,
    );
    assert.deepEqual(second.delta, {
      external_calls: "1",
      usd_micros: "250000",
    });
    assert.deepEqual(second.totals, {
      external_calls: "3",
      usd_micros: "750000",
    });
    assert.throws(
      () =>
        reconcileSpend(
          config,
          "verification",
          {
            output: events("4", [
              { id: "call-1", usd: "300001", calls: "1" },
            ]),
            sourceSha256: { ledger: "3".repeat(64) },
          },
          second,
        ),
      /changed after reconciliation/,
    );
  });

  it("detects watermark regression and over-budget totals", () => {
    const first = reconcileSpend(
      config,
      "execution",
      {
        output: events("5", [
          { id: "call-1", usd: "900000", calls: "4" },
        ]),
        sourceSha256: {},
      },
    );
    assert.throws(
      () =>
        reconcileSpend(
          config,
          "verification",
          {
            output: events("4", [
              { id: "call-2", usd: "1", calls: "0" },
            ]),
            sourceSha256: {},
          },
          first,
        ),
      /watermark regressed/,
    );
    const over = reconcileSpend(
      config,
      "verification",
      {
        output: events("6", [
          { id: "call-2", usd: "100001", calls: "1" },
        ]),
        sourceSha256: {},
      },
      first,
    );
    assert.equal(over.verdict, "over_budget");
  });

  it("rejects duplicates, noncanonical numbers, and unknown units", () => {
    assert.throws(
      () =>
        events("2", [
          { id: "same", usd: "1", calls: "0" },
          { id: "same", usd: "1", calls: "0" },
        ]),
      /duplicate event/,
    );
    assert.throws(
      () =>
        validateAccountingEvents({
          schema: ACCOUNTING_EVENTS_SCHEMA,
          watermarks: { provider: "01" },
          events: [],
        }),
      /canonical integer/,
    );
    assert.throws(
      () =>
        reconcileSpend(config, "execution", {
          output: validateAccountingEvents({
            schema: ACCOUNTING_EVENTS_SCHEMA,
            watermarks: { provider: "1" },
            events: [
              {
                id: "gpu-1",
                phase: "execution",
                units: { gpu_seconds: "1" },
              },
            ],
          }),
          sourceSha256: {},
        }),
      /unbudgeted unit/,
    );
  });
});
