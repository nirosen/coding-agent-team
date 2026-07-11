import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { generateControllerKeyPair } from "./control.js";
import {
  ACCOUNTING_CONFIG_SCHEMA,
  validateAccountingConfig,
} from "./accounting.js";
import {
  COMMAND_MANIFEST_SCHEMA,
  TEST_MANIFEST_SCHEMA,
  validateCommandManifest,
  validateTestManifest,
} from "./manifests.js";
import {
  POLICY_PROFILE_SCHEMA,
  RUN_BINDING_SCHEMA,
  artifactSha256,
  canonicalJson,
  loadRunBundle,
  sha256,
  signRunBinding,
  validatePolicyProfile,
  verifyRunBinding,
  type PolicyProfile,
  type UnsignedRunBinding,
} from "./policy.js";

function fixture() {
  const workspace = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "policy-workspace-")),
  );
  const bundle = fs.mkdtempSync(path.join(os.tmpdir(), "policy-bundle-"));
  const adapter = path.join(bundle, "adapter.mjs");
  fs.writeFileSync(adapter, "#!/usr/bin/env node\nconsole.log('{}');\n", {
    mode: 0o700,
  });
  const profile: PolicyProfile = {
    schema: POLICY_PROFILE_SCHEMA,
    profileId: "ai-sec-evaluation",
    profileVersion: "1",
    enforcement: "hard",
    phases: ["selection", "terminal"],
    terminalPhase: "terminal",
    transitions: [
      {
        from: "selection",
        to: "terminal",
        requires: ["commands", "receipts", "accounting", "authorization", "idle"],
      },
    ],
  };
  const commands = validateCommandManifest({
    schema: COMMAND_MANIFEST_SCHEMA,
    commands: [
      {
        id: "selection-check",
        phase: "selection",
        kind: "command",
        argv: [process.execPath, "-e", "process.exit(0)"],
        cwd: ".",
        timeoutMs: 10_000,
        envAllowlist: [],
        executableSha256: sha256(fs.readFileSync(process.execPath)),
        expectedExitCodes: [0],
      },
    ],
  });
  const tests = validateTestManifest(
    { schema: TEST_MANIFEST_SCHEMA, selections: [] },
    commands,
  );
  const accounting = validateAccountingConfig({
    schema: ACCOUNTING_CONFIG_SCHEMA,
    adapter: {
      argv: [adapter],
      cwd: ".",
      executableSha256: sha256(fs.readFileSync(adapter)),
      envAllowlist: [],
      timeoutMs: 10_000,
    },
    sources: [],
    limits: { usd_micros: "0", external_calls: "0" },
  });
  const task = Buffer.from("Run the signed no-spend fixture.\n", "utf8");
  fs.writeFileSync(path.join(bundle, "task.md"), task);
  fs.writeFileSync(
    path.join(bundle, "profile.json"),
    `${canonicalJson(profile)}\n`,
  );
  fs.writeFileSync(
    path.join(bundle, "commands.json"),
    `${canonicalJson(commands)}\n`,
  );
  fs.writeFileSync(
    path.join(bundle, "tests.json"),
    `${canonicalJson(tests)}\n`,
  );
  fs.writeFileSync(
    path.join(bundle, "accounting.json"),
    `${canonicalJson(accounting)}\n`,
  );
  const keys = generateControllerKeyPair();
  const now = Date.now();
  const unsigned: UnsignedRunBinding = {
    schema: RUN_BINDING_SCHEMA,
    teamRunId: "team-policy-test",
    createdAt: now,
    expiresAt: now + 60_000,
    issuer: "test-controller",
    taskSha256: sha256(task),
    profileSha256: artifactSha256(profile),
    commandManifestSha256: artifactSha256(commands),
    testManifestSha256: artifactSha256(tests),
    accountingConfigSha256: artifactSha256(accounting),
    workspace: { cwd: workspace, gitHead: null },
  };
  const binding = signRunBinding(unsigned, keys.privateKeyPem);
  fs.writeFileSync(
    path.join(bundle, "binding.json"),
    `${canonicalJson(binding)}\n`,
  );
  return {
    workspace,
    bundle,
    profile,
    commands,
    tests,
    accounting,
    keys,
    binding,
    now,
  };
}

describe("signed run policy", () => {
  it("canonicalizes content independent of object insertion order", () => {
    assert.equal(
      canonicalJson({ z: [3, { b: true, a: "x" }], a: null }),
      '{"a":null,"z":[3,{"a":"x","b":true}]}',
    );
    assert.throws(() => canonicalJson({ amount: 0.1 }), /safe integers/);
  });

  it("loads an exact signed run bundle and rejects tampering", () => {
    const value = fixture();
    assert.equal(verifyRunBinding(value.binding, value.keys.publicKeyPem), true);
    const loaded = loadRunBundle(value.bundle, {
      publicKeyPem: value.keys.publicKeyPem,
      expectedCwd: value.workspace,
      expectedGitHead: null,
      now: value.now + 1,
    });
    assert.equal(loaded.binding.teamRunId, "team-policy-test");
    assert.equal(loaded.profile.profileId, "ai-sec-evaluation");

    fs.writeFileSync(
      path.join(value.bundle, "profile.json"),
      `${canonicalJson({ ...value.profile, profileVersion: "2" })}\n`,
    );
    assert.throws(
      () =>
        loadRunBundle(value.bundle, {
          publicKeyPem: value.keys.publicKeyPem,
          expectedCwd: value.workspace,
          expectedGitHead: null,
          now: value.now + 1,
        }),
      /does not match signed binding/,
    );
  });

  it("rejects unknown policy fields and invalid manifest references", () => {
    const value = fixture();
    assert.throws(
      () => validatePolicyProfile({ ...value.profile, surprise: true }),
      /unknown field/,
    );
    assert.throws(
      () =>
        validateCommandManifest({
          schema: COMMAND_MANIFEST_SCHEMA,
          commands: [
            {
              ...value.commands.commands[0],
              cwd: "../escape",
            },
          ],
        }),
      /cannot escape|stay inside/,
    );
    assert.throws(
      () =>
        validateCommandManifest({
          schema: COMMAND_MANIFEST_SCHEMA,
          commands: [
            {
              ...value.commands.commands[0],
              executableSha256: null,
            },
          ],
        }),
      /must be pinned/,
    );
    assert.throws(
      () =>
        validateTestManifest(
          {
            schema: TEST_MANIFEST_SCHEMA,
            selections: [
              {
                id: "wrong",
                phase: "selection",
                commandId: "selection-check",
                tests: ["test-a"],
                configPath: null,
                configSha256: null,
              },
            ],
          },
          value.commands,
        ),
      /matching test command/,
    );
  });
});
