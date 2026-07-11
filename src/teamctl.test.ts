import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { execFileSync, spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import {
  acknowledgeControl,
  authorizationMatches,
  publicKeyFingerprint,
  scanControlSpool,
  writeControlCapability,
} from "./control.js";
import { TeamStateStore } from "./state.js";

const root = path.resolve(import.meta.dirname, "..");

describe("controller artifacts", () => {
  it("keeps the example away from the live RUN6 workspace", () => {
    const example = fs.readFileSync(
      path.join(root, "controller", "controller.example.json"),
      "utf8",
    );
    assert.doesNotMatch(example, /run6/i);
    assert.match(example, /next-task/);
  });

  it("contains syntactically valid embedded worker Python", () => {
    const source = fs.readFileSync(path.join(root, "src", "teamctl.ts"), "utf8");
    const scripts = [
      ...source.matchAll(
        /const ([A-Z_]+_CODE) = String\.raw`([\s\S]*?)`;/g,
      ),
    ];
    assert.ok(scripts.length >= 4);
    for (const script of scripts) {
      const name = script[1]!;
      const code = script[2]!;
      const result = spawnSync(
        "python3",
        [
          "-c",
          "import sys; compile(sys.stdin.read(), sys.argv[1], 'exec')",
          name,
        ],
        { input: code, encoding: "utf8" },
      );
      assert.equal(result.status, 0, `${name}: ${result.stderr}`);
    }
  });

  it("steers and authorizes through teamctl without network", () => {
    const sandbox = fs.mkdtempSync(
      path.join(os.tmpdir(), "teamctl-e2e-test-"),
    );
    const home = path.join(sandbox, "home");
    const teamCwd = path.join(sandbox, "team");
    const harnessDir = path.join(sandbox, "harness");
    const controlRoot = path.join(sandbox, "control");
    const controlDir = path.join(controlRoot, "team-e2e");
    const fakeBin = path.join(sandbox, "bin");
    for (const dir of [home, teamCwd, harnessDir, fakeBin]) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(
      path.join(fakeBin, "ssh"),
      [
        "#!/bin/sh",
        'while [ "$1" = "-o" ]; do shift 2; done',
        "shift",
        'exec /bin/sh -c "$1"',
        "",
      ].join("\n"),
      { mode: 0o755 },
    );
    fs.writeFileSync(
      path.join(fakeBin, "tmux"),
      [
        "#!/bin/sh",
        'case "$1" in',
        "  has-session) exit 0 ;;",
        '  list-panes) printf "0\\n"; exit 0 ;;',
        "  *) exit 1 ;;",
        "esac",
        "",
      ].join("\n"),
      { mode: 0o755 },
    );

    const configPath = path.join(sandbox, "controller.json");
    fs.writeFileSync(
      configPath,
      JSON.stringify({
        worker_host: "local-test",
        team_cwd: teamCwd,
        harness_dir: harnessDir,
        worker_tmux_session: "team-e2e",
        worker_control_root: controlRoot,
        worker_public_key_path: path.join(home, "worker-controller.pub"),
        private_key_path: "~/.coding-agent-team/controller.key",
        public_key_path: "~/.coding-agent-team/controller.pub",
        minimum_free_gb: 0,
        require_docker: false,
      }),
    );
    const environment = {
      ...process.env,
      HOME: home,
      PATH: `${fakeBin}:${process.env.PATH ?? ""}`,
    };
    const teamctl = (...args: string[]): string =>
      execFileSync(
        path.join(root, "node_modules", ".bin", "tsx"),
        [
          path.join(root, "src", "teamctl.ts"),
          "--config",
          configPath,
          ...args,
        ],
        { cwd: root, env: environment, encoding: "utf8" },
      );

    assert.match(teamctl("self-test"), /PASS/);
    teamctl("keygen");
    const publicKey = fs.readFileSync(
      path.join(home, ".coding-agent-team", "controller.pub"),
      "utf8",
    );
    const state = new TeamStateStore(
      path.join(teamCwd, ".team-state"),
      "team-e2e",
      teamCwd,
    );
    state.upsert({
      jobId: "master-e2e",
      role: "master",
      status: "running",
    });
    writeControlCapability(controlDir, {
      active: true,
      teamRunId: "team-e2e",
      cwd: teamCwd,
      pid: process.pid,
      host: os.hostname(),
      startedAt: Date.now(),
      stateFile: state.filePath,
      publicKeyFingerprint: publicKeyFingerprint(publicKey),
    });

    teamctl("steer", "freeze before the next phase");
    let pending = scanControlSpool(controlDir, {
      publicKeyPem: publicKey,
      teamRunId: "team-e2e",
    });
    assert.equal(pending.length, 1);
    assert.equal(pending[0]?.envelope.text, "freeze before the next phase");
    acknowledgeControl(controlDir, pending[0]!);

    const question = "Approve this exact no-spend test gate?";
    state.markAwaitingHuman("master-e2e", question);
    teamctl("authorize", "approve");
    pending = scanControlSpool(controlDir, {
      publicKeyPem: publicKey,
      teamRunId: "team-e2e",
    });
    assert.equal(pending.length, 1);
    assert.equal(
      authorizationMatches(pending[0]!.envelope, {
        teamRunId: "team-e2e",
        jobId: "master-e2e",
        question,
      }),
      true,
    );
  });
});
