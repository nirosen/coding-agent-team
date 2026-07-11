import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { SDKCustomTool, SDKJsonValue } from "@cursor/sdk";
import {
  reconcileSpend,
  reconciliationSha256,
  runAccountingAdapter,
  validateAccountingConfig,
  type AccountingConfig,
  type SpendReconciliation,
} from "./accounting.js";
import type { ControlEnvelope } from "./control.js";
import {
  freezeRunArtifacts,
  commandDigest,
  validateCommandManifest,
  validateTestManifest,
  type CommandManifest,
  type FrozenArtifactRef,
  type FrozenRunArtifacts,
  type TestManifest,
} from "./manifests.js";
import {
  artifactSha256,
  canonicalJson,
  sha256,
  type LoadedRunBundle,
  type PolicyProfile,
  type PolicyTransition,
} from "./policy.js";
import type { ProcessRegistry } from "./process-registry.js";
import {
  type PolicyGateRecord,
  type TeamStateStore,
} from "./state.js";
import { requireGitHead, workspaceSnapshotSha256 } from "./workspace.js";

export const READINESS_SEAL_SCHEMA = "coding-agent-team-readiness-seal/v1";

export type GateAuthorization = {
  decision: "approve" | "deny" | "cancel";
  authorizationId?: string;
  controlEnvelope?: ControlEnvelope;
};

export type ReadinessSeal = {
  schema: typeof READINESS_SEAL_SCHEMA;
  teamRunId: string;
  profileId: string;
  profileVersion: string;
  profileSha256: string;
  bindingSha256: string;
  terminalPhase: string;
  artifactSha256: Record<string, string>;
  reconciliationSha256: string[];
  receiptsSha256: string;
  gateHistorySha256: string;
  finalAuthorizationId: string;
  finalAuthorizationEnvelopeSha256: string;
  workspaceSha256: string;
  sealedAt: number;
};

type PendingGate = {
  record: PolicyGateRecord;
  transition: PolicyTransition;
  evidence: Record<string, unknown>;
  reconciliation?: SpendReconciliation;
};

function syncDirectory(directory: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(directory, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "EINVAL" && code !== "ENOTSUP" && code !== "EISDIR") {
      throw error;
    }
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function writeArtifact(
  directory: string,
  name: string,
  value: unknown,
): FrozenArtifactRef {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const info = fs.lstatSync(directory);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`policy artifact path must be a real directory: ${directory}`);
  }
  const contents = `${canonicalJson(value)}\n`;
  const filePath = path.join(directory, name);
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL |
        (fs.constants.O_NOFOLLOW ?? 0),
      0o600,
    );
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
  syncDirectory(directory);
  return { path: filePath, sha256: sha256(contents.trimEnd()) };
}

function accountingEvidence(value: SpendReconciliation): Record<string, unknown> {
  return {
    previousSha256: value.previousSha256,
    sourceSha256: value.sourceSha256,
    watermarks: value.watermarks,
    eventIds: value.eventIds,
    eventSha256: value.eventSha256,
    delta: value.delta,
    totals: value.totals,
    limits: value.limits,
    verdict: value.verdict,
  };
}

function pinnedWorkspaceFileSha256(
  workspace: string,
  relativePath: string,
  expectedSha256: string,
): string {
  const candidate = path.resolve(workspace, relativePath);
  const resolved = fs.realpathSync(candidate);
  if (
    resolved !== workspace &&
    !resolved.startsWith(`${workspace}${path.sep}`)
  ) {
    throw new Error(`pinned artifact escapes workspace: ${relativePath}`);
  }
  const info = fs.lstatSync(candidate);
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    info.size > 64 * 1024 * 1024
  ) {
    throw new Error(`pinned artifact is not a small regular file: ${relativePath}`);
  }
  const actual = sha256(fs.readFileSync(candidate));
  if (actual !== expectedSha256) {
    throw new Error(`pinned artifact digest changed: ${relativePath}`);
  }
  return actual;
}

export class PolicyRuntime {
  readonly bundle: LoadedRunBundle;
  readonly profile: PolicyProfile;
  readonly commands: CommandManifest;
  readonly tests: TestManifest;
  readonly accounting: AccountingConfig;
  readonly artifacts: FrozenRunArtifacts;
  private readonly state: TeamStateStore;
  private readonly workspace: string;
  private readonly runArtifactDirectory: string;
  private registry?: ProcessRegistry;
  private pending?: PendingGate;
  private lastReconciliation?: SpendReconciliation;
  private reconciliationRefs: FrozenArtifactRef[] = [];
  private finalAuthorization?: GateAuthorization;

  constructor(opts: {
    bundle: LoadedRunBundle;
    state: TeamStateStore;
    stateDirectory: string;
    workspace: string;
  }) {
    this.bundle = opts.bundle;
    this.profile = opts.bundle.profile;
    this.commands = validateCommandManifest(opts.bundle.commandManifest);
    this.tests = validateTestManifest(opts.bundle.testManifest, this.commands);
    this.accounting = validateAccountingConfig(opts.bundle.accountingConfig);
    for (const command of this.commands.commands) {
      if (!this.profile.phases.includes(command.phase)) {
        throw new Error(
          `command ${command.id} references unknown phase ${command.phase}`,
        );
      }
      if (command.phase === this.profile.terminalPhase) {
        throw new Error(
          `terminal phase cannot declare executable command ${command.id}`,
        );
      }
    }
    for (const selection of this.tests.selections) {
      if (!this.profile.phases.includes(selection.phase)) {
        throw new Error(
          `test selection ${selection.id} references unknown phase ${selection.phase}`,
        );
      }
    }
    this.state = opts.state;
    this.workspace = fs.realpathSync(opts.workspace);
    if (
      opts.bundle.binding.workspace.gitHead !== requireGitHead(this.workspace)
    ) {
      throw new Error("policy runtime Git HEAD does not match the signed binding");
    }
    this.runArtifactDirectory = path.join(
      opts.stateDirectory,
      opts.bundle.binding.teamRunId,
      "policy",
    );
    this.artifacts = freezeRunArtifacts(
      opts.stateDirectory,
      opts.bundle.binding.teamRunId,
      {
        task: opts.bundle.taskBytes,
        profile: this.profile,
        commands: this.commands,
        tests: this.tests,
        accounting: this.accounting,
        binding: this.bundle.binding,
      },
    );
    this.state.initializePolicy({
      profileId: this.profile.profileId,
      profileVersion: this.profile.profileVersion,
      profileSha256: this.bundle.binding.profileSha256,
      bindingSha256: artifactSha256(this.bundle.binding),
      currentPhase: this.profile.phases[0]!,
      terminalPhase: this.profile.terminalPhase,
      artifacts: this.artifacts,
      gateHistory: [],
      reconciliationRefs: [],
    });
  }

  attachRegistry(registry: ProcessRegistry): void {
    if (this.registry) throw new Error("process registry is already attached");
    this.registry = registry;
  }

  currentPhase(): string {
    return (
      this.state.snapshot().policy?.currentPhase ?? this.profile.phases[0]!
    );
  }

  assertExecutionOpen(): void {
    if (this.pending || this.state.snapshot().runStatus === "awaiting_human") {
      throw new Error(
        "supervised execution is frozen while a policy gate awaits authorization",
      );
    }
    if (this.currentPhase() === this.profile.terminalPhase) {
      throw new Error("supervised execution is closed in the terminal phase");
    }
  }

  phaseTool(): SDKCustomTool {
    return {
      description:
        "Request an evidence-checked transition to the next phase in the signed policy. The harness, not the model, creates the exact authorization question.",
      inputSchema: {
        type: "object",
        properties: { targetPhase: { type: "string" } },
        required: ["targetPhase"],
        additionalProperties: false,
      },
      execute: async (args): Promise<SDKJsonValue> => {
        if (typeof args.targetPhase !== "string") {
          throw new Error("request_phase_transition requires targetPhase");
        }
        const result = this.requestTransition(args.targetPhase);
        return {
          status: "authorization_required",
          gateId: result.gateId,
          evidenceSha256: result.evidenceSha256,
          question: result.question,
          instruction:
            "End this turn. The harness will wait for a signed authorization; do not print or invent a different gate.",
        };
      },
    };
  }

  pendingQuestion(): string | undefined {
    return this.pending?.record.question;
  }

  private transitionTo(targetPhase: string): PolicyTransition {
    const current = this.currentPhase();
    const transition = this.profile.transitions.find(
      (candidate) =>
        candidate.from === current && candidate.to === targetPhase,
    );
    if (!transition) {
      throw new Error(`policy does not allow transition ${current} -> ${targetPhase}`);
    }
    if (!transition.requires.includes("authorization")) {
      throw new Error("hard-policy transitions must require authorization");
    }
    return transition;
  }

  private collectEvidence(
    transition: PolicyTransition,
    persistReconciliation: boolean,
  ): {
    evidence: Record<string, unknown>;
    reconciliation?: SpendReconciliation;
  } {
    const snapshot = this.state.snapshot();
    const phaseCommands = this.commands.commands.filter(
      (command) => command.phase === transition.from,
    );
    const passedReceipts = snapshot.receipts.filter(
      (receipt) =>
        receipt.phase === transition.from && receipt.status === "passed",
    );
    const workspaceSha256 = workspaceSnapshotSha256(this.workspace);
    for (const receipt of passedReceipts) {
      const command = this.commands.commands.find(
        (candidate) => candidate.id === receipt.commandId,
      );
      if (!command || receipt.commandSha256 !== commandDigest(command)) {
        throw new Error(
          `execution receipt does not match the frozen command: ${receipt.receiptId}`,
        );
      }
      if (
        (command.kind === "test" || command.kind === "review") &&
        receipt.workspaceSha256 !== workspaceSha256
      ) {
        throw new Error(
          `workspace changed after ${command.kind} receipt: ${receipt.receiptId}`,
        );
      }
    }
    const passedCommandIds = new Set(
      passedReceipts.map((receipt) => receipt.commandId),
    );
    const testConfigSha256 = Object.fromEntries(
      this.tests.selections
        .filter(
          (selection) =>
            selection.phase === transition.from &&
            selection.configPath !== null &&
            selection.configSha256 !== null,
        )
        .map((selection) => [
          selection.id,
          pinnedWorkspaceFileSha256(
            this.workspace,
            selection.configPath!,
            selection.configSha256!,
          ),
        ])
        .sort(([left], [right]) => left.localeCompare(right)),
    );
    if (
      transition.requires.includes("commands") &&
      phaseCommands.length === 0
    ) {
      throw new Error(`phase ${transition.from} has no frozen commands`);
    }
    if (transition.requires.includes("receipts")) {
      const missing = phaseCommands
        .filter((command) => !passedCommandIds.has(command.id))
        .map((command) => command.id);
      if (missing.length > 0) {
        throw new Error(`phase ${transition.from} lacks receipts: ${missing.join(", ")}`);
      }
    }
    if (transition.requires.includes("tests")) {
      const requiredTests = this.tests.selections.filter(
        (selection) => selection.phase === transition.from,
      );
      if (requiredTests.length === 0) {
        throw new Error(`phase ${transition.from} has no frozen test selection`);
      }
      const missing = requiredTests
        .filter((selection) => !passedCommandIds.has(selection.commandId))
        .map((selection) => selection.id);
      if (missing.length > 0) {
        throw new Error(`phase ${transition.from} lacks passing tests: ${missing.join(", ")}`);
      }
    }
    if (transition.requires.includes("review")) {
      const reviewCommands = phaseCommands.filter(
        (command) => command.kind === "review",
      );
      if (
        reviewCommands.length === 0 ||
        reviewCommands.some((command) => !passedCommandIds.has(command.id))
      ) {
        throw new Error(`phase ${transition.from} lacks a passing review receipt`);
      }
    }
    if (transition.requires.includes("idle")) {
      if (!this.registry) throw new Error("process registry is not attached");
      this.registry.assertIdle();
      const active = this.state.activeProcesses();
      if (active.length > 0) {
        throw new Error(
          `state still contains active supervised processes: ${active
            .map((record) => record.processId)
            .join(", ")}`,
        );
      }
    }

    let reconciliation: SpendReconciliation | undefined;
    let reconciliationEvidence: Record<string, unknown> | undefined;
    if (transition.requires.includes("accounting")) {
      const adapter = runAccountingAdapter(this.accounting, this.workspace);
      reconciliation = reconcileSpend(
        this.accounting,
        transition.from,
        adapter,
        this.lastReconciliation,
      );
      if (reconciliation.verdict !== "pass") {
        throw new Error("accounting reconciliation exceeds the signed budget");
      }
      reconciliationEvidence = accountingEvidence(reconciliation);
      if (persistReconciliation) {
        const ref = writeArtifact(
          this.runArtifactDirectory,
          `reconciliation-${String(this.reconciliationRefs.length + 1).padStart(3, "0")}.json`,
          reconciliation,
        );
        this.reconciliationRefs.push(ref);
        this.state.addReconciliationRef(ref);
      }
    }
    return {
      evidence: {
        teamRunId: this.bundle.binding.teamRunId,
        profileSha256: this.bundle.binding.profileSha256,
        bindingSha256: artifactSha256(this.bundle.binding),
        from: transition.from,
        to: transition.to,
        commandManifestSha256: this.bundle.binding.commandManifestSha256,
        testManifestSha256: this.bundle.binding.testManifestSha256,
        workspaceSha256,
        priorGateHistorySha256: artifactSha256(
          (snapshot.policy?.gateHistory ?? []).filter(
            (gate) => gate.resolvedAt !== undefined,
          ),
        ),
        testConfigSha256,
        receipts: passedReceipts
          .map((receipt) => ({
            receiptId: receipt.receiptId,
            commandId: receipt.commandId,
            commandSha256: receipt.commandSha256,
            workspaceSha256: receipt.workspaceSha256,
            status: receipt.status,
          }))
          .sort((left, right) => left.receiptId.localeCompare(right.receiptId)),
        accounting: reconciliationEvidence ?? null,
      },
      reconciliation,
    };
  }

  requestTransition(targetPhase: string): PolicyGateRecord {
    if (this.pending) throw new Error("a policy transition is already pending");
    const transition = this.transitionTo(targetPhase);
    const collected = this.collectEvidence(transition, true);
    const evidenceSha256 = artifactSha256(collected.evidence);
    const gateId = `gate-${crypto.randomUUID()}`;
    const question = [
      `Approve policy transition ${transition.from}->${transition.to}`,
      `for gate ${gateId}`,
      `with evidence_sha256=${evidenceSha256}?`,
      `Allowed replies: approve | deny | cancel`,
    ].join(" ");
    const record: PolicyGateRecord = {
      gateId,
      from: transition.from,
      to: transition.to,
      evidenceSha256,
      workspaceSha256: collected.evidence.workspaceSha256 as string,
      question,
      questionSha256: sha256(question.trim()),
      requestedAt: Date.now(),
    };
    this.pending = {
      record,
      transition,
      evidence: collected.evidence,
      reconciliation: collected.reconciliation,
    };
    this.state.setPolicyGate(record);
    return structuredClone(record);
  }

  authorizePending(authorization: GateAuthorization): void {
    if (!this.pending) throw new Error("no policy transition is pending");
    const pending = this.pending;
    const current = this.collectEvidence(pending.transition, false);
    const currentSha256 = artifactSha256(current.evidence);
    if (currentSha256 !== pending.record.evidenceSha256) {
      throw new Error(
        `policy evidence changed while awaiting authorization: ${pending.record.evidenceSha256} -> ${currentSha256}`,
      );
    }
    this.state.resolvePolicyGate({
      decision: authorization.decision,
      authorizationId: authorization.authorizationId,
    });
    if (authorization.decision !== "approve") {
      this.pending = undefined;
      return;
    }
    // Chain the next phase to the reconciliation that was durably written
    // before this authorization. The fresh reconciliation above is only a
    // stability check and intentionally is not an artifact-chain node.
    this.lastReconciliation =
      pending.reconciliation ?? this.lastReconciliation;
    this.state.advancePolicyPhase(pending.transition.to);
    this.finalAuthorization = authorization;
    this.pending = undefined;
    if (this.currentPhase() === this.profile.terminalPhase) {
      this.writeReadinessSeal();
    }
  }

  assertReady(): void {
    if (!this.isReady()) {
      const state = this.state.snapshot();
      throw new Error(
        `hard-policy run is not sealed ready (phase=${state.policy?.currentPhase ?? "unknown"})`,
      );
    }
  }

  isReady(): boolean {
    const state = this.state.snapshot();
    return (
      state.runStatus === "ready" &&
      state.policy?.currentPhase === this.profile.terminalPhase &&
      Boolean(state.policy.readinessSeal)
    );
  }

  private writeReadinessSeal(): void {
    if (!this.registry) throw new Error("process registry is not attached");
    this.registry.assertIdle();
    if (this.state.activeProcesses().length > 0) {
      throw new Error("cannot seal readiness while supervised work is active");
    }
    const authorization = this.finalAuthorization;
    if (
      !authorization?.authorizationId ||
      !authorization.controlEnvelope
    ) {
      throw new Error(
        "terminal readiness requires a signed controller authorization",
      );
    }
    const snapshot = this.state.snapshot();
    const passedCommandIds = new Set(
      snapshot.receipts
        .filter((receipt) => receipt.status === "passed")
        .map((receipt) => receipt.commandId),
    );
    const missingCommands = this.commands.commands
      .filter((command) => !passedCommandIds.has(command.id))
      .map((command) => command.id);
    if (missingCommands.length > 0) {
      throw new Error(
        `terminal readiness lacks command receipts: ${missingCommands.join(", ")}`,
      );
    }
    if (
      snapshot.receipts.some((receipt) => receipt.status !== "passed") ||
      snapshot.policy?.gateHistory.some(
        (gate) => gate.resolvedAt !== undefined && gate.decision !== "approve",
      )
    ) {
      throw new Error("failed receipts or gates prevent readiness sealing");
    }
    const seal: ReadinessSeal = {
      schema: READINESS_SEAL_SCHEMA,
      teamRunId: snapshot.teamRunId,
      profileId: this.profile.profileId,
      profileVersion: this.profile.profileVersion,
      profileSha256: this.bundle.binding.profileSha256,
      bindingSha256: artifactSha256(this.bundle.binding),
      terminalPhase: this.profile.terminalPhase,
      artifactSha256: Object.fromEntries(
        Object.entries(this.artifacts).map(([name, ref]) => [name, ref.sha256]),
      ),
      reconciliationSha256: this.reconciliationRefs.map((ref) => ref.sha256),
      receiptsSha256: artifactSha256(snapshot.receipts),
      gateHistorySha256: artifactSha256(snapshot.policy?.gateHistory ?? []),
      finalAuthorizationId: authorization.authorizationId,
      finalAuthorizationEnvelopeSha256: artifactSha256(
        authorization.controlEnvelope,
      ),
      workspaceSha256:
        snapshot.policy?.gateHistory.at(-1)?.workspaceSha256 ??
        workspaceSnapshotSha256(this.workspace),
      sealedAt: Date.now(),
    };
    const ref = writeArtifact(
      this.runArtifactDirectory,
      "readiness-seal.json",
      seal,
    );
    this.state.setReadinessSeal(ref);
  }
}

export function verifyReadinessSeal(value: unknown): ReadinessSeal {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("readiness seal must be an object");
  }
  const seal = value as Record<string, unknown>;
  const expected = [
    "schema",
    "teamRunId",
    "profileId",
    "profileVersion",
    "profileSha256",
    "bindingSha256",
    "terminalPhase",
    "artifactSha256",
    "reconciliationSha256",
    "receiptsSha256",
    "gateHistorySha256",
    "finalAuthorizationId",
    "finalAuthorizationEnvelopeSha256",
    "workspaceSha256",
    "sealedAt",
  ];
  const unknown = Object.keys(seal).find((key) => !expected.includes(key));
  const missing = expected.find(
    (key) => !Object.prototype.hasOwnProperty.call(seal, key),
  );
  if (unknown || missing || seal.schema !== READINESS_SEAL_SCHEMA) {
    throw new Error(
      unknown
        ? `readiness seal contains unknown field: ${unknown}`
        : `readiness seal is invalid${missing ? `; missing ${missing}` : ""}`,
    );
  }
  for (const field of [
    "teamRunId",
    "profileId",
    "profileVersion",
    "terminalPhase",
    "finalAuthorizationId",
  ]) {
    if (
      typeof seal[field] !== "string" ||
      !/^[A-Za-z0-9_.:@-]{1,256}$/.test(seal[field] as string)
    ) {
      throw new Error(`readiness seal ${field} is invalid`);
    }
  }
  for (const field of [
    "profileSha256",
    "bindingSha256",
    "receiptsSha256",
    "gateHistorySha256",
    "finalAuthorizationEnvelopeSha256",
    "workspaceSha256",
  ]) {
    if (
      typeof seal[field] !== "string" ||
      !/^[0-9a-f]{64}$/.test(seal[field] as string)
    ) {
      throw new Error(`readiness seal ${field} is invalid`);
    }
  }
  if (
    typeof seal.sealedAt !== "number" ||
    !Number.isSafeInteger(seal.sealedAt) ||
    seal.sealedAt < 0
  ) {
    throw new Error("readiness seal sealedAt is invalid");
  }
  const artifacts = seal.artifactSha256;
  if (!artifacts || typeof artifacts !== "object" || Array.isArray(artifacts)) {
    throw new Error("readiness seal artifactSha256 is invalid");
  }
  for (const [name, digest] of Object.entries(
    artifacts as Record<string, unknown>,
  )) {
    if (
      !/^[A-Za-z0-9_.-]{1,128}$/.test(name) ||
      typeof digest !== "string" ||
      !/^[0-9a-f]{64}$/.test(digest)
    ) {
      throw new Error("readiness seal contains an invalid artifact digest");
    }
  }
  if (
    !Array.isArray(seal.reconciliationSha256) ||
    seal.reconciliationSha256.some(
      (digest) => typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest),
    )
  ) {
    throw new Error("readiness seal reconciliationSha256 is invalid");
  }
  return seal as ReadinessSeal;
}

export function readinessSealSha256(seal: ReadinessSeal): string {
  return sha256(canonicalJson(seal));
}

export function reconciliationRefSha256(
  reconciliation: SpendReconciliation,
): string {
  return reconciliationSha256(reconciliation);
}
