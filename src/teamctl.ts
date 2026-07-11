#!/usr/bin/env node
/**
 * Codex-facing controller CLI.
 *
 * Runs on the controller host (mec04), signs commands locally with Ed25519,
 * and transfers only signed envelopes/public keys to the worker over SSH.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  CONTROL_SCHEMA,
  generateControllerKeyPair,
  isUnsafeAuthorizationValue,
  looksLikeSecret,
  publicKeyFingerprint,
  questionSha256,
  redactSecrets,
  signControlEnvelope,
  type AuthorizationDecision,
  type ControlCapability,
  type UnsignedControlEnvelope,
  verifyControlEnvelope,
  writeControlEnvelope,
  scanControlSpool,
  acknowledgeControl,
} from "./control.js";
import type { TeamStateFile } from "./state.js";

type ControllerConfig = {
  worker_host: string;
  team_cwd: string;
  harness_dir: string;
  worker_tmux_session: string;
  worker_control_root: string;
  worker_public_key_path: string;
  private_key_path: string;
  public_key_path: string;
  minimum_free_gb?: number;
  require_docker?: boolean;
};

type RemoteStatus = {
  capability?: ControlCapability;
  state?: TeamStateFile;
  tmuxAlive: boolean;
  tmuxPaneDead: boolean;
  staleCapabilities: Array<Pick<ControlCapability, "teamRunId" | "pid" | "controlDir">>;
};

function usage(): never {
  console.error(`Usage:
  npm run teamctl -- --config controller/controller.json <command>

Commands:
  keygen                         Generate controller Ed25519 key pair
  self-test                      Verify signing/spool locally; no SSH
  status                         Print active worker/capability/state JSON
  tail                           Capture recent harness tmux output
  start <task-file>              Start a new signed-control harness run
  steer <text...>                Queue signed run-scoped guidance
  authorize <decision>           Sign exact pending HITL gate

Decisions:
  approve | approve:<scope> | approve-<scope> | deny | cancel | choice:<value>
`);
  process.exit(2);
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\"'\"'`)}'`;
}

function parseCli(argv: string[]): {
  configPath: string;
  command: string;
  rest: string[];
} {
  let configPath = path.resolve("controller/controller.json");
  const args = [...argv];
  if (args[0] === "--config") {
    if (!args[1]) usage();
    configPath = path.resolve(args[1]);
    args.splice(0, 2);
  }
  const command = args.shift();
  if (!command) usage();
  return { configPath, command, rest: args };
}

function loadConfig(configPath: string): {
  config: ControllerConfig;
  configDir: string;
} {
  const config = JSON.parse(
    fs.readFileSync(configPath, "utf8"),
  ) as ControllerConfig;
  if (!/^[A-Za-z0-9_.@-]+$/.test(config.worker_host)) {
    throw new Error("worker_host contains unsafe characters");
  }
  for (const [field, value] of Object.entries({
    team_cwd: config.team_cwd,
    harness_dir: config.harness_dir,
    worker_control_root: config.worker_control_root,
    worker_public_key_path: config.worker_public_key_path,
  })) {
    if (
      typeof value !== "string" ||
      !value.startsWith("/") ||
      /[\u0000-\u001f\u007f]/.test(value)
    ) {
      throw new Error(`${field} must be an absolute path without control characters`);
    }
  }
  if (!/^[A-Za-z0-9_.-]+$/.test(config.worker_tmux_session)) {
    throw new Error("worker_tmux_session contains unsafe characters");
  }
  if (
    config.minimum_free_gb !== undefined &&
    (!Number.isFinite(config.minimum_free_gb) ||
      config.minimum_free_gb < 0 ||
      config.minimum_free_gb > 100_000)
  ) {
    throw new Error("minimum_free_gb is invalid");
  }
  return { config, configDir: path.dirname(configPath) };
}

function resolveConfigPath(configDir: string, configured: string): string {
  if (configured === "~" || configured.startsWith("~/")) {
    return path.join(os.homedir(), configured.slice(2));
  }
  return path.isAbsolute(configured)
    ? configured
    : path.resolve(configDir, configured);
}

function remotePython(
  config: ControllerConfig,
  code: string,
  args: string[],
  opts: { input?: string; capture?: boolean; timeoutMs?: number } = {},
): string {
  const command = [
    "python3",
    "-c",
    shellQuote(code),
    ...args.map(shellQuote),
  ].join(" ");
  const result = spawnSync(
    "ssh",
    [
      "-o",
      "BatchMode=yes",
      "-o",
      "ConnectTimeout=15",
      config.worker_host,
      command,
    ],
    {
      encoding: "utf8",
      input: opts.input,
      stdio: opts.capture
        ? ["pipe", "pipe", "pipe"]
        : ["pipe", "inherit", "inherit"],
      timeout: opts.timeoutMs ?? 30_000,
    },
  );
  if (result.status !== 0) {
    throw new Error(
      `worker SSH failed (${result.status}): ${result.stderr || result.error?.message || ""}`,
    );
  }
  return result.stdout ?? "";
}

const STATUS_CODE = String.raw`
import json,os,pathlib,subprocess,sys
root=pathlib.Path(sys.argv[1]).expanduser().resolve()
cwd=sys.argv[2]
session=sys.argv[3]
def process_alive(pid):
  if pid<=0: return False
  try: os.kill(pid,0); return True
  except PermissionError: return True
  except ProcessLookupError: return False
active=[]
stale=[]
if root.is_dir():
  for enabled in root.glob("*/enabled.json"):
    try:
      if enabled.is_symlink() or enabled.stat().st_size>65536: continue
      cap=json.loads(enabled.read_text())
      if pathlib.Path(cap.get("controlDir","")).resolve()!=enabled.parent.resolve(): continue
      if cap.get("active") and cap.get("cwd")==cwd:
        pid=int(cap.get("pid",0))
        if process_alive(pid): active.append((enabled.stat().st_mtime,cap))
        else: stale.append({"teamRunId":cap.get("teamRunId"),"pid":pid,"controlDir":cap.get("controlDir")})
    except Exception:
      pass
active.sort(reverse=True,key=lambda item:item[0])
cap=active[0][1] if active else None
state=None
if cap:
  state_path=pathlib.Path(cap["stateFile"])
  expected=(pathlib.Path(cwd)/".team-state").resolve()
  if state_path.is_file() and not state_path.is_symlink() and state_path.stat().st_size<=10485760 and state_path.resolve().parent==expected:
    candidate=json.loads(state_path.read_text())
    if candidate.get("teamRunId")==cap.get("teamRunId") and candidate.get("cwd")==cwd:
      state=candidate
tmux=subprocess.run(["tmux","has-session","-t",session],capture_output=True).returncode==0
pane_dead=False
if tmux:
  panes=subprocess.run(["tmux","list-panes","-t",session,"-F","#{pane_dead}"],text=True,capture_output=True)
  pane_dead=panes.returncode!=0 or "1" in panes.stdout.split()
print(json.dumps({"capability":cap,"state":state,"tmuxAlive":tmux,"tmuxPaneDead":pane_dead,"staleCapabilities":stale},indent=2))
`;

function getStatus(config: ControllerConfig): RemoteStatus {
  const output = remotePython(
    config,
    STATUS_CODE,
    [
      config.worker_control_root,
      config.team_cwd,
      config.worker_tmux_session,
    ],
    { capture: true },
  );
  return JSON.parse(output) as RemoteStatus;
}

function redactForDisplay(value: unknown): unknown {
  if (typeof value === "string") return redactSecrets(value);
  if (Array.isArray(value)) return value.map(redactForDisplay);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [
        key,
        redactForDisplay(nested),
      ]),
    );
  }
  return value;
}

function keyPaths(
  config: ControllerConfig,
  configDir: string,
): { privatePath: string; publicPath: string } {
  const paths = {
    privatePath: resolveConfigPath(configDir, config.private_key_path),
    publicPath: resolveConfigPath(configDir, config.public_key_path),
  };
  const keyRoot = path.join(os.homedir(), ".coding-agent-team");
  for (const candidate of [paths.privatePath, paths.publicPath]) {
    const resolved = path.resolve(candidate);
    if (
      resolved !== keyRoot &&
      !resolved.startsWith(`${path.resolve(keyRoot)}${path.sep}`)
    ) {
      throw new Error(`controller keys must stay under ${keyRoot}`);
    }
  }
  return paths;
}

function readPrivateFile(filePath: string): string {
  let fd: number | undefined;
  try {
    const before = fs.lstatSync(filePath);
    if (
      !before.isFile() ||
      before.isSymbolicLink() ||
      before.size > 64 * 1024
    ) {
      throw new Error(`controller key must be a small regular file: ${filePath}`);
    }
    fd = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const opened = fs.fstatSync(fd);
    if (!opened.isFile() || opened.ino !== before.ino) {
      throw new Error(`controller key changed while opening: ${filePath}`);
    }
    if ((opened.mode & 0o077) !== 0) {
      throw new Error(`controller key permissions must be 0600: ${filePath}`);
    }
    return fs.readFileSync(fd, "utf8");
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function writeNewPrivateFile(filePath: string, contents: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(
      filePath,
      fs.constants.O_WRONLY |
        fs.constants.O_CREAT |
        fs.constants.O_EXCL,
      0o600,
    );
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function syncDirectory(dir: string): void {
  let fd: number | undefined;
  try {
    fd = fs.openSync(dir, fs.constants.O_RDONLY);
    fs.fsyncSync(fd);
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

function keygen(config: ControllerConfig, configDir: string): void {
  const { privatePath, publicPath } = keyPaths(config, configDir);
  if (fs.existsSync(privatePath) || fs.existsSync(publicPath)) {
    throw new Error("refusing to overwrite existing controller key");
  }
  fs.mkdirSync(path.dirname(privatePath), { recursive: true, mode: 0o700 });
  fs.mkdirSync(path.dirname(publicPath), { recursive: true, mode: 0o700 });
  for (const dir of new Set([
    path.dirname(privatePath),
    path.dirname(publicPath),
  ])) {
    const keyDir = fs.lstatSync(dir);
    if (!keyDir.isDirectory() || keyDir.isSymbolicLink()) {
      throw new Error("controller key directory must be a real directory");
    }
    fs.chmodSync(dir, 0o700);
  }
  const pair = generateControllerKeyPair();
  writeNewPrivateFile(privatePath, pair.privateKeyPem);
  writeNewPrivateFile(publicPath, pair.publicKeyPem);
  syncDirectory(path.dirname(privatePath));
  if (path.dirname(publicPath) !== path.dirname(privatePath)) {
    syncDirectory(path.dirname(publicPath));
  }
  console.log(`private: ${privatePath}`);
  console.log(`public:  ${publicPath}`);
  console.log(`fingerprint: SHA256:${publicKeyFingerprint(pair.publicKeyPem)}`);
}

function selfTest(): void {
  const keys = generateControllerKeyPair();
  const now = Date.now();
  const envelope = signControlEnvelope(
    {
      schema: CONTROL_SCHEMA,
      id: `self-test-${crypto.randomUUID()}`,
      kind: "steer",
      createdAt: now,
      expiresAt: now + 60_000,
      issuer: "teamctl-self-test",
      teamRunId: "team-self-test",
      text: "local no-network control self-test",
    },
    keys.privateKeyPem,
  );
  if (!verifyControlEnvelope(envelope, keys.publicKeyPem)) {
    throw new Error("self-test signature verification failed");
  }
  const controlDir = fs.mkdtempSync(
    path.join(os.tmpdir(), "teamctl-self-test-"),
  );
  try {
    writeControlEnvelope(controlDir, envelope);
    const pending = scanControlSpool(controlDir, {
      publicKeyPem: keys.publicKeyPem,
      teamRunId: "team-self-test",
    });
    if (pending.length !== 1) {
      throw new Error("self-test spool delivery failed");
    }
    acknowledgeControl(controlDir, pending[0]!);
  } finally {
    fs.rmSync(controlDir, { recursive: true, force: true });
  }
  console.log("teamctl self-test: PASS (Ed25519 + durable spool; no SSH)");
}

function readControllerKeys(
  config: ControllerConfig,
  configDir: string,
): {
  privateKey: string;
  publicKey: string;
  fingerprint: string;
} {
  const { privatePath, publicPath } = keyPaths(config, configDir);
  const privateKey = readPrivateFile(privatePath);
  const publicKey = readPrivateFile(publicPath);
  const derived = crypto
    .createPublicKey(crypto.createPrivateKey(privateKey))
    .export({ type: "spki", format: "pem" })
    .toString();
  if (publicKeyFingerprint(derived) !== publicKeyFingerprint(publicKey)) {
    throw new Error("controller public/private keys do not match");
  }
  return {
    privateKey,
    publicKey,
    fingerprint: publicKeyFingerprint(publicKey),
  };
}

const START_CODE = String.raw`
import base64,json,os,pathlib,socket,subprocess,sys,time,uuid
team=pathlib.Path(sys.argv[1])
harness=pathlib.Path(sys.argv[2])
session=sys.argv[3]
task=base64.b64decode(sys.stdin.read())
public_key=pathlib.Path(sys.argv[4]).expanduser()
min_gb=sys.argv[5]
require_docker=sys.argv[6]=="1"
control_root=pathlib.Path(sys.argv[7]).expanduser().resolve()
public_key_bytes=base64.b64decode(sys.argv[8])
expected_fingerprint=sys.argv[9]
def process_alive(pid):
  if pid<=0: return False
  try: os.kill(pid,0); return True
  except PermissionError: return True
  except ProcessLookupError: return False
if not team.is_dir(): raise SystemExit(f"team cwd not found: {team}")
if not harness.is_dir(): raise SystemExit(f"harness not found: {harness}")
if subprocess.run(["tmux","has-session","-t",session],capture_output=True).returncode==0:
  panes=subprocess.run(["tmux","list-panes","-t",session,"-F","#{pane_dead}"],text=True,capture_output=True)
  if panes.returncode==0 and panes.stdout.split() and all(value=="1" for value in panes.stdout.split()):
    subprocess.run(["tmux","kill-session","-t",session],check=True)
  else:
    raise SystemExit(f"live tmux session already exists: {session}")
if control_root.is_dir():
  for enabled in control_root.glob("*/enabled.json"):
    try:
      if enabled.is_symlink() or enabled.stat().st_size>65536: continue
      cap=json.loads(enabled.read_text())
      pid=int(cap.get("pid",0))
      if cap.get("active") and cap.get("cwd")==str(team) and pid>0 and process_alive(pid):
        raise SystemExit(f"active control run already owns cwd: {cap.get('teamRunId')}")
    except (json.JSONDecodeError,ValueError,TypeError):
      continue
lock=team/".team-state"/"writer.lock"
if lock.exists():
  if lock.is_symlink() or not lock.is_file() or lock.stat().st_size>8192:
    raise SystemExit(f"unsafe writer lock; inspect manually: {lock}")
  try:
    lock_data=json.loads(lock.read_text())
    lock_pid=int(lock_data.get("pid",0))
    if lock_data.get("schema")!="coding-agent-team-lock/v1" or lock_pid<=0:
      raise ValueError("invalid lock schema or pid")
    if lock_data.get("host")!=socket.gethostname() or process_alive(lock_pid):
      raise SystemExit(f"active writer lock exists: {lock}")
    os.replace(lock,lock.with_name(lock.name+f".stale.{int(time.time()*1000)}.{uuid.uuid4().hex}"))
    lock_dir_fd=os.open(lock.parent,os.O_RDONLY)
    try: os.fsync(lock_dir_fd)
    finally: os.close(lock_dir_fd)
  except (json.JSONDecodeError,ValueError,TypeError):
    raise SystemExit(f"malformed writer lock; inspect manually: {lock}")
public_key.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
if public_key.parent.is_symlink(): raise SystemExit("public key parent cannot be a symlink")
os.chmod(public_key.parent,0o700)
if public_key.exists():
  if public_key.is_symlink() or not public_key.is_file() or public_key.read_bytes()!=public_key_bytes:
    raise SystemExit("worker controller public key differs; refusing replacement")
else:
  key_tmp=public_key.with_name(public_key.name+f".{os.getpid()}.{uuid.uuid4().hex}.tmp")
  with key_tmp.open("xb") as handle:
    handle.write(public_key_bytes); handle.flush(); os.fsync(handle.fileno())
  os.chmod(key_tmp,0o600)
  try: os.link(key_tmp,public_key)
  except FileExistsError:
    if public_key.is_symlink() or public_key.read_bytes()!=public_key_bytes:
      raise SystemExit("worker controller public key changed concurrently")
  finally: key_tmp.unlink(missing_ok=True)
  key_dir_fd=os.open(public_key.parent,os.O_RDONLY)
  try: os.fsync(key_dir_fd)
  finally: os.close(key_dir_fd)
tasks=pathlib.Path.home()/".coding-agent-team"/"tasks"
tasks.mkdir(parents=True,exist_ok=True,mode=0o700)
task_file=tasks/f"task-{int(time.time()*1000)}-{uuid.uuid4().hex}.md"
tmp=task_file.with_suffix(".tmp")
with tmp.open("xb") as handle:
  handle.write(task); handle.flush(); os.fsync(handle.fileno())
os.chmod(tmp,0o600)
os.replace(tmp,task_file)
task_dir_fd=os.open(tasks,os.O_RDONLY)
try: os.fsync(task_dir_fd)
finally: os.close(task_dir_fd)
args=["npm","run","team","--","--cwd",str(team),"--task-file",str(task_file),
      "--steer","--controller-public-key",str(public_key),
      "--min-free-gb",min_gb,"--verbose"]
if require_docker: args.append("--require-docker")
quoted=" ".join(__import__("shlex").quote(item) for item in args)
command=f"cd {__import__('shlex').quote(str(harness))} && source scripts/load-env.sh && exec {quoted}"
launch_started=int(time.time()*1000)
subprocess.run(["tmux","new-session","-d","-s",session,command],check=True)
subprocess.run(["tmux","set-option","-t",session,"remain-on-exit","on"],check=True)
for _ in range(120):
  for enabled in control_root.glob("*/enabled.json") if control_root.is_dir() else []:
    try:
      cap=json.loads(enabled.read_text())
      pid=int(cap.get("pid",0))
      if (cap.get("active") and cap.get("cwd")==str(team)
          and cap.get("publicKeyFingerprint")==expected_fingerprint
          and int(cap.get("startedAt",0))>=launch_started
          and process_alive(pid)):
        print(f"started tmux={session} run={cap.get('teamRunId')} task={task_file}")
        raise SystemExit(0)
    except (json.JSONDecodeError,ValueError,TypeError):
      pass
  pane_dead=subprocess.run(["tmux","list-panes","-t",session,"-F","#{pane_dead}"],text=True,capture_output=True)
  if pane_dead.returncode!=0 or "1" in pane_dead.stdout.split():
    pane=subprocess.run(["tmux","capture-pane","-pt",f"{session}:0","-S","-80"],text=True,capture_output=True)
    raise SystemExit("harness tmux exited before control capability became active\n"+pane.stdout+pane.stderr)
  time.sleep(.5)
raise SystemExit("harness is still live but control capability was not observed within 60s; run status before retrying")
`;

function start(
  config: ControllerConfig,
  configDir: string,
  taskPath: string,
): void {
  const resolvedTask = path.resolve(taskPath);
  const taskInfo = fs.lstatSync(resolvedTask);
  if (
    !taskInfo.isFile() ||
    taskInfo.isSymbolicLink() ||
    taskInfo.size > 1024 * 1024
  ) {
    throw new Error("task must be a regular non-symlink file of at most 1 MiB");
  }
  const task = fs.readFileSync(resolvedTask);
  if (!task.toString("utf8").trim()) throw new Error("task file is empty");
  const keys = readControllerKeys(config, configDir);
  remotePython(
    config,
    START_CODE,
    [
      config.team_cwd,
      config.harness_dir,
      config.worker_tmux_session,
      config.worker_public_key_path,
      String(config.minimum_free_gb ?? 20),
      config.require_docker === false ? "0" : "1",
      config.worker_control_root,
      Buffer.from(keys.publicKey).toString("base64"),
      keys.fingerprint,
    ],
    { input: task.toString("base64"), timeoutMs: 75_000 },
  );
}

const WRITE_ENVELOPE_CODE = String.raw`
import base64,json,os,pathlib,subprocess,sys,uuid
control=pathlib.Path(sys.argv[1])
expected_run=sys.argv[2]
expected_fingerprint=sys.argv[3]
payload=json.loads(base64.b64decode(sys.argv[4]))
root=pathlib.Path(sys.argv[5]).expanduser().resolve()
session=sys.argv[6]
expected_cwd=sys.argv[7]
if control.resolve().parent!=root: raise SystemExit("control directory is outside configured root")
enabled=control/"enabled.json"
if not enabled.is_file() or enabled.is_symlink() or enabled.stat().st_size>65536: raise SystemExit("control capability unavailable")
cap=json.loads(enabled.read_text())
if not cap.get("active"): raise SystemExit("control capability is inactive")
if cap.get("teamRunId")!=expected_run: raise SystemExit("team run changed")
if cap.get("publicKeyFingerprint")!=expected_fingerprint: raise SystemExit("controller key mismatch")
if cap.get("cwd")!=expected_cwd: raise SystemExit("controller cwd mismatch")
pid=int(cap.get("pid",0))
if pid<=0: raise SystemExit("harness pid is invalid")
try: os.kill(pid,0)
except (ProcessLookupError,ValueError): raise SystemExit("harness process is not alive")
panes=subprocess.run(["tmux","list-panes","-t",session,"-F","#{pane_dead}"],text=True,capture_output=True)
if panes.returncode!=0 or not panes.stdout.split() or any(value=="1" for value in panes.stdout.split()):
  raise SystemExit("harness tmux is unavailable or dead")
if pathlib.Path(cap.get("controlDir","")).resolve()!=control.resolve(): raise SystemExit("control directory mismatch")
inbox=control/"inbox"
inbox.mkdir(parents=True,exist_ok=True,mode=0o700)
if inbox.is_symlink(): raise SystemExit("control inbox cannot be a symlink")
name=f"{payload['createdAt']:016d}-{payload['id']}.json"
tmp=control/f".{name}.{os.getpid()}.{uuid.uuid4().hex}.tmp"
fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
with os.fdopen(fd,"w") as handle:
  handle.write(json.dumps(payload,indent=2)+"\n"); handle.flush(); os.fsync(handle.fileno())
try: os.link(tmp,inbox/name)
except FileExistsError: raise SystemExit("control envelope id already exists")
finally: tmp.unlink(missing_ok=True)
for directory in (control,inbox):
  dir_fd=os.open(directory,os.O_RDONLY)
  try: os.fsync(dir_fd)
  finally: os.close(dir_fd)
print(inbox/name)
`;

function sendEnvelope(
  config: ControllerConfig,
  status: RemoteStatus,
  envelope: UnsignedControlEnvelope,
  privateKey: string,
  fingerprint: string,
): void {
  const capability = status.capability;
  if (!capability?.active) throw new Error("no active control capability");
  if (!status.tmuxAlive || status.tmuxPaneDead) {
    throw new Error("worker tmux is unavailable or dead");
  }
  if (capability.publicKeyFingerprint !== fingerprint) {
    throw new Error("active worker uses a different controller key");
  }
  const signed = signControlEnvelope(envelope, privateKey);
  remotePython(config, WRITE_ENVELOPE_CODE, [
    capability.controlDir,
    capability.teamRunId,
    fingerprint,
    Buffer.from(JSON.stringify(signed)).toString("base64"),
    config.worker_control_root,
    config.worker_tmux_session,
    config.team_cwd,
  ]);
  console.log(
    JSON.stringify(
      { queued: signed.id, kind: signed.kind, teamRunId: signed.teamRunId },
      null,
      2,
    ),
  );
}

function baseEnvelope(
  status: RemoteStatus,
  kind: "steer" | "authorization",
): Omit<UnsignedControlEnvelope, "text" | "decision" | "questionSha256"> {
  if (!status.capability?.active) throw new Error("no active team run");
  const now = Date.now();
  return {
    schema: CONTROL_SCHEMA,
    id: `${kind}-${crypto.randomUUID()}`,
    kind,
    createdAt: now,
    expiresAt: now + 15 * 60 * 1000,
    issuer: "mec04-codex-controller",
    teamRunId: status.capability.teamRunId,
  };
}

function parseDecision(raw: string): {
  decision: AuthorizationDecision;
  value?: string;
} {
  const answer = raw.trim();
  if (looksLikeSecret(answer)) {
    throw new Error("secret-shaped values are forbidden in authorizations");
  }
  if (/^approve$/i.test(answer)) return { decision: "approve" };
  const approve = answer.match(/^approve[-:]([A-Za-z0-9_.-]{1,128})$/i);
  if (approve?.[1] && !isUnsafeAuthorizationValue(approve[1])) {
    return { decision: "approve", value: approve[1] };
  }
  if (/^deny$/i.test(answer)) return { decision: "deny" };
  if (/^cancel$/i.test(answer)) return { decision: "cancel" };
  const choice = answer.match(/^choice:([A-Za-z0-9_.-]{1,128})$/i);
  if (choice?.[1] && !isUnsafeAuthorizationValue(choice[1])) {
    return { decision: "choice", value: choice[1] };
  }
  throw new Error(
    "invalid decision; use approve, approve:<scope>, deny, cancel, or choice:<value>",
  );
}

function steer(
  config: ControllerConfig,
  configDir: string,
  text: string,
): void {
  if (!text.trim()) throw new Error("steer text is empty");
  if (looksLikeSecret(text)) {
    throw new Error("secret-shaped values are forbidden in steers");
  }
  const status = getStatus(config);
  const keys = readControllerKeys(config, configDir);
  const runningJob = Object.values(status.state?.jobs ?? {}).find(
    (job) => job.status === "running",
  );
  sendEnvelope(
    config,
    status,
    {
      ...baseEnvelope(status, "steer"),
      jobId: runningJob?.jobId,
      text: text.trim(),
    },
    keys.privateKey,
    keys.fingerprint,
  );
}

function authorize(
  config: ControllerConfig,
  configDir: string,
  rawDecision: string,
): void {
  const status = getStatus(config);
  const keys = readControllerKeys(config, configDir);
  const waiting = Object.values(status.state?.jobs ?? {}).filter(
    (job) => job.status === "awaiting_human" && job.hitlQuestion,
  );
  if (waiting.length !== 1) {
    throw new Error(
      `expected exactly one awaiting_human job, found ${waiting.length}`,
    );
  }
  const job = waiting[0]!;
  if (looksLikeSecret(job.hitlQuestion!)) {
    throw new Error(
      "pending HITL question contains a secret-shaped value; refusing authorization",
    );
  }
  const parsed = parseDecision(rawDecision);
  sendEnvelope(
    config,
    status,
    {
      ...baseEnvelope(status, "authorization"),
      jobId: job.jobId,
      questionSha256:
        job.hitlQuestionSha256 ?? questionSha256(job.hitlQuestion!),
      decision: parsed.decision,
      value: parsed.value,
    },
    keys.privateKey,
    keys.fingerprint,
  );
}

const TAIL_CODE = String.raw`
import subprocess,sys
session=sys.argv[1]
result=subprocess.run(["tmux","capture-pane","-pt",f"{session}:0","-S","-160"],text=True,capture_output=True)
if result.returncode: raise SystemExit(result.stderr)
print(result.stdout,end="")
`;

function main(): void {
  const cli = parseCli(process.argv.slice(2));
  const { config, configDir } = loadConfig(cli.configPath);
  switch (cli.command) {
    case "keygen":
      if (cli.rest.length) usage();
      keygen(config, configDir);
      return;
    case "self-test":
      if (cli.rest.length) usage();
      selfTest();
      return;
    case "status":
      if (cli.rest.length) usage();
      console.log(JSON.stringify(redactForDisplay(getStatus(config)), null, 2));
      return;
    case "tail":
      if (cli.rest.length) usage();
      process.stdout.write(
        redactSecrets(
          remotePython(config, TAIL_CODE, [config.worker_tmux_session], {
            capture: true,
          }),
        ),
      );
      return;
    case "start":
      if (cli.rest.length !== 1) usage();
      start(config, configDir, cli.rest[0]!);
      return;
    case "steer":
      if (!cli.rest.length) usage();
      steer(config, configDir, cli.rest.join(" "));
      return;
    case "authorize":
      if (cli.rest.length !== 1) usage();
      authorize(config, configDir, cli.rest[0]!);
      return;
    default:
      usage();
  }
}

try {
  main();
} catch (error) {
  console.error(
    redactSecrets(error instanceof Error ? error.message : String(error)),
  );
  process.exitCode = 1;
}
