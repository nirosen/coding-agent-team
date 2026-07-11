# coding-agent-team

Local Cursor SDK orchestration for VPN/SSH workers. An Opus master delegates to
specialists while a separate, low-latency Codex session can inspect status,
steer an active run, or relay an explicit human authorization.

## Architecture

```
Nir
 ├─ direct SSH/tmux ───────────────────────────────┐
 └─ Codex controller (mec04)                      │
       └─ SSH + signed, expiring controls         ▼
                                             worker (mec06)
                                     Opus master + specialists
                                             │
                                dedicated repository/worktree
```

- Master and standalone jobs use classifier fallback chains.
- Inline SDK specialists use explicit first-hop model assignments.
- Fan-out and execution shards run concurrently when requested.
- One writer lock protects each target cwd.
- Durable state is written atomically under `<cwd>/.team-state/`.
- Preflight can enforce free-space and Docker requirements before model spend.
- Mid-turn cancellation is used only when the selected runtime supports it;
  otherwise a steer is applied after the current turn settles.
- Cursor Auto-review is enabled for local SDK tool calls.

## Worker setup

```bash
git clone https://github.com/nirosen/coding-agent-team.git
cd coding-agent-team
chmod +x scripts/*.sh controller/teamctl
./scripts/bootstrap.sh
```

The first bootstrap creates a gitignored `.env` and exits. Fill
`CURSOR_API_KEY` and, optionally, Slack settings on that host, then rerun:

```bash
./scripts/bootstrap.sh
source scripts/load-env.sh
```

The bootstrap installs the Cursor CLI command `agent`, runs `agent login` when
needed, installs packages, and typechecks. Secrets remain host-local. This
harness never rotates or revokes credentials and never accepts credentials in
steer/authorization messages.

## Start a direct worker run

Use a dedicated clean clone/worktree:

```bash
npm run team -- \
  --cwd /path/to/dedicated-worktree \
  --task-file /path/to/task.md \
  --no-steer \
  --min-free-gb 20 \
  --require-docker \
  --verbose
```

`--no-steer` is an explicit opt-out for a direct, non-steerable run. Omit it
only after configuring `CODING_AGENT_CONTROL_PUBLIC_KEY` or pass
`--controller-public-key`; signed control is required by default.

Run under tmux for laptop disconnects:

```bash
tmux new -s coding-team
# run the command above
# detach: Ctrl-b, then d
tmux attach -t coding-team
```

Local SDK runs appear in this terminal, not Cursor’s cloud Agents Window.

## Signed control plane

With `--steer`, the harness accepts Ed25519-signed JSON envelopes in a
run-scoped spool outside the target repository. Every control is:

- bound to the exact `teamRunId`;
- signed by the configured controller key;
- schema validated and size limited;
- expiring and protected against replay;
- atomically moved to `processed/` or `rejected/`.

Authorizations additionally bind to the exact job and normalized HITL-question
hash. Allowed decisions are:

```
approve
approve:<scope>
deny
cancel
choice:<value>
```

A steer changes guidance only. It never grants spend, deploy, push, destructive
cleanup, credential, or other named-gate authority.

## mec04 Codex controller → mec06 worker

Set up the controller in a separate clone on mec04:

```bash
cd controller
cp controller.example.json controller.json
# Edit controller.json. Use a dedicated next-task cwd, never a live run.
./teamctl self-test
./teamctl keygen
./launch-controller.sh
tmux attach -t aisec-controller
```

The private key stays under `~/.coding-agent-team/` on mec04. `teamctl start`
installs only its public key on mec06. It creates the worker key only when
absent and refuses to replace a different existing key; the controller never
rotates or revokes it.

Controller commands:

```bash
./teamctl status
./teamctl tail
./teamctl start tasks/my-task.md
./teamctl steer "freeze accounting before the next named gate"
./teamctl authorize "approve:phase-a"
```

`status` is read-only. The Codex controller must obtain a current-turn user
instruction before `start`, `steer`, or `authorize`; it must not infer approval
from previous turns. See `controller/AGENTS.md`.

Do not deploy this build into a workspace with a currently active writer. Test
the end-to-end controller flow first on a no-spend mock task.

## Enforcement boundary

Signed controls authenticate who supplied guidance or a gate decision; they do
not interpose on Cursor’s internal tool executor. The master is instructed to
stop before named gates, and control-channel failure aborts or fails the run,
but prompt policy alone is not a security boundary against a noncompliant
model.

For hard guarantees, run the worker with least privilege: no production
credentials, no deploy/push rights, isolated Docker resources, and OS/Cursor
hooks that deny protected commands independently of the model. Authenticate
out of band only after a matching gate. Do not treat the harness’s
`HITL_REQUIRED` protocol as a substitute for those controls.

## Slack HITL and optional steering

```bash
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_CHANNEL_ID=C...
export SLACK_ALLOWED_USER_IDS=U123...,U456...
export SLACK_STEER_ENABLED=false
```

Slack replies are accepted only from allowlisted user IDs. HITL replies use the
structured decisions above; free text and secret-shaped values are rejected.
Outbound-only webhooks cannot provide HITL replies.

If Slack steering is explicitly enabled, messages must target the active run:

```
STEER <teamRunId>: short imperative guidance
```

When signed control is configured, it is the authoritative authorization
channel; Slack is notification-only and timeout fails closed. Without signed
control, the harness uses allowlisted Slack, then the attached TTY. Slack API
calls are paginated and time bounded.

## State and verification

State file:

```
<cwd>/.team-state/team-<teamRunId>.json
```

Useful commands:

```bash
npm run team -- --help
npm run typecheck
npm test
```
