# coding-agent-team

Local Cursor SDK multi-agent team for VPN/SSH remotes: one **Opus master** spawns specialty subagents with **classifier fallback chains** ending on **Grok**. Optional scout fan-out, parallel exec, watchdog, and **Slack HITL** (ask + await your reply).

## Architecture (P1)

```
  YOU (VPN/SSH) · local only · brain + latency
       │
       v
  MASTER  Opus → Sol fast → Terra fast → GPT → Grok
       │
       ├─ implementer / tester / executor / debugger  (Sol→Terra→GPT→Grok)
       ├─ reviewer  (Opus→Sol→Terra→GPT→Grok)
       ├─ --fan-out scouts  (Luna→Grok)
       ├─ --parallel-exec shards
       └─ Slack HITL + watchdog (stale/idle/auth)
```

## Remote server setup (no secret copy-paste)

On each VPN/SSH host:

```bash
git clone https://github.com/nirosen/coding-agent-team.git
cd coding-agent-team
cp .env.example .env
# edit .env locally on the host — never commit it
npm install
export $(grep -v '^#' .env | xargs)   # or use your secret manager
npm run team -- --cwd /path/to/your/repo --task "..."
```

**Secrets stay on the host only** (`.env` is gitignored). This repo has placeholders in `.env.example` only.

```bash
export CURSOR_API_KEY=...
# optional HITL
export SLACK_BOT_TOKEN=xoxb-...
export SLACK_CHANNEL_ID=C...   # #nir-ccb-aisec
```

**Never commit tokens.** Rotate any secret that was pasted into chat.

Confirm model ids for your account with a small script using `Cursor.models.list()` if create fails on an id (especially Luna).

## Live interactive session

Local SDK runs **do not** appear in Cursor’s Agents Window (that filter is for cloud/SDK cloud). Watch the session in the **SSH terminal** where you launch the team:

```bash
ssh you@remote
cd coding-agent-team
npm run team -- --cwd /path/to/repo --task "..."
# optional: --verbose   more events
#           --quiet     text-only
```

You’ll see role banners, streaming assistant text, tool calls (`⚙`), status lines, and classifier fallbacks. If the master needs approval and Slack isn’t set, it prompts `Your reply>` in that same TTY.

Second window (optional): `tail -f /path/to/repo/.team-state/team-*.json` for job status.

```bash
npm run team -- --cwd /path/to/repo --task "Add rate limiting to the login API"

npm run team -- --cwd /path/to/repo --fan-out \
  --fan-out-focus "auth entrypoints" \
  --fan-out-focus "existing rate-limit middleware" \
  --task "How does auth work and where to add limits?"

npm run team -- --cwd /path/to/repo \
  --task "Fix flaky suite" \
  --exec-shard "npm test -- --shard=1/2" \
  --exec-shard "npm test -- --shard=2/2"
```

State: `<cwd>/.team-state/team-*.json`.

## Slack HITL

When the master prints `HITL_REQUIRED: ...`, the runner posts to Slack and waits for a **thread reply** (approve/deny, choice, or free text), then continues.

Webhook-only (`SLACK_WEBHOOK_URL`) is alert-outbound; bidirectional Q&A needs the bot token + channel id.

## Scripts

```bash
npm run team -- --help
npm run typecheck
```
