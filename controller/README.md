# mec04 Codex controller

The controller and worker use separate hosts and separate working trees:

```
Nir ↔ Codex/Luna (mec04) ──SSH + signed controls──► team harness (worker)
```

The controller’s Ed25519 private key never leaves mec04. The worker has only
the public key and rejects unsigned, expired, wrong-run, or wrong-question
messages.

`launch-controller.sh` keeps Codex in `workspace-write` with standing network
access disabled. SSH-backed `teamctl` commands use Codex’s native on-request
approval. It does not use `danger-full-access`.

## One-time setup on mec04

```bash
cp controller.example.json controller.json
# Edit controller.json: point team_cwd at a dedicated next-task clone.
npm install
./teamctl self-test
./teamctl keygen
```

Do not configure `team_cwd` to the live RUN6 workspace.

## Launch

```bash
./launch-controller.sh
tmux attach -t aisec-controller
```

From another machine:

```bash
ssh -t cyl-mec04 'tmux attach -t aisec-controller'
```

The controller may query status at any time. `steer` and `authorize` work only
for runs started with the matching public key. `start` installs that public key
on the worker and launches the harness in a separate worker tmux session.

Test the full flow first with a no-spend mock repository/task.
