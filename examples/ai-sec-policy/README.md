# AI-sec hard-policy profile

This profile supplies phase semantics only. A controller-side run bundle must
also contain:

```
task.md
profile.json
commands.json
tests.json
accounting.json
```

`teamctl start <bundle-directory>` validates those files, resolves the worker
workspace identity, generates a unique run ID, signs `binding.json`, and
transfers the completed bundle. Do not create `binding.json` manually.

The command manifest uses exact argv arrays, relative working directories,
environment-variable names (never values), expected exit codes, and required
executable SHA-256 pins. Test selections reference test command IDs and may
pin a workspace-relative test configuration path and digest.

The accounting config maps logical source slots to run-specific ledger paths
and pins an adapter executable by SHA-256. The adapter prints:

```json
{
  "schema": "coding-agent-team-accounting-events/v1",
  "watermarks": { "provider": "0" },
  "events": []
}
```

Each event has a unique ID, phase, and canonical non-negative integer units
such as `usd_micros` and `external_calls`. The harness validates adapter and
source hashes, event immutability, monotonic watermarks, exact totals, and
signed limits. The adapter is still responsible for mapping authoritative
provider receipts into this standard form; the harness cannot independently
observe provider billing.
