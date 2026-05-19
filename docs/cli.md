# CLI reference

This page documents the public, basic local CLI workflows for
Latchpoint Core: the `check` mode that turns a policy plus an action
or a diff into a verdict and an evidence pack, the `verify` mode that
hash-checks an evidence pack and optionally replays the recorded gate
decision, and the `run` mode that drives a JSON payload through the
local synthetic adapter and writes the resulting evidence pack and
per-section files to a directory.

The CLI is invoked as `latchpoint-core ...`. All three modes are
available both as flag-based forms (default flat-arg form for `check`,
`--verify` for `verify`) and as the subcommands `check`, `verify`,
and `run`. The evaluation path reads no system clock, generates no
randomness, and makes no network calls.

## Verdict mapping

| Decision           | Mnemonic   | Exit code |
|--------------------|------------|-----------|
| `approve`          | `PASS`     | `0`       |
| `block`            | `FIX`      | `1`       |
| `override_required`| `ESCALATE` | `2`       |

Any fail-closed configuration error (malformed policy, malformed
action, malformed diff, missing file, unreadable file, malformed
JSON, malformed evidence pack, gate evaluation error, evidence build
error) maps to `ESCALATE` / exit `2`.

## `check` mode

Loads a policy, validates an action descriptor (or synthesises one
from a unified diff), evaluates the gate, and emits a verdict plus an
evidence pack with a stable SHA-256 `pack_hash`. `check` is the
default mode when no `--verify` flag is supplied.

### Flags

| Flag             | Required | Default | Purpose                                                                                                                                                              |
|------------------|----------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--policy`       | yes      | —       | Path to a YAML policy file.                                                                                                                                          |
| `--action`       | one of   | —       | Path to a JSON action descriptor. Mutually exclusive with `--diff`.                                                                                                  |
| `--diff`         | one of   | —       | Path to a unified-diff text file. The diff adapter parses changed paths and added/removed lines and synthesises an action. Mutually exclusive with `--action`.       |
| `--risk-tier`    | no       | `T1`    | One of `T0`, `T1`, `T2`, `T3`, `T4`. Only meaningful with `--diff`. `T4` routes the synthesised diff action to `ESCALATE` via the engine's built-in `override_required` default. |
| `--at`           | no       | `1970-01-01T00:00:00+00:00` | ISO 8601 build-time stamp recorded in the synthesised action's `timestamp` field. Only meaningful with `--diff`. No system clock is read.            |
| `--evidence-out` | no       | —       | Path to write the canonical-JSON evidence pack to. Parent directories are created.                                                                                   |

Exactly one of `--action` or `--diff` must be supplied. Supplying
both or neither is a configuration error and fails closed.

### Stdout

```
verdict: PASS|FIX|ESCALATE
decision: approve|block|override_required
reason: <one line per reason>
gates_evaluated: <comma-separated list>
pack_hash: <64-hex-character SHA-256>
```

When `--evidence-out` is supplied, one extra line is printed:

```
evidence_path: <path>
```

### Exit codes

| Code | Meaning                                                                  |
|------|--------------------------------------------------------------------------|
| `0`  | `verdict: PASS`.                                                          |
| `1`  | `verdict: FIX`.                                                           |
| `2`  | `verdict: ESCALATE`, or any fail-closed configuration error.              |

### Example — structured action

```bash
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

Returns `verdict: PASS`, exit `0`. Substituting
`examples/actions/risky.json` returns `verdict: FIX`, exit `1`;
substituting `examples/actions/escalate.json` returns
`verdict: ESCALATE`, exit `2`.

### Example — diff input

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/safe_docs.diff
```

Returns `verdict: PASS`. A docs-only diff matches no rule.

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/private_path.diff
```

Returns `verdict: FIX`. The diff adds a synthetic machine-local
home-path pattern; the policy's regex gate fires on
`inputs.added_lines`.

Adding `--risk-tier T4` routes a passing diff to `ESCALATE` via the
engine's `override_required` default:

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/workflow.diff \
  --risk-tier T4
```

## `verify` mode

Reads an evidence-pack JSON file, recomputes section and pack hashes
from the canonical bytes, and compares them against the embedded
manifest. When `--policy` and `--action` are both supplied, the
verifier additionally replays the recorded gate decision and confirms
that the supplied policy and action reproduce it.

Verify mode is selected by passing the `--verify` flag.

### Flags

| Flag            | Required | Default | Purpose                                                                                                                                                                  |
|-----------------|----------|---------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--verify`      | yes      | —       | Switches the parser into verify mode.                                                                                                                                    |
| `--evidence-in` | yes      | —       | Path to an evidence-pack JSON file.                                                                                                                                      |
| `--policy`      | no       | —       | YAML policy file. Required when `--action` is supplied. Used together with `--action` to replay the recorded gate decision.                                              |
| `--action`      | no       | —       | JSON action descriptor. Required when `--policy` is supplied.                                                                                                            |
| `--override`    | no       | —       | Path to a JSON object describing the override decision recorded in the evidence pack. Triggers override-aware replay: the recorded outcome is re-evaluated against the supplied inputs and an `override_replay_status` line is reported. Same JSON shape as the `run`-mode `--override` flag. |
| `--ledger`      | no       | —       | Path to a JSON-array ledger chain file. Triggers ledger-aware replay: the chain must hash-verify end to end and the recorded `pack_hash` must appear in it exactly once. Unlike `run` mode, the path must already exist; a missing path is a configuration error and fails closed. |

`--policy` and `--action` must both be supplied or both omitted.
Supplying exactly one is a configuration error and fails closed.

`--override` and `--ledger` are optional companion replay checks. They
are independent of basic evidence-hash verification, which needs only
`--evidence-in`.

### Stdout

```
verify_status: PASS|FAIL
pack_hash: <recomputed pack hash>
replay_status: REPLAY_PASS|REPLAY_FAIL|NOT_REPLAYABLE
reason: <one line per verify reason>
replay_reason: <one line per replay reason>
override_replay_status: OVERRIDE_REPLAY_PASS|OVERRIDE_REPLAY_FAIL|OVERRIDE_NOT_REPLAYABLE|OVERRIDE_NOT_PRESENT
override_replay_reason: <one line per override replay reason>
ledger_replay_status: LEDGER_REPLAY_PASS|LEDGER_REPLAY_FAIL|LEDGER_NOT_REPLAYABLE
ledger_replay_reason: <one line per ledger replay reason>
```

`replay_status` is `REPLAY_PASS` when the supplied policy + action
reproduce the recorded decision, `REPLAY_FAIL` on any mismatch, and
`NOT_REPLAYABLE` when `--policy` or `--action` is omitted.

`override_replay_status` is `OVERRIDE_NOT_PRESENT` when the evidence
pack records no override and no override-replay inputs are supplied,
`OVERRIDE_NOT_REPLAYABLE` when the pack does record an override but
override-replay inputs are absent (for example, `--override` is
omitted), and `OVERRIDE_REPLAY_PASS` / `OVERRIDE_REPLAY_FAIL` when the
recorded override is re-evaluated.
`ledger_replay_status` is `LEDGER_NOT_REPLAYABLE` when `--ledger` is
omitted, and `LEDGER_REPLAY_PASS` / `LEDGER_REPLAY_FAIL` when a chain
is checked. On `LEDGER_REPLAY_PASS`, three further lines —
`ledger_replay_sequence`, `ledger_replay_prev_hash`, and
`ledger_replay_entry_hash` — record the matched chain entry.

### Exit codes

| Code | Meaning                                                                                                  |
|------|----------------------------------------------------------------------------------------------------------|
| `0`  | `verify_status: PASS`, `replay_status` ∈ `{REPLAY_PASS, NOT_REPLAYABLE}`, and neither `override_replay_status` nor `ledger_replay_status` is a `*_REPLAY_FAIL`. |
| `2`  | `verify_status: FAIL`, any `REPLAY_FAIL` / `OVERRIDE_REPLAY_FAIL` / `LEDGER_REPLAY_FAIL`, malformed input, missing file, or unreadable file. |

### Example — hash check only

```bash
latchpoint-core --verify --evidence-in evidence.json
```

### Example — hash check + replay

```bash
latchpoint-core --verify \
  --evidence-in evidence.json \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

## `run` mode

Loads a YAML policy, reads a JSON payload object, drives it through
the local synthetic adapter, evaluates the gate, builds an evidence
pack, and writes the pack and per-section files as canonical JSON to
`--out`. The output directory must be empty or absent; the pipeline
refuses to overwrite a non-empty directory.

Selected by passing `run` as the subcommand:

```bash
latchpoint-core run --policy POLICY --payload PAYLOAD --out OUT [...]
```

### Flags

| Flag            | Required | Default | Purpose                                                                                                                                            |
|-----------------|----------|---------|----------------------------------------------------------------------------------------------------------------------------------------------------|
| `--policy`      | yes      | —       | Path to a YAML policy file.                                                                                                                        |
| `--payload`     | yes      | —       | Path to a JSON payload file. Must be a JSON object.                                                                                                |
| `--out`         | yes      | —       | Output directory. Must be empty or absent. The pipeline refuses to overwrite a non-empty directory.                                                |
| `--at`          | no       | —       | Optional ISO 8601 build-time stamp recorded deterministically in the evidence pack metadata. No system clock is ever read.                         |
| `--kill-switch` | no       | —       | Path to a JSON object with a single `state` field (`ACTIVE` \| `INACTIVE`). `ACTIVE` fails closed before policy evaluation and exits `2`.          |
| `--override`    | no       | —       | Path to a caller-supplied override decision. Applicable overrides allow the run to continue; rejected outcomes fail closed and write no evidence.  |
| `--ledger`      | no       | —       | Path to a JSON-array ledger chain. When supplied with an applicable `--override` and `--at`, a single `LedgerEntry` is appended after evidence write. |

### Stdout

```
verdict: PASS|FIX|ESCALATE
decision: approve|block|override_required
reason: <one line per reason>
gates_evaluated: <comma-separated list>
pack_hash: <64-hex-character SHA-256>
evidence_path: <directory path>
```

When `--override` resolves as applicable, an additional
`override_outcome:` line is printed before `evidence_path`.

### Exit codes

| Code | Meaning                                                                                  |
|------|------------------------------------------------------------------------------------------|
| `0`  | `verdict: PASS`.                                                                          |
| `1`  | `verdict: FIX`.                                                                           |
| `2`  | `verdict: ESCALATE`, or any fail-closed configuration error (malformed policy, malformed payload, adapter rejection, gate evaluation error, evidence build error, `--out` non-empty, mid-write OSError). |

### Example

```bash
latchpoint-core run \
  --policy examples/policies/basic.yaml \
  --payload examples/actions/safe.json \
  --out ./evidence_dir
```

Writes the canonical evidence pack and per-section files into
`./evidence_dir`. Identical inputs (same `--policy`, `--payload`, and
`--at` when supplied) produce byte-identical output files.

## Determinism

For `check`, `verify`, and `run`, identical inputs produce
byte-identical output. The evaluation path performs no clock reads,
no randomness, and no network access. The CLI performs local
filesystem I/O only on the paths supplied as flag values.

## Non-goals

- The CLI is not a hosted service and makes no network calls.
- The CLI is not a CI integration. Calling code (any CI system, a
  Git hook, an editor) is responsible for acting on the exit code.
- The diff adapter is not a repository scanner. It sees only the
  unified-diff text supplied via `--diff`.
- The CLI does not auto-detect elevated-blast-radius paths. `T4`
  escalation is caller-supplied via `--risk-tier T4`.

## See also

- [`evidence.md`](evidence.md) — evidence-pack schema, `pack_hash`
  derivation, tamper-detection scope.
- [`policies.md`](policies.md) — full policy schema.
- [`limitations.md`](limitations.md) — the full list of what
  Latchpoint Core does not do.
