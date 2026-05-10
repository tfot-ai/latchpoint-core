# Quickstart

This walkthrough installs Latchpoint Core, runs the CLI against the
synthetic samples in `examples/`, generates an evidence pack, verifies
it, and demonstrates tamper detection.

## Install

Requires Python 3.11+.

```bash
pip install -e .
```

The package installs the `latchpoint-core` CLI and exposes
`latchpoint_core` as the importable Python package.

## Check a structured action

```bash
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

Output:

```
verdict: PASS
decision: approve
gates_evaluated:
pack_hash: <64-hex-character SHA-256>
```

Try the other two action samples to see `FIX` and `ESCALATE`:

```bash
latchpoint-core --policy examples/policies/basic.yaml --action examples/actions/risky.json
latchpoint-core --policy examples/policies/basic.yaml --action examples/actions/escalate.json
```

## Check a diff

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/safe_docs.diff
```

Returns `PASS` — the docs-only diff matches no rule.

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/private_path.diff
```

Returns `FIX` — the diff adds a synthetic machine-local home path and
the regex gate `machine_local_path_in_added_lines` fires.

## Generate and verify an evidence pack

```bash
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json \
  --evidence-out evidence.json

latchpoint-core --verify --evidence-in evidence.json
```

Output:

```
verify_status: PASS
pack_hash: <64-hex-character SHA-256>
replay_status: NOT_REPLAYABLE
```

Add `--policy` and `--action` to re-run the gate and confirm the recorded decision matches:

```bash
latchpoint-core --verify --evidence-in evidence.json \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

```
verify_status: PASS
pack_hash: <64-hex-character SHA-256>
replay_status: REPLAY_PASS
```

## Tamper detection

Edit `evidence.json` to change any recognized field (e.g., the
`policy_verdict.decision`), then verify again:

```bash
latchpoint-core --verify --evidence-in evidence.json
```

Returns `verify_status: FAIL` and exit code `2`.

## Next

- [`concepts.md`](concepts.md) — vocabulary.
- [`policies.md`](policies.md) — full policy schema.
- [`diff-input.md`](diff-input.md) — diff acceptance rules.
- [`evidence.md`](evidence.md) — evidence pack schema and replay.
- [`limitations.md`](limitations.md) — what Latchpoint Core does not do.
