# Evidence

An evidence pack is canonical JSON with a stable SHA-256 hash. It is
the portable artifact a third party can verify or replay without
re-running the model that produced the original action.

## Structure

```
{
  "deterministic_facts": {
    "action_id":   <string>,
    "policy_hash": <64-hex-character SHA-256>,
    "inputs":      <mapping>,
    "metadata":    <optional mapping>,
    "override":    <optional {override_id, outcome}>
  },
  "policy_verdict": {
    "decision":         "approve" | "block" | "override_required",
    "reasons":          [<string>, ...],
    "gates_evaluated":  [<string>, ...]
  },
  "model_derived_judgments": {
    "judgments": <mapping>
  },
  "manifest": {
    "pack_hash":      <64-hex-character SHA-256>,
    "section_hashes": {
      "deterministic_facts":      <hash>,
      "policy_verdict":           <hash>,
      "model_derived_judgments":  <hash>
    }
  }
}
```

`metadata` and `override` are omitted from the canonical JSON when
absent, preserving pack-hash byte stability for runs that did not
supply them.

## Canonical JSON

All evidence pack output uses sorted keys, compact separators
(`,` and `:`), and no trailing newline. Identical inputs produce a
byte-identical file with the same `pack_hash`.

## `pack_hash` derivation

1. Each section is serialised to canonical JSON and hashed with
   SHA-256. The three section hashes are recorded under
   `manifest.section_hashes`.
2. `manifest.section_hashes` is itself serialised to canonical JSON
   and hashed with SHA-256. The result is `manifest.pack_hash`.

## Verify

```bash
latchpoint-core --verify --evidence-in evidence.json
```

Recomputes section hashes from the canonical bytes and pack hash from
the recomputed section-hashes map. Compares both against the embedded
`manifest.pack_hash` and `manifest.section_hashes`. Output:

```
verify_status: PASS | FAIL
pack_hash: <recomputed pack hash>
replay_status: NOT_REPLAYABLE
```

## Replay

Add `--policy` and `--action` to re-run the gate from the original
inputs and confirm the recorded decision matches:

```bash
latchpoint-core --verify --evidence-in evidence.json \
  --policy <policy>.yaml \
  --action <action>.json
```

The verifier:

1. Recomputes the policy hash from the supplied policy and compares
   it against `deterministic_facts.policy_hash`.
2. Confirms the supplied action's `id` matches
   `deterministic_facts.action_id`.
3. Re-runs `evaluate_action(policy, action)` and compares the
   recomputed decision and `gates_evaluated` against the recorded
   ones.

`replay_status` is `REPLAY_PASS` when all three match,
`REPLAY_FAIL` on any mismatch, `NOT_REPLAYABLE` when `--policy` or
`--action` is omitted.

## Tamper detection

Verification is strict over every recognised evidence field. Modifying
the `decision`, the `inputs`, the `judgments`, or the manifest itself
changes one or more hashes; verify returns `verify_status: FAIL` with
explicit `reason: section hash mismatch: <name>` or
`reason: pack hash mismatch` lines, and exit code `2`. Hash mismatch
never returns `PASS`.

Unknown fields outside the verified schema may be ignored on read for
forward compatibility, so they are not part of the current tamper-
detection claim.

## Exit codes (`--verify` mode)

| Code | Meaning |
|---|---|
| `0` | Hash PASS and (`REPLAY_PASS` or `NOT_REPLAYABLE`). |
| `2` | Hash FAIL, replay FAIL, malformed input, missing file, or unreadable file. |
