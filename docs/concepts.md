# Concepts

This page defines the small set of terms used by the CLI, the docs, and
the public Python API.

## Policy

A YAML file describing one or more gates that an action or diff must
pass. Loaded by `latchpoint_core.policy_loader`. See
[`policies.md`](policies.md) for the schema.

## Action

A JSON descriptor of a proposed action: an `id`, a `type`, a `target`,
a `risk_tier` in `T0..T4`, plus required identifiers and optional
`inputs`/`metadata` mappings. Validated by
`latchpoint_core.action_model`.

## Diff

A unified-diff text file. The diff adapter
(`latchpoint_core.diff_adapter`) parses changed paths and added/removed
lines, computes a stable `diff_hash`, and synthesises a structured
action that the gate evaluator runs. Explicit pattern detection inside
the diff only — not semantic code review and not repository scanning.

## Risk tier

One of `T0`, `T1`, `T2`, `T3`, `T4`. Caller-supplied. Tier `T4`
denotes "human approval required" and routes to `ESCALATE` via the
engine's built-in `override_required` default.

## Gate

A named rule that fires on an action or diff. A gate has a `trigger`
(currently `pre_execution`), a list of conditions, an
`action_on_fail` (`BLOCK`, `WARN`, or `LOG`), and optional
`applies_to` tier filters.

## Verdict

One of `approve` | `block` | `override_required` (the canonical
decision), surfaced as the human-readable mnemonic
`PASS` / `FIX` / `ESCALATE`. Exit codes are `0` / `1` / `2`
respectively. See [`evidence.md`](evidence.md) for fail-closed-error
semantics.

## Evidence pack

A canonical-JSON container with three sections —
`deterministic_facts`, `policy_verdict`, `model_derived_judgments` —
plus a manifest carrying per-section SHA-256 hashes and a top-level
`pack_hash`. Built by `latchpoint_core.evidence_pack`. See
[`evidence.md`](evidence.md) for the schema.

## Verify

Recompute section and pack hashes from the canonical bytes and compare
against the embedded manifest. Performed by
`latchpoint_core.evidence_verifier`.

## Replay

When `--policy` and `--action` are supplied alongside `--verify`, the
verifier re-runs the gate against the recorded inputs and confirms the
recomputed decision matches the recorded one.

## Tamper detection

Verification is strict over the recognized canonical evidence content
(the four sections listed under [Evidence pack](#evidence-pack)).
Modifying any recognized field changes the section hash and the pack
hash, and verify returns `verify_status: FAIL` with one or more
`reason: section hash mismatch` or `pack hash mismatch` lines and exit
code `2`. Fields outside the recognized schema are not part of the
current tamper-detection claim.
