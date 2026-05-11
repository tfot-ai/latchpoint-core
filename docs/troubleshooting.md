# Troubleshooting

Practical recovery for the most common things that go wrong on the path
from "I have a policy" to "I have a verified evidence pack". Latchpoint
Core fails closed: any configuration error during a `check` run maps to
`verdict: ESCALATE` and exit code `2`; any error during a `verify` run
maps to `verify_status: FAIL` and exit code `2`. The structured
`reason:` lines on stdout localise the failure.

## Policy load errors

The loader is strict. On failure it raises a `PolicyError` with one of
the following `code` values; the CLI surfaces the error as
`verdict: ESCALATE` / exit `2`. Codes (see [`policies.md`](policies.md#errors)
for the full list):

- `parse_error` — file missing, unreadable, not UTF-8, or invalid
  YAML 1.2.
- `schema_violation` — a required field is missing, has the wrong type,
  or two gates share the same `name`.
- `regex_violation` — `name` does not match `^[a-z][a-z0-9_-]*$`, or
  `version` is not valid SemVer 2.0.0.
- `enum_violation` — `trigger`, `action_on_fail`, condition `type`, or
  condition `operator` is outside the allowed alphabet. The allowed
  values are listed in [Gate shape](policies.md#gate-shape) and
  [Condition shape](policies.md#condition-shape).
- `mutual_exclusion_violation` — a simple condition has both `value`
  and `value_from`, or neither.
- `unknown_field` — a top-level, gate, or condition key is not in the
  schema. The loader has no permissive read; delete the field or
  replace it with a recognised one.

## Field-path and condition errors

A condition's `field` is a dot-notation path on the action descriptor.
The engine reads the path literally.

- Top-level fields are read directly: `type`, `target`, `risk_tier`,
  `id`, `agent_id`, `session_id`, `timestamp`.
- Nested fields under `inputs.*` are read by path. In diff mode only
  the fields the diff adapter synthesises are present
  (`inputs.changed_paths`, `inputs.changed_paths_blob`,
  `inputs.added_lines`, `inputs.removed_lines`, `inputs.diff_hash`,
  `inputs.diff_summary` — see
  [`diff-input.md`](diff-input.md#synthesised-action)). In
  structured-action mode `inputs.*` is whatever the caller writes into
  the action JSON.
- A field that does not exist on the action reads as `null`. Operator
  semantics over a missing field are operator-specific; see the
  operator table in [Condition shape](policies.md#condition-shape). If
  a condition silently never fires, check the spelling of the path
  against your action JSON.

## Regex confusion

`regex` conditions match against the value of a single `field`. Two
fields the diff adapter exposes are joined for regex convenience:

- `inputs.added_lines` and `inputs.removed_lines` are newline-joined
  strings of the `+` and `-` content lines from the diff.
- `inputs.changed_paths_blob` is a newline-joined string of post-image
  paths.

A pattern intended to match "one line" must be written with that
joining in mind — anchors like `^` and `$` over a newline-joined blob
are easy to get wrong. Copy the regex from the worked example in
[`policies.md`](policies.md#worked-example-diff-policy) before writing
your own.

YAML escaping is separate from regex escaping: backslashes inside a
double-quoted YAML string need doubling (`"\\d"`); single-quoted YAML
strings pass them through (`'\d'`).

## Unexpected `ESCALATE`

`ESCALATE` (decision `override_required`, exit code `2`) has two
paths:

- **Caller-supplied `T4`.** `--risk-tier T4` on a diff routes the
  synthesised action to `ESCALATE` via the engine's built-in
  `override_required` default, even when no gate fires. Drop
  `--risk-tier T4` if you did not intend a human-review tier.
- **Fail-closed configuration error.** Any malformed policy, action,
  diff, or evidence input maps to `ESCALATE` rather than `FIX`. Common
  causes: a `PolicyError` (see [Policy load errors](#policy-load-errors)),
  a `DiffAdapterError` (see below), supplying both `--action` and
  `--diff` or neither in check mode, or supplying exactly one of
  `--policy` / `--action` in verify mode.

The verdict-to-exit-code mapping is documented in
[`cli.md`](cli.md#verdict-mapping).

## Diff-input errors

`DiffAdapterError` is raised when:

- the diff file is unreadable;
- the diff is empty;
- the diff contains no changed paths (e.g., a hunk-only excerpt with
  no `+++` or `diff --git` headers);
- `--risk-tier` is not one of `T0`, `T1`, `T2`, `T3`, `T4`;
- `--at` is supplied but empty, or the synthesised `agent_id` /
  `session_id` slot is empty.

All of these map to `verdict: ESCALATE` and exit `2`. See
[`diff-input.md`](diff-input.md#acceptance) for the unified-diff
headers the adapter recognises.

## Verify and replay mismatches

In verify mode, failure is reported as `verify_status: FAIL` /
exit `2` with explicit `reason:` lines:

- `reason: section hash mismatch: <name>` — a field in the named
  section (`deterministic_facts`, `policy_verdict`, or
  `model_derived_judgments`) was modified after the pack was written.
  The recomputed canonical-JSON hash no longer matches
  `manifest.section_hashes[<name>]`.
- `reason: pack hash mismatch` — `manifest.section_hashes` was
  modified, or `manifest.pack_hash` does not match the recomputed pack
  hash.
- Other `reason:` lines surface malformed evidence JSON, a missing
  file, or an unreadable file.

Hash mismatch on recognised content never returns
`verify_status: PASS`. Unknown fields outside the recognised schema
may be ignored on read for forward compatibility and are not part of
the current tamper-detection claim — do not rely on verification
rejecting arbitrary unknown fields. See
[`evidence.md`](evidence.md#tamper-detection).

`replay_status` is independent of `verify_status`:

- `NOT_REPLAYABLE` — `--policy` or `--action` was not supplied; the
  hash check still ran.
- `REPLAY_PASS` — the supplied policy and action reproduce the
  recorded decision and `gates_evaluated`.
- `REPLAY_FAIL` — the recomputed policy hash, the action `id`, or the
  recomputed decision does not match the recorded one. Confirm you are
  passing the same policy and action that produced the pack. In diff
  mode, use the sidecar `<evidence-out>.action.json` the check run
  wrote alongside the evidence pack — see
  [`diff-input.md`](diff-input.md#sidecar-action-json).

`--policy` and `--action` must both be supplied or both omitted in
verify mode. Supplying exactly one is a configuration error and fails
closed.

## Evidence files and paths

- `--evidence-out` is a `check`-mode flag; it writes the
  canonical-JSON pack to that path and creates parent directories.
- `--evidence-in` is a `verify`-mode flag; it reads an existing pack
  from that path.
- In diff check mode, supplying `--evidence-out` also writes
  `<evidence-out>.action.json` — the synthesised action descriptor
  used as the replay sidecar.
- The pack is canonical JSON (sorted keys, compact separators `,` and
  `:`, no trailing newline). Editing the file with a tool that
  pretty-prints it changes the bytes and causes `pack hash mismatch`
  on verify.

## Exit codes at a glance

| Mode | Code | Meaning |
|---|---|---|
| `check` | `0` | `verdict: PASS`. |
| `check` | `1` | `verdict: FIX`. |
| `check` | `2` | `verdict: ESCALATE`, or any fail-closed configuration error. |
| `verify` | `0` | `verify_status: PASS` and `replay_status` ∈ `{REPLAY_PASS, NOT_REPLAYABLE}`. |
| `verify` | `2` | `verify_status: FAIL`, `replay_status: REPLAY_FAIL`, malformed input, missing file, or unreadable file. |
