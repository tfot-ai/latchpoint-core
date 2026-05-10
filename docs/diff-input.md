# Diff input

`latchpoint-core --diff <path>` accepts a unified-diff text file and
runs the gate evaluator against a structured action synthesised from
the diff. This is **explicit pattern detection inside the diff** —
extraction of changed paths and added/removed lines — not semantic
code review and not repository scanning.

## Acceptance

The diff adapter recognises these unified-diff header shapes:

- `+++ b/<path>` — post-image path. Captured into `changed_paths`.
- `+++ /dev/null` — deletion-only block. Skipped on the post-image side.
- `diff --git a/<path> b/<path>` — file separator. The post-image path
  is captured.
- `rename to <path>` — captures the new path.

Hunk markers (`@@`), `---` headers, `index` lines, `new file mode`,
`deleted file mode`, `Binary files`, and `similarity index` lines are
not treated as content.

Plain context lines are ignored. `+` lines are captured into
`added_lines`. `-` lines are captured into `removed_lines`.

## Synthesised action

The adapter produces a structured action with these fields:

| Field | Value |
|---|---|
| `id` | UUID derived deterministically from `(diff_hash, risk_tier, at)` |
| `type` | `"diff.apply"` |
| `target` | First entry in `changed_paths` |
| `risk_tier` | Caller-supplied via `--risk-tier`; default `T1` |
| `timestamp` | Caller-supplied via `--at`; default `1970-01-01T00:00:00+00:00` |
| `agent_id` | Fixed sentinel `"diff"` |
| `session_id` | Fixed sentinel `"diff"` |
| `inputs.changed_paths` | List of post-image paths |
| `inputs.changed_paths_blob` | Newline-joined paths for regex over many paths |
| `inputs.added_lines` | Newline-joined `+` content lines |
| `inputs.removed_lines` | Newline-joined `-` content lines |
| `inputs.diff_hash` | SHA-256 over the input bytes |
| `inputs.diff_summary` | `<file_count> file(s); +<added>/-<removed> lines` |

## Determinism

Identical diff bytes plus identical `--risk-tier` and `--at` produce a
byte-identical synthesised action and therefore a byte-identical
evidence pack with the same `pack_hash`. The system clock is never
read.

## Verdict routing

| Condition | Verdict |
|---|---|
| No gate fires AND `risk_tier != "T4"` | `PASS` |
| Any FAIL gate fires (e.g., regex match) | `FIX` |
| No FAIL gate AND `risk_tier == "T4"` | `ESCALATE` |

`T4` is the caller's signal that an elevated-blast-radius diff requires
human review. The engine does not auto-detect workflow paths or
sensitive areas in this slice; the caller chooses the tier.

## Sidecar action JSON

When both `--diff` and `--evidence-out` are supplied in check mode, the
CLI writes the synthesised action to `<evidence-out>.action.json`
alongside the evidence pack. A later `--verify --action <sidecar>`
invocation can replay the recorded gate decision.

## Errors

`DiffAdapterError` is raised when:

- the diff file is unreadable;
- the diff is empty;
- the diff contains no changed paths;
- `--risk-tier` is not in `T0..T4`;
- `--at`, `agent_id`, or `session_id` is empty.

In CLI mode all of these map to `verdict: ESCALATE` and exit code `2`.
