# Policies

## What is a policy?

A Latchpoint policy is the rulebook the engine uses to evaluate a
proposed agent code change. It is a single YAML 1.2 file in a
Latchpoint-specific schema — not a generic ADR, OpenAPI spec,
Terraform policy, Rego policy, CI workflow, or linter config. The
building blocks (gates, conditions, allowlists, denylists, regexes,
thresholds, risk tiers) come from familiar policy-as-code ideas, but
the field names, operator alphabet, and verdict vocabulary are
specific to this engine.

A first-time reader generally trips over five overlapping terms.
They are distinct here:

- **Engineering principle.** The human intent behind a rule, e.g.
  "don't expand scope" or "always declare success criteria". Not
  written in YAML; lives in your team's contributor docs.
- **Policy.** The YAML file that encodes one or more principles into
  deterministic checks. The unit Latchpoint loads, hashes, and
  evaluates.
- **Gate.** One named check inside a policy, with a trigger
  (`pre_execution`), a fail action (`BLOCK` / `WARN` / `LOG`), an
  optional risk-tier filter (`applies_to`), and a list of conditions.
- **Condition.** One rule inside a gate that resolves true or false
  against the action descriptor. Has a `type`
  (`threshold` / `regex` / `allowlist` / `denylist` / `custom`), a
  `field` (dot-notation path on the action), an `operator`, and
  exactly one of `value` or `value_from`.
- **Input field.** The value a condition reads — either a top-level
  field of the action descriptor (`type`, `risk_tier`, `target`,
  etc.) or a nested path under `inputs.*`. In diff mode the diff
  adapter populates `inputs.changed_paths`,
  `inputs.changed_paths_blob`, `inputs.added_lines`,
  `inputs.removed_lines`, `inputs.diff_hash`, and
  `inputs.diff_summary`. In structured-action mode `inputs` is
  whatever the caller writes in the action JSON; the engine does
  not synthesize fields.

The loader is strict: unknown fields, duplicate gate names,
malformed types, and unrecognised operators all fail closed with a
structured error (see `Errors` below).

## From engineering principle to policy check

The four principles below show the recommended translation into a
Latchpoint check today. Each row uses one of three labels:

- **Directly expressible.** The current schema and the action / diff
  fields the engine already exposes are enough; no caller
  pre-processing required.
- **Expressible if the caller supplies a specific input field.** The
  condition machinery exists, but the relevant field is not
  produced by the engine — the caller pre-computes it and passes
  it under `inputs`.
- **Not currently automatic.** The engine performs no semantic
  analysis for this; a meaningful check requires external
  pre-processing outside Latchpoint.

| Engineering principle | Latchpoint check | Today's expressibility |
|---|---|---|
| Surgical changes — did the diff touch files outside the declared scope? | Restrict the post-image paths the diff is allowed to touch. | **Directly expressible** for a fixed allowlist or denylist of path patterns: a `regex` condition on `inputs.changed_paths_blob` with `matches` or `not_matches`. **Expressible if the caller supplies a specific input field** when the declared scope varies per action: the caller pre-computes a result (e.g. `inputs.scope_violation: true`) and the policy uses a `custom` condition with `is_not_null` / `exists`. The action descriptor has no `declared_scope` field today. |
| Goal-driven verification — did the completion report include matching evidence? | Require the action to carry a pre-extracted verification result. | **Expressible if the caller supplies a specific input field.** No `completion_report` or `evidence` field exists on the action descriptor. The caller performs the check externally (e.g. sets `inputs.completion_verified: true`) and the policy uses a `custom` condition (`is_not_null`, `exists`, or `contains`). The engine does not parse or compare free-form reports. |
| Simplicity first — did the change add unnecessary new dependencies, configs, or abstractions? | Apply numeric ceilings on diff size, or fail when a caller-supplied flag is set. | **Expressible if the caller supplies a specific input field.** In diff mode the engine surfaces `inputs.diff_summary` (a formatted string) plus the path and content blobs, but does **not** surface `file_count`, `added_line_count`, or `removed_line_count` as queryable numeric fields, so clean `threshold` conditions on diff size require the caller to pre-compute the number and pass it in `inputs`. "New dependency added" is **not currently automatic** — the diff adapter is line-based and has no language-syntax awareness; parse package manifests externally and pass a boolean or count. |
| Think before coding — did the run declare assumptions, scope, stop conditions, and success criteria? | Require declared planning fields to be present and non-empty. | **Expressible if the caller supplies a specific input field.** None of `assumptions`, `scope`, `stop_conditions`, or `success_criteria` are action-descriptor top-level fields. The caller passes them under `inputs` (e.g. `inputs.assumptions`, `inputs.success_criteria`) and the policy uses a `custom` condition with `is_not_null` to require presence. The engine enforces only presence and shape, not meaning. |

Latchpoint does not perform semantic code review, dependency
reasoning, or repository scanning. It evaluates the action descriptor
and diff fields it is given. Anything richer than that — natural-
language review of a completion report, AST-level analysis of a
diff, or fetching the repository to count touched modules — is the
caller's job, not the engine's.

## Top-level shape

```yaml
name: <lowercase-with-dashes-or-underscores>
version: "<SemVer 2.0.0>"
description: <optional string>
author: <optional string>
risk_tier_overrides: <optional mapping keyed by T0..T4>
escalation_rules: <optional mapping>
metadata: <optional mapping>
gates:
  - <gate>
  - <gate>
```

Required: `name`, `version`, `gates`. Everything else is optional.
`name` matches `^[a-z][a-z0-9_-]*$`. `version` must be a valid
SemVer 2.0.0 string.

## Gate shape

```yaml
name: <lowercase-with-underscores>
trigger: pre_execution        # currently the only supported trigger
action_on_fail: BLOCK | WARN | LOG
applies_to: [T0, T1, T2, T3, T4]   # optional tier filter
override: false                # boolean, default false
conditions:
  - <condition>
  - <condition>
```

`name` matches `^[a-z][a-z0-9_]*$`. Gate names are unique within a
policy. When `applies_to` is omitted the gate runs for every tier.

## Condition shape

A simple condition:

```yaml
type: <threshold|regex|allowlist|denylist|custom>
field: <dot-notation path on the action descriptor>
operator: <see operator table>
value: <literal>            # exactly one of value or value_from
value_from: <field path>    # exactly one of value or value_from
```

Operators by type:

| `type` | allowed `operator` |
|---|---|
| `threshold` | `>=`, `>`, `<=`, `<`, `==`, `!=` |
| `regex` | `matches`, `not_matches` |
| `allowlist` | `in`, `not_in` |
| `denylist` | `in`, `not_in` |
| `custom` | `is_not_null`, `is_null`, `exists`, `contains` |

A grouped condition with `any_of`:

```yaml
- any_of:
    - <simple condition>
    - <simple condition>
```

`any_of` evaluates true when at least one of the inner simple
conditions is true. Sibling conditions in a gate's `conditions` list
are AND-ed; an `any_of` block is OR-ed inside.

## Worked example: basic policy

`examples/policies/basic.yaml`:

```yaml
name: basic_demo
version: "0.1.0"
description: "Basic demo policy. Blocks high-risk destructive ops on T3+."
gates:
  - name: high_risk_destructive_block
    trigger: pre_execution
    action_on_fail: BLOCK
    applies_to: [T3, T4]
    conditions:
      - type: denylist
        field: type
        operator: in
        value: ["filesystem.delete"]
```

A T3 or T4 action with `type == "filesystem.delete"` returns `FIX`
(decision `block`).

## Worked example: diff policy

`examples/policies/diff.yaml`:

```yaml
name: diff_demo
version: "0.1.0"
description: "Diff-mode demo policy. One regex gate over inputs.added_lines for explicit machine-local home-path detection inside the diff."
gates:
  - name: machine_local_path_in_added_lines
    trigger: pre_execution
    action_on_fail: BLOCK
    conditions:
      - type: regex
        field: inputs.added_lines
        operator: matches
        value: "/Users/[A-Za-z0-9_.\\-]+/"
```

The diff adapter places newline-joined `+` lines from the diff into
`inputs.added_lines`; the regex gate fires when any added line contains
a synthetic machine-local home path.

## Errors

The loader raises `PolicyError` with a structured `code` on any of:
- `parse_error` — file unreadable, not UTF-8, or malformed YAML.
- `schema_violation` — wrong type, missing required field, or
  duplicate gate name.
- `regex_violation` — `name` or `version` does not match its required
  pattern.
- `enum_violation` — value not in an allowed alphabet (e.g.,
  `trigger`, `action_on_fail`, condition `type`/`operator`).
- `mutual_exclusion_violation` — both or neither of `value` /
  `value_from` supplied on a simple condition.
- `unknown_field` — top-level, gate, or condition contains a field
  not in the schema.
