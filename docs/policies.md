# Policies

A Latchpoint policy is a single YAML 1.2 file. The loader is strict:
unknown fields, duplicate gate names, malformed types, and unrecognised
operators all fail closed with a structured error.

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
