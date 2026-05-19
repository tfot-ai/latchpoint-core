# Latchpoint Core

[![tests](https://github.com/tfot-ai/latchpoint-core/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/tfot-ai/latchpoint-core/actions/workflows/tests.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)

Deterministic governance layer for agent-generated software.

Latchpoint Core is a Python package and local CLI that turns a written
policy and a description of a proposed action — either a structured
action JSON or a unified diff — into a verdict (`PASS`, `FIX`, or
`ESCALATE`) and a portable evidence pack with a stable SHA-256 hash.
The evidence pack can be verified or replayed by anyone holding the
same policy and inputs. The evaluation path is offline and deterministic:
no clock, no randomness, no network, no platform integration.

## What it does

- **Input.** A YAML policy file plus either a JSON action descriptor or
  a unified-diff text file.
- **Output.** A verdict (`PASS` / `FIX` / `ESCALATE`) and a canonical-
  JSON evidence pack with a stable `pack_hash`.
- **Where it runs.** Locally. No network calls, no telemetry.

## Install

Requires Python 3.11+.

### Agent install (recommended)

If you use a coding agent (Claude Code, Codex, Cursor, Windsurf, or
similar), [`AGENT_INSTALL.md`](AGENT_INSTALL.md) contains a
copy-paste prompt that installs Latchpoint Core into a local virtual
environment, runs the `PASS` / `FIX` / `ESCALATE` example flows, and
verifies and replays an evidence pack. The prompt is install- and
verification-only: it does not install globally, modify your shell
configuration, modify CI, add git hooks, or commit on your behalf,
and it does not write any file in your own repository.

### Manual install

```bash
git clone https://github.com/tfot-ai/latchpoint-core.git
cd latchpoint-core
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install .
```

The package installs the `latchpoint-core` CLI and exposes
`latchpoint_core` as the importable Python package. The runtime depends
on `PyYAML>=6.0` only.

For test extras:

```bash
python -m pip install '.[test]'
```

The CLI exposes three deterministic offline modes — `check`, `verify`,
and `run` — available both as flag-based forms and as subcommands. See
[`docs/cli.md`](docs/cli.md) for the full reference.

## Quickstart: check a structured action

```bash
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

Exit `0`. Prints `verdict: PASS`, `decision: approve`, and a `pack_hash:` line.

```bash
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/risky.json
```

Exit `1`. Prints `verdict: FIX`, `decision: block`, the firing gate, and a `pack_hash:` line.

```bash
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/escalate.json
```

Exit `2`. Prints `verdict: ESCALATE`, `decision: override_required`, and a `pack_hash:` line.

## Quickstart: check a diff

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/safe_docs.diff
```

Exit `0`. A safe documentation diff returns `PASS`.

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/private_path.diff
```

Exit `1`. The diff adds a synthetic machine-local home-path pattern;
the policy's regex gate fires on `inputs.added_lines` and returns `FIX`.

```bash
latchpoint-core \
  --policy examples/policies/diff.yaml \
  --diff examples/diffs/workflow.diff \
  --risk-tier T4
```

Exit `2`. With `--risk-tier T4` the change routes to `ESCALATE` via the
engine's `override_required` default. Without `--risk-tier T4` the same
diff returns `PASS` — the engine does not auto-detect elevated-blast-
radius paths in this slice.

## Verdicts

| Verdict | Decision | Exit | Meaning |
|---------|----------|------|---------|
| `PASS` | `approve` | `0` | No gate fired and no caller-supplied tier escalation. |
| `FIX` | `block` | `1` | A gate fired (e.g., a denylist rule, a regex match). |
| `ESCALATE` | `override_required` | `2` | Caller-supplied `T4` risk tier requested human review, or any fail-closed error. |

## Evidence and verify/replay

Write the evidence pack to a file:

```bash
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json \
  --evidence-out evidence.json
```

`evidence.json` is canonical JSON (sorted keys, compact separators) with
a stable `pack_hash`. Re-running on the same inputs writes a byte-
identical file.

Verify the pack hash without rerunning the gate:

```bash
latchpoint-core --verify --evidence-in evidence.json
```

Verify and replay (recompute the gate decision from the original policy
and action, compare against the recorded one):

```bash
latchpoint-core --verify --evidence-in evidence.json \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

**Tamper detection.** Verification is strict over the recognized
canonical evidence content: the `deterministic_facts`, `policy_verdict`,
`model_derived_judgments`, and `manifest` sections. Changing any of
that recognized content changes the section hash and the pack hash, and
re-verify returns `verify_status: FAIL` with one or more
`reason: section hash mismatch` or `pack hash mismatch` lines, exit `2`.
A hash mismatch on recognized content never returns `PASS`.

Fields outside that recognized schema are not part of the current
verification claim — they may be ignored on read for forward
compatibility, so do not rely on verification rejecting arbitrary unknown
fields. The guarantee is bounded by what the verifier's schema today
recognizes as canonical.

## What is a policy?

A Latchpoint policy is the rulebook the engine uses to evaluate a
proposed agent code change. It is a Latchpoint-specific YAML file,
not a generic ADR, OpenAPI spec, Terraform policy, Rego policy, CI
workflow, or linter config. The building blocks — gates, conditions,
allowlists, denylists, regexes, thresholds, and risk tiers — come
from familiar policy-as-code ideas; the field names, operator
alphabet, and verdict vocabulary are specific to this engine. Writing
one means deciding which deterministic checks must run before an
action is allowed to apply.

### Example

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

The policy declares one gate: a denylist on the action's `type` field
that fires when `type == "filesystem.delete"` and the action's
`risk_tier` is `T3` or `T4`. See [`docs/policies.md`](docs/policies.md)
for the full schema.

## Limitations

- **Deterministic gate, not a model reviewer.** Latchpoint evaluates
  policy rules, not natural-language code review.
- **Diff support is rule-based.** The diff adapter does explicit pattern
  detection (paths, added/removed lines). It is not semantic code
  review and does not scan a repository.
- **No clock, no randomness, no network.** Identical inputs always
  produce a byte-identical evidence pack.
- **Workflow / config-risk escalation is caller-supplied** via
  `--risk-tier T4`; the engine does not auto-detect elevated-blast-
  radius paths.

See [`docs/limitations.md`](docs/limitations.md) for the full list.

## Further reading

- [`docs/quickstart.md`](docs/quickstart.md) — install, run, verify, replay, and tamper-detect in a few minutes.
- [`docs/concepts.md`](docs/concepts.md) — the vocabulary the CLI, docs, and Python API share.
- [`docs/policies.md`](docs/policies.md) — full policy schema, with worked examples.
- [`docs/cli.md`](docs/cli.md) — the basic CLI reference for `check` and `verify` modes.
- [`docs/diff-input.md`](docs/diff-input.md) — accepted unified-diff shapes and the synthesised-action fields.
- [`docs/evidence.md`](docs/evidence.md) — evidence-pack schema, `pack_hash` derivation, tamper-detection scope.
- [`docs/limitations.md`](docs/limitations.md) — the full list of what Latchpoint Core does not do.
- [`docs/troubleshooting.md`](docs/troubleshooting.md) — recovery for the most common policy, diff, and verify failures.
- [`docs/versioning-compatibility.md`](docs/versioning-compatibility.md) — current versioning posture and compatibility expectations for developers.

## Development

```bash
pip install -e '.[dev]'
python -m pytest -q
```

## License

Apache-2.0. See [`LICENSE`](LICENSE).

## Contact

`info@latchpoint.ai`
