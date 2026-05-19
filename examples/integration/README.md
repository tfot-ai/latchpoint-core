# Integration examples

Worked, copy-pasteable examples for wiring **Latchpoint Core** into a
project or repository workflow. They build on the conceptual guidance
in [`../../docs/integration-notes.md`](../../docs/integration-notes.md)
and show concrete command shapes.

Everything here describes only the public Core behavior present in this
repository: a local CLI and a local Python package that turns a policy
plus a proposed change into a verdict and an evidence pack.

## What these examples are — and are not

These files are **starting points to copy and adapt**, not supported
entrypoints. They add no runtime behavior to Latchpoint Core itself.

Latchpoint Core, as published here, is **not**:

- an automatic install-and-wire step — you copy and adapt these files
  by hand;
- a GitHub App;
- a hosted or continuous-monitoring service;
- an automatic merge / apply / revert tool;
- a replacement for CI or for code review.

It is a deterministic, local, offline policy gate. The surrounding
workflow stays in control of what happens after the verdict. See
[`../../docs/limitations.md`](../../docs/limitations.md) for the full
list of what Core does not do.

## Files in this directory

| File | What it shows |
|------|----------------|
| [`advisory-shell-check.sh`](advisory-shell-check.sh) | A local advisory wrapper a developer runs before pushing. |
| [`github-actions-advisory.yml`](github-actions-advisory.yml) | An **illustrative, non-active** CI snippet. It is deliberately *not* in `.github/workflows/`, so GitHub does not run it. |

## 1. Local shell / advisory check

[`advisory-shell-check.sh`](advisory-shell-check.sh) takes a policy
file and a captured unified diff, runs `latchpoint-core`, writes an
evidence pack, and reports the verdict from the process exit code:

```bash
./advisory-shell-check.sh path/to/policy.yaml path/to/change.diff evidence.json
```

The underlying command is the documented `check` mode:

```bash
latchpoint-core \
  --policy path/to/policy.yaml \
  --diff path/to/change.diff \
  --evidence-out evidence.json
```

Interpret the exit code (see [`../../docs/cli.md`](../../docs/cli.md)):

| Exit | Verdict | What the caller should do |
|------|---------|---------------------------|
| `0` | `PASS` | No gate fired for this change against this policy. Continue per your workflow. |
| `1` | `FIX` | A gate fired and named the issue. Repair the change and re-run. |
| `2` | `ESCALATE` | Route to human review — or investigate a fail-closed configuration error (malformed policy, malformed input, missing file). |

The wrapper only **reports** the verdict; it does not apply, merge, or
revert anything. The script is illustrative — review and adapt it
before using it in your own project.

You can try it against the demo fixtures shipped in this repository:

```bash
./advisory-shell-check.sh \
  ../policies/diff.yaml \
  ../diffs/safe_docs.diff \
  evidence.json
```

## 2. CI advisory pattern

[`github-actions-advisory.yml`](github-actions-advisory.yml) shows one
way a CI job *could* invoke Latchpoint Core against a captured diff.

Important constraints:

- **It is an illustrative example, not an active workflow.** It lives
  in this directory on purpose. It is *not* in `.github/workflows/`,
  so GitHub will not run it. To use it, copy it into your own
  project's `.github/workflows/`, review it, and adapt every path.
- **It is advisory / non-blocking.** The snippet uses
  `continue-on-error: true` so a non-zero verdict reports without
  failing the build. Promote it to a blocking gate only once your
  team has decided the policy's coverage is trusted enough — that is a
  team decision, not a default.
- **It is not production-ready.** Treat it as a sketch to adapt.
- **Pin the Core version.** Pin an exact commit SHA or the `v0.0.1`
  tag rather than tracking a moving branch
  ([`../../docs/versioning-compatibility.md`](../../docs/versioning-compatibility.md)).
- **The diff adapter is not a repository scanner.** It sees only the
  unified-diff text passed via `--diff`; the CI job captures that diff
  explicitly ([`../../docs/diff-input.md`](../../docs/diff-input.md)).

## 3. Agent harness pattern

An agent harness can export the unified diff or the structured action
descriptor for the change it is about to apply or land, and check that
artifact with Core before proceeding:

```bash
# The harness writes the proposed change it captured to disk, then:
latchpoint-core \
  --policy path/to/policy.yaml \
  --diff path/to/proposed-change.diff \
  --evidence-out evidence.json
# ... or, for a structured action descriptor:
latchpoint-core \
  --policy path/to/policy.yaml \
  --action path/to/proposed-action.json \
  --evidence-out evidence.json
```

What this pattern means:

- The harness is responsible for **producing** the diff or action
  descriptor. Pass only documented inputs — a policy plus a documented
  action descriptor or unified diff
  ([`../../docs/policies.md`](../../docs/policies.md),
  [`../../docs/diff-input.md`](../../docs/diff-input.md)).
- Core **checks the proposed change against the policy** and returns a
  verdict. It evaluates explicit policy rules; it does not review code
  or reason about the agent's intent.
- The verdict is a **gate signal, not agent judgment**. A `PASS` is a
  policy result, not an endorsement of the agent's work.
- **Core does not control the agent.** The surrounding harness decides
  what happens after the verdict — proceed, repair, or escalate.

## 4. Evidence handling

When `--evidence-out` is supplied, Core writes a portable evidence
pack — canonical JSON with a stable `pack_hash`
([`../../docs/evidence.md`](../../docs/evidence.md)):

- **Store the pack** as an artifact or log if your workflow wants an
  audit trail — a CI artifact store, a directory beside the change, an
  attachment on a review record. Core writes the pack only to the
  local path you pass; it does **not** upload it. Any upload is a step
  the surrounding workflow chooses to add (the CI snippet here does
  this with a separate `upload-artifact` step).
- **Preserve the inputs** that produced it — the policy file and the
  action descriptor or diff — so the run can be checked later.
- **Record the producing revision** of Latchpoint Core
  ([`../../docs/versioning-compatibility.md`](../../docs/versioning-compatibility.md)).
- **Verify and replay** the pack later:

  ```bash
  # Hash-check the pack on its own:
  latchpoint-core --verify --evidence-in evidence.json

  # Hash-check and replay the recorded gate decision:
  latchpoint-core --verify --evidence-in evidence.json \
    --policy path/to/policy.yaml \
    --action path/to/proposed-action.json
  ```

## 5. Boundaries

Across every pattern above, Latchpoint Core:

- does **not** install or wire itself into your project automatically;
- is **not** a GitHub App, a hosted service, or a continuous-monitoring
  system;
- does **not** merge, apply, revert, or modify anything;
- does **not** replace CI or code review;
- only reads the files you pass and writes only the evidence path you
  ask for.

Core is a gate signal. Scheduling, applying changes, and any platform
integration stay with the surrounding workflow.

## See also

- [`../../docs/integration-notes.md`](../../docs/integration-notes.md) — integration posture and patterns.
- [`../../docs/cli.md`](../../docs/cli.md) — CLI modes, flags, and exit codes.
- [`../../docs/policies.md`](../../docs/policies.md) — policy schema.
- [`../../docs/diff-input.md`](../../docs/diff-input.md) — unified-diff input rules.
- [`../../docs/evidence.md`](../../docs/evidence.md) — evidence pack format, verify, replay.
- [`../../docs/versioning-compatibility.md`](../../docs/versioning-compatibility.md) — versioning posture and how to pin Core.
- [`../../docs/troubleshooting.md`](../../docs/troubleshooting.md) — recovery for common failures.
