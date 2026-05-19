# Integration notes

This page is for developers who want to wire Latchpoint Core into a
workflow today. It describes how Core fits alongside the tools you
already run, what it expects as input, what it returns, and what it
deliberately does not do. It describes only the public Core behavior
present in this repository.

## Current integration posture

Latchpoint Core is a **local CLI** and a local Python package. It
evaluates a proposed change that the caller supplies, against a policy
that the caller supplies, and returns a verdict and an evidence pack.

What that means for integration:

- It is **not** a hosted service, a daemon, a GitHub App, or a central
  control plane. There is no server to point at and no webhook to
  register ([`limitations.md`](limitations.md)).
- It does **not** apply, merge, revert, or modify anything by itself.
  It reads the files you pass and writes only the evidence output path
  you ask for.
- The evaluation path is offline and deterministic — no clock, no
  randomness, no network. Identical inputs produce a byte-identical
  evidence pack.

Core is a **gate signal**. The surrounding workflow stays in control of
what happens next.

## Basic integration pattern

Every integration follows the same shape:

1. An external workflow — a CI job, a shell script, an agent harness, a
   reviewer at a terminal — produces or captures a **proposed change**.
   That is either a structured action descriptor (JSON) or a
   unified-diff text file.
2. The workflow invokes `latchpoint-core` with a **policy file** and the
   proposed change.
3. `latchpoint-core` returns a **verdict** (`PASS` / `FIX` /
   `ESCALATE`), a process **exit code** (`0` / `1` / `2`), and,
   when asked, an **evidence pack**.
4. The workflow reads the verdict and the evidence pack and **decides
   what to do next**.

Latchpoint itself does not merge, revert, land, or modify the
repository. The decision and the action stay with the caller.

## Suggested integration surfaces

Core slots into any caller that can produce a diff or an action
descriptor and act on an exit code:

- **Local shell scripts** — a wrapper a developer runs before pushing.
- **CI jobs** — a step that checks a captured diff (see
  [CI integration notes](#ci-integration-notes) below).
- **Pre-merge advisory checks** — a non-blocking signal surfaced on a
  change before it is merged.
- **Agent harnesses** — any harness that can export the diff or action
  descriptor it is about to apply (see
  [Agent harness notes](#agent-harness-notes) below).
- **Manual reviewer workflows** — a reviewer running the CLI by hand
  against a diff to get a deterministic, reproducible verdict.

## Inputs and outputs

**Inputs you supply:**

- A **policy file** — a Latchpoint YAML policy describing the gates the
  change must pass ([`policies.md`](policies.md)).
- A **proposed change** — either a structured **action descriptor**
  (JSON) or a **unified diff** text file ([`diff-input.md`](diff-input.md)).
- Optionally, an **evidence output path** (`--evidence-out`) to write
  the evidence pack to.
- Optionally, a caller-supplied **risk tier** (`--risk-tier`); tier
  `T4` routes a diff change to `ESCALATE`.

**Outputs you read:**

- A **verdict**: `PASS`, `FIX`, or `ESCALATE`, with matching exit codes
  `0`, `1`, and `2` ([`cli.md`](cli.md)).
- An **evidence pack** — canonical JSON with a stable `pack_hash` —
  when `--evidence-out` is supplied. The pack can be verified or
  replayed later by anyone holding the same policy and inputs
  ([`evidence.md`](evidence.md)).

Latchpoint does not write the policy, produce the diff or action, or
infer the risk tier for you. Those are caller inputs.

## Minimal example

A diff-based check that writes an evidence pack, using documented flags
only:

```bash
latchpoint-core \
  --policy path/to/policy.yaml \
  --diff path/to/change.diff \
  --evidence-out path/to/evidence.json
```

The command prints the verdict, the decision, the gates evaluated, the
`pack_hash`, and the `evidence_path`, and exits `0` / `1` / `2`. A
structured action descriptor can be passed with `--action` instead of
`--diff` (exactly one of the two is required).

For the full flag set, modes, and worked examples, see
[`cli.md`](cli.md), [`policies.md`](policies.md),
[`diff-input.md`](diff-input.md), and [`evidence.md`](evidence.md).

## Handling verdicts

The verdict is about **that proposed change against that policy** —
nothing wider.

- **`PASS`** (exit `0`) — the policy was satisfied for the proposed
  change. The integration may continue according to the caller's
  workflow. `PASS` does **not** mean the change is globally correct,
  secure, production-ready, or mergeable; it means no gate fired and no
  caller-supplied tier escalation applied.
- **`FIX`** (exit `1`) — a gate fired and named the issue. The caller
  should stop, repair the change, and resubmit it for a fresh check.
- **`ESCALATE`** (exit `2`) — the caller should route the change to a
  human or manual review path. Exit `2` is also returned for any
  fail-closed configuration error (malformed policy, malformed input,
  missing file); treat an unexpected `ESCALATE` as something to
  investigate ([`troubleshooting.md`](troubleshooting.md)).

Decide on the verdict and exit code. Avoid branching on the exact
wording of human-readable stdout lines.

## Evidence handling

When you pass `--evidence-out`, Core writes a portable evidence pack:

- **Store the pack** somewhere your workflow can retrieve it later — a
  CI artifact store, a directory beside the change, an attachment on a
  review record.
- **Preserve the inputs** that produced it: the policy file and the
  action descriptor or diff. `verify` checks the pack's hashes on its
  own; `replay` additionally needs the original policy and action to
  recompute the recorded decision ([`evidence.md`](evidence.md)).
- **Record the producing revision** of Latchpoint Core, so a later
  reader knows which revision generated the pack
  ([`versioning-compatibility.md`](versioning-compatibility.md)).
- **Verify and replay** packs as part of an audit or a handoff:
  `latchpoint-core --verify --evidence-in <pack>` checks the hashes;
  adding `--policy` and `--action` replays the gate decision.
- The evidence pack stays local. Core does not upload it. Send it
  somewhere only if the caller's workflow chooses to.

## CI integration notes

- **Start advisory / non-blocking.** Until the team has confidence in
  the policy's coverage, run the Core step so it reports a verdict
  without failing the build. Promote it to a blocking gate once the
  policy is trusted.
- **Pin the Core version or commit.** Pin an exact commit SHA or the
  `v0.0.1` tag rather than tracking a moving branch, as described in
  [`versioning-compatibility.md`](versioning-compatibility.md).
- **Do not rely on undocumented stdout wording.** Human-readable lines
  and their exact phrasing may change. Branch on the process **exit
  code** instead.
- **Prefer structured output.** Where your CI logic needs detail beyond
  pass/fail, read documented **evidence pack fields**
  ([`evidence.md`](evidence.md)) rather than parsing free-text output.
- **The diff adapter is not a repository scanner.** It sees only the
  unified-diff text you supply via `--diff`; capture the diff in the CI
  job and pass it explicitly ([`diff-input.md`](diff-input.md)).

## Agent harness notes

- **Capture the change before it is applied.** Have the agent export
  the unified diff or the action descriptor for the work it is about to
  apply or land, and check that artifact with Core.
- **Pass only documented inputs.** Supply a policy plus a documented
  action descriptor or unified diff. Do not pass internal harness state
  Core does not document.
- **Treat the verdict as a gate signal, not agent judgment.** Core
  evaluates explicit policy rules; it does not review code or reason
  about intent ([`limitations.md`](limitations.md)). A `PASS` is a
  policy result, not an endorsement of the agent's work.
- **Core does not control the agent.** It returns a verdict; the
  harness decides whether the agent proceeds, repairs, or escalates.

## Non-goals and boundaries

Latchpoint Core, as published in this repository, is **not**:

- a GitHub App,
- a hosted approval service,
- a continuous-monitoring system,
- a CI replacement,
- a code-review replacement,
- an automatic merge or apply tool,
- a compliance or certification mechanism.

It is a deterministic, local, offline policy gate. The surrounding
workflow owns scheduling, applying changes, and any platform
integration. See [`limitations.md`](limitations.md) for the full list
of what Core does not do.

## See also

- [`quickstart.md`](quickstart.md) — install, run, verify, replay.
- [`cli.md`](cli.md) — CLI modes, flags, and arguments.
- [`policies.md`](policies.md) — policy schema.
- [`diff-input.md`](diff-input.md) — unified-diff input rules.
- [`evidence.md`](evidence.md) — evidence pack format, verify, replay.
- [`troubleshooting.md`](troubleshooting.md) — recovery for common
  failures.
- [`versioning-compatibility.md`](versioning-compatibility.md) —
  versioning posture and how to pin Core.
- [`limitations.md`](limitations.md) — what Latchpoint Core does not do.
