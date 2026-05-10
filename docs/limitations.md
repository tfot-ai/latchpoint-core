# Limitations

Latchpoint Core is a deliberately small, deterministic policy gate.
This page lists what it does **not** do.

## Not a model-based reviewer

Latchpoint Core does not run an LLM, classifier, embedding model, or
any other learned component on the policy path. It evaluates explicit
rules over explicit fields. Anything that would require the policy gate
to "understand" the code or the diff is out of scope.

## Not a repository scanner

The diff adapter sees only the unified-diff text the caller supplies.
It does not clone repositories, read other files in a working tree, or
follow symlinks. Pattern detection happens inside the diff text — not
across a repository.

## Not a CI replacement

There is no scheduler, no webhook, no GitHub App, no CI integration in
this package. The CLI exits with `0` / `1` / `2` based on the verdict;
calling code (any CI system, a Git hook, an editor) is responsible for
acting on those exit codes.

## Not a hosted service

Latchpoint Core is a local CLI and a local Python package. There is no
network call in the evaluation path. There is no telemetry. No hosted
service is included in this repository.

## Determinism boundary

The evaluation path performs **no** clock reads, **no** randomness, and
**no** network access. Identical inputs produce a byte-identical
evidence pack with the same `pack_hash`. The CLI does perform local
filesystem I/O to read input files and (optionally) write evidence
output.

## Risk-tier escalation is caller-supplied

The engine does not auto-detect workflow files, secrets-shaped strings,
or other "high-blast-radius" patterns and route them to `ESCALATE`. A
diff is `ESCALATE` only when the caller supplies `--risk-tier T4`.
Build that detection into the calling code, or define explicit policy
rules.

## Diff input is unified-diff text only

The diff adapter expects a standard unified-diff text file. Other diff
formats (Git binary patch, hunk-only excerpts, JSON-encoded patches)
are not supported.

## Policy schema is small and stable

The policy schema covers `threshold`, `regex`, `allowlist`,
`denylist`, and `custom` condition types, with a fixed set of
operators per type. Extensions to the schema are not supported in this
package; new condition types or operators would be a deliberate future
release.

## Evidence schema versioning

The evidence pack schema in this package is the only version recognised
for tamper detection. Forward-compatible reads may ignore unknown
fields, but the tamper-detection guarantee covers only the documented
sections. Multi-version protocol negotiation, signed attestations, and
transparency-log integrations are not part of this package.

## What you supply

- A policy file. Latchpoint does not write policies for you.
- The action descriptor or the unified diff. Latchpoint does not
  produce these.
- The risk tier, when relevant. Latchpoint does not infer it.
- The build-time stamp, when you want one recorded in the evidence
  pack. Latchpoint never reads the system clock.
