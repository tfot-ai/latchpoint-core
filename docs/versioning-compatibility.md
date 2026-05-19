# Versioning and compatibility

This page explains, in practical terms, how to think about versions and
compatibility when you build on Latchpoint Core today. It describes the
current posture honestly; it does not promise a compatibility contract
that the project has not yet committed to.

## Current project stage

Latchpoint Core is **pre-release**. The package version is `0.0.1`
(see [`pyproject.toml`](../pyproject.toml)), a `0.x` version, and the
repository carries a matching `v0.0.1` tag.

At this stage, expect the public surface to move. The CLI flags, policy
fields, action descriptor shape, unified-diff handling, evidence pack
shape, validation and error messages, and the bundled `examples/` may
all change before a stable release. Treat everything below as the
project's *current design intent*, not a guarantee.

## Versioning policy

The project currently has **no formal, documented SemVer policy**. The
`0.x` version line communicates pre-release status in the usual way: a
`0.x` version makes no backwards-compatibility promise across changes.

There is no `CHANGELOG` file in the repository today. Until one exists,
the `git` history and tags are the record of what changed.

How to pin today:

- **Pin an exact commit SHA** in any automation or dependency
  specification. This is the most precise option and is recommended.
- **Pin the `v0.0.1` tag** if you prefer a named reference. Note that a
  tag is a convenience pointer; an exact commit SHA is stronger.
- **Do not** depend on "latest `master`" in automation. The default
  branch is `master`, and it moves.

There is no published package on a package index referenced by this
repository; install is from source (see [`../README.md`](../README.md)
and [`quickstart.md`](quickstart.md)). Pin the source revision you
install from.

## Compatibility surfaces

When the project changes, these are the public surfaces a developer
integration can observe. Treat them as compatibility-relevant:

- **CLI command names and flags** — the `check`, `verify`, and `run`
  modes and their flags ([`cli.md`](cli.md)).
- **Policy format** — the YAML policy schema: gates, conditions,
  operators, risk-tier filters ([`policies.md`](policies.md)).
- **Action descriptor format** — the JSON action input shape
  ([`concepts.md`](concepts.md)).
- **Unified diff input** — the accepted diff shapes and the synthesised
  action fields ([`diff-input.md`](diff-input.md)).
- **Verdict vocabulary** — `PASS` / `FIX` / `ESCALATE` and the
  `approve` / `block` / `override_required` decisions, with exit codes
  `0` / `1` / `2`.
- **Evidence pack format** — the canonical-JSON sections and the
  `pack_hash` derivation ([`evidence.md`](evidence.md)).
- **Verify / replay behavior** — what verification recomputes and what
  the tamper-detection claim covers ([`evidence.md`](evidence.md)).
- **Examples and test fixtures** — the policies, actions, and diffs in
  `examples/`.

## What may change before a stable release

Expect movement in:

- policy fields, condition types, and operators,
- evidence pack fields,
- CLI flags and mode wiring,
- example file paths and example contents,
- validation and error messages, including their exact wording,
- internal implementation details (module names, function signatures,
  the importable `latchpoint_core` API), which are not a documented
  public API.

## What is comparatively stable

These reflect the **current design intent** of the project. They are
the parts least likely to change in shape, because they are the core
model rather than incidental detail. They are still not a guarantee:

- the **local, offline, deterministic** evaluation model — no clock, no
  randomness, no network on the evaluation path
  ([`limitations.md`](limitations.md)),
- the **explicit policy + proposed change** input pattern: a written
  policy plus either a structured action or a unified diff,
- the **`PASS` / `FIX` / `ESCALATE`** verdict vocabulary,
- the **evidence / verify / replay** concept: a portable evidence pack
  with a stable hash that a third party can re-check.

If one of these changes, treat it as a significant release-level change.

## Upgrade guidance

When you move to a newer revision:

1. Read the release notes or changelog if one exists at that revision.
   None exists today; until then, review the `git` log between the old
   and new revisions.
2. Re-run the quickstart and any example flows you depend on
   ([`quickstart.md`](quickstart.md)) and confirm they still behave as
   your integration expects.
3. Re-run `verify` — and `replay`, where you have the original policy
   and action — against representative evidence packs
   ([`evidence.md`](evidence.md)).
4. Compare the policy and evidence pack schemas where you have
   integration-specific assumptions ([`policies.md`](policies.md),
   [`evidence.md`](evidence.md)).
5. **Do not assume evidence packs produced by an older revision verify
   under a newer one.** Cross-version evidence compatibility is not
   documented or guaranteed. Re-generate packs from current inputs when
   you upgrade, and keep the producing revision recorded.

## Integration guidance

For automation built on Latchpoint Core today:

- **Pin an exact commit SHA or the `v0.0.1` tag.** Do not track a
  moving branch.
- **Do not rely on undocumented internals.** The importable
  `latchpoint_core` modules and functions are implementation detail,
  not a documented public API.
- **Treat CLI stdout wording as less stable than structured output.**
  Human-readable lines and their exact phrasing may change. Prefer the
  process **exit codes** (`0` / `1` / `2`) and the **evidence pack
  fields** ([`evidence.md`](evidence.md)) as your integration contract.
- **Prefer documented flags and documented evidence pack fields** over
  parsing free-text output.

## Explicit non-guarantees

Latchpoint Core does **not** currently promise any of the following:

- no production-readiness guarantee,
- no enterprise-grade, compliance, or certification guarantee,
- no backwards-compatibility guarantee — no public surface is covered
  by a documented compatibility contract,
- no guarantee that any planned capability exists in the public
  product today; this documentation describes only the public Core
  behavior present in this repository,
- no promise of a stable internal Python API.

If and when the project adopts a formal versioning and compatibility
policy, this page will be updated to describe it.

## See also

- [`quickstart.md`](quickstart.md) — install, run, verify, replay.
- [`cli.md`](cli.md) — CLI modes, flags, and arguments.
- [`policies.md`](policies.md) — policy schema.
- [`concepts.md`](concepts.md) — shared vocabulary.
- [`diff-input.md`](diff-input.md) — unified-diff input rules.
- [`evidence.md`](evidence.md) — evidence pack format, verify, replay.
- [`limitations.md`](limitations.md) — what Latchpoint Core does not do.
- [`troubleshooting.md`](troubleshooting.md) — recovery for common failures.
