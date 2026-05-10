# Security Policy

Latchpoint Core is a deterministic, offline policy engine: it does not
make network calls, does not read or write to anywhere outside the paths
you pass on the command line, and depends only on `PyYAML` at runtime.

## Reporting a vulnerability

If you believe you have found a security vulnerability in Latchpoint Core,
please report it privately to:

`info@latchpoint.ai`

Please include:

- a description of the issue,
- steps to reproduce (a minimal policy + input is ideal), and
- the affected version (`pip show latchpoint-core`).

We will acknowledge receipt within a few working days. We aim to confirm
the issue, agree a remediation timeline, and publish a fix release before
public disclosure.

## Scope

In scope:

- Bugs in the policy evaluator, evidence-pack canonicalization, hash
  computation, verification, replay, or override / ledger handling that
  produce an incorrect verdict, an incorrect `pack_hash`, or that allow
  tampered evidence to verify as `PASS`.
- Determinism breaks: identical inputs producing different evidence-pack
  bytes or different `pack_hash` values.
- Fail-open behavior in the CLI: any malformed input that returns exit
  code `0` instead of `2`.

Out of scope:

- General Python ecosystem issues in the runtime (`PyYAML`, `pytest`,
  Python itself).
- Misconfigured policies authored by the caller.
- Performance issues that are not security-relevant.

## Supported versions

This is an early release. Security fixes are provided on the latest
released version only.
