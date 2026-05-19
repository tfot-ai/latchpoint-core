#!/usr/bin/env bash
#
# advisory-shell-check.sh — ILLUSTRATIVE EXAMPLE.
#
# A local advisory wrapper around the public `latchpoint-core` CLI.
# It is a starting point to copy and adapt into your own project — not
# a supported entrypoint, and it adds no runtime behavior to Latchpoint
# Core itself. Review it before use.
#
# What it does:
#   - Runs `latchpoint-core` in `check` mode against a policy file and
#     a captured unified diff.
#   - Writes an evidence pack to an output path.
#   - Reports the verdict from the process exit code (0/1/2).
#
# What it does NOT do:
#   - It does not apply, merge, or revert anything. It only reports.
#   - It does not install or wire Latchpoint Core for you.
#   - The surrounding workflow decides what happens after the verdict.
#
# Usage:
#   ./advisory-shell-check.sh <policy.yaml> <change.diff> [evidence-out.json]
#
# See ../../docs/cli.md for the full CLI reference.

set -euo pipefail

usage="usage: advisory-shell-check.sh <policy.yaml> <change.diff> [evidence-out.json]"
POLICY="${1:?${usage}}"
DIFF="${2:?${usage}}"
EVIDENCE_OUT="${3:-evidence.json}"

# Capture the exit code ourselves: a non-zero verdict (FIX / ESCALATE)
# is an expected result here, not a script failure, so disable `set -e`
# around the call.
set +e
latchpoint-core \
  --policy "${POLICY}" \
  --diff "${DIFF}" \
  --evidence-out "${EVIDENCE_OUT}"
verdict_exit=$?
set -e

# Exit-code mapping is documented in ../../docs/cli.md.
case "${verdict_exit}" in
  0)
    echo "advisory: PASS — no gate fired for this change against this policy."
    ;;
  1)
    echo "advisory: FIX — a gate fired. Repair the change and re-run."
    ;;
  2)
    echo "advisory: ESCALATE — route the change to human review, or"
    echo "          investigate a fail-closed configuration error"
    echo "          (see ../../docs/troubleshooting.md)."
    ;;
  *)
    echo "advisory: unexpected exit code ${verdict_exit}." >&2
    ;;
esac

# Re-emit the verdict's exit code unchanged. The caller (a developer, a
# CI step, an agent harness) decides what to do with it.
exit "${verdict_exit}"
