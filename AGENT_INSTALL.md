# Agent Install

This file is an agent-native installer for Latchpoint Core. Paste the
prompt block below into a coding agent (Claude Code, Codex, Cursor,
Windsurf, or similar) and the agent will:

1. clone and install Latchpoint Core into a local Python virtual
   environment,
2. verify the installation by running the `PASS`, `FIX`, and
   `ESCALATE` example flows,
3. optionally prepare the current repository as a local advisory
   policy gate, without modifying CI, hooks, or unrelated code.

Two modes are supported:

- **Install-only.** Clone, install, verify. The agent stops after
  printing a verification report.
- **Install + repo wiring.** Same as install-only, then create three
  advisory files inside the user's current repository:
  `.latchpoint/policy.yaml`, `scripts/latchpoint-check.sh`, and
  `.latchpoint/README.md`. Nothing else in the repo is touched.

Both modes are local, offline after the initial `git clone` and
`pip install`, and read-only with respect to the user's existing
code.

## How to use

1. Open the coding agent in the directory where you want
   `latchpoint-core/` to be cloned. For Install + repo wiring, open
   it at the root of the repository you want to wire.
2. Decide your mode:
   - `MODE=install-only`, or
   - `MODE=install-and-wire`.
3. Copy the entire prompt block below and paste it into the agent.
4. Replace the `MODE` line at the top of the prompt with your choice.
5. Submit the prompt.

The agent should execute the steps in order, stop on any failure,
and print a final report.

## The prompt

```
You are installing Latchpoint Core for the current user. Follow these
instructions exactly. Do not improvise. Do not skip verification.
Stop and report on any failure.

MODE: install-only        # change to: install-and-wire   if desired

# ---------------------------------------------------------------
# HARD CONSTRAINTS — apply to BOTH modes
# ---------------------------------------------------------------
# - Do not install packages globally. Use a repo-local virtual
#   environment only.
# - Do not run sudo. Do not modify the user's shell rc files.
# - Do not enable telemetry. Do not add network calls. Latchpoint
#   Core's evaluation path is offline by design.
# - Do not modify Latchpoint Core source code, evaluator semantics,
#   or its dependencies.
# - Do not run destructive commands (rm -rf on anything outside the
#   newly-created latchpoint-core/ clone, force-push, reset --hard
#   on the user's repo, etc.).
# - Do not push, open pull requests, or create commits on the user's
#   behalf.
# - Do not write outside the paths explicitly listed in these
#   instructions.
# - If any step fails, stop and print: the failing command, the exit
#   code, the captured stderr (last 50 lines), and the step number.
#   Do not attempt to "fix forward" by editing Latchpoint sources or
#   the user's repo.

# ---------------------------------------------------------------
# STEP 0 — Preflight
# ---------------------------------------------------------------
# Run these commands and confirm each succeeds. Print the output.
#
#   command -v git
#   command -v python3
#   python3 --version
#
# Requirement: Python 3.11 or newer. If python3 is older than 3.11,
# stop and report. Do not attempt to install a new Python
# interpreter on the user's system.

# ---------------------------------------------------------------
# STEP 1 — Clone Latchpoint Core
# ---------------------------------------------------------------
# Use the current working directory as the parent. If a
# latchpoint-core/ directory already exists here, stop and report —
# do not overwrite it.
#
#   test ! -e latchpoint-core
#   git clone https://github.com/tfot-ai/latchpoint-core.git
#   cd latchpoint-core

# ---------------------------------------------------------------
# STEP 2 — Create a repo-local virtual environment
# ---------------------------------------------------------------
#   python3 -m venv .venv
#   . .venv/bin/activate
#   python -m pip install --upgrade pip
#
# All subsequent python and pip invocations in this prompt run
# inside .venv. Do not use the system Python.

# ---------------------------------------------------------------
# STEP 3 — Install Latchpoint Core (editable, with test extras)
# ---------------------------------------------------------------
#   pip install -e '.[test]'
#
# Confirm the CLI is on PATH inside the venv:
#
#   which latchpoint-core
#   latchpoint-core --help | head -n 20

# ---------------------------------------------------------------
# STEP 4 — Verify PASS / FIX / ESCALATE
# ---------------------------------------------------------------
# Run the three example flows shipped in examples/. Capture exit
# codes. The expected exit codes are 0, 1, 2 respectively.
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/safe.json
#   echo "exit=$?"
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/risky.json
#   echo "exit=$?"
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/escalate.json
#   echo "exit=$?"
#
# Then write and verify an evidence pack:
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/safe.json \
#     --evidence-out /tmp/latchpoint_evidence.json
#
#   latchpoint-core --verify --evidence-in /tmp/latchpoint_evidence.json
#
# Capture the `pack_hash:` line from each run. The two runs against
# safe.json must report an identical pack_hash.
#
# Finally, run the test suite:
#
#   python -m pytest -q
#
# All tests must pass. If any fail, stop and report.

# ---------------------------------------------------------------
# STEP 5 — (install-and-wire ONLY) Prepare the user's repository
# ---------------------------------------------------------------
# Skip this step entirely when MODE=install-only.
#
# Hard constraints for this step:
# - The user's repo is the directory where the agent was originally
#   opened, NOT latchpoint-core/.
# - Do not modify, rename, or delete any file in the user's repo
#   other than the three files listed below.
# - Do not stage, commit, or push.
# - Do not modify .gitignore, CI workflows, pre-commit configs, or
#   any git hooks. Do not install a git hook.
# - Do not edit unrelated source code.
# - Each of the three files must be created only if it does not
#   already exist. If any of them already exists, leave it untouched
#   and report which ones were skipped.
#
# Return to the user's repo root before creating these files:
#
#   cd <user-repo-root>
#   test -d .git || { echo "not a git repo — stop"; exit 1; }
#
# File 1 — .latchpoint/policy.yaml
# A minimal starter advisory policy. The content below is a literal
# template; do not improvise additional gates.
#
#     name: starter_advisory
#     version: "0.1.0"
#     description: "Starter advisory policy for local agent-change review. Edit before relying on it."
#     gates:
#       - name: machine_local_path_in_added_lines
#         trigger: pre_execution
#         action_on_fail: BLOCK
#         conditions:
#           - type: regex
#             field: inputs.added_lines
#             operator: matches
#             value: "/Users/[A-Za-z0-9_.\\-]+/"
#
# File 2 — scripts/latchpoint-check.sh
# An executable wrapper that runs Latchpoint Core against a diff
# read from stdin or supplied as the first argument. It assumes the
# user activates the same virtual environment created in STEP 2
# (path printed at the end of this prompt). Mark it executable with
# chmod +x.
#
#     #!/usr/bin/env bash
#     # Local advisory check. Reads a unified diff from $1 or stdin.
#     # Exit codes: 0=PASS, 1=FIX, 2=ESCALATE/error.
#     set -u
#     POLICY="${LATCHPOINT_POLICY:-.latchpoint/policy.yaml}"
#     if [ "$#" -ge 1 ] && [ -f "$1" ]; then
#       DIFF_PATH="$1"
#     else
#       DIFF_PATH="$(mktemp -t latchpoint-diff.XXXXXX)"
#       cat - > "$DIFF_PATH"
#     fi
#     if ! command -v latchpoint-core >/dev/null 2>&1; then
#       echo "latchpoint-core not on PATH. Activate the Latchpoint venv first." >&2
#       exit 2
#     fi
#     latchpoint-core --policy "$POLICY" --diff "$DIFF_PATH"
#
# File 3 — .latchpoint/README.md
# A short README inside the user's repo explaining what was added,
# the advisory-only intent, and how to invoke the wrapper. Use this
# template verbatim:
#
#     # Latchpoint (local advisory)
#
#     This directory contains a local advisory configuration for
#     Latchpoint Core. It is not wired into CI, git hooks, or any
#     automated enforcement. It is intended to be invoked manually
#     or by a developer's local agent before applying a change.
#
#     ## Files
#
#     - `policy.yaml` — a starter advisory policy. Edit it to match
#       the rules you want to enforce locally.
#     - `../scripts/latchpoint-check.sh` — a wrapper that runs the
#       policy against a unified diff. Reads the diff from the first
#       argument or stdin.
#
#     ## Usage
#
#     Activate the virtual environment where `latchpoint-core` is
#     installed, then:
#
#         git diff > /tmp/change.diff
#         scripts/latchpoint-check.sh /tmp/change.diff
#
#     Exit codes: `0` = PASS, `1` = FIX, `2` = ESCALATE or error.
#
#     ## Scope
#
#     - Local-only. No network calls, no telemetry.
#     - Advisory. Nothing in this repo is enforced automatically by
#       these files.
#     - Editable. The policy is a starting point, not a production
#       rule set.
#
# After creating all three files, run `ls -la .latchpoint scripts`
# and print the result. Do NOT run `git add`, `git commit`, or
# `git push`. Do NOT modify any other file.

# ---------------------------------------------------------------
# STEP 6 — Final report
# ---------------------------------------------------------------
# Print a single report block with the following fields. Use exactly
# these labels. One field per line.
#
#   mode: install-only | install-and-wire
#   latchpoint_core_path: <absolute path to the clone>
#   venv_path: <absolute path to the .venv>
#   python_version: <output of python --version>
#   latchpoint_core_version: <output of `pip show latchpoint-core | grep ^Version`>
#   pass_exit: <exit code from safe.json run>           # expected 0
#   fix_exit:  <exit code from risky.json run>          # expected 1
#   escalate_exit: <exit code from escalate.json run>   # expected 2
#   pack_hash_safe: <pack_hash from the safe.json run>
#   verify_status: <verify_status line from --verify>   # expected PASS
#   pytest_status: <pass | fail>
#   wired_files: <comma-separated list of files created in STEP 5, or "none">
#   skipped_files: <comma-separated list of pre-existing files skipped in STEP 5, or "none">
#
# After printing the report, stop. Do not propose follow-up edits.
# Do not push. Do not commit.
```

## What the agent will NOT do

- It will not install anything globally.
- It will not run `sudo`.
- It will not modify your shell configuration files.
- It will not configure or run a CI workflow.
- It will not install a pre-commit, pre-push, or any other git hook.
- It will not stage, commit, or push changes to any repository.
- It will not edit files outside the three advisory files listed
  for install-and-wire mode.
- It will not contact any network endpoint beyond the initial
  `git clone` and `pip install` of the package and its single
  declared dependency (`PyYAML`).

## After the agent finishes

You can re-run the verification at any time:

```bash
cd latchpoint-core
. .venv/bin/activate
python -m pytest -q
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

If you ran `install-and-wire`, the advisory wrapper inside your
repository is invoked manually:

```bash
git diff > /tmp/change.diff
scripts/latchpoint-check.sh /tmp/change.diff
```

Refer to [`README.md`](README.md), [`docs/quickstart.md`](docs/quickstart.md),
and [`docs/cli.md`](docs/cli.md) for the full local workflow.
