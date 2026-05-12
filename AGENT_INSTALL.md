# Agent Install

This file is an agent-native installer for Latchpoint Core. Paste the
prompt block below into a coding agent (Claude Code, Codex, Cursor,
Windsurf, or similar) and the agent will:

1. clone Latchpoint Core,
2. install it into a repo-local Python virtual environment,
3. verify the install by running the `PASS`, `FIX`, and `ESCALATE`
   example flows, writing an evidence pack, and verifying and
   replaying it,
4. print a final report.

Repository wiring is intentionally deferred. This prompt only
installs and verifies Latchpoint Core. It does not touch your own
repository, your shell configuration, CI, or any git hooks.

## How to use

1. Open the coding agent in the directory where you want
   `latchpoint-core/` to be cloned.
2. Copy the entire prompt block below and paste it into the agent.
3. Submit the prompt.

The agent should execute the steps in order, stop on any failure,
and print a final report.

## The prompt

```
You are installing Latchpoint Core for the current user. Follow these
instructions exactly. Do not improvise. Do not skip verification.
Stop and report on any failure.

# ---------------------------------------------------------------
# HARD CONSTRAINTS
# ---------------------------------------------------------------
# - Do not install packages globally. Use a repo-local virtual
#   environment only.
# - Do not run sudo. Do not modify the user's shell rc files.
# - Do not enable telemetry. Do not add network calls. Latchpoint
#   Core's evaluation path is offline by design.
# - Do not modify Latchpoint Core source code, evaluator semantics,
#   or its dependencies.
# - Do not run destructive commands (rm -rf on anything outside the
#   newly-created latchpoint-core/ clone, force-push, reset --hard,
#   etc.).
# - Do not push, open pull requests, or create commits on the user's
#   behalf.
# - Do not write outside the paths explicitly listed in these
#   instructions.
# - If any step fails, stop and print: the failing command, the exit
#   code, the captured stderr (last 50 lines), and the step number.
#   Do not attempt to "fix forward" by editing Latchpoint sources.

# ---------------------------------------------------------------
# STEP 0 — Preflight
# ---------------------------------------------------------------
# Confirm git is available:
#
#   command -v git
#
# Locate a Python interpreter that is 3.11 or newer. Try the
# explicit names first (so a system `python3` that is older than
# 3.11 — for example Apple's system 3.9 on macOS — does not block
# the install when a newer interpreter is already installed
# alongside it). Use the first one that resolves and reports a
# version >= 3.11. Do not attempt to install a new Python
# interpreter on the user's system; only discover existing ones.
#
#   for cand in python3.13 python3.12 python3.11 python3; do
#     if command -v "$cand" >/dev/null 2>&1; then
#       ver="$("$cand" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
#       major="${ver%.*}"; minor="${ver#*.}"
#       if [ "$major" -ge 3 ] && [ "$minor" -ge 11 ]; then
#         PY="$cand"
#         break
#       fi
#     fi
#   done
#   test -n "${PY:-}" || { echo "no python >= 3.11 found"; exit 1; }
#   "$PY" --version
#
# If no Python 3.11+ interpreter is found, stop and report. Do not
# attempt to install one.

# ---------------------------------------------------------------
# STEP 1 — Clone Latchpoint Core
# ---------------------------------------------------------------
# Clone into the current working directory. If a latchpoint-core/
# directory already exists, stop and report — do not overwrite it.
#
#   test ! -e latchpoint-core
#   git clone https://github.com/tfot-ai/latchpoint-core.git
#   cd latchpoint-core

# ---------------------------------------------------------------
# STEP 2 — Create a repo-local virtual environment
# ---------------------------------------------------------------
# Use the interpreter discovered in STEP 0 (the `$PY` variable).
#
#   "$PY" -m venv .venv
#   . .venv/bin/activate
#   python -m pip install --upgrade pip setuptools wheel
#
# All subsequent python and pip invocations in this prompt run
# inside .venv. Do not use the system Python.

# ---------------------------------------------------------------
# STEP 3 — Install Latchpoint Core (editable)
# ---------------------------------------------------------------
#   python -m pip install -e .
#
# Confirm the CLI is on PATH inside the venv:
#
#   which latchpoint-core
#   latchpoint-core --help | head -n 20
#
# Then run an import smoke test inside the venv:
#
#   python -c "import latchpoint_core; print('import ok')"
#
# Expected output: `import ok`.
#
# If this fails with `ModuleNotFoundError: No module named
# 'latchpoint_core'` on macOS, see the editable-install .pth note in
# `docs/troubleshooting.md` (section "ModuleNotFoundError after
# editable install on macOS"). The fix is scoped to this venv only.
# Do not edit Latchpoint sources, reinstall outside the venv, or
# rerun `pip install` with elevated privileges.

# ---------------------------------------------------------------
# STEP 4 — Run PASS / FIX / ESCALATE examples
# ---------------------------------------------------------------
# Run the three example flows shipped in examples/. Capture exit
# codes. The expected exit codes are 0, 1, 2 respectively.
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/safe.json
#   echo "exit=$?"     # expected 0 — verdict: PASS
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/risky.json
#   echo "exit=$?"     # expected 1 — verdict: FIX
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/escalate.json
#   echo "exit=$?"     # expected 2 — verdict: ESCALATE
#
# If any exit code does not match, stop and report.

# ---------------------------------------------------------------
# STEP 5 — Write, verify, and replay an evidence pack
# ---------------------------------------------------------------
# Write an evidence pack from the PASS run:
#
#   latchpoint-core \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/safe.json \
#     --evidence-out /tmp/latchpoint_evidence.json
#
# Capture the `pack_hash:` line from the output.
#
# Verify the pack hash (no policy/action — hash check only):
#
#   latchpoint-core --verify --evidence-in /tmp/latchpoint_evidence.json
#   echo "exit=$?"     # expected 0 — verify_status: PASS
#
# Verify and replay (recompute the gate decision from the original
# policy and action and compare against the recorded one):
#
#   latchpoint-core --verify \
#     --evidence-in /tmp/latchpoint_evidence.json \
#     --policy examples/policies/basic.yaml \
#     --action examples/actions/safe.json
#   echo "exit=$?"     # expected 0 — verify_status: PASS, replay_status: REPLAY_PASS
#
# If either exit code is non-zero, or either `verify_status` is not
# PASS, or `replay_status` from the replay run is not REPLAY_PASS,
# stop and report.

# ---------------------------------------------------------------
# STEP 6 — Final report
# ---------------------------------------------------------------
# Print a single report block with the following fields. Use exactly
# these labels. One field per line.
#
#   latchpoint_core_path: <absolute path to the clone>
#   venv_path: <absolute path to the .venv>
#   python_version: <output of python --version>
#   latchpoint_core_version: <output of `pip show latchpoint-core | grep ^Version`>
#   pass_exit: <exit code from safe.json run>            # expected 0
#   fix_exit:  <exit code from risky.json run>           # expected 1
#   escalate_exit: <exit code from escalate.json run>    # expected 2
#   pack_hash: <pack_hash from the safe.json run>
#   verify_status: <verify_status line from --verify>    # expected PASS
#   replay_status: <replay_status line from verify+replay> # expected REPLAY_PASS
#
# After printing the report, stop. Do not propose follow-up edits.
# Do not push. Do not commit. Do not modify the user's repository.
```

## What the agent will NOT do

- It will not install anything globally.
- It will not run `sudo`.
- It will not modify your shell configuration files.
- It will not configure or run a CI workflow.
- It will not install a pre-commit, pre-push, or any other git hook.
- It will not stage, commit, or push changes to any repository.
- It will not write any file outside the cloned `latchpoint-core/`
  directory and `/tmp/latchpoint_evidence.json`.
- It will not contact any network endpoint beyond the initial
  `git clone` and `pip install`. The only runtime dependency is
  `PyYAML`.

## After the agent finishes

You can re-run the verification at any time:

```bash
cd latchpoint-core
. .venv/bin/activate
latchpoint-core \
  --policy examples/policies/basic.yaml \
  --action examples/actions/safe.json
```

Refer to [`README.md`](README.md), [`docs/quickstart.md`](docs/quickstart.md),
and [`docs/cli.md`](docs/cli.md) for the full local workflow.
