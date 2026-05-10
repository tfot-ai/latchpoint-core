"""Latchpoint Core CLI demo.

Three deterministic offline modes (no network, no clock, no randomness):

* ``check`` (default flat-arg form, also available as a subcommand):
  load a policy, validate an action payload, evaluate the gate, and
  emit an evidence pack with a stable SHA-256 pack hash.

* ``verify`` (also available as a subcommand): read an evidence-pack
  JSON file, recompute its section and pack hashes, and optionally
  replay the recorded gate decision when both ``--policy`` and
  ``--action`` are supplied.

* ``run``: payload-mode local end-to-end pipeline. Loads a policy,
  reads a JSON payload, drives it through the local synthetic adapter,
  evaluates the gate, builds an evidence pack, and writes the pack and
  per-section files as canonical JSON to ``--out`` (which must be empty
  or absent). Identical inputs produce byte-identical output.

Verdict mapping. The internal source vocabulary
``approve | block | override_required`` is the canonical decision; the
product-level mnemonic ``PASS / FIX / ESCALATE`` is emitted alongside
for human readers.

    approve            -> PASS     (exit 0)
    block              -> FIX      (exit 1)
    override_required  -> ESCALATE (exit 2)

Fail-closed errors (``PolicyError``, ``ActionError``,
``GateEvaluationError``, ``EvidenceError``, ``AdapterError``,
malformed JSON, missing file, unreadable file) map to ``ESCALATE`` /
exit 2 in every mode.

Exit-code matrix for ``run`` mode (canonical wording):

    0 -- approve / PASS
    1 -- block / FIX
    2 -- override_required / ESCALATE OR any structured pre-verdict
         failure (out-dir refusal, malformed policy, malformed payload,
         adapter rejection, gate evaluation error, evidence build
         error, mid-write OSError)

In ``verify`` mode the exit code is:

    PASS hash + (REPLAY_PASS or NOT_REPLAYABLE)  -> 0
    anything else (FAIL hash, REPLAY_FAIL, ...)  -> 2
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .action_model import ActionDescriptor, ActionError, validate_action
from .adapters import (
    AdapterError,
    AdapterInput,
    SyntheticAdapter,
    adapt_payload,
)
from .diff_adapter import (
    DEFAULT_TIMESTAMP as _DIFF_DEFAULT_TIMESTAMP,
    DiffAdapterError,
    derive_sidecar_path,
    diff_to_action,
)
from .evidence_model import (
    DeterministicFacts,
    EvidenceError,
    ModelDerivedJudgments,
    OverrideEvidence,
    PolicyVerdict,
)
from .evidence_pack import (
    SECTION_NAMES,
    build_evidence_pack,
    evidence_pack_to_canonical_json,
    section_canonical_json,
)
from .evidence_verifier import verify_evidence
from .gate_evaluator import evaluate_action
from .gate_model import GateEvaluationError
from .ledger import (
    LedgerEntry,
    LedgerError,
    append_ledger_entry,
    canonicalize_ledger_entry,
    verify_ledger_chain,
)
from .policy_loader import load_policy, policy_to_canonical_json
from .policy_model import Policy, PolicyError
from .safety_controls import (
    OverrideContext,
    OverrideDecision,
    SafetyControlError,
    evaluate_kill_switch,
    evaluate_override,
)

VERDICT_MAP: dict[str, tuple[str, int]] = {
    "approve": ("PASS", 0),
    "block": ("FIX", 1),
    "override_required": ("ESCALATE", 2),
}

_SUBCOMMANDS: tuple[str, ...] = ("run", "check", "verify")

_RUN_PACK_FILENAME: str = "evidence_pack.json"
_RUN_SECTION_NAMES: tuple[str, ...] = SECTION_NAMES

_FAIL_CLOSED_EXCEPTIONS: tuple[type[BaseException], ...] = (
    FileNotFoundError,
    json.JSONDecodeError,
    UnicodeDecodeError,
    PolicyError,
    ActionError,
    AdapterError,
    DiffAdapterError,
    GateEvaluationError,
    EvidenceError,
    OSError,
)


def _policy_hash(policy: Policy) -> str:
    return hashlib.sha256(policy_to_canonical_json(policy).encode("utf-8")).hexdigest()


_EPILOG = """\
Modes:
  check    (default) policy + action -> verdict + evidence pack
  verify   evidence -> hash check + (optional) replay of the gate decision
  run      payload-mode pipeline: policy + payload -> verdict + evidence
           pack written to --out (must be empty or absent)

Examples:
  Check a safe action and print the verdict:
    latchpoint-core \\
      --policy examples/policies/basic.yaml \\
      --action examples/actions/safe.json

  Check and write the evidence pack to disk:
    latchpoint-core \\
      --policy examples/policies/basic.yaml \\
      --action examples/actions/safe.json \\
      --evidence-out evidence.json

  Verify an evidence pack (hash check only):
    latchpoint-core --verify --evidence-in evidence.json

  Verify and replay (recomputes the gate decision from policy + action):
    latchpoint-core --verify --evidence-in evidence.json \\
      --policy examples/policies/basic.yaml \\
      --action examples/actions/safe.json

  Payload-mode run (writes evidence pack and section files to a directory):
    latchpoint-core run \\
      --policy examples/policies/basic.yaml \\
      --payload examples/actions/safe.json \\
      --out ./evidence_dir

Exit codes:
  0  PASS                check/run approve, OR verify hash PASS with replay
                         PASS or NOT_REPLAYABLE
  1  FIX                 check/run block (gate fired)
  2  ESCALATE / FAIL     check/run override_required, OR any structured
                         pre-verdict failure (malformed input, missing
                         file, hash mismatch, replay mismatch, refusal to
                         overwrite a non-empty --out directory)

Determinism: no clock, no randomness, no network.
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="latchpoint-core",
        description=(
            "Latchpoint Core CLI demo. Default flat-arg mode (check) "
            "evaluates one action against one policy and emits a deterministic "
            "verdict plus an evidence pack with a stable SHA-256 pack_hash. "
            "With --verify, instead reads an evidence pack and recomputes its "
            "hashes; with --policy and --action also supplied, replays the "
            "recorded gate decision. The same modes are available as the "
            "subcommands check, verify, and run."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--policy",
        default=None,
        help=(
            "Path to a YAML policy file. Required in check mode; "
            "optional in --verify mode (used for replay alongside --action)."
        ),
    )
    parser.add_argument(
        "--action",
        default=None,
        help=(
            "Path to a JSON action descriptor. Required in check "
            "mode unless --diff is supplied; optional in --verify mode (used "
            "for replay alongside --policy). Mutually exclusive with --diff."
        ),
    )
    parser.add_argument(
        "--diff",
        default=None,
        help=(
            "Path to a unified-diff text file. When supplied in check mode, "
            "the diff adapter performs deterministic diff-to-action "
            "translation: it parses changed paths and added/removed lines "
            "and produces a structured action that the gate "
            "evaluator runs. Explicit pattern detection inside the diff "
            "only -- not semantic code review and not repo scanning. "
            "Mutually exclusive with --action."
        ),
    )
    parser.add_argument(
        "--risk-tier",
        default=None,
        choices=("T0", "T1", "T2", "T3", "T4"),
        help=(
            "Caller-supplied risk tier for diff-derived actions (default T1 "
            "when omitted with --diff). Choose T4 to route an elevated-"
            "blast-radius diff to ESCALATE via the engine's built-in "
            "override_required default; the engine does NOT auto-detect "
            "elevated-blast-radius paths. Ignored when --diff "
            "is not supplied."
        ),
    )
    parser.add_argument(
        "--at",
        default=None,
        help=(
            "Optional ISO 8601 build-time stamp recorded in the action's "
            "timestamp field for diff-derived actions. Defaults to the "
            "deterministic epoch sentinel "
            f"{_DIFF_DEFAULT_TIMESTAMP!r} when --diff is supplied without "
            "--at; real-world callers should supply a meaningful value. "
            "No system clock is ever read. Ignored when --diff is not "
            "supplied."
        ),
    )
    parser.add_argument(
        "--evidence-out",
        default=None,
        help=(
            "Optional path to write the canonical-JSON evidence pack to in "
            "check mode. Parent directories are created. Ignored in --verify mode."
        ),
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "Verify (and optionally replay) an existing evidence pack instead "
            "of producing one. Requires --evidence-in."
        ),
    )
    parser.add_argument(
        "--evidence-in",
        default=None,
        help="Path to an evidence-pack JSON file to verify. Required with --verify.",
    )
    parser.add_argument(
        "--override",
        default=None,
        help=(
            "Optional path to a JSON object describing an override "
            "decision recorded in the evidence pack. Used by --verify to "
            "re-evaluate the recorded override against caller-supplied "
            "inputs. Same JSON shape as the run-mode --override flag: "
            "override_id, applies_to_action_id, not_after, consumed, now."
        ),
    )
    parser.add_argument(
        "--ledger",
        default=None,
        help=(
            "Optional path to a JSON-array ledger chain file. Used by "
            "--verify to re-assert that the recorded pack appears in the "
            "chain and that the chain itself hash-verifies end to end. "
            "Unlike run mode, the path must already exist; a missing path "
            "is a configuration error in verify mode and fails closed."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="subcommand",
        required=False,
        metavar="SUBCOMMAND",
        title="subcommands",
        description=(
            "Optional explicit subcommand form. Equivalent to the flat-arg "
            "modes above; the run subcommand is payload-mode only."
        ),
    )

    run_parser = subparsers.add_parser(
        "run",
        help=(
            "Payload-mode local run: policy + payload -> verdict + evidence directory."
        ),
        description=(
            "Run a deterministic local payload-mode pipeline. Loads the YAML "
            "policy, reads the JSON payload, drives it through the local "
            "synthetic adapter, evaluates the gate, builds an evidence pack, "
            "and writes the pack and per-section files as canonical JSON to "
            "--out. The --out directory must be empty or absent. No clock, no "
            "randomness, no network. Identical inputs (--policy, --payload, "
            "and --at when supplied) produce byte-identical output files."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_parser.add_argument(
        "--policy",
        required=True,
        help="Path to a YAML policy file.",
    )
    run_parser.add_argument(
        "--payload",
        required=True,
        help="Path to a JSON payload file. Must be a JSON object.",
    )
    run_parser.add_argument(
        "--out",
        required=True,
        help=(
            "Output directory. Must not exist or must be empty. The pipeline "
            "refuses to overwrite a non-empty directory."
        ),
    )
    run_parser.add_argument(
        "--at",
        default=None,
        help=(
            "Optional ISO 8601 build-time stamp. When supplied it is recorded "
            "deterministically in the evidence pack metadata; when omitted no "
            "build-time field is written. No system clock is ever read."
        ),
    )
    run_parser.add_argument(
        "--kill-switch",
        default=None,
        help=(
            "Optional path to a JSON object with a single 'state' field "
            "(ACTIVE | INACTIVE). ACTIVE fails closed before policy "
            "evaluation, writes no evidence output, and exits 2. INACTIVE "
            "permits a normal run. Any other state value is malformed and "
            "fails closed."
        ),
    )
    run_parser.add_argument(
        "--override",
        default=None,
        help=(
            "Optional path to a JSON object describing a caller-supplied "
            "override decision. Required keys: override_id (str), "
            "applies_to_action_id (str), not_after (int, caller-defined "
            "units), consumed (bool), now (int, same units as not_after; "
            "no system clock is read). When the override evaluator returns "
            "'applicable', the run continues and an override_outcome line "
            "is printed; any rejected outcome fails closed, writes no "
            "evidence output, and exits 2. Kill-switch takes precedence."
        ),
    )
    run_parser.add_argument(
        "--ledger",
        default=None,
        help=(
            "Optional path to a JSON-array ledger chain file. When supplied, "
            "and only when an applicable --override is also supplied, a single "
            "LedgerEntry recording the override-consumption pack_hash is "
            "appended to the chain after the evidence pack is written. If the "
            "path does not exist a new chain is created; if it exists it must "
            "verify under verify_ledger_chain before extension. Requires "
            "--override and --at; fails closed without either. Kill-switch "
            "still takes precedence."
        ),
    )

    check_parser = subparsers.add_parser(
        "check",
        help=(
            "Check mode (subcommand form): policy + action -> verdict + evidence pack."
        ),
        description=(
            "Subcommand form of the default check mode. Identical semantics "
            "to the flat-arg form."
        ),
    )
    check_parser.add_argument("--policy", required=True)
    check_parser.add_argument(
        "--action",
        default=None,
        help="Path to a JSON action descriptor. Mutually exclusive with --diff.",
    )
    check_parser.add_argument(
        "--diff",
        default=None,
        help=(
            "Path to a unified-diff text file. Deterministic diff-to-action "
            "translation; explicit pattern detection inside the diff only. "
            "Mutually exclusive with --action."
        ),
    )
    check_parser.add_argument(
        "--risk-tier",
        default=None,
        choices=("T0", "T1", "T2", "T3", "T4"),
        help=(
            "Caller-supplied risk tier for diff-derived actions (default T1). "
            "Choose T4 to route to ESCALATE via the engine's built-in "
            "override_required default."
        ),
    )
    check_parser.add_argument(
        "--at",
        default=None,
        help=(
            "Optional ISO 8601 build-time stamp recorded in diff-derived "
            f"actions. Defaults to {_DIFF_DEFAULT_TIMESTAMP!r}."
        ),
    )
    check_parser.add_argument("--evidence-out", default=None)

    verify_parser = subparsers.add_parser(
        "verify",
        help=(
            "Verify mode (subcommand form): hash check + optional replay of "
            "the gate decision."
        ),
        description=(
            "Subcommand form of --verify. Identical semantics to the flat-arg "
            "form. Requires --evidence-in; optional --policy and --action "
            "trigger a replay."
        ),
    )
    verify_parser.add_argument("--evidence-in", required=True)
    verify_parser.add_argument("--policy", default=None)
    verify_parser.add_argument("--action", default=None)
    verify_parser.add_argument(
        "--override",
        default=None,
        help=(
            "Optional path to a JSON object describing the override "
            "decision recorded in the evidence pack. Triggers override-"
            "aware replay: the verifier re-evaluates the recorded outcome "
            "against the supplied inputs and reports an "
            "override_replay_status line."
        ),
    )
    verify_parser.add_argument(
        "--ledger",
        default=None,
        help=(
            "Optional path to a JSON-array ledger chain file. "
            "Triggers ledger-aware replay: the verifier asserts the chain "
            "hash-verifies under verify_ledger_chain and that the recorded "
            "pack_hash appears in it exactly once. The path must already "
            "exist; a missing path is a configuration error and fails closed."
        ),
    )

    return parser


def _escalate(reason: str) -> int:
    print("verdict: ESCALATE")
    print("decision: error")
    print(f"error: {reason}", file=sys.stderr)
    return 2


def _err_row(code: str, path: str = "", message: str = "") -> dict[str, str]:
    return {"code": code, "path": path, "message": message}


def _emit_structured_error(category: str, errors: list[dict[str, str]]) -> None:
    envelope: dict[str, Any] = {"error": category, "errors": errors}
    sys.stderr.write(json.dumps(envelope, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stderr.flush()


def _run_metadata(at: str | None) -> dict[str, Any] | None:
    if at is None:
        return None
    return {"build_time": at}


def _run_check(args: argparse.Namespace) -> int:
    if args.policy is None:
        return _escalate("check mode requires --policy")

    diff_path_raw = getattr(args, "diff", None)
    action_path_raw = args.action

    if diff_path_raw is not None and action_path_raw is not None:
        return _escalate("--action and --diff are mutually exclusive")
    if diff_path_raw is None and action_path_raw is None:
        return _escalate("check mode requires either --action or --diff")

    action_data: dict[str, Any]
    try:
        if diff_path_raw is not None:
            risk_tier = getattr(args, "risk_tier", None) or "T1"
            at = getattr(args, "at", None) or _DIFF_DEFAULT_TIMESTAMP
            action_data = diff_to_action(
                Path(diff_path_raw),
                risk_tier=risk_tier,
                at=at,
            )
        else:
            action_path = Path(action_path_raw)
            action_text = action_path.read_text(encoding="utf-8")
            action_data = json.loads(action_text)

        policy = load_policy(args.policy)
        action = validate_action(action_data)
        ev = evaluate_action(policy, action)
        facts = DeterministicFacts(
            action_id=action.id,
            policy_hash=_policy_hash(policy),
            inputs=dict(action.inputs) if action.inputs is not None else {},
        )
        verdict = PolicyVerdict(
            decision=ev.decision,
            reasons=tuple(ev.reasons),
            gates_evaluated=tuple(ev.gates_evaluated),
        )
        pack = build_evidence_pack(facts, verdict, ModelDerivedJudgments(judgments={}))
    except _FAIL_CLOSED_EXCEPTIONS as exc:
        return _escalate(f"{type(exc).__name__}: {exc}")

    mnemonic, code = VERDICT_MAP[verdict.decision]
    print(f"verdict: {mnemonic}")
    print(f"decision: {verdict.decision}")
    for reason in verdict.reasons:
        print(f"reason: {reason}")
    print(f"gates_evaluated: {','.join(verdict.gates_evaluated)}")
    print(f"pack_hash: {pack.manifest.pack_hash}")

    if args.evidence_out:
        out = Path(args.evidence_out)
        if out.parent and str(out.parent) not in ("", "."):
            out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
        print(f"evidence_path: {out}")

        # Sidecar derived-action JSON: only written when --diff produced
        # the action (so a later --verify --action <sidecar> can replay).
        if diff_path_raw is not None:
            sidecar = derive_sidecar_path(out)
            sidecar.write_text(
                json.dumps(action_data, sort_keys=True, separators=(",", ":")) + "\n",
                encoding="utf-8",
            )
            print(f"action_sidecar_path: {sidecar}")
    return code


def _run_verify(args: argparse.Namespace) -> int:
    if args.evidence_in is None:
        return _escalate("--verify requires --evidence-in")
    if (args.policy is None) != (args.action is None):
        return _escalate(
            "--verify replay requires both --policy and --action, or neither"
        )

    override_decision: OverrideDecision | None = None
    override_context: OverrideContext | None = None
    override_path = getattr(args, "override", None)
    if override_path is not None:
        override_payload = _validate_override_file(override_path)
        if override_payload is None:
            return _escalate("override input unreadable or malformed")
        try:
            override_decision = OverrideDecision(
                override_id=override_payload["override_id"],
                applies_to_action_id=override_payload["applies_to_action_id"],
                not_after=override_payload["not_after"],
                consumed=override_payload["consumed"],
            )
        except TypeError as exc:
            _emit_structured_error(
                "override",
                [_err_row("malformed_field", "override", str(exc))],
            )
            return _escalate("override payload field types invalid")
        # The override-replay context's action_id is taken from the
        # override file itself (applies_to_action_id), since verify mode
        # does not necessarily know the original action object. This
        # makes the override_id/applies_to_action_id binding the source
        # of truth and lets the verifier compare against the recorded
        # override.
        override_context = OverrideContext(
            action_id=override_payload["applies_to_action_id"],
            now=override_payload["now"],
        )

    ledger_chain: tuple[LedgerEntry, ...] | None = None
    ledger_path = getattr(args, "ledger", None)
    if ledger_path is not None:
        if not Path(ledger_path).exists():
            _emit_structured_error(
                "ledger",
                [_err_row("read_error", "ledger", "ledger file does not exist")],
            )
            return _escalate("ledger file does not exist")
        ledger_chain = _load_or_init_ledger_chain(ledger_path)
        if ledger_chain is None:
            return _escalate("ledger input unreadable, malformed, or broken")

    try:
        policy: Policy | None = (
            load_policy(args.policy) if args.policy is not None else None
        )
        action: ActionDescriptor | None
        if args.action is not None:
            action_text = Path(args.action).read_text(encoding="utf-8")
            action = validate_action(json.loads(action_text))
        else:
            action = None
        result = verify_evidence(
            Path(args.evidence_in),
            policy=policy,
            action=action,
            override_decision=override_decision,
            override_context=override_context,
            ledger_chain=ledger_chain,
        )
    except _FAIL_CLOSED_EXCEPTIONS as exc:
        return _escalate(f"{type(exc).__name__}: {exc}")

    pack_hash_display = result.pack_hash if result.pack_hash is not None else "<none>"
    print(f"verify_status: {result.status}")
    print(f"pack_hash: {pack_hash_display}")
    print(f"replay_status: {result.replay_status}")
    for reason in result.reasons:
        print(f"reason: {reason}")
    for replay_reason in result.replay_reasons:
        print(f"replay_reason: {replay_reason}")
    print(f"override_replay_status: {result.override_replay_status}")
    for override_replay_reason in result.override_replay_reasons:
        print(f"override_replay_reason: {override_replay_reason}")
    print(f"ledger_replay_status: {result.ledger_replay_status}")
    for ledger_replay_reason in result.ledger_replay_reasons:
        print(f"ledger_replay_reason: {ledger_replay_reason}")
    if result.ledger_replay_match is not None:
        match = result.ledger_replay_match
        print(f"ledger_replay_sequence: {match.sequence}")
        print(f"ledger_replay_prev_hash: {match.prev_hash}")
        print(f"ledger_replay_entry_hash: {match.entry_hash}")

    if (
        result.status == "PASS"
        and result.replay_status in {"REPLAY_PASS", "NOT_REPLAYABLE"}
        and result.override_replay_status
        in {
            "OVERRIDE_REPLAY_PASS",
            "OVERRIDE_NOT_REPLAYABLE",
            "OVERRIDE_NOT_PRESENT",
        }
        and result.ledger_replay_status
        in {
            "LEDGER_REPLAY_PASS",
            "LEDGER_NOT_REPLAYABLE",
        }
    ):
        return 0
    return 2


_OVERRIDE_REQUIRED_KEYS: tuple[str, ...] = (
    "override_id",
    "applies_to_action_id",
    "not_after",
    "consumed",
    "now",
)


def _read_safety_json(path_str: str, category: str) -> dict[str, Any] | None:
    """Read and parse a JSON object from ``path_str``.

    On failure, emit a structured stderr envelope under ``category`` and
    return ``None``. The caller is expected to fail closed (exit 2).
    """
    try:
        text = Path(path_str).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as exc:
        _emit_structured_error(
            category, [_err_row("read_error", category, type(exc).__name__)]
        )
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _emit_structured_error(
            category, [_err_row("json_decode_error", category, exc.msg)]
        )
        return None
    if not isinstance(data, dict):
        _emit_structured_error(
            category,
            [_err_row("not_object", category, f"{category} must be a JSON object")],
        )
        return None
    return data


def _check_kill_switch(path_str: str) -> int | None:
    """Evaluate a caller-supplied kill-switch JSON file.

    Returns ``None`` when the kill switch permits continuation. Returns
    an exit code (always 2) when the kill switch is active or malformed,
    after emitting a structured stderr envelope.
    """
    data = _read_safety_json(path_str, "kill_switch")
    if data is None:
        return _escalate("kill-switch input unreadable or malformed")
    if "state" not in data:
        _emit_structured_error(
            "kill_switch",
            [_err_row("missing_field", "kill_switch.state", "missing 'state' field")],
        )
        return _escalate("kill-switch missing 'state'")
    try:
        result = evaluate_kill_switch(data["state"])
    except SafetyControlError as exc:
        _emit_structured_error(
            "kill_switch", [_err_row(exc.code, exc.path, exc.message)]
        )
        return _escalate("kill-switch state malformed")
    if result.outcome != "permit":
        _emit_structured_error(
            "kill_switch",
            [_err_row("active_engaged", "kill_switch.state", result.reason)],
        )
        return _escalate("kill-switch is active")
    return None


def _validate_override_file(path_str: str) -> dict[str, Any] | None:
    """Read and shape-check an override JSON file.

    Returns the parsed object on success. Returns ``None`` after emitting
    a structured stderr envelope on file / shape failure; the caller is
    expected to fail closed.
    """
    data = _read_safety_json(path_str, "override")
    if data is None:
        return None
    missing = [key for key in _OVERRIDE_REQUIRED_KEYS if key not in data]
    if missing:
        _emit_structured_error(
            "override",
            [
                _err_row("missing_field", f"override.{key}", "missing required field")
                for key in missing
            ],
        )
        return None
    return data


_LEDGER_ERROR_CODE_MAP: dict[str, str] = {
    LedgerError.MALFORMED_ENTRY: "schema_violation",
    LedgerError.SCHEMA_VIOLATION: "schema_violation",
    LedgerError.BROKEN_CHAIN: "broken_chain",
    LedgerError.HASH_MISMATCH: "hash_mismatch",
}


def _check_ledger_companions(args: argparse.Namespace) -> int | None:
    """Enforce --ledger requires --override and --at.

    Returns ``None`` when the companion flags are present, or an exit
    code (always 2) after emitting a structured stderr envelope.
    """
    if getattr(args, "override", None) is None:
        _emit_structured_error(
            "ledger",
            [
                _err_row(
                    "requires_override",
                    "ledger",
                    "--ledger requires --override (an applicable override "
                    "is the consumption event being recorded)",
                )
            ],
        )
        return _escalate("--ledger requires --override")
    if getattr(args, "at", None) is None:
        _emit_structured_error(
            "ledger",
            [
                _err_row(
                    "requires_at",
                    "ledger",
                    "--ledger requires --at (LedgerEntry.append_time is "
                    "caller-supplied; no system clock is read)",
                )
            ],
        )
        return _escalate("--ledger requires --at")
    return None


def _load_or_init_ledger_chain(
    path_str: str,
) -> tuple[LedgerEntry, ...] | None:
    """Load an existing chain file, verify it, and return the chain.

    Returns the empty tuple when the path does not exist (the caller
    is starting a fresh chain). Returns ``None`` after emitting a
    structured stderr envelope on any failure (read error, malformed
    JSON, non-array, schema violation, broken chain, hash mismatch).
    """
    path = Path(path_str)
    if not path.exists():
        return ()
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as exc:
        _emit_structured_error(
            "ledger",
            [_err_row("read_error", "ledger", type(exc).__name__)],
        )
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        _emit_structured_error(
            "ledger",
            [_err_row("json_decode_error", "ledger", exc.msg)],
        )
        return None
    if not isinstance(data, list):
        _emit_structured_error(
            "ledger",
            [
                _err_row(
                    "not_array",
                    "ledger",
                    f"ledger file must contain a JSON array, got {type(data).__name__}",
                )
            ],
        )
        return None
    entries: list[LedgerEntry] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            _emit_structured_error(
                "ledger",
                [
                    _err_row(
                        "schema_violation",
                        f"ledger[{index}]",
                        f"chain entry must be an object, got {type(item).__name__}",
                    )
                ],
            )
            return None
        required = {"sequence", "pack_hash", "prev_hash", "append_time", "entry_hash"}
        missing = sorted(required - set(item.keys()))
        if missing:
            _emit_structured_error(
                "ledger",
                [
                    _err_row(
                        "schema_violation",
                        f"ledger[{index}].{key}",
                        "missing required field",
                    )
                    for key in missing
                ],
            )
            return None
        try:
            entries.append(
                LedgerEntry(
                    sequence=item["sequence"],
                    pack_hash=item["pack_hash"],
                    prev_hash=item["prev_hash"],
                    append_time=item["append_time"],
                    entry_hash=item["entry_hash"],
                )
            )
        except (TypeError, ValueError) as exc:
            _emit_structured_error(
                "ledger",
                [_err_row("schema_violation", f"ledger[{index}]", str(exc))],
            )
            return None
    chain = tuple(entries)
    result = verify_ledger_chain(chain)
    if not result.ok:
        rows = []
        for err in result.errors:
            mapped = _LEDGER_ERROR_CODE_MAP.get(err.code, err.code)
            rows.append(_err_row(mapped, err.path, err.message))
        _emit_structured_error("ledger", rows)
        return None
    return chain


def _append_and_write_ledger(
    path_str: str,
    chain: tuple[LedgerEntry, ...],
    *,
    pack_hash: str,
    append_time: str,
) -> LedgerEntry | None:
    """Append a new entry to ``chain`` and write the extended chain.

    Returns the new ``LedgerEntry`` on success. Returns ``None`` after
    emitting a structured stderr envelope on a build error (e.g.
    LedgerError) or write error (OSError). The caller is expected to
    fail closed exit 2.
    """
    try:
        new_entry = append_ledger_entry(
            chain, pack_hash=pack_hash, append_time=append_time
        )
    except LedgerError as exc:
        mapped = _LEDGER_ERROR_CODE_MAP.get(exc.code, exc.code)
        _emit_structured_error("ledger", [_err_row(mapped, exc.path, exc.message)])
        return None
    extended = chain + (new_entry,)
    payload: list[dict[str, Any]] = []
    for entry in extended:
        envelope = json.loads(canonicalize_ledger_entry(entry))
        envelope["entry_hash"] = entry.entry_hash
        payload.append(envelope)
    serialised = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    try:
        Path(path_str).write_text(serialised, encoding="utf-8")
    except OSError as exc:
        _emit_structured_error(
            "ledger", [_err_row("write_error", "ledger", type(exc).__name__)]
        )
        return None
    return new_entry


def _evaluate_override_payload(
    payload: dict[str, Any], action_id: str
) -> tuple[str, str] | int:
    """Run the override primitive on a validated payload.

    Returns ``(outcome, reason)`` when the override is applicable and the
    run should continue. Returns an exit code (always 2) when the
    override evaluator raises a structured error or returns any rejected
    outcome; in that case a structured stderr envelope has already been
    emitted.
    """
    try:
        decision = OverrideDecision(
            override_id=payload["override_id"],
            applies_to_action_id=payload["applies_to_action_id"],
            not_after=payload["not_after"],
            consumed=payload["consumed"],
        )
        context = OverrideContext(action_id=action_id, now=payload["now"])
    except TypeError as exc:
        _emit_structured_error(
            "override",
            [_err_row("malformed_field", "override", str(exc))],
        )
        return _escalate("override payload field types invalid")
    try:
        result = evaluate_override(decision, context)
    except SafetyControlError as exc:
        _emit_structured_error("override", [_err_row(exc.code, exc.path, exc.message)])
        return _escalate("override is malformed")
    if result.outcome != "applicable":
        _emit_structured_error(
            "override",
            [_err_row(result.outcome, "override", result.reason)],
        )
        return _escalate(f"override {result.outcome}")
    return result.outcome, result.reason


def _run_run_mode(args: argparse.Namespace) -> int:
    # kill-switch: fail closed before policy evaluation.
    kill_switch_path = getattr(args, "kill_switch", None)
    if kill_switch_path is not None:
        ks_exit = _check_kill_switch(kill_switch_path)
        if ks_exit is not None:
            return ks_exit

    # override: shape-validate the file early; semantic evaluation
    # is deferred until after the gate produces an action_id.
    override_path = getattr(args, "override", None)
    override_payload: dict[str, Any] | None = None
    if override_path is not None:
        override_payload = _validate_override_file(override_path)
        if override_payload is None:
            return _escalate("override input unreadable or malformed")

    # override-consumption ledger pre-flight: companion-flag check
    # and chain load+verify before any disk write.
    ledger_path = getattr(args, "ledger", None)
    ledger_chain: tuple[LedgerEntry, ...] | None = None
    if ledger_path is not None:
        companions_exit = _check_ledger_companions(args)
        if companions_exit is not None:
            return companions_exit
        ledger_chain = _load_or_init_ledger_chain(ledger_path)
        if ledger_chain is None:
            return _escalate("ledger input unreadable, malformed, or broken")

    out_dir = Path(args.out)

    if out_dir.exists():
        if not out_dir.is_dir():
            _emit_structured_error(
                "out",
                [_err_row("not_directory", "out", "--out path is not a directory")],
            )
            return _escalate("--out path exists and is not a directory")
        try:
            has_entries = any(out_dir.iterdir())
        except OSError as exc:
            _emit_structured_error(
                "out", [_err_row("read_error", "out", type(exc).__name__)]
            )
            return _escalate("--out directory could not be read")
        if has_entries:
            _emit_structured_error(
                "out",
                [
                    _err_row(
                        "out_not_empty",
                        "out",
                        "refusing to overwrite a non-empty --out directory",
                    )
                ],
            )
            return _escalate("--out directory is not empty")
    else:
        try:
            out_dir.mkdir(parents=True, exist_ok=False)
        except OSError as exc:
            _emit_structured_error(
                "out", [_err_row("mkdir_failed", "out", type(exc).__name__)]
            )
            return _escalate("--out directory could not be created")

    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:
        _emit_structured_error("policy", [_err_row(exc.code, exc.path, exc.message)])
        return _escalate("policy load failed")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as exc:
        _emit_structured_error(
            "policy",
            [_err_row("read_error", "policy", type(exc).__name__)],
        )
        return _escalate("policy file unreadable")

    try:
        payload_text = Path(args.payload).read_text(encoding="utf-8")
    except (FileNotFoundError, OSError, UnicodeDecodeError) as exc:
        _emit_structured_error(
            "payload",
            [_err_row("read_error", "payload", type(exc).__name__)],
        )
        return _escalate("payload file unreadable")

    try:
        payload_data = json.loads(payload_text)
    except json.JSONDecodeError as exc:
        _emit_structured_error(
            "payload",
            [_err_row("json_decode_error", "payload", exc.msg)],
        )
        return _escalate("payload JSON malformed")

    if not isinstance(payload_data, dict):
        _emit_structured_error(
            "payload",
            [
                _err_row(
                    "not_object",
                    "payload",
                    "payload must be a JSON object",
                )
            ],
        )
        return _escalate("payload must be a JSON object")

    adapter_input = AdapterInput(operation="synthetic.echo", payload=payload_data)
    adapter_result = adapt_payload(SyntheticAdapter(), adapter_input)
    if not adapter_result.ok or adapter_result.output is None:
        rows = [
            _err_row(err.code, err.path, err.message) for err in adapter_result.errors
        ]
        _emit_structured_error("adapter", rows)
        return _escalate("adapter rejected payload")

    action = adapter_result.output.action

    try:
        evaluation = evaluate_action(policy, action)
    except GateEvaluationError as exc:
        _emit_structured_error("gate", [_err_row(exc.code, exc.path, exc.message)])
        return _escalate("gate evaluation failed")

    override_outcome_line: str | None = None
    override_evidence: OverrideEvidence | None = None
    if override_payload is not None:
        ov_result = _evaluate_override_payload(override_payload, action.id)
        if isinstance(ov_result, int):
            return ov_result
        outcome, reason = ov_result
        override_outcome_line = f"override_outcome: {outcome} ({reason})"
        override_evidence = OverrideEvidence(
            override_id=override_payload["override_id"],
            outcome=outcome,
        )

    try:
        facts = DeterministicFacts(
            action_id=action.id,
            policy_hash=_policy_hash(policy),
            inputs=dict(action.inputs) if action.inputs is not None else {},
            metadata=_run_metadata(args.at),
            override=override_evidence,
        )
        verdict = PolicyVerdict(
            decision=evaluation.decision,
            reasons=tuple(evaluation.reasons),
            gates_evaluated=tuple(evaluation.gates_evaluated),
        )
        pack = build_evidence_pack(facts, verdict, ModelDerivedJudgments(judgments={}))
    except EvidenceError as exc:
        _emit_structured_error("evidence", [_err_row(exc.code, exc.path, exc.message)])
        return _escalate("evidence pack build failed")

    try:
        (out_dir / _RUN_PACK_FILENAME).write_text(
            evidence_pack_to_canonical_json(pack), encoding="utf-8"
        )
        for section in _RUN_SECTION_NAMES:
            (out_dir / f"{section}.json").write_text(
                section_canonical_json(pack, section), encoding="utf-8"
            )
    except OSError as exc:
        _emit_structured_error(
            "write", [_err_row("write_error", "out", type(exc).__name__)]
        )
        return _escalate("evidence pack write failed")

    new_ledger_entry: LedgerEntry | None = None
    if ledger_path is not None and override_evidence is not None:
        # Companion-flag check above already enforced --at presence.
        assert ledger_chain is not None
        assert args.at is not None
        new_ledger_entry = _append_and_write_ledger(
            ledger_path,
            ledger_chain,
            pack_hash=pack.manifest.pack_hash,
            append_time=args.at,
        )
        if new_ledger_entry is None:
            return _escalate("ledger append/write failed")

    mnemonic, code = VERDICT_MAP[verdict.decision]
    print(f"verdict: {mnemonic}")
    print(f"decision: {verdict.decision}")
    for reason in verdict.reasons:
        print(f"reason: {reason}")
    print(f"gates_evaluated: {','.join(verdict.gates_evaluated)}")
    if override_outcome_line is not None:
        print(override_outcome_line)
    print(f"pack_hash: {pack.manifest.pack_hash}")
    print(f"evidence_path: {out_dir / _RUN_PACK_FILENAME}")
    if new_ledger_entry is not None:
        print(f"ledger_sequence: {new_ledger_entry.sequence}")
        print(f"ledger_entry_hash: {new_ledger_entry.entry_hash}")
        print(f"ledger_path: {ledger_path}")
    return code


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    sub = getattr(args, "subcommand", None)
    if sub == "run":
        return _run_run_mode(args)
    if sub == "check":
        return _run_check(args)
    if sub == "verify":
        return _run_verify(args)
    if args.verify:
        return _run_verify(args)
    return _run_check(args)


if __name__ == "__main__":
    sys.exit(main())
