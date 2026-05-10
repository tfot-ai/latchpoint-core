"""Tests for the deterministic gate evaluator."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from latchpoint_core import (
    AnyOf,
    Condition,
    Gate,
    Policy,
    build_evidence_pack,
    verify_evidence_pack,
)
from latchpoint_core.action_model import (
    ActionDescriptor,
    ActionError,
    validate_action,
)
from latchpoint_core.evidence_model import (
    DeterministicFacts,
    ModelDerivedJudgments,
    POLICY_VERDICT_DECISIONS,
    PolicyVerdict,
)
from latchpoint_core.evidence_pack import evidence_pack_to_canonical_json
from latchpoint_core.gate_evaluator import evaluate_action
from latchpoint_core.gate_model import (
    GATE_STATUSES,
    GateEvaluation,
    GateEvaluationError,
    GateResult,
)
from latchpoint_core.policy_model import _MISSING

ROOT = Path(__file__).resolve().parent
ACTION_FIXTURES = ROOT / "fixtures" / "actions"
POLICY_FIXTURES = ROOT / "fixtures" / "policies"
SRC_DIR = ROOT.parent / "src" / "latchpoint_core"

OC1_MODULES = (
    SRC_DIR / "action_model.py",
    SRC_DIR / "gate_model.py",
    SRC_DIR / "gate_evaluator.py",
)

FORBIDDEN_STDLIB_TOPLEVELS = (
    "os",
    "time",
    "datetime",
    "random",
    "secrets",
    "socket",
    "urllib",
    "requests",
    "subprocess",
    "http",
    "asyncio",
)

FORBIDDEN_NAMESPACES = (
    "latchpoint_" "app",
    "latchpoint_" "governance",
    "latchpoint",
)


def _action(name: str) -> ActionDescriptor:
    with (ACTION_FIXTURES / name).open("r", encoding="utf-8") as fh:
        return validate_action(json.load(fh))


def _gate(
    name: str,
    *,
    trigger: str = "pre_execution",
    action_on_fail: str = "BLOCK",
    applies_to: tuple[str, ...] | None = None,
    conditions: tuple = (),
    override: bool = False,
) -> Gate:
    return Gate(
        name=name,
        trigger=trigger,
        action_on_fail=action_on_fail,
        applies_to=applies_to,
        conditions=conditions,
        override=override,
    )


def _policy(*gates: Gate) -> Policy:
    return Policy(name="testpack", version="0.1.0", gates=tuple(gates))


# ------------------------------------------------------------------ #
# 1-8: basic decision flow                                            #
# ------------------------------------------------------------------ #


def test_evaluate_minimal_action_against_minimal_policy_passes():
    p = _policy(_gate("always_pass", conditions=()))
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    assert e.gates_evaluated == ("always_pass",)
    assert e.reasons == ()


def test_safe_action_skips_tier_scoped_gate():
    p = _policy(
        _gate(
            "tier_gate",
            applies_to=("T3", "T4"),
            conditions=(
                Condition(
                    type="threshold", field="risk_tier", operator=">=", value="T3"
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    assert e.gates_evaluated == ()
    assert e.gate_results[0].status == "SKIP"


def test_high_risk_action_blocks_via_threshold():
    p = Policy.load(POLICY_FIXTURES / "gate_eval_basic.yaml")
    e = evaluate_action(p, _action("high_risk_action.json"))
    assert e.decision == "block"
    assert "high_risk_block" in e.gates_evaluated


def test_t4_action_yields_override_required():
    p = _policy(_gate("noop", conditions=()))
    e = evaluate_action(p, _action("escalation_action.json"))
    assert e.decision == "override_required"
    assert e.reasons[-1] == "T4 risk tier requires human approval"


def test_t4_action_with_block_fired_blocks_takes_precedence():
    p = _policy(
        _gate(
            "deny",
            action_on_fail="BLOCK",
            conditions=(
                Condition(
                    type="denylist",
                    field="inputs.target_kind",
                    operator="in",
                    value=["policy.modify"],
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("escalation_action.json"))
    assert e.decision == "block"


def test_skipped_gate_does_not_affect_decision():
    p = _policy(
        _gate(
            "tier_only",
            applies_to=("T3", "T4"),
            conditions=(
                Condition(
                    type="threshold", field="risk_tier", operator=">=", value="T3"
                ),
            ),
        ),
        _gate("ok", conditions=()),
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    assert "tier_only" not in e.gates_evaluated
    assert "ok" in e.gates_evaluated


def test_warn_gate_does_not_block():
    p = _policy(
        _gate(
            "warn_check",
            action_on_fail="WARN",
            conditions=(
                Condition(
                    type="custom",
                    field="reversibility",
                    operator="is_not_null",
                    value=True,
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    assert any(r.status == "WARN" for r in e.gate_results)
    assert any("warn_check" in reason for reason in e.reasons)


def test_log_only_gate_records_reason_does_not_block():
    p = _policy(
        _gate(
            "log_check",
            action_on_fail="LOG",
            conditions=(
                Condition(
                    type="custom",
                    field="reversibility",
                    operator="is_not_null",
                    value=True,
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    log_results = [r for r in e.gate_results if r.gate_name == "log_check"]
    assert log_results[0].status == "PASS"
    assert log_results[0].reason != ""


# ------------------------------------------------------------------ #
# 9-19: malformed inputs / fail-closed                                #
# ------------------------------------------------------------------ #


def test_malformed_action_raises_action_error():
    with pytest.raises(ActionError):
        validate_action({"id": "x"})


def test_unknown_operator_synthesised_yields_error_status():
    p = _policy(
        _gate(
            "bad_op",
            conditions=(
                Condition(
                    type="threshold", field="risk_tier", operator="???", value="T3"
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "block"
    assert any(r.status == "ERROR" for r in e.gate_results)


def test_threshold_missing_field_yields_error():
    p = _policy(
        _gate(
            "missing",
            conditions=(
                Condition(
                    type="threshold", field="inputs.amount", operator=">=", value=10
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "block"
    assert e.gate_results[0].status == "ERROR"


def test_threshold_risk_tier_string_compare():
    p = _policy(
        _gate(
            "tier_block",
            conditions=(
                Condition(
                    type="threshold", field="risk_tier", operator=">=", value="T3"
                ),
            ),
        )
    )
    high = _action("high_risk_action.json")
    e = evaluate_action(p, high)
    assert e.decision == "block"


def test_threshold_invalid_tier_yields_error():
    p = _policy(
        _gate(
            "badtier",
            conditions=(
                Condition(
                    type="threshold", field="risk_tier", operator=">=", value="T7"
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "block"
    assert e.gate_results[0].status == "ERROR"


def test_threshold_subtier_qualifier_yields_error():
    p = _policy(
        _gate(
            "subtier",
            conditions=(
                Condition(
                    type="threshold", field="risk_tier", operator=">=", value="T2.pii"
                ),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.gate_results[0].status == "ERROR"


def test_threshold_mixed_tier_and_number_yields_error():
    p = _policy(
        _gate(
            "mixed",
            conditions=(
                Condition(type="threshold", field="risk_tier", operator=">=", value=5),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.gate_results[0].status == "ERROR"


def test_regex_against_missing_field_yields_error():
    for op in ("matches", "not_matches"):
        p = _policy(
            _gate(
                f"re_{op}",
                conditions=(
                    Condition(
                        type="regex",
                        field="inputs.payload",
                        operator=op,
                        value="^safe-.*",
                    ),
                ),
            )
        )
        e = evaluate_action(p, _action("minimal_action.json"))
        assert e.gate_results[0].status == "ERROR", op


def test_regex_invalid_pattern_yields_error():
    p = _policy(
        _gate(
            "badre",
            conditions=(
                Condition(type="regex", field="id", operator="matches", value="["),
            ),
        )
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.gate_results[0].status == "ERROR"


def test_in_not_in_against_missing_field_yields_error():
    for op in ("in", "not_in"):
        p = _policy(
            _gate(
                f"list_{op}",
                conditions=(
                    Condition(
                        type="allowlist",
                        field="inputs.does_not_exist",
                        operator=op,
                        value=["x"],
                    ),
                ),
            )
        )
        e = evaluate_action(p, _action("minimal_action.json"))
        assert e.gate_results[0].status == "ERROR", op


def test_value_from_missing_field_yields_error():
    cond = Condition(
        type="threshold",
        field="risk_tier",
        operator=">=",
        value=_MISSING,
        value_from="inputs.does_not_exist",
    )
    p = _policy(_gate("vf", conditions=(cond,)))
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.gate_results[0].status == "ERROR"


# ------------------------------------------------------------------ #
# 20-22: determinism + non-mutation                                    #
# ------------------------------------------------------------------ #


def test_evaluation_is_deterministic():
    p = Policy.load(POLICY_FIXTURES / "gate_eval_basic.yaml")
    a = _action("high_risk_action.json")
    e1 = evaluate_action(p, a)
    e2 = evaluate_action(p, a)
    assert e1 == e2

    v1 = PolicyVerdict(
        decision=e1.decision, reasons=e1.reasons, gates_evaluated=e1.gates_evaluated
    )
    v2 = PolicyVerdict(
        decision=e2.decision, reasons=e2.reasons, gates_evaluated=e2.gates_evaluated
    )
    pack1 = build_evidence_pack(
        DeterministicFacts(action_id=a.id, policy_hash="0" * 64, inputs={"x": 1}),
        v1,
        ModelDerivedJudgments(judgments={}),
    )
    pack2 = build_evidence_pack(
        DeterministicFacts(action_id=a.id, policy_hash="0" * 64, inputs={"x": 1}),
        v2,
        ModelDerivedJudgments(judgments={}),
    )
    assert evidence_pack_to_canonical_json(pack1) == evidence_pack_to_canonical_json(
        pack2
    )


def test_reasons_have_stable_ordering():
    error_gate = _gate(
        "g_error",
        conditions=(
            Condition(type="threshold", field="inputs.amount", operator=">=", value=1),
        ),
    )
    fail_gate = _gate(
        "g_fail",
        action_on_fail="BLOCK",
        conditions=(
            Condition(
                type="custom", field="reversibility", operator="is_not_null", value=True
            ),
        ),
    )
    warn_gate = _gate(
        "g_warn",
        action_on_fail="WARN",
        conditions=(
            Condition(
                type="custom", field="reversibility", operator="is_not_null", value=True
            ),
        ),
    )
    p = _policy(error_gate, fail_gate, warn_gate)
    e = evaluate_action(p, _action("minimal_action.json"))
    error_reasons = [r for r in e.reasons if "g_error" in r]
    fail_reasons = [r for r in e.reasons if "g_fail" in r]
    warn_reasons = [r for r in e.reasons if "g_warn" in r]
    assert error_reasons and fail_reasons and warn_reasons
    error_idx = e.reasons.index(error_reasons[0])
    fail_idx = e.reasons.index(fail_reasons[0])
    warn_idx = e.reasons.index(warn_reasons[0])
    assert error_idx < fail_idx < warn_idx


def test_evaluator_does_not_mutate_inputs():
    p = Policy.load(POLICY_FIXTURES / "gate_eval_basic.yaml")
    a = _action("high_risk_action.json")
    p_repr = repr(p)
    a_repr = repr(a)
    evaluate_action(p, a)
    assert repr(p) == p_repr
    assert repr(a) == a_repr


# ------------------------------------------------------------------ #
# 23-24: AST import discipline                                        #
# ------------------------------------------------------------------ #


def _module_imports(path: Path) -> tuple[list[str], list[tuple[int, str | None]]]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    plain: list[str] = []
    fromimports: list[tuple[int, str | None]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                plain.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            fromimports.append((node.level, node.module))
    return plain, fromimports


def test_implementation_modules_use_only_stdlib():
    for path in OC1_MODULES:
        plain, fromimports = _module_imports(path)
        for mod in plain:
            top = mod.split(".")[0]
            assert top not in FORBIDDEN_STDLIB_TOPLEVELS, f"{path}: import {mod}"
        for level, mod in fromimports:
            if level != 0 or mod is None:
                continue
            if mod == "__future__":
                continue
            top = mod.split(".")[0]
            assert top not in FORBIDDEN_STDLIB_TOPLEVELS, f"{path}: from {mod}"


def test_no_sibling_imports():
    for path in OC1_MODULES:
        plain, fromimports = _module_imports(path)
        for mod in plain:
            top = mod.split(".")[0]
            assert top not in FORBIDDEN_NAMESPACES, f"{path}: import {mod}"
        for _level, mod in fromimports:
            if mod is None:
                continue
            top = mod.split(".")[0]
            assert top not in FORBIDDEN_NAMESPACES, f"{path}: from {mod}"


# ------------------------------------------------------------------ #
# 25: evidence pack integration                                        #
# ------------------------------------------------------------------ #


def test_evaluation_embeds_in_evidence_pack():
    p = Policy.load(POLICY_FIXTURES / "gate_eval_basic.yaml")
    a = _action("high_risk_action.json")
    e = evaluate_action(p, a)
    verdict = PolicyVerdict(
        decision=e.decision, reasons=e.reasons, gates_evaluated=e.gates_evaluated
    )
    facts = DeterministicFacts(action_id=a.id, policy_hash="0" * 64, inputs={"k": "v"})
    pack = build_evidence_pack(facts, verdict, ModelDerivedJudgments(judgments={}))
    assert verify_evidence_pack(pack).ok is True


# ------------------------------------------------------------------ #
# 26-31: edge cases & invariants                                       #
# ------------------------------------------------------------------ #


def test_empty_policy_gates_yields_approve():
    p = Policy(name="empty", version="0.1.0", gates=())
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    assert e.gates_evaluated == ()
    assert e.reasons == ()


def test_all_skip_yields_approve():
    p = _policy(
        _gate("post", trigger="post_execution"), _gate("cont", trigger="continuous")
    )
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    assert e.gates_evaluated == ()
    assert all(r.status == "SKIP" for r in e.gate_results)


def test_empty_any_of_does_not_match():
    p = _policy(_gate("e", conditions=(AnyOf(any_of=()),)))
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision == "approve"
    assert e.gate_results[0].status == "PASS"


def test_applies_to_empty_tuple_skips_all():
    p = _policy(_gate("none", applies_to=()))
    for fixture in (
        "minimal_action.json",
        "high_risk_action.json",
        "escalation_action.json",
    ):
        e = evaluate_action(p, _action(fixture))
        assert e.gate_results[0].status == "SKIP", fixture


def test_reason_strings_do_not_leak_field_values():
    secret = "secret-xyz-do-not-leak"
    raw = {
        "id": "00000000-0000-4000-8000-000000000099",
        "type": "test.leak",
        "target": "tmp/leak",
        "risk_tier": "T1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "agent_id": "leak-agent",
        "session_id": "leak-session",
        "inputs": {"payload": secret},
    }
    a = validate_action(raw)
    p = _policy(
        _gate(
            "g",
            action_on_fail="BLOCK",
            conditions=(
                Condition(
                    type="regex",
                    field="inputs.payload",
                    operator="matches",
                    value="^secret-",
                ),
            ),
        )
    )
    e = evaluate_action(p, a)
    assert e.decision == "block"
    for reason in e.reasons:
        assert secret not in reason
    for r in e.gate_results:
        assert secret not in r.reason


def test_threshold_int_float_equivalence():
    raw = {
        "id": "00000000-0000-4000-8000-000000000050",
        "type": "test.numeric",
        "target": "tmp/n",
        "risk_tier": "T1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "agent_id": "n-agent",
        "session_id": "n-session",
        "inputs": {"amount": 5},
    }
    a = validate_action(raw)
    p = _policy(
        _gate(
            "eq",
            action_on_fail="BLOCK",
            conditions=(
                Condition(
                    type="threshold", field="inputs.amount", operator="==", value=5.0
                ),
            ),
        )
    )
    e = evaluate_action(p, a)
    assert e.decision == "block"


def test_gate_statuses_alphabet():
    assert GATE_STATUSES == ("PASS", "FAIL", "WARN", "SKIP", "ERROR")


def test_gate_evaluation_decision_in_oc3_enum():
    p = _policy(_gate("ok"))
    e = evaluate_action(p, _action("minimal_action.json"))
    assert e.decision in POLICY_VERDICT_DECISIONS
    assert isinstance(e, GateEvaluation)
    assert isinstance(e.gate_results[0], GateResult)


def test_gate_evaluation_error_categories_match_module_constants():
    err = GateEvaluationError("malformed_action", "p", "m")
    assert err.code == "malformed_action"
    with pytest.raises(ValueError):
        GateEvaluationError("not_a_real_code", "p", "m")
