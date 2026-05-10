"""Deterministic gate evaluator.

Pure function ``evaluate_action(policy, action) -> GateEvaluation``.

The evaluator consumes a frozen :class:`~.policy_model.Policy` and a
frozen :class:`~.action_model.ActionDescriptor` and returns a frozen
:class:`~.gate_model.GateEvaluation`. It does no I/O, makes no network
calls, reads no clock, draws no randomness, and never mutates inputs.

Decision aggregation (in order):
    1. Any ``ERROR`` gate ⇒ ``block`` (fail-closed).
    2. Else any ``FAIL`` gate ⇒ ``block``.
    3. Else action.risk_tier == "T4" ⇒ ``override_required``
       (T4 risk tier denotes human approval required.)
    4. Else ⇒ ``approve``.

Per-gate status:
    SKIP — gate.trigger != "pre_execution" OR action.risk_tier not
           in gate.applies_to (when applies_to is not None).
    ERROR — any condition raised :class:`GateEvaluationError`.
    FAIL — gate fired and action_on_fail == "BLOCK".
    WARN — gate fired and action_on_fail == "WARN".
    PASS — gate did not fire (or LOG-fired; reason recorded for audit).
"""

from __future__ import annotations

import functools
import re
from collections.abc import Mapping as _Mapping
from typing import Any

from .action_model import ActionDescriptor, _NOT_FOUND, _TIER_ORDER, resolve_field
from .gate_model import (
    GateEvaluation,
    GateEvaluationError,
    GateResult,
)
from .policy_model import _MISSING, AnyOf, Condition, Gate, Policy

_PHASE = "pre_execution"

_THRESHOLD_OPERATORS = frozenset({">=", ">", "<=", "<", "==", "!="})
_REGEX_OPERATORS = frozenset({"matches", "not_matches"})
_LISTMATCH_OPERATORS = frozenset({"in", "not_in"})
_CUSTOM_OPERATORS = frozenset({"is_null", "is_not_null", "exists", "contains"})


@functools.lru_cache(maxsize=128)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags=0)
    except re.error as exc:
        raise GateEvaluationError(
            GateEvaluationError.INVALID_PATTERN,
            path=pattern,
            message=str(exc),
        ) from exc


def evaluate_action(policy: Policy, action: ActionDescriptor) -> GateEvaluation:
    results: list[GateResult] = []
    for idx, gate in enumerate(policy.gates):
        results.append(_evaluate_gate(gate, idx, action))

    error_reasons = tuple(r.reason for r in results if r.status == "ERROR" and r.reason)
    fail_reasons = tuple(r.reason for r in results if r.status == "FAIL" and r.reason)
    warn_reasons = tuple(r.reason for r in results if r.status == "WARN" and r.reason)

    decision: str
    extra_reasons: tuple[str, ...] = ()
    if error_reasons:
        decision = "block"
    elif fail_reasons:
        decision = "block"
    elif action.risk_tier == "T4":
        decision = "override_required"
        extra_reasons = ("T4 risk tier requires human approval",)
    else:
        decision = "approve"

    reasons = error_reasons + fail_reasons + warn_reasons + extra_reasons

    gates_evaluated = tuple(r.gate_name for r in results if r.status != "SKIP")

    return GateEvaluation(
        decision=decision,
        reasons=reasons,
        gates_evaluated=gates_evaluated,
        gate_results=tuple(results),
    )


def _evaluate_gate(gate: Gate, gate_index: int, action: ActionDescriptor) -> GateResult:
    if gate.trigger != _PHASE:
        return GateResult(
            gate_name=gate.name,
            status="SKIP",
            reason="",
            action_on_fail=gate.action_on_fail,
        )
    if gate.applies_to is not None and action.risk_tier not in gate.applies_to:
        return GateResult(
            gate_name=gate.name,
            status="SKIP",
            reason="",
            action_on_fail=gate.action_on_fail,
        )

    try:
        fired = _evaluate_conditions(gate.conditions, action)
    except GateEvaluationError as exc:
        return GateResult(
            gate_name=gate.name,
            status="ERROR",
            reason=(
                f"gate '{gate.name}' (index {gate_index}) errored: "
                f"[{exc.code}] at '{exc.path}'"
            ),
            action_on_fail=gate.action_on_fail,
        )

    if not fired:
        return GateResult(
            gate_name=gate.name,
            status="PASS",
            reason="",
            action_on_fail=gate.action_on_fail,
        )

    if gate.action_on_fail == "BLOCK":
        status = "FAIL"
    elif gate.action_on_fail == "WARN":
        status = "WARN"
    elif gate.action_on_fail == "LOG":
        status = "PASS"
    else:
        return GateResult(
            gate_name=gate.name,
            status="ERROR",
            reason=(
                f"gate '{gate.name}' (index {gate_index}) errored: "
                f"[{GateEvaluationError.UNSUPPORTED_OPERATOR}] "
                f"at 'action_on_fail={gate.action_on_fail!r}'"
            ),
            action_on_fail=gate.action_on_fail,
        )

    reason = f"gate '{gate.name}' (index {gate_index}) fired"
    return GateResult(
        gate_name=gate.name,
        status=status,
        reason=reason,
        action_on_fail=gate.action_on_fail,
    )


def _evaluate_conditions(conditions: tuple, action: ActionDescriptor) -> bool:
    if not conditions:
        return False
    for sib_idx, sib in enumerate(conditions):
        if isinstance(sib, AnyOf):
            if not _evaluate_any_of(sib, action):
                return False
        elif isinstance(sib, Condition):
            if not _evaluate_condition(sib, action):
                return False
        else:
            raise GateEvaluationError(
                GateEvaluationError.UNKNOWN_CONDITION_TYPE,
                path=f"conditions[{sib_idx}]",
                message=f"unsupported condition node type: {type(sib).__name__}",
            )
    return True


def _evaluate_any_of(any_of: AnyOf, action: ActionDescriptor) -> bool:
    if not any_of.any_of:
        return False
    for inner in any_of.any_of:
        if _evaluate_condition(inner, action):
            return True
    return False


def _evaluate_condition(cond: Condition, action: ActionDescriptor) -> bool:
    field_value = resolve_field(action, cond.field)
    ref_value = _resolve_ref_value(cond, action)

    ctype = cond.type
    op = cond.operator

    if ctype == "threshold":
        if op not in _THRESHOLD_OPERATORS:
            raise GateEvaluationError(
                GateEvaluationError.UNSUPPORTED_OPERATOR,
                path=f"{cond.field}",
                message=f"threshold operator {op!r} not supported",
            )
        return _eval_threshold(cond.field, op, field_value, ref_value)

    if ctype == "regex":
        if op not in _REGEX_OPERATORS:
            raise GateEvaluationError(
                GateEvaluationError.UNSUPPORTED_OPERATOR,
                path=f"{cond.field}",
                message=f"regex operator {op!r} not supported",
            )
        return _eval_regex(cond.field, op, field_value, ref_value)

    if ctype in ("allowlist", "denylist"):
        if op not in _LISTMATCH_OPERATORS:
            raise GateEvaluationError(
                GateEvaluationError.UNSUPPORTED_OPERATOR,
                path=f"{cond.field}",
                message=f"{ctype} operator {op!r} not supported",
            )
        return _eval_listmatch(cond.field, op, field_value, ref_value)

    if ctype == "custom":
        if op not in _CUSTOM_OPERATORS:
            raise GateEvaluationError(
                GateEvaluationError.UNSUPPORTED_OPERATOR,
                path=f"{cond.field}",
                message=f"custom operator {op!r} not supported",
            )
        return _eval_custom(cond.field, op, field_value, ref_value)

    raise GateEvaluationError(
        GateEvaluationError.UNKNOWN_CONDITION_TYPE,
        path=f"{cond.field}",
        message=f"unknown condition type: {ctype!r}",
    )


def _resolve_ref_value(cond: Condition, action: ActionDescriptor) -> Any:
    if cond.value is not _MISSING:
        return cond.value
    if cond.value_from is not _MISSING:
        if not isinstance(cond.value_from, str):
            raise GateEvaluationError(
                GateEvaluationError.VALUE_TYPE_MISMATCH,
                path=f"{cond.field}",
                message="value_from must be a string field path",
            )
        resolved = resolve_field(action, cond.value_from)
        if resolved is _NOT_FOUND:
            raise GateEvaluationError(
                GateEvaluationError.FIELD_RESOLUTION_ERROR,
                path=cond.value_from,
                message="value_from field path did not resolve",
            )
        return resolved
    return _MISSING


def _eval_threshold(field: str, op: str, field_value: Any, ref_value: Any) -> bool:
    if field_value is _NOT_FOUND:
        raise GateEvaluationError(
            GateEvaluationError.FIELD_RESOLUTION_ERROR,
            path=field,
            message="threshold field did not resolve",
        )
    if ref_value is _MISSING:
        raise GateEvaluationError(
            GateEvaluationError.VALUE_TYPE_MISMATCH,
            path=field,
            message="threshold condition requires a reference value",
        )

    a: Any
    b: Any
    if isinstance(field_value, str) or isinstance(ref_value, str):
        if not isinstance(field_value, str) or not isinstance(ref_value, str):
            raise GateEvaluationError(
                GateEvaluationError.TIER_COMPARE_ERROR,
                path=field,
                message="threshold mixed tier and non-string operand",
            )
        if field_value not in _TIER_ORDER or ref_value not in _TIER_ORDER:
            raise GateEvaluationError(
                GateEvaluationError.TIER_COMPARE_ERROR,
                path=field,
                message=(
                    "threshold tier comparison requires both operands to be "
                    "T0..T4 strings"
                ),
            )
        a = _TIER_ORDER[field_value]
        b = _TIER_ORDER[ref_value]
    else:
        if isinstance(field_value, bool) or isinstance(ref_value, bool):
            raise GateEvaluationError(
                GateEvaluationError.VALUE_TYPE_MISMATCH,
                path=field,
                message="threshold operands must be numeric, not boolean",
            )
        if not isinstance(field_value, (int, float)) or not isinstance(
            ref_value, (int, float)
        ):
            raise GateEvaluationError(
                GateEvaluationError.VALUE_TYPE_MISMATCH,
                path=field,
                message="threshold operands must be numeric or both T0..T4",
            )
        a = field_value
        b = ref_value

    if op == ">=":
        return a >= b
    if op == ">":
        return a > b
    if op == "<=":
        return a <= b
    if op == "<":
        return a < b
    if op == "==":
        return a == b
    if op == "!=":
        return a != b
    raise GateEvaluationError(
        GateEvaluationError.UNSUPPORTED_OPERATOR,
        path=field,
        message=f"threshold operator {op!r} not supported",
    )


def _eval_regex(field: str, op: str, field_value: Any, ref_value: Any) -> bool:
    if field_value is _NOT_FOUND:
        raise GateEvaluationError(
            GateEvaluationError.FIELD_RESOLUTION_ERROR,
            path=field,
            message="regex field did not resolve",
        )
    if not isinstance(field_value, str):
        raise GateEvaluationError(
            GateEvaluationError.VALUE_TYPE_MISMATCH,
            path=field,
            message="regex requires a string field",
        )
    if not isinstance(ref_value, str):
        raise GateEvaluationError(
            GateEvaluationError.VALUE_TYPE_MISMATCH,
            path=field,
            message="regex requires a string reference value",
        )
    pattern = _compile_regex(ref_value)
    matched = pattern.search(field_value) is not None
    if op == "matches":
        return matched
    return not matched


def _eval_listmatch(field: str, op: str, field_value: Any, ref_value: Any) -> bool:
    if field_value is _NOT_FOUND:
        raise GateEvaluationError(
            GateEvaluationError.FIELD_RESOLUTION_ERROR,
            path=field,
            message=f"{op} field did not resolve",
        )
    if not isinstance(ref_value, (list, tuple)):
        raise GateEvaluationError(
            GateEvaluationError.VALUE_TYPE_MISMATCH,
            path=field,
            message=f"{op} reference value must be a list or tuple",
        )
    if op == "in":
        return field_value in ref_value
    return field_value not in ref_value


def _eval_custom(field: str, op: str, field_value: Any, ref_value: Any) -> bool:
    if op == "is_null":
        if field_value is _NOT_FOUND:
            raise GateEvaluationError(
                GateEvaluationError.FIELD_RESOLUTION_ERROR,
                path=field,
                message="is_null requires the field path to resolve",
            )
        return field_value is None
    if op == "is_not_null":
        if field_value is _NOT_FOUND:
            raise GateEvaluationError(
                GateEvaluationError.FIELD_RESOLUTION_ERROR,
                path=field,
                message="is_not_null requires the field path to resolve",
            )
        return field_value is not None
    if op == "exists":
        return field_value is not _NOT_FOUND
    if op == "contains":
        if field_value is _NOT_FOUND:
            raise GateEvaluationError(
                GateEvaluationError.FIELD_RESOLUTION_ERROR,
                path=field,
                message="contains field did not resolve",
            )
        if isinstance(field_value, str):
            if not isinstance(ref_value, str):
                raise GateEvaluationError(
                    GateEvaluationError.VALUE_TYPE_MISMATCH,
                    path=field,
                    message="contains on a string requires a string value",
                )
            return ref_value in field_value
        if isinstance(field_value, (list, tuple)):
            return ref_value in field_value
        if isinstance(field_value, _Mapping):
            return ref_value in field_value
        raise GateEvaluationError(
            GateEvaluationError.VALUE_TYPE_MISMATCH,
            path=field,
            message="contains requires a string, list, tuple, or mapping field",
        )
    raise GateEvaluationError(
        GateEvaluationError.UNSUPPORTED_OPERATOR,
        path=field,
        message=f"custom operator {op!r} not supported",
    )
