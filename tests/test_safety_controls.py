"""Tests for the safety-controls primitive.

Covers the kill-switch mapping, the structured override evaluator
(applicable plus four named rejection outcomes plus structurally
malformed exception path), the promotion / demotion classifier
(positive promotion, valid demotion, forbidden self-transition,
unknown stage), determinism across repeated calls, frozen-result
mutation rejection, structured-error category completeness, and
hygiene boundaries (no clock / random / filesystem / network
dependencies in the implementation source).
"""

from __future__ import annotations

import dataclasses
import importlib

import pytest

from latchpoint_core.safety_controls import (
    KILL_SWITCH_OUTCOMES,
    KILL_SWITCH_STATES,
    OVERRIDE_OUTCOMES,
    PROMOTION_STAGES,
    PROMOTION_TRANSITION_KINDS,
    SAFETY_ERROR_CATEGORIES,
    KillSwitchResult,
    OverrideContext,
    OverrideDecision,
    OverrideResult,
    PromotionDecision,
    PromotionResult,
    SafetyControlError,
    classify_promotion_demotion,
    evaluate_kill_switch,
    evaluate_override,
)

OVERRIDE_ID = "ov-1"
ACTION_ID = "act-1"
OTHER_ACTION_ID = "act-2"
NOW_T0 = 1_000
NOT_AFTER_FUTURE = 2_000
NOT_AFTER_PAST = 500


def _valid_decision() -> OverrideDecision:
    return OverrideDecision(
        override_id=OVERRIDE_ID,
        applies_to_action_id=ACTION_ID,
        not_after=NOT_AFTER_FUTURE,
        consumed=False,
    )


def _valid_context() -> OverrideContext:
    return OverrideContext(action_id=ACTION_ID, now=NOW_T0)


def test_kill_switch_active_fail_closed() -> None:
    result = evaluate_kill_switch("ACTIVE")
    assert isinstance(result, KillSwitchResult)
    assert result.outcome == "fail_closed"
    assert result.reason == "active_engaged"


def test_kill_switch_inactive_permits() -> None:
    result = evaluate_kill_switch("INACTIVE")
    assert isinstance(result, KillSwitchResult)
    assert result.outcome == "permit"
    assert result.reason == "inactive_permits_continuation"


@pytest.mark.parametrize(
    "bad_state",
    ["", "active", "Inactive", "KILLED", "ACTIVE ", 0, None, b"ACTIVE"],
)
def test_kill_switch_malformed_raises_structured_error(bad_state: object) -> None:
    with pytest.raises(SafetyControlError) as exc_info:
        evaluate_kill_switch(bad_state)
    assert exc_info.value.code == SafetyControlError.KILL_SWITCH_MALFORMED
    assert exc_info.value.path == "state"


def test_override_applicable() -> None:
    result = evaluate_override(_valid_decision(), _valid_context())
    assert isinstance(result, OverrideResult)
    assert result.outcome == "applicable"
    assert result.reason == "all_checks_passed"


def test_override_rejected_expired() -> None:
    decision = dataclasses.replace(_valid_decision(), not_after=NOT_AFTER_PAST)
    result = evaluate_override(decision, _valid_context())
    assert result.outcome == "rejected_expired"
    assert result.reason == "now_after_not_after"


def test_override_rejected_already_consumed() -> None:
    decision = dataclasses.replace(_valid_decision(), consumed=True)
    result = evaluate_override(decision, _valid_context())
    assert result.outcome == "rejected_already_consumed"
    assert result.reason == "consumed_flag_true"


def test_override_rejected_non_applicable() -> None:
    context = dataclasses.replace(_valid_context(), action_id=OTHER_ACTION_ID)
    result = evaluate_override(_valid_decision(), context)
    assert result.outcome == "rejected_non_applicable"
    assert result.reason == "action_id_mismatch"


def test_override_rejected_structurally_invalid_empty_override_id() -> None:
    decision = dataclasses.replace(_valid_decision(), override_id="")
    result = evaluate_override(decision, _valid_context())
    assert result.outcome == "rejected_structurally_invalid"
    assert result.reason == "empty_override_id"


def test_override_rejected_structurally_invalid_empty_applies_to() -> None:
    decision = dataclasses.replace(_valid_decision(), applies_to_action_id="")
    result = evaluate_override(decision, _valid_context())
    assert result.outcome == "rejected_structurally_invalid"
    assert result.reason == "empty_applies_to_action_id"


@pytest.mark.parametrize(
    "field, bad_value",
    [
        ("override_id", 42),
        ("override_id", None),
        ("override_id", b"o-1"),
        ("applies_to_action_id", 7),
        ("applies_to_action_id", None),
        ("not_after", "not-an-int"),
        ("not_after", None),
        ("not_after", True),
        ("consumed", 0),
        ("consumed", "false"),
        ("consumed", None),
    ],
)
def test_override_malformed_decision_field_raises(
    field: str, bad_value: object
) -> None:
    base: dict[str, object] = dict(
        override_id=OVERRIDE_ID,
        applies_to_action_id=ACTION_ID,
        not_after=NOT_AFTER_FUTURE,
        consumed=False,
    )
    base[field] = bad_value
    decision = OverrideDecision(**base)  # type: ignore[arg-type]
    with pytest.raises(SafetyControlError) as exc_info:
        evaluate_override(decision, _valid_context())
    assert exc_info.value.code == SafetyControlError.OVERRIDE_MALFORMED
    assert exc_info.value.path == f"decision.{field}"


@pytest.mark.parametrize(
    "field, bad_value",
    [
        ("action_id", 42),
        ("action_id", None),
        ("now", "1000"),
        ("now", None),
        ("now", True),
    ],
)
def test_override_malformed_context_field_raises(field: str, bad_value: object) -> None:
    base: dict[str, object] = dict(action_id=ACTION_ID, now=NOW_T0)
    base[field] = bad_value
    context = OverrideContext(**base)  # type: ignore[arg-type]
    with pytest.raises(SafetyControlError) as exc_info:
        evaluate_override(_valid_decision(), context)
    assert exc_info.value.code == SafetyControlError.OVERRIDE_MALFORMED
    assert exc_info.value.path == f"context.{field}"


def test_override_malformed_when_decision_is_wrong_type() -> None:
    with pytest.raises(SafetyControlError) as exc_info:
        evaluate_override("not-a-decision", _valid_context())  # type: ignore[arg-type]
    assert exc_info.value.code == SafetyControlError.OVERRIDE_MALFORMED
    assert exc_info.value.path == "decision"


def test_override_malformed_when_context_is_wrong_type() -> None:
    with pytest.raises(SafetyControlError) as exc_info:
        evaluate_override(_valid_decision(), "not-a-context")  # type: ignore[arg-type]
    assert exc_info.value.code == SafetyControlError.OVERRIDE_MALFORMED
    assert exc_info.value.path == "context"


def test_override_does_not_mutate_decision() -> None:
    decision = _valid_decision()
    snapshot = dataclasses.replace(decision)
    evaluate_override(decision, _valid_context())
    evaluate_override(decision, _valid_context())
    assert decision == snapshot


def test_promotion_dev_to_shadow_is_promotion() -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage="DEV", to_stage="SHADOW")
    )
    assert isinstance(result, PromotionResult)
    assert result.kind == "promotion"
    assert result.valid is True
    assert result.reason == "adjacent_forward"


def test_promotion_shadow_to_canary_is_promotion() -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage="SHADOW", to_stage="CANARY")
    )
    assert result.kind == "promotion"
    assert result.valid is True


def test_promotion_dev_to_canary_is_invalid_non_adjacent() -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage="DEV", to_stage="CANARY")
    )
    assert result.kind == "invalid_stage"
    assert result.valid is False
    assert result.reason == "non_adjacent_promotion"


def test_demotion_live_to_dev_allowed() -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage="LIVE", to_stage="DEV")
    )
    assert result.kind == "demotion"
    assert result.valid is True
    assert result.reason == "any_lower_stage_allowed"


def test_demotion_canary_to_shadow_allowed() -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage="CANARY", to_stage="SHADOW")
    )
    assert result.kind == "demotion"
    assert result.valid is True


def test_promotion_self_transition_forbidden() -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage="SHADOW", to_stage="SHADOW")
    )
    assert result.kind == "self_transition"
    assert result.valid is False
    assert result.reason == "self_transition_forbidden"


@pytest.mark.parametrize(
    "from_stage, to_stage, expected_reason",
    [
        ("FOO", "DEV", "from_stage_unknown"),
        ("DEV", "BAR", "to_stage_unknown"),
        ("", "DEV", "from_stage_unknown"),
        ("dev", "shadow", "from_stage_unknown"),
    ],
)
def test_promotion_unknown_stage_invalid(
    from_stage: str, to_stage: str, expected_reason: str
) -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage=from_stage, to_stage=to_stage)
    )
    assert result.kind == "invalid_stage"
    assert result.valid is False
    assert result.reason == expected_reason


def test_promotion_non_promotion_decision_object_returns_invalid_stage() -> None:
    result = classify_promotion_demotion("not-a-decision")  # type: ignore[arg-type]
    assert result.kind == "invalid_stage"
    assert result.valid is False
    assert result.reason == "decision_not_promotion_decision"


def test_determinism_kill_switch_repeated_calls_are_equal() -> None:
    a = evaluate_kill_switch("INACTIVE")
    b = evaluate_kill_switch("INACTIVE")
    c = evaluate_kill_switch("ACTIVE")
    d = evaluate_kill_switch("ACTIVE")
    assert a == b
    assert c == d


def test_determinism_override_repeated_calls_are_equal() -> None:
    a = evaluate_override(_valid_decision(), _valid_context())
    b = evaluate_override(_valid_decision(), _valid_context())
    assert a == b


def test_determinism_promotion_repeated_calls_are_equal() -> None:
    decision = PromotionDecision(from_stage="DEV", to_stage="SHADOW")
    a = classify_promotion_demotion(decision)
    b = classify_promotion_demotion(decision)
    assert a == b


def test_kill_switch_result_is_frozen() -> None:
    result = evaluate_kill_switch("INACTIVE")
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.outcome = "fail_closed"  # type: ignore[misc]


def test_override_result_is_frozen() -> None:
    result = evaluate_override(_valid_decision(), _valid_context())
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.outcome = "rejected_expired"  # type: ignore[misc]


def test_promotion_result_is_frozen() -> None:
    result = classify_promotion_demotion(
        PromotionDecision(from_stage="DEV", to_stage="SHADOW")
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.kind = "demotion"  # type: ignore[misc]


def test_override_decision_is_frozen() -> None:
    decision = _valid_decision()
    with pytest.raises(dataclasses.FrozenInstanceError):
        decision.consumed = True  # type: ignore[misc]


def test_safety_error_categories_are_complete_and_unique() -> None:
    assert set(SAFETY_ERROR_CATEGORIES) == {
        SafetyControlError.KILL_SWITCH_MALFORMED,
        SafetyControlError.OVERRIDE_MALFORMED,
    }
    assert len(SAFETY_ERROR_CATEGORIES) == len(set(SAFETY_ERROR_CATEGORIES))


def test_kill_switch_alphabets_are_unique() -> None:
    assert len(KILL_SWITCH_STATES) == len(set(KILL_SWITCH_STATES))
    assert len(KILL_SWITCH_OUTCOMES) == len(set(KILL_SWITCH_OUTCOMES))


def test_override_outcomes_are_unique() -> None:
    assert len(OVERRIDE_OUTCOMES) == len(set(OVERRIDE_OUTCOMES))


def test_promotion_alphabets_are_unique() -> None:
    assert len(PROMOTION_STAGES) == len(set(PROMOTION_STAGES))
    assert len(PROMOTION_TRANSITION_KINDS) == len(set(PROMOTION_TRANSITION_KINDS))


def test_safety_control_error_rejects_unknown_code() -> None:
    with pytest.raises(ValueError):
        SafetyControlError("not_a_real_code")


def test_safety_controls_module_has_no_clock_or_random_or_io_imports() -> None:
    safety_module = importlib.import_module("latchpoint_core.safety_controls")
    forbidden_attrs = {
        "time",
        "datetime",
        "random",
        "uuid",
        "os",
        "subprocess",
        "socket",
        "pathlib",
        "urllib",
        "http",
    }
    leaked = forbidden_attrs & set(vars(safety_module))
    assert not leaked, (
        f"safety_controls module imports forbidden runtime modules: {leaked}"
    )
