"""Tests for ActionDescriptor, validate_action, resolve_field."""

from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType

import pytest

from latchpoint_core.action_model import (
    ACTION_ERROR_CATEGORIES,
    RISK_TIERS,
    ActionDescriptor,
    ActionError,
    _NOT_FOUND,
    _TIER_ORDER,
    resolve_field,
    validate_action,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "actions"


def _load(name: str) -> dict:
    with (FIXTURES / name).open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_validate_minimal_action_returns_frozen_descriptor():
    action = validate_action(_load("minimal_action.json"))
    assert isinstance(action, ActionDescriptor)
    assert action.id == "00000000-0000-4000-8000-000000000001"
    assert action.type == "file.read"
    assert action.risk_tier == "T1"
    assert action.reversibility is True
    assert isinstance(action.inputs, MappingProxyType)


def test_validate_high_risk_and_escalation_actions():
    high = validate_action(_load("high_risk_action.json"))
    esc = validate_action(_load("escalation_action.json"))
    assert high.risk_tier == "T3"
    assert esc.risk_tier == "T4"


def test_validate_action_rejects_missing_required_fields():
    bad = {"id": "x"}
    with pytest.raises(ActionError) as ei:
        validate_action(bad)
    codes = [e.code for e in ei.value.errors]
    assert "schema_violation" in codes


def test_validate_action_rejects_bad_tier():
    raw = _load("minimal_action.json")
    raw["risk_tier"] = "T7"
    with pytest.raises(ActionError) as ei:
        validate_action(raw)
    assert any(e.code == "tier_violation" for e in ei.value.errors)


def test_validate_action_rejects_unknown_field():
    raw = _load("minimal_action.json")
    raw["surprise"] = 1
    with pytest.raises(ActionError) as ei:
        validate_action(raw)
    assert any(e.code == "unknown_field" for e in ei.value.errors)


def test_validate_action_freezes_inputs_against_mutation():
    action = validate_action(_load("minimal_action.json"))
    assert action.inputs is not None
    with pytest.raises(TypeError):
        action.inputs["path"] = "tampered"  # type: ignore[index]


def test_resolve_field_walks_dot_paths():
    action = validate_action(_load("high_risk_action.json"))
    assert resolve_field(action, "risk_tier") == "T3"
    assert resolve_field(action, "inputs.amount") == 5000
    assert resolve_field(action, "inputs.target_kind") == "filesystem.write"


def test_resolve_field_returns_not_found_on_missing_segment():
    action = validate_action(_load("minimal_action.json"))
    assert resolve_field(action, "inputs.missing") is _NOT_FOUND
    assert resolve_field(action, "metadata.anything") is _NOT_FOUND
    assert resolve_field(action, "nonexistent") is _NOT_FOUND
    assert resolve_field(action, "") is _NOT_FOUND


def test_action_error_categories_and_tier_order_match_spec():
    assert ACTION_ERROR_CATEGORIES == (
        "malformed_action",
        "schema_violation",
        "unknown_field",
        "tier_violation",
    )
    assert RISK_TIERS == ("T0", "T1", "T2", "T3", "T4")
    assert _TIER_ORDER["T0"] == 0
    assert _TIER_ORDER["T4"] == 4
