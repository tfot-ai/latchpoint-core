"""Tests for the adapter Protocol and synthetic reference adapter.

Covers Protocol conformance, deterministic translation of a caller-
supplied payload into an ActionDescriptor, fail-closed handling of
malformed and unsupported inputs, and preservation of nested validator
error detail.
"""

from __future__ import annotations

import dataclasses
import importlib

import pytest

from latchpoint_core.action_model import ActionDescriptor
from latchpoint_core.adapters import (
    ADAPTER_ERROR_CATEGORIES,
    AdapterError,
    AdapterInput,
    AdapterOutput,
    AdapterProtocol,
    AdapterResult,
    SyntheticAdapter,
    adapt_payload,
)


def _valid_payload() -> dict[str, object]:
    return {
        "id": "act-001",
        "type": "review",
        "target": "object/example",
        "risk_tier": "T1",
        "timestamp": "2026-01-01T00:00:00Z",
        "agent_id": "agent-a",
        "session_id": "session-x",
    }


def _adapt(adapter: SyntheticAdapter, **overrides: object) -> AdapterResult:
    payload = _valid_payload()
    payload.update(overrides)
    return adapter.adapt(AdapterInput(operation="synthetic.echo", payload=payload))


def test_supported_operations_and_name_stable() -> None:
    a = SyntheticAdapter()
    assert a.name == "synthetic"
    assert a.supported_operations == ("synthetic.echo",)


def test_synthetic_adapter_converts_valid_payload() -> None:
    result = _adapt(SyntheticAdapter())
    assert result.ok is True
    assert result.errors == ()
    assert result.output is not None
    action = result.output.action
    assert isinstance(action, ActionDescriptor)
    assert action.id == "act-001"
    assert action.type == "review"
    assert action.target == "object/example"
    assert action.risk_tier == "T1"
    assert action.timestamp == "2026-01-01T00:00:00Z"
    assert action.agent_id == "agent-a"
    assert action.session_id == "session-x"


def test_repeated_adaptation_is_structurally_equal() -> None:
    a = SyntheticAdapter()
    r1 = _adapt(a)
    r2 = _adapt(a)
    assert r1 == r2


def test_action_field_equality_is_byte_stable() -> None:
    a = SyntheticAdapter()
    r1 = _adapt(a)
    r2 = _adapt(a)
    assert r1.output is not None and r2.output is not None
    assert r1.output.action == r2.output.action


def test_missing_required_field_fails_closed() -> None:
    a = SyntheticAdapter()
    payload = _valid_payload()
    del payload["id"]
    result = a.adapt(AdapterInput(operation="synthetic.echo", payload=payload))
    assert result.ok is False
    assert result.output is None
    codes = {e.code for e in result.errors}
    assert AdapterError.DOWNSTREAM_VALIDATION in codes
    assert any(e.path == "id" for e in result.errors)


def test_invalid_field_type_fails_closed() -> None:
    result = _adapt(SyntheticAdapter(), risk_tier=7)
    assert result.ok is False
    assert result.output is None
    assert any(
        e.code == AdapterError.DOWNSTREAM_VALIDATION and e.path == "risk_tier"
        for e in result.errors
    )


def test_unsupported_operation_fails_closed() -> None:
    a = SyntheticAdapter()
    result = a.adapt(
        AdapterInput(operation="vendor.something", payload=_valid_payload())
    )
    assert result.ok is False
    assert result.output is None
    assert len(result.errors) == 1
    assert result.errors[0].code == AdapterError.UNSUPPORTED_OPERATION
    assert result.errors[0].path == "operation"


def test_malformed_inner_payload_fails_closed() -> None:
    a = SyntheticAdapter()
    result = a.adapt(
        AdapterInput(operation="synthetic.echo", payload=["not", "a", "mapping"])  # type: ignore[arg-type]
    )
    assert result.ok is False
    assert result.output is None
    assert len(result.errors) == 1
    assert result.errors[0].code == AdapterError.MALFORMED_PAYLOAD
    assert result.errors[0].path == "payload"


def test_non_adapterinput_argument_fails_closed() -> None:
    a = SyntheticAdapter()
    result = a.adapt({"operation": "synthetic.echo", "payload": _valid_payload()})  # type: ignore[arg-type]
    assert result.ok is False
    assert result.output is None
    assert len(result.errors) == 1
    assert result.errors[0].code == AdapterError.MALFORMED_PAYLOAD


def test_unknown_top_level_field_fails_closed() -> None:
    a = SyntheticAdapter()
    payload = _valid_payload()
    payload["unexpected_extra"] = "x"
    result = a.adapt(AdapterInput(operation="synthetic.echo", payload=payload))
    assert result.ok is False
    assert result.output is None
    codes = {e.code for e in result.errors}
    assert AdapterError.DOWNSTREAM_VALIDATION in codes
    assert any(e.path == "unexpected_extra" for e in result.errors)


def test_adapter_protocol_runtime_checkable() -> None:
    assert isinstance(SyntheticAdapter(), AdapterProtocol)


def test_adapt_payload_dispatches_to_adapter_adapt() -> None:
    a = SyntheticAdapter()
    payload = AdapterInput(operation="synthetic.echo", payload=_valid_payload())
    via_helper = adapt_payload(a, payload)
    via_method = a.adapt(payload)
    assert via_helper == via_method


def test_nested_action_error_details_preserved() -> None:
    a = SyntheticAdapter()
    payload = _valid_payload()
    del payload["id"]
    del payload["type"]
    payload["risk_tier"] = "T9"  # invalid tier
    result = a.adapt(AdapterInput(operation="synthetic.echo", payload=payload))
    assert result.ok is False
    paths = {e.path for e in result.errors}
    assert "id" in paths
    assert "type" in paths
    assert "risk_tier" in paths
    for e in result.errors:
        assert isinstance(e, AdapterError)
        assert e.code == AdapterError.DOWNSTREAM_VALIDATION


def test_adapter_module_has_no_clock_or_random_or_io_imports() -> None:
    adapters_module = importlib.import_module("latchpoint_core.adapters")
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
    leaked = forbidden_attrs & set(vars(adapters_module))
    assert not leaked, f"adapters module imports forbidden runtime modules: {leaked}"


def test_adapter_error_categories_complete_and_unique() -> None:
    assert set(ADAPTER_ERROR_CATEGORIES) == {
        AdapterError.MALFORMED_PAYLOAD,
        AdapterError.SCHEMA_VIOLATION,
        AdapterError.UNSUPPORTED_OPERATION,
        AdapterError.DOWNSTREAM_VALIDATION,
    }
    assert len(ADAPTER_ERROR_CATEGORIES) == len(set(ADAPTER_ERROR_CATEGORIES))


def test_synthetic_adapter_dataclass_is_frozen_and_replaceable() -> None:
    a1 = SyntheticAdapter()
    a2 = SyntheticAdapter()
    assert a1 == a2
    a3 = dataclasses.replace(a1, name="synthetic-alt")
    assert a3.name == "synthetic-alt"
    assert a3.supported_operations == a1.supported_operations
    with pytest.raises(dataclasses.FrozenInstanceError):
        a1.name = "mutated"  # type: ignore[misc]


def test_adapter_input_and_output_are_frozen() -> None:
    inp = AdapterInput(operation="synthetic.echo", payload={})
    with pytest.raises(dataclasses.FrozenInstanceError):
        inp.operation = "mutated"  # type: ignore[misc]
    out = AdapterOutput(
        action=SyntheticAdapter()
        .adapt(AdapterInput(operation="synthetic.echo", payload=_valid_payload()))
        .output.action  # type: ignore[union-attr]
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        out.action = out.action  # type: ignore[misc]
