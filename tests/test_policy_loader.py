"""Tests for the policy loader, validator, and canonical JSON serialiser."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
import yaml

from latchpoint_core import (
    ERROR_CATEGORIES,
    AnyOf,
    Condition,
    Gate,
    Policy,
    PolicyError,
    ValidationResult,
    collect_errors,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "policies"
SRC = Path(__file__).resolve().parent.parent / "src" / "latchpoint_core"


def _err_codes(exc: PolicyError) -> list[str]:
    if exc.errors:
        return [e.code for e in exc.errors]
    return [exc.code]


def _err_paths(exc: PolicyError) -> list[str]:
    if exc.errors:
        return [e.path for e in exc.errors]
    return [exc.path]


def test_valid_minimal_loads():
    p = Policy.load(FIXTURES / "valid_minimal.yaml")
    assert p.name == "minimal_pack"
    assert p.version == "0.1.0"
    assert len(p.gates) == 1
    g = p.gates[0]
    assert g.name == "log_only_gate"
    assert g.trigger == "post_execution"
    assert g.action_on_fail == "BLOCK"
    assert g.conditions == ()
    assert g.applies_to is None
    assert g.override is False


def test_valid_with_conditions_loads():
    p = Policy.load(FIXTURES / "valid_with_conditions.yaml")
    assert p.name == "conditions_pack"
    assert p.version == "1.2.0"
    assert p.description == "Covers threshold, allowlist, custom, and any_of."
    assert len(p.gates) == 2

    high_risk = p.gates[0]
    assert high_risk.name == "high_risk_block"
    assert high_risk.applies_to == ("T3", "T4")
    assert len(high_risk.conditions) == 2
    threshold_cond = high_risk.conditions[0]
    assert isinstance(threshold_cond, Condition)
    assert threshold_cond.type == "threshold"
    assert threshold_cond.operator == ">="
    assert threshold_cond.value == "T3"
    any_of = high_risk.conditions[1]
    assert isinstance(any_of, AnyOf)
    assert len(any_of.any_of) == 2
    assert any_of.any_of[0].type == "allowlist"
    assert any_of.any_of[1].type == "custom"

    assert p.risk_tier_overrides is not None
    assert "T3" in p.risk_tier_overrides
    assert p.escalation_rules is not None
    assert p.metadata is not None


def test_missing_required_field_fails_closed():
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(FIXTURES / "invalid_missing_policy_id.yaml")
    err = exc_info.value
    codes = _err_codes(err)
    paths = _err_paths(err)
    assert PolicyError.SCHEMA_VIOLATION in codes
    assert "name" in paths


def test_unknown_top_level_field_fails_closed():
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(FIXTURES / "invalid_unknown_top_level.yaml")
    err = exc_info.value
    assert PolicyError.UNKNOWN_FIELD in _err_codes(err)
    assert "note" in _err_paths(err)


def test_duplicate_gate_id_fails_closed():
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(FIXTURES / "invalid_duplicate_gate_id.yaml")
    err = exc_info.value
    codes = _err_codes(err)
    paths = _err_paths(err)
    assert PolicyError.SCHEMA_VIOLATION in codes
    assert any("name" in p and "gates[1]" in p for p in paths)


def test_invalid_gate_shape_fails_closed_enum_violation(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "name: bad_pack\n"
        'version: "0.1.0"\n'
        "gates:\n"
        "  - name: broken_gate\n"
        "    trigger: never_execution\n"
        "    conditions: []\n"
    )
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(bad)
    assert PolicyError.ENUM_VIOLATION in _err_codes(exc_info.value)


def test_invalid_condition_shape_fails_closed_mutual_exclusion(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "name: mutex_pack\n"
        'version: "0.1.0"\n'
        "gates:\n"
        "  - name: mutex_gate\n"
        "    trigger: pre_execution\n"
        "    conditions:\n"
        "      - type: threshold\n"
        "        field: risk_tier\n"
        '        operator: ">="\n'
        "        value: T2\n"
        "        value_from: inputs.tier\n"
    )
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(bad)
    assert PolicyError.MUTUAL_EXCLUSION_VIOLATION in _err_codes(exc_info.value)


def test_validate_and_load_equivalent():
    path = FIXTURES / "valid_with_conditions.yaml"
    p_loaded = Policy.load(path)
    raw = yaml.safe_load(path.read_text())
    p_validated = Policy.validate(raw)
    assert p_loaded.to_canonical_json() == p_validated.to_canonical_json()


def test_canonical_json_stable_across_calls():
    p = Policy.load(FIXTURES / "valid_with_conditions.yaml")
    j1 = p.to_canonical_json()
    j2 = p.to_canonical_json()
    assert j1 == j2


def test_canonical_json_byte_identical_round_trip():
    import json

    p = Policy.load(FIXTURES / "valid_with_conditions.yaml")
    a = p.to_canonical_json()
    reparsed = json.loads(a)
    p2 = Policy.validate(reparsed)
    b = p2.to_canonical_json()
    assert a == b
    assert isinstance(a, str)
    assert "\n" not in a


def test_round_trip_minimal_policy():
    import json

    p = Policy.load(FIXTURES / "valid_minimal.yaml")
    a = p.to_canonical_json()
    p2 = Policy.validate(json.loads(a))
    assert a == p2.to_canonical_json()


def test_error_category_strings_stable():
    assert ERROR_CATEGORIES == (
        "parse_error",
        "schema_violation",
        "regex_violation",
        "enum_violation",
        "mutual_exclusion_violation",
        "unknown_field",
    )
    assert PolicyError.PARSE_ERROR == "parse_error"
    assert PolicyError.SCHEMA_VIOLATION == "schema_violation"
    assert PolicyError.REGEX_VIOLATION == "regex_violation"
    assert PolicyError.ENUM_VIOLATION == "enum_violation"
    assert PolicyError.MUTUAL_EXCLUSION_VIOLATION == "mutual_exclusion_violation"
    assert PolicyError.UNKNOWN_FIELD == "unknown_field"


_FORBIDDEN_TOP_LEVEL_MODULES = frozenset(
    {
        "os",
        "time",
        "random",
        "socket",
        "urllib",
        "requests",
        "subprocess",
        "datetime",
        "secrets",
        "http",
        "asyncio",
    }
)


def _imports_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod:
                found.add(mod.split(".")[0])
    return found


def test_no_forbidden_imports_in_implementation():
    for fname in ("policy_model.py", "policy_loader.py", "__init__.py"):
        imports = _imports_in(SRC / fname)
        bad = imports & _FORBIDDEN_TOP_LEVEL_MODULES
        assert not bad, f"{fname} contains forbidden imports: {sorted(bad)}"


def test_no_sibling_repo_imports():
    forbidden = {"latchpoint_" "app", "latchpoint_" "governance", "latchpoint"}
    for fname in ("policy_model.py", "policy_loader.py", "__init__.py"):
        imports = _imports_in(SRC / fname)
        bad = imports & forbidden
        assert not bad, f"{fname} imports from sibling repo namespace: {sorted(bad)}"


def test_policy_error_path_locator(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "name: locator_pack\n"
        'version: "0.1.0"\n'
        "gates:\n"
        "  - name: ok_gate\n"
        "    trigger: pre_execution\n"
        "    conditions: []\n"
        "  - name: locator_gate\n"
        "    trigger: pre_execution\n"
        "    conditions:\n"
        "      - type: threshold\n"
        "        field: risk_tier\n"
        '        operator: "INVALID"\n'
        "        value: T2\n"
    )
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(bad)
    err = exc_info.value
    paths = _err_paths(err)
    assert any(p == "gates[1].conditions[0].operator" for p in paths), (
        f"expected exact path locator, got {paths}"
    )


def test_collect_errors_returns_validation_result():
    raw = yaml.safe_load((FIXTURES / "invalid_unknown_top_level.yaml").read_text())
    result = collect_errors(raw)
    assert isinstance(result, ValidationResult)
    assert result.ok is False
    assert any(e.code == PolicyError.UNKNOWN_FIELD for e in result.errors)


def test_collect_errors_ok_on_valid():
    raw = yaml.safe_load((FIXTURES / "valid_minimal.yaml").read_text())
    result = collect_errors(raw)
    assert result.ok is True
    assert result.errors == ()


def test_parse_error_on_malformed_yaml(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text('name: "unterminated\n')
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(bad)
    assert exc_info.value.code == PolicyError.PARSE_ERROR


def test_parse_error_on_duplicate_top_level_key(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text('name: dup1\nname: dup2\nversion: "0.1.0"\ngates: []\n')
    with pytest.raises(PolicyError) as exc_info:
        Policy.load(bad)
    assert exc_info.value.code == PolicyError.PARSE_ERROR


def test_canonical_json_sort_keys_and_separators():
    import json

    p = Policy.load(FIXTURES / "valid_with_conditions.yaml")
    out = p.to_canonical_json()
    re_emitted = json.dumps(
        json.loads(out),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    assert out == re_emitted
    assert not out.endswith("\n")
    assert not out.startswith("﻿")


def test_canonical_json_applies_to_sorted():
    p = Policy.load(FIXTURES / "valid_with_conditions.yaml")
    out = p.to_canonical_json()
    assert '"applies_to":["T3","T4"]' in out


def test_policy_error_invalid_code_rejected():
    with pytest.raises(ValueError):
        PolicyError("not_a_real_code", "x", "y")


def test_policy_frozen_immutable():
    p = Policy.load(FIXTURES / "valid_minimal.yaml")
    with pytest.raises(Exception):
        p.name = "mutated"  # type: ignore[misc]


def test_gate_frozen_immutable():
    p = Policy.load(FIXTURES / "valid_minimal.yaml")
    g = p.gates[0]
    assert isinstance(g, Gate)
    with pytest.raises(Exception):
        g.name = "mutated"  # type: ignore[misc]
