"""Policy loader, validator, and canonical JSON serialiser.

Loads single-file YAML 1.2 in safe mode, validates against the policy
schema, and emits canonical JSON. Fail-closed on any violation.

No network, no clock, no environment, no randomness.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

import yaml
from yaml.constructor import ConstructorError

from .policy_model import (
    AnyOf,
    Condition,
    Gate,
    Policy,
    PolicyError,
    ValidationResult,
    _MISSING,
)

_POLICY_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_GATE_NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_TIER_KEY_RE = re.compile(r"^T[0-4]$")
_SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)"
    r"(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)

_TRIGGERS = frozenset({"pre_execution", "post_execution", "continuous"})
_ACTIONS = frozenset({"BLOCK", "WARN", "LOG"})
_TIERS = frozenset({"T0", "T1", "T2", "T3", "T4"})

_CONDITION_TYPES = frozenset({"threshold", "regex", "allowlist", "denylist", "custom"})
_OPERATORS_BY_TYPE: dict[str, frozenset[str]] = {
    "threshold": frozenset({">=", ">", "<=", "<", "==", "!="}),
    "regex": frozenset({"matches", "not_matches"}),
    "allowlist": frozenset({"in", "not_in"}),
    "denylist": frozenset({"in", "not_in"}),
    "custom": frozenset({"is_not_null", "is_null", "exists", "contains"}),
}

_TOP_LEVEL_REQUIRED = frozenset({"name", "version", "gates"})
_TOP_LEVEL_OPTIONAL = frozenset(
    {"description", "author", "risk_tier_overrides", "escalation_rules", "metadata"}
)
_TOP_LEVEL_ALLOWED = _TOP_LEVEL_REQUIRED | _TOP_LEVEL_OPTIONAL

_GATE_REQUIRED = frozenset({"name", "trigger", "conditions"})
_GATE_OPTIONAL = frozenset({"action_on_fail", "applies_to", "override"})
_GATE_ALLOWED = _GATE_REQUIRED | _GATE_OPTIONAL

_SIMPLE_CONDITION_REQUIRED = frozenset({"type", "field", "operator"})
_SIMPLE_CONDITION_OPTIONAL = frozenset({"value", "value_from"})
_SIMPLE_CONDITION_ALLOWED = _SIMPLE_CONDITION_REQUIRED | _SIMPLE_CONDITION_OPTIONAL


class _StrictSafeLoader(yaml.SafeLoader):
    pass


def _construct_mapping_strict(
    loader: yaml.SafeLoader, node: yaml.Node, deep: bool = False
) -> dict:
    if not isinstance(node, yaml.MappingNode):
        raise ConstructorError(
            None,
            None,
            f"expected a mapping node, found {type(node).__name__}",
            node.start_mark,
        )
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            hash(key)
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found unhashable key: {exc}",
                key_node.start_mark,
            ) from None
        if key in mapping:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_mapping_strict,
)


def _err(code: str, path: str, message: str) -> PolicyError:
    return PolicyError(code, path, message)


def _freeze_mapping(m: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(m))


def _validate_simple_condition(
    raw: Any, base_path: str, errors: list[PolicyError]
) -> Condition | None:
    if not isinstance(raw, Mapping):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                base_path,
                f"condition must be a mapping, got {type(raw).__name__}",
            )
        )
        return None

    keys = set(raw.keys())
    missing = _SIMPLE_CONDITION_REQUIRED - keys
    for k in sorted(missing):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.{k}",
                f"missing required field {k!r}",
            )
        )
    unknown = keys - _SIMPLE_CONDITION_ALLOWED
    for k in sorted(unknown):
        errors.append(
            _err(
                PolicyError.UNKNOWN_FIELD,
                f"{base_path}.{k}",
                f"unknown field {k!r} at simple condition",
            )
        )
    if missing or unknown:
        return None

    type_v = raw.get("type")
    field_v = raw.get("field")
    op_v = raw.get("operator")

    type_ok = isinstance(type_v, str)
    if not type_ok:
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.type",
                f"type must be a string, got {type(type_v).__name__}",
            )
        )
    elif type_v not in _CONDITION_TYPES:
        errors.append(
            _err(
                PolicyError.ENUM_VIOLATION,
                f"{base_path}.type",
                f"type must be one of {sorted(_CONDITION_TYPES)!r}, got {type_v!r}",
            )
        )
        type_ok = False

    if not isinstance(field_v, str):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.field",
                f"field must be a string, got {type(field_v).__name__}",
            )
        )
        return None

    if not isinstance(op_v, str):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.operator",
                f"operator must be a string, got {type(op_v).__name__}",
            )
        )
        return None

    if type_ok and isinstance(type_v, str):
        allowed = _OPERATORS_BY_TYPE[type_v]
        if op_v not in allowed:
            errors.append(
                _err(
                    PolicyError.ENUM_VIOLATION,
                    f"{base_path}.operator",
                    f"operator {op_v!r} not allowed for type {type_v!r}; "
                    f"allowed: {sorted(allowed)!r}",
                )
            )

    has_value = "value" in raw
    has_value_from = "value_from" in raw
    if has_value and has_value_from:
        errors.append(
            _err(
                PolicyError.MUTUAL_EXCLUSION_VIOLATION,
                base_path,
                "exactly one of 'value' or 'value_from' must be set, both were given",
            )
        )
        return None
    if not has_value and not has_value_from:
        errors.append(
            _err(
                PolicyError.MUTUAL_EXCLUSION_VIOLATION,
                base_path,
                "exactly one of 'value' or 'value_from' must be set, neither was given",
            )
        )
        return None

    vf = raw.get("value_from")
    if has_value_from and not isinstance(vf, str):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.value_from",
                f"value_from must be a string, got {type(vf).__name__}",
            )
        )
        return None

    if not type_ok:
        return None

    assert isinstance(type_v, str)
    if has_value:
        return Condition(
            type=type_v,
            field=field_v,
            operator=op_v,
            value=raw["value"],
        )
    assert isinstance(vf, str)
    return Condition(
        type=type_v,
        field=field_v,
        operator=op_v,
        value_from=vf,
    )


def _validate_condition_entry(
    raw: Any, base_path: str, errors: list[PolicyError]
) -> Condition | AnyOf | None:
    if isinstance(raw, Mapping) and set(raw.keys()) == {"any_of"}:
        any_of_val = raw["any_of"]
        if not isinstance(any_of_val, list) or not any_of_val:
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    f"{base_path}.any_of",
                    "any_of must be a non-empty list of simple conditions",
                )
            )
            return None
        subs: list[Condition] = []
        ok = True
        for j, sub in enumerate(any_of_val):
            sc = _validate_simple_condition(sub, f"{base_path}.any_of[{j}]", errors)
            if sc is None:
                ok = False
            else:
                subs.append(sc)
        if not ok:
            return None
        return AnyOf(any_of=tuple(subs))
    return _validate_simple_condition(raw, base_path, errors)


def _validate_gate(
    raw: Any,
    index: int,
    seen_names: set[str],
    errors: list[PolicyError],
) -> Gate | None:
    base_path = f"gates[{index}]"
    if not isinstance(raw, Mapping):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                base_path,
                f"gate must be a mapping, got {type(raw).__name__}",
            )
        )
        return None

    keys = set(raw.keys())
    missing = _GATE_REQUIRED - keys
    for k in sorted(missing):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.{k}",
                f"missing required field {k!r}",
            )
        )
    unknown = keys - _GATE_ALLOWED
    for k in sorted(unknown):
        errors.append(
            _err(
                PolicyError.UNKNOWN_FIELD,
                f"{base_path}.{k}",
                f"unknown field {k!r} at gate",
            )
        )
    if missing:
        return None

    name_raw = raw.get("name")
    name_ok = isinstance(name_raw, str)
    if not name_ok:
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.name",
                f"gate name must be a string, got {type(name_raw).__name__}",
            )
        )
    else:
        assert isinstance(name_raw, str)
        if not _GATE_NAME_RE.match(name_raw):
            errors.append(
                _err(
                    PolicyError.REGEX_VIOLATION,
                    f"{base_path}.name",
                    f"gate name {name_raw!r} does not match {_GATE_NAME_RE.pattern!r}",
                )
            )
            name_ok = False
        elif name_raw in seen_names:
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    f"{base_path}.name",
                    f"duplicate gate name {name_raw!r} (gate names must be unique within a pack)",
                )
            )
            name_ok = False
        else:
            seen_names.add(name_raw)

    trigger_raw = raw.get("trigger")
    trigger: str | None = None
    if not isinstance(trigger_raw, str):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.trigger",
                f"trigger must be a string, got {type(trigger_raw).__name__}",
            )
        )
    elif trigger_raw not in _TRIGGERS:
        errors.append(
            _err(
                PolicyError.ENUM_VIOLATION,
                f"{base_path}.trigger",
                f"trigger must be one of {sorted(_TRIGGERS)!r}, got {trigger_raw!r}",
            )
        )
    else:
        trigger = trigger_raw

    action_raw = raw.get("action_on_fail", "BLOCK")
    action: str = "BLOCK"
    if not isinstance(action_raw, str):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.action_on_fail",
                f"action_on_fail must be a string, got {type(action_raw).__name__}",
            )
        )
    elif action_raw not in _ACTIONS:
        errors.append(
            _err(
                PolicyError.ENUM_VIOLATION,
                f"{base_path}.action_on_fail",
                f"action_on_fail must be one of {sorted(_ACTIONS)!r}, got {action_raw!r}",
            )
        )
    else:
        action = action_raw

    applies_to: tuple[str, ...] | None = None
    if "applies_to" in raw:
        applies_to_raw = raw["applies_to"]
        if applies_to_raw is None:
            applies_to = None
        elif not isinstance(applies_to_raw, list):
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    f"{base_path}.applies_to",
                    f"applies_to must be a list, got {type(applies_to_raw).__name__}",
                )
            )
        else:
            applies_to_list: list[str] = []
            for j, t in enumerate(applies_to_raw):
                if not isinstance(t, str):
                    errors.append(
                        _err(
                            PolicyError.SCHEMA_VIOLATION,
                            f"{base_path}.applies_to[{j}]",
                            f"tier must be a string, got {type(t).__name__}",
                        )
                    )
                    continue
                if t not in _TIERS:
                    errors.append(
                        _err(
                            PolicyError.ENUM_VIOLATION,
                            f"{base_path}.applies_to[{j}]",
                            f"tier {t!r} not in {sorted(_TIERS)!r}",
                        )
                    )
                    continue
                applies_to_list.append(t)
            applies_to = tuple(applies_to_list)

    override_raw = raw.get("override", False)
    override: bool = False
    if not isinstance(override_raw, bool):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                f"{base_path}.override",
                f"override must be a boolean, got {type(override_raw).__name__}",
            )
        )
    else:
        override = override_raw

    conditions_raw = raw.get("conditions")
    conditions: tuple = ()
    if "conditions" in raw:
        if conditions_raw is None:
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    f"{base_path}.conditions",
                    "conditions must be a list, got null",
                )
            )
        elif not isinstance(conditions_raw, list):
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    f"{base_path}.conditions",
                    f"conditions must be a list, got {type(conditions_raw).__name__}",
                )
            )
        else:
            cond_list: list = []
            for j, cond_raw in enumerate(conditions_raw):
                entry = _validate_condition_entry(
                    cond_raw, f"{base_path}.conditions[{j}]", errors
                )
                if entry is not None:
                    cond_list.append(entry)
            conditions = tuple(cond_list)

    if not name_ok or trigger is None:
        return None

    assert isinstance(name_raw, str)
    return Gate(
        name=name_raw,
        trigger=trigger,
        action_on_fail=action,
        applies_to=applies_to,
        conditions=conditions,
        override=override,
    )


def _validate_optional_str(
    data: Mapping[str, Any], key: str, errors: list[PolicyError]
) -> str | None:
    if key not in data:
        return None
    v = data[key]
    if v is None:
        return None
    if not isinstance(v, str):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                key,
                f"{key} must be a string, got {type(v).__name__}",
            )
        )
        return None
    return v


def _validate_permissive_mapping(
    data: Mapping[str, Any], key: str, errors: list[PolicyError]
) -> Mapping[str, Any] | None:
    if key not in data:
        return None
    v = data[key]
    if v is None:
        return None
    if not isinstance(v, Mapping):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                key,
                f"{key} must be a mapping, got {type(v).__name__}",
            )
        )
        return None
    return _freeze_mapping(v)


def _validate_risk_tier_overrides(
    data: Mapping[str, Any], errors: list[PolicyError]
) -> Mapping[str, Any] | None:
    if "risk_tier_overrides" not in data:
        return None
    v = data["risk_tier_overrides"]
    if v is None:
        return None
    if not isinstance(v, Mapping):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                "risk_tier_overrides",
                f"risk_tier_overrides must be a mapping, got {type(v).__name__}",
            )
        )
        return None
    for k in v:
        if not isinstance(k, str) or not _TIER_KEY_RE.match(k):
            errors.append(
                _err(
                    PolicyError.REGEX_VIOLATION,
                    f"risk_tier_overrides.{k}",
                    f"risk_tier_overrides key {k!r} does not match {_TIER_KEY_RE.pattern!r}",
                )
            )
    return _freeze_mapping(v)


def _validate_top_level(
    data: Mapping[str, Any],
) -> tuple[Policy | None, list[PolicyError]]:
    errors: list[PolicyError] = []

    keys = set(data.keys())
    missing = _TOP_LEVEL_REQUIRED - keys
    for k in sorted(missing):
        errors.append(
            _err(
                PolicyError.SCHEMA_VIOLATION,
                k,
                f"missing required top-level field {k!r}",
            )
        )
    unknown = keys - _TOP_LEVEL_ALLOWED
    for k in sorted(unknown):
        errors.append(
            _err(
                PolicyError.UNKNOWN_FIELD,
                k,
                f"unknown top-level field {k!r}",
            )
        )

    name: str | None = None
    if "name" in data:
        nv = data["name"]
        if not isinstance(nv, str):
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    "name",
                    f"name must be a string, got {type(nv).__name__}",
                )
            )
        elif not _POLICY_NAME_RE.match(nv):
            errors.append(
                _err(
                    PolicyError.REGEX_VIOLATION,
                    "name",
                    f"name {nv!r} does not match {_POLICY_NAME_RE.pattern!r}",
                )
            )
        else:
            name = nv

    version: str | None = None
    if "version" in data:
        vv = data["version"]
        if not isinstance(vv, str):
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    "version",
                    f"version must be a string, got {type(vv).__name__}",
                )
            )
        elif not _SEMVER_RE.match(vv):
            errors.append(
                _err(
                    PolicyError.REGEX_VIOLATION,
                    "version",
                    f"version {vv!r} is not a valid SemVer 2.0.0 string",
                )
            )
        else:
            version = vv

    gates: tuple[Gate, ...] = ()
    gates_present = False
    if "gates" in data:
        gates_raw = data["gates"]
        if not isinstance(gates_raw, list):
            errors.append(
                _err(
                    PolicyError.SCHEMA_VIOLATION,
                    "gates",
                    f"gates must be a list, got {type(gates_raw).__name__}",
                )
            )
        else:
            seen_names: set[str] = set()
            built: list[Gate] = []
            for i, g_raw in enumerate(gates_raw):
                g = _validate_gate(g_raw, i, seen_names, errors)
                if g is not None:
                    built.append(g)
            gates = tuple(built)
            gates_present = True

    description = _validate_optional_str(data, "description", errors)
    author = _validate_optional_str(data, "author", errors)
    risk_tier_overrides = _validate_risk_tier_overrides(data, errors)
    escalation_rules = _validate_permissive_mapping(data, "escalation_rules", errors)
    metadata = _validate_permissive_mapping(data, "metadata", errors)

    if errors:
        return None, errors
    if name is None or version is None or not gates_present:
        return None, errors

    return (
        Policy(
            name=name,
            version=version,
            gates=gates,
            description=description,
            author=author,
            risk_tier_overrides=risk_tier_overrides,
            escalation_rules=escalation_rules,
            metadata=metadata,
        ),
        errors,
    )


def load_policy(path: str | Path) -> Policy:
    p = Path(path)
    if not p.is_file():
        raise PolicyError(
            PolicyError.PARSE_ERROR,
            str(p),
            f"not a regular file: {p}",
        )
    raw = p.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PolicyError(
            PolicyError.PARSE_ERROR,
            str(p),
            f"file is not valid UTF-8: {exc}",
        ) from None
    try:
        data = yaml.load(text, Loader=_StrictSafeLoader)
    except yaml.YAMLError as exc:
        raise PolicyError(
            PolicyError.PARSE_ERROR,
            str(p),
            f"YAML parse error: {exc}",
        ) from None
    if data is None:
        raise PolicyError(
            PolicyError.SCHEMA_VIOLATION,
            "",
            "top-level document is empty",
        )
    if not isinstance(data, Mapping):
        raise PolicyError(
            PolicyError.SCHEMA_VIOLATION,
            "",
            f"top-level must be a mapping, got {type(data).__name__}",
        )
    return validate_policy(data)


def validate_policy(data: Mapping[str, Any]) -> Policy:
    if not isinstance(data, Mapping):
        raise PolicyError(
            PolicyError.SCHEMA_VIOLATION,
            "",
            f"top-level must be a mapping, got {type(data).__name__}",
        )
    policy, errors = _validate_top_level(data)
    if errors:
        first = errors[0]
        raise PolicyError(
            first.code,
            first.path,
            first.message,
            errors=tuple(errors),
        )
    assert policy is not None
    return policy


def collect_errors(data: Mapping[str, Any]) -> ValidationResult:
    if not isinstance(data, Mapping):
        return ValidationResult(
            ok=False,
            errors=(
                PolicyError(
                    PolicyError.SCHEMA_VIOLATION,
                    "",
                    f"top-level must be a mapping, got {type(data).__name__}",
                ),
            ),
        )
    _, errors = _validate_top_level(data)
    return ValidationResult(ok=not errors, errors=tuple(errors))


def _condition_to_plain(c: Condition | AnyOf) -> dict:
    if isinstance(c, AnyOf):
        return {"any_of": [_condition_to_plain(s) for s in c.any_of]}
    out: dict = {
        "type": c.type,
        "field": c.field,
        "operator": c.operator,
    }
    if c.value is not _MISSING:
        out["value"] = c.value
    elif c.value_from is not _MISSING:
        out["value_from"] = c.value_from
    return out


def _gate_to_plain(g: Gate) -> dict:
    out: dict = {
        "name": g.name,
        "trigger": g.trigger,
        "action_on_fail": g.action_on_fail,
        "conditions": [_condition_to_plain(c) for c in g.conditions],
        "override": g.override,
    }
    if g.applies_to is not None:
        out["applies_to"] = sorted(g.applies_to)
    return out


def _to_plain(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {k: _to_plain(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_to_plain(x) for x in v]
    return v


def _policy_to_plain(p: Policy) -> dict:
    out: dict = {
        "name": p.name,
        "version": p.version,
        "gates": [_gate_to_plain(g) for g in p.gates],
    }
    if p.description is not None:
        out["description"] = p.description
    if p.author is not None:
        out["author"] = p.author
    if p.risk_tier_overrides is not None:
        out["risk_tier_overrides"] = _to_plain(p.risk_tier_overrides)
    if p.escalation_rules is not None:
        out["escalation_rules"] = _to_plain(p.escalation_rules)
    if p.metadata is not None:
        out["metadata"] = _to_plain(p.metadata)
    return out


def policy_to_canonical_json(p: Policy) -> str:
    return json.dumps(
        _policy_to_plain(p),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
