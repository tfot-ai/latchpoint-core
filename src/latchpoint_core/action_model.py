"""Action descriptor data model.

Frozen, deterministic dataclasses that represent an agent action
proposed for governance.

No I/O, no clock, no randomness, no environment.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from types import MappingProxyType
from typing import Any, Mapping

ACTION_ERROR_CATEGORIES: tuple[str, ...] = (
    "malformed_action",
    "schema_violation",
    "unknown_field",
    "tier_violation",
)

RISK_TIERS: tuple[str, ...] = ("T0", "T1", "T2", "T3", "T4")

_TIER_ORDER: Mapping[str, int] = MappingProxyType(
    {tier: idx for idx, tier in enumerate(RISK_TIERS)}
)


class _NotFound:
    __slots__ = ()
    _instance: "_NotFound | None" = None

    def __new__(cls) -> "_NotFound":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "_NOT_FOUND"

    def __bool__(self) -> bool:
        return False


_NOT_FOUND = _NotFound()


class ActionError(Exception):
    MALFORMED_ACTION = "malformed_action"
    SCHEMA_VIOLATION = "schema_violation"
    UNKNOWN_FIELD = "unknown_field"
    TIER_VIOLATION = "tier_violation"

    def __init__(
        self,
        code: str,
        path: str = "",
        message: str = "",
        errors: tuple["ActionError", ...] = (),
    ) -> None:
        if code not in ACTION_ERROR_CATEGORIES:
            raise ValueError(f"invalid ActionError code: {code!r}")
        self.code = code
        self.path = path
        self.message = message
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        if not self.errors:
            return f"[{self.code}] {self.path}: {self.message}"
        parts = [f"[{e.code}] {e.path}: {e.message}" for e in self.errors]
        return f"{len(self.errors)} action error(s): " + "; ".join(parts)


@dataclass(frozen=True, slots=True)
class ActionDescriptor:
    id: str
    type: str
    target: str
    risk_tier: str
    timestamp: str
    agent_id: str
    session_id: str
    inputs: Mapping[str, Any] | None = None
    expected_outputs: Mapping[str, Any] | None = None
    reversibility: bool | None = None
    parent_action_id: str | None = None
    metadata: Mapping[str, Any] | None = None


_REQUIRED_STR_FIELDS: tuple[str, ...] = (
    "id",
    "type",
    "target",
    "timestamp",
    "agent_id",
    "session_id",
)
_OPTIONAL_MAPPING_FIELDS: tuple[str, ...] = (
    "inputs",
    "expected_outputs",
    "metadata",
)
_KNOWN_FIELDS: frozenset[str] = frozenset(f.name for f in fields(ActionDescriptor))


def validate_action(data: Any) -> ActionDescriptor:
    """Validate raw mapping data and return a frozen ActionDescriptor.

    Fail-closed: any unknown field, missing required field, wrong type, or
    invalid tier raises ActionError with a single nested ``schema_violation``
    or ``tier_violation`` entry.
    """
    if not isinstance(data, Mapping):
        raise ActionError(
            ActionError.MALFORMED_ACTION,
            path="",
            message=f"expected mapping, got {type(data).__name__}",
        )

    errors: list[ActionError] = []

    unknown = [k for k in data.keys() if k not in _KNOWN_FIELDS]
    for key in unknown:
        errors.append(
            ActionError(
                ActionError.UNKNOWN_FIELD,
                path=str(key),
                message="unknown action field",
            )
        )

    for name in _REQUIRED_STR_FIELDS:
        if name not in data:
            errors.append(
                ActionError(
                    ActionError.SCHEMA_VIOLATION,
                    path=name,
                    message="required field missing",
                )
            )
            continue
        v = data[name]
        if not isinstance(v, str) or v == "":
            errors.append(
                ActionError(
                    ActionError.SCHEMA_VIOLATION,
                    path=name,
                    message="expected non-empty string",
                )
            )

    if "risk_tier" not in data:
        errors.append(
            ActionError(
                ActionError.SCHEMA_VIOLATION,
                path="risk_tier",
                message="required field missing",
            )
        )
    else:
        tier = data["risk_tier"]
        if not isinstance(tier, str):
            errors.append(
                ActionError(
                    ActionError.SCHEMA_VIOLATION,
                    path="risk_tier",
                    message="expected string",
                )
            )
        elif tier not in RISK_TIERS:
            errors.append(
                ActionError(
                    ActionError.TIER_VIOLATION,
                    path="risk_tier",
                    message=f"risk_tier must be one of {RISK_TIERS!r}",
                )
            )

    for name in _OPTIONAL_MAPPING_FIELDS:
        if (
            name in data
            and data[name] is not None
            and not isinstance(data[name], Mapping)
        ):
            errors.append(
                ActionError(
                    ActionError.SCHEMA_VIOLATION,
                    path=name,
                    message="expected mapping",
                )
            )

    if "reversibility" in data and data["reversibility"] is not None:
        if not isinstance(data["reversibility"], bool):
            errors.append(
                ActionError(
                    ActionError.SCHEMA_VIOLATION,
                    path="reversibility",
                    message="expected boolean",
                )
            )

    if "parent_action_id" in data and data["parent_action_id"] is not None:
        if (
            not isinstance(data["parent_action_id"], str)
            or data["parent_action_id"] == ""
        ):
            errors.append(
                ActionError(
                    ActionError.SCHEMA_VIOLATION,
                    path="parent_action_id",
                    message="expected non-empty string",
                )
            )

    if errors:
        raise ActionError(
            errors[0].code,
            path="",
            message="action validation failed",
            errors=tuple(errors),
        )

    def _freeze(value: Any) -> Any:
        if isinstance(value, Mapping):
            return MappingProxyType({k: _freeze(v) for k, v in value.items()})
        if isinstance(value, list):
            return tuple(_freeze(v) for v in value)
        return value

    return ActionDescriptor(
        id=data["id"],
        type=data["type"],
        target=data["target"],
        risk_tier=data["risk_tier"],
        timestamp=data["timestamp"],
        agent_id=data["agent_id"],
        session_id=data["session_id"],
        inputs=_freeze(data["inputs"]) if data.get("inputs") is not None else None,
        expected_outputs=(
            _freeze(data["expected_outputs"])
            if data.get("expected_outputs") is not None
            else None
        ),
        reversibility=data.get("reversibility"),
        parent_action_id=data.get("parent_action_id"),
        metadata=_freeze(data["metadata"])
        if data.get("metadata") is not None
        else None,
    )


def resolve_field(action: ActionDescriptor, path: str) -> Any:
    """Resolve a dot-notation path on an ActionDescriptor.

    Returns the resolved value, or the ``_NOT_FOUND`` sentinel if any
    segment is missing. Non-recursive; does not call back into itself.
    """
    if not isinstance(path, str) or path == "":
        return _NOT_FOUND
    segments = path.split(".")
    current: Any = action
    for seg in segments:
        if current is None:
            return _NOT_FOUND
        if isinstance(current, ActionDescriptor):
            if seg in _KNOWN_FIELDS:
                current = getattr(current, seg)
                continue
            return _NOT_FOUND
        if isinstance(current, Mapping):
            if seg in current:
                current = current[seg]
                continue
            return _NOT_FOUND
        return _NOT_FOUND
    return current
