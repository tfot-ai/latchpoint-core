"""Policy data model.

Frozen, deterministic dataclasses that represent a loaded policy pack.
No I/O, no clock, no randomness, no environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

ERROR_CATEGORIES: tuple[str, ...] = (
    "parse_error",
    "schema_violation",
    "regex_violation",
    "enum_violation",
    "mutual_exclusion_violation",
    "unknown_field",
)


class _Missing:
    __slots__ = ()
    _instance: "_Missing | None" = None

    def __new__(cls) -> "_Missing":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "_MISSING"

    def __bool__(self) -> bool:
        return False


_MISSING = _Missing()


class PolicyError(Exception):
    PARSE_ERROR = "parse_error"
    SCHEMA_VIOLATION = "schema_violation"
    REGEX_VIOLATION = "regex_violation"
    ENUM_VIOLATION = "enum_violation"
    MUTUAL_EXCLUSION_VIOLATION = "mutual_exclusion_violation"
    UNKNOWN_FIELD = "unknown_field"

    def __init__(
        self,
        code: str,
        path: str = "",
        message: str = "",
        errors: tuple["PolicyError", ...] = (),
    ) -> None:
        if code not in ERROR_CATEGORIES:
            raise ValueError(f"invalid PolicyError code: {code!r}")
        self.code = code
        self.path = path
        self.message = message
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        if not self.errors:
            return f"[{self.code}] {self.path}: {self.message}"
        parts = [f"[{e.code}] {e.path}: {e.message}" for e in self.errors]
        return f"{len(self.errors)} validation error(s): " + "; ".join(parts)


@dataclass(frozen=True, slots=True)
class ValidationResult:
    ok: bool
    errors: tuple[PolicyError, ...]


@dataclass(frozen=True, slots=True)
class Condition:
    type: str
    field: str
    operator: str
    value: Any = _MISSING
    value_from: Any = _MISSING


@dataclass(frozen=True, slots=True)
class AnyOf:
    any_of: tuple[Condition, ...]


@dataclass(frozen=True, slots=True)
class Gate:
    name: str
    trigger: str
    action_on_fail: str
    applies_to: tuple[str, ...] | None
    conditions: tuple
    override: bool


@dataclass(frozen=True, slots=True)
class Policy:
    name: str
    version: str
    gates: tuple[Gate, ...]
    description: str | None = None
    author: str | None = None
    risk_tier_overrides: Mapping[str, Any] | None = None
    escalation_rules: Mapping[str, Any] | None = None
    metadata: Mapping[str, Any] | None = None

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        from .policy_loader import load_policy

        return load_policy(path)

    @classmethod
    def validate(cls, data: Mapping[str, Any]) -> "Policy":
        from .policy_loader import validate_policy

        return validate_policy(data)

    def to_canonical_json(self) -> str:
        from .policy_loader import policy_to_canonical_json

        return policy_to_canonical_json(self)
