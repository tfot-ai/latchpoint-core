"""Gate evaluation result data model.

Frozen, deterministic dataclasses for the per-gate status alphabet, the
final decision aggregate, and the structured error type raised by the
evaluator on malformed inputs.

The decision vocabulary (`approve | block | override_required`) is
re-exported from the evidence model so that an evaluator result can
be embedded into an EvidencePack without translation.

No I/O, no clock, no randomness, no environment.
"""

from __future__ import annotations

from dataclasses import dataclass

from .evidence_model import POLICY_VERDICT_DECISIONS

__all__ = [
    "GATE_EVALUATION_ERROR_CATEGORIES",
    "GATE_STATUSES",
    "POLICY_VERDICT_DECISIONS",
    "GateEvaluation",
    "GateEvaluationError",
    "GateResult",
]

GATE_STATUSES: tuple[str, ...] = ("PASS", "FAIL", "WARN", "SKIP", "ERROR")

GATE_EVALUATION_ERROR_CATEGORIES: tuple[str, ...] = (
    "malformed_action",
    "unsupported_operator",
    "field_resolution_error",
    "unknown_condition_type",
    "value_type_mismatch",
    "invalid_pattern",
    "tier_compare_error",
)


class GateEvaluationError(Exception):
    MALFORMED_ACTION = "malformed_action"
    UNSUPPORTED_OPERATOR = "unsupported_operator"
    FIELD_RESOLUTION_ERROR = "field_resolution_error"
    UNKNOWN_CONDITION_TYPE = "unknown_condition_type"
    VALUE_TYPE_MISMATCH = "value_type_mismatch"
    INVALID_PATTERN = "invalid_pattern"
    TIER_COMPARE_ERROR = "tier_compare_error"

    def __init__(self, code: str, path: str = "", message: str = "") -> None:
        if code not in GATE_EVALUATION_ERROR_CATEGORIES:
            raise ValueError(f"invalid GateEvaluationError code: {code!r}")
        self.code = code
        self.path = path
        self.message = message
        super().__init__(f"[{code}] {path}: {message}")


@dataclass(frozen=True, slots=True)
class GateResult:
    gate_name: str
    status: str
    reason: str
    action_on_fail: str


@dataclass(frozen=True, slots=True)
class GateEvaluation:
    decision: str
    reasons: tuple[str, ...]
    gates_evaluated: tuple[str, ...]
    gate_results: tuple[GateResult, ...]
