"""Promotion / demotion classifier, structured override, and
kill-switch primitives.

Frozen, deterministic dataclasses and pure functions for caller-supplied
safety-control evaluation. The kill-switch primitive maps a caller-
supplied ``state`` string to a fail-closed-or-permit result; structurally
malformed states raise a structured ``SafetyControlError``. The override
primitive evaluates a caller-supplied ``OverrideDecision`` against a
caller-supplied ``OverrideContext`` and returns one of a small fixed set
of named outcomes; structurally malformed inputs raise. The promotion /
demotion classifier reports whether a (from_stage, to_stage) transition
is a valid promotion (adjacent forward), a valid demotion (any lower
stage), a forbidden self-transition, or an invalid-stage transition.

The primitive does not mutate any input. Consumed-state checking is
pure: the caller is responsible for flipping the ``consumed`` flag on
successful application by constructing a new ``OverrideDecision``.
Expiration uses caller-supplied integer comparison only; no clock is
read.

No I/O, no clock, no randomness, no environment.
"""

from __future__ import annotations

from dataclasses import dataclass

KILL_SWITCH_STATES: tuple[str, ...] = ("INACTIVE", "ACTIVE")

KILL_SWITCH_OUTCOMES: tuple[str, ...] = ("permit", "fail_closed")

OVERRIDE_OUTCOMES: tuple[str, ...] = (
    "applicable",
    "rejected_expired",
    "rejected_already_consumed",
    "rejected_non_applicable",
    "rejected_structurally_invalid",
)

PROMOTION_STAGES: tuple[str, ...] = ("DEV", "SHADOW", "CANARY", "LIVE")

PROMOTION_TRANSITION_KINDS: tuple[str, ...] = (
    "promotion",
    "demotion",
    "self_transition",
    "invalid_stage",
)

SAFETY_ERROR_CATEGORIES: tuple[str, ...] = (
    "kill_switch_malformed",
    "override_malformed",
)


class SafetyControlError(Exception):
    KILL_SWITCH_MALFORMED = "kill_switch_malformed"
    OVERRIDE_MALFORMED = "override_malformed"

    def __init__(
        self,
        code: str,
        path: str = "",
        message: str = "",
        errors: tuple["SafetyControlError", ...] = (),
    ) -> None:
        if code not in SAFETY_ERROR_CATEGORIES:
            raise ValueError(f"invalid SafetyControlError code: {code!r}")
        self.code = code
        self.path = path
        self.message = message
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        if not self.errors:
            return f"[{self.code}] {self.path}: {self.message}"
        parts = [f"[{e.code}] {e.path}: {e.message}" for e in self.errors]
        return f"{len(self.errors)} safety control error(s): " + "; ".join(parts)


@dataclass(frozen=True, slots=True)
class KillSwitchResult:
    outcome: str
    reason: str


@dataclass(frozen=True, slots=True)
class OverrideDecision:
    override_id: str
    applies_to_action_id: str
    not_after: int
    consumed: bool


@dataclass(frozen=True, slots=True)
class OverrideContext:
    action_id: str
    now: int


@dataclass(frozen=True, slots=True)
class OverrideResult:
    outcome: str
    reason: str


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    from_stage: str
    to_stage: str


@dataclass(frozen=True, slots=True)
class PromotionResult:
    kind: str
    valid: bool
    reason: str


def evaluate_kill_switch(state: object) -> KillSwitchResult:
    """Map a caller-supplied kill-switch state to a permit / fail-closed result.

    ``"INACTIVE"`` permits continuation. ``"ACTIVE"`` is fail-closed.
    Any other value raises ``SafetyControlError`` with code
    ``KILL_SWITCH_MALFORMED``.
    """
    if not isinstance(state, str):
        raise SafetyControlError(
            SafetyControlError.KILL_SWITCH_MALFORMED,
            path="state",
            message=f"state must be a string, got {type(state).__name__}",
        )
    if state == "INACTIVE":
        return KillSwitchResult(
            outcome="permit", reason="inactive_permits_continuation"
        )
    if state == "ACTIVE":
        return KillSwitchResult(outcome="fail_closed", reason="active_engaged")
    raise SafetyControlError(
        SafetyControlError.KILL_SWITCH_MALFORMED,
        path="state",
        message=f"state must be one of {KILL_SWITCH_STATES!r}, got {state!r}",
    )


def _require_str(value: object, path: str, label: str) -> None:
    if not isinstance(value, str):
        raise SafetyControlError(
            SafetyControlError.OVERRIDE_MALFORMED,
            path=path,
            message=f"{label} must be a string, got {type(value).__name__}",
        )


def _require_int_not_bool(value: object, path: str, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SafetyControlError(
            SafetyControlError.OVERRIDE_MALFORMED,
            path=path,
            message=f"{label} must be an int, got {type(value).__name__}",
        )


def _require_bool(value: object, path: str, label: str) -> None:
    if not isinstance(value, bool):
        raise SafetyControlError(
            SafetyControlError.OVERRIDE_MALFORMED,
            path=path,
            message=f"{label} must be a bool, got {type(value).__name__}",
        )


def evaluate_override(
    decision: OverrideDecision, context: OverrideContext
) -> OverrideResult:
    """Evaluate a caller-supplied override decision against a context.

    Structurally malformed inputs (wrong dataclass type, wrong field
    types) raise ``SafetyControlError`` with code ``OVERRIDE_MALFORMED``.
    Otherwise, returns one of the named outcomes in
    ``OVERRIDE_OUTCOMES``. The primitive does not mutate ``decision``.
    """
    if not isinstance(decision, OverrideDecision):
        raise SafetyControlError(
            SafetyControlError.OVERRIDE_MALFORMED,
            path="decision",
            message=(
                f"decision must be an OverrideDecision, got {type(decision).__name__}"
            ),
        )
    if not isinstance(context, OverrideContext):
        raise SafetyControlError(
            SafetyControlError.OVERRIDE_MALFORMED,
            path="context",
            message=(
                f"context must be an OverrideContext, got {type(context).__name__}"
            ),
        )
    _require_str(decision.override_id, "decision.override_id", "override_id")
    _require_str(
        decision.applies_to_action_id,
        "decision.applies_to_action_id",
        "applies_to_action_id",
    )
    _require_int_not_bool(decision.not_after, "decision.not_after", "not_after")
    _require_bool(decision.consumed, "decision.consumed", "consumed")
    _require_str(context.action_id, "context.action_id", "action_id")
    _require_int_not_bool(context.now, "context.now", "now")
    if not decision.override_id:
        return OverrideResult(
            outcome="rejected_structurally_invalid",
            reason="empty_override_id",
        )
    if not decision.applies_to_action_id:
        return OverrideResult(
            outcome="rejected_structurally_invalid",
            reason="empty_applies_to_action_id",
        )
    if not context.action_id:
        return OverrideResult(
            outcome="rejected_structurally_invalid",
            reason="empty_context_action_id",
        )
    if decision.consumed:
        return OverrideResult(
            outcome="rejected_already_consumed", reason="consumed_flag_true"
        )
    if context.now > decision.not_after:
        return OverrideResult(outcome="rejected_expired", reason="now_after_not_after")
    if decision.applies_to_action_id != context.action_id:
        return OverrideResult(
            outcome="rejected_non_applicable", reason="action_id_mismatch"
        )
    return OverrideResult(outcome="applicable", reason="all_checks_passed")


def classify_promotion_demotion(decision: PromotionDecision) -> PromotionResult:
    """Classify a (from_stage, to_stage) transition.

    Returns ``promotion`` (valid=True) for an adjacent forward step,
    ``demotion`` (valid=True) for any lower stage, ``self_transition``
    (valid=False) when ``from_stage == to_stage``, and ``invalid_stage``
    (valid=False) when either stage is unknown or the transition skips
    a forward stage.
    """
    if not isinstance(decision, PromotionDecision):
        return PromotionResult(
            kind="invalid_stage",
            valid=False,
            reason="decision_not_promotion_decision",
        )
    if decision.from_stage not in PROMOTION_STAGES:
        return PromotionResult(
            kind="invalid_stage", valid=False, reason="from_stage_unknown"
        )
    if decision.to_stage not in PROMOTION_STAGES:
        return PromotionResult(
            kind="invalid_stage", valid=False, reason="to_stage_unknown"
        )
    if decision.from_stage == decision.to_stage:
        return PromotionResult(
            kind="self_transition",
            valid=False,
            reason="self_transition_forbidden",
        )
    from_index = PROMOTION_STAGES.index(decision.from_stage)
    to_index = PROMOTION_STAGES.index(decision.to_stage)
    if to_index > from_index:
        if to_index == from_index + 1:
            return PromotionResult(
                kind="promotion", valid=True, reason="adjacent_forward"
            )
        return PromotionResult(
            kind="invalid_stage",
            valid=False,
            reason="non_adjacent_promotion",
        )
    return PromotionResult(
        kind="demotion", valid=True, reason="any_lower_stage_allowed"
    )
