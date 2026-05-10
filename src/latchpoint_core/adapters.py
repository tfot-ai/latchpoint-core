"""Adapter Protocol and one synthetic reference adapter.

A stdlib-only ``Protocol`` describing how an adapter translates a
caller-supplied payload into the project's internal action shape (an
``ActionDescriptor`` produced by :mod:`latchpoint_core.action_model`).
The module ships exactly one synthetic reference adapter.

The adapter surface is pure transformation: no I/O, no clock, no
randomness, no environment, no network, no filesystem, no subprocess,
no persistence. Adapters never raise on bad payloads; they return a
frozen :class:`AdapterResult` with ``ok=False`` and a homogeneous
tuple of :class:`AdapterError` entries. A downstream
``ActionError`` raised by ``validate_action`` is converted into one or
more ``AdapterError(DOWNSTREAM_VALIDATION, ...)`` entries so the
public surface stays homogeneous.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from .action_model import ActionDescriptor, ActionError, validate_action

ADAPTER_ERROR_CATEGORIES: tuple[str, ...] = (
    "malformed_payload",
    "schema_violation",
    "unsupported_operation",
    "downstream_validation",
)


class AdapterError(Exception):
    MALFORMED_PAYLOAD = "malformed_payload"
    SCHEMA_VIOLATION = "schema_violation"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    DOWNSTREAM_VALIDATION = "downstream_validation"

    def __init__(
        self,
        code: str,
        path: str = "",
        message: str = "",
        errors: tuple["AdapterError", ...] = (),
    ) -> None:
        if code not in ADAPTER_ERROR_CATEGORIES:
            raise ValueError(f"invalid AdapterError code: {code!r}")
        self.code = code
        self.path = path
        self.message = message
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        if not self.errors:
            return f"[{self.code}] {self.path}: {self.message}"
        parts = [f"[{e.code}] {e.path}: {e.message}" for e in self.errors]
        return f"{len(self.errors)} adapter error(s): " + "; ".join(parts)


@dataclass(frozen=True, slots=True)
class AdapterInput:
    operation: str
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class AdapterOutput:
    action: ActionDescriptor


@dataclass(frozen=True, slots=True)
class AdapterResult:
    ok: bool
    output: AdapterOutput | None
    errors: tuple[AdapterError, ...]


@runtime_checkable
class AdapterProtocol(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def supported_operations(self) -> tuple[str, ...]: ...

    def adapt(self, payload: AdapterInput) -> AdapterResult: ...


def _convert_action_error(action_error: ActionError) -> tuple[AdapterError, ...]:
    if action_error.errors:
        return tuple(
            AdapterError(
                AdapterError.DOWNSTREAM_VALIDATION,
                path=child.path,
                message=child.message,
            )
            for child in action_error.errors
        )
    return (
        AdapterError(
            AdapterError.DOWNSTREAM_VALIDATION,
            path=action_error.path,
            message=action_error.message,
        ),
    )


@dataclass(frozen=True, slots=True)
class SyntheticAdapter:
    name: str = "synthetic"
    supported_operations: tuple[str, ...] = ("synthetic.echo",)

    def adapt(self, payload: AdapterInput) -> AdapterResult:
        if not isinstance(payload, AdapterInput):
            return AdapterResult(
                ok=False,
                output=None,
                errors=(
                    AdapterError(
                        AdapterError.MALFORMED_PAYLOAD,
                        path="",
                        message=(
                            f"expected AdapterInput, got {type(payload).__name__}"
                        ),
                    ),
                ),
            )
        if payload.operation not in self.supported_operations:
            return AdapterResult(
                ok=False,
                output=None,
                errors=(
                    AdapterError(
                        AdapterError.UNSUPPORTED_OPERATION,
                        path="operation",
                        message=(
                            f"operation {payload.operation!r} is not supported by "
                            f"adapter {self.name!r}"
                        ),
                    ),
                ),
            )
        if not isinstance(payload.payload, Mapping):
            return AdapterResult(
                ok=False,
                output=None,
                errors=(
                    AdapterError(
                        AdapterError.MALFORMED_PAYLOAD,
                        path="payload",
                        message=(
                            f"expected mapping, got {type(payload.payload).__name__}"
                        ),
                    ),
                ),
            )
        try:
            action = validate_action(dict(payload.payload))
        except ActionError as e:
            return AdapterResult(ok=False, output=None, errors=_convert_action_error(e))
        return AdapterResult(ok=True, output=AdapterOutput(action=action), errors=())


def adapt_payload(adapter: AdapterProtocol, payload: AdapterInput) -> AdapterResult:
    """Dispatch ``payload`` through ``adapter`` and return its result.

    A free-function entry point that mirrors :meth:`AdapterProtocol.adapt`;
    callers that hold an adapter reference may use either form.
    """
    return adapter.adapt(payload)
