"""Append-only ledger primitive with prior-hash chaining.

Pure, in-memory data model and verifier for an append-only chain of
``LedgerEntry`` records. Each entry binds an evidence pack hash and a
caller-supplied append time into a deterministic ``entry_hash``; each
non-genesis entry references the previous entry's ``entry_hash`` via
``prev_hash``. A ``verify_ledger_chain`` function recomputes the chain
from the entries alone, without invoking the gate engine and without
reading evidence files.

Deterministic by construction: stable key ordering, compact JSON
separators, no clock, no randomness, no environment, no network, no
filesystem reads, no persistence. Fail-closed on malformed input.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

GENESIS_PREV_HASH: str = "0" * 64

LEDGER_ERROR_CATEGORIES: tuple[str, ...] = (
    "malformed_entry",
    "schema_violation",
    "broken_chain",
    "hash_mismatch",
)

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


class LedgerError(Exception):
    MALFORMED_ENTRY = "malformed_entry"
    SCHEMA_VIOLATION = "schema_violation"
    BROKEN_CHAIN = "broken_chain"
    HASH_MISMATCH = "hash_mismatch"

    def __init__(
        self,
        code: str,
        path: str = "",
        message: str = "",
        errors: tuple["LedgerError", ...] = (),
    ) -> None:
        if code not in LEDGER_ERROR_CATEGORIES:
            raise ValueError(f"invalid LedgerError code: {code!r}")
        self.code = code
        self.path = path
        self.message = message
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        if not self.errors:
            return f"[{self.code}] {self.path}: {self.message}"
        parts = [f"[{e.code}] {e.path}: {e.message}" for e in self.errors]
        return f"{len(self.errors)} ledger error(s): " + "; ".join(parts)


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    sequence: int
    pack_hash: str
    prev_hash: str
    append_time: str
    entry_hash: str


@dataclass(frozen=True, slots=True)
class LedgerVerificationResult:
    ok: bool
    length: int
    head_hash: str | None
    errors: tuple[LedgerError, ...]


def _canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _validate_sequence(value: object, path: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LedgerError(
            LedgerError.SCHEMA_VIOLATION,
            path=path,
            message=f"sequence must be an int, got {type(value).__name__}",
        )
    if value < 0:
        raise LedgerError(
            LedgerError.SCHEMA_VIOLATION,
            path=path,
            message=f"sequence must be >= 0, got {value}",
        )


def _validate_hex64(value: object, path: str, label: str) -> None:
    if not isinstance(value, str):
        raise LedgerError(
            LedgerError.SCHEMA_VIOLATION,
            path=path,
            message=f"{label} must be a string, got {type(value).__name__}",
        )
    if not _HEX64_RE.match(value):
        raise LedgerError(
            LedgerError.SCHEMA_VIOLATION,
            path=path,
            message=f"{label} must be a 64-char lowercase hex string",
        )


def _validate_append_time(value: object, path: str) -> None:
    if not isinstance(value, str):
        raise LedgerError(
            LedgerError.SCHEMA_VIOLATION,
            path=path,
            message=f"append_time must be a string, got {type(value).__name__}",
        )
    if not value:
        raise LedgerError(
            LedgerError.SCHEMA_VIOLATION,
            path=path,
            message="append_time must be a non-empty string",
        )


def _entry_envelope_dict(
    *, sequence: int, pack_hash: str, prev_hash: str, append_time: str
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "pack_hash": pack_hash,
        "prev_hash": prev_hash,
        "append_time": append_time,
    }


def canonicalize_ledger_entry(entry: LedgerEntry) -> str:
    """Return the canonical JSON used for hashing a ledger entry.

    The ``entry_hash`` field is excluded from the hashed payload (the same
    envelope-identity rule used by the evidence pack manifest).
    """
    return _canonical_json(
        _entry_envelope_dict(
            sequence=entry.sequence,
            pack_hash=entry.pack_hash,
            prev_hash=entry.prev_hash,
            append_time=entry.append_time,
        )
    )


def compute_ledger_entry_hash(
    *, sequence: int, pack_hash: str, prev_hash: str, append_time: str
) -> str:
    """Return the SHA-256 hex of the canonical JSON over the four envelope fields."""
    _validate_sequence(sequence, "entry.sequence")
    _validate_hex64(pack_hash, "entry.pack_hash", "pack_hash")
    _validate_hex64(prev_hash, "entry.prev_hash", "prev_hash")
    _validate_append_time(append_time, "entry.append_time")
    return _sha256_hex(
        _canonical_json(
            _entry_envelope_dict(
                sequence=sequence,
                pack_hash=pack_hash,
                prev_hash=prev_hash,
                append_time=append_time,
            )
        )
    )


def append_ledger_entry(
    chain: tuple[LedgerEntry, ...],
    *,
    pack_hash: str,
    append_time: str,
    genesis_prev_hash: str = GENESIS_PREV_HASH,
) -> LedgerEntry:
    """Build the next ``LedgerEntry`` for ``chain``.

    The caller decides how to extend the chain (e.g., ``chain + (entry,)``).
    For an empty chain, ``prev_hash`` is ``genesis_prev_hash``; otherwise
    ``prev_hash`` is the previous entry's ``entry_hash``. Fail-closed on
    malformed inputs and on a malformed final entry of ``chain``.
    """
    if not isinstance(chain, tuple):
        raise LedgerError(
            LedgerError.SCHEMA_VIOLATION,
            path="chain",
            message=f"chain must be a tuple, got {type(chain).__name__}",
        )
    _validate_hex64(genesis_prev_hash, "genesis_prev_hash", "genesis_prev_hash")
    if chain:
        last = chain[-1]
        if not isinstance(last, LedgerEntry):
            raise LedgerError(
                LedgerError.MALFORMED_ENTRY,
                path=f"chain[{len(chain) - 1}]",
                message=(
                    f"chain entries must be LedgerEntry, got {type(last).__name__}"
                ),
            )
        _validate_hex64(
            last.entry_hash,
            f"chain[{len(chain) - 1}].entry_hash",
            "entry_hash",
        )
        prev_hash = last.entry_hash
        sequence = last.sequence + 1
        if sequence != len(chain):
            raise LedgerError(
                LedgerError.SCHEMA_VIOLATION,
                path=f"chain[{len(chain) - 1}].sequence",
                message=(
                    f"chain prefix sequence broken: expected {len(chain) - 1}, "
                    f"got {last.sequence}"
                ),
            )
    else:
        prev_hash = genesis_prev_hash
        sequence = 0
    entry_hash = compute_ledger_entry_hash(
        sequence=sequence,
        pack_hash=pack_hash,
        prev_hash=prev_hash,
        append_time=append_time,
    )
    return LedgerEntry(
        sequence=sequence,
        pack_hash=pack_hash,
        prev_hash=prev_hash,
        append_time=append_time,
        entry_hash=entry_hash,
    )


def _verify_entry_shape(entry: object, index: int) -> tuple[LedgerError, ...]:
    if not isinstance(entry, LedgerEntry):
        return (
            LedgerError(
                LedgerError.MALFORMED_ENTRY,
                path=f"chain[{index}]",
                message=(
                    f"chain entries must be LedgerEntry, got {type(entry).__name__}"
                ),
            ),
        )
    errors: list[LedgerError] = []

    def _capture(call) -> None:
        try:
            call()
        except LedgerError as e:
            errors.append(e)

    _capture(lambda: _validate_sequence(entry.sequence, f"chain[{index}].sequence"))
    _capture(
        lambda: _validate_hex64(
            entry.pack_hash, f"chain[{index}].pack_hash", "pack_hash"
        )
    )
    _capture(
        lambda: _validate_hex64(
            entry.prev_hash, f"chain[{index}].prev_hash", "prev_hash"
        )
    )
    _capture(
        lambda: _validate_append_time(entry.append_time, f"chain[{index}].append_time")
    )
    _capture(
        lambda: _validate_hex64(
            entry.entry_hash, f"chain[{index}].entry_hash", "entry_hash"
        )
    )
    return tuple(errors)


def verify_ledger_chain(
    chain: tuple[LedgerEntry, ...],
    *,
    genesis_prev_hash: str = GENESIS_PREV_HASH,
) -> LedgerVerificationResult:
    """Recompute and validate a ledger chain end-to-end.

    Empty chains verify successfully with ``length=0`` and ``head_hash=None``.
    Otherwise each entry is checked for shape, sequence-by-index, prior-hash
    linkage (or genesis on index 0), and ``entry_hash`` recomputation. All
    errors are collected; ``ok`` is true only when no error is recorded.
    """
    if not isinstance(chain, tuple):
        return LedgerVerificationResult(
            ok=False,
            length=0,
            head_hash=None,
            errors=(
                LedgerError(
                    LedgerError.SCHEMA_VIOLATION,
                    path="chain",
                    message=f"chain must be a tuple, got {type(chain).__name__}",
                ),
            ),
        )
    if not chain:
        return LedgerVerificationResult(ok=True, length=0, head_hash=None, errors=())
    try:
        _validate_hex64(genesis_prev_hash, "genesis_prev_hash", "genesis_prev_hash")
    except LedgerError as e:
        return LedgerVerificationResult(
            ok=False, length=len(chain), head_hash=None, errors=(e,)
        )
    errors: list[LedgerError] = []
    for index, entry in enumerate(chain):
        shape_errors = _verify_entry_shape(entry, index)
        if shape_errors:
            errors.extend(shape_errors)
            continue
        if entry.sequence != index:
            errors.append(
                LedgerError(
                    LedgerError.SCHEMA_VIOLATION,
                    path=f"chain[{index}].sequence",
                    message=(
                        f"sequence must equal index: expected {index}, "
                        f"got {entry.sequence}"
                    ),
                )
            )
            continue
        expected_prev = genesis_prev_hash if index == 0 else chain[index - 1].entry_hash
        if entry.prev_hash != expected_prev:
            errors.append(
                LedgerError(
                    LedgerError.BROKEN_CHAIN,
                    path=f"chain[{index}].prev_hash",
                    message=("prev_hash does not match expected previous entry hash"),
                )
            )
            continue
        recomputed = _sha256_hex(
            _canonical_json(
                _entry_envelope_dict(
                    sequence=entry.sequence,
                    pack_hash=entry.pack_hash,
                    prev_hash=entry.prev_hash,
                    append_time=entry.append_time,
                )
            )
        )
        if recomputed != entry.entry_hash:
            errors.append(
                LedgerError(
                    LedgerError.HASH_MISMATCH,
                    path=f"chain[{index}].entry_hash",
                    message="entry_hash does not match recomputed hash",
                )
            )
    head_hash = chain[-1].entry_hash if isinstance(chain[-1], LedgerEntry) else None
    return LedgerVerificationResult(
        ok=not errors,
        length=len(chain),
        head_hash=head_hash,
        errors=tuple(errors),
    )
