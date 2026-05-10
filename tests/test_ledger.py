"""Tests for the append-only ledger primitive.

Covers canonical-JSON byte stability, hash determinism, prior-hash
chaining, fail-closed handling of malformed input, and explicit
empty-chain behavior.
"""

from __future__ import annotations

import dataclasses
import importlib

import pytest

from latchpoint_core.ledger import (
    GENESIS_PREV_HASH,
    LEDGER_ERROR_CATEGORIES,
    LedgerEntry,
    LedgerError,
    LedgerVerificationResult,
    append_ledger_entry,
    canonicalize_ledger_entry,
    compute_ledger_entry_hash,
    verify_ledger_chain,
)

PACK_HASH_A = "a" * 64
PACK_HASH_B = "b" * 64
PACK_HASH_C = "c" * 64
APPEND_TIME_1 = "2026-01-01T00:00:00Z"
APPEND_TIME_2 = "2026-01-02T00:00:00Z"
APPEND_TIME_3 = "2026-01-03T00:00:00Z"


def _build_three_entry_chain() -> tuple[LedgerEntry, ...]:
    chain: tuple[LedgerEntry, ...] = ()
    for pack_hash, ts in (
        (PACK_HASH_A, APPEND_TIME_1),
        (PACK_HASH_B, APPEND_TIME_2),
        (PACK_HASH_C, APPEND_TIME_3),
    ):
        chain = chain + (
            append_ledger_entry(chain, pack_hash=pack_hash, append_time=ts),
        )
    return chain


def test_canonical_entry_json_is_byte_stable() -> None:
    entry = append_ledger_entry((), pack_hash=PACK_HASH_A, append_time=APPEND_TIME_1)
    first = canonicalize_ledger_entry(entry)
    second = canonicalize_ledger_entry(entry)
    assert first == second


def test_canonical_entry_json_byte_identical_for_reordered_kwargs() -> None:
    a = compute_ledger_entry_hash(
        sequence=0,
        pack_hash=PACK_HASH_A,
        prev_hash=GENESIS_PREV_HASH,
        append_time=APPEND_TIME_1,
    )
    b = compute_ledger_entry_hash(
        append_time=APPEND_TIME_1,
        prev_hash=GENESIS_PREV_HASH,
        pack_hash=PACK_HASH_A,
        sequence=0,
    )
    assert a == b


def test_compute_entry_hash_is_stable() -> None:
    h1 = compute_ledger_entry_hash(
        sequence=0,
        pack_hash=PACK_HASH_A,
        prev_hash=GENESIS_PREV_HASH,
        append_time=APPEND_TIME_1,
    )
    h2 = compute_ledger_entry_hash(
        sequence=0,
        pack_hash=PACK_HASH_A,
        prev_hash=GENESIS_PREV_HASH,
        append_time=APPEND_TIME_1,
    )
    assert h1 == h2
    assert len(h1) == 64
    assert all(c in "0123456789abcdef" for c in h1)


def test_compute_entry_hash_excludes_envelope() -> None:
    entry = append_ledger_entry((), pack_hash=PACK_HASH_A, append_time=APPEND_TIME_1)
    payload_with_arbitrary_entry_hash_replacement = canonicalize_ledger_entry(
        dataclasses.replace(entry, entry_hash="f" * 64)
    )
    payload_with_original_entry_hash = canonicalize_ledger_entry(entry)
    assert (
        payload_with_arbitrary_entry_hash_replacement
        == payload_with_original_entry_hash
    )


def test_append_genesis_uses_declared_genesis_prev_hash() -> None:
    entry = append_ledger_entry((), pack_hash=PACK_HASH_A, append_time=APPEND_TIME_1)
    assert entry.sequence == 0
    assert entry.prev_hash == GENESIS_PREV_HASH
    assert entry.pack_hash == PACK_HASH_A
    assert entry.append_time == APPEND_TIME_1
    assert entry.entry_hash == compute_ledger_entry_hash(
        sequence=0,
        pack_hash=PACK_HASH_A,
        prev_hash=GENESIS_PREV_HASH,
        append_time=APPEND_TIME_1,
    )


def test_append_links_via_previous_entry_hash() -> None:
    e0 = append_ledger_entry((), pack_hash=PACK_HASH_A, append_time=APPEND_TIME_1)
    e1 = append_ledger_entry((e0,), pack_hash=PACK_HASH_B, append_time=APPEND_TIME_2)
    assert e1.sequence == 1
    assert e1.prev_hash == e0.entry_hash
    assert e1.entry_hash != e0.entry_hash


def test_verify_empty_chain_is_ok_with_zero_length_and_none_head() -> None:
    result = verify_ledger_chain(())
    assert isinstance(result, LedgerVerificationResult)
    assert result.ok is True
    assert result.length == 0
    assert result.head_hash is None
    assert result.errors == ()


def test_verify_three_entry_chain_passes() -> None:
    chain = _build_three_entry_chain()
    result = verify_ledger_chain(chain)
    assert result.ok is True
    assert result.length == 3
    assert result.head_hash == chain[-1].entry_hash
    assert result.errors == ()


def test_verify_broken_prev_hash_fails_closed() -> None:
    chain = _build_three_entry_chain()
    tampered = (
        chain[:1]
        + (dataclasses.replace(chain[1], prev_hash="0" * 63 + "1"),)
        + chain[2:]
    )
    result = verify_ledger_chain(tampered)
    assert result.ok is False
    codes = {e.code for e in result.errors}
    assert LedgerError.BROKEN_CHAIN in codes
    assert any(e.path == "chain[1].prev_hash" for e in result.errors)


def test_verify_mutated_pack_hash_fails_closed() -> None:
    chain = _build_three_entry_chain()
    tampered = (
        chain[:1] + (dataclasses.replace(chain[1], pack_hash=PACK_HASH_C),) + chain[2:]
    )
    result = verify_ledger_chain(tampered)
    assert result.ok is False
    codes = {e.code for e in result.errors}
    assert LedgerError.HASH_MISMATCH in codes


def test_verify_out_of_order_sequence_fails_closed() -> None:
    chain = _build_three_entry_chain()
    tampered = chain[:1] + (dataclasses.replace(chain[1], sequence=42),) + chain[2:]
    result = verify_ledger_chain(tampered)
    assert result.ok is False
    codes = {e.code for e in result.errors}
    assert LedgerError.SCHEMA_VIOLATION in codes


@pytest.mark.parametrize(
    "bad_pack_hash",
    ["", "z" * 64, "A" * 64, "a" * 63, "a" * 65, "0x" + "a" * 62],
)
def test_malformed_pack_hash_rejected_at_compute(bad_pack_hash: str) -> None:
    with pytest.raises(LedgerError) as exc_info:
        compute_ledger_entry_hash(
            sequence=0,
            pack_hash=bad_pack_hash,
            prev_hash=GENESIS_PREV_HASH,
            append_time=APPEND_TIME_1,
        )
    assert exc_info.value.code == LedgerError.SCHEMA_VIOLATION
    assert exc_info.value.path == "entry.pack_hash"


@pytest.mark.parametrize("bad_append_time", ["", 0, None, b"2026-01-01T00:00:00Z"])
def test_malformed_append_time_rejected_at_compute(bad_append_time: object) -> None:
    with pytest.raises(LedgerError) as exc_info:
        compute_ledger_entry_hash(
            sequence=0,
            pack_hash=PACK_HASH_A,
            prev_hash=GENESIS_PREV_HASH,
            append_time=bad_append_time,  # type: ignore[arg-type]
        )
    assert exc_info.value.code == LedgerError.SCHEMA_VIOLATION
    assert exc_info.value.path == "entry.append_time"


@pytest.mark.parametrize("bad_sequence", [-1, -100, 1.5, "0", True, None])
def test_negative_or_non_int_sequence_rejected(bad_sequence: object) -> None:
    with pytest.raises(LedgerError) as exc_info:
        compute_ledger_entry_hash(
            sequence=bad_sequence,  # type: ignore[arg-type]
            pack_hash=PACK_HASH_A,
            prev_hash=GENESIS_PREV_HASH,
            append_time=APPEND_TIME_1,
        )
    assert exc_info.value.code == LedgerError.SCHEMA_VIOLATION
    assert exc_info.value.path == "entry.sequence"


def test_ledger_module_has_no_clock_or_random_or_io_imports() -> None:
    ledger_module = importlib.import_module("latchpoint_core.ledger")
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
    leaked = forbidden_attrs & set(vars(ledger_module))
    assert not leaked, f"ledger module imports forbidden runtime modules: {leaked}"


def test_ledger_error_categories_are_complete_and_unique() -> None:
    assert set(LEDGER_ERROR_CATEGORIES) == {
        LedgerError.MALFORMED_ENTRY,
        LedgerError.SCHEMA_VIOLATION,
        LedgerError.BROKEN_CHAIN,
        LedgerError.HASH_MISMATCH,
    }
    assert len(LEDGER_ERROR_CATEGORIES) == len(set(LEDGER_ERROR_CATEGORIES))
