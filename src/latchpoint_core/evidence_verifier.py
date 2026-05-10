"""Evidence verifier and replay.

Given an evidence pack as a Python mapping, JSON string, or filesystem
path, recompute section + pack hashes from canonical bytes and compare
against the embedded manifest. Optionally replay the recorded gate
decision when the caller supplies the original Policy and
ActionDescriptor.

Deterministic by construction: no clock, no randomness, no environment,
no network, no filesystem reads beyond the optional caller-supplied
JSON path. Fail-closed on malformed / tampered / missing-section input.

Public surface:
- ``verify_evidence(source, *, policy=None, action=None, override_decision=None,
  override_context=None, ledger_chain=None) -> EvidenceVerifierResult``
- ``EvidenceVerifierResult``
- ``LedgerReplayMatch``
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .action_model import ActionDescriptor
from .evidence_model import (
    DeterministicFacts,
    EvidencePack,
    EvidencePackManifest,
    ModelDerivedJudgments,
    OverrideEvidence,
    PolicyVerdict,
)
from .evidence_pack import (
    SECTION_NAMES,
    canonical_json,
    deterministic_facts_canonical_json,
    model_derived_judgments_canonical_json,
    policy_verdict_canonical_json,
)
from .gate_evaluator import evaluate_action
from .gate_model import GateEvaluationError
from .ledger import LedgerEntry, LedgerError, verify_ledger_chain
from .policy_loader import policy_to_canonical_json
from .policy_model import Policy
from .safety_controls import (
    OverrideContext,
    OverrideDecision,
    SafetyControlError,
    evaluate_override,
)

_PASS = "PASS"
_FAIL = "FAIL"
_REPLAY_PASS = "REPLAY_PASS"
_REPLAY_FAIL = "REPLAY_FAIL"
_NOT_REPLAYABLE = "NOT_REPLAYABLE"
_OVERRIDE_REPLAY_PASS = "OVERRIDE_REPLAY_PASS"
_OVERRIDE_REPLAY_FAIL = "OVERRIDE_REPLAY_FAIL"
_OVERRIDE_NOT_REPLAYABLE = "OVERRIDE_NOT_REPLAYABLE"
_OVERRIDE_NOT_PRESENT = "OVERRIDE_NOT_PRESENT"
_LEDGER_REPLAY_PASS = "LEDGER_REPLAY_PASS"
_LEDGER_REPLAY_FAIL = "LEDGER_REPLAY_FAIL"
_LEDGER_NOT_REPLAYABLE = "LEDGER_NOT_REPLAYABLE"

_LEDGER_ERROR_CODE_MAP: dict[str, str] = {
    LedgerError.MALFORMED_ENTRY: "schema_violation",
    LedgerError.SCHEMA_VIOLATION: "schema_violation",
    LedgerError.BROKEN_CHAIN: "broken_chain",
    LedgerError.HASH_MISMATCH: "hash_mismatch",
}


@dataclass(frozen=True, slots=True)
class LedgerReplayMatch:
    sequence: int
    prev_hash: str
    entry_hash: str


@dataclass(frozen=True, slots=True)
class EvidenceVerifierResult:
    status: str
    reasons: tuple[str, ...]
    pack_hash: str | None
    section_hashes: Mapping[str, str]
    replay_status: str
    replay_reasons: tuple[str, ...]
    override_replay_status: str = _OVERRIDE_NOT_PRESENT
    override_replay_reasons: tuple[str, ...] = ()
    ledger_replay_status: str = _LEDGER_NOT_REPLAYABLE
    ledger_replay_reasons: tuple[str, ...] = ()
    ledger_replay_match: LedgerReplayMatch | None = None


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _empty_section_hashes() -> Mapping[str, str]:
    return MappingProxyType({})


def _normalize_source(
    source: object,
) -> tuple[Mapping[str, Any] | None, str | None]:
    if isinstance(source, Mapping):
        return source, None
    if isinstance(source, Path):
        return _load_path(source)
    if isinstance(source, str):
        if source.lstrip().startswith("{"):
            return _parse_json_text(source, origin="JSON string")
        return _load_path(Path(source))
    return None, f"unsupported source type: {type(source).__name__}"


def _load_path(path: Path) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        text = path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, OSError, UnicodeDecodeError) as exc:
        return None, f"failed to read evidence file: {type(exc).__name__}: {exc}"
    return _parse_json_text(text, origin=f"file {path}")


def _parse_json_text(
    text: str, *, origin: str
) -> tuple[Mapping[str, Any] | None, str | None]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, f"malformed JSON in {origin}: {exc}"
    if not isinstance(data, Mapping):
        return None, (
            f"evidence in {origin} must be a JSON object, got {type(data).__name__}"
        )
    return data, None


def _build_pack_from_dict(
    data: Mapping[str, Any],
) -> tuple[EvidencePack | None, tuple[str, ...]]:
    missing = [name for name in (*SECTION_NAMES, "manifest") if name not in data]
    if missing:
        return None, tuple(f"missing top-level section: {name}" for name in missing)

    facts_raw = data["deterministic_facts"]
    verdict_raw = data["policy_verdict"]
    judgments_raw = data["model_derived_judgments"]
    manifest_raw = data["manifest"]

    for label, payload in (
        ("deterministic_facts", facts_raw),
        ("policy_verdict", verdict_raw),
        ("model_derived_judgments", judgments_raw),
        ("manifest", manifest_raw),
    ):
        if not isinstance(payload, Mapping):
            return None, (
                f"section payload not a mapping: {label} ({type(payload).__name__})",
            )

    try:
        override_raw = facts_raw.get("override")
        if override_raw is None:
            override: OverrideEvidence | None = None
        else:
            if not isinstance(override_raw, Mapping):
                return None, (
                    "schema violation reconstructing pack: "
                    f"deterministic_facts.override must be a mapping, "
                    f"got {type(override_raw).__name__}",
                )
            override = OverrideEvidence(
                override_id=override_raw["override_id"],
                outcome=override_raw["outcome"],
            )
        facts = DeterministicFacts(
            action_id=facts_raw["action_id"],
            policy_hash=facts_raw["policy_hash"],
            inputs=MappingProxyType(dict(facts_raw["inputs"])),
            metadata=(
                MappingProxyType(dict(facts_raw["metadata"]))
                if facts_raw.get("metadata") is not None
                else None
            ),
            override=override,
        )
        verdict = PolicyVerdict(
            decision=verdict_raw["decision"],
            reasons=tuple(verdict_raw["reasons"]),
            gates_evaluated=tuple(verdict_raw["gates_evaluated"]),
        )
        judgments = ModelDerivedJudgments(
            judgments=MappingProxyType(dict(judgments_raw["judgments"])),
        )
        manifest = EvidencePackManifest(
            pack_hash=manifest_raw["pack_hash"],
            section_hashes=MappingProxyType(dict(manifest_raw["section_hashes"])),
        )
    except (KeyError, TypeError, ValueError) as exc:
        return None, (
            f"schema violation reconstructing pack: {type(exc).__name__}: {exc}",
        )

    pack = EvidencePack(
        deterministic_facts=facts,
        policy_verdict=verdict,
        model_derived_judgments=judgments,
        manifest=manifest,
    )
    return pack, ()


def _recompute_section_hashes(pack: EvidencePack) -> dict[str, str]:
    return {
        "deterministic_facts": _sha256_hex(
            deterministic_facts_canonical_json(pack.deterministic_facts)
        ),
        "policy_verdict": _sha256_hex(
            policy_verdict_canonical_json(pack.policy_verdict)
        ),
        "model_derived_judgments": _sha256_hex(
            model_derived_judgments_canonical_json(pack.model_derived_judgments)
        ),
    }


def _recompute_pack_hash(section_hashes: Mapping[str, str]) -> str:
    return _sha256_hex(canonical_json(dict(section_hashes)))


def _attempt_replay(
    pack: EvidencePack,
    policy: Policy | None,
    action: ActionDescriptor | None,
) -> tuple[str, tuple[str, ...]]:
    if policy is None or action is None:
        return _NOT_REPLAYABLE, ("replay inputs not supplied",)

    recomputed_policy_hash = _sha256_hex(policy_to_canonical_json(policy))
    if recomputed_policy_hash != pack.deterministic_facts.policy_hash:
        return _REPLAY_FAIL, ("policy_hash mismatch",)

    if action.id != pack.deterministic_facts.action_id:
        return _REPLAY_FAIL, ("action_id mismatch",)

    try:
        recomputed = evaluate_action(policy, action)
    except GateEvaluationError as exc:
        return _REPLAY_FAIL, (f"gate evaluation raised {type(exc).__name__}: {exc}",)

    if recomputed.decision != pack.policy_verdict.decision:
        return _REPLAY_FAIL, (
            "decision mismatch: "
            f"recomputed={recomputed.decision!r}, "
            f"recorded={pack.policy_verdict.decision!r}",
        )

    if tuple(recomputed.gates_evaluated) != tuple(pack.policy_verdict.gates_evaluated):
        return _REPLAY_FAIL, ("gates_evaluated mismatch",)

    return _REPLAY_PASS, ()


def _attempt_override_replay(
    pack: EvidencePack,
    override_decision: OverrideDecision | None,
    override_context: OverrideContext | None,
) -> tuple[str, tuple[str, ...]]:
    """Re-evaluate the recorded override against caller-supplied inputs.

    Decision matrix:

    | pack has override? | inputs supplied? | status                  |
    |--------------------|------------------|-------------------------|
    | no                 | no               | OVERRIDE_NOT_PRESENT    |
    | no                 | yes              | OVERRIDE_REPLAY_FAIL    |
    | yes                | no               | OVERRIDE_NOT_REPLAYABLE |
    | yes                | yes              | PASS or FAIL by replay  |

    "Inputs supplied" means BOTH override_decision and override_context
    are non-None. Supplying only one is treated as "not supplied" for
    matrix purposes; this mirrors the existing gate-replay rule that
    requires both policy and action.
    """
    inputs_supplied = override_decision is not None and override_context is not None
    pack_override = pack.deterministic_facts.override

    if pack_override is None:
        if not inputs_supplied:
            return _OVERRIDE_NOT_PRESENT, ()
        return _OVERRIDE_REPLAY_FAIL, (
            "override-replay inputs supplied for a pack with no recorded override",
        )

    if not inputs_supplied:
        return _OVERRIDE_NOT_REPLAYABLE, ("override replay inputs not supplied",)

    assert override_decision is not None
    assert override_context is not None

    if override_decision.override_id != pack_override.override_id:
        return _OVERRIDE_REPLAY_FAIL, (
            "override_id mismatch: "
            f"recomputed={override_decision.override_id!r}, "
            f"recorded={pack_override.override_id!r}",
        )

    try:
        result = evaluate_override(override_decision, override_context)
    except SafetyControlError as exc:
        return _OVERRIDE_REPLAY_FAIL, (
            f"override evaluation raised {exc.code}: {exc.path}: {exc.message}",
        )

    if result.outcome != pack_override.outcome:
        return _OVERRIDE_REPLAY_FAIL, (
            "override outcome mismatch: "
            f"recomputed={result.outcome!r}, "
            f"recorded={pack_override.outcome!r}",
        )

    return _OVERRIDE_REPLAY_PASS, ()


def _attempt_ledger_replay(
    pack: EvidencePack,
    ledger_chain: tuple[LedgerEntry, ...] | None,
) -> tuple[str, tuple[str, ...], LedgerReplayMatch | None]:
    """Re-assert the recorded pack against a ledger chain.

    Decision matrix:

    | chain supplied? | chain verifies? | pack hash in chain?     | status                |
    |-----------------|-----------------|-------------------------|-----------------------|
    | no              | n/a             | n/a                     | LEDGER_NOT_REPLAYABLE |
    | yes             | no              | n/a                     | LEDGER_REPLAY_FAIL    |
    | yes             | yes             | absent                  | LEDGER_REPLAY_FAIL    |
    | yes             | yes             | present, exactly once   | LEDGER_REPLAY_PASS    |
    | yes             | yes             | present, multiple times | LEDGER_REPLAY_FAIL    |

    The match record on PASS captures the matched entry's
    ``(sequence, prev_hash, entry_hash)``.
    """
    if ledger_chain is None:
        return _LEDGER_NOT_REPLAYABLE, (), None

    chain_result = verify_ledger_chain(ledger_chain)
    if not chain_result.ok:
        reasons = tuple(
            f"{_LEDGER_ERROR_CODE_MAP.get(err.code, err.code)}: {err.path}: {err.message}"
            for err in chain_result.errors
        )
        return _LEDGER_REPLAY_FAIL, reasons, None

    matches = [
        entry for entry in ledger_chain if entry.pack_hash == pack.manifest.pack_hash
    ]
    if not matches:
        return _LEDGER_REPLAY_FAIL, ("pack_hash not in chain",), None
    if len(matches) > 1:
        return (
            _LEDGER_REPLAY_FAIL,
            ("pack_hash appears multiple times in chain",),
            None,
        )

    entry = matches[0]
    return (
        _LEDGER_REPLAY_PASS,
        (),
        LedgerReplayMatch(
            sequence=entry.sequence,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
        ),
    )


def verify_evidence(
    source: Mapping[str, Any] | str | Path,
    *,
    policy: Policy | None = None,
    action: ActionDescriptor | None = None,
    override_decision: OverrideDecision | None = None,
    override_context: OverrideContext | None = None,
    ledger_chain: tuple[LedgerEntry, ...] | None = None,
) -> EvidenceVerifierResult:
    parsed, parse_error = _normalize_source(source)
    if parse_error is not None:
        return EvidenceVerifierResult(
            status=_FAIL,
            reasons=(parse_error,),
            pack_hash=None,
            section_hashes=_empty_section_hashes(),
            replay_status=_NOT_REPLAYABLE,
            replay_reasons=("hash verification failed",),
            override_replay_status=_OVERRIDE_NOT_REPLAYABLE,
            override_replay_reasons=("hash verification failed",),
            ledger_replay_status=_LEDGER_NOT_REPLAYABLE,
            ledger_replay_reasons=("hash verification failed",),
            ledger_replay_match=None,
        )

    assert parsed is not None
    pack, build_errors = _build_pack_from_dict(parsed)
    if pack is None:
        return EvidenceVerifierResult(
            status=_FAIL,
            reasons=build_errors,
            pack_hash=None,
            section_hashes=_empty_section_hashes(),
            replay_status=_NOT_REPLAYABLE,
            replay_reasons=("hash verification failed",),
            override_replay_status=_OVERRIDE_NOT_REPLAYABLE,
            override_replay_reasons=("hash verification failed",),
            ledger_replay_status=_LEDGER_NOT_REPLAYABLE,
            ledger_replay_reasons=("hash verification failed",),
            ledger_replay_match=None,
        )

    recomputed_section_hashes = _recompute_section_hashes(pack)
    recomputed_pack_hash = _recompute_pack_hash(recomputed_section_hashes)
    section_hashes_view = MappingProxyType(dict(recomputed_section_hashes))

    reasons: list[str] = []
    for name in SECTION_NAMES:
        expected = pack.manifest.section_hashes.get(name)
        if expected != recomputed_section_hashes[name]:
            reasons.append(f"section hash mismatch: {name}")

    if recomputed_pack_hash != pack.manifest.pack_hash:
        reasons.append("pack hash mismatch")

    if reasons:
        return EvidenceVerifierResult(
            status=_FAIL,
            reasons=tuple(reasons),
            pack_hash=recomputed_pack_hash,
            section_hashes=section_hashes_view,
            replay_status=_NOT_REPLAYABLE,
            replay_reasons=("hash verification failed",),
            override_replay_status=_OVERRIDE_NOT_REPLAYABLE,
            override_replay_reasons=("hash verification failed",),
            ledger_replay_status=_LEDGER_NOT_REPLAYABLE,
            ledger_replay_reasons=("hash verification failed",),
            ledger_replay_match=None,
        )

    replay_status, replay_reasons = _attempt_replay(pack, policy, action)
    override_replay_status, override_replay_reasons = _attempt_override_replay(
        pack, override_decision, override_context
    )
    ledger_replay_status, ledger_replay_reasons, ledger_replay_match = (
        _attempt_ledger_replay(pack, ledger_chain)
    )
    return EvidenceVerifierResult(
        status=_PASS,
        reasons=(),
        pack_hash=recomputed_pack_hash,
        section_hashes=section_hashes_view,
        replay_status=replay_status,
        replay_reasons=replay_reasons,
        override_replay_status=override_replay_status,
        override_replay_reasons=override_replay_reasons,
        ledger_replay_status=ledger_replay_status,
        ledger_replay_reasons=ledger_replay_reasons,
        ledger_replay_match=ledger_replay_match,
    )
