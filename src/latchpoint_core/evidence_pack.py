"""Evidence pack builder, canonical JSON serialiser, and verifier.

Deterministic by construction: stable key ordering, compact JSON
separators, no clock, no randomness, no environment, no network, no
filesystem reads. Builds a three-section evidence pack with a SHA-256
pack hash and per-section hashes, and verifies hash integrity by
recomputation. Fail-closed on malformed input at build time.
"""

from __future__ import annotations

import hashlib
import json
import re
from types import MappingProxyType
from typing import Any, Mapping

from .evidence_model import (
    POLICY_VERDICT_DECISIONS,
    DeterministicFacts,
    EvidenceError,
    EvidencePack,
    EvidencePackManifest,
    ModelDerivedJudgments,
    OverrideEvidence,
    PolicyVerdict,
    VerificationResult,
)

SECTION_NAMES: tuple[str, ...] = (
    "deterministic_facts",
    "policy_verdict",
    "model_derived_judgments",
)

_POLICY_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _to_plain(v: Any) -> Any:
    if isinstance(v, Mapping):
        return {str(k): _to_plain(val) for k, val in v.items()}
    if isinstance(v, (list, tuple)):
        return [_to_plain(x) for x in v]
    return v


def _check_json_friendly(value: Any, path: str) -> None:
    if value is None or isinstance(value, (bool, int, float, str)):
        return
    if isinstance(value, Mapping):
        for k, val in value.items():
            if not isinstance(k, str):
                raise EvidenceError(
                    EvidenceError.MALFORMED_EVIDENCE,
                    path=path,
                    message=f"non-string mapping key: {type(k).__name__}",
                )
            _check_json_friendly(val, f"{path}.{k}")
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check_json_friendly(item, f"{path}[{i}]")
        return
    raise EvidenceError(
        EvidenceError.MALFORMED_EVIDENCE,
        path=path,
        message=f"non JSON-friendly value: {type(value).__name__}",
    )


def _validate_facts(facts: DeterministicFacts) -> None:
    if not isinstance(facts.action_id, str) or not facts.action_id:
        raise EvidenceError(
            EvidenceError.SCHEMA_VIOLATION,
            path="deterministic_facts.action_id",
            message="action_id must be a non-empty string",
        )
    if not isinstance(facts.policy_hash, str) or not _POLICY_HASH_RE.match(
        facts.policy_hash
    ):
        raise EvidenceError(
            EvidenceError.SCHEMA_VIOLATION,
            path="deterministic_facts.policy_hash",
            message="policy_hash must be a 64-char lowercase hex string",
        )
    if not isinstance(facts.inputs, Mapping):
        raise EvidenceError(
            EvidenceError.SCHEMA_VIOLATION,
            path="deterministic_facts.inputs",
            message=f"inputs must be a Mapping, got {type(facts.inputs).__name__}",
        )
    _check_json_friendly(dict(facts.inputs), "deterministic_facts.inputs")
    if facts.metadata is not None:
        if not isinstance(facts.metadata, Mapping):
            raise EvidenceError(
                EvidenceError.SCHEMA_VIOLATION,
                path="deterministic_facts.metadata",
                message=(
                    f"metadata must be a Mapping or None, got "
                    f"{type(facts.metadata).__name__}"
                ),
            )
        _check_json_friendly(dict(facts.metadata), "deterministic_facts.metadata")
    if facts.override is not None:
        if not isinstance(facts.override, OverrideEvidence):
            raise EvidenceError(
                EvidenceError.SCHEMA_VIOLATION,
                path="deterministic_facts.override",
                message=(
                    f"override must be an OverrideEvidence or None, got "
                    f"{type(facts.override).__name__}"
                ),
            )
        if (
            not isinstance(facts.override.override_id, str)
            or not facts.override.override_id
        ):
            raise EvidenceError(
                EvidenceError.SCHEMA_VIOLATION,
                path="deterministic_facts.override.override_id",
                message="override_id must be a non-empty string",
            )
        if not isinstance(facts.override.outcome, str) or not facts.override.outcome:
            raise EvidenceError(
                EvidenceError.SCHEMA_VIOLATION,
                path="deterministic_facts.override.outcome",
                message="outcome must be a non-empty string",
            )


def _validate_verdict(verdict: PolicyVerdict) -> None:
    if verdict.decision not in POLICY_VERDICT_DECISIONS:
        raise EvidenceError(
            EvidenceError.SCHEMA_VIOLATION,
            path="policy_verdict.decision",
            message=(
                f"decision must be one of {POLICY_VERDICT_DECISIONS}, "
                f"got {verdict.decision!r}"
            ),
        )
    if not isinstance(verdict.reasons, tuple) or not all(
        isinstance(r, str) for r in verdict.reasons
    ):
        raise EvidenceError(
            EvidenceError.SCHEMA_VIOLATION,
            path="policy_verdict.reasons",
            message="reasons must be a tuple[str, ...]",
        )
    if not isinstance(verdict.gates_evaluated, tuple) or not all(
        isinstance(g, str) for g in verdict.gates_evaluated
    ):
        raise EvidenceError(
            EvidenceError.SCHEMA_VIOLATION,
            path="policy_verdict.gates_evaluated",
            message="gates_evaluated must be a tuple[str, ...]",
        )


def _validate_judgments(judgments: ModelDerivedJudgments) -> None:
    if not isinstance(judgments.judgments, Mapping):
        raise EvidenceError(
            EvidenceError.SCHEMA_VIOLATION,
            path="model_derived_judgments.judgments",
            message=(
                f"judgments must be a Mapping, got {type(judgments.judgments).__name__}"
            ),
        )
    _check_json_friendly(dict(judgments.judgments), "model_derived_judgments.judgments")


def _facts_to_plain(facts: DeterministicFacts) -> dict:
    out: dict = {
        "action_id": facts.action_id,
        "policy_hash": facts.policy_hash,
        "inputs": _to_plain(facts.inputs),
    }
    if facts.metadata is not None:
        out["metadata"] = _to_plain(facts.metadata)
    if facts.override is not None:
        out["override"] = {
            "override_id": facts.override.override_id,
            "outcome": facts.override.outcome,
        }
    return out


def _verdict_to_plain(verdict: PolicyVerdict) -> dict:
    return {
        "decision": verdict.decision,
        "reasons": list(verdict.reasons),
        "gates_evaluated": list(verdict.gates_evaluated),
    }


def _judgments_to_plain(judgments: ModelDerivedJudgments) -> dict:
    return {"judgments": _to_plain(judgments.judgments)}


def _manifest_to_plain(manifest: EvidencePackManifest) -> dict:
    return {
        "pack_hash": manifest.pack_hash,
        "section_hashes": _to_plain(manifest.section_hashes),
    }


def deterministic_facts_canonical_json(facts: DeterministicFacts) -> str:
    return canonical_json(_facts_to_plain(facts))


def policy_verdict_canonical_json(verdict: PolicyVerdict) -> str:
    return canonical_json(_verdict_to_plain(verdict))


def model_derived_judgments_canonical_json(
    judgments: ModelDerivedJudgments,
) -> str:
    return canonical_json(_judgments_to_plain(judgments))


def section_canonical_json(pack: EvidencePack, name: str) -> str:
    if name == "deterministic_facts":
        return deterministic_facts_canonical_json(pack.deterministic_facts)
    if name == "policy_verdict":
        return policy_verdict_canonical_json(pack.policy_verdict)
    if name == "model_derived_judgments":
        return model_derived_judgments_canonical_json(pack.model_derived_judgments)
    raise EvidenceError(
        EvidenceError.SCHEMA_VIOLATION,
        path="manifest.section_hashes",
        message=f"unknown section name: {name!r}",
    )


def _section_hashes_from_data(
    facts: DeterministicFacts,
    verdict: PolicyVerdict,
    judgments: ModelDerivedJudgments,
) -> dict[str, str]:
    return {
        "deterministic_facts": _sha256_hex(deterministic_facts_canonical_json(facts)),
        "policy_verdict": _sha256_hex(policy_verdict_canonical_json(verdict)),
        "model_derived_judgments": _sha256_hex(
            model_derived_judgments_canonical_json(judgments)
        ),
    }


def _section_hashes_from_pack(pack: EvidencePack) -> dict[str, str]:
    return _section_hashes_from_data(
        pack.deterministic_facts,
        pack.policy_verdict,
        pack.model_derived_judgments,
    )


def _pack_hash_from(section_hashes_map: Mapping[str, str]) -> str:
    return _sha256_hex(canonical_json(dict(section_hashes_map)))


def build_evidence_pack(
    facts: DeterministicFacts,
    verdict: PolicyVerdict,
    judgments: ModelDerivedJudgments,
) -> EvidencePack:
    _validate_facts(facts)
    _validate_verdict(verdict)
    _validate_judgments(judgments)
    section_hashes = _section_hashes_from_data(facts, verdict, judgments)
    pack_hash = _pack_hash_from(section_hashes)
    manifest = EvidencePackManifest(
        pack_hash=pack_hash,
        section_hashes=MappingProxyType(dict(section_hashes)),
    )
    return EvidencePack(
        deterministic_facts=facts,
        policy_verdict=verdict,
        model_derived_judgments=judgments,
        manifest=manifest,
    )


def evidence_pack_to_canonical_json(pack: EvidencePack) -> str:
    return canonical_json(
        {
            "deterministic_facts": _facts_to_plain(pack.deterministic_facts),
            "policy_verdict": _verdict_to_plain(pack.policy_verdict),
            "model_derived_judgments": _judgments_to_plain(
                pack.model_derived_judgments
            ),
            "manifest": _manifest_to_plain(pack.manifest),
        }
    )


def verify_evidence_pack(pack: EvidencePack) -> VerificationResult:
    errors: list[EvidenceError] = []
    recomputed = _section_hashes_from_pack(pack)
    for name in SECTION_NAMES:
        expected = pack.manifest.section_hashes.get(name)
        if expected != recomputed[name]:
            errors.append(
                EvidenceError(
                    EvidenceError.HASH_MISMATCH,
                    path=name,
                    message="section hash mismatch",
                )
            )
    recomputed_pack_hash = _pack_hash_from(recomputed)
    if recomputed_pack_hash != pack.manifest.pack_hash:
        errors.append(
            EvidenceError(
                EvidenceError.TAMPER_DETECTED,
                path="manifest.pack_hash",
                message="pack hash mismatch",
            )
        )
    return VerificationResult(
        ok=not errors,
        pack_hash=recomputed_pack_hash,
        section_hashes=MappingProxyType(dict(recomputed)),
        errors=tuple(errors),
    )
