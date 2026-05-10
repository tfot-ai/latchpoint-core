"""Evidence pack data model.

Frozen, deterministic dataclasses that represent a generated evidence
pack with three-section separation (deterministic_facts, policy_verdict,
model_derived_judgments) plus an embedded manifest of section and pack
hashes.

No I/O, no clock, no randomness, no environment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

EVIDENCE_ERROR_CATEGORIES: tuple[str, ...] = (
    "malformed_evidence",
    "schema_violation",
    "hash_mismatch",
    "tamper_detected",
)

POLICY_VERDICT_DECISIONS: tuple[str, ...] = (
    "approve",
    "block",
    "override_required",
)


class EvidenceError(Exception):
    MALFORMED_EVIDENCE = "malformed_evidence"
    SCHEMA_VIOLATION = "schema_violation"
    HASH_MISMATCH = "hash_mismatch"
    TAMPER_DETECTED = "tamper_detected"

    def __init__(
        self,
        code: str,
        path: str = "",
        message: str = "",
        errors: tuple["EvidenceError", ...] = (),
    ) -> None:
        if code not in EVIDENCE_ERROR_CATEGORIES:
            raise ValueError(f"invalid EvidenceError code: {code!r}")
        self.code = code
        self.path = path
        self.message = message
        self.errors = errors
        super().__init__(self._format())

    def _format(self) -> str:
        if not self.errors:
            return f"[{self.code}] {self.path}: {self.message}"
        parts = [f"[{e.code}] {e.path}: {e.message}" for e in self.errors]
        return f"{len(self.errors)} evidence error(s): " + "; ".join(parts)


@dataclass(frozen=True, slots=True)
class OverrideEvidence:
    """Recorded operator-supplied override decision.

    Captured in ``DeterministicFacts`` when, and only when, a caller-
    supplied override evaluator returned the ``applicable`` outcome.
    The field is omitted from the canonical JSON of
    ``deterministic_facts`` when absent, preserving pack-hash byte
    stability for evidence packs produced without an override.
    """

    override_id: str
    outcome: str


@dataclass(frozen=True, slots=True)
class DeterministicFacts:
    action_id: str
    policy_hash: str
    inputs: Mapping[str, Any]
    metadata: Mapping[str, Any] | None = None
    override: OverrideEvidence | None = None


@dataclass(frozen=True, slots=True)
class PolicyVerdict:
    decision: str
    reasons: tuple[str, ...]
    gates_evaluated: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ModelDerivedJudgments:
    judgments: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class EvidencePackManifest:
    pack_hash: str
    section_hashes: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class EvidencePack:
    deterministic_facts: DeterministicFacts
    policy_verdict: PolicyVerdict
    model_derived_judgments: ModelDerivedJudgments
    manifest: EvidencePackManifest


@dataclass(frozen=True, slots=True)
class VerificationResult:
    ok: bool
    pack_hash: str
    section_hashes: Mapping[str, str]
    errors: tuple[EvidenceError, ...]
