"""Tests for the evidence pack: build, canonical JSON, hashing, verify."""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import re
from pathlib import Path

import pytest

from latchpoint_core import (
    EVIDENCE_ERROR_CATEGORIES,
    POLICY_VERDICT_DECISIONS,
    DeterministicFacts,
    EvidenceError,
    EvidencePack,
    EvidencePackManifest,
    EvidenceVerificationResult,
    ModelDerivedJudgments,
    Policy,
    PolicyVerdict,
    build_evidence_pack,
    evidence_pack_to_canonical_json,
    verify_evidence_pack,
)

SRC = Path(__file__).resolve().parent.parent / "src" / "latchpoint_core"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_VALID_POLICY_HASH = "a" * 64

_FORBIDDEN_TOP_LEVEL_MODULES = frozenset(
    {
        "os",
        "time",
        "random",
        "socket",
        "urllib",
        "requests",
        "subprocess",
        "datetime",
        "secrets",
        "http",
        "asyncio",
    }
)


def _make_minimal_pack() -> EvidencePack:
    return build_evidence_pack(
        DeterministicFacts(
            action_id="action_001",
            policy_hash=_VALID_POLICY_HASH,
            inputs={"k": "v"},
            metadata=None,
        ),
        PolicyVerdict(decision="approve", reasons=("ok",), gates_evaluated=("g1",)),
        ModelDerivedJudgments(judgments={"note": "advisory"}),
    )


def _imports_in(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod:
                found.add(mod.split(".")[0])
    return found


def test_build_minimal_pack():
    pack = _make_minimal_pack()
    assert isinstance(pack, EvidencePack)
    assert isinstance(pack.manifest, EvidencePackManifest)
    assert _HEX64_RE.match(pack.manifest.pack_hash)


def test_three_section_names_exact():
    pack = _make_minimal_pack()
    assert set(pack.manifest.section_hashes.keys()) == {
        "deterministic_facts",
        "policy_verdict",
        "model_derived_judgments",
    }
    for name, h in pack.manifest.section_hashes.items():
        assert _HEX64_RE.match(h), f"{name} hash not 64-char hex: {h!r}"


def test_canonical_json_stable_across_calls():
    pack = _make_minimal_pack()
    a = evidence_pack_to_canonical_json(pack)
    b = evidence_pack_to_canonical_json(pack)
    assert a == b
    assert not a.endswith("\n")
    assert not a.startswith("﻿")


def test_canonical_json_byte_identical_for_reordered_input():
    inputs_a = {"alpha": 1, "beta": 2, "gamma": 3}
    inputs_b = {"gamma": 3, "alpha": 1, "beta": 2}
    metadata_a = {"x": "1", "y": "2"}
    metadata_b = {"y": "2", "x": "1"}
    judgments_a = {"j1": "a", "j2": "b"}
    judgments_b = {"j2": "b", "j1": "a"}
    p1 = build_evidence_pack(
        DeterministicFacts(
            action_id="a1",
            policy_hash=_VALID_POLICY_HASH,
            inputs=inputs_a,
            metadata=metadata_a,
        ),
        PolicyVerdict(
            decision="block",
            reasons=("r1", "r2"),
            gates_evaluated=("g_a", "g_b"),
        ),
        ModelDerivedJudgments(judgments=judgments_a),
    )
    p2 = build_evidence_pack(
        DeterministicFacts(
            action_id="a1",
            policy_hash=_VALID_POLICY_HASH,
            inputs=inputs_b,
            metadata=metadata_b,
        ),
        PolicyVerdict(
            decision="block",
            reasons=("r1", "r2"),
            gates_evaluated=("g_a", "g_b"),
        ),
        ModelDerivedJudgments(judgments=judgments_b),
    )
    assert evidence_pack_to_canonical_json(p1) == evidence_pack_to_canonical_json(p2)
    assert p1.manifest.pack_hash == p2.manifest.pack_hash
    assert p1.manifest.section_hashes == p2.manifest.section_hashes


def test_pack_hash_stable():
    p1 = _make_minimal_pack()
    p2 = _make_minimal_pack()
    assert p1.manifest.pack_hash == p2.manifest.pack_hash


def test_section_hashes_stable():
    p1 = _make_minimal_pack()
    p2 = _make_minimal_pack()
    assert p1.manifest.section_hashes == p2.manifest.section_hashes


def test_section_hash_matches_recomputation():
    pack = _make_minimal_pack()
    facts_json = json.dumps(
        {
            "action_id": pack.deterministic_facts.action_id,
            "policy_hash": pack.deterministic_facts.policy_hash,
            "inputs": dict(pack.deterministic_facts.inputs),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    expected = hashlib.sha256(facts_json.encode("utf-8")).hexdigest()
    assert pack.manifest.section_hashes["deterministic_facts"] == expected


def test_pack_hash_is_sha256_of_section_hashes_canonical_json():
    pack = _make_minimal_pack()
    sh_json = json.dumps(
        dict(pack.manifest.section_hashes),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    expected = hashlib.sha256(sh_json.encode("utf-8")).hexdigest()
    assert pack.manifest.pack_hash == expected


def test_verify_passes_for_untampered_pack():
    pack = _make_minimal_pack()
    res = verify_evidence_pack(pack)
    assert isinstance(res, EvidenceVerificationResult)
    assert res.ok is True
    assert res.errors == ()
    assert res.pack_hash == pack.manifest.pack_hash
    assert dict(res.section_hashes) == dict(pack.manifest.section_hashes)


def test_verify_fails_closed_on_tampered_facts():
    pack = _make_minimal_pack()
    tampered_facts = dataclasses.replace(
        pack.deterministic_facts, action_id="action_002_tampered"
    )
    tampered_pack = dataclasses.replace(pack, deterministic_facts=tampered_facts)
    res = verify_evidence_pack(tampered_pack)
    assert res.ok is False
    codes = [e.code for e in res.errors]
    paths = [e.path for e in res.errors]
    assert EvidenceError.HASH_MISMATCH in codes
    assert "deterministic_facts" in paths
    assert EvidenceError.TAMPER_DETECTED in codes
    assert "manifest.pack_hash" in paths


def test_verify_fails_closed_on_tampered_judgments():
    pack = _make_minimal_pack()
    tampered_j = dataclasses.replace(
        pack.model_derived_judgments, judgments={"note": "MUTATED"}
    )
    tampered_pack = dataclasses.replace(pack, model_derived_judgments=tampered_j)
    res = verify_evidence_pack(tampered_pack)
    assert res.ok is False
    codes = [e.code for e in res.errors]
    paths = [e.path for e in res.errors]
    assert EvidenceError.HASH_MISMATCH in codes
    assert "model_derived_judgments" in paths


def test_verify_fails_closed_on_tampered_manifest_pack_hash():
    pack = _make_minimal_pack()
    bad_manifest = dataclasses.replace(pack.manifest, pack_hash="0" * 64)
    tampered_pack = dataclasses.replace(pack, manifest=bad_manifest)
    res = verify_evidence_pack(tampered_pack)
    assert res.ok is False
    codes = [e.code for e in res.errors]
    assert EvidenceError.TAMPER_DETECTED in codes


def test_verify_fails_closed_on_tampered_verdict():
    pack = _make_minimal_pack()
    tampered_v = dataclasses.replace(pack.policy_verdict, decision="block")
    tampered_pack = dataclasses.replace(pack, policy_verdict=tampered_v)
    res = verify_evidence_pack(tampered_pack)
    assert res.ok is False
    codes = [e.code for e in res.errors]
    paths = [e.path for e in res.errors]
    assert EvidenceError.HASH_MISMATCH in codes
    assert "policy_verdict" in paths


def test_malformed_decision_fails_closed():
    with pytest.raises(EvidenceError) as exc_info:
        build_evidence_pack(
            DeterministicFacts(
                action_id="a1", policy_hash=_VALID_POLICY_HASH, inputs={}
            ),
            PolicyVerdict(decision="maybe", reasons=(), gates_evaluated=()),
            ModelDerivedJudgments(judgments={}),
        )
    assert exc_info.value.code == EvidenceError.SCHEMA_VIOLATION
    assert exc_info.value.path == "policy_verdict.decision"


def test_malformed_policy_hash_fails_closed():
    for bad in ("short", "A" * 64, "g" * 64, ""):
        with pytest.raises(EvidenceError) as exc_info:
            build_evidence_pack(
                DeterministicFacts(action_id="a1", policy_hash=bad, inputs={}),
                PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
                ModelDerivedJudgments(judgments={}),
            )
        assert exc_info.value.code == EvidenceError.SCHEMA_VIOLATION
        assert exc_info.value.path == "deterministic_facts.policy_hash"


def test_malformed_action_id_fails_closed():
    with pytest.raises(EvidenceError) as exc_info:
        build_evidence_pack(
            DeterministicFacts(action_id="", policy_hash=_VALID_POLICY_HASH, inputs={}),
            PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
            ModelDerivedJudgments(judgments={}),
        )
    assert exc_info.value.code == EvidenceError.SCHEMA_VIOLATION
    assert exc_info.value.path == "deterministic_facts.action_id"


def test_malformed_inputs_type_fails_closed():
    with pytest.raises(EvidenceError) as exc_info:
        build_evidence_pack(
            DeterministicFacts(
                action_id="a1",
                policy_hash=_VALID_POLICY_HASH,
                inputs=["not", "a", "map"],  # type: ignore[arg-type]
            ),
            PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
            ModelDerivedJudgments(judgments={}),
        )
    assert exc_info.value.code == EvidenceError.SCHEMA_VIOLATION
    assert exc_info.value.path == "deterministic_facts.inputs"


def test_malformed_judgments_type_fails_closed():
    with pytest.raises(EvidenceError) as exc_info:
        build_evidence_pack(
            DeterministicFacts(
                action_id="a1", policy_hash=_VALID_POLICY_HASH, inputs={}
            ),
            PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
            ModelDerivedJudgments(judgments=["bad"]),  # type: ignore[arg-type]
        )
    assert exc_info.value.code == EvidenceError.SCHEMA_VIOLATION
    assert exc_info.value.path == "model_derived_judgments.judgments"


def test_malformed_evidence_on_non_string_mapping_key():
    with pytest.raises(EvidenceError) as exc_info:
        build_evidence_pack(
            DeterministicFacts(
                action_id="a1",
                policy_hash=_VALID_POLICY_HASH,
                inputs={1: "value"},  # type: ignore[dict-item]
            ),
            PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
            ModelDerivedJudgments(judgments={}),
        )
    assert exc_info.value.code == EvidenceError.MALFORMED_EVIDENCE


def test_malformed_reasons_type_fails_closed():
    with pytest.raises(EvidenceError) as exc_info:
        build_evidence_pack(
            DeterministicFacts(
                action_id="a1", policy_hash=_VALID_POLICY_HASH, inputs={}
            ),
            PolicyVerdict(
                decision="approve",
                reasons=("ok", 42),  # type: ignore[arg-type]
                gates_evaluated=(),
            ),
            ModelDerivedJudgments(judgments={}),
        )
    assert exc_info.value.code == EvidenceError.SCHEMA_VIOLATION
    assert exc_info.value.path == "policy_verdict.reasons"


def test_evidence_error_codes_stable():
    assert EVIDENCE_ERROR_CATEGORIES == (
        "malformed_evidence",
        "schema_violation",
        "hash_mismatch",
        "tamper_detected",
    )
    assert EvidenceError.MALFORMED_EVIDENCE == "malformed_evidence"
    assert EvidenceError.SCHEMA_VIOLATION == "schema_violation"
    assert EvidenceError.HASH_MISMATCH == "hash_mismatch"
    assert EvidenceError.TAMPER_DETECTED == "tamper_detected"


def test_policy_verdict_decisions_stable():
    assert POLICY_VERDICT_DECISIONS == ("approve", "block", "override_required")


def test_no_clock_random_network_imports_in_implementation():
    for fname in ("evidence_model.py", "evidence_pack.py", "__init__.py"):
        imports = _imports_in(SRC / fname)
        bad = imports & _FORBIDDEN_TOP_LEVEL_MODULES
        assert not bad, f"{fname} contains forbidden imports: {sorted(bad)}"


def test_pack_includes_policy_hash_without_importing_siblings():
    policy = Policy.validate({"name": "example_pack", "version": "1.0.0", "gates": []})
    policy_canonical = policy.to_canonical_json()
    policy_hash = hashlib.sha256(policy_canonical.encode("utf-8")).hexdigest()
    assert _HEX64_RE.match(policy_hash)
    pack = build_evidence_pack(
        DeterministicFacts(
            action_id="policy_integration_action",
            policy_hash=policy_hash,
            inputs={"policy_canonical_json": policy_canonical},
        ),
        PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
        ModelDerivedJudgments(judgments={}),
    )
    res = verify_evidence_pack(pack)
    assert res.ok is True
    assert pack.deterministic_facts.policy_hash == policy_hash


def test_pack_immutability_evidence_pack():
    pack = _make_minimal_pack()
    with pytest.raises(dataclasses.FrozenInstanceError):
        pack.deterministic_facts = pack.deterministic_facts  # type: ignore[misc]


def test_pack_immutability_manifest():
    pack = _make_minimal_pack()
    with pytest.raises(dataclasses.FrozenInstanceError):
        pack.manifest.pack_hash = "x"  # type: ignore[misc]


def test_pack_immutability_sections():
    pack = _make_minimal_pack()
    with pytest.raises(dataclasses.FrozenInstanceError):
        pack.deterministic_facts.action_id = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pack.policy_verdict.decision = "block"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        pack.model_derived_judgments.judgments = {}  # type: ignore[misc]


def test_judgments_mutation_does_not_change_policy_verdict_section_hash():
    """Mutating ``model_derived_judgments`` on a recorded pack must not change the
    policy_verdict's section hash. The model_derived_judgments section
    hash is independent of the policy_verdict section hash."""
    pack_a = _make_minimal_pack()
    mutated_j = dataclasses.replace(
        pack_a.model_derived_judgments,
        judgments={"note": "totally different judgment"},
    )
    pack_b = build_evidence_pack(
        pack_a.deterministic_facts,
        pack_a.policy_verdict,
        mutated_j,
    )
    assert (
        pack_a.manifest.section_hashes["policy_verdict"]
        == pack_b.manifest.section_hashes["policy_verdict"]
    )
    assert (
        pack_a.manifest.section_hashes["deterministic_facts"]
        == pack_b.manifest.section_hashes["deterministic_facts"]
    )
    assert (
        pack_a.manifest.section_hashes["model_derived_judgments"]
        != pack_b.manifest.section_hashes["model_derived_judgments"]
    )
    assert pack_a.manifest.pack_hash != pack_b.manifest.pack_hash


def test_metadata_optional_omitted_from_canonical_when_none():
    """Per the canonical-artifact-identity rule: optional metadata
    fields serialize only when non-None, so default-path hashes stay
    byte-stable."""
    pack_no_metadata = build_evidence_pack(
        DeterministicFacts(
            action_id="a1",
            policy_hash=_VALID_POLICY_HASH,
            inputs={},
            metadata=None,
        ),
        PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
        ModelDerivedJudgments(judgments={}),
    )
    pack_json = evidence_pack_to_canonical_json(pack_no_metadata)
    assert '"metadata"' not in pack_json


# ---------------------------------------------------------------------------
# Override-evidence recording.
# ---------------------------------------------------------------------------


def test_override_optional_omitted_from_canonical_when_none():
    """Same omit-when-None rule applies to the optional override field:
    when absent it MUST NOT appear in the canonical JSON, preserving
    pack-hash byte stability for runs that do not supply an override.
    """
    from latchpoint_core import OverrideEvidence  # noqa: F401  (smoke)

    pack = _make_minimal_pack()
    pack_json = evidence_pack_to_canonical_json(pack)
    assert '"override"' not in pack_json
    facts_section = json.dumps(
        {
            "action_id": pack.deterministic_facts.action_id,
            "policy_hash": pack.deterministic_facts.policy_hash,
            "inputs": dict(pack.deterministic_facts.inputs),
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    expected_section_hash = hashlib.sha256(facts_section.encode("utf-8")).hexdigest()
    assert pack.manifest.section_hashes["deterministic_facts"] == expected_section_hash


def test_override_present_serializes_with_sorted_child_keys():
    from latchpoint_core import OverrideEvidence

    pack = build_evidence_pack(
        DeterministicFacts(
            action_id="action_001",
            policy_hash=_VALID_POLICY_HASH,
            inputs={"k": "v"},
            metadata=None,
            override=OverrideEvidence(override_id="ov-1", outcome="applicable"),
        ),
        PolicyVerdict(decision="approve", reasons=("ok",), gates_evaluated=("g1",)),
        ModelDerivedJudgments(judgments={}),
    )
    pack_json = evidence_pack_to_canonical_json(pack)
    # Override block present with canonical key ordering (outcome before
    # override_id alphabetically).
    assert '"override":{"outcome":"applicable","override_id":"ov-1"}' in pack_json


def test_override_changes_pack_hash_vs_no_override():
    from latchpoint_core import OverrideEvidence

    base_facts = DeterministicFacts(
        action_id="action_001",
        policy_hash=_VALID_POLICY_HASH,
        inputs={"k": "v"},
        metadata=None,
    )
    with_override_facts = dataclasses.replace(
        base_facts,
        override=OverrideEvidence(override_id="ov-1", outcome="applicable"),
    )
    verdict = PolicyVerdict(
        decision="approve", reasons=("ok",), gates_evaluated=("g1",)
    )
    judgments = ModelDerivedJudgments(judgments={})
    pack_a = build_evidence_pack(base_facts, verdict, judgments)
    pack_b = build_evidence_pack(with_override_facts, verdict, judgments)
    assert pack_a.manifest.pack_hash != pack_b.manifest.pack_hash
    assert (
        pack_a.manifest.section_hashes["deterministic_facts"]
        != pack_b.manifest.section_hashes["deterministic_facts"]
    )
    # Other sections are identical because only deterministic_facts changed.
    assert (
        pack_a.manifest.section_hashes["policy_verdict"]
        == pack_b.manifest.section_hashes["policy_verdict"]
    )
    assert (
        pack_a.manifest.section_hashes["model_derived_judgments"]
        == pack_b.manifest.section_hashes["model_derived_judgments"]
    )


def test_override_verifies_round_trip():
    from latchpoint_core import OverrideEvidence

    pack = build_evidence_pack(
        DeterministicFacts(
            action_id="action_001",
            policy_hash=_VALID_POLICY_HASH,
            inputs={"k": "v"},
            metadata=None,
            override=OverrideEvidence(override_id="ov-1", outcome="applicable"),
        ),
        PolicyVerdict(decision="approve", reasons=("ok",), gates_evaluated=("g1",)),
        ModelDerivedJudgments(judgments={}),
    )
    result = verify_evidence_pack(pack)
    assert result.ok is True
    assert result.errors == ()


@pytest.mark.parametrize(
    "bad_override_id, bad_outcome",
    [
        ("", "applicable"),
        ("ov-1", ""),
    ],
)
def test_override_invalid_inner_strings_fail_closed(
    bad_override_id: str, bad_outcome: str
):
    from latchpoint_core import OverrideEvidence

    facts = DeterministicFacts(
        action_id="action_001",
        policy_hash=_VALID_POLICY_HASH,
        inputs={},
        metadata=None,
        override=OverrideEvidence(override_id=bad_override_id, outcome=bad_outcome),
    )
    with pytest.raises(EvidenceError) as exc:
        build_evidence_pack(
            facts,
            PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
            ModelDerivedJudgments(judgments={}),
        )
    assert exc.value.code == EvidenceError.SCHEMA_VIOLATION
    assert exc.value.path.startswith("deterministic_facts.override.")


def test_override_wrong_type_fails_closed():
    facts = DeterministicFacts(
        action_id="action_001",
        policy_hash=_VALID_POLICY_HASH,
        inputs={},
        metadata=None,
        override="not-an-OverrideEvidence",  # type: ignore[arg-type]
    )
    with pytest.raises(EvidenceError) as exc:
        build_evidence_pack(
            facts,
            PolicyVerdict(decision="approve", reasons=(), gates_evaluated=()),
            ModelDerivedJudgments(judgments={}),
        )
    assert exc.value.code == EvidenceError.SCHEMA_VIOLATION
    assert exc.value.path == "deterministic_facts.override"
