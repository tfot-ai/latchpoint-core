"""Tests for evidence verification and replay."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from latchpoint_core import (
    ActionDescriptor,
    DeterministicFacts,
    EvidencePack,
    EvidenceVerifierResult,
    ModelDerivedJudgments,
    Policy,
    PolicyVerdict,
    build_evidence_pack,
    evaluate_action,
    evidence_pack_to_canonical_json,
    validate_action,
    verify_evidence,
)
from latchpoint_core.policy_loader import load_policy

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC = REPO_ROOT / "src" / "latchpoint_core"
VERIFIER_SRC = SRC / "evidence_verifier.py"
FIXTURE_POLICY_MINIMAL = (
    REPO_ROOT / "tests" / "fixtures" / "policies" / "valid_minimal.yaml"
)
FIXTURE_ACTION_MINIMAL = (
    REPO_ROOT / "tests" / "fixtures" / "actions" / "minimal_action.json"
)

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

_FORBIDDEN_SIBLING_NAMESPACES = ("latchpoint_" "app", "latchpoint_" "governance")


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


def _pack_to_dict(pack: EvidencePack) -> dict:
    return json.loads(evidence_pack_to_canonical_json(pack))


def _load_minimal_policy_action() -> tuple[Policy, ActionDescriptor]:
    policy = load_policy(FIXTURE_POLICY_MINIMAL)
    action_data = json.loads(FIXTURE_ACTION_MINIMAL.read_text(encoding="utf-8"))
    action = validate_action(action_data)
    return policy, action


def _make_real_replayable_pack() -> tuple[EvidencePack, Policy, ActionDescriptor]:
    policy, action = _load_minimal_policy_action()
    ev = evaluate_action(policy, action)

    from latchpoint_core.policy_loader import policy_to_canonical_json

    policy_hash = hashlib.sha256(
        policy_to_canonical_json(policy).encode("utf-8")
    ).hexdigest()

    pack = build_evidence_pack(
        DeterministicFacts(
            action_id=action.id,
            policy_hash=policy_hash,
            inputs=dict(action.inputs) if action.inputs is not None else {},
            metadata=None,
        ),
        PolicyVerdict(
            decision=ev.decision,
            reasons=tuple(ev.reasons),
            gates_evaluated=tuple(ev.gates_evaluated),
        ),
        ModelDerivedJudgments(judgments={}),
    )
    return pack, policy, action


def _imports_in(path: Path) -> tuple[set[str], set[tuple[int, str]]]:
    """Return (absolute module names, relative ImportFrom (level, module) tuples)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    absolute: set[str] = set()
    relative: set[tuple[int, str]] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                absolute.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                relative.add((node.level, node.module or ""))
            elif node.module is not None:
                absolute.add(node.module)
    return absolute, relative


def test_verify_passes_for_untampered_pack_dict() -> None:
    pack = _make_minimal_pack()
    result = verify_evidence(_pack_to_dict(pack))
    assert isinstance(result, EvidenceVerifierResult)
    assert result.status == "PASS"
    assert result.reasons == ()
    assert result.pack_hash == pack.manifest.pack_hash
    assert dict(result.section_hashes) == dict(pack.manifest.section_hashes)
    assert result.replay_status == "NOT_REPLAYABLE"
    assert result.replay_reasons == ("replay inputs not supplied",)


def test_verify_fails_when_section_payload_tampered() -> None:
    pack = _make_minimal_pack()
    data = _pack_to_dict(pack)
    data["deterministic_facts"]["inputs"]["k"] = "TAMPERED"
    result = verify_evidence(data)
    assert result.status == "FAIL"
    assert any(
        "section hash mismatch: deterministic_facts" in r for r in result.reasons
    )
    assert any("pack hash mismatch" in r for r in result.reasons)
    assert result.replay_status == "NOT_REPLAYABLE"


def test_verify_fails_when_top_level_section_missing() -> None:
    pack = _make_minimal_pack()
    data = _pack_to_dict(pack)
    del data["policy_verdict"]
    result = verify_evidence(data)
    assert result.status == "FAIL"
    assert any("missing top-level section: policy_verdict" in r for r in result.reasons)
    assert result.pack_hash is None


def test_verify_fails_when_section_hash_in_manifest_corrupted() -> None:
    pack = _make_minimal_pack()
    data = _pack_to_dict(pack)
    data["manifest"]["section_hashes"]["deterministic_facts"] = "f" * 64
    result = verify_evidence(data)
    assert result.status == "FAIL"
    assert any(
        "section hash mismatch: deterministic_facts" in r for r in result.reasons
    )


def test_verify_fails_when_pack_hash_in_manifest_corrupted() -> None:
    pack = _make_minimal_pack()
    data = _pack_to_dict(pack)
    data["manifest"]["pack_hash"] = "0" * 64
    result = verify_evidence(data)
    assert result.status == "FAIL"
    assert any("pack hash mismatch" in r for r in result.reasons)


def test_verify_accepts_json_string_input() -> None:
    pack = _make_minimal_pack()
    json_text = evidence_pack_to_canonical_json(pack)
    result = verify_evidence(json_text)
    assert result.status == "PASS"
    assert result.pack_hash == pack.manifest.pack_hash


def test_verify_accepts_json_file_path_input(tmp_path: Path) -> None:
    pack = _make_minimal_pack()
    out = tmp_path / "evidence.json"
    out.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    result = verify_evidence(out)
    assert result.status == "PASS"
    assert result.pack_hash == pack.manifest.pack_hash

    result_str_path = verify_evidence(str(out))
    assert result_str_path.status == "PASS"


def test_verify_fails_closed_on_malformed_json() -> None:
    result = verify_evidence("{not json")
    assert result.status == "FAIL"
    assert any("malformed JSON" in r for r in result.reasons)
    assert result.pack_hash is None
    assert result.replay_status == "NOT_REPLAYABLE"


def test_verify_fails_closed_on_missing_file(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.json"
    result = verify_evidence(missing)
    assert result.status == "FAIL"
    assert any("failed to read evidence file" in r for r in result.reasons)


def test_verify_is_deterministic_across_repeated_calls() -> None:
    pack = _make_minimal_pack()
    data = _pack_to_dict(pack)
    a = verify_evidence(data)
    b = verify_evidence(data)
    assert a.status == b.status
    assert a.reasons == b.reasons
    assert a.pack_hash == b.pack_hash
    assert dict(a.section_hashes) == dict(b.section_hashes)
    assert a.replay_status == b.replay_status
    assert a.replay_reasons == b.replay_reasons


def test_replay_passes_when_policy_and_action_match_recorded_verdict() -> None:
    pack, policy, action = _make_real_replayable_pack()
    result = verify_evidence(_pack_to_dict(pack), policy=policy, action=action)
    assert result.status == "PASS"
    assert result.replay_status == "REPLAY_PASS"
    assert result.replay_reasons == ()


def test_replay_returns_not_replayable_when_no_inputs_supplied() -> None:
    pack, _, _ = _make_real_replayable_pack()
    result = verify_evidence(_pack_to_dict(pack))
    assert result.status == "PASS"
    assert result.replay_status == "NOT_REPLAYABLE"
    assert result.replay_reasons == ("replay inputs not supplied",)


def test_replay_fails_on_policy_hash_mismatch() -> None:
    pack = _make_minimal_pack()
    policy, action = _load_minimal_policy_action()
    result = verify_evidence(_pack_to_dict(pack), policy=policy, action=action)
    assert result.status == "PASS"
    assert result.replay_status == "REPLAY_FAIL"
    assert result.replay_reasons == ("policy_hash mismatch",)


def test_replay_fails_on_action_id_mismatch() -> None:
    pack, policy, _ = _make_real_replayable_pack()
    different_action_data = {
        "id": "00000000-0000-4000-8000-DIFFERENT0001",
        "type": "file.read",
        "target": "tmp/example.txt",
        "risk_tier": "T1",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "agent_id": "test-agent-minimal",
        "session_id": "test-session-minimal",
        "inputs": {"path": "tmp/example.txt"},
        "reversibility": True,
    }
    different_action = validate_action(different_action_data)
    result = verify_evidence(
        _pack_to_dict(pack), policy=policy, action=different_action
    )
    assert result.status == "PASS"
    assert result.replay_status == "REPLAY_FAIL"
    assert result.replay_reasons == ("action_id mismatch",)


def test_module_does_not_import_network_clock_random() -> None:
    absolute, _ = _imports_in(VERIFIER_SRC)
    top_levels = {name.split(".", 1)[0] for name in absolute}
    leaked = top_levels & _FORBIDDEN_TOP_LEVEL_MODULES
    assert leaked == set(), f"forbidden modules imported by verifier: {leaked}"


def test_module_does_not_import_sibling_repo_packages() -> None:
    absolute, relative = _imports_in(VERIFIER_SRC)
    for name in absolute:
        for forbidden in _FORBIDDEN_SIBLING_NAMESPACES:
            assert not name.startswith(forbidden), (
                f"sibling namespace import: {name} (matches {forbidden})"
            )
    # Relative imports (`from . import X`) are intra-package by definition; they
    # cannot leak to siblings since they are rooted in latchpoint_core.
    for level, module in relative:
        assert level >= 1
        assert module not in _FORBIDDEN_SIBLING_NAMESPACES


def test_demo_emitted_evidence_verifies_pass(tmp_path: Path) -> None:
    out = tmp_path / "demo_evidence.json"
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "latchpoint_core.demo_cli",
            "--policy",
            str(FIXTURE_POLICY_MINIMAL),
            "--action",
            str(FIXTURE_ACTION_MINIMAL),
            "--evidence-out",
            str(out),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (
        0,
        1,
        2,
    ), f"demo CLI returned unexpected code: {proc.returncode}; stderr={proc.stderr}"
    assert out.exists(), f"demo did not write evidence file; stderr={proc.stderr}"

    result = verify_evidence(out)
    assert result.status == "PASS"
    assert result.pack_hash is not None


def test_verifier_module_uses_only_relative_intra_package_imports() -> None:
    absolute, relative = _imports_in(VERIFIER_SRC)
    stdlib_only_absolute = {
        "hashlib",
        "json",
        "dataclasses",
        "pathlib",
        "types",
        "typing",
        "__future__",
    }
    unexpected = absolute - stdlib_only_absolute
    assert unexpected == set(), (
        f"verifier module has unexpected absolute imports: {unexpected}"
    )
    assert relative, "verifier should reuse intra-package modules via relative imports"


@pytest.mark.parametrize(
    "bad_input",
    [
        123,
        12.5,
        b"{}",
        ["not", "a", "mapping"],
        None,
    ],
)
def test_verify_fails_closed_on_unsupported_source_type(bad_input: object) -> None:
    result = verify_evidence(bad_input)  # type: ignore[arg-type]
    assert result.status == "FAIL"
    assert any("unsupported source type" in r for r in result.reasons)


# ---------------------------------------------------------------------------
# Override-evidence round-trip and tamper detection.
# ---------------------------------------------------------------------------


def _build_pack_with_override(override: object | None) -> EvidencePack:
    from latchpoint_core import OverrideEvidence

    facts_kwargs = {
        "action_id": "action_001",
        "policy_hash": _VALID_POLICY_HASH,
        "inputs": {"k": "v"},
        "metadata": None,
    }
    if override is not None:
        if isinstance(override, OverrideEvidence):
            facts_kwargs["override"] = override
        else:
            facts_kwargs["override"] = OverrideEvidence(
                override_id="ov-1", outcome="applicable"
            )
    return build_evidence_pack(
        DeterministicFacts(**facts_kwargs),
        PolicyVerdict(decision="approve", reasons=("ok",), gates_evaluated=("g1",)),
        ModelDerivedJudgments(judgments={}),
    )


def test_verify_passes_for_old_pack_without_override(tmp_path: Path) -> None:
    """A pack written before the override-recording slice (no
    ``override`` key in deterministic_facts) MUST verify successfully
    after the slice lands.
    """
    pack = _build_pack_with_override(None)
    pack_json_text = evidence_pack_to_canonical_json(pack)
    assert '"override"' not in pack_json_text
    pack_path = tmp_path / "old_pack.json"
    pack_path.write_text(pack_json_text, encoding="utf-8")

    result = verify_evidence(pack_path)
    assert result.status == "PASS"
    assert result.reasons == ()
    assert result.replay_status == "NOT_REPLAYABLE"


def test_verify_passes_for_new_pack_with_override(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_json_text = evidence_pack_to_canonical_json(pack)
    assert '"override"' in pack_json_text
    pack_path = tmp_path / "new_pack.json"
    pack_path.write_text(pack_json_text, encoding="utf-8")

    result = verify_evidence(pack_path)
    assert result.status == "PASS"


def test_verify_fails_on_tampered_override_id(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    raw = json.loads(evidence_pack_to_canonical_json(pack))
    raw["deterministic_facts"]["override"]["override_id"] = "ov-tampered"
    pack_path = tmp_path / "tampered_id.json"
    pack_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    result = verify_evidence(pack_path)
    assert result.status == "FAIL"
    assert any("section hash mismatch" in r for r in result.reasons)


def test_verify_fails_on_tampered_override_outcome(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    raw = json.loads(evidence_pack_to_canonical_json(pack))
    raw["deterministic_facts"]["override"]["outcome"] = "rejected_expired"
    pack_path = tmp_path / "tampered_outcome.json"
    pack_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    result = verify_evidence(pack_path)
    assert result.status == "FAIL"
    assert any("section hash mismatch" in r for r in result.reasons)


def test_verify_fails_on_inserted_override_block(tmp_path: Path) -> None:
    """A pack originally produced without an override that has an
    override block grafted in MUST fail verification: the manifest
    section_hashes still reflect the override-less canonical bytes.
    """
    pack = _build_pack_with_override(None)
    raw = json.loads(evidence_pack_to_canonical_json(pack))
    raw["deterministic_facts"]["override"] = {
        "override_id": "ov-x",
        "outcome": "applicable",
    }
    pack_path = tmp_path / "inserted.json"
    pack_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    result = verify_evidence(pack_path)
    assert result.status == "FAIL"
    assert any("section hash mismatch" in r for r in result.reasons)


def test_verify_fails_on_non_mapping_override_field(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    raw = json.loads(evidence_pack_to_canonical_json(pack))
    raw["deterministic_facts"]["override"] = "not-a-mapping"
    pack_path = tmp_path / "bad_override_shape.json"
    pack_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    result = verify_evidence(pack_path)
    assert result.status == "FAIL"


# ---------------------------------------------------------------------------
# Override-aware replay channel.
# ---------------------------------------------------------------------------


def _override_inputs(
    *,
    override_id: str = "ov-1",
    applies_to: str = "action_001",
    not_after: int = 9_999,
    consumed: bool = False,
    now: int = 1_000,
):
    """Construct the (OverrideDecision, OverrideContext) pair the
    verifier expects for replay."""
    from latchpoint_core import OverrideContext, OverrideDecision

    decision = OverrideDecision(
        override_id=override_id,
        applies_to_action_id=applies_to,
        not_after=not_after,
        consumed=consumed,
    )
    context = OverrideContext(action_id=applies_to, now=now)
    return decision, context


def test_override_replay_old_pack_no_inputs_is_not_present(tmp_path: Path) -> None:
    pack = _build_pack_with_override(None)
    pack_path = tmp_path / "old.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    result = verify_evidence(pack_path)
    assert result.status == "PASS"
    assert result.override_replay_status == "OVERRIDE_NOT_PRESENT"
    assert result.override_replay_reasons == ()


def test_override_replay_new_pack_no_inputs_is_not_replayable(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "new.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    result = verify_evidence(pack_path)
    assert result.status == "PASS"
    assert result.override_replay_status == "OVERRIDE_NOT_REPLAYABLE"


def test_override_replay_new_pack_matching_inputs_passes(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "new.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    decision, context = _override_inputs()
    result = verify_evidence(
        pack_path, override_decision=decision, override_context=context
    )
    assert result.status == "PASS"
    assert result.override_replay_status == "OVERRIDE_REPLAY_PASS"
    assert result.override_replay_reasons == ()


def test_override_replay_outcome_mismatch_fails(tmp_path: Path) -> None:
    """Pack recorded outcome=applicable; replay with not_after < now
    forces rejected_expired and yields OVERRIDE_REPLAY_FAIL."""
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "new.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    decision, context = _override_inputs(not_after=500, now=1000)
    result = verify_evidence(
        pack_path, override_decision=decision, override_context=context
    )
    assert result.status == "PASS"
    assert result.override_replay_status == "OVERRIDE_REPLAY_FAIL"
    assert any("outcome mismatch" in r for r in result.override_replay_reasons)


def test_override_replay_id_mismatch_fails(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "new.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    decision, context = _override_inputs(override_id="ov-OTHER")
    result = verify_evidence(
        pack_path, override_decision=decision, override_context=context
    )
    assert result.status == "PASS"
    assert result.override_replay_status == "OVERRIDE_REPLAY_FAIL"
    assert any("override_id mismatch" in r for r in result.override_replay_reasons)


def test_override_replay_old_pack_inputs_supplied_fails(tmp_path: Path) -> None:
    """Pack has no override; caller supplies override-replay inputs.
    This is a contradiction (the caller asserts an override that the
    pack does not record): OVERRIDE_REPLAY_FAIL."""
    pack = _build_pack_with_override(None)
    pack_path = tmp_path / "old.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    decision, context = _override_inputs()
    result = verify_evidence(
        pack_path, override_decision=decision, override_context=context
    )
    assert result.status == "PASS"
    assert result.override_replay_status == "OVERRIDE_REPLAY_FAIL"
    assert any("no recorded override" in r for r in result.override_replay_reasons)


def test_override_replay_with_only_decision_treated_as_no_inputs(
    tmp_path: Path,
) -> None:
    """Mirroring the gate-replay rule: only one of (decision, context)
    is treated as 'not supplied' for the purposes of the replay matrix."""
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "new.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    decision, _ = _override_inputs()
    result = verify_evidence(pack_path, override_decision=decision)
    assert result.status == "PASS"
    assert result.override_replay_status == "OVERRIDE_NOT_REPLAYABLE"


def test_override_replay_does_not_short_circuit_hash_verification(
    tmp_path: Path,
) -> None:
    """Override-replay must run AFTER hash verification; tampered
    override still produces verify_status FAIL."""
    pack = _build_pack_with_override(True)
    raw = json.loads(evidence_pack_to_canonical_json(pack))
    raw["deterministic_facts"]["override"]["outcome"] = "rejected_expired"
    pack_path = tmp_path / "tampered.json"
    pack_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    decision, context = _override_inputs()
    result = verify_evidence(
        pack_path, override_decision=decision, override_context=context
    )
    assert result.status == "FAIL"
    assert any("section hash mismatch" in r for r in result.reasons)
    # Override-replay channel is not the gate that caught this; we
    # short-circuit out of replay entirely on hash mismatch.
    assert result.override_replay_status == "OVERRIDE_NOT_REPLAYABLE"


# ---------------------------------------------------------------------------
# Ledger-aware replay channel.
# ---------------------------------------------------------------------------


def _chain_with_packs(*pack_hashes: str) -> tuple:
    """Build a verifying ledger chain over ``pack_hashes``.

    Caller-supplied append times are deterministic; uniqueness across
    pack_hashes is the caller's responsibility (the chain does
    not enforce uniqueness)."""
    from latchpoint_core import LedgerEntry, append_ledger_entry

    chain: tuple[LedgerEntry, ...] = ()
    for index, pack_hash in enumerate(pack_hashes):
        chain = chain + (
            append_ledger_entry(
                chain,
                pack_hash=pack_hash,
                append_time=f"2026-04-30T00:{index:02d}:00Z",
            ),
        )
    return chain


def test_ledger_replay_a_no_chain_supplied_old_pack_is_not_replayable(
    tmp_path: Path,
) -> None:
    pack = _build_pack_with_override(None)
    pack_path = tmp_path / "old.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    result = verify_evidence(pack_path)
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_NOT_REPLAYABLE"
    assert result.ledger_replay_reasons == ()
    assert result.ledger_replay_match is None


def test_ledger_replay_a_no_chain_supplied_new_pack_is_not_replayable(
    tmp_path: Path,
) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "new.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    result = verify_evidence(pack_path)
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_NOT_REPLAYABLE"
    assert result.ledger_replay_reasons == ()
    assert result.ledger_replay_match is None


def test_ledger_replay_b_pack_at_sequence_zero_passes(tmp_path: Path) -> None:
    from latchpoint_core import GENESIS_PREV_HASH, LedgerReplayMatch

    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "p.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    chain = _chain_with_packs(pack.manifest.pack_hash)
    result = verify_evidence(pack_path, ledger_chain=chain)
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_REPLAY_PASS"
    assert result.ledger_replay_reasons == ()
    assert isinstance(result.ledger_replay_match, LedgerReplayMatch)
    assert result.ledger_replay_match.sequence == 0
    assert result.ledger_replay_match.prev_hash == GENESIS_PREV_HASH
    assert result.ledger_replay_match.entry_hash == chain[0].entry_hash


def test_ledger_replay_c_pack_at_non_zero_sequence_passes(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "p.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    other_hash = "a" * 64
    chain = _chain_with_packs(other_hash, pack.manifest.pack_hash)
    result = verify_evidence(pack_path, ledger_chain=chain)
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_REPLAY_PASS"
    assert result.ledger_replay_match is not None
    assert result.ledger_replay_match.sequence == 1
    assert result.ledger_replay_match.prev_hash == chain[0].entry_hash
    assert result.ledger_replay_match.entry_hash == chain[1].entry_hash


def test_ledger_replay_d_pack_not_in_chain_fails(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "p.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    chain = _chain_with_packs("a" * 64, "b" * 64)
    result = verify_evidence(pack_path, ledger_chain=chain)
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_REPLAY_FAIL"
    assert result.ledger_replay_reasons == ("pack_hash not in chain",)
    assert result.ledger_replay_match is None


def test_ledger_replay_d_empty_chain_treats_pack_as_absent(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "p.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    result = verify_evidence(pack_path, ledger_chain=())
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_REPLAY_FAIL"
    assert result.ledger_replay_reasons == ("pack_hash not in chain",)


def test_ledger_replay_e_broken_chain_fails(tmp_path: Path) -> None:
    import dataclasses

    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "p.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    chain = _chain_with_packs("a" * 64, pack.manifest.pack_hash, "c" * 64)
    tampered = (
        chain[:1]
        + (dataclasses.replace(chain[1], prev_hash="0" * 63 + "1"),)
        + chain[2:]
    )
    result = verify_evidence(pack_path, ledger_chain=tampered)
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_REPLAY_FAIL"
    assert any("broken_chain" in r for r in result.ledger_replay_reasons)
    assert result.ledger_replay_match is None


def test_ledger_replay_f_multiple_matches_fails(tmp_path: Path) -> None:
    pack = _build_pack_with_override(True)
    pack_path = tmp_path / "p.json"
    pack_path.write_text(evidence_pack_to_canonical_json(pack), encoding="utf-8")
    # Chain with the same pack_hash at two distinct sequences. Uniqueness
    # is not a chain invariant, so this verifies under
    # verify_ledger_chain but the verifier rejects it for replay.
    chain = _chain_with_packs(
        pack.manifest.pack_hash, "a" * 64, pack.manifest.pack_hash
    )
    result = verify_evidence(pack_path, ledger_chain=chain)
    assert result.status == "PASS"
    assert result.ledger_replay_status == "LEDGER_REPLAY_FAIL"
    assert result.ledger_replay_reasons == (
        "pack_hash appears multiple times in chain",
    )
    assert result.ledger_replay_match is None


def test_ledger_replay_g_hash_mismatch_short_circuits(tmp_path: Path) -> None:
    """Ledger replay must run AFTER hash verification; tampered pack
    bytes still produce verify_status FAIL with the ledger channel
    short-circuited to NOT_REPLAYABLE."""
    pack = _build_pack_with_override(True)
    raw = json.loads(evidence_pack_to_canonical_json(pack))
    raw["deterministic_facts"]["override"]["outcome"] = "rejected_expired"
    pack_path = tmp_path / "tampered.json"
    pack_path.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    chain = _chain_with_packs(pack.manifest.pack_hash)
    result = verify_evidence(pack_path, ledger_chain=chain)
    assert result.status == "FAIL"
    assert result.ledger_replay_status == "LEDGER_NOT_REPLAYABLE"
    assert result.ledger_replay_reasons == ("hash verification failed",)
    assert result.ledger_replay_match is None


def test_ledger_replay_n_result_constructible_with_pre_pr17_fields() -> None:
    """The three new fields default safely; constructing a result with
    only the fields that existed pre-PR-#17 still succeeds."""
    result = EvidenceVerifierResult(
        status="PASS",
        reasons=(),
        pack_hash="a" * 64,
        section_hashes={},
        replay_status="NOT_REPLAYABLE",
        replay_reasons=(),
    )
    assert result.ledger_replay_status == "LEDGER_NOT_REPLAYABLE"
    assert result.ledger_replay_reasons == ()
    assert result.ledger_replay_match is None


def test_ledger_replay_o_match_record_is_frozen() -> None:
    import dataclasses

    from latchpoint_core import LedgerReplayMatch

    match = LedgerReplayMatch(sequence=0, prev_hash="0" * 64, entry_hash="a" * 64)
    with pytest.raises(dataclasses.FrozenInstanceError):
        match.sequence = 1  # type: ignore[misc]
