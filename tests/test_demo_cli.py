"""End-to-end tests for the `latchpoint_core.demo_cli` CLI.

Cover the verdict / exit-code mapping, evidence-pack writing,
determinism across runs, fail-closed behaviour on malformed inputs,
the run / verify subcommands, the kill-switch and override flags,
the override-consumption ledger, and the native --diff input mode.
No network. The public examples under ``examples/`` are the inputs;
transient artefacts go to ``tmp_path``.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pytest

from latchpoint_core import demo_cli

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = REPO_ROOT / "examples"
SAFE_ACTION = EXAMPLES / "actions" / "safe.json"
RISKY_ACTION = EXAMPLES / "actions" / "risky.json"
PUBLIC_POLICY = EXAMPLES / "policies" / "basic.yaml"


def _run(argv: list[str], capsys: pytest.CaptureFixture) -> tuple[int, str, str]:
    code = demo_cli.main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _parse_pack_hash(stdout: str) -> str:
    m = re.search(r"^pack_hash: ([0-9a-f]{64})$", stdout, re.MULTILINE)
    assert m, f"pack_hash line not found in stdout:\n{stdout}"
    return m.group(1)


def test_safe_example_returns_pass_and_exit_0(capsys: pytest.CaptureFixture) -> None:
    code, out, _ = _run(
        ["--policy", str(PUBLIC_POLICY), "--action", str(SAFE_ACTION)], capsys
    )
    assert code == 0
    assert "verdict: PASS" in out
    assert "decision: approve" in out
    assert re.search(r"^pack_hash: [0-9a-f]{64}$", out, re.MULTILINE)


def test_risky_example_returns_fix_and_exit_1(capsys: pytest.CaptureFixture) -> None:
    code, out, _ = _run(
        ["--policy", str(PUBLIC_POLICY), "--action", str(RISKY_ACTION)], capsys
    )
    assert code == 1
    assert "verdict: FIX" in out
    assert "decision: block" in out
    assert "gates_evaluated: high_risk_destructive_block" in out
    assert re.search(r"^reason: gate 'high_risk_destructive_block'", out, re.MULTILINE)


def test_evidence_out_writes_canonical_json(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_file = tmp_path / "evidence" / "risky.json"
    code, stdout, _ = _run(
        [
            "--policy",
            str(PUBLIC_POLICY),
            "--action",
            str(RISKY_ACTION),
            "--evidence-out",
            str(out_file),
        ],
        capsys,
    )
    assert code == 1
    assert out_file.is_file()
    pack = json.loads(out_file.read_text(encoding="utf-8"))
    assert set(pack.keys()) == {
        "deterministic_facts",
        "policy_verdict",
        "model_derived_judgments",
        "manifest",
    }
    assert pack["manifest"]["pack_hash"] == _parse_pack_hash(stdout)
    assert set(pack["manifest"]["section_hashes"].keys()) == {
        "deterministic_facts",
        "policy_verdict",
        "model_derived_judgments",
    }
    assert pack["policy_verdict"]["decision"] == "block"
    assert f"evidence_path: {out_file}" in stdout


def test_pack_hash_is_stable_across_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_a = tmp_path / "a.json"
    out_b = tmp_path / "subdir" / "b.json"
    _run(
        [
            "--policy",
            str(PUBLIC_POLICY),
            "--action",
            str(RISKY_ACTION),
            "--evidence-out",
            str(out_a),
        ],
        capsys,
    )
    _run(
        [
            "--policy",
            str(PUBLIC_POLICY),
            "--action",
            str(RISKY_ACTION),
            "--evidence-out",
            str(out_b),
        ],
        capsys,
    )
    bytes_a = out_a.read_bytes()
    bytes_b = out_b.read_bytes()
    assert bytes_a == bytes_b, "evidence-pack JSON differs across runs with same inputs"
    pack_a = json.loads(bytes_a)
    pack_b = json.loads(bytes_b)
    assert pack_a["manifest"]["pack_hash"] == pack_b["manifest"]["pack_hash"]


def test_malformed_action_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bad_action = tmp_path / "bad.json"
    bad_action.write_text("{this is not valid json", encoding="utf-8")
    code, out, err = _run(
        ["--policy", str(PUBLIC_POLICY), "--action", str(bad_action)], capsys
    )
    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "JSONDecodeError" in err


def test_malformed_policy_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bad_policy = tmp_path / "bad.yaml"
    bad_policy.write_text("name: 1234\nversion: not-a-semver\n", encoding="utf-8")
    code, out, err = _run(
        ["--policy", str(bad_policy), "--action", str(SAFE_ACTION)], capsys
    )
    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "PolicyError" in err


def test_missing_files_fail_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    missing_policy = tmp_path / "nope-policy.yaml"
    missing_action = tmp_path / "nope-action.json"
    code_p, out_p, err_p = _run(
        ["--policy", str(missing_policy), "--action", str(SAFE_ACTION)], capsys
    )
    assert code_p == 2
    assert "verdict: ESCALATE" in out_p
    assert "PolicyError" in err_p

    code_a, out_a, err_a = _run(
        ["--policy", str(PUBLIC_POLICY), "--action", str(missing_action)], capsys
    )
    assert code_a == 2
    assert "verdict: ESCALATE" in out_a
    assert "FileNotFoundError" in err_a


def _produce_evidence(
    action_path: Path,
    out_file: Path,
    capsys: pytest.CaptureFixture,
) -> str:
    code, stdout, _ = _run(
        [
            "--policy",
            str(PUBLIC_POLICY),
            "--action",
            str(action_path),
            "--evidence-out",
            str(out_file),
        ],
        capsys,
    )
    assert out_file.is_file(), (
        f"check mode failed to produce evidence (code={code}); stdout={stdout!r}"
    )
    return _parse_pack_hash(stdout)


def _verify_pack_hash_line(stdout: str) -> str:
    m = re.search(r"^pack_hash: (.+)$", stdout, re.MULTILINE)
    assert m, f"pack_hash line not found in verify stdout:\n{stdout}"
    return m.group(1)


def test_verify_succeeds_on_evidence_from_check_mode(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ev_file = tmp_path / "ev.json"
    expected_hash = _produce_evidence(SAFE_ACTION, ev_file, capsys)

    code, out, _ = _run(["--verify", "--evidence-in", str(ev_file)], capsys)

    assert code == 0
    assert "verify_status: PASS" in out
    assert "replay_status: NOT_REPLAYABLE" in out
    assert _verify_pack_hash_line(out) == expected_hash


def test_verify_with_policy_and_action_replays_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ev_file = tmp_path / "ev.json"
    _produce_evidence(SAFE_ACTION, ev_file, capsys)

    code, out, _ = _run(
        [
            "--verify",
            "--evidence-in",
            str(ev_file),
            "--policy",
            str(PUBLIC_POLICY),
            "--action",
            str(SAFE_ACTION),
        ],
        capsys,
    )

    assert code == 0
    assert "verify_status: PASS" in out
    assert "replay_status: REPLAY_PASS" in out


def test_verify_without_replay_inputs_passes_when_hash_valid(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ev_file = tmp_path / "risky_ev.json"
    _produce_evidence(RISKY_ACTION, ev_file, capsys)

    code, out, _ = _run(["--verify", "--evidence-in", str(ev_file)], capsys)

    assert code == 0
    assert "verify_status: PASS" in out
    assert "replay_status: NOT_REPLAYABLE" in out


def test_verify_fails_on_tampered_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ev_file = tmp_path / "ev.json"
    _produce_evidence(RISKY_ACTION, ev_file, capsys)
    pack = json.loads(ev_file.read_text(encoding="utf-8"))
    pack["policy_verdict"]["decision"] = "approve"
    ev_file.write_text(json.dumps(pack, separators=(",", ":")), encoding="utf-8")

    code, out, _ = _run(["--verify", "--evidence-in", str(ev_file)], capsys)

    assert code == 2
    assert "verify_status: FAIL" in out
    assert "reason: section hash mismatch: policy_verdict" in out


def test_verify_fails_on_malformed_evidence(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")

    code, out, _ = _run(["--verify", "--evidence-in", str(bad)], capsys)

    assert code == 2
    assert "verify_status: FAIL" in out
    assert re.search(r"^reason: malformed JSON ", out, re.MULTILINE)


def test_verify_fails_on_missing_evidence_file(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    missing = tmp_path / "nope.json"

    code, out, _ = _run(["--verify", "--evidence-in", str(missing)], capsys)

    assert code == 2
    assert "verify_status: FAIL" in out
    assert re.search(r"^reason: failed to read evidence file:", out, re.MULTILINE)


def test_verify_with_only_policy_no_action_escalates(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ev_file = tmp_path / "ev.json"
    _produce_evidence(SAFE_ACTION, ev_file, capsys)

    code, out, err = _run(
        [
            "--verify",
            "--evidence-in",
            str(ev_file),
            "--policy",
            str(PUBLIC_POLICY),
        ],
        capsys,
    )

    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "--policy and --action" in err


def test_verify_without_evidence_in_escalates(
    capsys: pytest.CaptureFixture,
) -> None:
    code, out, err = _run(["--verify"], capsys)

    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "--evidence-in" in err


def test_check_mode_still_requires_an_input(
    capsys: pytest.CaptureFixture,
) -> None:
    # --policy alone (no --action and no --diff) must fail closed with
    # exit 2 and ESCALATE. Either --action or --diff is required.
    code, out, err = _run(["--policy", str(PUBLIC_POLICY)], capsys)

    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "--action" in err and "--diff" in err


def test_verify_output_is_byte_stable_across_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ev_file = tmp_path / "ev.json"
    _produce_evidence(SAFE_ACTION, ev_file, capsys)

    code_a, out_a, _ = _run(["--verify", "--evidence-in", str(ev_file)], capsys)
    code_b, out_b, _ = _run(["--verify", "--evidence-in", str(ev_file)], capsys)

    assert code_a == code_b == 0
    assert out_a == out_b


def test_help_text_documents_check_verify_replay_and_exit_codes() -> None:
    help_text = demo_cli._build_parser().format_help()
    # Modes are named.
    assert "check" in help_text
    assert "--verify" in help_text
    assert "--evidence-in" in help_text
    assert "--evidence-out" in help_text
    # Replay guidance.
    assert "replay" in help_text.lower()
    # Exit-code table is present and lists all three codes.
    assert "Exit codes" in help_text
    for code_line in ("0  PASS", "1  FIX", "2  ESCALATE"):
        assert code_line in help_text, (
            f"expected exit-code guidance {code_line!r} in help text:\n{help_text}"
        )
    # Determinism note is present.
    assert "no clock" in help_text
    assert "no network" in help_text


def test_verify_replay_fail_returns_nonzero(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ev_file = tmp_path / "ev.json"
    _produce_evidence(SAFE_ACTION, ev_file, capsys)

    different_policy = tmp_path / "different.yaml"
    different_policy.write_text(
        PUBLIC_POLICY.read_text(encoding="utf-8").replace(
            'version: "0.1.0"', 'version: "0.1.1"'
        ),
        encoding="utf-8",
    )

    code, out, _ = _run(
        [
            "--verify",
            "--evidence-in",
            str(ev_file),
            "--policy",
            str(different_policy),
            "--action",
            str(SAFE_ACTION),
        ],
        capsys,
    )

    assert code == 2
    assert "verify_status: PASS" in out
    assert "replay_status: REPLAY_FAIL" in out
    assert "replay_reason: policy_hash mismatch" in out


# ---------------------------------------------------------------------------
# `run` subcommand: payload-mode end-to-end pipeline.
# ---------------------------------------------------------------------------

_RUN_FILES = (
    "evidence_pack.json",
    "deterministic_facts.json",
    "policy_verdict.json",
    "model_derived_judgments.json",
)

def _structured_error(stderr: str) -> dict:
    for line in stderr.splitlines():
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise AssertionError(f"no structured JSON envelope in stderr:\n{stderr}")


def test_run_subcommand_golden_path_returns_pass_and_writes_pack(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out_safe"
    code, stdout, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 0
    assert "verdict: PASS" in stdout
    assert "decision: approve" in stdout
    pack_hash = _parse_pack_hash(stdout)

    for name in _RUN_FILES:
        assert (out / name).is_file(), f"missing {name}"

    pack = json.loads((out / "evidence_pack.json").read_text(encoding="utf-8"))
    assert set(pack.keys()) == {
        "deterministic_facts",
        "policy_verdict",
        "model_derived_judgments",
        "manifest",
    }
    assert pack["manifest"]["pack_hash"] == pack_hash
    assert f"evidence_path: {out / 'evidence_pack.json'}" in stdout


def test_run_subcommand_deny_path_returns_fix_and_writes_pack(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out_risky"
    code, stdout, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(RISKY_ACTION),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 1
    assert "verdict: FIX" in stdout
    assert "decision: block" in stdout
    pack_hash = _parse_pack_hash(stdout)

    for name in _RUN_FILES:
        assert (out / name).is_file()

    pack = json.loads((out / "evidence_pack.json").read_text(encoding="utf-8"))
    assert pack["policy_verdict"]["decision"] == "block"
    assert pack["manifest"]["pack_hash"] == pack_hash


def test_run_subcommand_malformed_policy_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bad_policy = tmp_path / "bad_policy.yaml"
    bad_policy.write_text(": : not valid yaml\n", encoding="utf-8")
    out = tmp_path / "out"
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(bad_policy),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "policy"
    assert envelope["errors"]
    # Out dir was empty before; no evidence files should exist.
    assert not list(out.glob("*.json"))


def test_run_subcommand_malformed_payload_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bad_payload = tmp_path / "bad_payload.json"
    bad_payload.write_text("{not json", encoding="utf-8")
    out = tmp_path / "out"
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(bad_payload),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "payload"
    assert envelope["errors"][0]["code"] == "json_decode_error"
    assert not list(out.glob("*.json"))


def test_run_subcommand_payload_not_object_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    array_payload = tmp_path / "array.json"
    array_payload.write_text("[1, 2, 3]", encoding="utf-8")
    out = tmp_path / "out"
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(array_payload),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "payload"
    assert envelope["errors"][0]["code"] == "not_object"
    assert not list(out.glob("*.json"))


def test_run_subcommand_adapter_rejection_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    incomplete = tmp_path / "incomplete_payload.json"
    # Object but missing required ActionDescriptor fields (e.g. id).
    incomplete.write_text(
        json.dumps({"type": "file.read", "target": "tmp/x.txt"}),
        encoding="utf-8",
    )
    out = tmp_path / "out"
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(incomplete),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "adapter"
    assert envelope["errors"]
    assert not list(out.glob("*.json"))


def test_run_subcommand_gate_error_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    bad_policy = tmp_path / "bad_op_policy.yaml"
    bad_policy.write_text(
        "name: bad_op_policy\n"
        'version: "0.1.0"\n'
        "gates:\n"
        "  - name: bogus\n"
        "    trigger: pre_execution\n"
        "    action_on_fail: BLOCK\n"
        "    applies_to: [T0, T1, T2, T3, T4]\n"
        "    conditions:\n"
        "      - type: denylist\n"
        "        field: type\n"
        "        operator: nope_not_an_operator\n"
        '        value: ["filesystem.delete"]\n',
        encoding="utf-8",
    )
    out = tmp_path / "out"
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(bad_policy),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    # Either the policy loader rejects the bogus operator at load time
    # ("policy") or the gate evaluator rejects it at evaluation time
    # ("gate"). Both are valid fail-closed paths for an unsupported
    # operator; assert it is one of the two structured categories.
    assert envelope["error"] in {"policy", "gate"}
    assert not list(out.glob("*.json"))


def test_run_subcommand_refuses_non_empty_out_dir(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out_dirty"
    out.mkdir()
    sentinel = out / "preexisting.txt"
    sentinel.write_text("untouched", encoding="utf-8")
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "out"
    assert envelope["errors"][0]["code"] == "out_not_empty"
    assert sentinel.read_text(encoding="utf-8") == "untouched"
    assert not (out / "evidence_pack.json").exists()


def test_run_subcommand_byte_stable_with_same_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    common = [
        "run",
        "--policy",
        str(PUBLIC_POLICY),
        "--payload",
        str(SAFE_ACTION),
        "--at",
        "2026-04-29T00:00:00Z",
    ]
    code_a, _, _ = _run([*common, "--out", str(out_a)], capsys)
    code_b, _, _ = _run([*common, "--out", str(out_b)], capsys)
    assert code_a == 0 and code_b == 0
    for name in _RUN_FILES:
        assert (out_a / name).read_bytes() == (out_b / name).read_bytes(), (
            f"{name} differs between runs with identical inputs"
        )


def test_run_subcommand_byte_stable_without_at(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    base = [
        "run",
        "--policy",
        str(PUBLIC_POLICY),
        "--payload",
        str(SAFE_ACTION),
    ]
    code_a, _, _ = _run([*base, "--out", str(out_a)], capsys)
    code_b, _, _ = _run([*base, "--out", str(out_b)], capsys)
    assert code_a == 0 and code_b == 0
    for name in _RUN_FILES:
        assert (out_a / name).read_bytes() == (out_b / name).read_bytes()
    # Confirm metadata field is absent (build_time only present when --at supplied).
    facts = json.loads((out_a / "deterministic_facts.json").read_text(encoding="utf-8"))
    assert "metadata" not in facts or facts.get("metadata") in (None, {})


def test_run_subcommand_registered_alongside_check_and_verify(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    # Set-equality: ordering of the registry tuple is not a product invariant.
    assert set(demo_cli._SUBCOMMANDS) == {"run", "check", "verify"}

    # Subcommand form of legacy check works.
    code_check, out_check, _ = _run(
        ["check", "--policy", str(PUBLIC_POLICY), "--action", str(SAFE_ACTION)],
        capsys,
    )
    assert code_check == 0
    assert "verdict: PASS" in out_check

    # Subcommand form of legacy verify works against a freshly produced pack.
    pack_path = tmp_path / "produced.json"
    code_make, _, _ = _run(
        [
            "--policy",
            str(PUBLIC_POLICY),
            "--action",
            str(SAFE_ACTION),
            "--evidence-out",
            str(pack_path),
        ],
        capsys,
    )
    assert code_make == 0
    code_verify, out_verify, _ = _run(
        ["verify", "--evidence-in", str(pack_path)], capsys
    )
    assert code_verify == 0
    assert "verify_status: PASS" in out_verify


# ---------------------------------------------------------------------------
# `run` subcommand bindings: --kill-switch and --override.
# ---------------------------------------------------------------------------


def _safe_action_id() -> str:
    return json.loads(SAFE_ACTION.read_text(encoding="utf-8"))["id"]


def _write_kill_switch(tmp_path: Path, state: object, name: str = "ks.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps({"state": state}), encoding="utf-8")
    return path


def _write_override(
    tmp_path: Path,
    *,
    override_id: str = "ov-1",
    applies_to_action_id: str | None = None,
    not_after: int = 9_999,
    consumed: bool = False,
    now: int = 1_000,
    name: str = "ov.json",
) -> Path:
    if applies_to_action_id is None:
        applies_to_action_id = _safe_action_id()
    path = tmp_path / name
    path.write_text(
        json.dumps(
            {
                "override_id": override_id,
                "applies_to_action_id": applies_to_action_id,
                "not_after": not_after,
                "consumed": consumed,
                "now": now,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_run_with_inactive_kill_switch_allows_normal_run(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    ks = _write_kill_switch(tmp_path, "INACTIVE")
    code, stdout, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--kill-switch",
            str(ks),
        ],
        capsys,
    )
    assert code == 0
    assert "verdict: PASS" in stdout
    for name in _RUN_FILES:
        assert (out / name).is_file()


def test_run_with_active_kill_switch_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    ks = _write_kill_switch(tmp_path, "ACTIVE")
    code, stdout, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--kill-switch",
            str(ks),
        ],
        capsys,
    )
    assert code == 2
    assert "verdict: ESCALATE" in stdout
    assert "pack_hash" not in stdout
    envelope = _structured_error(stderr)
    assert envelope["error"] == "kill_switch"
    # No evidence files written; out dir was never created either.
    assert not out.exists() or not list(out.glob("*.json"))


@pytest.mark.parametrize(
    "bad_state", ["active", "Inactive", "KILLED", "", "ACTIVE ", 0, None]
)
def test_run_with_malformed_kill_switch_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    bad_state: object,
) -> None:
    out = tmp_path / "out"
    ks = _write_kill_switch(tmp_path, bad_state)
    code, stdout, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--kill-switch",
            str(ks),
        ],
        capsys,
    )
    assert code == 2
    assert "verdict: ESCALATE" in stdout
    envelope = _structured_error(stderr)
    assert envelope["error"] == "kill_switch"
    assert not out.exists() or not list(out.glob("*.json"))


def test_run_with_missing_kill_switch_file_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--kill-switch",
            str(tmp_path / "does-not-exist.json"),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "kill_switch"


def test_run_with_applicable_override_continues(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    ov = _write_override(tmp_path)
    code, stdout, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--override",
            str(ov),
        ],
        capsys,
    )
    assert code == 0
    assert "verdict: PASS" in stdout
    assert "override_outcome: applicable" in stdout
    for name in _RUN_FILES:
        assert (out / name).is_file()


@pytest.mark.parametrize(
    "kwargs, expected_outcome",
    [
        ({"consumed": True}, "rejected_already_consumed"),
        ({"not_after": 0}, "rejected_expired"),
        ({"applies_to_action_id": "some-other-action"}, "rejected_non_applicable"),
        ({"override_id": ""}, "rejected_structurally_invalid"),
    ],
)
def test_run_with_rejected_override_fails_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    kwargs: dict,
    expected_outcome: str,
) -> None:
    out = tmp_path / "out"
    ov = _write_override(tmp_path, **kwargs)
    code, stdout, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--override",
            str(ov),
        ],
        capsys,
    )
    assert code == 2
    assert "verdict: ESCALATE" in stdout
    assert "pack_hash" not in stdout
    envelope = _structured_error(stderr)
    assert envelope["error"] == "override"
    assert envelope["errors"][0]["code"] == expected_outcome
    # out_dir was created (for the run pre-flight) but no evidence files
    # were written.
    assert not list(out.glob("*.json"))


def test_run_with_malformed_override_field_types_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    bad = tmp_path / "bad_ov.json"
    # not_after as a string violates the OverrideDecision int type.
    bad.write_text(
        json.dumps(
            {
                "override_id": "ov-1",
                "applies_to_action_id": _safe_action_id(),
                "not_after": "not-an-int",
                "consumed": False,
                "now": 1000,
            }
        ),
        encoding="utf-8",
    )
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--override",
            str(bad),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "override"
    assert envelope["errors"][0]["code"] == "override_malformed"
    assert not list(out.glob("*.json"))


def test_run_with_override_missing_required_field_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    bad = tmp_path / "bad_ov.json"
    bad.write_text(
        json.dumps(
            {
                "override_id": "ov-1",
                # applies_to_action_id missing
                "not_after": 9999,
                "consumed": False,
                "now": 1000,
            }
        ),
        encoding="utf-8",
    )
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--override",
            str(bad),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "override"
    assert envelope["errors"][0]["code"] == "missing_field"


def test_run_with_malformed_override_json_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    bad = tmp_path / "bad_ov.json"
    bad.write_text("{not-json", encoding="utf-8")
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--override",
            str(bad),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "override"
    assert envelope["errors"][0]["code"] == "json_decode_error"


def test_kill_switch_takes_precedence_over_override(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out"
    ks = _write_kill_switch(tmp_path, "ACTIVE", name="ks.json")
    # Deliberately malformed override; kill-switch should fire first and
    # neither the override nor the gate should be evaluated.
    bad_ov = tmp_path / "ov.json"
    bad_ov.write_text("{not-json", encoding="utf-8")
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--kill-switch",
            str(ks),
            "--override",
            str(bad_ov),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "kill_switch"


def test_run_byte_stability_identical_inputs_with_override_applicable(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    ov = _write_override(tmp_path, name="ov.json")
    common = [
        "run",
        "--policy",
        str(PUBLIC_POLICY),
        "--payload",
        str(SAFE_ACTION),
        "--at",
        "2026-04-30T00:00:00Z",
        "--override",
        str(ov),
    ]
    code_a, out_text_a, _ = _run([*common, "--out", str(out_a)], capsys)
    code_b, out_text_b, _ = _run([*common, "--out", str(out_b)], capsys)
    assert code_a == 0 and code_b == 0
    # Stdout shape stable.
    assert out_text_a.replace(str(out_a), "<OUT>") == out_text_b.replace(
        str(out_b), "<OUT>"
    )
    # Evidence-pack files byte-stable across runs with the same
    # applicable override; the override recording layer is now active
    # (deterministic_facts.override is included in the canonical JSON
    # for these runs) but that does not break byte-stability when the
    # inputs are identical.
    for name in _RUN_FILES:
        assert (out_a / name).read_bytes() == (out_b / name).read_bytes(), (
            f"{name} differs across identical successful runs with override"
        )


def test_run_no_override_deterministic_facts_omits_override_key(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """When --override is not supplied, deterministic_facts canonical
    JSON MUST NOT contain the literal substring ``"override"``.

    This is the byte-level expression of the omit-when-None discipline
    that protects pack-hash byte stability for every existing pack.
    """
    out = tmp_path / "out"
    code, _, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--at",
            "2026-04-30T00:00:00Z",
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 0
    facts_bytes = (out / "deterministic_facts.json").read_bytes()
    assert b'"override"' not in facts_bytes
    pack_bytes = (out / "evidence_pack.json").read_bytes()
    # The pack-level JSON also must not carry the override key on the
    # no-override path; a leak would corrupt the back-compat anchor.
    pack = json.loads(pack_bytes)
    assert "override" not in pack["deterministic_facts"]


def test_run_with_applicable_override_records_in_deterministic_facts(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """The override decision is recorded in deterministic_facts when
    the override evaluator returned ``applicable``.
    """
    out = tmp_path / "out"
    ov = _write_override(tmp_path, override_id="ov-record-1")
    code, stdout, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--out",
            str(out),
            "--override",
            str(ov),
        ],
        capsys,
    )
    assert code == 0
    assert "override_outcome: applicable" in stdout
    pack = json.loads((out / "evidence_pack.json").read_text(encoding="utf-8"))
    assert pack["deterministic_facts"]["override"] == {
        "override_id": "ov-record-1",
        "outcome": "applicable",
    }
    # Manifest section hash must match what we would recompute for the
    # written deterministic_facts canonical JSON.
    facts_text = (out / "deterministic_facts.json").read_text(encoding="utf-8")
    import hashlib

    recomputed = hashlib.sha256(facts_text.encode("utf-8")).hexdigest()
    assert pack["manifest"]["section_hashes"]["deterministic_facts"] == recomputed


def test_run_with_applicable_override_pack_hash_differs_from_no_override(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Recording an applicable override changes the pack hash.

    This is the dual of the back-compat anchor: with --override the
    pack hash MUST differ from the no-override baseline (recording is
    active and observable).
    """
    out_no = tmp_path / "no"
    out_with = tmp_path / "with"
    ov = _write_override(tmp_path, override_id="ov-diff-1")
    base = [
        "run",
        "--policy",
        str(PUBLIC_POLICY),
        "--payload",
        str(SAFE_ACTION),
        "--at",
        "2026-04-30T00:00:00Z",
    ]
    code_no, stdout_no, _ = _run([*base, "--out", str(out_no)], capsys)
    code_with, stdout_with, _ = _run(
        [*base, "--out", str(out_with), "--override", str(ov)], capsys
    )
    assert code_no == 0 and code_with == 0
    h_no = _parse_pack_hash(stdout_no)
    h_with = _parse_pack_hash(stdout_with)
    assert h_with != h_no


def test_run_with_applicable_override_byte_stable_across_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Two runs with the same applicable override produce byte-identical
    pack files.
    """
    out_a = tmp_path / "a"
    out_b = tmp_path / "b"
    ov = _write_override(tmp_path, override_id="ov-stability-1")
    common = [
        "run",
        "--policy",
        str(PUBLIC_POLICY),
        "--payload",
        str(SAFE_ACTION),
        "--at",
        "2026-04-30T00:00:00Z",
        "--override",
        str(ov),
    ]
    code_a, _, _ = _run([*common, "--out", str(out_a)], capsys)
    code_b, _, _ = _run([*common, "--out", str(out_b)], capsys)
    assert code_a == 0 and code_b == 0
    for name in _RUN_FILES:
        assert (out_a / name).read_bytes() == (out_b / name).read_bytes()


def test_run_help_documents_kill_switch_and_override_flags() -> None:
    parser = demo_cli._build_parser()
    help_text = parser.format_help()
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for choice_parser in action.choices.values():
                help_text += "\n" + choice_parser.format_help()
    assert "--kill-switch" in help_text
    assert "--override" in help_text


# ---------------------------------------------------------------------------
# Override-aware replay in --verify mode.
# ---------------------------------------------------------------------------


def _build_pack_no_override(tmp_path: Path, capsys: pytest.CaptureFixture) -> Path:
    """Produce an evidence pack without any --override (back-compat)."""
    out = tmp_path / "no_ov_pack"
    code, _, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--at",
            "2026-04-30T00:00:00Z",
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 0, "no-override pack production failed"
    return out / "evidence_pack.json"


def _build_pack_with_override(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    override_id: str = "ov-1",
) -> tuple[Path, Path]:
    """Produce an evidence pack via `run --override` and return the
    (pack_path, override_json_path) pair."""
    out = tmp_path / f"ov_pack_{override_id}"
    ov = _write_override(
        tmp_path, override_id=override_id, name=f"ov_{override_id}.json"
    )
    code, _, _ = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--at",
            "2026-04-30T00:00:00Z",
            "--override",
            str(ov),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 0, "with-override pack production failed"
    return out / "evidence_pack.json", ov


def test_verify_cli_no_override_inputs_on_no_override_pack_is_back_compat(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path = _build_pack_no_override(tmp_path, capsys)
    code, stdout, _ = _run(["verify", "--evidence-in", str(pack_path)], capsys)
    assert code == 0
    assert "verify_status: PASS" in stdout
    assert "replay_status: NOT_REPLAYABLE" in stdout
    # New override-replay channel reports OVERRIDE_NOT_PRESENT.
    assert "override_replay_status: OVERRIDE_NOT_PRESENT" in stdout


def test_verify_cli_no_override_inputs_on_with_override_pack(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, _ = _build_pack_with_override(tmp_path, capsys)
    code, stdout, _ = _run(["verify", "--evidence-in", str(pack_path)], capsys)
    assert code == 0
    assert "verify_status: PASS" in stdout
    assert "override_replay_status: OVERRIDE_NOT_REPLAYABLE" in stdout


def test_verify_cli_matching_override_inputs_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, ov = _build_pack_with_override(tmp_path, capsys, override_id="ov-match")
    code, stdout, _ = _run(
        ["verify", "--evidence-in", str(pack_path), "--override", str(ov)],
        capsys,
    )
    assert code == 0
    assert "verify_status: PASS" in stdout
    assert "override_replay_status: OVERRIDE_REPLAY_PASS" in stdout


def test_verify_cli_id_mismatch_override_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, _ = _build_pack_with_override(
        tmp_path, capsys, override_id="ov-recorded"
    )
    other_ov = _write_override(
        tmp_path, override_id="ov-DIFFERENT", name="ov_other.json"
    )
    code, stdout, _ = _run(
        [
            "verify",
            "--evidence-in",
            str(pack_path),
            "--override",
            str(other_ov),
        ],
        capsys,
    )
    assert code == 2
    assert "verify_status: PASS" in stdout
    assert "override_replay_status: OVERRIDE_REPLAY_FAIL" in stdout
    assert "override_id mismatch" in stdout


def test_verify_cli_outcome_mismatch_override_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, _ = _build_pack_with_override(
        tmp_path, capsys, override_id="ov-applicable"
    )
    expired_ov = _write_override(
        tmp_path,
        override_id="ov-applicable",
        not_after=500,
        now=1000,
        name="ov_expired.json",
    )
    code, stdout, _ = _run(
        [
            "verify",
            "--evidence-in",
            str(pack_path),
            "--override",
            str(expired_ov),
        ],
        capsys,
    )
    assert code == 2
    assert "override_replay_status: OVERRIDE_REPLAY_FAIL" in stdout
    assert "outcome mismatch" in stdout


def test_verify_cli_override_inputs_on_no_override_pack_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path = _build_pack_no_override(tmp_path, capsys)
    ov = _write_override(tmp_path, override_id="ov-asserted", name="ov_assert.json")
    code, stdout, _ = _run(
        ["verify", "--evidence-in", str(pack_path), "--override", str(ov)],
        capsys,
    )
    assert code == 2
    assert "override_replay_status: OVERRIDE_REPLAY_FAIL" in stdout
    assert "no recorded override" in stdout


def test_verify_cli_malformed_override_file_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path = _build_pack_no_override(tmp_path, capsys)
    bad_ov = tmp_path / "bad_ov.json"
    bad_ov.write_text("{not-json", encoding="utf-8")
    code, _, stderr = _run(
        ["verify", "--evidence-in", str(pack_path), "--override", str(bad_ov)],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "override"


def test_verify_cli_help_documents_override_flag() -> None:
    parser = demo_cli._build_parser()
    # Pull verify subparser help only.
    verify_help = ""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            verify_help = action.choices["verify"].format_help()
    assert "--override" in verify_help


# ---------------------------------------------------------------------------
# Override-consumption ledger (--ledger flag on run subcommand).
# ---------------------------------------------------------------------------

_GENESIS_PREV_HASH = "0" * 64


def _ledger_run_args(
    *,
    out: Path,
    override_path: Path | None,
    ledger_path: Path | None,
    at: str | None = "2026-04-30T00:00:00Z",
    payload: Path = SAFE_ACTION,
) -> list[str]:
    args = [
        "run",
        "--policy",
        str(PUBLIC_POLICY),
        "--payload",
        str(payload),
        "--out",
        str(out),
    ]
    if at is not None:
        args.extend(["--at", at])
    if override_path is not None:
        args.extend(["--override", str(override_path)])
    if ledger_path is not None:
        args.extend(["--ledger", str(ledger_path)])
    return args


def test_ledger_a_creates_new_chain_on_fresh_path(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out_a"
    ov = _write_override(tmp_path, override_id="ov-A")
    chain_path = tmp_path / "chain_a.json"  # does NOT exist yet
    code, stdout, _ = _run(
        _ledger_run_args(out=out, override_path=ov, ledger_path=chain_path),
        capsys,
    )
    assert code == 0
    assert "verdict: PASS" in stdout
    assert "ledger_sequence: 0" in stdout
    assert re.search(r"^ledger_entry_hash: [0-9a-f]{64}$", stdout, re.MULTILINE)
    assert f"ledger_path: {chain_path}" in stdout

    assert chain_path.is_file()
    chain = json.loads(chain_path.read_text(encoding="utf-8"))
    assert isinstance(chain, list)
    assert len(chain) == 1
    entry = chain[0]
    assert entry["sequence"] == 0
    assert entry["prev_hash"] == _GENESIS_PREV_HASH
    pack = json.loads((out / "evidence_pack.json").read_text(encoding="utf-8"))
    assert entry["pack_hash"] == pack["manifest"]["pack_hash"]
    # entry_hash matches recomputation: same SHA-256 as the canonical
    # envelope we just stored.
    import hashlib

    envelope = {
        "sequence": entry["sequence"],
        "pack_hash": entry["pack_hash"],
        "prev_hash": entry["prev_hash"],
        "append_time": entry["append_time"],
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    assert entry["entry_hash"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_ledger_b_extends_existing_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    chain_path = tmp_path / "chain_b.json"
    ov = _write_override(tmp_path, override_id="ov-B")
    out_first = tmp_path / "out_b1"
    out_second = tmp_path / "out_b2"
    code1, _, _ = _run(
        _ledger_run_args(
            out=out_first,
            override_path=ov,
            ledger_path=chain_path,
            at="2026-04-30T00:00:00Z",
        ),
        capsys,
    )
    code2, stdout2, _ = _run(
        _ledger_run_args(
            out=out_second,
            override_path=ov,
            ledger_path=chain_path,
            at="2026-04-30T00:01:00Z",
        ),
        capsys,
    )
    assert code1 == 0 and code2 == 0
    assert "ledger_sequence: 1" in stdout2
    chain = json.loads(chain_path.read_text(encoding="utf-8"))
    assert len(chain) == 2
    assert chain[0]["sequence"] == 0
    assert chain[1]["sequence"] == 1
    # prior-hash chaining holds.
    assert chain[1]["prev_hash"] == chain[0]["entry_hash"]


def test_ledger_c_byte_identical_across_runs_with_same_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    ov = _write_override(tmp_path, override_id="ov-C")
    out_a = tmp_path / "out_ca"
    out_b = tmp_path / "out_cb"
    chain_a = tmp_path / "chain_ca.json"
    chain_b = tmp_path / "chain_cb.json"
    _run(
        _ledger_run_args(
            out=out_a,
            override_path=ov,
            ledger_path=chain_a,
            at="2026-04-30T00:00:00Z",
        ),
        capsys,
    )
    _run(
        _ledger_run_args(
            out=out_b,
            override_path=ov,
            ledger_path=chain_b,
            at="2026-04-30T00:00:00Z",
        ),
        capsys,
    )
    assert chain_a.read_bytes() == chain_b.read_bytes()


def test_ledger_d_without_override_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out_d"
    chain = tmp_path / "chain_d.json"
    code, _, stderr = _run(
        _ledger_run_args(out=out, override_path=None, ledger_path=chain),
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "ledger"
    assert envelope["errors"][0]["code"] == "requires_override"
    assert not chain.exists()
    assert not list(out.glob("*.json")) if out.exists() else True


def test_ledger_e_without_at_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out_e"
    chain = tmp_path / "chain_e.json"
    ov = _write_override(tmp_path, override_id="ov-E")
    code, _, stderr = _run(
        _ledger_run_args(out=out, override_path=ov, ledger_path=chain, at=None),
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "ledger"
    assert envelope["errors"][0]["code"] == "requires_at"
    assert not chain.exists()


def test_ledger_f_malformed_json_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    chain = tmp_path / "chain_f.json"
    chain.write_text("{not-json", encoding="utf-8")
    original_bytes = chain.read_bytes()
    out = tmp_path / "out_f"
    ov = _write_override(tmp_path, override_id="ov-F")
    code, _, stderr = _run(
        _ledger_run_args(out=out, override_path=ov, ledger_path=chain),
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "ledger"
    assert envelope["errors"][0]["code"] == "json_decode_error"
    # File untouched.
    assert chain.read_bytes() == original_bytes
    assert not list(out.glob("*.json")) if out.exists() else True


def test_ledger_g_non_array_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    chain = tmp_path / "chain_g.json"
    chain.write_text(json.dumps({"not": "an array"}), encoding="utf-8")
    out = tmp_path / "out_g"
    ov = _write_override(tmp_path, override_id="ov-G")
    code, _, stderr = _run(
        _ledger_run_args(out=out, override_path=ov, ledger_path=chain),
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "ledger"
    assert envelope["errors"][0]["code"] == "not_array"


def test_ledger_h_tampered_chain_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    # Build a one-entry chain via a normal run.
    ov = _write_override(tmp_path, override_id="ov-H")
    chain = tmp_path / "chain_h.json"
    out_first = tmp_path / "out_h1"
    code, _, _ = _run(
        _ledger_run_args(out=out_first, override_path=ov, ledger_path=chain),
        capsys,
    )
    assert code == 0
    # Tamper with pack_hash on the only entry (breaks recomputed hash).
    raw = json.loads(chain.read_text(encoding="utf-8"))
    raw[0]["pack_hash"] = "f" * 64
    chain.write_text(
        json.dumps(raw, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    tampered_bytes = chain.read_bytes()
    # Re-run, attempting to extend the broken chain.
    out_second = tmp_path / "out_h2"
    code2, _, stderr = _run(
        _ledger_run_args(
            out=out_second,
            override_path=ov,
            ledger_path=chain,
            at="2026-04-30T00:01:00Z",
        ),
        capsys,
    )
    assert code2 == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "ledger"
    codes = {row["code"] for row in envelope["errors"]}
    assert codes & {"hash_mismatch", "broken_chain", "schema_violation"}, codes
    # Tampered file is unchanged (we refuse to extend a broken chain).
    assert chain.read_bytes() == tampered_bytes


def test_ledger_i_pack_hash_unchanged_when_ledger_added(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Adding --ledger MUST NOT change the evidence pack bytes."""
    ov_path = _write_override(tmp_path, override_id="ov-anchor-1")
    out_no_ledger = tmp_path / "out_no_ledger"
    out_with_ledger = tmp_path / "out_with_ledger"
    chain = tmp_path / "chain_i.json"
    code_no, stdout_no, _ = _run(
        _ledger_run_args(out=out_no_ledger, override_path=ov_path, ledger_path=None),
        capsys,
    )
    code_with, stdout_with, _ = _run(
        _ledger_run_args(out=out_with_ledger, override_path=ov_path, ledger_path=chain),
        capsys,
    )
    assert code_no == 0 and code_with == 0
    # The two pack-hashes must match each other (run-to-run
    # determinism with vs. without --ledger).
    assert _parse_pack_hash(stdout_no) == _parse_pack_hash(stdout_with)
    # All four pack-related files byte-identical between the two runs.
    for name in _RUN_FILES:
        assert (out_no_ledger / name).read_bytes() == (
            out_with_ledger / name
        ).read_bytes(), f"{name} differs depending on --ledger"


def test_ledger_k_help_documents_ledger_flag() -> None:
    parser = demo_cli._build_parser()
    run_help = ""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            run_help = action.choices["run"].format_help()
    assert "--ledger" in run_help


def test_ledger_l_kill_switch_takes_precedence_over_ledger(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out = tmp_path / "out_l"
    ov = _write_override(tmp_path, override_id="ov-L")
    chain = tmp_path / "chain_l.json"
    ks = _write_kill_switch(tmp_path, "ACTIVE", name="ks_l.json")
    code, _, stderr = _run(
        [
            "run",
            "--policy",
            str(PUBLIC_POLICY),
            "--payload",
            str(SAFE_ACTION),
            "--at",
            "2026-04-30T00:00:00Z",
            "--kill-switch",
            str(ks),
            "--override",
            str(ov),
            "--ledger",
            str(chain),
            "--out",
            str(out),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "kill_switch"
    # Ledger never created.
    assert not chain.exists()
    # No evidence files.
    assert not list(out.glob("*.json")) if out.exists() else True


# ---------------------------------------------------------------------------
# Verify-mode ``--ledger``: ledger-aware replay channel.
# ---------------------------------------------------------------------------


def _produce_pack_with_ledger(
    tmp_path: Path,
    capsys: pytest.CaptureFixture,
    *,
    out_name: str = "out_p",
    chain_name: str = "chain_p.json",
    ov_id: str = "ov-VR",
    at: str = "2026-04-30T00:00:00Z",
) -> tuple[Path, Path]:
    """Drive a run-mode invocation that produces both an evidence pack and
    a ledger entry for it. Returns (evidence_pack_path, chain_path)."""
    out = tmp_path / out_name
    chain = tmp_path / chain_name
    ov = _write_override(tmp_path, override_id=ov_id, name=f"{ov_id}.json")
    code, _, _ = _run(
        _ledger_run_args(out=out, override_path=ov, ledger_path=chain, at=at),
        capsys,
    )
    assert code == 0
    pack_path = out / "evidence_pack.json"
    assert pack_path.is_file()
    assert chain.is_file()
    return pack_path, chain


def test_verify_ledger_h_pass_subcommand(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, chain_path = _produce_pack_with_ledger(tmp_path, capsys)
    code, out, _ = _run(
        [
            "verify",
            "--evidence-in",
            str(pack_path),
            "--ledger",
            str(chain_path),
        ],
        capsys,
    )
    assert code == 0
    assert "verify_status: PASS" in out
    assert "ledger_replay_status: LEDGER_REPLAY_PASS" in out
    assert re.search(r"^ledger_replay_sequence: 0$", out, re.MULTILINE)
    assert re.search(r"^ledger_replay_prev_hash: [0-9a-f]{64}$", out, re.MULTILINE)
    assert re.search(r"^ledger_replay_entry_hash: [0-9a-f]{64}$", out, re.MULTILINE)


def test_verify_ledger_h_pass_flat_arg(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, chain_path = _produce_pack_with_ledger(tmp_path, capsys)
    code, out, _ = _run(
        [
            "--verify",
            "--evidence-in",
            str(pack_path),
            "--ledger",
            str(chain_path),
        ],
        capsys,
    )
    assert code == 0
    assert "ledger_replay_status: LEDGER_REPLAY_PASS" in out


def test_verify_ledger_i_fail_with_different_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, _ = _produce_pack_with_ledger(
        tmp_path, capsys, out_name="out_a", chain_name="chain_a.json", ov_id="ov-IA"
    )
    # Build a second, independent chain (different override_id ⇒ different
    # pack ⇒ different pack_hash inside).
    _, chain_b_path = _produce_pack_with_ledger(
        tmp_path, capsys, out_name="out_b", chain_name="chain_b.json", ov_id="ov-IB"
    )
    code, out, _ = _run(
        [
            "verify",
            "--evidence-in",
            str(pack_path),
            "--ledger",
            str(chain_b_path),
        ],
        capsys,
    )
    assert code == 2
    assert "ledger_replay_status: LEDGER_REPLAY_FAIL" in out
    assert "ledger_replay_reason: pack_hash not in chain" in out


def test_verify_ledger_j_missing_path_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, _ = _produce_pack_with_ledger(tmp_path, capsys)
    nonexistent = tmp_path / "no_such_chain.json"
    assert not nonexistent.exists()
    code, _, stderr = _run(
        [
            "verify",
            "--evidence-in",
            str(pack_path),
            "--ledger",
            str(nonexistent),
        ],
        capsys,
    )
    assert code == 2
    envelope = _structured_error(stderr)
    assert envelope["error"] == "ledger"
    assert envelope["errors"][0]["code"] == "read_error"
    assert not nonexistent.exists()


def test_verify_ledger_k_back_compat_without_ledger(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    """Without --ledger, verify mode prints LEDGER_NOT_REPLAYABLE and
    existing channel lines remain in shape."""
    ev_file = tmp_path / "ev.json"
    _produce_evidence(SAFE_ACTION, ev_file, capsys)
    code, out, _ = _run(["--verify", "--evidence-in", str(ev_file)], capsys)
    assert code == 0
    assert "verify_status: PASS" in out
    assert re.search(r"^replay_status: NOT_REPLAYABLE$", out, re.MULTILINE)
    assert re.search(
        r"^override_replay_status: OVERRIDE_NOT_PRESENT$", out, re.MULTILINE
    )
    assert re.search(
        r"^ledger_replay_status: LEDGER_NOT_REPLAYABLE$", out, re.MULTILINE
    )


def test_verify_ledger_l_all_four_channels_pass(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    pack_path, chain_path = _produce_pack_with_ledger(tmp_path, capsys, ov_id="ov-LL")
    ov_for_verify = _write_override(
        tmp_path, override_id="ov-LL", name="ov_for_verify.json"
    )
    code, out, _ = _run(
        [
            "verify",
            "--evidence-in",
            str(pack_path),
            "--policy",
            str(PUBLIC_POLICY),
            "--action",
            str(SAFE_ACTION),
            "--override",
            str(ov_for_verify),
            "--ledger",
            str(chain_path),
        ],
        capsys,
    )
    assert code == 0
    assert "verify_status: PASS" in out
    assert "replay_status: REPLAY_PASS" in out
    assert "override_replay_status: OVERRIDE_REPLAY_PASS" in out
    assert "ledger_replay_status: LEDGER_REPLAY_PASS" in out


def test_verify_ledger_m_help_documents_ledger_flag() -> None:
    parser = demo_cli._build_parser()
    verify_help = ""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            verify_help = action.choices["verify"].format_help()
    assert "--ledger" in verify_help


# ---------------------------------------------------------------------------
# Native diff-input mode (check mode --diff)
# ---------------------------------------------------------------------------

DIFFS = EXAMPLES / "diffs"
DIFF_POLICY = EXAMPLES / "policies" / "diff.yaml"
SAFE_DIFF = DIFFS / "safe_docs.diff"
PRIVATE_PATH_DIFF = DIFFS / "private_path.diff"
WORKFLOW_DIFF = DIFFS / "workflow.diff"
MALFORMED_DIFF = REPO_ROOT / "tests" / "fixtures" / "diffs" / "malformed.diff"


def test_diff_safe_docs_returns_pass_and_exit_0(
    capsys: pytest.CaptureFixture,
) -> None:
    code, out, _ = _run(
        ["--policy", str(DIFF_POLICY), "--diff", str(SAFE_DIFF)], capsys
    )
    assert code == 0
    assert "verdict: PASS" in out
    assert re.search(r"^pack_hash: [0-9a-f]{64}$", out, re.MULTILINE)


def test_diff_private_path_returns_fix_and_exit_1(
    capsys: pytest.CaptureFixture,
) -> None:
    code, out, _ = _run(
        ["--policy", str(DIFF_POLICY), "--diff", str(PRIVATE_PATH_DIFF)], capsys
    )
    assert code == 1
    assert "verdict: FIX" in out
    assert "machine_local_path_in_added_lines" in out


def test_diff_workflow_with_t4_returns_escalate_and_exit_2(
    capsys: pytest.CaptureFixture,
) -> None:
    code, out, _ = _run(
        [
            "--policy", str(DIFF_POLICY),
            "--diff", str(WORKFLOW_DIFF),
            "--risk-tier", "T4",
        ],
        capsys,
    )
    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "decision: override_required" in out


def test_diff_workflow_at_t1_passes_without_caller_supplied_t4(
    capsys: pytest.CaptureFixture,
) -> None:
    # The engine does NOT auto-detect elevated-blast-radius paths in this
    # slice. Without --risk-tier T4 the workflow diff is just another diff
    # whose added lines do not match the path-leak gate.
    code, out, _ = _run(
        ["--policy", str(DIFF_POLICY), "--diff", str(WORKFLOW_DIFF)], capsys
    )
    assert code == 0
    assert "verdict: PASS" in out


def test_diff_and_action_mutually_exclusive(
    capsys: pytest.CaptureFixture,
) -> None:
    code, out, err = _run(
        [
            "--policy", str(DIFF_POLICY),
            "--diff", str(SAFE_DIFF),
            "--action", str(SAFE_ACTION),
        ],
        capsys,
    )
    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "mutually exclusive" in err


def test_diff_evidence_out_writes_action_sidecar(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_file = tmp_path / "evidence.json"
    code, out, _ = _run(
        [
            "--policy", str(DIFF_POLICY),
            "--diff", str(SAFE_DIFF),
            "--evidence-out", str(out_file),
        ],
        capsys,
    )
    assert code == 0
    assert out_file.exists()

    sidecar = out_file.with_suffix(out_file.suffix + ".action.json")
    assert sidecar.exists()
    assert f"action_sidecar_path: {sidecar}" in out

    sidecar_data = json.loads(sidecar.read_text(encoding="utf-8"))
    for k in ("id", "type", "target", "risk_tier", "timestamp",
              "agent_id", "session_id", "inputs"):
        assert k in sidecar_data, f"sidecar missing required field {k!r}"
    assert sidecar_data["type"] == "diff.apply"
    assert sidecar_data["target"] == "README.md"
    assert "diff_hash" in sidecar_data["inputs"]


def test_action_mode_does_not_write_sidecar(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_file = tmp_path / "evidence.json"
    code, _, _ = _run(
        [
            "--policy", str(PUBLIC_POLICY),
            "--action", str(SAFE_ACTION),
            "--evidence-out", str(out_file),
        ],
        capsys,
    )
    assert code == 0
    sidecar = out_file.with_suffix(out_file.suffix + ".action.json")
    assert not sidecar.exists(), "sidecar must only be written in --diff mode"


def test_diff_pack_hash_stable_across_runs(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    out_a = tmp_path / "a.json"
    out_b = tmp_path / "b.json"
    common = ["--policy", str(DIFF_POLICY), "--diff", str(SAFE_DIFF),
              "--at", "2026-05-05T00:00:00+00:00"]
    code_a, _, _ = _run([*common, "--evidence-out", str(out_a)], capsys)
    code_b, _, _ = _run([*common, "--evidence-out", str(out_b)], capsys)
    assert code_a == 0 and code_b == 0
    assert out_a.read_bytes() == out_b.read_bytes(), (
        "pack bytes must be identical for identical --diff + --policy + --at"
    )


def test_diff_malformed_fails_closed_exit_2(
    capsys: pytest.CaptureFixture,
) -> None:
    code, out, err = _run(
        ["--policy", str(DIFF_POLICY), "--diff", str(MALFORMED_DIFF)], capsys
    )
    assert code == 2
    assert "verdict: ESCALATE" in out
    assert "DiffAdapterError" in err


def test_diff_verify_replay_via_sidecar(
    tmp_path: Path, capsys: pytest.CaptureFixture
) -> None:
    # Produce evidence + sidecar via --diff, then verify+replay using the
    # sidecar action JSON (--diff is intentionally NOT supported in verify
    # mode in this slice; the sidecar covers the round-trip).
    out_file = tmp_path / "evidence.json"
    sidecar = out_file.with_suffix(out_file.suffix + ".action.json")

    code_check, _, _ = _run(
        [
            "--policy", str(DIFF_POLICY),
            "--diff", str(SAFE_DIFF),
            "--evidence-out", str(out_file),
        ],
        capsys,
    )
    assert code_check == 0
    assert sidecar.exists()

    code_verify, out_verify, _ = _run(
        [
            "--verify",
            "--evidence-in", str(out_file),
            "--policy", str(DIFF_POLICY),
            "--action", str(sidecar),
        ],
        capsys,
    )
    assert code_verify == 0
    assert "verify_status: PASS" in out_verify
    assert "replay_status: REPLAY_PASS" in out_verify


def test_diff_help_documents_caller_supplied_t4_and_no_repo_scanning() -> None:
    # The CLI help text must be honest: T4 escalation is caller-supplied
    # and the diff adapter is described as explicit pattern detection
    # inside the diff, not "scanning" or "semantic" review. argparse wraps
    # long strings, so compare against whitespace-collapsed help.
    parser = demo_cli._build_parser()
    top_help = parser.format_help()
    flat = re.sub(r"\s+", " ", top_help)
    assert "--diff" in flat
    assert "--risk-tier" in flat
    assert "Explicit pattern detection inside the diff" in flat
    assert "not semantic code review" in flat
    assert "not repo scanning" in flat
    assert "engine does NOT auto-detect" in flat
