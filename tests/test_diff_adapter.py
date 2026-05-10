"""Unit tests for the deterministic diff-to-action adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from latchpoint_core.diff_adapter import (
    DEFAULT_TIMESTAMP,
    DiffAdapterError,
    derive_sidecar_path,
    diff_to_action,
    parse_unified_diff,
)


_SAFE_DOCS = (
    "diff --git a/README.md b/README.md\n"
    "index 0000001..0000002 100644\n"
    "--- a/README.md\n"
    "+++ b/README.md\n"
    "@@ -1,3 +1,3 @@\n"
    " # Project\n"
    "-A typo here.\n"
    "+A typo fixed.\n"
    " End.\n"
)

_PRIVATE_PATH = (
    "diff --git a/src/loader.py b/src/loader.py\n"
    "index 0000003..0000004 100644\n"
    "--- a/src/loader.py\n"
    "+++ b/src/loader.py\n"
    "@@ -1,5 +1,7 @@\n"
    " def load_secrets():\n"
    "-    return {}\n"
    "+    # convenience default for local dev\n"
    '+    path = "/Users/example/project/SECRETS.txt"\n'
    "+    return open(path).read()\n"
    "\n"
    " def main():\n"
    "     print(load_secrets())\n"
)

_WORKFLOW = (
    "diff --git a/.github/workflows/release.yml b/.github/workflows/release.yml\n"
    "index 0000005..0000006 100644\n"
    "--- a/.github/workflows/release.yml\n"
    "+++ b/.github/workflows/release.yml\n"
    "@@ -10,8 +10,6 @@ jobs:\n"
    "   deploy:\n"
    "     runs-on: ubuntu-latest\n"
    "     needs: build\n"
    "-    environment:\n"
    "-      name: production-approval\n"
    "     steps:\n"
    "       - uses: actions/checkout@v4\n"
    "       - run: ./scripts/deploy.sh production\n"
)

_MULTIFILE = (
    "diff --git a/a.py b/a.py\n"
    "index 1..2 100644\n"
    "--- a/a.py\n"
    "+++ b/a.py\n"
    "@@ -0,0 +1 @@\n"
    "+x = 1\n"
    "diff --git a/b.py b/b.py\n"
    "index 3..4 100644\n"
    "--- a/b.py\n"
    "+++ b/b.py\n"
    "@@ -0,0 +1 @@\n"
    "+y = 2\n"
)

_RENAME = (
    "diff --git a/old.py b/new.py\n"
    "similarity index 100%\n"
    "rename from old.py\n"
    "rename to new.py\n"
)

_BINARY = (
    "diff --git a/logo.png b/logo.png\n"
    "index aaa..bbb 100644\n"
    "Binary files a/logo.png and b/logo.png differ\n"
)


# --- parse_unified_diff -----------------------------------------------------


def test_parse_safe_docs_basic_shape() -> None:
    parsed = parse_unified_diff(_SAFE_DOCS)
    assert parsed["changed_paths"] == ["README.md"]
    assert parsed["changed_paths_blob"] == "README.md"
    assert "A typo fixed." in parsed["added_lines"]
    assert "A typo here." in parsed["removed_lines"]
    assert parsed["added_line_count"] == 1
    assert parsed["removed_line_count"] == 1
    assert parsed["file_count"] == 1


def test_parse_private_path_added_lines_carry_literal() -> None:
    parsed = parse_unified_diff(_PRIVATE_PATH)
    assert parsed["changed_paths"] == ["src/loader.py"]
    assert "/Users/example/project/SECRETS.txt" in parsed["added_lines"]


def test_parse_workflow_changed_paths() -> None:
    parsed = parse_unified_diff(_WORKFLOW)
    assert parsed["changed_paths"] == [".github/workflows/release.yml"]
    assert "production-approval" in parsed["removed_lines"]


def test_parse_multifile_preserves_order() -> None:
    parsed = parse_unified_diff(_MULTIFILE)
    assert parsed["changed_paths"] == ["a.py", "b.py"]
    assert parsed["changed_paths_blob"] == "a.py\nb.py"
    assert parsed["added_lines"] == "x = 1\ny = 2"


def test_parse_rename_captures_new_path() -> None:
    parsed = parse_unified_diff(_RENAME)
    assert "new.py" in parsed["changed_paths"]
    assert parsed["added_line_count"] == 0
    assert parsed["removed_line_count"] == 0


def test_parse_binary_records_path_no_lines() -> None:
    parsed = parse_unified_diff(_BINARY)
    assert parsed["changed_paths"] == ["logo.png"]
    assert parsed["added_lines"] == ""
    assert parsed["removed_lines"] == ""


def test_parse_empty_raises() -> None:
    with pytest.raises(DiffAdapterError, match="empty"):
        parse_unified_diff("")
    with pytest.raises(DiffAdapterError, match="empty"):
        parse_unified_diff("   \n\t\n")


def test_parse_no_changed_paths_raises() -> None:
    with pytest.raises(DiffAdapterError, match="no changed paths"):
        parse_unified_diff("@@ -1,1 +1,1 @@\n-x\n+y\n")


# --- diff_to_action ---------------------------------------------------------


def _write(tmp_path: Path, name: str, text: str) -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_diff_to_action_returns_validatable_mapping(tmp_path: Path) -> None:
    diff_path = _write(tmp_path, "safe.diff", _SAFE_DOCS)
    action = diff_to_action(diff_path)
    # Required ActionDescriptor fields
    for k in ("id", "type", "target", "risk_tier", "timestamp", "agent_id", "session_id"):
        assert k in action and isinstance(action[k], str) and action[k]
    assert action["type"] == "diff.apply"
    assert action["target"] == "README.md"
    assert action["risk_tier"] == "T1"  # default
    assert action["timestamp"] == DEFAULT_TIMESTAMP

    inputs = action["inputs"]
    assert inputs["changed_paths"] == ["README.md"]
    assert isinstance(inputs["diff_hash"], str) and len(inputs["diff_hash"]) == 64
    assert "1 file(s)" in inputs["diff_summary"]


def test_diff_to_action_byte_stable_across_calls(tmp_path: Path) -> None:
    diff_path = _write(tmp_path, "safe.diff", _SAFE_DOCS)
    a = diff_to_action(diff_path, risk_tier="T1", at="2026-05-05T00:00:00+00:00")
    b = diff_to_action(diff_path, risk_tier="T1", at="2026-05-05T00:00:00+00:00")
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_diff_to_action_id_changes_with_risk_tier(tmp_path: Path) -> None:
    diff_path = _write(tmp_path, "safe.diff", _SAFE_DOCS)
    t1 = diff_to_action(diff_path, risk_tier="T1")
    t4 = diff_to_action(diff_path, risk_tier="T4")
    assert t1["id"] != t4["id"]


def test_diff_to_action_id_changes_with_at(tmp_path: Path) -> None:
    diff_path = _write(tmp_path, "safe.diff", _SAFE_DOCS)
    a = diff_to_action(diff_path, at="2026-01-01T00:00:00+00:00")
    b = diff_to_action(diff_path, at="2026-02-01T00:00:00+00:00")
    assert a["id"] != b["id"]


def test_diff_to_action_rejects_invalid_risk_tier(tmp_path: Path) -> None:
    diff_path = _write(tmp_path, "safe.diff", _SAFE_DOCS)
    with pytest.raises(DiffAdapterError, match="risk_tier"):
        diff_to_action(diff_path, risk_tier="T9")


def test_diff_to_action_rejects_empty_metadata(tmp_path: Path) -> None:
    diff_path = _write(tmp_path, "safe.diff", _SAFE_DOCS)
    with pytest.raises(DiffAdapterError, match="agent_id"):
        diff_to_action(diff_path, agent_id="")
    with pytest.raises(DiffAdapterError, match="session_id"):
        diff_to_action(diff_path, session_id="")
    with pytest.raises(DiffAdapterError, match="at"):
        diff_to_action(diff_path, at="")


def test_diff_to_action_rejects_empty_diff(tmp_path: Path) -> None:
    diff_path = _write(tmp_path, "empty.diff", "")
    with pytest.raises(DiffAdapterError, match="empty"):
        diff_to_action(diff_path)


def test_diff_to_action_rejects_unreadable_path(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.diff"
    with pytest.raises(DiffAdapterError, match="cannot read"):
        diff_to_action(missing)


def test_derive_sidecar_path() -> None:
    p = Path("/tmp/some/evidence.json")
    assert derive_sidecar_path(p).name == "evidence.json.action.json"
