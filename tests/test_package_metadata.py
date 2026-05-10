"""Tests that the top-level package __version__ stays in sync with the
distribution version declared in pyproject.toml. Stdlib only."""

import tomllib
from pathlib import Path

import latchpoint_core


def test_version_matches_pyproject() -> None:
    pyproject_path = Path(__file__).resolve().parent.parent / "pyproject.toml"
    with pyproject_path.open("rb") as fh:
        data = tomllib.load(fh)
    assert latchpoint_core.__version__ == data["project"]["version"]
