"""Deterministic diff-to-action translation.

This module translates a unified-diff string into an ``ActionDescriptor``-shaped
mapping suitable for the gate evaluator. It performs **explicit
pattern detection inside the diff** — namely extraction of changed paths and
added/removed line content — and computes a stable SHA-256 ``diff_hash`` over
the input bytes. It is **not** semantic code review and does **not** scan a
repository; the only input the adapter sees is the unified-diff text the caller
supplies.

Determinism contract:

* Pure function. No clock reads, no randomness, no network, no subprocess.
* Identical diff bytes plus identical caller-supplied non-diff inputs
  (``risk_tier``, ``at``) produce a byte-identical action mapping (and
  therefore a byte-identical evidence pack).
* ``action_id`` is derived deterministically from a fixed UUID namespace and
  the input fingerprint (``diff_hash`` + ``risk_tier`` + ``at``); the system
  clock is never read.
* ``agent_id`` and ``session_id`` are fixed sentinels (``"diff"``).

Verdict routing (engine-side, unchanged):

* No gate fires plus ``risk_tier`` not ``T4`` → PASS.
* A FAIL gate fires (e.g., regex on ``inputs.added_lines`` matches a
  forbidden literal) → FIX.
* No FAIL gate fires plus ``risk_tier == "T4"`` → ESCALATE (the engine's
  built-in ``override_required`` default; the caller chooses ``T4`` to
  request human review of an elevated-blast-radius change).
"""

from __future__ import annotations

import hashlib
import uuid
from pathlib import Path
from typing import Any

from .action_model import RISK_TIERS

__all__ = (
    "DEFAULT_AGENT_ID",
    "DEFAULT_SESSION_ID",
    "DEFAULT_TIMESTAMP",
    "DiffAdapterError",
    "diff_to_action",
    "parse_unified_diff",
)

# Fixed UUID namespace used to derive deterministic action_ids from the
# diff fingerprint. Bumping this constant would invalidate every previously
# recorded action_id; treat as load-bearing.
_DIFF_NAMESPACE = uuid.UUID("00000000-0000-5000-8000-d1ff00000001")

DEFAULT_AGENT_ID: str = "diff"
DEFAULT_SESSION_ID: str = "diff"
DEFAULT_TIMESTAMP: str = "1970-01-01T00:00:00+00:00"


class DiffAdapterError(ValueError):
    """Raised on malformed diff input or invalid caller-supplied metadata."""


def parse_unified_diff(diff_text: str) -> dict[str, Any]:
    """Parse a unified-diff string and return structured fields.

    Returned mapping has these keys (all deterministic from the input):

    * ``changed_paths``       — list[str], post-image paths in source order.
    * ``changed_paths_blob``  — str, newline-joined for regex over many paths.
    * ``added_lines``         — str, newline-joined ``+`` content lines.
    * ``removed_lines``       — str, newline-joined ``-`` content lines.
    * ``added_line_count``    — int.
    * ``removed_line_count``  — int.
    * ``file_count``          — int, ``len(changed_paths)``.

    Recognised header shapes: ``+++ b/<path>`` (post-image), ``+++ /dev/null``
    (deletion-only block; skipped on the post-image side), ``diff --git
    a/<path> b/<path>`` (file separator), ``rename to <path>``. Hunk markers
    (``@@``), ``---`` headers, ``index`` lines, ``new file mode`` /
    ``deleted file mode``, ``Binary files`` lines, and ``similarity index``
    are not treated as content. Plain context lines are ignored.

    Raises ``DiffAdapterError`` on empty input or input that contains no
    changed paths.
    """
    if not diff_text.strip():
        raise DiffAdapterError("diff is empty")

    changed_paths: list[str] = []
    added: list[str] = []
    removed: list[str] = []

    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            rest = raw[4:]
            if rest == "/dev/null":
                continue
            if rest.startswith("b/"):
                rest = rest[2:]
            if rest and rest not in changed_paths:
                changed_paths.append(rest)
            continue

        if raw.startswith("diff --git "):
            parts = raw.split(" ")
            if len(parts) >= 4 and parts[3].startswith("b/"):
                p = parts[3][2:]
                if p and p not in changed_paths:
                    changed_paths.append(p)
            continue

        if raw.startswith("rename to "):
            new_path = raw[len("rename to "):].strip()
            if new_path and new_path not in changed_paths:
                changed_paths.append(new_path)
            continue

        if (
            raw.startswith("--- ")
            or raw.startswith("index ")
            or raw.startswith("@@")
            or raw.startswith("similarity index ")
            or raw.startswith("rename from ")
            or raw.startswith("new file mode ")
            or raw.startswith("deleted file mode ")
            or raw.startswith("Binary files ")
        ):
            continue

        if raw.startswith("+") and not raw.startswith("+++"):
            added.append(raw[1:])
            continue
        if raw.startswith("-") and not raw.startswith("---"):
            removed.append(raw[1:])
            continue

    if not changed_paths:
        raise DiffAdapterError("diff contains no changed paths")

    return {
        "changed_paths": changed_paths,
        "changed_paths_blob": "\n".join(changed_paths),
        "added_lines": "\n".join(added),
        "removed_lines": "\n".join(removed),
        "added_line_count": len(added),
        "removed_line_count": len(removed),
        "file_count": len(changed_paths),
    }


def _derive_action_id(diff_hash: str, risk_tier: str, at: str) -> str:
    fingerprint = f"{diff_hash}|{risk_tier}|{at}"
    return str(uuid.uuid5(_DIFF_NAMESPACE, fingerprint))


def diff_to_action(
    diff_path: Path,
    *,
    risk_tier: str = "T1",
    at: str = DEFAULT_TIMESTAMP,
    agent_id: str = DEFAULT_AGENT_ID,
    session_id: str = DEFAULT_SESSION_ID,
) -> dict[str, Any]:
    """Read a unified diff from disk and return an ``ActionDescriptor`` mapping.

    The returned mapping is in the shape ``validate_action`` expects: required
    fields ``id, type, target, risk_tier, timestamp, agent_id, session_id``
    plus ``inputs`` carrying the diff metadata.

    Caller-supplied:

    * ``risk_tier`` — defaults to ``T1``. The caller selects ``T4`` to route
      elevated-blast-radius changes through the engine's built-in
      ``override_required`` default (engine-level ESCALATE).
    * ``at`` — ISO 8601 build-time stamp, defaults to the deterministic epoch
      sentinel ``1970-01-01T00:00:00+00:00``. Real-world callers should
      supply a meaningful ``--at`` value; the default keeps test fixtures
      reproducible without leaking the system clock.

    Determinism guarantee: identical diff bytes + identical ``risk_tier`` +
    identical ``at`` produce a byte-identical mapping.

    Raises ``DiffAdapterError`` on:

    * unreadable / empty / no-changed-path diffs;
    * ``risk_tier`` not in ``RISK_TIERS``;
    * empty/non-string ``at``, ``agent_id``, or ``session_id``.
    """
    if risk_tier not in RISK_TIERS:
        raise DiffAdapterError(
            f"risk_tier must be one of {sorted(RISK_TIERS)!r}, got {risk_tier!r}"
        )
    for name, value in (("at", at), ("agent_id", agent_id), ("session_id", session_id)):
        if not isinstance(value, str) or not value:
            raise DiffAdapterError(f"{name} must be a non-empty string")

    try:
        diff_bytes = diff_path.read_bytes()
    except OSError as exc:
        raise DiffAdapterError(f"cannot read diff file: {exc}") from exc

    diff_hash = hashlib.sha256(diff_bytes).hexdigest()
    diff_text = diff_bytes.decode("utf-8")
    parsed = parse_unified_diff(diff_text)

    target = parsed["changed_paths"][0]
    summary = (
        f"{parsed['file_count']} file(s); "
        f"+{parsed['added_line_count']}/-{parsed['removed_line_count']} lines"
    )

    return {
        "id": _derive_action_id(diff_hash, risk_tier, at),
        "type": "diff.apply",
        "target": target,
        "risk_tier": risk_tier,
        "timestamp": at,
        "agent_id": agent_id,
        "session_id": session_id,
        "inputs": {
            "changed_paths": list(parsed["changed_paths"]),
            "changed_paths_blob": parsed["changed_paths_blob"],
            "added_lines": parsed["added_lines"],
            "removed_lines": parsed["removed_lines"],
            "diff_hash": diff_hash,
            "diff_summary": summary,
        },
    }


def derive_sidecar_path(evidence_out: Path) -> Path:
    """Return the conventional sidecar path for a derived action.

    Used by the CLI when ``--diff`` and ``--evidence-out`` are both supplied:
    the derived action is written to ``<evidence_out>.action.json`` next to
    the evidence pack so a later ``--verify --action <sidecar>`` invocation
    can replay the recorded gate decision.
    """
    return evidence_out.with_suffix(evidence_out.suffix + ".action.json")
