"""IR V2 input assembler (Issue #87, stage: file-level fact transport).

This is the *only* module in the evidence-projection package that imports the
engine. It assembles the normalised IR V2 input record by reusing the graph's
own production entry points -- it never re-implements lock / thread / call
analysis and never modifies the engine:

    query_concurrency_context  -> thread_context + spawn_join + may_parallel
    query_access_lockset       -> held_locks + lock relations
    query_call_relation        -> may_call
    query_analysis(sparse_cfg) + build_deref_resolution -> deref_resolves_to /
                                                            same_storage

Contract honoured (Owner decision #87, R2):

* **reuse, don't re-implement** -- each fact class is read through its existing
  production entry point (``query_*`` / ``build_*``), with no re-derived points-to,
  lock, thread or call analysis and no engine mutation.
* **consistent snapshot** -- every query is issued against the *same* ``database``
  and ``file_path`` within one assembly; the caller supplies one ``run_context``
  that the transformer applies uniformly.
* **query-failed vs fact-absent** -- a non-``available`` analyzer status is
  recorded in ``missing[analyzer]`` (a *query failure*, surfaced as a limitation),
  whereas an ``available`` status with empty lists is a truthful *fact absence*
  and produces no limitation.
* **fail-closed** -- any unexpected exception from an engine entry point is
  captured as ``status="failed"`` + ``missing[analyzer]``, never re-raised.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from provenlattice.analysis_call_relation import query_call_relation
from provenlattice.analysis_concurrency_context import (
    query_access_lockset,
    query_concurrency_context,
)
from provenlattice.analysis_query import query_analysis
from provenlattice.deref_resolution import build_deref_resolution


def _q(repo, database, file_path) -> tuple[str, Any, str | None]:
    """Run one read-only engine entry point and classify its outcome.

    Returns ``(status, payload, reason)`` where ``payload`` is the analyzer's
    output (or ``None`` on failure). Never raises.
    """
    try:
        result = query_concurrency_context(repo, file_path, database=database)
        status = str(result.get("status") or "failed")
        return status, result, result.get("reason")
    except Exception as exc:  # noqa: BLE001 -- fail-closed on any fault
        return "failed", None, "%s: %s" % (type(exc).__name__, exc)


def _ql(repo, database, file_path) -> tuple[str, Any, str | None]:
    try:
        result = query_access_lockset(repo, file_path, database=database)
        status = str(result.get("status") or "failed")
        return status, result, result.get("reason")
    except Exception as exc:  # noqa: BLE001
        return "failed", None, "%s: %s" % (type(exc).__name__, exc)


def _qc(repo, database, file_path) -> tuple[str, Any, str | None]:
    try:
        result = query_call_relation(repo, file_path, database=database)
        status = str(result.get("status") or "failed")
        return status, result, result.get("reason")
    except Exception as exc:  # noqa: BLE001
        return "failed", None, "%s: %s" % (type(exc).__name__, exc)


def _qd(repo, database, file_path, enable_deref) -> tuple[str, Any, str | None]:
    try:
        env = query_analysis(repo, "sparse_cfg", file_path=file_path,
                             database=database)
        if env.get("status") != "available":
            return (str(env.get("status") or "failed"), None,
                    env.get("reason"))
        events = env.get("events") or []
        result = build_deref_resolution(events, enable=enable_deref)
        return "available", result, None
    except Exception as exc:  # noqa: BLE001
        return "failed", None, "%s: %s" % (type(exc).__name__, exc)


def _aggregate(statuses: list[str]) -> str:
    if not statuses:
        return "failed"
    if all(s == "available" for s in statuses):
        return "available"
    if any(s == "available" for s in statuses):
        return "partial"
    for s in ("failed", "stale", "not_built", "unsupported", "timeout"):
        if s in statuses:
            return s
    return statuses[0]


def assemble_ir_v2_input(
    repo: str | Path,
    database: str | Path | None = None,
    *,
    file_path: str | None = None,
    enable_deref: bool = False,
    defect_type: str = "race_condition",
) -> dict[str, Any]:
    """Assemble the IR V2 input record for one file.

    ``file_path`` is required (the five fact classes are file-scoped); a missing
    ``file_path`` yields a fail-closed ``failed`` record rather than a fabricate
    whole-repo answer.
    """
    if not file_path:
        return {
            "defect_type": defect_type,
            "file_path": "",
            "status": "failed",
            "reason": "file_path is required for IR V2 file-level facts",
            "missing": {"file_path": "missing file_path"},
            "concurrency_context": None,
            "access_lockset": None,
            "call_relation": None,
            "deref_resolution": None,
            "baseline_bundle": None,
            "enable_deref": enable_deref,
            "error": "invalid_request",
        }

    cc_status, cc, cc_reason = _q(repo, database, file_path)
    lockset_status, lockset, lockset_reason = _ql(repo, database, file_path)
    callrel_status, callrel, callrel_reason = _qc(repo, database, file_path)
    deref_status, deref, deref_reason = _qd(repo, database, file_path,
                                           enable_deref)

    statuses = [cc_status, lockset_status, callrel_status, deref_status]
    missing: dict[str, str] = {}
    if cc_status != "available":
        missing["concurrency_context"] = str(cc_reason or cc_status)
    if lockset_status != "available":
        missing["access_lockset"] = str(lockset_reason or lockset_status)
    if callrel_status != "available":
        missing["call_relation"] = str(callrel_reason or callrel_status)
    if deref_status != "available":
        missing["deref_resolution"] = str(deref_reason or deref_status)

    return {
        "defect_type": defect_type,
        "file_path": file_path,
        "status": _aggregate(statuses),
        "reason": None,
        "missing": missing,
        "concurrency_context": cc if cc_status == "available" else None,
        "access_lockset": lockset if lockset_status == "available" else None,
        "call_relation": callrel if callrel_status == "available" else None,
        "deref_resolution": deref if deref_status == "available" else None,
        "baseline_bundle": None,
        "enable_deref": enable_deref,
        "error": None,
    }


__all__ = ["assemble_ir_v2_input"]
