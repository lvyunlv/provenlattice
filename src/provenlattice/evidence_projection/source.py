"""Real-graph Source adapter for the Evidence Projection chain.

The single real entry point ProvenLattice exposes for defect evidence is
``provenlattice.defect_query.query_defect_candidates``. This module wraps it
behind a fail-closed ``query_defect`` that never raises: every terminal the
engine can reach -- including its own ``AnalysisRequestError`` and unexpected
exceptions -- is mapped onto the v1 envelope status set and returned as a
structured dict.

The wrapper is a pure reader and adds no facts, no defaults and no verdicts:
it forwards exactly one engine call and classifies its outcome.

Status mapping (deterministic, from the engine's own contract):

=======================  ====================================================
Engine outcome           Source status   Notes
=======================  ====================================================
``status=="available"``  ``ok``          one or more live candidates
+ non-empty candidates
``status=="available"``  ``empty``       engine ran, zero candidates
+ zero candidates
``status=="stale"``      ``stale``       engine answered fail-closed (partial
                                         / stale upstream), no candidates
``AnalysisRequestError`` ``not_built``   code ``base_graph_required`` (never
``base_graph_required``                   indexed) -- distinct from ``stale``
``AnalysisRequestError`` ``failed``      code ``invalid_request``,
                                         ``unknown_defect_query``, ...
any other exception      ``failed``      unexpected fault, still fail-closed
=======================  ====================================================

``query_defect`` never coerces ``stale`` into ``not_built`` or vice-versa:
``upstream_not_built`` (missing sparse_cfg/sparse_dfg) and
``upstream_analysis_stale`` (out-of-date analysis) arrive as ``literal
status="stale"`` payloads and are preserved as ``stale``, carrying the raw
engine ``reason`` so a caller can tell the two apart. Only the repository
being entirely absent (``base_graph_required``) is ``not_built``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from provenlattice.defect_query import query_defect_candidates
from provenlattice.orchestrator import AnalysisRequestError

from . import constants as C

# Engine terminal codes that are "the repository has not been indexed", as
# opposed to "indexed but the derived upstream is missing/stale".
_NOT_BUILT_CODES = frozenset({"base_graph_required"})


def query_defect(
    repo: str | Path,
    *,
    defect_type: str,
    database: str | Path | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Run one real defect query and classify the outcome.

    Returns ``{"status", "result", "error", "reason"}``:

    * ``status`` is a v1 terminal (``ok``/``empty``/``stale``/``not_built``/
      ``failed``);
    * ``result`` is the engine's full answer dict when the engine reached a
      live result (``ok`` or ``empty``), else ``None``;
    * ``error`` is the engine error code when it failed closed, else ``None``;
    * ``reason`` is a short, stable human-readable description.

    Never raises for any engine outcome or unexpected exception.
    """
    try:
        result = query_defect_candidates(
            repo, defect_type=defect_type, database=database, **kwargs)
    except AnalysisRequestError as exc:
        error = exc.code or "unknown_request_error"
        if error in _NOT_BUILT_CODES:
            return {"status": C.ST_NOT_BUILT, "result": None,
                    "error": error, "reason": exc.detail or error}
        return {"status": C.ST_FAILED, "result": None,
                "error": error, "reason": exc.detail or error}
    except Exception as exc:  # noqa: BLE001 -- fail-closed on any fault
        return {"status": C.ST_FAILED, "result": None,
                "error": "unexpected_error",
                "reason": "%s: %s" % (type(exc).__name__, exc)}

    status = result.get("status")
    if status == "stale":
        return {"status": C.ST_STALE, "result": result,
                "error": "stale",
                "reason": str(result.get("reason") or "stale")}

    if status != "available":
        return {"status": C.ST_FAILED, "result": result,
                "error": "unexpected_status",
                "reason": "engine returned status=%r" % (status,)}

    candidates = result.get("candidates") or []
    if candidates:
        return {"status": C.ST_OK, "result": result,
                "error": None, "reason": None}
    return {"status": C.ST_EMPTY, "result": result,
            "error": None, "reason": None}


__all__ = ["query_defect"]