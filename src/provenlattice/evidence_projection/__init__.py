"""FactBundle v2.1 evidence projection (GATE-0).

A self-contained, versioned projection chain over the real ProvenLattice
``query_defect`` results:

    Engine/Query (``provenlattice.defect_query.query_defect_candidates``)
        -> Source adapter (``source``)
        -> per-candidate projection (``projection``)
        -> FactBundle v2.1 envelope + validation (``adapter``)

The two public entry points are :func:`adapter.analyze_shared_access` (Race
Condition) and :func:`adapter.analyze_double_free` (Double Free). The
projection module is engine-agnostic and never imports the engine: it consumes
the already-serialized candidate records produced by ``query_defect_candidates``.

This package is additive and read-only over the rest of the repository: it does
not modify engine fact production, the parser/walker, CFG/DFG, alias analysis,
Happens-Before, GT/Prompt/Skill/Scorer, or any existing module under
``src/provenlattice/``.
"""

from .adapter import analyze_double_free, analyze_shared_access, validate_bundle_v2
from .projection import assert_candidate_binding

__all__ = [
    "analyze_shared_access",
    "analyze_double_free",
    "validate_bundle_v2",
    "assert_candidate_binding",
]
