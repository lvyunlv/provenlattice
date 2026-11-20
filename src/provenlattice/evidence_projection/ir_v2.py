"""Canonical Evidence IR V2 (Issue #87).

A pure, deterministic transformer that projects the five *file-level*
concurrency fact classes (already produced by the graph, but never before
projected into the skill-facing evidence interface) into a typed, versioned IR.

    Engine analyzers (thread_context / access_lockset / call_relation /
    deref_resolution) -> IR V2 input record -> :func:`assemble_ir_v2`
    -> Canonical Evidence IR V2

Positioning (Owner decision #87): this is a **new IR V2**, parallel to the
frozen IR V1 (``ir.py``). It does NOT extend IR V1, does NOT modify the GATE-0
FactBundle v2.1, and does NOT re-implement any engine analysis -- it consumes
the already-serialised outputs of the engine's ``build_*`` / ``query_*`` entry
points (via the :mod:`.ir_v2_source` assembler, which is the *only* module that
imports the engine).

The central design distinction (see the #87 field-mapping matrix):

* **Facts** -- atomic, single-owner observations: ``thread_entry_point`` /
  ``thread_spawn`` / ``thread_join`` / ``resource_lifetime`` / ``may_parallel`` /
  ``held_locks`` (plus the candidate-bound ``shared_access`` baseline when a
  FactBundle v2.1 is supplied).
* **Relations** -- typed connections between facts/entities: ``spawn_join`` /
  ``protect`` / ``same_lock`` / ``different_lock`` / ``unlock_omitted_on_path`` /
  ``may_call`` / ``deref_resolves_to`` / ``same_storage``.

Semantic limits enforced (and validated) here:

* ``held_locks`` is a **fact** (a per-access must-hold lock set, always
  ``ambiguous``); the lock *protecting* an access is the ``protect`` relation.
  Neither is promoted to ``GUARDED_BY``.
* ``spawn_join`` is a pairing/coordination relation, never ``HAPPENS_BEFORE``.
* ``may_parallel`` confidence is ``ambiguous`` / ``unresolved`` only (never a
  resolved concurrency verdict).
* ``deref_resolves_to`` preserves the three-state ``must`` / ``may`` / ``unknown``
  and never upgrades ``may`` to ``must``.
* ``may_call`` preserves the frozen fail-closed rule: a target is named only for
  ``unique_same_file_assignment``; zero and two-or-more both answer ``[]``.
* ``candidate_id`` is nullable: file-level facts/relations exist before any
  candidate is identified and are NOT evidence of an invalid fact.

This module imports only ``.ir`` (for the shared status enums) and the standard
library. It never imports the engine, GT, Prompt, Skill or Scorer, and it never
mutates its inputs.
"""

from __future__ import annotations

import copy
from typing import Any, Mapping

from . import ir

IR_SCHEMA_VERSION = "2"
PROJECTOR_VERSION = "2"

# The IR V2 contract marker and the input-record schema version. The input
# record is the normalised, engine-agnostic payload assembled by
# ``ir_v2_source.assemble_ir_v2_input`` (or synthesised by tests).
CONTRACT_VERSION = "canonical-evidence-ir-v2"
INPUT_SCHEMA_VERSION = "ir-v2-input-v1"

# Reuse the frozen status enums so IR V2 and IR V1 never drift on the meaning of
# a terminal status or claim status.
BUNDLE_STATUSES = ir.BUNDLE_STATUSES
CLAIM_STATUSES = ir.CLAIM_STATUSES
NOT_RECORDED = ir.NOT_RECORDED

# The ten standard blocks, identical skeleton to IR V1 so a consumer can
# navigate both versions the same way.
IR_BLOCKS = (
    "run", "candidates", "claims", "facts", "relations",
    "locations", "provenance", "coverage", "limitations", "source_envelope",
)

# --- typed fact / relation vocabularies -------------------------------------

FACT_TYPES = (
    "shared_access",
    "thread_entry_point",
    "thread_spawn",
    "thread_join",
    "resource_lifetime",
    "may_parallel",
    "held_locks",
)

RELATION_TYPES = (
    "spawn_join",
    "protect",
    "same_lock",
    "different_lock",
    "unlock_omitted_on_path",
    "may_call",
    "deref_resolves_to",
    "same_storage",
)

# Confidence is type-specific and is the *only* place a verdict level is
# expressed. The per-type vocabularies below encode the semantic limits the
# Owner froze: may_parallel / held_locks can never be ``definite``;
# deref_resolves_to keeps the three-state; may_call keeps the fail-closed
# resolution vocabulary.
FACT_CONFIDENCE_BY_TYPE: dict[str, tuple[str, ...]] = {
    "shared_access": ("definite",),
    "thread_entry_point": ("definite",),
    "thread_spawn": ("definite",),
    "thread_join": ("definite",),
    "resource_lifetime": ("candidate",),
    "may_parallel": ("ambiguous", "unresolved"),
    "held_locks": ("ambiguous",),
}

RELATION_CONFIDENCE_BY_TYPE: dict[str, tuple[str, ...]] = {
    "spawn_join": ("definite",),
    "protect": ("ambiguous",),
    "same_lock": ("ambiguous",),
    "different_lock": ("ambiguous",),
    "unlock_omitted_on_path": ("ambiguous",),
    "may_call": ("unknown", "unique_same_file_assignment",
                 "ambiguous_multiple_assignments"),
    "deref_resolves_to": ("must", "may", "unknown"),
    "same_storage": ("must",),
}

# First-order relations the graph does NOT produce. They are listed explicitly
# in ``coverage.not_produced`` (never emitted as relations, never implied).
NOT_PRODUCED = ("happens_before", "guarded_by")

# Mapping from an input-record terminal status to the IR bundle_status.
_STATUS_TO_BUNDLE = {
    "available": "ok",
    "ok": "ok",
    "empty": "empty",
    "partial": "partial",
    "stale": "stale",
    "not_built": "not_built",
    "unsupported": "unsupported_only",
    "failed": "failed",
    "timeout": "timeout",
}


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------


def _rc(ctx: Mapping[str, Any], name: str) -> str:
    value = ctx.get(name)
    if value is None or str(value) == "":
        return NOT_RECORDED
    return value if isinstance(value, str) else str(value)


def _pstr(value: Any) -> str:
    if value is None:
        return ""
    return value if isinstance(value, str) else str(value)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _span(value: Any) -> list[int]:
    if isinstance(value, (list, tuple)) and len(value) >= 2:
        try:
            return [int(value[0] or 0), int(value[1] or 0)]
        except (TypeError, ValueError):
            return [0, 0]
    return [0, 0]


def _first(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value is not None and str(value) != "":
            return str(value)
    return ""


def _line(record: Mapping[str, Any]) -> int:
    for key in ("start_line", "line", "start_byte"):
        value = record.get(key)
        if value is not None:
            return _as_int(value)
    return 0


# ---------------------------------------------------------------------------
# fact / relation builders (one per type, engine field -> typed payload)
# ---------------------------------------------------------------------------


def _fact(fact_type, fact_id, payload, *, confidence, candidate_id=None,
          file="", line=0, line_span=None, provenance="") -> dict[str, Any]:
    return {
        "fact_id": _pstr(fact_id),
        "fact_type": fact_type,
        "candidate_id": candidate_id,
        "file": _pstr(file),
        "line": line,
        "line_span": line_span if line_span is not None else [line, line],
        "provenance": _pstr(provenance),
        "confidence": confidence,
        "payload": payload,
    }


def _relation(relation_type, relation_id, endpoints, payload, *,
              confidence, candidate_id=None,
              provenance="") -> dict[str, Any]:
    return {
        "relation_id": _pstr(relation_id),
        "relation_type": relation_type,
        "candidate_id": candidate_id,
        "confidence": confidence,
        "endpoints": list(endpoints),
        "payload": payload,
        "provenance": _pstr(provenance),
    }


def _thread_entry_facts(record: Mapping[str, Any], file: str) -> list[dict]:
    out = []
    for name in sorted(record.get("thread_entry_points") or []):
        out.append(_fact(
            "thread_entry_point", "entry:" + _pstr(name),
            {"function": _pstr(name)},
            confidence="definite", file=file,
            provenance="analysis_concurrency_context.build_concurrency_context",
        ))
    return out


def _thread_spawn_facts(record: Mapping[str, Any], file: str) -> list[dict]:
    # Event-level facts carry byte offsets (``start_byte``/``end_byte``), not
    # source lines; ``line`` stays 0 (never fabricate a line from a byte offset).
    out = []
    for event in record.get("spawns") or []:
        if not isinstance(event, Mapping):
            continue
        payload = copy.deepcopy(dict(event))
        out.append(_fact(
            "thread_spawn", _first(event, "event_id"), payload,
            confidence="definite", file=file,
            provenance="analysis_concurrency_context.build_concurrency_context",
        ))
    return out


def _thread_join_facts(record: Mapping[str, Any], file: str) -> list[dict]:
    out = []
    for event in record.get("joins") or []:
        if not isinstance(event, Mapping):
            continue
        payload = copy.deepcopy(dict(event))
        out.append(_fact(
            "thread_join", _first(event, "event_id"), payload,
            confidence="definite", file=file,
            provenance="analysis_concurrency_context.build_concurrency_context",
        ))
    return out


def _resource_lifetime_facts(record: Mapping[str, Any], file: str) -> list[dict]:
    out = []
    for item in record.get("resource_lifetime") or []:
        if not isinstance(item, Mapping):
            continue
        payload = copy.deepcopy(dict(item))
        out.append(_fact(
            "resource_lifetime", _first(item, "spawn_event_id", "object"), payload,
            confidence="candidate", file=file,
            provenance="analysis_concurrency_context.build_concurrency_context",
        ))
    return out


def _may_parallel_facts(record: Mapping[str, Any], file: str) -> list[dict]:
    out = []
    for item in record.get("may_parallel") or []:
        if not isinstance(item, Mapping):
            continue
        confidence = _pstr(item.get("candidate_state")) or "ambiguous"
        if confidence not in FACT_CONFIDENCE_BY_TYPE["may_parallel"]:
            confidence = "ambiguous"  # fail-closed: never upgrade to definite
        identity = _pstr(item.get("identity"))
        subject = _pstr(item.get("subject"))
        fact_id = "may_parallel:" + (identity or ("unresolved:" + subject))
        payload = copy.deepcopy(dict(item))
        out.append(_fact(
            "may_parallel", fact_id, payload,
            confidence=confidence, file=file,
            provenance="analysis_concurrency_context.build_concurrency_context",
        ))
    return out


def _held_locks_facts(record: Mapping[str, Any], file: str) -> list[dict]:
    # access_locksets carry real source lines (``start_line``/``end_line``).
    out = []
    for item in record.get("access_locksets") or []:
        if not isinstance(item, Mapping):
            continue
        start_line = _as_int(item.get("start_line"))
        end_line = _as_int(item.get("end_line")) or start_line
        payload = copy.deepcopy(dict(item))
        out.append(_fact(
            "held_locks", _first(item, "access_event_id"), payload,
            confidence="ambiguous", file=file, line=start_line,
            line_span=[start_line, end_line],
            provenance="concurrency_lock_scenarios.build_access_lockset",
        ))
    return out


def _spawn_join_relations(record: Mapping[str, Any]) -> list[dict]:
    out = []
    for item in record.get("spawn_join_pairs") or []:
        if not isinstance(item, Mapping):
            continue
        spawn = _pstr(item.get("spawn"))
        join = _pstr(item.get("join"))
        payload = {
            "owner": _pstr(item.get("owner")),
            "handle_decl": _pstr(item.get("handle_decl")),
            "thread_function": _pstr(item.get("thread_function")),
        }
        out.append(_relation(
            "spawn_join", "spawn_join:%s:%s" % (spawn, join), [spawn, join],
            payload, confidence="definite",
            provenance="analysis_concurrency_context.build_concurrency_context",
        ))
    return out


def _lockset_relations(record: Mapping[str, Any]) -> list[dict]:
    """Map access_lockset ``relations`` (PROTECTS / SAME_LOCK / DIFFERENT_LOCK /
    UNLOCK_OMITTED_ON_PATH) to typed IR V2 relations."""
    out = []
    kind_map = {
        "PROTECTS": "protect",
        "SAME_LOCK": "same_lock",
        "DIFFERENT_LOCK": "different_lock",
        "UNLOCK_OMITTED_ON_PATH": "unlock_omitted_on_path",
    }
    for item in record.get("relations") or []:
        if not isinstance(item, Mapping):
            continue
        kind = _pstr(item.get("relation"))
        relation_type = kind_map.get(kind)
        if relation_type is None:
            continue
        payload = copy.deepcopy(dict(item))
        payload.pop("relation", None)

        if relation_type in ("protect", "unlock_omitted_on_path"):
            lock = _pstr(item.get("lock"))
            access = _pstr(item.get("access_event_id"))
            relation_id = "%s:%s:%s" % (relation_type, lock, access)
            endpoints = [lock, access]
        else:  # same_lock / different_lock
            subject = _pstr(item.get("subject"))
            pair = [str(x) for x in (item.get("access_event_ids") or [])]
            relation_id = "%s:%s:%s" % (
                relation_type, subject, ":".join(pair))
            endpoints = pair
        out.append(_relation(
            relation_type, relation_id, endpoints, payload,
            confidence="ambiguous",
            provenance="concurrency_lock_scenarios.build_access_lockset",
        ))
    return out


def _may_call_relations(record: Mapping[str, Any]) -> list[dict]:
    out = []
    for item in record.get("call_relations") or []:
        if not isinstance(item, Mapping):
            continue
        decl = _pstr(item.get("subject_decl"))
        member = _pstr(item.get("subject_member"))
        resolution = _pstr(item.get("resolution")) or "unknown"
        payload = copy.deepcopy(dict(item))
        slot = "%s.%s" % (decl, member) if decl else member
        may_call = item.get("may_call") or []
        # Frozen fail-closed rule: zero / two-or-more targets both answer [].
        target = str(may_call[0]) if may_call else ""
        out.append(_relation(
            "may_call", "may_call:%s:%s" % (decl, member), [slot, target],
            payload, confidence=resolution,
            provenance="analysis_call_relation.build_call_relation",
        ))
    return out


def _deref_relations(record: Mapping[str, Any]) -> list[dict]:
    out = []
    for item in record.get("deref_resolves_to") or []:
        if not isinstance(item, Mapping):
            continue
        confidence = _pstr(item.get("confidence")) or "unknown"
        if confidence not in RELATION_CONFIDENCE_BY_TYPE["deref_resolves_to"]:
            confidence = "unknown"  # fail-closed: never upgrade to must
        access = _pstr(item.get("access_event_id"))
        target = _pstr(item.get("deref_resolves_to"))
        payload = copy.deepcopy(dict(item))
        out.append(_relation(
            "deref_resolves_to", "deref:%s" % access, [access, target], payload,
            confidence=confidence,
            provenance="deref_resolution.build_deref_resolution",
        ))
    return out


def _same_storage_relations(record: Mapping[str, Any]) -> list[dict]:
    out = []
    for item in record.get("same_storage") or []:
        if not isinstance(item, Mapping):
            continue
        storage = _pstr(item.get("storage_object_id"))
        payload = copy.deepcopy(dict(item))
        accesses = [
            _first(side, "access_event_id")
            for side in (item.get("accesses") or [])
            if isinstance(side, Mapping)
        ]
        out.append(_relation(
            "same_storage", "same_storage:%s" % storage, accesses, payload,
            confidence="must",
            provenance="deref_resolution.build_deref_resolution",
        ))
    return out


# ---------------------------------------------------------------------------
# baseline (FactBundle v2.1 -> candidate-bound facts / candidates / locations)
# ---------------------------------------------------------------------------


def _baseline_facts(bundle: Mapping[str, Any]) -> list[dict]:
    """Candidate-bound ``shared_access`` facts from a FactBundle v2.1, mirroring
    IR V1's candidate-bound fact projection but stamped as IR V2 facts."""
    out = []
    for pc in bundle.get("evidence_locations") or []:
        if not isinstance(pc, Mapping):
            continue
        ckey = _pstr(pc.get("candidate_key"))
        for row in (pc.get("access_rows") or []):
            if not isinstance(row, Mapping):
                continue
            out.append(_fact(
                "shared_access",
                _first(row, "source_fact_id", "event_id"),
                copy.deepcopy(dict(row)),
                confidence="definite", candidate_id=ckey,
                file=_pstr(row.get("file")), line=_line(row),
                line_span=_span(row.get("line_span")),
                provenance=_pstr(row.get("provenance")),
            ))
    return out


def _baseline_candidates(bundle: Mapping[str, Any]) -> list[dict]:
    out = []
    for pc in bundle.get("evidence_locations") or []:
        if not isinstance(pc, Mapping):
            continue
        out.append({
            "id": _pstr(pc.get("candidate_key")),
            "defect_type": _pstr(bundle.get("defect_type")),
            "evidence_id": _pstr(pc.get("evidence_id")),
            "defect_key": _pstr(pc.get("defect_key")),
            "discriminator": _pstr(pc.get("discriminator")),
            "identity": _pstr(pc.get("identity")),
            "subject": _pstr(pc.get("subject")),
            "primary_anchor": copy.deepcopy(pc.get("primary_anchor")),
        })
    out.sort(key=lambda c: c["id"])
    return out


def _baseline_locations(bundle: Mapping[str, Any]) -> list[dict]:
    out = []
    for loc in bundle.get("supporting_locations") or []:
        if not isinstance(loc, Mapping):
            continue
        out.append({
            "candidate_id": _pstr(loc.get("candidate_key")),
            "file": _pstr(loc.get("file")),
            "line": _line(loc),
            "line_span": _span(loc.get("line_span")),
            "owner": _pstr(loc.get("owner")),
            "role": _pstr(loc.get("role")),
            "semantic_role": _pstr(loc.get("semantic_role")),
            "anchor_class": _pstr(loc.get("anchor_class")),
            "source_fact_id": _pstr(loc.get("source_fact_id")),
            "event_id": _pstr(loc.get("event_id")),
            "provenance": _pstr(loc.get("provenance")),
        })
    out.sort(key=lambda l: (l["candidate_id"], l["file"], l["line"],
                            l["semantic_role"], l["event_id"]))
    return out


# ---------------------------------------------------------------------------
# limitations
# ---------------------------------------------------------------------------


def _limitations(input_record: Mapping[str, Any], facts: list[dict]) -> list[str]:
    out: list[str] = []

    status = _pstr(input_record.get("status"))
    if status and status not in ("available", "ok"):
        out.append(
            "bundle status=%s: file-level evidence query did not deliver a "
            "complete available result" % status)

    missing = input_record.get("missing")
    if isinstance(missing, Mapping):
        for analyzer in sorted(missing):
            out.append("analyzer %s unavailable: %s"
                       % (analyzer, _pstr(missing.get(analyzer))))

    # The graph's own declared gaps live inside the concurrency_context bundle.
    cc = input_record.get("concurrency_context") or {}
    if isinstance(cc, Mapping):
        for gap in (cc.get("capability_gaps") or []):
            out.append("capability gap: " + _pstr(gap))
        for evidence in (cc.get("missing_evidence") or []):
            out.append("missing evidence: " + _pstr(evidence))

    # Per-fact degradations, mirroring IR V1's explicit-degradation rule.
    for f in facts:
        if not f["fact_id"]:
            out.append("fact of type %s lacks an engine fact id" % f["fact_type"])

    # Per-access held_locks limitations live inside the access_lockset bundle.
    lockset = input_record.get("access_lockset") or {}
    if isinstance(lockset, Mapping):
        for item in (lockset.get("access_locksets") or []):
            if isinstance(item, Mapping):
                for lim in (item.get("limitation") or []):
                    out.append("held_locks limitation: " + _pstr(lim))

    seen: set[str] = set()
    result: list[str] = []
    for item in out:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


# ---------------------------------------------------------------------------
# transformer
# ---------------------------------------------------------------------------


def assemble_ir_v2(
    input_record: Mapping[str, Any],
    *,
    run_context: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project an IR V2 input record into the Canonical Evidence IR V2.

    Pure and deterministic: never mutates ``input_record``, never reads the
    engine / DB / git HEAD, and returns an equal result for equal inputs.

    ``input_record`` is the normalised payload assembled by
    ``ir_v2_source.assemble_ir_v2_input`` (or synthesised by tests)::

        {
            "defect_type": str,
            "file_path": str,
            "status": "available" | "stale" | ...,
            "reason": None,
            "missing": {analyzer: reason},     # non-available analyzers
            "concurrency_context": {...} | None,
            "access_lockset": {...} | None,
            "call_relation": {...} | None,
            "deref_resolution": {...} | None,
            "baseline_bundle": {...} | None,   # optional FactBundle v2.1
        }
    """
    if not isinstance(input_record, Mapping):
        raise TypeError("input_record must be a mapping, got %r"
                        % (type(input_record).__name__,))

    record = dict(input_record)
    ctx = run_context if isinstance(run_context, Mapping) else {}
    file = _pstr(record.get("file_path"))
    defect_type = _pstr(record.get("defect_type"))

    cc = record.get("concurrency_context") or {}
    lockset = record.get("access_lockset") or {}
    callrel = record.get("call_relation") or {}
    deref = record.get("deref_resolution") or {}
    baseline = record.get("baseline_bundle")

    # --- run block -----------------------------------------------------------
    run = {
        "code_revision": _rc(ctx, "code_revision"),
        "engine_version": _rc(ctx, "engine_version"),
        "db_snapshot_identity": _rc(ctx, "db_snapshot_identity"),
        "source_schema_version": INPUT_SCHEMA_VERSION,
        "contract_version": CONTRACT_VERSION,
        "projection_version": (
            _pstr(baseline.get("projection_version"))
            if isinstance(baseline, Mapping) else NOT_RECORDED),
        "adapter_version": (
            _pstr(baseline.get("adapter_version"))
            if isinstance(baseline, Mapping) else NOT_RECORDED),
        "core_adapter_version": (
            _pstr(baseline.get("core_adapter_version"))
            if isinstance(baseline, Mapping) else ""),
        "projector_version": PROJECTOR_VERSION,
        "query_params": {
            "ir_version": IR_SCHEMA_VERSION,
            "defect_type": defect_type,
            "file_path": file,
            "enable_deref": bool(record.get("enable_deref")),
        },
        "error": copy.deepcopy(record.get("error")),
        "reason": copy.deepcopy(record.get("reason")),
    }

    # --- facts ---------------------------------------------------------------
    facts: list[dict[str, Any]] = []
    facts.extend(_thread_entry_facts(cc, file))
    facts.extend(_thread_spawn_facts(cc, file))
    facts.extend(_thread_join_facts(cc, file))
    facts.extend(_resource_lifetime_facts(cc, file))
    facts.extend(_may_parallel_facts(cc, file))
    facts.extend(_held_locks_facts(lockset, file))
    if isinstance(baseline, Mapping):
        facts.extend(_baseline_facts(baseline))
    facts.sort(key=lambda f: (f["fact_type"], f["fact_id"],
                              f["candidate_id"] or ""))

    # --- relations -----------------------------------------------------------
    relations: list[dict[str, Any]] = []
    relations.extend(_spawn_join_relations(cc))
    relations.extend(_lockset_relations(lockset))
    relations.extend(_may_call_relations(callrel))
    relations.extend(_deref_relations(deref))
    relations.extend(_same_storage_relations(deref))
    relations.sort(key=lambda r: (r["relation_type"], r["relation_id"]))

    # --- candidates / locations (baseline only) ------------------------------
    candidates: list[dict[str, Any]] = []
    locations: list[dict[str, Any]] = []
    if isinstance(baseline, Mapping):
        candidates = _baseline_candidates(baseline)
        locations = _baseline_locations(baseline)

    # --- provenance ----------------------------------------------------------
    provenance: list[dict[str, Any]] = []
    for f in facts:
        provenance.append({
            "target_kind": "fact",
            "fact_id": f["fact_id"],
            "candidate_id": f["candidate_id"],
            "origin": f["provenance"],
            "projection_version": run["projection_version"],
            "adapter_version": run["adapter_version"],
            "contract_version": run["contract_version"],
        })
    for r in relations:
        provenance.append({
            "target_kind": "relation",
            "fact_id": r["relation_id"],
            "candidate_id": r["candidate_id"],
            "origin": r["provenance"],
            "projection_version": run["projection_version"],
            "adapter_version": run["adapter_version"],
            "contract_version": run["contract_version"],
        })
    provenance.sort(key=lambda p: (p["target_kind"], p["fact_id"],
                                   p["candidate_id"] or "", p["origin"]))

    # --- coverage ------------------------------------------------------------
    fact_types = {t: sum(1 for f in facts if f["fact_type"] == t)
                  for t in FACT_TYPES}
    relation_types = {t: sum(1 for r in relations if r["relation_type"] == t)
                      for t in RELATION_TYPES}
    confidence: dict[str, int] = {}
    for f in facts:
        confidence[f["confidence"]] = confidence.get(f["confidence"], 0) + 1
    for r in relations:
        confidence[r["confidence"]] = confidence.get(r["confidence"], 0) + 1
    coverage: dict[str, Any] = {
        "fact_types": fact_types,
        "relation_types": relation_types,
        "confidence": confidence,
        "not_produced": list(NOT_PRODUCED),
    }
    if isinstance(baseline, Mapping):
        coverage["source_location"] = copy.deepcopy(
            baseline.get("location_coverage"))

    # --- limitations ---------------------------------------------------------
    limitations = _limitations(record, facts)

    status = _pstr(record.get("status"))
    bundle_status = _STATUS_TO_BUNDLE.get(status, "failed")

    return {
        "ir_schema_version": IR_SCHEMA_VERSION,
        "bundle_status": bundle_status,
        "run": run,
        "candidates": candidates,
        "claims": [],
        "facts": facts,
        "relations": relations,
        "locations": locations,
        "provenance": provenance,
        "coverage": coverage,
        "limitations": limitations,
        "source_envelope": copy.deepcopy(record),
    }


# ---------------------------------------------------------------------------
# validator
# ---------------------------------------------------------------------------


def validate_evidence_ir_v2(evidence: Any) -> list[str]:
    """Validate a Canonical Evidence IR V2 structure (empty list == valid).

    Structural only: 10 blocks, per-block required fields, version separation
    (``ir_schema_version="2"`` / ``run.projector_version="2"``), typed
    fact/relation vocabularies, per-type confidence limits (no may_parallel /
    held_locks definite, no GUARDED_BY / HAPPENS_BEFORE relation, DEREF
    three-state), nullable ``candidate_id``, and explicit degradation.
    """
    probs: list[str] = []
    if not isinstance(evidence, Mapping):
        return ["ir is not a mapping"]

    if evidence.get("ir_schema_version") != IR_SCHEMA_VERSION:
        probs.append("bad ir_schema_version: %r (expected %r)"
                     % (evidence.get("ir_schema_version"), IR_SCHEMA_VERSION))
    for block in IR_BLOCKS:
        if block not in evidence:
            probs.append("missing IR block: " + block)

    if "bundle_status" not in evidence:
        probs.append("missing bundle_status")
    elif evidence.get("bundle_status") not in BUNDLE_STATUSES:
        probs.append("bad bundle_status: %r" % (evidence.get("bundle_status"),))

    probs.extend(_validate_run(evidence.get("run")))
    probs.extend(_validate_candidates(evidence.get("candidates")))
    probs.extend(_validate_claims(evidence.get("claims")))
    probs.extend(_validate_facts(evidence.get("facts")))
    probs.extend(_validate_relations(evidence.get("relations")))
    probs.extend(_validate_locations(evidence.get("locations")))
    probs.extend(_validate_provenance(evidence.get("provenance")))
    probs.extend(_validate_coverage(evidence.get("coverage")))
    probs.extend(_validate_limitations(evidence.get("limitations")))
    probs.extend(_validate_source_envelope(evidence.get("source_envelope")))

    probs.extend(_validate_binding(evidence))
    return probs


def _validate_run(run: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(run, Mapping):
        return ["run is not a mapping"]
    required = (
        "code_revision", "engine_version", "db_snapshot_identity",
        "source_schema_version", "contract_version", "projection_version",
        "adapter_version", "core_adapter_version", "projector_version",
        "query_params", "error", "reason",
    )
    for k in required:
        if k not in run:
            probs.append("run missing " + k)

    for k in ("code_revision", "engine_version", "db_snapshot_identity"):
        if run.get(k) in (None, ""):
            probs.append("run.%s must be %r when absent (got %r)"
                         % (k, NOT_RECORDED, run.get(k)))

    if run.get("projector_version") != PROJECTOR_VERSION:
        probs.append("run.projector_version must be %r (got %r)"
                     % (PROJECTOR_VERSION, run.get("projector_version")))
    if run.get("projector_version") == run.get("projection_version"):
        probs.append("run.projector_version must not equal run.projection_version")

    if run.get("contract_version") != CONTRACT_VERSION:
        probs.append("run.contract_version must be %r (got %r)"
                     % (CONTRACT_VERSION, run.get("contract_version")))
    if run.get("query_params") is None:
        probs.append("run.query_params must be an object, got null")
    return probs


def _validate_candidates(candidates: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(candidates, list):
        return ["candidates is not a list"]
    ids: list[str] = []
    for i, c in enumerate(candidates):
        if not isinstance(c, Mapping):
            probs.append("candidates[%d] is not a mapping" % i)
            continue
        if "id" not in c:
            probs.append("candidates[%d] missing id" % i)
        else:
            cid = str(c.get("id") or "")
            if not cid:
                probs.append("candidates[%d].id is empty" % i)
            else:
                ids.append(cid)
        for k in ("defect_type", "identity", "subject"):
            if k not in c:
                probs.append("candidates[%d] missing %s" % (i, k))
        if "primary_anchor" not in c:
            probs.append("candidates[%d] missing primary_anchor" % i)
    if len(ids) != len(set(ids)):
        probs.append("duplicate candidate.id")
    return probs


def _validate_claims(claims: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(claims, list):
        return ["claims is not a list"]
    for i, cl in enumerate(claims):
        if not isinstance(cl, Mapping):
            probs.append("claims[%d] is not a mapping" % i)
            continue
        if "claim" not in cl:
            probs.append("claims[%d] missing claim" % i)
        if cl.get("status") not in CLAIM_STATUSES:
            probs.append("claims[%d] bad status: %r" % (i, cl.get("status")))
    return probs


def _validate_facts(facts: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(facts, list):
        return ["facts is not a list"]
    for i, f in enumerate(facts):
        if not isinstance(f, Mapping):
            probs.append("facts[%d] is not a mapping" % i)
            continue
        for k in ("fact_id", "fact_type", "candidate_id", "confidence",
                  "payload"):
            if k not in f:
                probs.append("facts[%d] missing %s" % (i, k))
                continue
        fact_type = f.get("fact_type")
        if fact_type not in FACT_TYPES:
            probs.append("facts[%d] bad fact_type: %r" % (i, fact_type))
            continue
        confidence = f.get("confidence")
        allowed = FACT_CONFIDENCE_BY_TYPE.get(fact_type, ())
        if confidence not in allowed:
            probs.append("facts[%d] bad confidence %r for %s (allowed %r)"
                         % (i, confidence, fact_type, allowed))
        if not str(f.get("fact_id") or ""):
            probs.append("facts[%d] empty fact_id" % i)
        if not isinstance(f.get("payload"), Mapping):
            probs.append("facts[%d] payload is not a mapping" % i)
    return probs


def _validate_relations(relations: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(relations, list):
        return ["relations is not a list"]
    for i, r in enumerate(relations):
        if not isinstance(r, Mapping):
            probs.append("relations[%d] is not a mapping" % i)
            continue
        for k in ("relation_id", "relation_type", "confidence", "endpoints",
                  "payload"):
            if k not in r:
                probs.append("relations[%d] missing %s" % (i, k))
                continue
        relation_type = r.get("relation_type")
        if relation_type not in RELATION_TYPES:
            probs.append("relations[%d] bad relation_type: %r"
                         % (i, relation_type))
            continue
        confidence = r.get("confidence")
        allowed = RELATION_CONFIDENCE_BY_TYPE.get(relation_type, ())
        if confidence not in allowed:
            probs.append("relations[%d] bad confidence %r for %s (allowed %r)"
                         % (i, confidence, relation_type, allowed))
        if not isinstance(r.get("endpoints"), list):
            probs.append("relations[%d] endpoints is not a list" % i)
        if not isinstance(r.get("payload"), Mapping):
            probs.append("relations[%d] payload is not a mapping" % i)
    return probs


def _validate_locations(locations: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(locations, list):
        return ["locations is not a list"]
    for i, loc in enumerate(locations):
        if not isinstance(loc, Mapping):
            probs.append("locations[%d] is not a mapping" % i)
            continue
        for k in ("candidate_id", "file", "line", "semantic_role",
                  "anchor_class"):
            if k not in loc:
                probs.append("locations[%d] missing %s" % (i, k))
    return probs


def _validate_provenance(provenance: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(provenance, list):
        return ["provenance is not a list"]
    for i, p in enumerate(provenance):
        if not isinstance(p, Mapping):
            probs.append("provenance[%d] is not a mapping" % i)
            continue
        for k in ("target_kind", "fact_id", "origin"):
            if k not in p:
                probs.append("provenance[%d] missing %s" % (i, k))
        if p.get("target_kind") not in ("fact", "relation"):
            probs.append("provenance[%d] bad target_kind: %r"
                         % (i, p.get("target_kind")))
    return probs


def _validate_coverage(coverage: Any) -> list[str]:
    if not isinstance(coverage, Mapping):
        return ["coverage is not a mapping"]
    probs: list[str] = []
    for k in ("fact_types", "relation_types", "confidence", "not_produced"):
        if k not in coverage:
            probs.append("coverage missing " + k)
    if list(coverage.get("not_produced") or []) != list(NOT_PRODUCED):
        probs.append("coverage.not_produced must equal %r (got %r)"
                     % (list(NOT_PRODUCED), coverage.get("not_produced")))
    return probs


def _validate_limitations(limitations: Any) -> list[str]:
    probs: list[str] = []
    if not isinstance(limitations, list):
        return ["limitations is not a list"]
    for i, item in enumerate(limitations):
        if not isinstance(item, str) or not item:
            probs.append("limitations[%d] must be a non-empty string" % i)
    return probs


def _validate_source_envelope(env: Any) -> list[str]:
    if not isinstance(env, Mapping):
        return ["source_envelope is not a mapping"]
    return []


def _validate_binding(evidence: Mapping[str, Any]) -> list[str]:
    """Nullable-candidate binding: a non-null ``candidate_id`` must reference a
    real candidate id (a null ``candidate_id`` is a valid file-level fact)."""
    probs: list[str] = []
    candidates = evidence.get("candidates")
    cids: set[str] = set()
    if isinstance(candidates, list):
        cids = {str(c.get("id") or "") for c in candidates
                if isinstance(c, Mapping)}

    for kind in ("facts", "relations"):
        for i, item in enumerate(evidence.get(kind) or []):
            if not isinstance(item, Mapping):
                continue
            cid = item.get("candidate_id")
            if cid is not None and str(cid) not in cids:
                probs.append("%s[%d].candidate_id %r not in candidate ids"
                             % (kind, i, cid))
    return probs


__all__ = [
    "IR_SCHEMA_VERSION",
    "PROJECTOR_VERSION",
    "CONTRACT_VERSION",
    "INPUT_SCHEMA_VERSION",
    "IR_BLOCKS",
    "FACT_TYPES",
    "RELATION_TYPES",
    "FACT_CONFIDENCE_BY_TYPE",
    "RELATION_CONFIDENCE_BY_TYPE",
    "NOT_PRODUCED",
    "assemble_ir_v2",
    "validate_evidence_ir_v2",
]
