"""Query-time MAY_CALL derivation (F2, Issue #45 / SUB-09 R6).

Reads the READ/WRITE access facts ``sparse_cfg:cpp`` already materialises and
derives, fail-closed, the finite ``MAY_CALL`` target set the frozen G0
call-relation contract (``sub09_g0_call_relation_contract.md`` §4) and the V4
FE-6 split proposal (``sub09_fe6_implementation_split_proposal.md`` §1.2 / §4)
specify:

* the canonical slot is ``(subject_decl, subject_member)``, scoped to one file;
* F1's bounded indirect field-callee READ is stamped ``is_indirect=true``;
* F1's WRITE of that same slot carries ``write_source`` = the right-hand root
  identifier (``g_timePara.procFunc = timer_fn`` -> ``timer_fn``);
* the two join on the canonical slot; the distinct ``write_source`` values are
  resolved against the base ``nodes`` table (``kind in {Function, Method}`` and
  the same ``file_id``), deduplicated by qualified name, then mapped through the
  frozen rule::

      count == 0  -> MAY_CALL=[]  resolution="unknown"
      count == 1  -> MAY_CALL=[t] resolution="unique_same_file_assignment"
      count >= 2  -> MAY_CALL=[]  resolution="ambiguous_multiple_assignments"

No source-order / "last assignment" inference (``p.fn = a; p.fn = b`` stays
``{}``); an indirect call never upgrades to a definite ``CALLS``, and the
``resolver.py`` ``indirect_call_shape`` fail-closed invariant is preserved
untouched. An unresolved identity (no ``subject_decl``) and a non-function
``write_source`` both fall to ``count == 0``.

Pure query-time reader (the ``scenario_relations`` / ``defect_query``
precedent): it never creates, rebuilds or refreshes analysis data, never writes
a physical edge, and never changes the SQL schema. Default OFF: nothing here is
registered as an analyzer or capability and nothing runs during ``index``.
Freshness is delegated to ``query_analysis``; a stale or missing ``sparse_cfg``
answers that honest status instead of partial facts.

D1 (issue-pilot#91) adds a second, additive reader -- ``build_call_site_clones``
/ ``query_call_site_clones`` -- that composes the same published facts one step
further: a callee's access and lock rows are cloned to each of its resolved call
sites, parameter subjects are bound to the caller's declared argument identity,
and the clone is owned by the caller (the thread context).  Direct calls join
their CALLS row by the frozen ``(file_id, owner_symbol_id, start_line)`` key;
indirect calls reuse the MAY_CALL derivation above and clone only a
``unique_same_file_assignment`` slot.  Nothing is written, no event id is
reused, and a single call site is not cloned.  See the D1 section below for the
fail-closed boundaries.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .analysis_query import query_analysis
from .contracts import parameters as split_parameters
from .models import (
    STORAGE_FIELD,
    STORAGE_FILE_STATIC,
    STORAGE_GLOBAL,
    STORAGE_PARAMETER,
    STORAGE_UNKNOWN,
)
from .storage import SQLiteStorage

SPARSE_CFG_ANALYZER = "sparse_cfg:cpp"
FUNCTION_KINDS = frozenset({"Function", "Method"})

# The same channel `sparsecfg._call_arguments` writes: the root identifier of
# every argument, in source order. Defined locally for the same reason
# `sparsedfg` and `analysis_java_scfg` define it locally -- the derived reader
# must not need the extractor's module to decode a published fact.
ARGUMENT_SEPARATOR = "\x1f"

RESOLUTION_UNKNOWN = "unknown"
RESOLUTION_UNIQUE = "unique_same_file_assignment"
RESOLUTION_AMBIGUOUS = "ambiguous_multiple_assignments"


def _annotations(event) -> dict:
    return event.get("annotations") or {}


def _resolve_targets(
    storage: SQLiteStorage, file_id: str | None, write_sources: set[str],
) -> list[dict]:
    """Resolve distinct ``write_source`` names to same-file Function/Method nodes.

    The base ``nodes`` table is the only authority (NIT #2): a name is a valid
    MAY_CALL target only when a ``Function``/``Method`` node with that short
    name and the same ``file_id`` exists. Prototype + definition of one function
    collapse at graph-build time via ``symbol_id``, and this query-side guard
    deduplicates by ``qualified_name`` as well, so the same logical function
    never counts twice (NIT #3). A name that names no function contributes
    nothing -- it is not a target and does not raise the count.
    """
    if not write_sources or file_id is None:
        return []
    by_qualified: dict[str, dict] = {}
    for source in sorted(write_sources):
        for row in storage.rows(
            "SELECT id, name, qualified_name FROM nodes "
            "WHERE kind IN ('Function','Method') AND file_id=? AND name=? "
            "ORDER BY id",
            (file_id, source),
        ):
            by_qualified.setdefault(row["qualified_name"], {
                "name": row["name"],
                "qualified_name": row["qualified_name"],
                "node_id": row["id"],
            })
    return [by_qualified[key] for key in sorted(by_qualified)]


def build_call_relation(
    events: list[dict], file_id: str | None, storage: SQLiteStorage,
) -> dict:
    """Derive per-slot MAY_CALL records from one file's sparse_cfg events.

    Pure and deterministic: the same events + storage yield the same records,
    with the slots sorted by ``(subject_decl, subject_member)`` and each slot's
    evidence lists stable-sorted.
    """
    reads_by_slot: dict[tuple[str, str], list[str]] = {}
    writes_by_slot: dict[tuple[str, str], dict] = {}
    for event in events:
        event_type = event.get("event_type")
        annotations = _annotations(event)
        decl = annotations.get("subject_decl", "")
        member = annotations.get("subject_member", "")
        if (
            event_type == "READ"
            and annotations.get("is_indirect") == "true"
            and "local_access_v1" not in annotations
        ):
            # V1 local callee facts feed definite assignment only. They are not
            # F1 shared-slot evidence and must not create legacy call relations.
            reads_by_slot.setdefault((decl, member), []).append(
                event.get("event_id"))
        elif event_type == "WRITE" and annotations.get("write_source"):
            record = writes_by_slot.setdefault(
                (decl, member), {"sources": set(), "event_ids": set()})
            record["sources"].add(annotations["write_source"])
            record["event_ids"].add(event.get("event_id"))

    relations: list[dict] = []
    for (decl, member) in sorted(reads_by_slot):
        read_ids = sorted(reads_by_slot[(decl, member)])
        writes = writes_by_slot.get((decl, member), {"sources": set(), "event_ids": set()})
        write_ids = sorted(writes["event_ids"])
        if not decl:
            # Unresolved identity: never join on the member name alone.
            targets, resolution, may_be_false_positive = [], RESOLUTION_UNKNOWN, True
        else:
            targets = _resolve_targets(storage, file_id, writes["sources"])
            if len(targets) == 0:
                resolution, may_be_false_positive = RESOLUTION_UNKNOWN, True
            elif len(targets) == 1:
                resolution, may_be_false_positive = RESOLUTION_UNIQUE, False
            else:
                resolution, may_be_false_positive = RESOLUTION_AMBIGUOUS, False
        # The frozen rule: a single target is the only case that names a target;
        # zero and two-or-more both answer an empty MAY_CALL list.
        may_call = [target["name"] for target in targets] if len(targets) == 1 else []
        relations.append({
            "subject_decl": decl,
            "subject_member": member,
            "may_call": may_call,
            "resolution": resolution,
            "may_be_false_positive": may_be_false_positive,
            "read_event_ids": read_ids,
            "write_event_ids": write_ids,
        })

    return {
        "call_relations": relations,
        "provenance": {
            "upstream_analyzer": SPARSE_CFG_ANALYZER,
            "read_slot_count": len(reads_by_slot),
            "relation_count": len(relations),
        },
    }


def query_call_relation(
    repo: str | Path, file_path: str, *, database: str | Path | None = None,
) -> dict:
    """Read one file's sparse_cfg facts and derive its MAY_CALL relations.

    C/C++ only, same-file scope. Python/Java and unbuilt/stale/corrupt files
    fall through to the sparse_cfg query's own honest status
    (``unsupported`` / ``not_built`` / ``stale`` / ``corrupt``) -- this reader
    never fabricates a target where its inputs are absent.
    """
    env = query_analysis(repo, "sparse_cfg", file_path=file_path, database=database)
    if env["status"] != "available":
        return {"status": env["status"], "reason": env.get("reason"),
                "call_relations": []}
    file_id = env.get("file_id")
    root = Path(repo).resolve()
    database = Path(database).resolve() if database else root / ".provenlattice" / "codegraph.db"
    with SQLiteStorage(database) as storage:
        result = build_call_relation(env.get("events", []), file_id, storage)
    result["status"] = "available"
    result["reason"] = None
    return result


# ---------------------------------------------------------------------------
# D1 (issue-pilot#91): cross-procedure call-site clone.
#
# The MAY_CALL reader above answers "which function can this call reach" for a
# function-pointer slot.  It deliberately stops there: the callee's own access
# rows keep the callee as their owner, so two threads that call one helper with
# two different arguments still read as one method.  D1 composes the missing
# half at query time -- every callee event is cloned to each resolved call site,
# parameter subjects are bound to the caller's argument identity, and the cloned
# rows carry the caller's thread context as their owner.  Nothing is written to
# the graph, no event id is reused, and no relation is minted.
#
# Fail-closed boundaries, all inherited from the frozen contracts:
#   * a call whose callee cannot be named (no CALLS row, a callee outside this
#     file, or a MAY_CALL slot that is ambiguous) is never cloned;
#   * an indirect call only clones through an existing `MAY_CALL` slot with
#     `unique_same_file_assignment`; ambiguous/unknown slots stay empty;
#   * parameter binding requires a declared caller-side identity.  A bare name
#     is not an object, so an unresolved argument does not produce a clone;
#   * a callee with a single call site already has one context and is not
#     cloned (the negative fixture).  At least two call sites are required;
#   * local / function-static / field subjects are not cloned.  A local dies
#     with the helper's frame, a function static is already the helper's one
#     object, and a field needs a receiver identity that belongs to G2.
# ---------------------------------------------------------------------------

CALL_SITE_RESOLVED = "resolved_call"
CALL_SITE_AMBIGUOUS = "ambiguous_call"
CALL_SITE_UNKNOWN = "unknown_call"
CALL_SITE_NOT_IN_GRAPH = "callee_not_in_graph"
CALL_SITE_OUT_OF_FILE = "callee_out_of_file"

CLONE_EVENT_TYPES = frozenset({
    "READ", "WRITE", "DEREFERENCE", "LOCK", "UNLOCK", "ATOMIC",
})
_CLONE_STORAGES = frozenset({STORAGE_GLOBAL, STORAGE_FILE_STATIC})


def _owner_symbol_id(event) -> str:
    return str(event.get("owner_symbol_id") or "")


def _owner_name(event) -> str:
    return str(event.get("owner_qualified_name") or event.get("owner_symbol_id") or "")


def _event_sort_key(event) -> tuple:
    return (
        _owner_name(event),
        int(event.get("start_byte") or 0),
        int(event.get("end_byte") or 0),
        str(event.get("event_id") or ""),
    )


def _is_indirect_read(event) -> bool:
    return (
        event.get("event_type") == "READ"
        and _annotations(event).get("is_indirect") == "true"
    )


def _json_metadata(value) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            parsed = json.loads(value)
        except ValueError:
            return {}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _direct_callee(
    storage: SQLiteStorage, file_id: str | None, owner_id: str, start_line: int,
) -> tuple[str | None, str, set[str]]:
    """Resolve one direct CALL event through its published CALLS row.

    The join is the frozen one (`(file_id, owner_symbol_id, start_line)`): a
    semantic CALL point is structural and its ``matched_name`` is
    ``call_expression``, so the callee name lives in ``raw_references``.  A key
    that names more than one function, or one whose resolution is ambiguous,
    stays unknown -- picking a winner would be the very "last assignment"
    inference the MAY_CALL contract rejects.
    """
    if not file_id or not owner_id:
        return None, CALL_SITE_UNKNOWN, {"callee_unknown"}
    rows = storage.rows(
        "SELECT raw_name, resolved_symbol_id, status, metadata FROM raw_references "
        "WHERE file_id=? AND owner_symbol_id=? AND reference_type='CALLS' "
        "AND start_line=? ORDER BY id",
        (file_id, owner_id, int(start_line)),
    )
    if not rows:
        return None, CALL_SITE_UNKNOWN, {"callee_unknown"}
    if len(rows) > 1:
        # More than one CALLS row on the key means the line carries more than
        # one call (or a duplicate/macro expansion); the callee of *this* CALL
        # point cannot be chosen without guessing.
        return None, CALL_SITE_AMBIGUOUS, {"callee_ambiguous"}
    row = rows[0]
    if str(row["status"]) == "ambiguous":
        return None, CALL_SITE_AMBIGUOUS, {"callee_ambiguous"}
    metadata = _json_metadata(row.get("metadata"))
    if (
        row["status"] != "resolved"
        or not row["resolved_symbol_id"]
        or metadata.get("call_kind") != "direct"
        # The C++ frontend's legacy rows label function-pointer calls direct;
        # only the C syntax classifier's shape is trustworthy (the same gate
        # #92 uses for lock reachability).
        or metadata.get("callee_shape") not in {"identifier", "qualified"}
    ):
        return None, CALL_SITE_NOT_IN_GRAPH, {"callee_not_in_graph"}
    return str(row["resolved_symbol_id"]), CALL_SITE_RESOLVED, set()


def _indirect_may_call(
    call: dict,
    relations: list[dict],
    indirect_reads_by_start: dict[int, list[dict]],
) -> tuple[str | None, str, str | None, set[str]]:
    """Resolve an indirect CALL through the frozen MAY_CALL derivation.

    The CALL point and the field-callee READ start at the same byte (the call
    expression starts with its callee), so the join is the published span --
    not the function name, not the line.  Returns ``(target_name, resolution,
    slot, missing)``; only a unique same-file assignment names a target.
    """
    start = int(call.get("start_byte") or 0)
    end = int(call.get("end_byte") or 0)
    owner = _owner_symbol_id(call)
    reads = [
        read for read in indirect_reads_by_start.get(start, ())
        if int(read.get("end_byte") or 0) <= end
        and _owner_symbol_id(read) == owner
    ]
    if not reads:
        return None, RESOLUTION_UNKNOWN, None, {"callee_unknown"}
    matched = []
    for read in reads:
        for relation in relations:
            if read.get("event_id") in relation.get("read_event_ids", ()):
                matched.append(relation)
    unique = {(item["subject_decl"], item["subject_member"]): item for item in matched}
    if len(unique) > 1:
        return None, RESOLUTION_AMBIGUOUS, None, {"callee_ambiguous"}
    if not unique:
        return None, RESOLUTION_UNKNOWN, None, {"callee_unknown"}
    relation = next(iter(unique.values()))
    slot = f"{relation['subject_decl']}.{relation['subject_member']}"
    if relation["resolution"] != RESOLUTION_UNIQUE or len(relation["may_call"]) != 1:
        return None, relation["resolution"], slot, {"callee_ambiguous"}
    return relation["may_call"][0], relation["resolution"], slot, set()


def _function_row(
    storage: SQLiteStorage, symbol_id: str, file_id: str | None,
) -> tuple[dict | None, str, set[str]]:
    row = storage.row(
        "SELECT id, name, qualified_name, kind, file_id, signature, metadata "
        "FROM nodes WHERE id=?",
        (symbol_id,),
    )
    if row is None or row["kind"] not in FUNCTION_KINDS:
        return None, CALL_SITE_NOT_IN_GRAPH, {"callee_not_in_graph"}
    if file_id is not None and row["file_id"] != file_id:
        return None, CALL_SITE_OUT_OF_FILE, {"callee_out_of_file"}
    return row, CALL_SITE_RESOLVED, set()


def _definition_row(storage: SQLiteStorage, node: dict) -> dict:
    """Prefer the one definition over a same-file prototype.

    A prototype and a definition are two nodes with the same qualified name
    (their signatures differ).  The call may resolve to either; the events and
    parameter names live on the definition.  More than one definition is the
    overload case and is left alone rather than picked.
    """
    rows = storage.rows(
        "SELECT id, name, qualified_name, kind, file_id, signature, metadata "
        "FROM nodes WHERE kind IN ('Function','Method') AND file_id=? "
        "AND qualified_name=? ORDER BY id",
        (node.get("file_id"), node.get("qualified_name")),
    )
    definitions = [
        row for row in rows if _json_metadata(row.get("metadata")).get("definition")
    ]
    return definitions[0] if len(definitions) == 1 else node


def _parameter_names(storage: SQLiteStorage, node: dict) -> tuple[str, ...] | None:
    """The callee's parameter list, preferring the definition's spelling.

    A prototype may omit parameter names (``(int)``); the definition usually
    has them.  Every candidate that says it is a definition is preferred, and
    disagreement inside the chosen pool stays unknown rather than guessing.
    """
    rows = storage.rows(
        "SELECT signature, metadata FROM nodes "
        "WHERE kind IN ('Function','Method') AND file_id=? AND qualified_name=? "
        "ORDER BY id",
        (node.get("file_id"), node.get("qualified_name")),
    ) or [node]
    definitions = [
        row for row in rows if _json_metadata(row.get("metadata")).get("definition")
    ]
    pool = definitions or rows
    lists: set[tuple[str, ...]] = set()
    for row in pool:
        names = tuple(split_parameters(str(row.get("signature") or "")))
        if names == ("void",):
            names = ()
        lists.add(names)
    if len(lists) != 1:
        return None
    return next(iter(lists))


def _caller_fact_index(events: list[dict]) -> dict[tuple[str, str], list[dict]]:
    """Caller-side facts about an argument root, best identity first.

    Every published row may carry the fact.  An access row is preferred to the
    CALL row (which only names the first argument), and a declared identity is
    preferred to a bare name -- the same order the 5B parameter join uses.
    """
    index: dict[tuple[str, str], list[dict]] = {}
    for event in events:
        annotations = _annotations(event)
        owner = _owner_symbol_id(event)
        subject = annotations.get("subject", "")
        if not owner or not subject:
            continue
        index.setdefault((owner, subject), []).append({
            "subject": subject,
            "subject_decl": annotations.get("subject_decl", ""),
            "subject_storage": annotations.get("subject_storage", ""),
            "subject_type": annotations.get("subject_type", ""),
            "subject_exact": annotations.get("subject_exact", "false"),
            "subject_owner": _owner_name(event),
            "subject_owner_symbol_id": owner,
            "source_event_type": event.get("event_type") or "",
            "event_id": event.get("event_id") or "",
        })
    return {
        key: sorted(
            value,
            key=lambda fact: (
                not bool(fact["subject_decl"]),
                fact["source_event_type"] == "CALL",
                fact["event_id"],
            ),
        )
        for key, value in index.items()
    }


def _pick_caller_fact(facts: list[dict] | None) -> dict | None:
    """A declared identity only.  A bare name is not an object."""
    for fact in facts or ():
        if fact.get("subject_decl"):
            return fact
    return None


def _clone_event_id(
    call_event_id: str, source_event_id: str, callee_id: str,
    subject_decl: str, subject_member: str,
) -> str:
    payload = ARGUMENT_SEPARATOR.join((
        call_event_id, source_event_id, callee_id, subject_decl, subject_member,
    ))
    return "event:clone:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _clone_event(
    source: dict, call: dict, callee: dict, bound: dict, ordinal: int,
) -> dict:
    annotations = dict(_annotations(source))
    # The versioned buffer/access facts describe the *callee's* expression and
    # embed its parameter identity (`object.decl = parameter:p`).  The clone's
    # subject is the caller's object, so carrying those blocks would publish a
    # stale nested identity.  The source event id is kept, and the original
    # block is one lookup away.
    for key in ("buffer_extent_v1", "memory_access_v1"):
        annotations.pop(key, None)
    annotations.update({
        "subject": bound["subject"],
        "subject_decl": bound["subject_decl"],
        "subject_storage": bound["subject_storage"],
        "subject_type": bound["subject_type"],
        # The callee's member path rides on the caller's root identity: the
        # callee wrote ``p->m`` and the caller handed it ``&s``, so the object
        # is ``s.m``.  This is a composition of two published facts, not a new
        # points-to result.
        "subject_member": annotations.get("subject_member", ""),
        "subject_exact": annotations.get("subject_exact", "false"),
        "subject_from": "call_site_argument",
        "call_site_event_id": call.get("event_id") or "",
        "callee_event_id": source.get("event_id") or "",
        "callee_symbol_id": callee["id"],
        "subject_owner": bound.get("subject_owner", call.get("owner_qualified_name") or ""),
        "subject_owner_symbol_id": bound.get(
            "subject_owner_symbol_id", call.get("owner_symbol_id") or ""),
        "argument_ordinal": str(ordinal) if ordinal >= 0 else "",
    })
    if bound.get("argument"):
        annotations["argument"] = bound["argument"]
    return {
        "event_id": _clone_event_id(
            call.get("event_id") or "", source.get("event_id") or "",
            callee["id"], bound["subject_decl"], annotations.get("subject_member", ""),
        ),
        "event_type": source.get("event_type"),
        "owner_symbol_id": call.get("owner_symbol_id") or "",
        "owner_qualified_name": call.get("owner_qualified_name") or "",
        "owner_kind": call.get("owner_kind") or "",
        "owner_signature": call.get("owner_signature") or "",
        "start_byte": call.get("start_byte") or 0,
        "end_byte": call.get("end_byte") or 0,
        "start_line": call.get("start_line") or 0,
        "end_line": call.get("end_line") or 0,
        "matched_name": source.get("matched_name") or "",
        "annotations": annotations,
    }


def _bound_from_annotation(annotations: dict) -> dict:
    return {
        "subject": annotations.get("subject", ""),
        "subject_decl": annotations.get("subject_decl", ""),
        "subject_storage": annotations.get("subject_storage", ""),
        "subject_type": annotations.get("subject_type", ""),
        "subject_exact": annotations.get("subject_exact", "false"),
        "argument": "",
    }


def build_call_site_clones(
    events: list[dict], file_id: str | None, storage: SQLiteStorage,
) -> dict:
    """Clone a callee's published accesses to each resolved call site.

    Pure and deterministic.  ``events`` is one file's ``sparse_cfg`` event
    list; ``storage`` is read-only and supplies the CALLS rows, function
    signatures and node identities.  The returned ``events`` are derived rows
    shaped exactly like sparse_cfg events, so a consumer can merge them into
    the same context without a second schema.
    """
    events = list(events)
    call_relation = build_call_relation(events, file_id, storage)
    relations = call_relation.get("call_relations", [])
    indirect_reads_by_start: dict[int, list[dict]] = {}
    for event in events:
        if _is_indirect_read(event):
            indirect_reads_by_start.setdefault(
                int(event.get("start_byte") or 0), []).append(event)

    events_by_owner: dict[str, list[dict]] = {}
    for event in events:
        owner = _owner_symbol_id(event)
        if owner:
            events_by_owner.setdefault(owner, []).append(event)
    for owner in events_by_owner:
        events_by_owner[owner].sort(key=_event_sort_key)

    caller_facts = _caller_fact_index(events)
    sites: list[dict] = []
    for call in sorted(
        (event for event in events if event.get("event_type") == "CALL"),
        key=_event_sort_key,
    ):
        caller_id = _owner_symbol_id(call)
        if not caller_id:
            continue
        annotations = _annotations(call)
        argument_roots = [
            name for name in str(annotations.get("arguments", "")).split(
                ARGUMENT_SEPARATOR) if name
        ]
        missing: set[str] = set()
        callee_id: str | None = None
        resolution = CALL_SITE_UNKNOWN
        via = ""
        slot = None
        target_name = ""

        if _is_indirect_read(call) or any(
            int(read.get("end_byte") or 0) <= int(call.get("end_byte") or 0)
            for read in indirect_reads_by_start.get(
                int(call.get("start_byte") or 0), ())
            if _owner_symbol_id(read) == caller_id
        ):
            target_name, resolution, slot, missing = _indirect_may_call(
                call, relations, indirect_reads_by_start)
            via = "may_call"
            if target_name:
                targets = _resolve_targets(storage, file_id, {target_name})
                if len(targets) == 1:
                    callee_id = targets[0]["node_id"]
                elif len(targets) > 1:
                    resolution = RESOLUTION_AMBIGUOUS
                    missing = {"callee_ambiguous"}
                else:
                    resolution = CALL_SITE_NOT_IN_GRAPH
                    missing = {"callee_not_in_graph"}
        else:
            callee_id, resolution, missing = _direct_callee(
                storage, file_id, caller_id,
                int(call.get("start_line") or 0),
            )
            via = "raw_references"

        callee = None
        params: tuple[str, ...] | None = None
        if callee_id:
            row, row_resolution, row_missing = _function_row(
                storage, callee_id, file_id)
            if row is None:
                callee_id = None
                resolution = row_resolution
                missing |= row_missing
            else:
                callee = _definition_row(storage, row)
                callee_id = callee["id"]
                params = _parameter_names(storage, callee)
                if not events_by_owner.get(callee_id):
                    missing.add("callee_has_no_events")

        sites.append({
            "call_site_event_id": call.get("event_id") or "",
            "caller": _owner_name(call),
            "caller_symbol_id": caller_id,
            "callee": callee["name"] if callee else (target_name or ""),
            "callee_symbol_id": callee_id or "",
            "callee_qualified_name": callee["qualified_name"] if callee else "",
            "via": via,
            "may_call_slot": slot,
            "resolution": resolution,
            "argument_roots": argument_roots,
            "parameters": list(params) if params is not None else [],
            "bindings": [],
            "cloned_event_ids": [],
            "missing_evidence": sorted(missing),
            "_call_event": call,
            "_callee": callee,
            "_params": params,
        })

    # A single call site already carries one context; cloning it would only
    # duplicate the callee under its caller's name (the negative fixture).
    by_callee: dict[str, list[dict]] = {}
    for site in sites:
        if site["callee_symbol_id"]:
            by_callee.setdefault(site["callee_symbol_id"], []).append(site)

    clone_events: list[dict] = []
    cloned_sites = 0
    for callee_id in sorted(by_callee):
        group = by_callee[callee_id]
        eligible = []
        for site in group:
            if site["caller_symbol_id"] == callee_id:
                site["missing_evidence"] = sorted(
                    set(site["missing_evidence"]) | {"recursive_call"})
            else:
                eligible.append(site)
        if len(eligible) < 2:
            for site in eligible:
                site["missing_evidence"] = sorted(
                    set(site["missing_evidence"]) | {"single_call_site"})
            continue
        for site in eligible:
            _emit_site_clones(site, events_by_owner, caller_facts, clone_events)
            if site["cloned_event_ids"]:
                cloned_sites += 1

    clone_events.sort(key=_event_sort_key)
    missing_evidence: set[str] = set()
    for site in sites:
        missing_evidence.update(site["missing_evidence"])
    for site in sites:
        site.pop("_call_event", None)
        site.pop("_callee", None)
        site.pop("_params", None)
    return {
        "call_sites": sites,
        "events": clone_events,
        "missing_evidence": sorted(missing_evidence),
        "provenance": {
            "upstream_analyzer": SPARSE_CFG_ANALYZER,
            "call_site_count": len(sites),
            "resolved_call_site_count": sum(
                1 for site in sites if site["callee_symbol_id"]),
            "cloned_call_site_count": cloned_sites,
            "cloned_event_count": len(clone_events),
        },
    }


def _emit_site_clones(
    site: dict,
    events_by_owner: dict[str, list[dict]],
    caller_facts: dict[tuple[str, str], list[dict]],
    out: list[dict],
) -> None:
    """Fill one site's bindings and cloned events (in place)."""
    call = site["_call_event"]
    callee = site["_callee"]
    params = site["_params"]
    caller_id = site["caller_symbol_id"]
    arguments = site["argument_roots"]
    missing = set(site["missing_evidence"])
    bindings: dict[tuple[str, int, str], dict] = {}

    arity_known = params is not None and len(arguments) == len(params)
    if params is None:
        missing.add("parameter_signature_unavailable")
    elif len(arguments) != len(params):
        missing.add("argument_arity_mismatch")

    for source in events_by_owner.get(callee["id"], ()):
        event_type = source.get("event_type")
        if event_type not in CLONE_EVENT_TYPES:
            continue
        annotations = _annotations(source)
        storage_class = annotations.get("subject_storage", "")
        bound: dict | None = None
        ordinal = -1

        if storage_class == STORAGE_PARAMETER:
            subject = annotations.get("subject", "")
            if event_type in {"READ", "WRITE", "DEREFERENCE", "ATOMIC"}:
                # Only a write/access *through* the parameter reaches the
                # caller's object.  `p->m` and `*p` do; a bare `p = q` rebinds
                # the callee's own by-value slot and must not be cloned (the
                # same boundary the 5B parameter join registers).
                member = annotations.get("subject_member", "")
                matched = str(source.get("matched_name") or "")
                if not member and not matched.lstrip("(").startswith("*"):
                    continue
            if not arity_known:
                # Positions after a dropped non-identifier argument cannot be
                # proved, so no parameter of this site is bound.
                continue
            try:
                ordinal = params.index(subject)
            except ValueError:
                missing.add("parameter_not_in_signature")
                continue
            argument = arguments[ordinal]
            fact = _pick_caller_fact(caller_facts.get((caller_id, argument)))
            if fact is None:
                missing.add("argument_identity_unresolved")
                continue
            bound = dict(fact)
            bound["argument"] = argument
            bindings.setdefault(
                (subject, ordinal, argument),
                {
                    "parameter": subject,
                    "ordinal": ordinal,
                    "argument": argument,
                    "subject_decl": fact["subject_decl"],
                    "subject_storage": fact["subject_storage"],
                    "subject_type": fact["subject_type"],
                    "subject_owner": fact["subject_owner"],
                    "subject_owner_symbol_id": fact["subject_owner_symbol_id"],
                    "join": "declared",
                },
            )
        elif storage_class in _CLONE_STORAGES and annotations.get("subject_decl"):
            bound = _bound_from_annotation(annotations)
        elif storage_class == STORAGE_FIELD:
            # `this->field` needs a receiver identity; that is G2's boundary.
            missing.add("field_receiver_unresolved")
            continue
        elif storage_class == STORAGE_UNKNOWN:
            missing.add("subject_identity_unresolved")
            continue
        else:
            # local / function_static: the callee's frame-owned object is not
            # the caller's object, and a function static is already the one
            # object every call shares.
            continue

        clone = _clone_event(source, call, callee, bound, ordinal)
        out.append(clone)
        site["cloned_event_ids"].append(clone["event_id"])

    site["bindings"] = [bindings[key] for key in sorted(bindings)]
    site["missing_evidence"] = sorted(missing)


def query_call_site_clones(
    repo: str | Path, file_path: str, *, database: str | Path | None = None,
) -> dict:
    """Read one file's sparse_cfg facts and derive its call-site clones.

    C/C++ only, same-file scope -- the same boundary as the frozen MAY_CALL
    reader.  Python/Java and unbuilt/stale files fall through to the
    sparse_cfg query's own honest status; this reader never fabricates a call
    site where its inputs are absent.
    """
    env = query_analysis(repo, "sparse_cfg", file_path=file_path, database=database)
    if env["status"] != "available":
        return {
            "status": env["status"], "reason": env.get("reason"),
            "call_sites": [], "events": [], "missing_evidence": [],
        }
    file_id = env.get("file_id")
    root = Path(repo).resolve()
    database = (
        Path(database).resolve() if database
        else root / ".provenlattice" / "codegraph.db"
    )
    with SQLiteStorage(database) as storage:
        result = build_call_site_clones(env.get("events", []), file_id, storage)
    result["status"] = "available"
    result["reason"] = None
    return result


__all__ = [
    "SPARSE_CFG_ANALYZER",
    "FUNCTION_KINDS",
    "RESOLUTION_UNKNOWN",
    "RESOLUTION_UNIQUE",
    "RESOLUTION_AMBIGUOUS",
    "CALL_SITE_RESOLVED",
    "CALL_SITE_AMBIGUOUS",
    "CALL_SITE_UNKNOWN",
    "CALL_SITE_NOT_IN_GRAPH",
    "CALL_SITE_OUT_OF_FILE",
    "CLONE_EVENT_TYPES",
    "build_call_relation",
    "build_call_site_clones",
    "query_call_relation",
    "query_call_site_clones",
]
