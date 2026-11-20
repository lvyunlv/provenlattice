"""Tests for the Canonical Evidence IR V2 (Issue #87, M1-M10).

Pure and engine-free: they drive :func:`ir_v2.assemble_ir_v2` and
:func:`ir_v2.validate_evidence_ir_v2` against synthetic IR V2 input records
that mirror the exact field shapes of the engine's ``build_*`` / ``query_*``
outputs (field names audited from ``analysis_concurrency_context``,
``concurrency_lock_scenarios``, ``analysis_call_relation``,
``deref_resolution``). They never import the engine and never read the DB.

The fixtures exercise each of the five concurrency fact classes across the four
M10 axes:

* positive  -- a fact/relation whose trigger conditions are met is produced;
* negative  -- a fact whose trigger condition is absent is NOT produced (and
  never fabricated);
* UNKNOWN   -- an unresolved identity degrades to ``unresolved`` / ``unknown``;
* PARTIAL   -- a non-empty ``limitation``/``missing`` degrades honestly.
"""

import copy
import json
import unittest

from provenlattice.evidence_projection import ir_v2

# The six fact types and eight relation types the IR V2 must decompose the five
# skill-named concurrency fact classes into (field-mapping matrix §0).
FACT_TYPES = {
    "shared_access", "thread_entry_point", "thread_spawn", "thread_join",
    "resource_lifetime", "may_parallel", "held_locks",
}
RELATION_TYPES = {
    "spawn_join", "protect", "same_lock", "different_lock",
    "unlock_omitted_on_path", "may_call", "deref_resolves_to", "same_storage",
}


def serialize(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# synthetic analyzer outputs (field-exact vs the engine producers)
# ---------------------------------------------------------------------------

def _concurrency_context():
    # thread_entry_points / spawns / joins / spawn_join_pairs / resource_lifetime
    # / may_parallel, from analysis_concurrency_context.build_concurrency_context.
    return {
        "thread_entry_points": ["main", "worker"],
        "spawns": [
            {"event_id": "s1", "owner": "main", "handle": "t",
             "handle_decl": "main:t", "thread_function": "worker",
             "start_byte": 10, "end_byte": 20},
            {"event_id": "s2", "owner": "main", "handle": "u",
             "handle_decl": "main:u", "thread_function": "worker",
             "start_byte": 100, "end_byte": 110},
        ],
        "joins": [
            {"event_id": "j1", "owner": "main", "handle": "t",
             "handle_decl": "main:t", "start_byte": 30, "end_byte": 40},
        ],
        "spawn_join_pairs": [
            {"owner": "main", "handle_decl": "main:t",
             "thread_function": "worker", "spawn": "s1", "join": "j1"},
        ],
        "resource_lifetime": [
            {"object": "local:x", "object_decl": "x", "object_name": "x",
             "thread_function": "worker", "handle": "u", "handle_decl": "main:u",
             "spawn_event_id": "s2", "spawn_start_byte": 100, "join_count": 0,
             "is_alive_at_access": False, "lifecycle_sequence": ["SPAWN", "DESTROY"]},
        ],
        "may_parallel": [
            {"identity": "main:g", "subject": "g", "storage": "global",
             "exact": "true", "unresolved": False,
             "owners": ["main", "worker"], "thread_entry_owners": ["worker"],
             "accesses": [
                 {"event_id": "a1", "event_type": "READ", "owner": "main",
                  "start_byte": 1, "end_byte": 2, "exact": "true"},
                 {"event_id": "a2", "event_type": "WRITE", "owner": "worker",
                  "start_byte": 3, "end_byte": 4, "exact": "true"},
             ],
             "evidence_references": ["a1", "a2"],
             "missing_evidence": [],
             "candidate_state": "ambiguous"},
            {"identity": None, "subject": "h", "storage": "unknown",
             "exact": "false", "unresolved": True,
             "owners": ["main", "worker"], "thread_entry_owners": [],
             "accesses": [
                 {"event_id": "a3", "event_type": "READ", "owner": "main",
                  "start_byte": 5, "end_byte": 6, "exact": "false"},
             ],
             "evidence_references": ["a3"],
             "missing_evidence": ["identity_unresolved"],
             "candidate_state": "unresolved"},
        ],
        "missing_evidence": [],
        "capability_gaps": [],
    }


def _access_lockset():
    # access_locksets / relations / coverage, from
    # concurrency_lock_scenarios.build_access_lockset.
    return {
        "access_locksets": [
            {"access_event_id": "a1", "event_type": "READ", "owner": "main",
             "owner_symbol_id": "main_sym", "subject": "g",
             "subject_decl": "main:g", "start_line": 10, "end_line": 10,
             "held_locks": ["lk1"], "limitation": [],
             "candidate_state": "ambiguous"},
            {"access_event_id": "a2", "event_type": "WRITE", "owner": "worker",
             "owner_symbol_id": "worker_sym", "subject": "g",
             "subject_decl": "main:g", "start_line": 20, "end_line": 20,
             "held_locks": ["lk1"], "limitation": ["lock_identity_inexact"],
             "candidate_state": "ambiguous"},
        ],
        "relations": [
            {"relation": "PROTECTS", "lock": "lk1", "access_event_id": "a1",
             "owner": "main", "owner_symbol_id": "main_sym"},
            {"relation": "UNLOCK_OMITTED_ON_PATH", "lock": "lk1",
             "access_event_id": "a1", "owner": "main",
             "owner_symbol_id": "main_sym", "candidate_state": "ambiguous"},
            {"relation": "SAME_LOCK", "subject": "main:g",
             "subject_decl": "main:g", "access_event_ids": ["a1", "a2"],
             "owners": ["main", "worker"], "locks": ["lk1"]},
            {"relation": "DIFFERENT_LOCK", "subject": "main:g",
             "subject_decl": "main:g", "access_event_ids": ["a1", "a2"],
             "owners": ["main", "worker"], "unprotected": False},
        ],
        "coverage": {
            "accesses": 2, "protected_accesses": 2, "unprotected_accesses": 0,
            "relations": {"PROTECTS": 1, "SAME_LOCK": 1, "DIFFERENT_LOCK": 1,
                          "UNLOCK_OMITTED_ON_PATH": 1},
        },
    }


def _call_relation():
    # call_relations / provenance, from analysis_call_relation.build_call_relation.
    return {
        "call_relations": [
            {"subject_decl": "main:c", "subject_member": "cb",
             "may_call": ["target_fn"],
             "resolution": "unique_same_file_assignment",
             "may_be_false_positive": False,
             "read_event_ids": ["r1"], "write_event_ids": ["w1"]},
            {"subject_decl": "main:d", "subject_member": "db",
             "may_call": [], "resolution": "unknown",
             "may_be_false_positive": True,
             "read_event_ids": ["r2"], "write_event_ids": []},
            {"subject_decl": "main:e", "subject_member": "eb",
             "may_call": [], "resolution": "ambiguous_multiple_assignments",
             "may_be_false_positive": False,
             "read_event_ids": ["r3"], "write_event_ids": ["w3"]},
        ],
        "provenance": {"upstream_analyzer": "sparse_cfg:cpp",
                       "read_slot_count": 3, "relation_count": 3},
    }


def _deref_resolution():
    # deref_resolves_to / same_storage / coverage, from
    # deref_resolution.build_deref_resolution (enable=True).
    return {
        "deref_resolves_to": [
            {"access_event_id": "d1", "owner": "worker", "expression": "p",
             "start_line": 15, "deref_resolves_to": "local:x",
             "confidence": "must"},
            {"access_event_id": "d2", "owner": "main", "expression": "q",
             "start_line": 25, "deref_resolves_to": "local:y",
             "confidence": "may"},
            {"access_event_id": "d3", "owner": "main", "expression": "r",
             "start_line": 35, "deref_resolves_to": "", "confidence": "unknown"},
        ],
        "same_storage": [
            {"storage_object_id": "local:x", "same_storage": "true",
             "deref_resolves_to": "local:x",
             "accesses": [
                 {"access_event_id": "d1", "event_type": "DEREFERENCE",
                  "owner": "worker", "expression": "p", "start_line": 15,
                  "deref_resolves_to": "local:x", "confidence": "must"},
                 {"access_event_id": "d4", "event_type": "DEREFERENCE",
                  "owner": "worker2", "expression": "p", "start_line": 16,
                  "deref_resolves_to": "local:x", "confidence": "must"},
             ]},
        ],
        "coverage": {"dereferences": 3, "resolved_must": 1, "resolved_may": 1,
                     "resolved_unknown": 1, "same_storage_pairs": 1},
    }


def full_input_record():
    """A fully-available input record exercising every fact/relation type."""
    return {
        "defect_type": "race_condition",
        "file_path": "src/t.c",
        "status": "available",
        "reason": None,
        "missing": {},
        "concurrency_context": _concurrency_context(),
        "access_lockset": _access_lockset(),
        "call_relation": _call_relation(),
        "deref_resolution": _deref_resolution(),
        "baseline_bundle": None,
        "enable_deref": True,
        "error": None,
    }


def empty_available_record():
    """All four analyzers available but with empty fact outputs (fact absence,
    not query failure)."""
    return {
        "defect_type": "race_condition",
        "file_path": "src/empty.c",
        "status": "available",
        "reason": None,
        "missing": {},
        "concurrency_context": {
            "thread_entry_points": [], "spawns": [], "joins": [],
            "spawn_join_pairs": [], "resource_lifetime": [],
            "may_parallel": [], "missing_evidence": [], "capability_gaps": [],
        },
        "access_lockset": {"access_locksets": [], "relations": [], "coverage": {}},
        "call_relation": {"call_relations": [], "provenance": {}},
        "deref_resolution": {"deref_resolves_to": [], "same_storage": [],
                             "coverage": {}},
        "baseline_bundle": None,
        "enable_deref": False,
        "error": None,
    }


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

class SixFactsEightRelationsTests(unittest.TestCase):
    """M1: the five concurrency fact classes decompose into 6 Facts + 8 Relations."""

    def setUp(self):
        self.evidence = ir_v2.assemble_ir_v2(full_input_record())

    def test_all_fact_types_are_produced(self):
        produced = {f["fact_type"] for f in self.evidence["facts"]}
        # All six except shared_access (which needs a baseline bundle).
        self.assertEqual(produced,
                         {"thread_entry_point", "thread_spawn", "thread_join",
                          "resource_lifetime", "may_parallel", "held_locks"})

    def test_all_relation_types_are_produced(self):
        produced = {r["relation_type"] for r in self.evidence["relations"]}
        self.assertEqual(produced, RELATION_TYPES)

    def test_spawn_join_endpoints_reference_event_ids(self):
        rel = next(r for r in self.evidence["relations"]
                   if r["relation_type"] == "spawn_join")
        self.assertEqual(rel["endpoints"], ["s1", "j1"])

    def test_protect_endpoints_are_lock_then_access(self):
        rel = next(r for r in self.evidence["relations"]
                   if r["relation_type"] == "protect")
        self.assertEqual(rel["endpoints"], ["lk1", "a1"])

    def test_may_call_endpoints_are_slot_then_target(self):
        rel = next(r for r in self.evidence["relations"]
                   if r["relation_type"] == "may_call"
                   and r["confidence"] == "unique_same_file_assignment")
        self.assertEqual(rel["endpoints"], ["main:c.cb", "target_fn"])

    def test_same_storage_endpoints_are_two_accesses(self):
        rel = next(r for r in self.evidence["relations"]
                   if r["relation_type"] == "same_storage")
        self.assertEqual(rel["endpoints"], ["d1", "d4"])


class ConfidenceConstraintTests(unittest.TestCase):
    """M2/M4: may_parallel / held_locks are never definite, DEREF three-state,
    may_call fail-closed."""

    def setUp(self):
        self.evidence = ir_v2.assemble_ir_v2(full_input_record())

    def test_may_parallel_never_definite(self):
        states = {f["confidence"] for f in self.evidence["facts"]
                  if f["fact_type"] == "may_parallel"}
        self.assertEqual(states, {"ambiguous", "unresolved"})
        self.assertNotIn("definite", states)

    def test_held_locks_always_ambiguous(self):
        states = {f["confidence"] for f in self.evidence["facts"]
                  if f["fact_type"] == "held_locks"}
        self.assertEqual(states, {"ambiguous"})

    def test_deref_three_state_no_upgrade(self):
        states = {r["confidence"] for r in self.evidence["relations"]
                  if r["relation_type"] == "deref_resolves_to"}
        self.assertEqual(states, {"must", "may", "unknown"})

    def test_may_call_fail_closed_resolutions(self):
        states = {r["confidence"] for r in self.evidence["relations"]
                  if r["relation_type"] == "may_call"}
        self.assertEqual(states, {"unknown", "unique_same_file_assignment",
                                  "ambiguous_multiple_assignments"})

    def test_same_storage_must_only(self):
        states = {r["confidence"] for r in self.evidence["relations"]
                  if r["relation_type"] == "same_storage"}
        self.assertEqual(states, {"must"})

    def test_resource_lifetime_is_candidate(self):
        states = {f["confidence"] for f in self.evidence["facts"]
                  if f["fact_type"] == "resource_lifetime"}
        self.assertEqual(states, {"candidate"})


class NotProducedTests(unittest.TestCase):
    """M9: happens_before and guarded_by stay not_produced, never relations."""

    def test_coverage_not_produced_explicit(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        self.assertEqual(evidence["coverage"]["not_produced"],
                         ["happens_before", "guarded_by"])

    def test_relations_never_emit_happens_before_or_guarded_by(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        types = {r["relation_type"] for r in evidence["relations"]}
        self.assertNotIn("happens_before", types)
        self.assertNotIn("guarded_by", types)
        self.assertNotIn("HAPPENS_BEFORE", types)
        self.assertNotIn("GUARDED_BY", types)


class CandidateIdNullableTests(unittest.TestCase):
    """M3: file-level facts carry candidate_id=null (not evidence-invalid)."""

    def test_file_level_facts_and_relations_are_null(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        self.assertEqual(evidence["candidates"], [])
        for f in evidence["facts"]:
            self.assertIsNone(f["candidate_id"], f["fact_type"])
        for r in evidence["relations"]:
            self.assertIsNone(r["candidate_id"], r["relation_type"])


class BaselineTests(unittest.TestCase):
    """Candidate-bound shared_access facts when a baseline bundle is supplied."""

    def test_baseline_bundle_produces_candidate_bound_facts(self):
        bundle = {
            "defect_type": "race_condition",
            "projection_version": "factbundle-projection-v2.1",
            "adapter_version": "provenlattice-evidence-projection-v1",
            "core_adapter_version": "core-1",
            "evidence_locations": [
                {"candidate_key": "ck-1", "evidence_id": "E-1", "defect_key": "d",
                 "discriminator": "di", "identity": "id", "subject": "s",
                 "primary_anchor": {"file": "src/t.c", "line": 1},
                 "access_rows": [
                     {"source_fact_id": "f1", "event_id": "e1",
                      "access_type": "READ", "file": "src/t.c", "line": 9,
                      "line_span": [9, 9], "provenance": "p"},
                 ]},
            ],
            "supporting_locations": [
                {"candidate_key": "ck-1", "file": "src/t.c", "line": 9,
                 "line_span": [9, 9], "owner": "o", "role": "r",
                 "semantic_role": "racing_access", "anchor_class": "supporting",
                 "source_fact_id": "f1", "event_id": "e1", "provenance": "p"},
            ],
        }
        record = empty_available_record()
        record["baseline_bundle"] = bundle
        evidence = ir_v2.assemble_ir_v2(record)

        self.assertEqual([c["id"] for c in evidence["candidates"]], ["ck-1"])
        shared = [f for f in evidence["facts"]
                  if f["fact_type"] == "shared_access"]
        self.assertEqual(len(shared), 1)
        self.assertEqual(shared[0]["candidate_id"], "ck-1")
        # any non-null candidate_id must bind to a real candidate id
        self.assertEqual(ir_v2.validate_evidence_ir_v2(evidence), [])


class VersionSeparationTests(unittest.TestCase):
    """M5: ir_schema_version == "2", projector_version distinct from
    projection_version."""

    def test_version_separation(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        self.assertEqual(evidence["ir_schema_version"], "2")
        run = evidence["run"]
        self.assertEqual(run["projector_version"], "2")
        self.assertEqual(run["contract_version"], "canonical-evidence-ir-v2")
        self.assertNotEqual(run["projector_version"], run["projection_version"])


class DeterminismTests(unittest.TestCase):
    """M10: byte-stable output for equal input."""

    def test_assembly_is_deterministic(self):
        a = ir_v2.assemble_ir_v2(full_input_record())
        b = ir_v2.assemble_ir_v2(full_input_record())
        self.assertEqual(serialize(a), serialize(b))

    def test_assembly_does_not_mutate_input(self):
        record = full_input_record()
        snapshot = copy.deepcopy(record)
        ir_v2.assemble_ir_v2(record)
        self.assertEqual(serialize(record), serialize(snapshot))


class ValidationTests(unittest.TestCase):
    """M5: the validator accepts valid IR and rejects violations."""

    def test_valid_output_passes(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        self.assertEqual(ir_v2.validate_evidence_ir_v2(evidence), [])

    def test_rejects_wrong_schema_version(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        evidence["ir_schema_version"] = "1"
        problems = ir_v2.validate_evidence_ir_v2(evidence)
        self.assertTrue(any("bad ir_schema_version" in p for p in problems))

    def test_rejects_may_parallel_definite(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        for f in evidence["facts"]:
            if f["fact_type"] == "may_parallel":
                f["confidence"] = "definite"
                break
        problems = ir_v2.validate_evidence_ir_v2(evidence)
        self.assertTrue(any("bad confidence" in p for p in problems))

    def test_rejects_guarded_by_relation(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        evidence["relations"].append({
            "relation_id": "gb1", "relation_type": "guarded_by",
            "candidate_id": None, "confidence": "must",
            "endpoints": ["f", "a"], "payload": {},
        })
        problems = ir_v2.validate_evidence_ir_v2(evidence)
        self.assertTrue(any("bad relation_type" in p for p in problems))

    def test_rejects_dangling_candidate_id(self):
        evidence = ir_v2.assemble_ir_v2(full_input_record())
        evidence["facts"][0]["candidate_id"] = "does-not-exist"
        problems = ir_v2.validate_evidence_ir_v2(evidence)
        self.assertTrue(any("not in candidate ids" in p for p in problems))


class QueryFailedVsFactAbsentTests(unittest.TestCase):
    """R2: query failure is a limitation; fact absence is not."""

    def test_available_with_empty_lists_is_not_a_failure(self):
        evidence = ir_v2.assemble_ir_v2(empty_available_record())
        self.assertEqual(evidence["bundle_status"], "ok")
        self.assertEqual(evidence["facts"], [])
        self.assertEqual(evidence["relations"], [])
        self.assertEqual(evidence["limitations"], [])

    def test_missing_analyzer_is_a_limitation(self):
        record = empty_available_record()
        record["status"] = "partial"
        record["missing"] = {"access_lockset": "not_built"}
        evidence = ir_v2.assemble_ir_v2(record)
        self.assertEqual(evidence["bundle_status"], "partial")
        self.assertTrue(any("access_lockset" in lim
                            for lim in evidence["limitations"]))

    def test_capability_gaps_become_limitations(self):
        record = empty_available_record()
        record["concurrency_context"]["capability_gaps"] = [
            "THREAD_JOIN carries no thread handle in the events layer"]
        evidence = ir_v2.assemble_ir_v2(record)
        self.assertTrue(any("capability gap" in lim
                            for lim in evidence["limitations"]))


class DerefDefaultOffTests(unittest.TestCase):
    """Decision 1: DEREF is default-OFF and must be requested explicitly."""

    def test_query_params_record_enable_deref(self):
        on = ir_v2.assemble_ir_v2(full_input_record())
        self.assertIs(on["run"]["query_params"]["enable_deref"], True)
        off = ir_v2.assemble_ir_v2(empty_available_record())
        self.assertIs(off["run"]["query_params"]["enable_deref"], False)

    def test_deref_relations_derive_only_from_deref_resolution(self):
        record = empty_available_record()
        record["deref_resolution"] = _deref_resolution()
        evidence = ir_v2.assemble_ir_v2(record)
        types = {r["relation_type"] for r in evidence["relations"]}
        self.assertIn("deref_resolves_to", types)
        self.assertIn("same_storage", types)


if __name__ == "__main__":
    unittest.main()