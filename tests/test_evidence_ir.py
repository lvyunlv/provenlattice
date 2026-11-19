"""Tests for the Canonical Evidence IR V1 (Issue #79, acceptance matrix M1-M15).

These tests are pure: they drive :func:`factbundle_v2_1_to_ir` and
:func:`validate_evidence_ir_v1` against the real GATE-0 fixtures plus small
synthetic bundles. They never run the engine, never touch GT/Prompt/Skill/Scorer,
and never modify the GATE-0 modules.
"""

import copy
import json
import unittest
from pathlib import Path

from provenlattice.evidence_projection import ir

FIXTURES = Path(__file__).resolve().parent.parent / "src" / "provenlattice" \
    / "evidence_projection" / "fixtures"
SCHEMA = Path(__file__).resolve().parent.parent / "src" / "provenlattice" \
    / "evidence_projection" / "schema" / "evidence_ir_v1.schema.json"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def race_bundle() -> dict:
    return load("race_factbundle_v2_1.json")


def double_free_bundle() -> dict:
    return load("double_free_factbundle_v2_1.json")


def row(event_id, access_type="READ", file="src/t.c", line=1):
    return {
        "access_type": access_type,
        "candidate_key": None,
        "event_id": event_id,
        "file": file,
        "held_locks": [],
        "line": line,
        "line_span": [line, line],
        "owner": "fn",
        "provenance": "candidate.evidence_v2.access",
        "source_fact_id": event_id,
    }


def synthetic_bundle(candidates):
    """Build a minimal but well-formed FactBundle v2.1 with the given candidates.

    ``candidates`` is a list of dicts: ``{"ckey", "identity", "subject",
    "rows", "sites"}`` where rows/sites are access-row / release-site dicts.
    """
    evidence_locations = []
    supporting_locations = []
    for cand in candidates:
        ckey = cand["ckey"]
        rows = [dict(r, candidate_key=ckey) for r in cand.get("rows", [])]
        sites = [dict(s, candidate_key=ckey) for s in cand.get("sites", [])]
        evidence_locations.append({
            "candidate_key": ckey,
            "evidence_id": ckey,
            "defect_key": "1.1",
            "discriminator": cand["identity"] + "|d",
            "identity": cand["identity"],
            "subject": cand["subject"],
            "primary_anchor": {"file": "src/t.c", "line": 1,
                               "line_span": [1, 1],
                               "provenance": "candidate.metadata.anchor_span"},
            "access_rows": rows,
            "release_sites": sites,
        })
        for r in rows:
            supporting_locations.append({
                "file": r["file"], "line": r["line"], "line_span": r["line_span"],
                "role": "shared_accesses", "semantic_role": "racing_access",
                "anchor_class": "supporting", "owner": r.get("owner", ""),
                "access_type": r["access_type"],
                "source_fact_id": r.get("source_fact_id", ""),
                "event_id": r.get("event_id", ""),
                "provenance": r["provenance"],
                "candidate_key": ckey, "held_locks": r.get("held_locks", []),
            })
        for s in sites:
            supporting_locations.append({
                "file": s["file"], "line": s["line"], "line_span": s["line_span"],
                "role": "release_sites", "semantic_role": "release_site",
                "anchor_class": "supporting", "owner": s.get("owner", ""),
                "access_type": "RELEASE",
                "source_fact_id": s.get("source_fact_id", ""),
                "event_id": s.get("event_id", ""),
                "provenance": s["provenance"],
                "candidate_key": ckey, "held_locks": [],
            })
    return {
        "api_version": "v1.1",
        "schema_version": "2.1",
        "contract_version": "skill-graph-factbundle-contract-v2.1",
        "projection_version": "factbundle-projection-v2.1",
        "adapter_version": "provenlattice-evidence-projection-v1",
        "core_adapter_version": "",
        "status": "ok",
        "defect_type": "race_condition",
        "facts": {},
        "supporting_locations": supporting_locations,
        "evidence_locations": evidence_locations,
        "location_coverage": {
            "candidates": len(evidence_locations),
            "with_primary_anchor": len(evidence_locations),
            "with_access_locations": 0,
            "with_support_locations": 0,
            "unlocated_candidates": [],
            "by_semantic_role": {"candidate_anchor": len(evidence_locations)},
        },
        "request": {"entry": "analyze_shared_access", "defect_type": "race_condition",
                    "case_workdir": ".", "database": None, "target_symbols": []},
        "error": None,
        "reason": None,
    }


class IRPositiveTests(unittest.TestCase):
    """M1: complete 9 blocks + required fields validate cleanly."""

    def test_race_bundle_validates(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])

    def test_double_free_bundle_validates(self):
        result = ir.factbundle_v2_1_to_ir(double_free_bundle())
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])

    def test_all_blocks_present(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        for block in ir.IR_BLOCKS:
            self.assertIn(block, result)
        self.assertIn("bundle_status", result)
        self.assertEqual(result["ir_schema_version"], "1")


class IRMissingFieldTests(unittest.TestCase):
    """M2: removing each block / required field fails and names the gap."""

    def test_missing_block_is_named(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        for block in ir.IR_BLOCKS:
            broken = copy.deepcopy(result)
            del broken[block]
            probs = ir.validate_evidence_ir_v1(broken)
            self.assertTrue(any("missing IR block: " + block in p for p in probs),
                            "block %s not flagged: %r" % (block, probs))

    def test_missing_run_field(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        for field in ("code_revision", "projection_version", "adapter_version",
                      "projector_version", "query_params"):
            broken = copy.deepcopy(result)
            del broken["run"][field]
            probs = ir.validate_evidence_ir_v1(broken)
            self.assertTrue(any(("run missing " + field) in p for p in probs))

    def test_missing_candidate_required_fields(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        broken = copy.deepcopy(result)
        del broken["candidates"][0]["id"]
        probs = ir.validate_evidence_ir_v1(broken)
        self.assertTrue(any("candidates[0] missing id" in p for p in probs))

    def test_missing_fact_coverage_provenance_fields(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        broken = copy.deepcopy(result)
        del broken["facts"][0]["fact_id"]
        del broken["coverage"]["source_location"]
        del broken["provenance"][0]["origin"]
        probs = ir.validate_evidence_ir_v1(broken)
        self.assertTrue(any("facts[0] missing fact_id" in p for p in probs))
        self.assertTrue(any("coverage missing source_location" in p for p in probs))
        self.assertTrue(any("provenance[0] missing origin" in p for p in probs))


class IRUnknownStateTests(unittest.TestCase):
    """M3: unknown states expressed explicitly, not faked or collapsed."""

    def test_unknown_claim_status_is_valid(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        result["claims"] = [{"claim": "candidate is a race", "status": "UNKNOWN"}]
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])

    def test_unknown_claim_status_not_collapsed_to_supported(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        result["claims"] = [{"claim": "x", "status": "PARTIAL"}]
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])
        self.assertNotEqual(result["claims"][0]["status"], "SUPPORTED")

    def test_bad_claim_status_is_flagged(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        result["claims"] = [{"claim": "x", "status": "CONFIRMED"}]
        probs = ir.validate_evidence_ir_v1(result)
        self.assertTrue(any("bad status" in p for p in probs))

    def test_fact_missing_id_is_flagged_not_faked(self):
        # a fact with no engine id is an explicit degradation -> flagged, not
        # silently accepted, and a limitation records it.
        bundle = synthetic_bundle([{
            "ckey": "C1", "identity": "global:x", "subject": "x",
            "rows": [row("", access_type="WRITE")], "sites": [],
        }])
        result = ir.factbundle_v2_1_to_ir(bundle)
        probs = ir.validate_evidence_ir_v1(result)
        self.assertTrue(any("empty fact_id" in p for p in probs))
        self.assertTrue(any("lacks an engine fact id" in l
                            for l in result["limitations"]))

    def test_relation_missing_type_is_flagged(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        result["relations"] = [{"from": "a", "to": "b"}]
        probs = ir.validate_evidence_ir_v1(result)
        self.assertTrue(any("relations[0] missing type" in p for p in probs))


class IRCrossCandidateTests(unittest.TestCase):
    """M4: facts/locations/provenance bind only to their real candidate."""

    def test_two_candidates_are_separated(self):
        bundle = synthetic_bundle([
            {"ckey": "C1", "identity": "global:a", "subject": "a",
             "rows": [row("event:A", "WRITE", line=1)], "sites": []},
            {"ckey": "C2", "identity": "global:b", "subject": "b",
             "rows": [row("event:B", "READ", line=2)], "sites": []},
        ])
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])
        by_candidate = {}
        for f in result["facts"]:
            by_candidate.setdefault(f["candidate_id"], set()).add(f["fact_id"])
        self.assertEqual(by_candidate["C1"], {"event:A"})
        self.assertEqual(by_candidate["C2"], {"event:B"})

    def test_wrong_candidate_binding_is_flagged(self):
        result = ir.factbundle_v2_1_to_ir(synthetic_bundle([
            {"ckey": "C1", "identity": "global:a", "subject": "a",
             "rows": [row("event:A", "WRITE")], "sites": []},
        ]))
        # corrupt the binding: point the fact at a non-existent candidate id
        result["facts"][0]["candidate_id"] = "NO-SUCH-CANDIDATE"
        probs = ir.validate_evidence_ir_v1(result)
        self.assertTrue(any("not in candidate ids" in p for p in probs))

    def test_release_fact_single_owner(self):
        bundle = synthetic_bundle([
            {"ckey": "C1", "identity": "global:p", "subject": "p",
             "rows": [], "sites": [row("event:R1", "RELEASE", line=5)]},
        ])
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])
        # a RELEASE fact owned by two different candidates is a merge
        result["facts"].append(dict(result["facts"][0], candidate_id="OTHER"))
        probs = ir.validate_evidence_ir_v1(result)
        self.assertTrue(any("claimed by several candidates" in p for p in probs))


class IRLosslessMappingTests(unittest.TestCase):
    """M5 + M9: real fact/event ids preserved and traceable."""

    def test_race_facts_preserve_event_ids(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        ids = {f["fact_id"] for f in result["facts"]}
        self.assertIn("event:dc28be3da118d4360824c4b3106f34c37947ed28e03dceba4161d6b5a79e7c48", ids)
        self.assertIn("event:b40801f937820c26dab6e86266b9ce61787f0b6c2ee45a5ed25cbac9a6eaf54d", ids)

    def test_double_free_facts_preserve_release_ids(self):
        result = ir.factbundle_v2_1_to_ir(double_free_bundle())
        ids = {f["fact_id"] for f in result["facts"]}
        self.assertEqual(len(ids), 2)
        for fid in ids:
            self.assertTrue(fid.startswith("event:"))

    def test_provenance_traceback(self):
        bundle = double_free_bundle()
        result = ir.factbundle_v2_1_to_ir(bundle)
        fact = result["facts"][0]
        rec = next(p for p in result["provenance"]
                   if p["fact_id"] == fact["fact_id"]
                   and p["candidate_id"] == fact["candidate_id"])
        self.assertEqual(rec["projection_version"], bundle["projection_version"])
        self.assertEqual(rec["adapter_version"], bundle["adapter_version"])
        self.assertEqual(rec["contract_version"], bundle["contract_version"])
        self.assertTrue(rec["origin"])


class IRVersionSeparationTests(unittest.TestCase):
    """M6: the four version fields are independent, projector = NOT_APPLICABLE."""

    def test_version_fields(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        self.assertEqual(result["ir_schema_version"], "1")
        self.assertEqual(result["run"]["projection_version"],
                         "factbundle-projection-v2.1")
        self.assertEqual(result["run"]["adapter_version"],
                         "provenlattice-evidence-projection-v1")
        self.assertEqual(result["run"]["projector_version"], "NOT_APPLICABLE")

    def test_projector_not_confused_with_projection(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        self.assertNotEqual(result["run"]["projector_version"],
                            result["run"]["projection_version"])
        # changing projector_version away from NOT_APPLICABLE must fail
        broken = copy.deepcopy(result)
        broken["run"]["projector_version"] = broken["run"]["projection_version"]
        probs = ir.validate_evidence_ir_v1(broken)
        self.assertTrue(any("projector_version" in p for p in probs))


class IRAdditiveTests(unittest.TestCase):
    """M7: an added optional field breaks neither schema nor semantics."""

    def test_unknown_optional_field_is_ignored(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        result["future_extension"] = {"anything": True}
        result["run"]["future_run_field"] = "x"
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])

    def test_schema_declares_required_blocks(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertEqual(schema["properties"]["ir_schema_version"]["const"], "1")
        self.assertEqual(
            set(schema["required"]),
            {"ir_schema_version", "bundle_status", "run", "candidates", "claims",
             "facts", "relations", "locations", "provenance", "coverage",
             "limitations", "source_envelope"})


class IRDeterminismTests(unittest.TestCase):
    """M8: same input -> byte-stable output."""

    def test_deterministic_serialisation(self):
        bundle = race_bundle()
        a = json.dumps(ir.factbundle_v2_1_to_ir(bundle), sort_keys=True)
        b = json.dumps(ir.factbundle_v2_1_to_ir(bundle), sort_keys=True)
        self.assertEqual(a, b)

    def test_no_input_mutation(self):
        bundle = race_bundle()
        before = json.dumps(bundle, sort_keys=True)
        ir.factbundle_v2_1_to_ir(bundle)
        self.assertEqual(json.dumps(bundle, sort_keys=True), before)


class IRDegradationTests(unittest.TestCase):
    """M10: missing location / id / facts -> explicit limitation."""

    def test_unlocated_candidate_is_limited(self):
        bundle = race_bundle()
        bundle = copy.deepcopy(bundle)
        bundle["location_coverage"]["unlocated_candidates"] = ["E-DEFECT-ghost"]
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertTrue(any("E-DEFECT-ghost" in l for l in result["limitations"]))

    def test_failed_status_is_limited(self):
        bundle = copy.deepcopy(race_bundle())
        bundle["status"] = "failed"
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertTrue(any("status=failed" in l for l in result["limitations"]))
        self.assertEqual(result["bundle_status"], "failed")


class IRSourceEnvelopeTests(unittest.TestCase):
    """M11: original fields complete, deep-copied, not normalised/coerced."""

    def test_source_envelope_is_lossless_deep_copy(self):
        bundle = race_bundle()
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertEqual(result["source_envelope"], bundle)
        self.assertIsNot(result["source_envelope"], bundle)

    def test_source_envelope_shares_no_mutable_reference(self):
        bundle = race_bundle()
        result = ir.factbundle_v2_1_to_ir(bundle)
        result["source_envelope"]["evidence_locations"][0]["candidate_key"] = "MUTATED"
        self.assertEqual(bundle["evidence_locations"][0]["candidate_key"],
                         "E-DEFECT-4e1cad3afc2ae5f2c6349606")
        # and the IR's own candidate id is untouched
        self.assertEqual(result["candidates"][0]["id"],
                         "E-DEFECT-4e1cad3afc2ae5f2c6349606")

    def test_original_types_preserved(self):
        bundle = race_bundle()
        result = ir.factbundle_v2_1_to_ir(bundle)
        env = result["source_envelope"]
        self.assertIsNone(env["error"])
        self.assertIsNone(env["reason"])
        self.assertEqual(env["core_adapter_version"], "")
        self.assertEqual(env["location_coverage"]["candidates"], 1)


class IRStatusIsolationTests(unittest.TestCase):
    """M12: bundle_status never mapped to claim status; claims=[] legal."""

    def test_bundle_status_not_mapped_to_claim_status(self):
        for status in ("ok", "empty", "unsupported_only", "stale", "failed"):
            bundle = copy.deepcopy(race_bundle())
            bundle["status"] = status
            result = ir.factbundle_v2_1_to_ir(bundle)
            self.assertEqual(result["bundle_status"], status)
            self.assertEqual(result["claims"], [])

    def test_no_supported_unsupported_auto_generated(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        self.assertEqual(result["claims"], [])
        # a bundle with no facts still yields no UNSUPPORTED claim
        empty = copy.deepcopy(race_bundle())
        empty["evidence_locations"] = []
        empty["supporting_locations"] = []
        result = ir.factbundle_v2_1_to_ir(empty)
        self.assertEqual(result["claims"], [])

    def test_empty_claims_is_valid(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        self.assertEqual(result["claims"], [])
        self.assertEqual(ir.validate_evidence_ir_v1(result), [])


class IRRunMetadataTests(unittest.TestCase):
    """M13: missing run metadata -> explicit NOT_RECORDED, never inferred."""

    def test_missing_run_metadata_is_not_recorded(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        self.assertEqual(result["run"]["code_revision"], "NOT_RECORDED")
        self.assertEqual(result["run"]["engine_version"], "NOT_RECORDED")
        self.assertEqual(result["run"]["db_snapshot_identity"], "NOT_RECORDED")

    def test_provided_run_metadata_is_used(self):
        ctx = {"code_revision": "abc123", "engine_version": "1.7.0",
               "db_snapshot_identity": "snap-42"}
        result = ir.factbundle_v2_1_to_ir(race_bundle(), run_context=ctx)
        self.assertEqual(result["run"]["code_revision"], "abc123")
        self.assertEqual(result["run"]["engine_version"], "1.7.0")
        self.assertEqual(result["run"]["db_snapshot_identity"], "snap-42")

    def test_empty_run_metadata_value_treated_as_not_recorded(self):
        ctx = {"code_revision": ""}
        result = ir.factbundle_v2_1_to_ir(race_bundle(), run_context=ctx)
        self.assertEqual(result["run"]["code_revision"], "NOT_RECORDED")


class IRRelationsCoverageTests(unittest.TestCase):
    """M14: no inferred relations; held_locks only in source_envelope."""

    def test_no_relations_inferred(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        self.assertEqual(result["relations"], [])

    def test_held_locks_not_in_locations(self):
        result = ir.factbundle_v2_1_to_ir(race_bundle())
        for loc in result["locations"]:
            self.assertNotIn("held_locks", loc)

    def test_coverage_is_only_source_location(self):
        bundle = race_bundle()
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertEqual(set(result["coverage"].keys()), {"source_location"})
        self.assertEqual(result["coverage"]["source_location"],
                         bundle["location_coverage"])


class IRCandidateIdentityTests(unittest.TestCase):
    """M15: candidate.id is the verbatim candidate_key, unique and non-empty."""

    def test_id_equals_candidate_key(self):
        bundle = race_bundle()
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertEqual(result["candidates"][0]["id"],
                         bundle["evidence_locations"][0]["candidate_key"])
        self.assertEqual(result["candidates"][0]["id"],
                         "E-DEFECT-4e1cad3afc2ae5f2c6349606")

    def test_ids_are_unique_and_non_empty(self):
        bundle = synthetic_bundle([
            {"ckey": "C1", "identity": "global:a", "subject": "a",
             "rows": [row("event:A", "WRITE", line=1)], "sites": []},
            {"ckey": "C2", "identity": "global:b", "subject": "b",
             "rows": [row("event:B", "READ", line=2)], "sites": []},
        ])
        result = ir.factbundle_v2_1_to_ir(bundle)
        ids = [c["id"] for c in result["candidates"]]
        self.assertEqual(ids, ["C1", "C2"])
        self.assertEqual(len(ids), len(set(ids)))

    def test_no_pseudo_identity_by_index(self):
        # candidate id must come from candidate_key, never a positional index
        bundle = synthetic_bundle([
            {"ckey": "ZK", "identity": "global:z", "subject": "z",
             "rows": [row("event:Z", "WRITE", line=3)], "sites": []},
        ])
        result = ir.factbundle_v2_1_to_ir(bundle)
        self.assertEqual(result["candidates"][0]["id"], "ZK")
        self.assertNotEqual(result["candidates"][0]["id"], "0")


if __name__ == "__main__":
    unittest.main()
