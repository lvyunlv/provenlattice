"""Unit tests for the FactBundle v2.1 adapter (envelope + validation).

These tests do **not** run the engine: they drive :func:`analyze_*` /
:func:`validate_bundle_v2` against a stubbed ``query_defect`` source and the
real captured fixtures, so the envelope shape, version surface, status mapping
and fail-closed binding are testable without a graph DB.
"""

import json
import unittest
from pathlib import Path
from unittest import mock

from provenlattice.evidence_projection import adapter
from provenlattice.evidence_projection import constants as C

FIXTURES = Path(__file__).resolve().parent.parent / "src" / "provenlattice" \
    / "evidence_projection" / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def source_ok(result: dict) -> dict:
    return {"status": C.ST_OK, "result": result, "error": None, "reason": None}


class EnvelopeValidationTests(unittest.TestCase):
    def test_validate_real_race_bundle(self) -> None:
        bundle = load("race_factbundle_v2_1.json")
        probs = adapter.validate_bundle_v2("analyze_shared_access", bundle)
        self.assertEqual(probs, [])
        self.assertEqual(bundle["api_version"], "v1.1")
        self.assertEqual(bundle["schema_version"], "2.1")
        self.assertEqual(bundle["location_coverage"]["candidates"], 1)

    def test_validate_real_double_free_bundle(self) -> None:
        bundle = load("double_free_factbundle_v2_1.json")
        probs = adapter.validate_bundle_v2("analyze_double_free", bundle)
        self.assertEqual(probs, [])
        # double-free release sites must be candidate-bound with fact ids
        sites = [l for l in bundle["supporting_locations"]
                 if l["semantic_role"] == "release_site"]
        self.assertGreaterEqual(len(sites), 2)
        for s in sites:
            self.assertTrue(s["candidate_key"])
            self.assertTrue(s["source_fact_id"].startswith("event:"))


class StatusMappingTests(unittest.TestCase):
    def _run(self, source_result: dict, entry: str = "analyze_double_free") -> dict:
        with mock.patch.object(adapter, "query_defect", return_value=source_result):
            if entry == "analyze_double_free":
                return adapter.analyze_double_free("repo", "graph.db")
            return adapter.analyze_shared_access("repo", "graph.db")

    def test_ok_maps_to_ok(self) -> None:
        cand = load("double_free_candidate.json")
        b = self._run(source_ok({"candidates": [cand]}))
        self.assertEqual(b["status"], "ok")
        self.assertEqual(b["location_coverage"]["candidates"], 1)
        self.assertEqual(adapter.validate_bundle_v2("analyze_double_free", b), [])

    def test_empty_maps_to_empty(self) -> None:
        b = self._run({"status": "empty", "result": {"candidates": []},
                       "error": None, "reason": None})
        self.assertEqual(b["status"], "empty")
        self.assertEqual(b["location_coverage"]["candidates"], 0)
        self.assertEqual(b["evidence_locations"], [])
        self.assertEqual(adapter.validate_bundle_v2("analyze_double_free", b), [])

    def test_stale_not_built_failed_terminals_carry_zero_candidates(self) -> None:
        for src_status, env_status in (
            ("stale", "stale"),
            ("not_built", "not_built"),
            ("failed", "failed"),
        ):
            b = self._run({"status": src_status, "result": None,
                           "error": "e", "reason": "r"})
            self.assertEqual(b["status"], env_status)
            self.assertEqual(b["location_coverage"]["candidates"], 0)
            self.assertEqual(b["evidence_locations"], [])
            self.assertEqual(adapter.validate_bundle_v2("analyze_double_free", b), [])


class RequestEchoTests(unittest.TestCase):
    def test_request_echo_records_target_symbols(self) -> None:
        cand = load("race_candidate.json")
        with mock.patch.object(adapter, "query_defect", return_value=source_ok(
                {"candidates": [cand]})) as src:
            b = adapter.analyze_shared_access("repo", "graph.db",
                                              target_symbols=("shared",))
            args, kwargs = src.call_args
        self.assertEqual(kwargs["subject"], "shared")
        self.assertEqual(b["request"]["target_symbols"], ["shared"])
        self.assertEqual(b["request"]["entry"], "analyze_shared_access")


class VersionSurfaceTests(unittest.TestCase):
    def test_version_constants(self) -> None:
        self.assertEqual(adapter.API_VERSION, "v1.1")
        self.assertEqual(adapter.SCHEMA_VERSION, "2.1")
        self.assertEqual(adapter.CONTRACT_VERSION,
                         "skill-graph-factbundle-contract-v2.1")
        self.assertEqual(adapter.PROJECTION_VERSION, "factbundle-projection-v2.1")

    def test_all_v2_keys_stamped(self) -> None:
        cand = load("race_candidate.json")
        with mock.patch.object(adapter, "query_defect", return_value=source_ok(
                {"candidates": [cand]})):
            b = adapter.analyze_shared_access("repo", "graph.db")
        for k in adapter.V2_ADDED_KEYS:
            self.assertIn(k, b)


if __name__ == "__main__":
    unittest.main()
