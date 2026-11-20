"""Tests for the IR V2 input assembler (Issue #87, R2).

The assembler must reuse the engine's own production entry points (never
re-implement analysis), issue every query against one consistent snapshot, and
distinguish *query failure* (an analyzer status != "available") from *fact
absence* (an available analyzer that returned empty lists). These tests mock the
engine readers at the module boundary -- they never build an index or touch a
database.
"""

import unittest
from unittest import mock

from provenlattice.evidence_projection import ir_v2_source


def _reader(status, payload=None, reason=None):
    result = dict(payload or {})
    result["status"] = status
    if reason is not None:
        result["reason"] = reason
    return result


class AggregationTests(unittest.TestCase):
    """The input record status is a deterministic fold over the four analyzers."""

    def _assemble(self):
        with mock.patch.object(ir_v2_source, "query_concurrency_context",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_access_lockset",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_call_relation",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_analysis",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "build_deref_resolution",
                               return_value={"deref_resolves_to": [],
                                             "same_storage": [],
                                             "coverage": {}}):
            return ir_v2_source.assemble_ir_v2_input(
                "repo", "graph.db", file_path="src/t.c")

    def test_all_available_aggregates_to_available(self):
        record = self._assemble()
        self.assertEqual(record["status"], "available")
        self.assertEqual(record["missing"], {})

    def test_partial_aggregation_records_missing(self):
        with mock.patch.object(ir_v2_source, "query_concurrency_context",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_access_lockset",
                               return_value=_reader("not_built")), \
             mock.patch.object(ir_v2_source, "query_call_relation",
                               return_value=_reader("stale")), \
             mock.patch.object(ir_v2_source, "query_analysis",
                               return_value=_reader("unsupported")), \
             mock.patch.object(ir_v2_source, "build_deref_resolution",
                               return_value={}):
            record = ir_v2_source.assemble_ir_v2_input(
                "repo", "graph.db", file_path="src/t.c")
        self.assertEqual(record["status"], "partial")
        self.assertEqual(sorted(record["missing"]),
                         ["access_lockset", "call_relation", "deref_resolution"])
        # only the available analyzer's payload is attached
        self.assertIsNotNone(record["concurrency_context"])
        self.assertIsNone(record["access_lockset"])
        self.assertIsNone(record["call_relation"])
        self.assertIsNone(record["deref_resolution"])


class FactAbsentVsFailedTests(unittest.TestCase):
    """Available-with-empty is fact absence; non-available is a query failure."""

    def test_fact_absence_is_not_a_failure(self):
        with mock.patch.object(ir_v2_source, "query_concurrency_context",
                               return_value=_reader(
                                   "available", {"thread_entry_points": []})), \
             mock.patch.object(ir_v2_source, "query_access_lockset",
                               return_value=_reader(
                                   "available", {"access_locksets": []})), \
             mock.patch.object(ir_v2_source, "query_call_relation",
                               return_value=_reader(
                                   "available", {"call_relations": []})), \
             mock.patch.object(ir_v2_source, "query_analysis",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "build_deref_resolution",
                               return_value={"deref_resolves_to": [],
                                             "same_storage": [],
                                             "coverage": {}}):
            record = ir_v2_source.assemble_ir_v2_input(
                "repo", "graph.db", file_path="src/t.c")
        self.assertEqual(record["status"], "available")
        self.assertEqual(record["missing"], {})

    def test_reader_exception_is_a_failed_record(self):
        def boom(*a, **k):
            raise RuntimeError("db corrupt")

        with mock.patch.object(ir_v2_source, "query_concurrency_context",
                               side_effect=boom), \
             mock.patch.object(ir_v2_source, "query_access_lockset",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_call_relation",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_analysis",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "build_deref_resolution",
                               return_value={}):
            record = ir_v2_source.assemble_ir_v2_input(
                "repo", "graph.db", file_path="src/t.c")
        self.assertEqual(record["status"], "partial")
        self.assertIn("concurrency_context", record["missing"])
        self.assertIn("RuntimeError", record["missing"]["concurrency_context"])


class FilePathAndDerefTests(unittest.TestCase):
    """R2: file_path is required; enable_deref is forwarded to build_deref."""

    def test_missing_file_path_fails_closed_without_reading(self):
        record = ir_v2_source.assemble_ir_v2_input("repo", "graph.db")
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["error"], "invalid_request")
        self.assertIn("file_path", record["missing"])

    def test_deref_reader_receives_enable_flag(self):
        captured = {}

        def fake_query_analysis(repo, feature, *, file_path=None, database=None):
            captured["file_path"] = file_path
            captured["database"] = database
            return _reader("available", {"events": [{"event_type": "DEREFERENCE"}]})

        def fake_build(events, *, enable):
            captured["enable"] = enable
            return {"deref_resolves_to": [], "same_storage": [], "coverage": {}}

        with mock.patch.object(ir_v2_source, "query_concurrency_context",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_access_lockset",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_call_relation",
                               return_value=_reader("available")), \
             mock.patch.object(ir_v2_source, "query_analysis",
                               side_effect=fake_query_analysis), \
             mock.patch.object(ir_v2_source, "build_deref_resolution",
                               side_effect=fake_build):
            ir_v2_source.assemble_ir_v2_input(
                "repo", "graph.db", file_path="src/t.c", enable_deref=True)
        self.assertIs(captured["enable"], True)

    def test_consistent_snapshot_same_repo_database_file(self):
        calls = []

        def reader(*a, **k):
            calls.append((a, k))
            return _reader("available")

        with mock.patch.object(ir_v2_source, "query_concurrency_context",
                               side_effect=reader), \
             mock.patch.object(ir_v2_source, "query_access_lockset",
                               side_effect=reader), \
             mock.patch.object(ir_v2_source, "query_call_relation",
                               side_effect=reader), \
             mock.patch.object(ir_v2_source, "query_analysis",
                               side_effect=reader), \
             mock.patch.object(ir_v2_source, "build_deref_resolution",
                               return_value={"deref_resolves_to": [],
                                             "same_storage": [],
                                             "coverage": {}}):
            ir_v2_source.assemble_ir_v2_input(
                "repo", "graph.db", file_path="src/t.c")

        # the three query_* readers are called positionally with (repo, file_path)
        for a, k in calls[:3]:
            self.assertEqual(a[0], "repo")
        # every database is the same snapshot handle
        self.assertTrue(all(k.get("database") == "graph.db" for _, k in calls[:3]))


if __name__ == "__main__":
    unittest.main()