"""E2E tests: real index -> real query -> FactBundle v2.1 projection.

Builds a real ProvenLattice graph index over known-good C buffer fixtures and
runs the two public entry points end-to-end, including the fail-closed
negative / empty / stale / not-built paths. These tests exercise the *real*
engine chain (``full_index`` -> ``analyze_scope`` -> ``query_defect_candidates``)
that ``adapter`` wraps, so they are the strongest evidence that the projection
consumes real candidates.
"""

import tempfile
import unittest
from pathlib import Path

from provenlattice.evidence_projection import (
    analyze_double_free,
    analyze_shared_access,
    validate_bundle_v2,
)
from provenlattice.graph import full_index
from provenlattice.orchestrator import analyze_scope

DF_POSITIVE = """#include <stdlib.h>
int df_pos(int n) {
    char *p = malloc(64);
    if (!p) return -1;
    free(p);
    free(p);
    return n;
}
"""

DF_NEGATIVE = """#include <stdlib.h>
int df_neg(int n) {
    char *p = malloc(64);
    if (!p) return -1;
    if (n) { free(p); }
    else { free(p); }
    return n;
}
"""

RACE_POSITIVE = """#include <pthread.h>
int shared = 0;
void *writer(void *arg) { shared = 42; return NULL; }
void *reader(void *arg) { return (void *)(long)shared; }
"""

RACE_NEGATIVE = """void independent(void) {
    int local_a = 1;
    int local_b = 2;
    local_a += local_b;
}
"""


def write(root: Path, relative: str, value: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8"))


class ProjectionE2EBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.database = Path(self.temp.name) / "graph.db"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def build(self, src: str) -> None:
        write(self.root, "src/t.c", src)
        full_index(self.root, self.database)
        analyze_scope(self.root, "src", ("defect",), database=self.database)


class DoubleFreeE2ETests(ProjectionE2EBase):
    def test_positive_candidate_bound_release_sites(self) -> None:
        self.build(DF_POSITIVE)
        bundle = analyze_double_free(str(self.root), self.database)
        self.assertEqual(bundle["status"], "ok")
        cov = bundle["location_coverage"]
        self.assertEqual(cov["candidates"], 1)
        self.assertEqual(cov["with_support_locations"], 1)

        ev = bundle["evidence_locations"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["defect_key"], "4.2")
        sites = ev[0]["release_sites"]
        self.assertEqual(len(sites), 2)
        for s in sites:
            self.assertTrue(s["candidate_key"].startswith("E-DEFECT-"))
            self.assertTrue(s["source_fact_id"].startswith("event:"))
            self.assertTrue(s["file"])
            self.assertTrue(s["line"])
        self.assertEqual(validate_bundle_v2("analyze_double_free", bundle), [])

    def test_negative_zero_candidates(self) -> None:
        self.build(DF_NEGATIVE)
        bundle = analyze_double_free(str(self.root), self.database)
        self.assertEqual(bundle["status"], "empty")
        self.assertEqual(bundle["location_coverage"]["candidates"], 0)
        self.assertEqual(validate_bundle_v2("analyze_double_free", bundle), [])

    def test_stale_upstream(self) -> None:
        # index but skip the sparse_dfg analysis -> the query fails closed as
        # stale; the bundle must report zero candidates, never partial facts.
        write(self.root, "src/t.c", DF_POSITIVE)
        full_index(self.root, self.database)
        bundle = analyze_double_free(str(self.root), self.database)
        self.assertEqual(bundle["status"], "stale")
        self.assertEqual(bundle["location_coverage"]["candidates"], 0)
        self.assertEqual(validate_bundle_v2("analyze_double_free", bundle), [])

    def test_not_built(self) -> None:
        # never indexed -> base_graph_required -> not_built
        write(self.root, "src/t.c", DF_POSITIVE)
        bundle = analyze_double_free(str(self.root), self.database)
        self.assertEqual(bundle["status"], "not_built")
        self.assertEqual(bundle["error"], "base_graph_required")
        self.assertEqual(bundle["location_coverage"]["candidates"], 0)
        self.assertEqual(validate_bundle_v2("analyze_double_free", bundle), [])


class SharedAccessE2ETests(ProjectionE2EBase):
    def test_positive_candidate_bound_access_rows(self) -> None:
        self.build(RACE_POSITIVE)
        bundle = analyze_shared_access(str(self.root), self.database)
        self.assertEqual(bundle["status"], "ok")
        cov = bundle["location_coverage"]
        self.assertEqual(cov["candidates"], 1)
        self.assertEqual(cov["with_access_locations"], 1)

        ev = bundle["evidence_locations"]
        self.assertEqual(len(ev), 1)
        self.assertEqual(ev[0]["defect_key"], "1.1")
        rows = ev[0]["access_rows"]
        self.assertEqual(len(rows), 2)
        kinds = {r["access_type"] for r in rows}
        self.assertTrue({"READ", "WRITE"} <= kinds)
        for r in rows:
            self.assertTrue(r["candidate_key"].startswith("E-DEFECT-"))
            # v1 access-row keys are present
            for k in ("method", "file", "line", "kind", "non_atomic", "decided"):
                self.assertIn(k, r)
        self.assertEqual(validate_bundle_v2("analyze_shared_access", bundle), [])

    def test_negative_zero_candidates(self) -> None:
        self.build(RACE_NEGATIVE)
        bundle = analyze_shared_access(str(self.root), self.database)
        self.assertEqual(bundle["status"], "empty")
        self.assertEqual(bundle["location_coverage"]["candidates"], 0)
        self.assertEqual(validate_bundle_v2("analyze_shared_access", bundle), [])

    def test_bundle_is_deterministic(self) -> None:
        # M10: same input + snapshot -> byte-stable output (analysis is a pure
        # reader, so a second run over the same DB returns the identical bundle).
        self.build(RACE_POSITIVE)
        first = analyze_shared_access(str(self.root), self.database)
        second = analyze_shared_access(str(self.root), self.database)
        self.assertEqual(first, second)


class DeterminismE2ETests(ProjectionE2EBase):
    def test_double_free_bundle_deterministic(self) -> None:
        self.build(DF_POSITIVE)
        first = analyze_double_free(str(self.root), self.database)
        second = analyze_double_free(str(self.root), self.database)
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()