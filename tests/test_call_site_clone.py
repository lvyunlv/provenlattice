"""D1 (issue-pilot#91): cross-procedure call-site clone for MAY_CALL.

Freezes the additive, query-time contract:

* a callee called from two sites is cloned to each site; a parameter subject is
  bound to the caller's declared argument identity (``p -> global:g1`` and
  ``p -> global:g2``), never merged by the parameter's spelling;
* lock parameters are bound the same way, so ``lock(l)`` becomes two contexts
  with ``global:m1`` and ``global:m2``;
* a callee with one call site already has one context and is not cloned;
* an indirect call only clones through an existing ``MAY_CALL`` slot whose
  resolution is ``unique_same_file_assignment``; ambiguous/unknown slots stay
  empty and fail closed;
* the cloned rows keep the source event id, are owned by the caller (the thread
  context), and a consumer can merge them into the concurrency context without
  a second schema;
* the reader is pure and deterministic, and never changes an existing event id
  or edge.
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from provenlattice.analysis_call_relation import (
    CALL_SITE_OUT_OF_FILE,
    CALL_SITE_RESOLVED,
    RESOLUTION_AMBIGUOUS,
    RESOLUTION_UNIQUE,
    build_call_site_clones,
    query_call_site_clones,
)
from provenlattice.analysis_concurrency_context import (
    build_concurrency_context,
    query_concurrency_context,
)
from provenlattice.analysis_query import query_analysis
from provenlattice.graph import full_index
from provenlattice.orchestrator import analyze_scope
from provenlattice.storage import SQLiteStorage


def write(root: Path, relative: str, value: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8"))


class CallSiteCloneTestBase(unittest.TestCase):
    FIXTURE: str = ""
    FILENAME: str = "src/a.c"
    EXTRA_FILES: dict[str, str] = {}

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        write(self.root, self.FILENAME, self.FIXTURE)
        for relative, body in self.EXTRA_FILES.items():
            write(self.root, relative, body)
        self.database = Path(self.temp.name) / "graph.db"
        full_index(self.root, self.database)
        analyze_scope(self.root, "src", ("sparse_cfg",), database=self.database)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def result(self) -> dict:
        return query_call_site_clones(
            self.root, self.FILENAME, database=self.database)

    def clones(self) -> dict:
        result = self.result()
        self.assertEqual(result["status"], "available", result.get("reason"))
        return result

    def events(self) -> list[dict]:
        env = query_analysis(
            self.root, "sparse_cfg", file_path=self.FILENAME,
            database=self.database,
        )
        self.assertEqual(env["status"], "available", env.get("reason"))
        return env["events"]

    def site_by_caller(self, result: dict, caller: str) -> dict:
        sites = [site for site in result["call_sites"] if site["caller"] == caller]
        self.assertEqual(len(sites), 1, result["call_sites"])
        return sites[0]

    def binding_map(self, site: dict) -> dict:
        return {
            binding["parameter"]: binding for binding in site["bindings"]
        }


TWO_THREADS_FIXTURE = (
    "#include <pthread.h>\n"
    "typedef pthread_mutex_t mutex_t;\n"
    "int g1;\n"
    "int g2;\n"
    "mutex_t m1;\n"
    "mutex_t m2;\n"
    "static void helper(int* p, mutex_t* l) {\n"
    "    pthread_mutex_lock(l);\n"
    "    (*p)++;\n"
    "    pthread_mutex_unlock(l);\n"
    "}\n"
    "void* thread_one(void* arg) {\n"
    "    helper(&g1, &m1);\n"
    "    return 0;\n"
    "}\n"
    "void* thread_two(void* arg) {\n"
    "    helper(&g2, &m2);\n"
    "    return 0;\n"
    "}\n"
)


class TwoCallSitesDifferentArgumentsTests(CallSiteCloneTestBase):
    FIXTURE = TWO_THREADS_FIXTURE

    def test_two_sites_are_cloned_and_resolved(self):
        result = self.clones()
        sites = [site for site in result["call_sites"] if site["callee"] == "helper"]
        self.assertEqual(len(sites), 2)
        # The helper's own calls to pthread_mutex_lock/unlock are CALL points
        # too; they have no same-file callee and stay in the audit list.
        self.assertGreater(len(result["call_sites"]), len(sites))
        for site in sites:
            self.assertEqual(site["resolution"], CALL_SITE_RESOLVED)
            self.assertEqual(site["via"], "raw_references")

    def test_parameter_bindings_follow_each_call_site(self):
        result = self.clones()
        one = self.binding_map(self.site_by_caller(result, "thread_one"))
        two = self.binding_map(self.site_by_caller(result, "thread_two"))
        self.assertEqual(one["p"]["argument"], "g1")
        self.assertEqual(one["p"]["subject_decl"], "global:g1")
        self.assertEqual(one["l"]["argument"], "m1")
        self.assertEqual(one["l"]["subject_decl"], "global:m1")
        self.assertEqual(two["p"]["argument"], "g2")
        self.assertEqual(two["p"]["subject_decl"], "global:g2")
        self.assertEqual(two["l"]["argument"], "m2")
        self.assertEqual(two["l"]["subject_decl"], "global:m2")

    def test_cloned_events_keep_the_source_and_take_the_caller_owner(self):
        result = self.clones()
        source_ids = {event["event_id"] for event in self.events()}
        clones = result["events"]
        # LOCK + WRITE + UNLOCK + DEREFERENCE per call site; CALL rows are not
        # cloned (they are the call site itself).
        self.assertEqual(len(clones), 8)
        for clone in clones:
            self.assertTrue(clone["event_id"].startswith("event:clone:"))
            annotations = clone["annotations"]
            self.assertIn(annotations["callee_event_id"], source_ids)
            self.assertNotEqual(clone["event_id"], annotations["callee_event_id"])
            self.assertIn(clone["owner_qualified_name"],
                          {"thread_one", "thread_two"})

    def test_lock_parameters_are_bound_to_the_caller_lock(self):
        result = self.clones()
        locks = {
            (clone["owner_qualified_name"], clone["event_type"],
             clone["annotations"]["subject_decl"])
            for clone in result["events"]
            if clone["event_type"] in {"LOCK", "UNLOCK"}
        }
        self.assertEqual(locks, {
            ("thread_one", "LOCK", "global:m1"),
            ("thread_one", "UNLOCK", "global:m1"),
            ("thread_two", "LOCK", "global:m2"),
            ("thread_two", "UNLOCK", "global:m2"),
        })

    def test_deterministic_output(self):
        first = json.dumps(self.result(), sort_keys=True)
        second = json.dumps(self.result(), sort_keys=True)
        self.assertEqual(first, second)


class SingleCallSiteTests(CallSiteCloneTestBase):
    FIXTURE = (
        "static void helper(int* p) { (*p)++; }\n"
        "void only(void) {\n"
        "    int x;\n"
        "    helper(&x);\n"
        "}\n"
    )

    def test_one_call_site_is_not_cloned(self):
        result = self.clones()
        self.assertEqual(len(result["call_sites"]), 1)
        site = result["call_sites"][0]
        self.assertEqual(site["resolution"], CALL_SITE_RESOLVED)
        self.assertEqual(site["cloned_event_ids"], [])
        self.assertIn("single_call_site", site["missing_evidence"])
        self.assertEqual(result["events"], [])


class IndirectUniqueTests(CallSiteCloneTestBase):
    FIXTURE = (
        "struct S { void (*fn)(int*); };\n"
        "struct S g;\n"
        "int g1;\n"
        "int g2;\n"
        "static void target(int* p) { (*p)++; }\n"
        "void setup(void) { g.fn = target; }\n"
        "void one(void) { g.fn(&g1); }\n"
        "void two(void) { g.fn(&g2); }\n"
    )

    def test_unique_may_call_is_reused_for_the_clone(self):
        result = self.clones()
        self.assertEqual(len(result["call_sites"]), 2)
        for site in result["call_sites"]:
            self.assertEqual(site["via"], "may_call")
            self.assertEqual(site["resolution"], RESOLUTION_UNIQUE)
            self.assertEqual(site["callee"], "target")
            self.assertEqual(site["may_call_slot"], "global:g.fn")
        self.assertTrue(result["events"])


class IndirectAmbiguousTests(CallSiteCloneTestBase):
    FIXTURE = (
        "struct S { void (*fn)(int*); };\n"
        "struct S g;\n"
        "int g1;\n"
        "static void first(int* p) { (*p)++; }\n"
        "static void second(int* p) { (*p)++; }\n"
        "void setup(void) { g.fn = first; g.fn = second; }\n"
        "void one(void) { g.fn(&g1); }\n"
        "void two(void) { g.fn(&g1); }\n"
    )

    def test_ambiguous_may_call_names_no_target(self):
        result = self.clones()
        self.assertEqual(len(result["call_sites"]), 2)
        for site in result["call_sites"]:
            self.assertEqual(site["via"], "may_call")
            self.assertEqual(site["resolution"], RESOLUTION_AMBIGUOUS)
            self.assertEqual(site["callee"], "")
            self.assertEqual(site["callee_symbol_id"], "")
            self.assertIn("callee_ambiguous", site["missing_evidence"])
        self.assertEqual(result["events"], [])


class ArgumentOrderDeformationTests(CallSiteCloneTestBase):
    FIXTURE = (
        "int x;\n"
        "int y;\n"
        "static void pair(int* first, int* second) {\n"
        "    (*first)++;\n"
        "    (*second)++;\n"
        "}\n"
        "void alpha(void) {\n"
        "    pair(&x, &y);\n"
        "}\n"
        "void beta(void) {\n"
        "    /* swapped on purpose */\n"
        "    pair(&y, &x);\n"
        "}\n"
    )

    def test_swapped_arguments_keep_the_positional_binding(self):
        result = self.clones()
        alpha = self.binding_map(self.site_by_caller(result, "alpha"))
        beta = self.binding_map(self.site_by_caller(result, "beta"))
        self.assertEqual(alpha["first"]["argument"], "x")
        self.assertEqual(alpha["first"]["subject_decl"], "global:x")
        self.assertEqual(alpha["first"]["subject_owner"], "alpha")
        self.assertEqual(alpha["second"]["argument"], "y")
        self.assertEqual(alpha["second"]["subject_decl"], "global:y")
        self.assertEqual(alpha["second"]["subject_owner"], "alpha")
        self.assertEqual(beta["first"]["argument"], "y")
        self.assertEqual(beta["first"]["subject_decl"], "global:y")
        self.assertEqual(beta["first"]["subject_owner"], "beta")
        self.assertEqual(beta["second"]["argument"], "x")
        self.assertEqual(beta["second"]["subject_decl"], "global:x")
        self.assertEqual(beta["second"]["subject_owner"], "beta")

    def test_rename_and_reformat_do_not_change_the_bindings(self):
        renamed = (
            "// a comment added only to move every line\n"
            "\n"
            "int x;\n"
            "int y;\n"
            "static void join(int* lhs, int* rhs) {\n"
            "    (*lhs)++;\n"
            "    (*rhs)++;\n"
            "}\n"
            "void alpha(void) {\n"
            "    join(&x, &y);\n"
            "}\n"
            "void beta(void) {\n"
            "    join(&y, &x);\n"
            "}\n"
        )
        original = self.clones()
        original_bindings = self._bindings(original)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            write(root, self.FILENAME, renamed)
            database = Path(temporary) / "graph.db"
            full_index(root, database)
            analyze_scope(root, "src", ("sparse_cfg",), database=database)
            after = query_call_site_clones(
                root, self.FILENAME, database=database)
        self.assertEqual(after["status"], "available")
        self.assertEqual(self._bindings(after), original_bindings)

    def _bindings(self, result: dict) -> dict:
        # Keyed by ordinal, not by the parameter's spelling: the deformation
        # renames the parameters, and the binding is positional.
        return {
            site["caller"]: {
                str(value["ordinal"]): (
                    value["argument"], value["subject_decl"], value["subject_owner"])
                for value in site["bindings"]
            }
            for site in result["call_sites"]
        }


class OutOfFileCalleeTests(CallSiteCloneTestBase):
    FIXTURE = (
        "int g1;\n"
        "int g2;\n"
        "void one(void) { remote(&g1); }\n"
        "void two(void) { remote(&g2); }\n"
    )
    EXTRA_FILES = {
        "src/b.c": "void remote(int* p) { (*p)++; }\n",
    }

    def test_callee_outside_the_file_is_not_cloned(self):
        result = self.clones()
        self.assertEqual(len(result["call_sites"]), 2)
        for site in result["call_sites"]:
            self.assertEqual(site["resolution"], CALL_SITE_OUT_OF_FILE)
            self.assertEqual(site["cloned_event_ids"], [])
            self.assertIn("callee_out_of_file", site["missing_evidence"])
        self.assertEqual(result["events"], [])


class UnresolvedArgumentTests(CallSiteCloneTestBase):
    FIXTURE = (
        "static void helper(int* p) { (*p)++; }\n"
        "void one(void) { helper(&undeclared_one); }\n"
        "void two(void) { helper(&undeclared_two); }\n"
    )

    def test_unknown_argument_identity_fails_closed(self):
        result = self.clones()
        self.assertEqual(len(result["call_sites"]), 2)
        for site in result["call_sites"]:
            self.assertEqual(site["bindings"], [])
            self.assertIn("argument_identity_unresolved", site["missing_evidence"])
        self.assertEqual(result["events"], [])


class ConcurrencyContextIntegrationTests(CallSiteCloneTestBase):
    FIXTURE = (
        "#include <pthread.h>\n"
        "typedef pthread_mutex_t mutex_t;\n"
        "int shared_value;\n"
        "mutex_t lock_a;\n"
        "mutex_t lock_b;\n"
        "static void helper(mutex_t* l) {\n"
        "    pthread_mutex_lock(l);\n"
        "    shared_value++;\n"
        "    pthread_mutex_unlock(l);\n"
        "}\n"
        "void* t_a(void* arg) { helper(&lock_a); return 0; }\n"
        "void* t_b(void* arg) { helper(&lock_b); return 0; }\n"
        "void start(void) {\n"
        "    pthread_t a;\n"
        "    pthread_t b;\n"
        "    pthread_create(&a, 0, t_a, 0);\n"
        "    pthread_create(&b, 0, t_b, 0);\n"
        "}\n"
    )

    def test_cloned_events_supply_the_missing_caller_contexts(self):
        events = self.events()
        clone_bundle = self.clones()
        self.assertTrue(clone_bundle["events"])

        without_clones = build_concurrency_context(events)
        before = [
            subject for subject in without_clones["may_parallel"]
            if subject["subject"] == "shared_value"
        ]
        self.assertEqual(before, [])

        merged = build_concurrency_context(events + clone_bundle["events"])
        after = [
            subject for subject in merged["may_parallel"]
            if subject["subject"] == "shared_value"
        ]
        self.assertEqual(len(after), 1)
        candidate = after[0]
        self.assertEqual(candidate["identity"], "global:shared_value")
        self.assertEqual(candidate["candidate_state"], "ambiguous")
        self.assertEqual(candidate["thread_entry_owners"], ["t_a", "t_b"])
        self.assertEqual(candidate["owners"], ["helper", "t_a", "t_b"])
        self.assertTrue(candidate["evidence_references"])

    def test_query_concurrency_context_is_wired_to_the_clone(self):
        context = query_concurrency_context(
            self.root, self.FILENAME, database=self.database)
        self.assertEqual(context["status"], "available")
        sites = context["call_site_clones"]
        helper_sites = [site for site in sites if site["callee"] == "helper"]
        self.assertEqual(len(helper_sites), 2)
        subjects = [
            subject for subject in context["may_parallel"]
            if subject["subject"] == "shared_value"
        ]
        self.assertEqual(len(subjects), 1)
        self.assertEqual(subjects[0]["thread_entry_owners"], ["t_a", "t_b"])
        self.assertEqual(subjects[0]["owners"], ["helper", "t_a", "t_b"])
        again = query_concurrency_context(
            self.root, self.FILENAME, database=self.database)
        self.assertEqual(
            json.dumps(context, sort_keys=True),
            json.dumps(again, sort_keys=True),
        )

    def test_legacy_build_output_is_unchanged_without_clones(self):
        context = build_concurrency_context(self.events())
        self.assertNotIn("call_site_clones", context)


class BuildCallSiteClonesIsPureTests(CallSiteCloneTestBase):
    FIXTURE = TWO_THREADS_FIXTURE

    def test_build_does_not_write_events_or_edges(self):
        before = self._counts()
        env = query_analysis(
            self.root, "sparse_cfg", file_path=self.FILENAME,
            database=self.database,
        )
        with SQLiteStorage(self.database) as storage:
            build_call_site_clones(env["events"], env["file_id"], storage)
        self.assertEqual(self._counts(), before)

    def _counts(self) -> tuple[int, int]:
        with closing(sqlite3.connect(self.database)) as connection:
            nodes = connection.execute(
                "SELECT COUNT(*) FROM analysis_nodes").fetchone()[0]
            edges = connection.execute(
                "SELECT COUNT(*) FROM analysis_edges").fetchone()[0]
        return int(nodes), int(edges)


class StatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_not_built_preserved(self):
        write(self.root, "src/a.c",
              "int g; void f(void) { g++; }\n")
        database = Path(self.temp.name) / "graph.db"
        full_index(self.root, database)
        result = query_call_site_clones(
            self.root, "src/a.c", database=database)
        self.assertEqual(result["status"], "not_built")
        self.assertEqual(result["call_sites"], [])
        self.assertEqual(result["events"], [])

    def test_stale_source_hash_fails_closed(self):
        write(self.root, "src/a.c",
              "static void h(int* p) { (*p)++; }\n"
              "void a(void) { int x; h(&x); }\n"
              "void b(void) { int x; h(&x); }\n")
        database = Path(self.temp.name) / "graph.db"
        full_index(self.root, database)
        analyze_scope(self.root, "src", ("sparse_cfg",), database=database)
        with closing(sqlite3.connect(database)) as connection:
            connection.execute(
                "UPDATE file_state SET source_hash='deadbeef' WHERE path='src/a.c'")
            connection.commit()
        result = query_call_site_clones(
            self.root, "src/a.c", database=database)
        self.assertEqual(result["status"], "stale")
        self.assertEqual(result["call_sites"], [])

    def test_python_reports_unsupported(self):
        write(self.root, "src/a.py", "def a():\n    return 1\n")
        database = Path(self.temp.name) / "graph.db"
        full_index(self.root, database)
        result = query_call_site_clones(
            self.root, "src/a.py", database=database)
        self.assertEqual(result["status"], "unsupported")
        self.assertEqual(result["call_sites"], [])


if __name__ == "__main__":
    unittest.main()
