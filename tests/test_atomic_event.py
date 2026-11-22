"""G1 ATOMIC facts: `_Atomic` objects and Verifier atomic blocks (issue-pilot#89).

The producer under test lives in `analysis_c_frontend.collect_atomic_facts` and
`analysis_c_scfg`'s ATOMIC point injection. The consumers (`defect.py`'s
`_touches_atomically` and `concurrency_race_scenarios.atomic_subjects`) are
frozen and are exercised here only through the public defect query.

Fixtures are synthetic and spelling-independent: the invariance test rewrites
every user name and the formatting, and the rule must not care.
"""

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from provenlattice.defect_query import query_defect_candidates
from provenlattice.graph import full_index
from provenlattice.orchestrator import analyze_scope


def write(root: Path, relative: str, value: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8"))


def _atomic_nodes(database: Path) -> list[dict]:
    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute(
            "SELECT payload FROM analysis_nodes "
            "WHERE feature='sparse_cfg:cpp' AND kind='ATOMIC' "
            "ORDER BY analysis_node_id"
        ).fetchall()
    return [json.loads(row[0]) for row in rows]


def _state(database: Path) -> dict:
    with closing(sqlite3.connect(database)) as connection:
        row = connection.execute(
            "SELECT metadata FROM analysis_state WHERE feature='sparse_cfg:cpp'"
        ).fetchone()
    return json.loads(row[0]) if row else {}


def _materialize(body: str) -> tuple[list[dict], dict, dict]:
    """Build one fixture; return (ATOMIC payloads, race envelope, state)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        database = Path(tmp) / "graph.db"
        write(root, "src/t.c", body)
        full_index(root, database)
        analyze_scope(root, "src", ("defect",), database=database)
        nodes = _atomic_nodes(database)
        state = _state(database)
        env = query_defect_candidates(
            root, defect_type="race_condition", database=database)
        assert env["status"] == "available", env.get("reason")
        return nodes, env, state


def _annotations(payload: dict) -> dict:
    return payload.get("annotations") or {}


def _subjects(nodes: list[dict]) -> set[str]:
    return {_annotations(node).get("subject", "") for node in nodes}


ATOMIC_TYPE = r"""
#include <pthread.h>
_Atomic int g_counter = 0;
void *bump(void *arg) {
    g_counter++;
    return NULL;
}
void start(void) {
    pthread_t t;
    pthread_create(&t, NULL, bump, NULL);
    g_counter = 2;
    pthread_join(t, NULL);
}
"""

PLAIN_TYPE = r"""
#include <pthread.h>
int g_counter = 0;
void *bump(void *arg) {
    g_counter++;
    return NULL;
}
void start(void) {
    pthread_t t;
    pthread_create(&t, NULL, bump, NULL);
    g_counter = 2;
    pthread_join(t, NULL);
}
"""

PAIRED_BLOCKS = r"""
#include <pthread.h>
int g_value = 0;
void *bump(void *arg) {
    __VERIFIER_atomic_begin();
    g_value++;
    __VERIFIER_atomic_end();
    return NULL;
}
void start(void) {
    pthread_t t;
    pthread_create(&t, NULL, bump, NULL);
    __VERIFIER_atomic_begin();
    g_value = 2;
    __VERIFIER_atomic_end();
    pthread_join(t, NULL);
}
"""

UNPAIRED_BLOCK = r"""
#include <pthread.h>
int g_value = 0;
void *bump(void *arg) {
    __VERIFIER_atomic_begin();
    g_value++;
    return NULL;
}
void start(void) {
    pthread_t t;
    pthread_create(&t, NULL, bump, NULL);
    g_value = 2;
    pthread_join(t, NULL);
}
"""

NESTED_BLOCK = r"""
#include <pthread.h>
int g_value = 0;
void *bump(void *arg) {
    __VERIFIER_atomic_begin();
    __VERIFIER_atomic_begin();
    g_value++;
    __VERIFIER_atomic_end();
    __VERIFIER_atomic_end();
    return NULL;
}
void start(void) {
    pthread_t t;
    pthread_create(&t, NULL, bump, NULL);
    g_value = 2;
    pthread_join(t, NULL);
}
"""

TYPEDEF_ALIAS = r"""
#include <pthread.h>
typedef _Atomic int atomic_int;
atomic_int g_counter = 0;
void *bump(void *arg) {
    g_counter++;
    return NULL;
}
void start(void) {
    pthread_t t;
    pthread_create(&t, NULL, bump, NULL);
    g_counter = 2;
    pthread_join(t, NULL);
}
"""

ATOMIC_TYPE_SPECIFIER = r"""
#include <pthread.h>
_Atomic(int) g_flag;
void *bump(void *arg) {
    g_flag = 1;
    return NULL;
}
void start(void) {
    pthread_t t;
    pthread_create(&t, NULL, bump, NULL);
    g_flag = 2;
    pthread_join(t, NULL);
}
"""

VOID_ALIAS = r"""
_Atomic int g_value;
void touch(void *p) {
    *(int *)p = 1;
}
"""

RENAMED_REFORMATTED = r"""
#include <pthread.h>

_Atomic long long aa=0;

void* bb(void* unused)
{
  aa++;
  return 0;
}

void cc(void)
{
  pthread_t hh;
  pthread_create(&hh,0,bb,0);
  aa=2;
  pthread_join(hh,0);
}
"""


class AtomicEventTests(unittest.TestCase):
    def test_atomic_type_emits_atomic_points(self) -> None:
        nodes, env, _state = _materialize(ATOMIC_TYPE)
        self.assertTrue(nodes, "an _Atomic object must publish ATOMIC points")
        self.assertEqual(_subjects(nodes), {"g_counter"})
        for node in nodes:
            self.assertEqual(
                _annotations(node).get("atomic_source"), "type_qualifier")
            self.assertIn(
                _annotations(node).get("atomic_access"),
                {"READ", "WRITE", "READ_MODIFY_WRITE"})
        races = [c for c in env["candidates"] if c["query"] == "race_condition"]
        self.assertEqual(races, [], "both sides are atomic and must be excluded")

    def test_plain_int_is_not_atomic(self) -> None:
        nodes, env, _state = _materialize(PLAIN_TYPE)
        self.assertEqual(nodes, [])
        races = [c for c in env["candidates"] if c["query"] == "race_condition"]
        self.assertEqual(len(races), 1)

    def test_paired_atomic_blocks_emit_atomic_points(self) -> None:
        nodes, env, _state = _materialize(PAIRED_BLOCKS)
        self.assertTrue(nodes)
        self.assertEqual(_subjects(nodes), {"g_value"})
        for node in nodes:
            self.assertEqual(
                _annotations(node).get("atomic_source"), "atomic_block")
        races = [c for c in env["candidates"] if c["query"] == "race_condition"]
        self.assertEqual(races, [], "both accesses are inside paired blocks")

    def test_unpaired_block_is_a_limitation_not_a_fact(self) -> None:
        nodes, env, state = _materialize(UNPAIRED_BLOCK)
        self.assertEqual(nodes, [])
        self.assertTrue(any(
            limit.startswith("atomic_block_unpaired_begin")
            for limit in state.get("atomic_limitations", ())))
        races = [c for c in env["candidates"] if c["query"] == "race_condition"]
        self.assertEqual(len(races), 1)

    def test_nested_block_is_a_limitation_not_a_fact(self) -> None:
        nodes, env, state = _materialize(NESTED_BLOCK)
        self.assertEqual(nodes, [])
        self.assertTrue(any(
            limit.startswith("atomic_block_nested")
            for limit in state.get("atomic_limitations", ())))
        races = [c for c in env["candidates"] if c["query"] == "race_condition"]
        self.assertEqual(len(races), 1)

    def test_typedef_alias_resolves_to_the_atomic_type(self) -> None:
        nodes, _env, _state = _materialize(TYPEDEF_ALIAS)
        self.assertTrue(nodes)
        self.assertEqual(_subjects(nodes), {"g_counter"})

    def test_atomic_type_specifier_spelling_is_recovered(self) -> None:
        nodes, _env, _state = _materialize(ATOMIC_TYPE_SPECIFIER)
        self.assertTrue(nodes, "the C11 _Atomic(type) spelling must be recovered")
        self.assertEqual(_subjects(nodes), {"g_flag"})
        self.assertEqual(
            _annotations(nodes[0]).get("atomic_source"), "type_specifier")

    def test_access_through_void_alias_is_not_atomic(self) -> None:
        nodes, _env, _state = _materialize(VOID_ALIAS)
        self.assertEqual(nodes, [], "an unresolved alias must stay unknown")

    def test_renaming_and_formatting_do_not_change_the_result(self) -> None:
        nodes, env, _state = _materialize(RENAMED_REFORMATTED)
        self.assertTrue(nodes)
        self.assertEqual(_subjects(nodes), {"aa"})
        races = [c for c in env["candidates"] if c["query"] == "race_condition"]
        self.assertEqual(races, [])

    def test_atomic_points_are_deterministic(self) -> None:
        first, _env, _state = _materialize(ATOMIC_TYPE)
        second, _env, _state = _materialize(ATOMIC_TYPE)
        shape = lambda nodes: sorted(
            (node.get("ordinal"), _annotations(node).get("subject", ""),
             _annotations(node).get("atomic_source", ""),
             _annotations(node).get("atomic_access", ""))
            for node in nodes
        )
        self.assertEqual(shape(first), shape(second))


if __name__ == "__main__":
    unittest.main()
