"""PAIR-05 post-join decline: bound join ordering alone orders the pair (P2).

Issue #88 (research #85 FINALIZATION-V1 §2.5). The rule under test reads only
event facts -- spawn handle identity, the bound join position and the access
positions. Every fixture is synthetic and carries no benchmark identity: no
case ids, suite names, variable names or ground truth drive the assertion; the
names are ordinary spelling and the invariance test rewrites them.

The change under test: a side whose every access follows the join that is
provably bound to the *other* side's thread entry is post-join, and the join
ordering establishes the happens-before edge by itself. The worker side does
not additionally have to be lock-guarded.
"""

import tempfile
import unittest
from pathlib import Path

from provenlattice.defect_query import query_defect_candidates
from provenlattice.graph import full_index
from provenlattice.orchestrator import analyze_scope


def write(root: Path, relative: str, value: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8"))


def _env(body: str, filename: str = "src/t.c") -> dict:
    """Build the upstream chain for one fixture and return the query envelope."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "repo"
        database = Path(tmp) / "graph.db"
        write(root, filename, body)
        full_index(root, database)
        analyze_scope(root, "src", ("defect",), database=database)
        env = query_defect_candidates(
            root, defect_type="race_condition", database=database)
        assert env["status"] == "available", env.get("reason")
        return env


def _races(body: str) -> list[dict]:
    return [c for c in _env(body)["candidates"] if c["query"] == "race_condition"]


POST_JOIN_UNGUARDED = r"""
#include <pthread.h>
int shared = 0;
void *worker(void *arg) {
    shared = 1;
    return NULL;
}
void starter(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    shared = 2;
}
"""

POST_JOIN_GUARDED = r"""
#include <pthread.h>
pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
int shared = 0;
void *worker(void *arg) {
    pthread_mutex_lock(&m);
    shared = 1;
    pthread_mutex_unlock(&m);
    return NULL;
}
void starter(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(t, NULL);
    shared = 2;
}
"""

NO_JOIN = r"""
#include <pthread.h>
int shared = 0;
void *worker(void *arg) {
    shared = 1;
    return NULL;
}
void starter(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    shared = 2;
}
"""

JOIN_AFTER_ACCESS = r"""
#include <pthread.h>
int shared = 0;
void *worker(void *arg) {
    shared = 1;
    return NULL;
}
void starter(void) {
    pthread_t t;
    pthread_create(&t, NULL, worker, NULL);
    shared = 2;
    pthread_join(t, NULL);
}
"""

UNRELATED_JOIN = r"""
#include <pthread.h>
int shared = 0;
void *worker(void *arg) {
    shared = 1;
    return NULL;
}
void *other(void *arg) {
    return NULL;
}
void starter(void) {
    pthread_t t;
    pthread_t u;
    pthread_create(&u, NULL, other, NULL);
    pthread_create(&t, NULL, worker, NULL);
    pthread_join(u, NULL);
    shared = 2;
}
"""

MISSING_HANDLE = r"""
#include <pthread.h>
int shared = 0;
void *worker(void *arg) {
    shared = 1;
    return NULL;
}
void starter(void) {
    pthread_join(g_thread, NULL);
    shared = 2;
}
"""

# The same shape as POST_JOIN_UNGUARDED with every user name rewritten and the
# formatting changed. The rule cannot depend on spelling.
RENAMED_REFORMATTED = r"""
#include <pthread.h>

int gValue=0;

void* body(void* unused)
{
  gValue=1;
  return 0;
}

void run(void)
{
  pthread_t handle;
  pthread_create(&handle,0,body,0);
  pthread_join(handle,0);
  gValue=2;
}
"""


class PostJoinDeclineTests(unittest.TestCase):
    """P2: join ordering alone declines a provably post-join pair."""

    def test_unguarded_peer_is_filtered(self) -> None:
        env = _env(POST_JOIN_UNGUARDED)
        races = [c for c in env["candidates"] if c["query"] == "race_condition"]
        self.assertEqual(races, [])
        self.assertGreaterEqual(
            env["coverage"].get("disqualified_post_lifecycle", 0), 1,
            "the decline must be auditable in the coverage block")

    def test_guarded_peer_is_still_filtered(self) -> None:
        self.assertEqual(_races(POST_JOIN_GUARDED), [])

    def test_without_join_the_pair_is_kept(self) -> None:
        self.assertEqual(len(_races(NO_JOIN)), 1)

    def test_access_before_the_join_keeps_the_pair(self) -> None:
        # Not every access of the side follows the join -> not provably
        # post-join -> keep (fail-closed).
        self.assertEqual(len(_races(JOIN_AFTER_ACCESS)), 1)

    def test_join_bound_to_another_thread_keeps_the_pair(self) -> None:
        # The bound join orders against `other`, not the candidate's worker.
        self.assertEqual(len(_races(UNRELATED_JOIN)), 1)

    def test_unresolved_handle_keeps_the_pair(self) -> None:
        # No declaration identity for the handle -> the join cannot be bound to
        # the other side -> UNKNOWN, never "ordered".
        self.assertEqual(len(_races(MISSING_HANDLE)), 1)

    def test_renaming_and_formatting_do_not_change_the_result(self) -> None:
        self.assertEqual(_races(RENAMED_REFORMATTED), [])

    def test_result_is_deterministic(self) -> None:
        first = _races(POST_JOIN_UNGUARDED)
        second = _races(POST_JOIN_UNGUARDED)
        self.assertEqual(first, second)
        self.assertEqual(first, [])


if __name__ == "__main__":
    unittest.main()
