"""G2 member/pointer identity (issue-pilot #90): lock designations.

Pins the events-layer fact this Issue delivers:

* a complete field path keeps its members: ``&s.mutex`` / ``&p->mutex``
  publish ``s.mutex`` / ``p.mutex`` with ``subject_exact=true`` -- the
  designation, not the root object;
* a path that leaves a subscript behind (``p->slots[i].lock()``) still names
  the root and stays inexact, so two array elements never read as one lock;
* a designation that is not a name (``pthread_mutex_lock(get_lock())``) stays
  empty and inexact;
* a ``this->member`` designation also stays empty and inexact: the events
  layer has no field-declaration identity, so the bare member name would
  merge with a same-named local lock;
* plain root locks (``&g_lock``, ``m.try_lock()``, ``guard(m)``) are unchanged;
* the sparse access subject is not touched: ``s.datum`` keeps its existing
  ``(subject_decl, subject_member)`` pair.
"""

import tempfile
import unittest
from pathlib import Path

from provenlattice.analysis_query import query_analysis
from provenlattice.concurrency_lock_scenarios import build_lock_scenarios
from provenlattice.graph import full_index
from provenlattice.orchestrator import analyze_scope


def write(root: Path, relative: str, value: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value.encode("utf-8"))


class MemberPointerIdentityBase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repo"
        self.database = Path(self.temp.name) / "graph.db"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def analyze(self, *features: str) -> None:
        full_index(self.root, self.database)
        analyze_scope(self.root, "src", features or ("events",),
                      database=self.database)

    def events(self, relative: str, feature: str = "events") -> list[dict]:
        env = query_analysis(self.root, feature, file_path=relative,
                             database=self.database)
        self.assertEqual(env["status"], "available", env.get("reason"))
        return env["events"]

    def locks(self, relative: str) -> list[dict]:
        return [event for event in self.events(relative)
                if event["event_type"] in {"LOCK", "UNLOCK"}]


class MemberLockIdentityTests(MemberPointerIdentityBase):
    def test_dot_member_is_the_designation(self) -> None:
        write(self.root, "src/dot.c",
              "#include <pthread.h>\n"
              "struct S { pthread_mutex_t mutex; };\n"
              "struct S g_s;\n"
              "void f(void) {\n"
              "    pthread_mutex_lock(&g_s.mutex);\n"
              "    pthread_mutex_unlock(&g_s.mutex);\n"
              "}\n")
        self.analyze()
        locks = self.locks("src/dot.c")
        self.assertEqual(len(locks), 2)
        for lock in locks:
            self.assertEqual(lock["lock_identity"], "g_s.mutex")
            self.assertTrue(lock["subject_exact"])

    def test_arrow_member_is_the_designation(self) -> None:
        write(self.root, "src/arrow.c",
              "#include <pthread.h>\n"
              "struct S { pthread_mutex_t mutex; };\n"
              "void f(struct S *p) {\n"
              "    pthread_mutex_lock(&p->mutex);\n"
              "    pthread_mutex_unlock(&p->mutex);\n"
              "}\n")
        self.analyze()
        locks = self.locks("src/arrow.c")
        self.assertEqual(len(locks), 2)
        for lock in locks:
            self.assertEqual(lock["lock_identity"], "p.mutex")
            self.assertTrue(lock["subject_exact"])

    def test_parenthesized_member_is_the_same_designation(self) -> None:
        write(self.root, "src/paren.c",
              "#include <pthread.h>\n"
              "struct S { pthread_mutex_t mutex; };\n"
              "struct S g_s;\n"
              "void f(void) {\n"
              "    pthread_mutex_lock(&(g_s.mutex));\n"
              "}\n")
        self.analyze()
        lock = self.locks("src/paren.c")[0]
        self.assertEqual(lock["lock_identity"], "g_s.mutex")
        self.assertTrue(lock["subject_exact"])

    def test_renamed_members_follow_the_source(self) -> None:
        write(self.root, "src/renamed.c",
              "#include <pthread.h>\n"
              "struct Node { pthread_mutex_t guard; };\n"
              "struct Node node;\n"
              "void work(void) {\n"
              "    pthread_mutex_lock(&node.guard);\n"
              "}\n")
        self.analyze()
        lock = self.locks("src/renamed.c")[0]
        self.assertEqual(lock["lock_identity"], "node.guard")
        self.assertTrue(lock["subject_exact"])


class RootLockIdentityTests(MemberPointerIdentityBase):
    def test_plain_global_lock_is_unchanged(self) -> None:
        write(self.root, "src/plain.c",
              "#include <pthread.h>\n"
              "pthread_mutex_t g_lock;\n"
              "void f(void) {\n"
              "    pthread_mutex_lock(&g_lock);\n"
              "    pthread_mutex_unlock(&g_lock);\n"
              "}\n")
        self.analyze()
        for lock in self.locks("src/plain.c"):
            self.assertEqual(lock["lock_identity"], "g_lock")
            self.assertTrue(lock["subject_exact"])

    def test_member_call_receiver_is_unchanged(self) -> None:
        write(self.root, "src/method.cc",
              "#include <mutex>\n"
              "std::mutex m;\n"
              "void f(void) {\n"
              "    m.lock();\n"
              "    m.unlock();\n"
              "}\n")
        self.analyze()
        for lock in self.locks("src/method.cc"):
            self.assertEqual(lock["lock_identity"], "m")
            self.assertTrue(lock["subject_exact"])


class SubscriptLockIdentityTests(MemberPointerIdentityBase):
    def test_subscript_stays_root_and_inexact(self) -> None:
        write(self.root, "src/subscript.cc",
              "struct holder { void lock(); void unlock(); };\n"
              "struct pool { struct holder *slots; };\n"
              "void f(struct pool *p, int i) {\n"
              "    p->slots[i].lock();\n"
              "    p->slots[i].unlock();\n"
              "}\n")
        self.analyze()
        for lock in self.locks("src/subscript.cc"):
            self.assertEqual(lock["lock_identity"], "p")
            self.assertFalse(lock["subject_exact"])


class UnknownLockIdentityTests(MemberPointerIdentityBase):
    def test_call_result_is_not_a_designation(self) -> None:
        write(self.root, "src/unknown.c",
              "#include <pthread.h>\n"
              "void f(void) {\n"
              "    pthread_mutex_lock(get_lock());\n"
              "}\n")
        self.analyze()
        lock = self.locks("src/unknown.c")[0]
        self.assertEqual(lock["lock_identity"], "")
        self.assertFalse(lock["subject_exact"])


class RaiiMemberLockTests(MemberPointerIdentityBase):
    def test_guard_keeps_the_member_designation(self) -> None:
        write(self.root, "src/raii.cc",
              "#include <mutex>\n"
              "struct S { std::mutex mutex; };\n"
              "S g_s;\n"
              "void f(void) {\n"
              "    std::lock_guard<std::mutex> guard(g_s.mutex);\n"
              "}\n")
        self.analyze()
        lock = self.locks("src/raii.cc")[0]
        self.assertEqual(lock["lock_identity"], "g_s.mutex")
        self.assertTrue(lock["subject_exact"])
        self.assertTrue(lock["raii"])


class ThisMemberIsNotResolvedTests(MemberPointerIdentityBase):
    def test_this_member_without_shadowing_stays_unresolved(self) -> None:
        write(self.root, "src/this_only.cc",
              "#include <mutex>\n"
              "struct S {\n"
              "    std::mutex m;\n"
              "    void f(void) {\n"
              "        this->m.lock();\n"
              "        this->m.unlock();\n"
              "    }\n"
              "};\n")
        self.analyze()
        locks = sorted(self.locks("src/this_only.cc"),
                       key=lambda event: event.get("start_byte") or 0)
        self.assertEqual(len(locks), 2)
        for lock in locks:
            self.assertEqual(lock["lock_identity"], "")
            self.assertFalse(lock["subject_exact"])

    def test_member_does_not_merge_with_a_same_named_local(self) -> None:
        write(self.root, "src/this_shadow.cc",
              "#include <mutex>\n"
              "struct S {\n"
              "    std::mutex m;\n"
              "    void f(void) {\n"
              "        std::mutex m;\n"
              "        m.lock();\n"
              "        this->m.lock();\n"
              "        this->m.unlock();\n"
              "        m.unlock();\n"
              "    }\n"
              "};\n")
        self.analyze()
        locks = sorted(self.locks("src/this_shadow.cc"),
                       key=lambda event: event.get("start_byte") or 0)
        self.assertEqual(
            [(lock["lock_identity"], lock["subject_exact"]) for lock in locks],
            [("m", True), ("", False), ("", False), ("m", True)],
        )

    def test_local_and_member_locks_do_not_form_a_self_deadlock(self) -> None:
        write(self.root, "src/this_scenario.cc",
              "#include <mutex>\n"
              "struct S {\n"
              "    std::mutex m;\n"
              "    void f(void) {\n"
              "        std::mutex m;\n"
              "        m.lock();\n"
              "        this->m.lock();\n"
              "        this->m.unlock();\n"
              "        m.unlock();\n"
              "    }\n"
              "};\n")
        self.analyze()
        scenarios = build_lock_scenarios(self.events("src/this_scenario.cc"))
        self.assertEqual(scenarios["candidates"], [])


class AccessSubjectUnchangedTests(MemberPointerIdentityBase):
    def test_field_access_keeps_the_declaration_and_member_pair(self) -> None:
        write(self.root, "src/access.c",
              "struct S { int datum; };\n"
              "struct S g_s;\n"
              "void f(void) {\n"
              "    g_s.datum = 5;\n"
              "}\n")
        self.analyze("sparse_cfg")
        writes = [event for event in self.events("src/access.c", "sparse_cfg")
                  if event["event_type"] == "WRITE"]
        self.assertTrue(writes)
        for event in writes:
            annotations = event.get("annotations") or {}
            self.assertEqual(annotations.get("subject_decl"), "global:g_s")
            self.assertEqual(annotations.get("subject_member"), "datum")


if __name__ == "__main__":
    unittest.main()
