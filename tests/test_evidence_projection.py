"""Unit tests for the engine-agnostic FactBundle v2.1 projection.

These tests exercise :mod:`provenlattice.evidence_projection.projection` on
synthetic candidate records that mirror the real engine shapes captured in
``fixtures/``. No engine, no graph DB: the projection is a pure function of its
candidate input, so its contract (binding, dedupe, cross-candidate isolation,
unresolved/UNKNOWN preservation, determinism) is fully testable here.
"""

import unittest

from provenlattice.evidence_projection import projection as P


# ---------------------------------------------------------------------------
# synthetic candidate builders (mirror the real fixture shapes)
# ---------------------------------------------------------------------------


def race_candidate(evidence_id, *, owner_a="symA", owner_b="symB",
                   identity="global:shared", write_event="event:w",
                   read_event="event:r", anchor="event:anchor") -> dict:
    return {
        "defect_key": "1.1",
        "query": "race_condition",
        "subject": {
            "kind": "shared_name", "name": "shared", "identity": identity,
            "decl": identity, "method": "reader", "owner_symbol_id": owner_a,
        },
        "anchor": anchor,
        "discriminator": "disc|%s|%s" % (owner_a, owner_b),
        "resolution_status": "resolved",
        "confidence": 0.5,
        "evidence_id": evidence_id,
        "related_accesses": [
            {"event_id": write_event, "access_kind": "WRITE", "event_type": "WRITE",
             "owner": "writer", "owner_symbol_id": owner_b,
             "relative_path": "src/t.c", "start_line": 3, "end_line": 3},
            {"event_id": read_event, "access_kind": "READ", "event_type": "READ",
             "owner": "reader", "owner_symbol_id": owner_a,
             "relative_path": "src/t.c", "start_line": 4, "end_line": 4},
        ],
        "evidence_v2": {
            "access": [
                {"access_event_id": write_event, "file": "src/t.c",
                 "source_span": [3, 3], "owner": "writer", "owner_symbol_id": owner_b,
                 "access_kind": "WRITE", "event_type": "WRITE"},
                {"access_event_id": read_event, "file": "src/t.c",
                 "source_span": [4, 4], "owner": "reader", "owner_symbol_id": owner_a,
                 "access_kind": "READ", "event_type": "READ"},
            ],
            "lock": {"access_locksets": [], "relations": []},
            "competing_access": [],
        },
        "metadata": {
            "access": {
                owner_a: {"kind": "read", "decided": True,
                          "writer_event": "", "reader_event": read_event},
                owner_b: {"kind": "write", "decided": True,
                          "writer_event": write_event, "reader_event": ""},
            },
            "anchor_span": {"relative_path": "src/t.c",
                            "start_line": 4, "end_line": 4},
        },
    }


def double_free_candidate(evidence_id, *, first_point="event:f1",
                          second_point="event:f2") -> dict:
    return {
        "defect_key": "4.2",
        "query": "double_free",
        "subject": {
            "kind": "release", "name": "p", "identity": "sym#local:p",
            "storage": "local", "type": "char", "member": "",
            "method": "df_pos", "owner_symbol_id": "symOwner",
        },
        "anchor": second_point,
        "discriminator": "sym#local:p|symOwner|RELEASE:0|RELEASE:1",
        "resolution_status": "resolved",
        "confidence": 0.5,
        "evidence_id": evidence_id,
        "facts": [
            {"event": "RELEASE", "method": "df_pos", "point": first_point,
             "subject": "p", "source": "src/t.c:5-5"},
            {"event": "RELEASE", "method": "df_pos", "point": second_point,
             "subject": "p", "source": "src/t.c:6-6"},
        ],
        "metadata": {
            "first_release": {"point": first_point, "source": "src/t.c:5-5",
                              "subject": "p", "declared": True},
            "second_release": {"point": second_point, "source": "src/t.c:6-6",
                               "subject": "p", "declared": True},
            "anchor_span": {"relative_path": "src/t.c",
                            "start_line": 6, "end_line": 6},
        },
        "evidence_v2": {"access": [], "lock": {"access_locksets": [], "relations": []},
                        "competing_access": [], "trace_evidence": []},
    }


# ---------------------------------------------------------------------------
# candidate_key (binding identity)
# ---------------------------------------------------------------------------


class CandidateKeyTests(unittest.TestCase):
    def test_prefers_evidence_id(self) -> None:
        c = double_free_candidate("E-DEFECT-abcdef")
        self.assertEqual(P.candidate_key(c), "E-DEFECT-abcdef")

    def test_falls_back_to_defect_key_discriminator(self) -> None:
        c = double_free_candidate("")
        key = P.candidate_key(c)
        self.assertTrue(key.startswith("dk:4.2|"))
        self.assertIn("RELEASE:0|RELEASE:1", key)

    def test_falls_back_to_identity_at_anchor(self) -> None:
        c = double_free_candidate("")
        c["defect_key"] = ""
        c["discriminator"] = ""
        self.assertTrue(P.candidate_key(c).startswith("sym#local:p@event:"))


# ---------------------------------------------------------------------------
# candidate-bound access projection
# ---------------------------------------------------------------------------


class AccessProjectionTests(unittest.TestCase):
    def test_rows_are_candidate_bound(self) -> None:
        c = race_candidate("E-DEFECT-race1")
        rows = P.project_candidate_accesses(c)
        self.assertEqual(len(rows), 2)
        for r in rows:
            self.assertEqual(r["candidate_key"], "E-DEFECT-race1")

    def test_rows_are_deduped(self) -> None:
        # related_accesses and evidence_v2 both carry the same two events;
        # the projection must not emit duplicates.
        c = race_candidate("E-DEFECT-race1")
        rows = P.project_candidate_accesses(c)
        self.assertEqual(len(rows), 2)
        self.assertEqual(len({(r["file"], r["line"], r["event_id"]) for r in rows}), 2)

    def test_writer_and_reader_kinds_preserved(self) -> None:
        c = race_candidate("E-DEFECT-race1")
        kinds = sorted(r["access_type"] for r in P.project_candidate_accesses(c))
        self.assertEqual(kinds, ["READ", "WRITE"])

    def test_dual_event_side_emits_two_rows(self) -> None:
        # D6-L2: a metadata side citing BOTH writer_event and reader_event must
        # yield one row per cited event, not "writer or reader".
        c = race_candidate("E-DEFECT-race1")
        owner = "symA"
        c["metadata"]["access"][owner] = {
            "kind": "read", "decided": True,
            "writer_event": "event:w", "reader_event": "event:r",
        }
        rows = P.project_candidate_accesses(c)
        # writer side: WRITE + READ; reader side: READ. Both events still unique.
        self.assertEqual(len(rows), 2)

    def test_unknown_kind_is_preserved(self) -> None:
        # a kind the engine does not recognise must stay UNKNOWN, never READ.
        self.assertEqual(P.norm_kind("weird_kind"), "UNKNOWN")
        self.assertEqual(P.norm_kind(""), "UNKNOWN")
        self.assertEqual(P.norm_kind(None), "UNKNOWN")
        # ... and a located source record whose access_kind is unrecognised
        # stays UNKNOWN end to end.
        c = race_candidate("E-DEFECT-race1")
        for a in c["evidence_v2"]["access"]:
            if a["access_event_id"] == "event:r":
                a["access_kind"] = "weird_kind"
                a["event_type"] = "weird_kind"
        for r in c["related_accesses"]:
            if r["event_id"] == "event:r":
                r["access_kind"] = "weird_kind"
                r["event_type"] = "weird_kind"
        rows = P.project_candidate_accesses(c)
        kinds = {r["access_type"] for r in rows}
        self.assertIn("UNKNOWN", kinds)
        self.assertNotIn("weird_kind", kinds)

    def test_missing_location_is_unresolved(self) -> None:
        # a cited event id with no location in any payload -> unresolved row
        # that keeps its event id and candidate key but no fabricated file/line.
        c = race_candidate("E-DEFECT-race1")
        c["metadata"]["access"]["symA"] = {
            "kind": "read", "decided": False,
            "writer_event": "", "reader_event": "event:missing",
        }
        c["related_accesses"] = [r for r in c["related_accesses"]
                                 if r["event_id"] != "event:r"]
        c["evidence_v2"]["access"] = [a for a in c["evidence_v2"]["access"]
                                      if a["access_event_id"] != "event:r"]
        rows = P.project_candidate_accesses(c)
        unresolved = [r for r in rows if r["event_id"] == "event:missing"]
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]["file"], "")
        self.assertEqual(unresolved[0]["line"], 0)
        self.assertEqual(unresolved[0]["candidate_key"], "E-DEFECT-race1")


class CrossCandidateIsolationTests(unittest.TestCase):
    def test_shared_identity_does_not_merge(self) -> None:
        # shared_name defects legitimately share one subject identity across
        # several candidates; binding on identity would merge them. The key
        # (evidence_id) must keep them apart.
        c1 = race_candidate("E-DEFECT-aaa")
        c2 = race_candidate("E-DEFECT-bbb", owner_a="symC", owner_b="symD",
                            write_event="event:w2", read_event="event:r2")
        self.assertEqual(c1["subject"]["identity"], c2["subject"]["identity"])
        self.assertNotEqual(P.candidate_key(c1), P.candidate_key(c2))

        p1 = P.project_candidate(c1)
        p2 = P.project_candidate(c2)
        self.assertEqual({r["candidate_key"] for r in p1["access_rows"]},
                         {"E-DEFECT-aaa"})
        self.assertEqual({r["candidate_key"] for r in p2["access_rows"]},
                         {"E-DEFECT-bbb"})


# ---------------------------------------------------------------------------
# release-site projection (double free)
# ---------------------------------------------------------------------------


class ReleaseSiteProjectionTests(unittest.TestCase):
    def test_sites_are_candidate_bound(self) -> None:
        c = double_free_candidate("E-DEFECT-df1")
        sites = P.project_candidate_release_sites(c)
        self.assertEqual(len(sites), 2)
        for s in sites:
            self.assertEqual(s["candidate_key"], "E-DEFECT-df1")
            self.assertEqual(s["access_type"], "RELEASE")

    def test_source_fact_id_is_the_facts_point(self) -> None:
        c = double_free_candidate("E-DEFECT-df1")
        sites = P.project_candidate_release_sites(c)
        self.assertEqual({s["source_fact_id"] for s in sites},
                         {"event:f1", "event:f2"})

    def test_release_sites_are_deduped(self) -> None:
        # metadata.first/second_release repeat the same facts[] events; the
        # projection must not emit four sites.
        c = double_free_candidate("E-DEFECT-df1")
        self.assertEqual(len(P.project_candidate_release_sites(c)), 2)


# ---------------------------------------------------------------------------
# bundle assembly + binding assertion
# ---------------------------------------------------------------------------


class BundleAssemblyTests(unittest.TestCase):
    def test_deterministic_order(self) -> None:
        c = race_candidate("E-DEFECT-race1")
        first = P.project_candidate(c)
        second = P.project_candidate(c)
        self.assertEqual(first, second)

    def test_supporting_locations_anchor_and_accesses(self) -> None:
        c = race_candidate("E-DEFECT-race1")
        projected = [P.project_candidate(c)]
        locs = P.build_supporting_locations(projected, role_fact_name="shared_accesses")
        roles = {l["semantic_role"] for l in locs}
        self.assertIn("candidate_anchor", roles)
        self.assertIn("racing_access", roles)
        for l in locs:
            self.assertTrue(l["candidate_key"])

    def test_assert_candidate_binding_clean(self) -> None:
        projected = [P.project_candidate(race_candidate("E-DEFECT-race1")),
                     P.project_candidate(double_free_candidate("E-DEFECT-df1"))]
        bundle = {
            "evidence_locations": P.evidence_locations(projected),
            "supporting_locations": P.build_supporting_locations(
                projected, role_fact_name="shared_accesses"),
        }
        self.assertEqual(P.assert_candidate_binding(bundle), [])

    def test_assert_candidate_binding_detects_cross_candidate_release(self) -> None:
        # one RELEASE fact claimed by two candidates is a cross-candidate merge.
        c1 = double_free_candidate("E-DEFECT-df1")
        c2 = double_free_candidate("E-DEFECT-df2")  # same fact points -> merge
        projected = [P.project_candidate(c1), P.project_candidate(c2)]
        bundle = {
            "evidence_locations": P.evidence_locations(projected),
            "supporting_locations": P.build_supporting_locations(
                projected, role_fact_name="release_sites"),
        }
        probs = P.assert_candidate_binding(bundle)
        self.assertTrue(any("several candidates" in p for p in probs), probs)


if __name__ == "__main__":
    unittest.main()
