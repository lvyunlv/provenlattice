# Fixtures

Captured **real** engine output, used by the adapter/validation tests against a
stub or in-memory source. These are examples of the exact candidate records the
live ProvenLattice engine produces — they are **not** synthetic, hand-crafted
"golden" shapes, and they are **not** GT/labels.

Because the engine's `E-DEFECT-` id, subject `identity`, event ids and source
hashes are derived from the analysed workspace (repo id + file content), these
values are **per-workspace deterministic but not portable across machines**.
The fixtures therefore record one concrete run; the E2E tests re-derive the
same shapes from real C buffer fixtures instead of asserting these exact ids.

## Provenance

Generated on `origin/main @ 87030960f7e2124973ac00d322a5917c2e85dada` by
building a real graph index and running the real `query_defect_candidates` /
`analyze_*` entry points (Python 3.11, `provenlattice.__version__ == 1.7.0`).

| File | Defect | Source | Contents |
| ---- | ------ | ------ | -------- |
| `race_candidate.json` | race_condition (`1.1`) | `int shared=0; void *writer(...){ shared=42; } void *reader(...){ return shared; }` | one real candidate dict, incl. `metadata.access`, `related_accesses`, `evidence_v2.access`/`lock` |
| `double_free_candidate.json` | double_free (`4.2`) | `df_pos` (malloc → free → free) | one real candidate dict, incl. `metadata.first_release/second_release`, `facts[]` (2× RELEASE) |
| `race_factbundle_v2_1.json` | race_condition | same as `race_candidate.json` | full `analyze_shared_access` bundle |
| `double_free_factbundle_v2_1.json` | double_free | same as `double_free_candidate.json` | full `analyze_double_free` bundle |

## Key shapes (for reading a fixture)

* race subject has `decl`; double-free subject has **no** `decl` key (it has
  `kind`/`name`/`identity`/`storage`/`type`/`member`/`method`/`owner_symbol_id`).
* double-free `facts[]` entries are `event: "RELEASE"` with `point`, `source`
  (`"src/t.c:N-N"`), `method`. `metadata.anchor_span` has
  `relative_path`/`start_line`/`end_line`.
* race `metadata.access` is a dict `owner_symbol_id -> {kind, decided,
  writer_event, reader_event}` (kind is lowercase `read`/`write`).
* race `related_accesses[].{event_id, access_kind(READ/WRITE), owner,
  owner_symbol_id, relative_path, start_line, end_line}` and
  `evidence_v2.access[].{access_event_id, file, source_span, owner,
  owner_symbol_id}`.
* `evidence_id` is always present (`E-DEFECT-…`) → the projection's
  `candidate_key`.

## Regenerating

The E2E test `tests/test_evidence_projection_e2e.py` reconstructs the same
shapes at run time; to refresh these files, rebuild a real index for the same
buffer fixtures and run `query_defect_candidates` + `analyze_*`, writing the
JSON back. Do not hand-edit candidate ids.