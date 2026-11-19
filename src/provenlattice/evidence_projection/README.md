# ProvenLattice Evidence Projection — FactBundle v2.1 (GATE-0)

Candidate-bound evidence projection over the **real** ProvenLattice defect
query. This package is the GATE-0 delivery of Issue #78: it reproduces the
real-graph fact delivery chain (`query_defect` → evidence projection →
FactBundle v2.1 binding + validation) for exactly two defect types, and
deliberately does **not** build the generic Evidence IR, Projector Registry,
multi-defect extension, or the five-interface Agent/Skill API (those are
later phases, authorised separately).

## Scope

| Authorised (GATE-0)                                   | NOT authorised |
| ----------------------------------------------------- | -------------- |
| `analyze_shared_access` (Race Condition)              | Canonical Evidence IR |
| `analyze_double_free` (Double Free)                   | Projector Registry |
| FactBundle v2.1 compatible envelope + validation      | multi-defect extension |
| Candidate ↔ Evidence binding proof                     | Agent / Skill API |
| `schema/`, `fixtures/`, this README, `tests/`          | Skill-consumer integration |

The implementation lives **only** under
`src/provenlattice/evidence_projection/` (plus its tests). No engine fact
production, parser/walker, CFG/DFG, alias, Happens-Before, detector verdict,
GT/Prompt/Skill/Scorer, 400-run artefact, historical frozen adapter, or
release/version/tag is modified.

## Modules

* `constants.py` — version + terminal-status constants the whole package shares.
* `projection.py` — engine-agnostic per-candidate projection. Never imports the
  engine; consumes already-serialised candidate records. A faithful port of the
  v2.1 reference semantics (candidate-bound access rows / release sites,
  dedupe, unresolved preservation, `assert_candidate_binding`).
* `source.py` — fail-closed wrapper over the single real entry point
  `provenlattice.defect_query.query_defect_candidates`.
* `adapter.py` — the two public `analyze_*` entry points + `validate_bundle_v2`.
* `schema/factbundle_v2_1.schema.json` — JSON Schema for the v2.1 envelope.
* `fixtures/` — real captured candidate records + real FactBundle v2.1 bundles.

## Dependency closure (audit trail)

The projection chain's exact inputs, so the delivered bundle can be traced back
to a real engine result without an old-machine absolute path or a silently
imported same-named module.

* **Repository / commit** — `sunSUNQ/provenlattice`, `main` @
  `87030960f7e2124973ac00d322a5917c2e85dada` (the GATE-0 baseline; not changed).
* **Real query entry** — `provenlattice.defect_query.query_defect_candidates(
  repo, *, defect_type=..., database=..., ...)`. There is no literal
  `query_defect` function; this is the only defect-evidence producer. Its
  answer is `{"status": "available"|"stale", "candidates": [...],
  "evidence_bundles": [...], ...}` where each candidate carries
  `evidence_id` (`E-DEFECT-<sha256[:24]>`), `related_accesses`,
  `evidence_v2` (the five-block Evidence Schema V2), `metadata`, and `facts`.
* **DB generation** — `provenlattice.storage.SQLiteStorage.current_generation(
  repo_id)` (the `repositories.current_generation` counter; the schema is
  created by `SQLiteStorage` on first open and carries no separate version
  number beyond that counter). `candidate_evidence` records `generation` and
  `commit="base"` in each `E-DEFECT-` id.
* **Upstream chain required** — `events -> sparse_cfg -> sparse_dfg` must be
  materialised (`analyze --features sparse_dfg`); a missing/stale upstream fails
  the query closed (`stale` / `not_built`), never yields partial facts.

### External v2.1 reference (behavioural baseline only)

The reference reproduction package
`provenlattice_real_factbundle_v2_1_repro.zip` (SHA-256-verified) provided two
real-graph modules used **only** as a behavioural baseline — they are external
research implementations, not ProvenLattice production code, and are **not**
copied or imported:

* `core/direct_api_adapter_f1_1_v2_1.py`
  `sha256:a861199e2446fa9ddfb16b256fe31a9b22290a61902cac4f01e0cec540174bcb`
* `core/factbundle_projection_v2_1.py`
  `sha256:e708abad89071612decf7d6afe131f2a04828c2291af1eab504af56c75adca70`

### Divergence from the reference (recorded, not hidden)

1. **Self-contained envelope.** The reference `direct_api_adapter_f1_1_v2_1.py`
   delegates terminal-status derivation and `build_bundle` to a *frozen external*
   v1 core (`direct_api_adapter_f1_1.py`) that is not in this repository. GATE-0
   must not fabricate that file, re-implement it verbatim, or import it from an
   old-machine path (`D:\contextbench_kg_bench\...`). `adapter.py` therefore
   builds a semantically-compatible envelope directly — same `api_version`
   `"v1.1"`, same terminal status set, same v1 access-row keys plus the v2.1
   additions — and stamps its own identity in `adapter_version`. This is
   **semantic**, not byte-level, parity.
2. **`PROV_RELEASE_META` provenance tag** is
   `candidate.metadata.first_release/second_release` (the real metadata keys),
   where the reference emits the slightly inaccurate
   `candidate.metadata.release_sites`.
3. The frozen v1 validator is not importable, so `validate_bundle_v2`
   reproduces the v1 checks it is known to apply (envelope keys, `api_version`,
   `status` set) in-line; the v2.1 checks are byte-level faithful.

## Entry points

```python
from provenlattice.evidence_projection import (
    analyze_shared_access, analyze_double_free, validate_bundle_v2)

bundle = analyze_double_free(case_workdir, database)   # -> FactBundle v2.1
issues = validate_bundle_v2("analyze_double_free", bundle)  # [] == bound
```

`case_workdir` is the checked-out Case workspace (the engine's `repo`);
`database` is the real graph DB path (`None` → engine default). `target_symbols`
(optional) narrows to one subject symbol. A fail-closed terminal (`stale`,
`not_built`, `failed`, `empty`) carries **zero** projected candidates — the
envelope may not assert a binding it does not have.

## Testing

```bash
$env:PYTHONPATH = "<worktree>/src"
python -m pytest tests/test_evidence_projection*.py -q
```

`tests/test_evidence_projection.py` unit-tests the pure projection (binding,
dedupe, cross-candidate isolation, unresolved/UNKNOWN preservation,
determinism); `tests/test_evidence_projection_adapter.py` unit-tests the
envelope + validation against the real fixtures and a stub source;
`tests/test_evidence_projection_e2e.py` builds a **real** index and runs the
two `analyze_*` entry points, including negative / empty / stale / not-built
paths.
