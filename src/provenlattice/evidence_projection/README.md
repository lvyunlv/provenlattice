# ProvenLattice Evidence Projection — FactBundle v2.1 (GATE-0)

Candidate-bound evidence projection over the **real** ProvenLattice defect
query. The GATE-0 delivery (Issue #78) reproduces the real-graph fact delivery
chain (`query_defect` → evidence projection → FactBundle v2.1 binding +
validation) for exactly two defect types. Issue #79 adds, additively and
separately, the **Canonical Evidence IR V1** (`ir.py`) that projects a
FactBundle v2.1 into a versioned, machine-verifiable unified evidence structure.
Issue #83 adds, additively, the **Projector Registry V1** (`registry.py`) that
wires the two GATE-0 projectors into one unified, fail-closed mechanism. It
deliberately does **not** build the multi-defect extension or the five-interface
Agent/Skill API (those are later phases, authorised separately).

## Scope

| Authorised (GATE-0 + #79 + #83)                        | NOT authorised (later phases) |
| ------------------------------------------------------ | ----------------------------- |
| `analyze_shared_access` (Race Condition)               | multi-defect extension        |
| `analyze_double_free` (Double Free)                    | Agent / Skill API             |
| FactBundle v2.1 compatible envelope + validation       | Skill-consumer integration    |
| Candidate ↔ Evidence binding proof                      | real 3rd-defect production    |
| Canonical Evidence IR V1 (`ir.py`, Issue #79)          |                               |
| Projector Registry V1 (`registry.py`, Issue #83)       |                               |
| `schema/`, `fixtures/`, this README, `tests/`          |                               |

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
* `ir.py` — Canonical Evidence IR V1 (Issue #79): `factbundle_v2_1_to_ir` +
  `validate_evidence_ir_v1` + the 9-block + `source_envelope` mapping. Pure and
  engine-free.
* `registry.py` — Projector Registry V1 (Issue #83): `Projector` protocol +
  `Registry` + production `REGISTRY`, wrapping the two GATE-0 `analyze_*`
  entries (read-only, fail-closed).
* `schema/factbundle_v2_1.schema.json` — JSON Schema for the v2.1 envelope.
* `schema/evidence_ir_v1.schema.json` — JSON Schema for the Canonical Evidence IR V1.
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

## Canonical Evidence IR V1 (Issue #79)

`ir.py` adds, additively, the **Canonical Evidence IR V1** — the *evidence
expression* stage that follows GATE-0's *evidence transport* stage. It is a
pure, deterministic, engine-free projection of a FactBundle v2.1 envelope into
a versioned, additive, machine-verifiable structure. It does **not** build the
Projector Registry, a multi-defect protocol, or an Agent/Skill API.

### Structure: 9 blocks + lossless fallback

| Block | Meaning |
| ----- | ------- |
| `run` | code revision / engine version / DB snapshot identity (from `run_context`, else `NOT_RECORDED`) + source schema / contract / projection / adapter / projector versions + query params + error/reason |
| `candidates` | stable non-empty id (`candidate.id` = verbatim GATE-0 `candidate_key`, C5), defect type, identity/subject, primary anchor |
| `claims` | falsifiable propositions + `SUPPORTED` / `UNSUPPORTED` / `UNKNOWN` / `PARTIAL`; V1 emits `[]` (not a detector, C3) |
| `facts` | atomic engine facts preserving the real fact/event id |
| `relations` | typed relations, only when evidence-backed; V1 emits `[]` (no inference, C4) |
| `locations` | source location, owner, semantic role, anchor class (no `held_locks`) |
| `provenance` | Engine fact → Candidate → Projector → Bundle trace chain |
| `coverage` | only `source_location` (the GATE-0 `location_coverage`, C4) |
| `limitations` | explicit degradation statements; never empty/`false` to mean "unknown" |
| `source_envelope` | deep copy of the original bundle — lossless fallback (C1) |

> The issue's prose names the candidate block `candidate` (singular); it is
> realised here as a `candidates` array because a FactBundle v2.1 may carry
> several candidate bindings (acceptance M4 cross-candidate pollution, M15
> candidate identity boundary). Each element carries `candidate.id` (verbatim
> `candidate_key`), `defect_type`, `identity`, `subject`, `primary_anchor` and
> the identity evidence.

### Field mapping (FactBundle v2.1 → IR)

| FactBundle v2.1 | IR |
| --------------- | -- |
| `api_version` | `source_envelope` (not merged into `ir_schema_version`) |
| `schema_version` | `run.source_schema_version` + `source_envelope` |
| `contract_version` | `run.contract_version` + `source_envelope` |
| `projection_version` | `run.projection_version` |
| `adapter_version` | `run.adapter_version` |
| `core_adapter_version` | `run.core_adapter_version` (may be empty) |
| `status` | top-level `bundle_status` (independent; never → claim status) |
| `defect_type` | `candidate.defect_type` |
| `error` / `reason` | `run.error` / `run.reason` + `source_envelope` |
| `facts` | IR `facts` + `source_envelope.facts` |
| `supporting_locations` | IR `locations` + `source_envelope` |
| `evidence_locations` | IR `locations` + `candidates` (binding) + `source_envelope` |
| `location_coverage` | `coverage.source_location` + `source_envelope` |
| `request` | `run.query_params` + `source_envelope` |
| `candidate_key` | `candidate.id` (verbatim, C5) |
| `evidence_id` / `defect_key` / `discriminator` | `candidate.*` |
| `identity` / `subject` | `candidate.identity` / `candidate.subject` |
| access_row `event_id` / `source_fact_id` | `facts` (real fact/event id) |
| access_row `held_locks` | `source_envelope` only (C4, never → `GUARDED_BY`) |

Fallback (C1): every unlisted field is preserved verbatim in `source_envelope`;
there is no silent drop, no normalisation / reorder / type coercion of original
values.

### Version compatibility (E2)

- `ir_schema_version` (`"1"`) — the IR's own structure version.
- `projection_version` (`factbundle-projection-v2.1`) — the existing GATE-0
  projection implementation.
- `adapter_version` (`provenlattice-evidence-projection-v1`) — the adapter
  implementation.
- `projector_version` (`NOT_APPLICABLE`) — no Projector Registry in this phase;
  **not** to be conflated with `projection_version`.

V1 is additive / forward-compatible: consumers ignore unknown optional fields;
published required fields are never removed or re-semanticised.

### Entry points

```python
from provenlattice.evidence_projection import ir

evidence = ir.factbundle_v2_1_to_ir(bundle, run_context={"code_revision": "..."})
problems = ir.validate_evidence_ir_v1(evidence)  # [] == valid
```

`factbundle_v2_1_to_ir` is pure and deterministic; it never mutates `bundle`,
never reads the engine / git HEAD / DB, and emits `claims == []` /
`relations == []`. `validate_evidence_ir_v1` returns a list of problem strings
(empty == valid) and proves the candidate↔evidence binding plus the M1–M15
structure. Test coverage lives in `tests/test_evidence_ir.py`.

## Projector Registry V1 (Issue #83)

`registry.py` adds, additively, the **Projector Registry V1** — a unified
Projector protocol + fail-closed registry that wires the two GATE-0 defect
projectors (`race_condition` / `double_free`) into one discoverable mechanism.
It **wraps** the GATE-0 `adapter.analyze_*` entries (read-only reference); it
never re-projects, never modifies the GATE-0 modules, and never touches the IR
V1 `ir.py`.

### Protocol + registry

```python
from provenlattice.evidence_projection import registry

registry.REGISTRY.list_projector_capabilities()
# -> [{"defect_type": "double_free", "projector_version": "1"},
#     {"defect_type": "race_condition", "projector_version": "1"}]

bundle = registry.REGISTRY.analyze("race_condition", case_workdir, database)
```

- `Projector` (Protocol) — `defect_type` + `projector_version` + `analyze(...)`;
  one implementation == one defect type.
- `Registry` — instantiable; `register_projector` / `get_projector` /
  `list_projector_capabilities` / `analyze`. Fail-closed: duplicate
  `defect_type` → `DuplicateDefectTypeError`; unknown `defect_type` →
  `UnknownDefectTypeError`; never a silent overwrite and never a placeholder.
- `REGISTRY` — the production global instance, with the two built-ins
  pre-registered (`race_condition`, `double_free`).

`AdapterProjector` wraps a GATE-0 `analyze_*` with frozen (read-only) metadata;
`analyze` forwards `(case_workdir, database, target_symbols, **kwargs)` verbatim
and returns the FactBundle v2.1 verbatim. The registry is pure forwarding, so
its output is byte-identical (and SHA-256 equal) to the direct GATE-0 entry.

### Version semantics (E2, tied to #79)

| Field | Layer | Value | Notes |
| ----- | ----- | ----- | ----- |
| `projector_version` | Registry mechanism | `"1"` | this module (`PROJECTOR_MECHANISM_VERSION`) |
| `projection_version` | GATE-0 projection | `factbundle-projection-v2.1` | stamped by `adapter`, never rewritten by the registry |
| IR `run.projector_version` | IR V1 (frozen) | `NOT_APPLICABLE` | `ir.py` unchanged; the registry does not write it |

The registry's `projector_version` is independent metadata; it is not written
into, and does not overwrite, the IR V1 `run.projector_version`. Writing a
registry projector identity into the IR would be a separate IR upgrade
(additive field / IR V2), out of scope for this phase.

### Dependency closure

`registry.py` imports only `adapter` (to wrap the two GATE-0 entries) and
`constants` (for the `defect_type` mapping); it never imports `ir.py`, the
engine, GT, Prompt, Skill or Scorer. The test-only third projector is
registered on an independent `Registry()` and never enters the production
`REGISTRY` or the FactBundle `defect_type` schema enum. Test coverage lives in
`tests/test_evidence_registry.py`.

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
