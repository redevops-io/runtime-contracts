# Status

Last verification date: **2026-10-15**. Package `0.3.14` (`pyproject.toml`), contract identity `v0.1`, commit `80e727d`.

**Maturity: proposed specification (alpha) with one in-repo reference adapter.** Not a service, not
independently validated.

## Shipped and tested (this repository's own tests)

| Item | Evidence |
|---|---|
| Schema types, canonical serialization and hashing (`rcv1`) | `tests/test_canonicalization.py`, `tests/test_contracts.py`, `golden/` |
| Golden fixtures (context view, investigation lifecycle, security, geospatial) | `tests/test_golden.py` |
| Seal vectors | `tests/golden_seal_vectors.json`, `tests/test_seal.py` |
| Adoption manifest and CLI (`status`, `verify`) | `tests/test_adoption.py`, `tests/test_release_discipline.py` |
| Quantify adapter reproduces golden hashes (`ADAPTER_STARTED`) | `adapters/quantify`, `tests/test_quantify_adapter.py` |
| Credential gate: tenant binding (request tenant must equal authority tenant; empty tenants and tenant-less authority denied), authority expiry | `tests/test_secret_contracts.py`, `tests/credential_tenant_vectors.json` |
| `qa/v1` contracts: frozen-assertion types, plan, run records, fault detection/recovery, manifest accounting, adapter and blob protocols | `tests/test_qa_*.py`, `golden/qa.json`, `golden/qa_canon_vectors.json`, `golden/qa.schema.json`, `docs/QA_V1.md` |
| `qa/v1` clarifications (additive): predicate `expected_hash`, value digests, idempotency key, set ordering, distinct integrity refusal codes, `FaultRecovery.reason_code`; existing goldens byte-identical | `tests/test_qa_clarifications.py`, `golden/qa_canon_vectors_addendum.json`, `golden/qa_clarifications.json`, `docs/QA_V1_COMPATIBILITY_REVIEW.md` |
| Whole suite | `python -m pytest -q` -> 1785 passed, 1 skipped (2026-10-30, Python 3.13, scrubbed environment); CI: `.github/workflows/tests.yml` |

## Conformance: proposed vs implemented

| | State |
|---|---|
| Proposed specification | All contract types listed in the README ("v0.1 scope" and the `0.3.x` additions). |
| Implemented adapters passing conformance tests | `quantify` only, and only to `ADAPTER_STARTED` (translation, not adoption). |
| Implementations at `CONFORMANT` or `DEPLOYED_CONFORMANT` | **none** |
| Conformance reports published | **none yet** |
| Open gates | `RAG_COMMIT_OBSERVABLE`, `BUILD_MANIFEST_EMITTED` (see `status` output) |

## Limitations

- Cross-language claims (Go, Kotlin) refer to private repositories; not checkable here.
- `adoption/implementations.yaml` was observed on 2026-07-31; some rows are stale (`agentic-os`,
  `discovery-runtime`, `mission-runtime` read `NOT_LOCATED`). The data file is intentionally not edited in this
  documentation change.
- Some referenced implementations are in repositories that are not public.
- Licence: see `LICENSE.md` (titled "source-available, not open source").

## Known gaps

- No conformance report artifact; no external review.
- Tag history has no stable `v0.1.0` (tags `v0.1.0-alpha.1..3`, `v0.2.x`, `v0.3.0..v0.3.14`); there are no GitHub releases.

## Evidence

[docs/evidence/](docs/evidence/) · [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) · [adoption/implementations.yaml](adoption/implementations.yaml)
