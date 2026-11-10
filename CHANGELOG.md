# Changelog

No curated changelog is kept. History:

- Tags: <https://github.com/redevops-io/runtime-contracts/tags> (`v0.1.0-alpha.1..3`, `v0.2.0..v0.2.4`, `v0.3.0..v0.3.17`; never delete or rewrite them).
- GitHub releases: none.
- Release rules and what each version number means: [docs/RELEASE_DISCIPLINE.md](docs/RELEASE_DISCIPLINE.md).
- `git log --oneline v0.3.13..v0.3.14` style ranges give per-release changes.

## v0.3.17 (2026-11-10)

- `authz/v1` (`runtime_contracts/authz/`, [docs/AUTHZ_QUALIFICATION.md](docs/AUTHZ_QUALIFICATION.md)): the decision envelope both authorization planes emit (`AuthorizationDecision`, `parse_envelope`, `validate_envelope`, `PolicyReason`, canonical `roles_hash`, `EnvelopeError`), the qualification vocabulary (`Qualification`, `Matrix`, `CaseResult`, `Invariant`, `qualification_to_verdict`, where `UNSUPPORTED` maps to `INDETERMINATE` and never to PASS), and the seven cross-edition invariants with a runner (`run_invariant`, `AuthzAdapter`, `AdapterBlocked`, `Unsupported`, `InvariantFailure`) that drives an implementation through its own enforcement seams rather than a mocked decision. Additive and opt-in: import `runtime_contracts.authz` — `runtime_contracts.__all__` is byte-identical to `v0.3.16`, and no golden file, canonicalization rule or `schema_version` changed.
- Qualification evidence with verdicts pinned: `tests/authz_contract/qualification.json` holds the expectation, `python scripts/authz_matrix.py --check` fails if a verdict moves without it. Cards: `docs/evidence/authz_qualification_matrix.json`, `docs/evidence/authz_production_matrix.json`. The reference adapters (kernel, enterprise overlay, RAG lane) live under `adapters/` and are **not in the wheel** — `[tool.setuptools.packages.find] include = ["runtime_contracts*"]` — so re-running a qualification needs a clone, not a pin.
- The #627 retrieval lane is now measured as a property (29 cells, deterministic probe) and proved by mutation: control clean, four mutants each caught, one of them only by a detector that insists the `LIMIT` sits in a statement carrying an authorization predicate. A `ingest(owners=…)` availability defect — a document indexed through the documented ownership path is unreadable even by its owner — is recorded there and left unfixed, because it fails closed and the fix belongs to redevops-rag.
- Downstream: `runtime_contracts/protocol/` is byte-identical to `v0.3.16`, so this release changes no credential decision. The tenant-binding and authority-expiry gate — the one that answers `TENANT_MISMATCH` for a tenant-less authority — arrived in `v0.3.15`. A consumer still pinned to `v0.3.14` meets it on the first upgrade that crosses that boundary, and not here.
- CI: `.github/workflows/tests.yml` now gates `pull_request` on the base branches pull requests are actually opened against. Filtering on `main` alone had silently dropped #42's pytest gate when it was retargeted; the gate was gone for about five hours and nothing failed.
- Suite: 1825 passed / 83 skipped at `918762766899` (Python 3.12.16, pytest 9.2.0, duckdb 2.0.0, full-history clone, no sibling checkouts configured). CI on the same content as a merge: 1817 passed / 91 skipped — the eight-test delta is cells that skip when tags and history are absent, itemised in `docs/AUTHZ_QUALIFICATION.md`.

## v0.3.16 (2026-10-31)

- `qa/v1` clarifications ([docs/QA_V1.md](docs/QA_V1.md), [docs/QA_V1_COMPATIBILITY_REVIEW.md](docs/QA_V1_COMPATIBILITY_REVIEW.md)), additive within `qa/v1`: normative definitions of a predicate's `expected_hash`, value digests, state hashes, the per-step idempotency key and the ordering of every set-valued field; five distinct integrity refusal codes (`ASSERTION_PROGRAM_MISMATCH`, `ASSERTION_PROGRAM_UNREGISTERED`, `ASSERTION_PIN_NOT_FOUND`, `ASSERTION_PIN_MALFORMED`, `BATCH_HALTED`, with `IntegrityRefusalCode` and `classify_refusal`, which fails closed on an unknown code); an optional `FaultRecovery.reason_code` (closed `RecoveryReason` vocabulary); and the statement that engine limits and kill-switch state are not manifest fields. New fixtures `golden/qa_canon_vectors_addendum.json` and `golden/qa_clarifications.json`. `golden/qa.json` and `golden/qa_canon_vectors.json` are byte-identical; `golden/qa.schema.json` and `golden/qa.inventory.json` gain additions only. No version change.

## v0.3.15 (2026-10-31)

- `qa/v1` (`runtime_contracts/qa/`, [docs/QA_V1.md](docs/QA_V1.md)): `TestSpec` and `Step` with a tagged `ui` / `resource` target, frozen assertions referenced by hash (`executor`, `requirement_ref`, `check_program_ref`), `QAPlan` (static lanes, `coverage_contract` `FULL`), run records, `FaultEvent` with separate `detection` and `recovery`, `RunManifest` with `assertions_declared` / `assertions_executed` / `assertions_skipped`, and the `QAAdapter`, `CheckAdapter`, `BlobStore` and `Redactor` protocols. Additive: no existing schema, hash or golden file changes.
- Fixtures for `qa/v1`: `golden/qa.json`, the self-contained `golden/qa_canon_vectors.json`, `golden/qa.schema.json` (JSON Schema) and `golden/qa.inventory.json` (additive-only field inventory).

- Docs: README status section, STATUS, CONTRIBUTING, SECURITY, evidence card, docs check.
- Credential gate: tenant binding and authority expiry enforced in `authorize_request` (vectors in `tests/credential_tenant_vectors.json`).
