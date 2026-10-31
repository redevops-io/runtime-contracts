# Changelog

No curated changelog is kept. History:

- Tags: <https://github.com/redevops-io/runtime-contracts/tags> (`v0.1.0-alpha.1..3`, `v0.2.0..v0.2.4`, `v0.3.0..v0.3.14`; never delete or rewrite them).
- GitHub releases: none.
- Release rules and what each version number means: [docs/RELEASE_DISCIPLINE.md](docs/RELEASE_DISCIPLINE.md).
- `git log --oneline v0.3.13..v0.3.14` style ranges give per-release changes.

## Unreleased

- `qa/v1` (`runtime_contracts/qa/`, [docs/QA_V1.md](docs/QA_V1.md)): `TestSpec` and `Step` with a tagged `ui` / `resource` target, frozen assertions referenced by hash (`executor`, `requirement_ref`, `check_program_ref`), `QAPlan` (static lanes, `coverage_contract` `FULL`), run records, `FaultEvent` with separate `detection` and `recovery`, `RunManifest` with `assertions_declared` / `assertions_executed` / `assertions_skipped`, and the `QAAdapter`, `CheckAdapter`, `BlobStore` and `Redactor` protocols. Additive: no existing schema, hash or golden file changes.
- Fixtures for `qa/v1`: `golden/qa.json`, the self-contained `golden/qa_canon_vectors.json`, `golden/qa.schema.json` (JSON Schema) and `golden/qa.inventory.json` (additive-only field inventory).
- `qa/v1` clarifications ([docs/QA_V1.md](docs/QA_V1.md), [docs/QA_V1_COMPATIBILITY_REVIEW.md](docs/QA_V1_COMPATIBILITY_REVIEW.md)), additive within `qa/v1`: normative definitions of a predicate's `expected_hash`, value digests, state hashes, the per-step idempotency key and the ordering of every set-valued field; five distinct integrity refusal codes (`ASSERTION_PROGRAM_MISMATCH`, `ASSERTION_PROGRAM_UNREGISTERED`, `ASSERTION_PIN_NOT_FOUND`, `ASSERTION_PIN_MALFORMED`, `BATCH_HALTED`, with `IntegrityRefusalCode` and `classify_refusal`, which fails closed on an unknown code); an optional `FaultRecovery.reason_code` (closed `RecoveryReason` vocabulary); and the statement that engine limits and kill-switch state are not manifest fields. New fixtures `golden/qa_canon_vectors_addendum.json` and `golden/qa_clarifications.json`. `golden/qa.json` and `golden/qa_canon_vectors.json` are byte-identical; `golden/qa.schema.json` and `golden/qa.inventory.json` gain additions only. No version change.

- Docs: README status section, STATUS, CONTRIBUTING, SECURITY, evidence card, docs check.
- Credential gate: tenant binding and authority expiry enforced in `authorize_request` (vectors in `tests/credential_tenant_vectors.json`).
