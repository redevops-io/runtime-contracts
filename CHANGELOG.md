# Changelog

No curated changelog is kept. History:

- Tags: <https://github.com/redevops-io/runtime-contracts/tags> (`v0.1.0-alpha.1..3`, `v0.2.0..v0.2.4`, `v0.3.0..v0.3.14`; never delete or rewrite them).
- GitHub releases: none.
- Release rules and what each version number means: [docs/RELEASE_DISCIPLINE.md](docs/RELEASE_DISCIPLINE.md).
- `git log --oneline v0.3.13..v0.3.14` style ranges give per-release changes.

## Unreleased

- `qa/v1` (`runtime_contracts/qa/`, [docs/QA_V1.md](docs/QA_V1.md)): `TestSpec` and `Step` with a tagged `ui` / `resource` target, frozen assertions referenced by hash (`executor`, `requirement_ref`, `check_program_ref`), `QAPlan` (static lanes, `coverage_contract` `FULL`), run records, `FaultEvent` with separate `detection` and `recovery`, `RunManifest` with `assertions_declared` / `assertions_executed` / `assertions_skipped`, and the `QAAdapter`, `CheckAdapter`, `BlobStore` and `Redactor` protocols. Additive: no existing schema, hash or golden file changes.
- Fixtures for `qa/v1`: `golden/qa.json`, the self-contained `golden/qa_canon_vectors.json`, `golden/qa.schema.json` (JSON Schema) and `golden/qa.inventory.json` (additive-only field inventory).

- Docs: README status section, STATUS, CONTRIBUTING, SECURITY, evidence card, docs check.
- Credential gate: tenant binding and authority expiry enforced in `authorize_request` (vectors in `tests/credential_tenant_vectors.json`).
