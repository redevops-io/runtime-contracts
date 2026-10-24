# Changelog

No curated changelog is kept. History:

- Tags: <https://github.com/redevops-io/runtime-contracts/tags> (`v0.1.0-alpha.1..3`, `v0.2.0..v0.2.4`, `v0.3.0..v0.3.14`; never delete or rewrite them).
- GitHub releases: none.
- Release rules and what each version number means: [docs/RELEASE_DISCIPLINE.md](docs/RELEASE_DISCIPLINE.md).
- `git log --oneline v0.3.13..v0.3.14` style ranges give per-release changes.

## Unreleased

- Docs: README status section, STATUS, CONTRIBUTING, SECURITY, evidence card, docs check.
- Credential gate: tenant binding and authority expiry enforced in `authorize_request` (vectors in `tests/credential_tenant_vectors.json`).
