# Implementation status

**Contract identity: v0.1** (`CONTRACT_VERSION`) · **package: 0.3.0.** The canonical
seal is stable and several implementations now conform to it (see the table below); the
contract *spec* has not rev'd past v0.1 because the identity has not changed — the 0.3.x
work is additive (concurrency-topology vocabulary, partial-order events) with unchanged
hashes for existing payloads.

> **This file is the single current status source.** Two earlier records —
> [`docs/deployment-inventory.md`](docs/deployment-inventory.md) (a dated 2026-07-31
> pre-work snapshot) and
> [`docs/RUNTIME_CONTRACTS_0.3.x_CONSOLIDATION.md`](docs/RUNTIME_CONTRACTS_0.3.x_CONSOLIDATION.md)
> (the now-completed 0.3.x consolidation plan) — are **historical** and may disagree on
> version/conformance/what-exists. Where they do, this file wins.

```bash
python -m runtime_contracts.cli status
python -m runtime_contracts.cli verify --implementation quantify
```

## Where each component stands

| Component | State | Gate | |
|---|---|---|---|
| quantify | SPECIFIED | CONFORMANT | gap |
| context-runtime | SPECIFIED | CONFORMANT | gap |
| redevops-rag | SPECIFIED | CONFORMANT | gap |
| wealth-manager | SPECIFIED | CONFORMANT | gap |
| rag-saas-platform | PLANNED | PARTIAL | gap |
| discovery-runtime | LOCATED (own repo) | seal-conformant per its README; unverified here | gap |
| mission-runtime | agentic-os/mission (not a standalone repo) | unverified | gap |
| sidekick | integration module in context-runtime | n/a | ok |
| agentic-os | LOCATED (own repo) | unverified | gap |

A component whose gate is `NOT_LOCATED` is a visible roadmap gap, not a red
build. It becomes a failure the day it is declared part of the release.

## Modelled in v0.1

`ArtifactHandle` · `Tenancy` / `Visibility` / `AuthorizationOutcome` ·
`ContextPreviewPlan` · `ContextView` · `RuntimeEvent` · `DereferenceEvent` ·
canonical hashing · golden fixtures · adoption manifest

## Also modelled

`VerificationResult` · `CapabilityDescriptor` · `MissionProgram` ·
`InvestigationTransitionEvent` · submission semantics · replay engine ·
finding routing.

## Added in 0.3.x (additive)

`TopologyKind` · `JoinPolicy` · `ConcurrencyGroup` (concurrency-topology
vocabulary) · partial-order events (`InvestigationTransitionEvent.parents` +
`causal_order()`). Backward-compatible: a parent-less event hashes exactly as in
v0.1, so golden fixtures are unchanged.

The v0.1 subset Phase B needs is complete. What remains is a **consumer**: the
control-plane adapter, an append-only ledger, and the inconclusive journey
persisted rather than fixtured.

## Deliberately out of v0.1

`EvidenceSpanHandle` · `GraphNeighborhoodHandle` · shared object leases ·
governed merge result · trajectory findings · case bundles · cache-aware session
metadata. Keeping these out is what stops v0.1 becoming the whole v10 roadmap.

## Two blocking deployment facts

Neither is about contracts, and both block conformance being *attributable*:

1. **`redevops-rag` is checked out twice at different commits** — submodule
   `e3e37df`, standalone `ceec853`. An adapter passing against one says nothing
   about the other.
2. **No runtime discloses its own source commit.** Both runtimes are libraries
   imported by `backend/services/`, not deployed services, so their running
   version is whatever the backend image was built with — not discoverable from
   the source tree.

Gated as `RAG_COMMIT_OBSERVABLE` and `BUILD_MANIFEST_EMITTED`.
