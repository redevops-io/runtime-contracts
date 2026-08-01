# Implementation status

**v0.1 — proposed canonical contract, implementation adoption pending.**
No implementation claims conformance. That is the accurate state, not a caveat.

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
| rag-saas-platform | PLANNED | PARTIAL | gap |
| mission-runtime | NOT_LOCATED | NOT_LOCATED | ok |
| discovery-runtime | NOT_LOCATED | NOT_LOCATED | ok |
| sidekick | NOT_LOCATED | NOT_LOCATED | ok |
| agentic-os | NOT_LOCATED | NOT_LOCATED | ok |

A component whose gate is `NOT_LOCATED` is a visible roadmap gap, not a red
build. It becomes a failure the day it is declared part of the release.

## Modelled in v0.1

`ArtifactHandle` · `Tenancy` / `Visibility` / `AuthorizationOutcome` ·
`ContextPreviewPlan` · `ContextView` · `RuntimeEvent` · `DereferenceEvent` ·
canonical hashing · golden fixtures · adoption manifest

## Specified in v0.1, not yet modelled

`CapabilityDescriptor` · `MissionProgram` · `InvestigationTransitionEvent` ·
`VerificationResult` — the remaining Phase B subset.

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
