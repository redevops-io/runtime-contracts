# runtime-contracts

**Status:** v0.1 — *proposed canonical contract, implementation adoption pending.*
No implementation currently claims conformance.

> `runtime-contracts` is the canonical, application-neutral contract package for
> ReDevOps runtime interoperability. Quantify.club provides the initial fixtures
> and design discipline but does not own the contracts semantically.
> Implementations conform through explicit adapters and golden fixtures.

---

## What this repository owns

- schema identity and versioning
- canonical serialization
- hashing rules
- compatibility rules
- visibility and tenancy semantics
- golden fixtures
- conformance expectations

## What it does not own

- planning algorithms
- retrieval logic
- Mission workflow implementations
- storage engines
- runtime-specific business logic

```
runtime-contracts   the ArtifactHandle wire contract
context-runtime     how handles are selected and materialized
redevops-rag        how candidate handles are retrieved
rag-saas-platform   how MissionProgram is currently executed
quantify            its adapter and application-specific artifacts
```

---

## The load-bearing invariant

```
same handles + same preview plan + same version pins + same contract version
    = same ContextView hash
```

Across implementations, across process restarts, across languages. Everything in
[docs/canonicalization.md](docs/canonicalization.md) exists to make that
reproducible rather than approximately true.

---

## v0.1 scope

**Specified and modelled now** — the subset Phase B requires:

`ArtifactHandle` · `ContextPreviewPlan` · `ContextView` · `DereferenceEvent` ·
`RuntimeEvent` · `CapabilityDescriptor` · `MissionProgram` ·
`InvestigationTransitionEvent` · `VerificationResult` · visibility and tenancy
types · canonical hashing · adoption manifest · golden fixtures

**Specified later** — deliberately out of v0.1 so it does not become the whole
v10 roadmap:

`EvidenceSpanHandle` · `GraphNeighborhoodHandle` · shared object leases ·
governed merge result · trajectory findings · case bundles · cache-aware session
metadata

---

## Adoption

Conformance is claimed per implementation and per contract, never globally.

```bash
python -m runtime_contracts.cli status
python -m runtime_contracts.cli verify --implementation quantify
```

`status` reports every implementation's maturity and gaps. `verify` fails when a
component that has *claimed* a level does not meet it. A component below its
release gate fails; a component whose gate is `NOT_LOCATED` is a visible roadmap
gap, not a red build.

Maturity runs `NOT_LOCATED → PLANNED → SPECIFIED → ADAPTER_STARTED →
ROUND_TRIP_PROVEN → PARTIAL_ADOPTION → CONFORMANT → DEPLOYED_CONFORMANT`.
Reproducing a golden hash earns `ADAPTER_STARTED`, not conformance: it proves
translation, not adoption.

See [adoption/implementations.yaml](adoption/implementations.yaml),
[IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) and
[docs/release-discipline.md](docs/release-discipline.md).

---

## Licence

**Apache-2.0**, deliberately, and differing from the AGPL-3.0 used by
`context-runtime` and `redevops-rag`.

A contract package has to be importable by every implementation that conforms to
it, including ones whose licensing is not yet decided. AGPL on the schemas would
make adopting the wire format a licensing decision about the adopter's own code,
which is the opposite of what a neutral contract is for. The schemas carry no
business logic, so there is nothing here that copyleft would protect.

**The licence covers this contract package only.** It does not relicense
implementations, adapters, or underlying runtime code: `context-runtime` and
`redevops-rag` keep AGPL-3.0, and an adapter carries whatever licence its own
repository does. Apache-2.0 here means importing the schemas and reproducing a
wire hash is not a licensing decision about the importer.

**This is a reversible call and it is the maintainers' to make** — it is written
down here rather than left implicit in a file header.
