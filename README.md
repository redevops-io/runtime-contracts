# runtime-contracts

[![License: AGPL-3.0 + Commons Clause](https://img.shields.io/badge/License-AGPL--3.0%20%2B%20Commons%20Clause-blue.svg)](LICENSE.md) ![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB.svg) [![NVIDIA Inception](https://img.shields.io/badge/NVIDIA-Inception%20Program%20Member-76B900.svg)](https://www.nvidia.com/en-us/startups/)
&nbsp;·&nbsp; self-hosted &nbsp;·&nbsp; no lock-in &nbsp;·&nbsp; source-available

> **🚀 NVIDIA Inception Program Member** — ReDevOps is a member of the NVIDIA Inception Program, supporting startups advancing AI and accelerated computing. Membership provides access to NVIDIA technology, technical resources, and the startup ecosystem. It does not imply product endorsement by NVIDIA.


**What it does.** The canonical, application-neutral *schemas, hashing rules, golden fixtures and an adoption
manifest* that let separate ReDevOps runtime components (Mission, Context, Discovery) exchange the same
artifacts and produce the same hashes. It is a Python package of types and checks, not a service.

**Who it's for.** Maintainers of a ReDevOps runtime component, or an engineer writing an adapter that must
produce byte-identical artifacts to the reference implementation.

**Maturity: proposed specification (alpha), with one in-repo reference adapter.** Details and the exact
conformance state are in [Status](#status) and [STATUS.md](STATUS.md).

> `runtime-contracts` is the canonical contract package for ReDevOps runtime interoperability. Quantify.club
> provides the initial fixtures and design discipline but does not own the contracts semantically.
> Implementations conform through explicit adapters and golden fixtures.

## Status

One statement, replacing earlier conflicting ones. Source of truth: [`adoption/implementations.yaml`](adoption/implementations.yaml)
(`python -m runtime_contracts.cli status`), verified 2026-10-15 at package `0.3.14`, commit `80e727d`.

| Question | Answer |
|---|---|
| Is the contract specified? | **Yes, as a proposed specification.** Contract identity `v0.1`; the `0.3.x` package work is additive. |
| Does any implementation claim conformance (`CONFORMANT`)? | **No.** None has reached `CONFORMANT` or `DEPLOYED_CONFORMANT`. |
| Which implemented adapters pass tests? | **Quantify** (`adapters/quantify`, tests in `tests/test_quantify_adapter.py`): reproduces golden hashes. By this repo's own definition that earns `ADAPTER_STARTED` (translation proven), not conformance. The manifest also records a non-public implementation as `PARTIAL_ADOPTION` (not verifiable here). |
| Others (context-runtime, redevops-rag) | `SPECIFIED`: a `mapping.yaml` exists under `adapters/`, no tested adapter code. |
| Conformance reports | **None yet.** The only machine-checked evidence is this repository's own test suite ([`tests` workflow](.github/workflows/tests.yml); 442 tests passed locally on 2026-10-15). |
| Manifest freshness | The manifest header says "Observed 2026-07-31"; entries for `agentic-os`, `discovery-runtime`, `mission-runtime` still read `NOT_LOCATED` even though `agentic-os` and `discovery-runtime` are now public repositories. Treat those rows as stale, not as a statement of absence. |

Naming: *Mission* = governed execution, *Context* = context selection/optimization, *Discovery* = finding and
prioritizing opportunities; together the one public product, **ReDevOps Runtime**. Glossary:
[agentic-os/docs/GLOSSARY.md](https://github.com/redevops-io/agentic-os/blob/main/docs/GLOSSARY.md).

## 3-minute example

```bash
git clone --depth 1 --branch v0.3.14 https://github.com/redevops-io/runtime-contracts.git && cd runtime-contracts
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m runtime_contracts.cli status      # per-implementation maturity and gaps
python -m pytest -q                         # golden fixtures + canonicalization tests
```

To depend on it from another project (not on PyPI):
`pip install "runtime-contracts @ git+https://github.com/redevops-io/runtime-contracts.git@v0.3.14"`.
No ReDevOps package is published on PyPI.

## Evidence

[`golden/`](golden/) fixtures and `tests/` (the hash invariant below); card
[`docs/evidence/rc_contextview_hash_invariant.yaml`](docs/evidence/rc_contextview_hash_invariant.yaml)
(*Internally reproduced*). Nothing here is externally reproduced or field validated.

## Limitations

Proposed spec; no `CONFORMANT` implementation; cross-language reproducibility (Go, Kotlin ports) is claimed
only for repositories that are not public and is not demonstrable from this repo; see [LICENSE.md](LICENSE.md) for licence terms.

## Docs

[STATUS](STATUS.md) · [IMPLEMENTATION_STATUS](IMPLEMENTATION_STATUS.md) · [canonicalization](docs/canonicalization.md) ·
[release discipline](docs/release-discipline.md) · [SECURITY](SECURITY.md) · [CONTRIBUTING](CONTRIBUTING.md) ·
[CHANGELOG](CHANGELOG.md)

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
(non-public)        how MissionProgram is currently executed, with its adapter and application-specific artifacts
```

---

## The load-bearing invariant

```
same handles + same preview plan + same version pins + same contract version
    = same ContextView hash
```

Intended to hold across implementations, process restarts and languages. Verified in this repo for Python only
(golden fixtures + tests). Everything in
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

**Added in 0.3.x (additive, backward-compatible)** — the concurrency-topology
vocabulary (`TopologyKind` · `JoinPolicy` · `ConcurrencyGroup`) and partial-order
events (an optional `parents` field on `InvestigationTransitionEvent` plus
`causal_order()`). Both are additive: an event with no `parents` serialises and
hashes exactly as before, so existing golden fixtures are unchanged.

**External / Professional Intelligence provider layer (`protocol/intelligence.py`,
`protocol/intelligence_registry.py`)** — the domain-neutral contract behind the
apps' intelligence moat: a `Capability` a DecisionCase asks for (never a provider
name), `EvidenceRequest` / `EvidenceArtifact` carrying provenance / cost /
freshness / license, the `IntelligenceProvider` protocols and registry, the
evidence-value gate (`decide_acquire` / `gated_acquire`), and the legal
authority-level ladder (`LegalAuthorityLevel` · `may_auto_execute`). Adapters and
the gate wiring live in `agentic-os`, never here.

**Bounded decision provider protocol (`protocol/decision_provider.py`)** — the
shared `decision-provider/v1` request/result contract for rules, compact
decision models, LLM adapters and learned policies. A provider scores or selects
from an already-permitted option set and can abstain, but it never grants write
authority or bypasses policy, approval, idempotency or independent readback.

**Email delivery execution + receipt (`protocol/email_delivery.py`)** — email
delivery is an *execution*, not evidence, so it has its own contract:
`EmailSendRequest` (idempotent by key), the normalized `EmailDeliveryStatus`
lifecycle, and `EmailDeliveryReceipt` whose terminal bounce/complaint/unsubscribe
states drive suppression as a governed side effect. Both intelligence and email
delivery are additive and leave existing fixtures unchanged.

---

## Adoption

Conformance is claimed per implementation and per contract, never globally. At present no implementation claims it (see [Status](#status)).

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

**AGPL-3.0-or-later WITH Commons-Clause** — source-available, not open source.
See [LICENSE.md](LICENSE.md) for the terms and what they permit.

Relicensed from Apache-2.0 on 2026-08-08, and the previous rationale is kept
below because it was correct about the trade-off and the trade-off has not
changed — only which side of it this project has chosen.

> Apache-2.0, deliberately. A contract package has to be importable by every
> implementation that conforms to it, including ones whose licensing is not yet
> decided. AGPL on the schemas would make adopting the wire format a licensing
> decision about the adopter's own code, which is the opposite of what a
> neutral contract is for. The schemas carry no business logic, so there is
> nothing here that copyleft would protect.

That reasoning still holds. Adopting these contracts *is* now a licensing
decision about the adopter's own code, and the word "neutral" in this README's
opening line should be read as application-neutral — it does not describe the
licence. These are canonical **within this runtime family**, not an open
standard anyone may implement commercially.

What changed is the priority: the runtime this package serves is
source-available and non-commercial, and a permissive contract layer under a
copyleft runtime is a gap through which the semantics leave without the terms.

**The licence covers this contract package only.** It does not relicense
implementations, adapters or runtime code by itself — but anything importing
these types to speak the contracts is a work based on this package and takes on
its terms. `LICENSE.md` records the one in-family consequence that follows,
concerning `mission-sdk`'s Apache-2.0 grant.

Reversible, and the maintainers'. It is written down here rather than left
implicit in a file header.

## Credential tenant binding

`authorize_request` denies a credential request unless the request tenant equals the authority principal's
tenant. Empty tenants are denied. An authority with no tenant is not treated as platform-wide: the contracts
define no platform-scope marker, so it is refused for tenant-scoped requests. Expired or unparsable-expiry
authorities are denied. Vectors: `tests/credential_tenant_vectors.json`.
