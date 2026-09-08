# RuntimeDigest — the one identity protocol behind the many hashes

The runtime has several integrity mechanisms — evidence identity, intent identity, event identity,
execution binding, authority chaining, context-view identity, artifact seals, audit-ledger chains,
per-tenant persistence envelopes. They look separate. They are all instances of **one protocol**, and
naming it makes the relationships — and the rules — explicit.

```
                         Runtime Identity
                                │
            canonicalize + domain + version
                                │
                             digest
                                │
     ┌───────────┬─────────────┼─────────────┬────────────┐
     ▼           ▼             ▼             ▼            ▼
  Evidence    Intent        Context        Event      Execution
  identity   identity      identity      identity      binding
```

This is a **protocol, not a base class.** There is deliberately no `RuntimeDigest` object every
subsystem must import — that would couple the planes and fight the functional-core boundaries. What is
shared is the *rule* below and the one canonicalization function ([`canonical.py`](../runtime_contracts/canonical.py)).

## The rule

Every runtime identity is:

```
RuntimeDigest :=
    algorithm                 # sha256
    canonicalization_version  # rcv1  (see canonicalization.md)
    semantic_domain           # what KIND of thing this identifies (evidence / intent / event / …)
    schema_version            # the version of that thing's schema
    canonical_bytes           # canonicalize(payload) under canonicalization_version
```

The digest string is `<canonicalization_version>:<sha256(canonical_bytes)>` — e.g. `rcv1:9f8e…`. The
`rcv1:` prefix already carries `algorithm` (implicitly) and `canonicalization_version`; the
`semantic_domain` and `schema_version` MUST travel with the digest — either folded into the hashed
`canonical_form` (as `RuntimeEvent` and `VerifiedIntent` do with `schema_id`/`schema_version`) or, for
a digest whose body cannot be extended without a migration, as **clear sidecar metadata** beside the
digest (as the persistence envelope does). A bare `sha256(json)` with no version and no domain is the
one shape to avoid: it cannot say how it was produced, so it cannot be replayed or cross-checked years
later.

## Two tiers, deliberately

Not every digest is meant to be reproduced in another language. Distinguish them, and label which is
which:

**Tier 1 — cross-language contract identity.** Produced under `rcv1`, byte-identical across the Python,
Go and Kotlin implementations, and covered by the [conformance suite](https://github.com/redevops-io/redevops-conformance)
(the golden fixtures + the CI gate). These are the identities that cross a boundary — an evidence
object, a verified intent, a runtime event, an execution binding, a context view. If two independent
implementations produce the same fixture's digest, they agree on the *protocol*, not on a shared bug.

**Tier 2 — domain-internal integrity / replay digests.** Byte-stable *within* one runtime, but not
required to reproduce in another, because nothing consumes them across languages. They still follow the
protocol (algorithm · canonicalization · domain · version), but they may deviate from `rcv1` for a
documented reason. Current members:

- **`plan_fingerprint` / mission `ContextView` id** ([`agentic_os/mission/context_view.py`](https://github.com/redevops-io/agentic-os)):
  a truncated `sha256[:16]` over joined parts. It is the anchor of **exact-replay** — a recompiled
  plan must reproduce the *sealed* fingerprint or replay fails closed. Byte-stability is the whole
  point; it is not an `rcv1` contract identity and does not cross a language boundary.
- **`AccessLedger` / `ProvenanceLedger` chain hashes** (enterprise): each entry's hash covers the
  previous one for tamper-evidence *where it is written*. Deliberately self-verifying per runtime (a
  ledger is re-verified in place, never reproduced elsewhere), so it is not held to cross-language
  parity.
- **persistence-envelope digest** (enterprise `persistence_encryption.py`): a tolerant
  `sha256(sorted-compact-json)` over arbitrary event payloads that may carry floats — which strict
  `rcv1` deliberately refuses — used for at-rest integrity + dedup. Tagged with
  `semantic_domain = "persistence-envelope"` so it never masquerades as an `rcv1` contract hash.

The distinction is the point: Tier 1 earns the "one protocol, many languages" claim; Tier 2 is honest
about being local. What is *not* acceptable is a Tier-2 digest that looks like a Tier-1 one (a bare
`rcv1:`-less, domain-less `sha256`) — a reader cannot tell which guarantees it carries.

## Changing a sealed digest is a versioned migration, never a silent edit

A Tier-2 digest anchors sealed/persisted artifacts (a sealed plan fingerprint, a persisted ledger
chain). Changing its rule — even an improvement, such as routing a ledger entry through `rcv1` to drop
a fragile float timestamp — **changes the value**, which breaks exact-replay of existing sealed plans
and `verify_chain()` on existing ledgers. Such a change MUST be a deliberate migration: stamp new
artifacts with a new digest version, verify old artifacts under the old rule, and never retroactively
reinterpret a value that was sealed under a different rule. This is why the known Tier-2 quirks
(the 16-hex truncation; the float in a ledger entry) are documented here rather than quietly "fixed" —
each is a migration to schedule, not a bug to patch.

## For a new digest

1. Pick the `semantic_domain` (what kind of thing).
2. Default to `rcv1` (Tier 1) so it is cross-language and conformance-testable. Choose Tier 2 only with
   a documented reason (byte-stable replay anchor; arbitrary float-bearing bodies; a per-runtime chain).
3. Make it self-describing: fold `schema_id`/`schema_version` into `canonical_form`, or carry the
   tuple as clear sidecar metadata.
4. If Tier 1, add a golden fixture to the conformance suite so all three implementations must reproduce
   it.

## See also

- [`canonicalization.md`](canonicalization.md) — the `rcv1` rules the digest bytes are produced under.
- The conformance suite — golden fixtures + the CI drift gate that pins `runtime-contracts` and runs
  the Python / Go / Kotlin re-derivations.
- Mission EXPLAIN `interpreted_under` / `GET /buildinfo` — every answer records the
  `runtime_contracts_version · canonicalization_version · schema_version` it was interpreted under, so a
  digest read years later can be tied to the exact rules that produced it.
