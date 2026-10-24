# runtime-contracts 0.3.x — consolidation plan (#5)

> **✅ COMPLETED — historical design record.** This plan is done: the package is at
> 0.3.0 on the Decimal canonical, the seal semantics were lifted onto it, and
> wealth-manager conforms. Kept for the design rationale (why Decimal won, the
> protocol/domain two-layer boundary), not as pending work. Current status lives in
> [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).

Consolidate the two divergent `runtime-contracts` lines into **one universal
cross-runtime protocol** at 0.3.x: canonical identity/seal, provenance, versioning,
evidence, lineage, verdicts — **not** domain models. Decision taken: the
**Decimal-based** canonicalization wins (it is consistent with wealth-manager's
integer-minor-unit money authority; float `%.12g` is the wrong direction).

## The two lines today

| | **Remote** `redevops-io/runtime-contracts` (`main`, 0.2.4) | **Local** `/mnt/backup/projects/runtime-contracts` (0.3.0, no remote) |
|---|---|---|
| Structure | `canonical.py` + `models/` (protocol/domain split) | flat: `seal.py`, `intent.py`, `evidence.py`, `proposals.py`, `events.py`, `outcomes.py`, `relations.py` |
| Numbers | **Decimal** (`decimal_string`) | float `%.12g` |
| Conformance | "no implementation claims conformance" (proposed) | wealth-manager conforms (via `seal_hash` / `content_hash`) |
| Has the #5 primitives? | yes — `Derivation` (provenance), `replay_ledger`/`replay_states` (lineage), `Verdict`/`VerificationResult` (verdicts), `DecisionEvidence`, `RuntimeEvent`, `CANONICALIZATION_VERSION`/`CONTRACT_VERSION` | partial — seal + evidence + relations, float-hashed |

**They produce different hashes for any numeric payload.** That is the gap #5 closes.

## Target: the 0.3.x surface (home = the remote repo)

`redevops-io/runtime-contracts`, bumped to 0.3.0, with an explicit two-layer boundary:

```
runtime_contracts/
  canonical.py         # PROTOCOL — identity. Decimal canonical, content_hash,
                       #   CANONICALIZATION_VERSION (bump), CONTRACT_VERSION
  protocol/            # PROTOCOL — the universal primitives, domain-neutral:
    seal.py            #   seal semantics (order-independent evidence/unresolved
                       #   sets, provenance excluded from identity) over canonical
    provenance.py      #   source_ref / Derivation chain-of-custody
    versioning.py      #   contract + canonicalization version stamping
    evidence.py        #   DecisionEvidence (protocol shape, not finance)
    lineage.py         #   supersedes / replay_ledger primitives
    verdicts.py        #   Verdict / VerificationResult / Disposition
  models/              # DOMAIN — layered ON TOP, never imported by protocol/:
    intent.py, mission.py, capability.py, …  (may move to a separate dist later)
```

Rule (unchanged governing principle): **contracts define meaning; runtimes
implement one decision.** The protocol layer is what every runtime must agree on
byte-for-byte; models are domain vocabulary that ride on it.

## Migration order (each step independently landable; re-hash contained)

1. **Affirm the Decimal canonical as the protocol identity.** In the remote:
   bump `CANONICALIZATION_VERSION`, freeze `content_hash`/`canonical_json`/
   `decimal_string` as the one identity function, add golden vectors (port the
   local `golden_seal_vectors.json` cases, re-computed under Decimal).
2. **Lift the seal semantics onto the Decimal canonical.** Re-implement the local
   `seal.py` rules (sorted keys, order-independent evidence/unresolved SETS,
   order-significant lists, version-in-hash, provenance excluded) as
   `protocol/seal.py` computing over `canonical_json` — numbers now Decimal.
3. **wealth-manager conforms.** Re-point `contracts.py::_digest` and the
   `content_hash` call sites (`gate.py`, `api/service.py`) from the local
   `seal.py` to `runtime_contracts` 0.3.x. This **re-hashes wealth-manager
   artifacts** (new `content_hash` values). Frozen Phase 2.5 is a separate,
   already-accepted line — its fixture hashes are untouched; the durable dev DB is
   re-seeded. Bump wealth-manager's `PAYLOAD_SCHEMA_VERSION` so old/new hashes are
   never silently compared.
4. **Retire the local float line.** Once wealth-manager is on 0.3.x, archive the
   divergent local `/mnt/backup/projects/runtime-contracts` checkout (wire it to
   the remote or delete it); there is one home again.
5. **redevops-conformance regenerates** its golden fixtures under the Decimal
   canonical (`seal_vectors`, `authorization_chain`, `binding`, `proposal`), and
   the Python runner asserts against 0.3.x. (#6 then adds Go/Kotlin runners on the
   same fixtures.)

## Blast radius (who re-hashes)

- **wealth-manager** — yes (step 3). Contained: 2.5 is frozen/separate; dev DB re-seeded; schema version bumped.
- **RAAAL** — **no**, not in #5. RAAAL keeps its `discovery-runtime` `intent_hash`; it adopts the canonical `runtime_artifact_hash` only at the boundary, via the **dual-identity adapter (#7)**.
- **agentic-os** — audit separately (uses inline contracts per module); not a #5 blocker.
- **redevops-conformance** — fixtures regenerate (step 5); expected.

## Out of scope for #5 (explicit)

- Enabling live Robinhood (held).
- Moving domain `models/` into a separate distribution (note it; do later if wanted).
- RAAAL adopting the canonical hash internally (that is #7's adapter, dual-identity:
  native `intent_hash` + canonical `runtime_artifact_hash`, no IntentField rewrite).

## Rule preserved

All ReDevOps runtimes are **protocol-compliant, not internally model-identical**:
they must agree on the canonical identity + protocol primitives, and may keep
whatever internal domain model they like behind that boundary.
