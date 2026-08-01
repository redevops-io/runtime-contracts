# Release discipline

The package has crossed from design notes into shared infrastructure. From here,
a released hash is a promise.

## Rules

1. **Never rewrite a released golden expected hash.** A consumer that reproduced
   it did so correctly; changing the expectation makes them wrong retroactively
   and there is no way for them to find out.
2. **If canonicalization changes, mint `rcv2`.** Not a silent fixture update. The
   prefix exists precisely so old and new digests can coexist and be told apart.
3. **If a schema changes incompatibly, bump its `schema_version`** — even while
   the package stays on `0.1.x`. Package version and schema version answer
   different questions.
4. **Tag only when the full suite passes**, golden fixtures and canonicalization
   tests included.
5. **A released tag is immutable.** Fix forward.

## What each version means

```
runtime-contracts 0.1.0    the package
rcv1                       the canonicalization rules
context-view/0.1           one schema
```

A schema can move to `0.2` on `rcv1`. A hashing change becomes `rcv2` without
renumbering any schema. Collapsing them would make every schema bump look like a
hashing change.

## Tags

| Tag | Contents |
|---|---|
| `v0.1.0-alpha.1` | Canonicalization, `ArtifactHandle`, `ContextPreviewPlan`, `ContextView`, `RuntimeEvent`, `VerificationResult`, `CapabilityDescriptor`, `MissionProgram`, `InvestigationTransitionEvent`, golden fixtures, Quantify adapter |

## Not yet public

Public release stays behind: stable canonical hashing · one Context Runtime
adapter passing · one RAG adapter passing · Quantify passing · the
inconclusive-Investigation journey passing · a backward-compatibility policy.

Of those, only the last two are met — the journey replays and is pinned as a
golden fixture, and this document is the policy.
