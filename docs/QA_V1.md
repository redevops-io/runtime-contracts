# QA contracts: `qa/v1`

**Contract family:** `qa/v1` · **schema version:** `0.1` · **hashing:** `rcv1` (unchanged) ·
**code:** `runtime_contracts/qa/`

`qa/v1` is the set of schemas two components need to agree on when one plans a verification, another executes and
records it, and a third reads the record: the test specification, the plan, what was observed and done, what each
assertion read, and the manifest a run ends with. It is types, hashing, fixtures and protocols. It contains no
browser, no adapter implementation, no scheduler and no storage; those belong to the components that implement the
protocols.

Nobody else defines these schemas. A runtime that needs one imports it; it does not keep a copy
([IMPLEMENTATION_SPLIT.md](IMPLEMENTATION_SPLIT.md)).

## What is in it

| Area | Types |
|---|---|
| Specification | `TestSpec`, `Step` (target is a tagged union: `ui` with a `LocatorDescriptor`, or `resource` with a `ResourceRef`), `AssertionSpec`, `FixtureRef`, `Budget` |
| Plan | `QAPlan` (static lanes, gates, `coverage_contract`) |
| Run records | `Observation`, `ActionReceipt`, `QAPolicyDecision`, `AssertionResult`, `ObservedValue`, `Checkpoint`, `ReviewItem`, `ReviewRecord`, `CleanupReport` |
| Faults | `FaultEvent` holding a `FaultDetection` and a `FaultRecovery` |
| Run | `RunManifest` |
| Recovery | `LocatorCandidate`, the only thing recovery may express |
| Protocols | `QAAdapter` (`qa-adapter/1`), `CheckAdapter` (`qa-check-adapter/1`), `BlobStore`, `Redactor`, and the typed errors they raise |
| Vocabulary | `Outcome` and `outcome_to_verdict`, which maps the run outcomes onto the existing `Verdict` |

Existing contracts are reused, not duplicated: `Verdict`, `Determinism`, `Check` (embedded in `AssertionResult`),
`SideEffect`, `Idempotency`, `RetrySafety`, `EvidenceRef` and `SecretRef`.

## Identity and custody

What a record says enters its `rcv1` hash. Who, when and how long (timestamps, durations, reviewer, cost counters,
free-text rationale) are custody and do not. Durations are integer milliseconds, money is a decimal string and floats
are refused. Order-independent sequences (assertions, fixtures, skipped assertions, enum sets) are sorted before
hashing; ordered ones (steps, locator frame paths, seeds) are not. An absent optional field is null and null is
dropped, so adding an optional field never changes the hash of an object that omits it.

Every independently addressed record carries `schema_id` (`runtime-contracts/qa/<name>`) and `schema_version` in its
hashed form. `to_json()` writes identity, a `custody` object and `content_hash`; `from_json()` refuses an unknown
key, an unknown schema id or version, an unknown enum value and a stored hash that does not match.

## The frozen-assertion rule

A run's expected results are fixed before the first adapter call and cannot be changed by any component during the
run. A change to an assertion is a new `TestSpec` version with a new hash, and it needs two named approvals.

The types enforce this:

- `AssertionSpec` and everything in it are frozen dataclasses over tuples and an immutable mapping. There is no method
  that returns an edited assertion.
- An assertion is referenced by the `rcv1` hash of its whole content, and a spec's set by `assertion_set_hash`. Both
  are recomputed from content on every read. `verify_assertion_set(assertions, pinned_hash)` refuses on any difference.
- `executor` (`PLAYWRIGHT` or `SCRIPT`) is required and hashed. `requirement_ref` is optional and hashed. For
  `SCRIPT`, `check_program_ref` pins the registered program by the full sha256 of its source.
- `determinism` is `DETERMINISTIC` and `on_unresolvable` is `INDETERMINATE`, both fixed. An unresolved or ambiguous
  subject is never healed and never a pass. Healing applies to step targets only.
- `assert_` and `run_check` take a subject and return an `ObservedValue`. They have no expected parameter and no
  verdict in the return type. The verifier compares.
- A recovery payload is parsed into `LocatorCandidate`. Any other key, an `expected` value or an assertion object
  included, is refused as `ASSERTION_INTEGRITY`.

Every integrity refusal ends the run as `INCONCLUSIVE` with reason `ASSERTION_INTEGRITY`. A `SCRIPT` assertion with
no `check_program_ref` is an invalid spec (`CHECK_PROGRAM_REF_REQUIRED`), which classifies as `TEST_DEFECT`; a program
hash that no longer matches the pinned assertion set is refused before execution as an integrity violation.

## Assertion accounting

`RunManifest` carries `assertions_declared`, `assertions_executed` and `assertions_skipped` (each skip with a
`reason_code`). `declared` equals `executed` union `skipped`, and the two are disjoint. A manifest that breaks this
can only be recorded as `INCONCLUSIVE(ASSERTION_INTEGRITY)`. A `PASS` requires every declared assertion executed and
passed deterministically, nothing skipped, every step satisfied and every detected fault recovered by its own
postcondition.

## Detection and recovery

A `FaultEvent` holds two records written in order. The `FaultDetection` is hashed first. The `FaultRecovery` that
follows names it by hash (`detection_ref`) and is judged by the step's own postcondition, not by how the run ended.
A false alarm, a miss, a mis-recovery and a suppressed recovery are all representable because each field stands alone.

## Plans

A planner emits a `QAPlan` as this data and the runner reads it as data; neither imports the other's code. `QAPlan` is
fully resolved and declarative: items in static lanes, gates, `max_parallel`, resource claims and a
planner. It has no field for work stealing, re-planning or dependency resolution, and `from_json` refuses unknown
keys. `coverage_contract` is `FULL`. `SUBSET` is a reserved value that every validator rejects with
`UNSUPPORTED_COVERAGE_CONTRACT`. A plan whose lane order and gates could never start is refused.

## Compatibility

Within `qa/v1` changes are additive only: new optional fields, new schemas, and new enum members that consumers treat
as non-certifying when unknown. Removing, renaming or retyping a field, making an optional field required, moving a
field between identity and custody, removing an enum member or changing a protocol is a `qa/v2` change. A
canonicalization change would mint `rcv2`. Consumers pin an exact tag and refuse an unknown major. A reader older than
a writer within a major checks a received record with `verify_stored_hash`, which recomputes over the bytes it received.

`golden/qa.inventory.json` is the committed field inventory and `tests/test_qa_additive_only.py` fails on any
non-additive difference.

## Fixtures and export

| File | Content |
|---|---|
| [`golden/qa.json`](../golden/qa.json) | One case per schema and value type, the hash relations, and the frozen-assertion refusal cases with their expected codes |
| [`golden/qa_canon_vectors.json`](../golden/qa_canon_vectors.json) | Self-contained: canonicalization vectors, every case input with its canonical bytes and SHA-256, and float refusals. An independent implementation of the `rcv1` rules reproduces it without this package |
| [`golden/qa.schema.json`](../golden/qa.schema.json) | JSON Schema (draft 2020-12) generated from the dataclasses |
| [`golden/qa.inventory.json`](../golden/qa.inventory.json) | Field inventory for the additive-only check |

```bash
python -m golden.qa                                                    # qa.json and qa_canon_vectors.json
python -m runtime_contracts.qa.schema_export golden/qa.schema.json     # JSON Schema
python -m runtime_contracts.qa.inventory golden/qa.inventory.json      # field inventory
python -m pytest -q tests/test_qa_golden.py tests/test_qa_refusals.py
```

A released case hash is never rewritten ([RELEASE_DISCIPLINE.md](RELEASE_DISCIPLINE.md)); a new optional field gets new
cases and leaves the old ones unchanged.

## Boundaries

The package imports the standard library only. A harness that executes `qa/v1` runs mirrors the records with its own
plain data and its own `rcv1`-rule canonicalization and imports nothing from this package; it checks itself against
`golden/qa_canon_vectors.json`. It holds no information about how a run is scored or judged from
outside; that lives with the code that scores runs. The leak-guard test fails on a field, enum, schema id, source
word or fixture key from that vocabulary.
