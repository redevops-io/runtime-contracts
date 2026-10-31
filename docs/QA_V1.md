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

## Clarifications within `qa/v1`

The definitions below were implicit in the code and are now stated. Each is additive: no existing hash, golden case
or vector changes (the proof is in [QA_V1_COMPATIBILITY_REVIEW.md](QA_V1_COMPATIBILITY_REVIEW.md)), and each has
vectors an independent implementation can reproduce from
[`golden/qa_canon_vectors_addendum.json`](../golden/qa_canon_vectors_addendum.json) and
[`golden/qa_clarifications.json`](../golden/qa_clarifications.json).

### The `expected_hash` of a predicate

`expected_hash` is the `rcv1` hash of the canonical form of the predicate, which is the object `{op, expected}`:
`op` is the enum value, `expected` is the frozen expected value, and `expected` is omitted for `EXISTS` and `ABSENT`.
Nothing else of the assertion enters it: not the id, the subject, the verifier, the executor or `requirement_ref`.
Two assertions with the same predicate share an `expected_hash`, and it never equals `assertion_hash`.
`expected` is normalized like any canonical value (NFC strings, decimals as canonical strings, no floats).
`AssertionSpec.expected_hash` is `Predicate.digest`, and an `AssertionResult` repeats it so that a verifier handed a
different expected value is refused (`EXPECTED_MISMATCH`). `EQUALS "Saved"` hashes to
`rcv1:1b995d3503f549f89ae235791af06f1923a99bb30ec7904e2e77921cd2830c80`.

### Value digests and state hashes

A record that carries a digest instead of a value (`ActionRecord.value_digest`, `ObservedValue.value_digest`,
`AssertionResult.actual_digest`) uses one definition: the `rcv1` hash of the canonical JSON text of the value. A
string is hashed after NFC normalization and with its two quote characters, so `"hunter2"` digests the bytes
`"hunter2"`. There is no prefix, salt or domain tag, and the action kind does not enter the digest of an action's
value. `value_digest(str)` and `json_value_digest(any JSON value)` compute it, and `action_value_digest(action)`
gives `ActionRecord.value_digest`: the value digest of a literal value, or the `SecretRef` fingerprint (the `rcv1` hash
of the reference's canonical form, never of the secret) for an action that carries a reference.

`state_before_hash`, `state_after_hash` and `Checkpoint.state_hash` are opaque `rcv1` hashes of whatever the producer
defines as the observable state. `qa/v1` specifies their shape, that they are identity, and one relation: an action
blocked by policy leaves the two hashes of its receipt equal. It does not specify how a producer derives them, so a
consumer compares them only with hashes from the same producer and never recomputes one.

### The idempotency key

The key is per step, not per attempt. Every attempt of one step in one run carries the same `idempotency_key`, so a
target can recognise a replay, and different steps of one run carry different keys. It is an opaque identifier of the
`Ident` shape, it is identity in `ActionReceipt` and `ActionRequest`, and nothing parses it. The sample key
`idem-s1-1` is one producer's spelling: its trailing `1` is part of the string and does not count attempts, and
attempt 2 of the same step carries the same key. A producer SHOULD also make keys differ between runs when the target
is shared. `idempotency_key_violations(receipts)` returns `IDEMPOTENCY_KEY_CHANGED_ACROSS_ATTEMPTS` or
`IDEMPOTENCY_KEY_SHARED_ACROSS_STEPS` for a set of receipts that breaks the rule.

### Ordering of set-valued fields

A set-valued field is sorted before hashing and its listed order is not identity; listing it twice is refused
(`DUPLICATE_ENTRY`). A writer emits a set in canonical order, because `verify_stored_hash` hashes the bytes it is
given and does not sort. The order depends on the field, and it is not one rule:

| Order | Fields |
|---|---|
| By the named key of each element, compared by Unicode code point | `TestSpec.assertions` (`assertion_id`), `TestSpec.fixtures` (`id`), `QAPlan.items` (`spec_ref`), `QAPlan.gates` (`item`), `QAPlan.resource_claims` (`resource`), `RunManifest.versions` (`component`), `assertions_skipped` (`assertion_id`), `step_results` (`step_id`), `assertion_results` (`assertion_id`) |
| By the canonical JSON text of each element, compared by Unicode code point | `FaultDetection.evidence_refs`, `ReviewItem.evidence_refs` |
| By the value: strings by Unicode code point after NFC, enums by member value | `TestSpec.depends_on`, `allowed_side_effects`, `sensitivity_labels`; `QAPlan.lanes`; `PlanGate.after`; `QAPolicyDecision.scope`; `RunManifest.assertions_declared`, `assertions_executed`; `CleanupReport.released`, `leaked`; `Step.permitted_recovery`; `ObserveRequest.capture`; the pins of an embedded `Check.evidence_refs` |

Sorting an object set by its canonical text is wrong for every field in the first row except where the key happens to
be the first key of the element: the canonical text starts with the element's alphabetically first field, which is
`content_hash` for a `FixtureRef`, `budget` for a `PlanItem`, `after` for a `PlanGate`, `amount` for a
`ResourceClaim`, `actual` for an `AssertionResult` and `postcondition` for a `StepResult`. Code point order is not
numeric and not case-folded: `a-1 < a-10 < a-9`, and `B-1` sorts before `a-1`. The ordered fields are `steps`,
`preconditions`, `cleanup`, `seeds`, `fault_events`, `receipts`, `frame_path`, `candidates_rejected_reasons`, a
subject's `inputs` and `subject_alternates`, and the candidates of a `LocateResult`; their listed order is identity.
`Check.evidence_refs` is sorted by the canonical form of `Check` and a pin listed twice is not removed, so a producer
lists each pin once. The addendum holds a case for every object set where the two orders differ, with the hash each
order gives.

### Integrity refusal codes

Every integrity refusal ends the run `INCONCLUSIVE` with reason `ASSERTION_INTEGRITY` and halts the batch. Five codes
were added so that refusals that used to share `ASSERTION_HASH_MISMATCH` can be told apart. `ASSERTION_HASH_MISMATCH`
keeps its meaning: a content hash recomputed from what was handed over differs from the hash it was pinned or
recorded under.

| Code | Raised when | Run outcome |
|---|---|---|
| `ASSERTION_PIN_MALFORMED` | the pinned `assertion_set_hash` is not `rcv1:` and 64 lowercase hex digits | `INCONCLUSIVE(ASSERTION_INTEGRITY)`, batch halts |
| `ASSERTION_PIN_NOT_FOUND` | a well-formed pin names an assertion set the spec store does not hold | same |
| `ASSERTION_PROGRAM_UNREGISTERED` | the check program an assertion names has no registry entry | same |
| `ASSERTION_PROGRAM_MISMATCH` | the registry holds that program under a different hash than the assertion froze | same |
| `BATCH_HALTED` | a call was refused because an earlier integrity refusal halted the batch | same |

The checks run in a fixed order: pin shape, then the store, then the recomputed hash
(`load_pinned_assertion_set`); registry entry, then program hash (`verify_check_program`). The refusal that halts the
batch keeps its own code and `BATCH_HALTED` is what every later call gets; what did not start is skipped with
`HALTED_INTEGRITY`. These refusals happen before an assertion is evaluated, so qa/v1 does not require a manifest for
them: the code, `run_outcome` and `run_reason` travel in the refusal, and the run's `ReviewItem.reason` may name the
specific code. A manifest's `outcome_reason` stays `ASSERTION_INTEGRITY`. `verify_assertion_set` is unchanged and
reports any difference, a malformed pinned value included, as `ASSERTION_HASH_MISMATCH`.

A consumer that does not know a refusal code fails closed. `classify_refusal(code)` returns
`(INCONCLUSIVE, ASSERTION_INTEGRITY)` for every integrity code and for every code it does not know, and `None` for a
known code that is not an integrity refusal. Every code added here maps to that same classification, so a consumer
that predates them reaches the outcome a current one reaches. `IntegrityRefusalCode` lists the vocabulary.

### Recovery reasons

`FaultRecovery.candidates_rejected_reasons` is per candidate: one `CodeToken` for each candidate that was considered
and rejected, in the order they were considered, never more of them than `candidates_considered`. It is an ordered
list, so order and repeats are identity. Its tokens are not a closed vocabulary; a consumer treats an unknown token as
opaque. A recovery that stopped before it considered any candidate has no place in that field for its reason, which is
what `reason_code` is for.

`FaultRecovery.reason_code` is optional, identity, and a closed vocabulary (`RecoveryReason`): why the recovery as a
whole did not recover. It is absent when `result` is `RECOVERED`. An absent value is null and null is dropped, so a
recovery that omits it hashes as it did before the field existed. An unknown value is refused as `UNKNOWN_ENUM_VALUE`
and is non-certifying. The vocabulary is `NO_UI_TARGET`, `NO_ROLE_NAME_ANCHOR`, `RECOVERER_ERROR`,
`CANDIDATE_CAP_EXCEEDED`, `ELAPSED_CAP`, `KILL_SWITCH`, `NO_CANDIDATE`, `AMBIGUOUS_CANDIDATES`, `RECOVERY_DISABLED`,
`BUDGET_EXHAUSTED`, `NOT_PERMITTED`, `NOT_RETRYABLE`, `ALREADY_APPLIED`, `RETRY_UNSAFE`,
`NO_IDEMPOTENCY_OR_POSTCONDITION_GUARD`, `INVALID_INPUT`, `UNKNOWN_SIDE_EFFECT_CLASS` and
`POSTCONDITION_NOT_VERIFIED`.

### Engine limits and kill-switch state

Engine limits (operator caps, recovery limits, per-step attempt ceilings) and kill-switch state are not manifest
fields and are outside `qa/v1` identity. A `RunManifest` that carries a key for them is refused as an unknown field.
The limits a spec grants are in its frozen `Budget`; cost counters are custody (`Counters`, `FaultRecovery.cost`) and
do not change a hash; `resource_limits` records the sandbox limits the run started under. The effect of the kill
switch on one fault is recorded where it happened, as `FaultRecovery.suppressed_reason = KILL_SWITCH` (and
`reason_code = KILL_SWITCH`). The switch's own state, who set it and when, belong to the runner's own records.

## Fixtures and export

| File | Content |
|---|---|
| [`golden/qa.json`](../golden/qa.json) | One case per schema and value type, the hash relations, and the frozen-assertion refusal cases with their expected codes |
| [`golden/qa_canon_vectors.json`](../golden/qa_canon_vectors.json) | Self-contained: canonicalization vectors, every case input with its canonical bytes and SHA-256, and float refusals. An independent implementation of the `rcv1` rules reproduces it without this package |
| [`golden/qa.schema.json`](../golden/qa.schema.json) | JSON Schema (draft 2020-12) generated from the dataclasses |
| [`golden/qa.inventory.json`](../golden/qa.inventory.json) | Field inventory for the additive-only check |
| [`golden/qa_canon_vectors_addendum.json`](../golden/qa_canon_vectors_addendum.json) | Self-contained and additive to `qa_canon_vectors.json`: predicate `expected_hash`, value digests, idempotency receipts, recovery records and the ordering of every set-valued field, with a version note |
| [`golden/qa_clarifications.json`](../golden/qa_clarifications.json) | Refusal and classification fixtures for the added integrity codes, the idempotency-key rule, `reason_code` and the identity boundary |

```bash
python -m golden.qa                                                    # qa.json and qa_canon_vectors.json
python -m runtime_contracts.qa.schema_export golden/qa.schema.json     # JSON Schema
python -m runtime_contracts.qa.inventory golden/qa.inventory.json      # field inventory
python -m golden.qa_clarifications                                 # the two additive fixture files
python -m pytest -q tests/test_qa_golden.py tests/test_qa_refusals.py
```

A released case hash is never rewritten ([RELEASE_DISCIPLINE.md](RELEASE_DISCIPLINE.md)); a new optional field gets new
cases and leaves the old ones unchanged.

## Boundaries

The package imports the standard library only. A harness that executes `qa/v1` runs mirrors the records with its own
plain data and its own `rcv1`-rule canonicalization and imports nothing from this package; it checks itself against
`golden/qa_canon_vectors.json` and `golden/qa_canon_vectors_addendum.json`. It holds no information about how a run is scored or judged from
outside; that lives with the code that scores runs. The leak-guard test fails on a field, enum, schema id, source
word or fixture key from that vocabulary.
