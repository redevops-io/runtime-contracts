# `qa/v1` compatibility review: clarifications

**Scope:** additions to the `qa/v1` interface made after its fixtures were first published, at commit
`13e00f23da74782af091aec607c47358e9814fc6`. **Result:** additive. No existing hash, golden case or vector changes.
These clarifications are released in `v0.3.16`; the fixtures they follow were first released in `v0.3.15`.

## What changed

| Area | Change | Kind |
|---|---|---|
| Predicate `expected_hash` | Defined: `rcv1` of the canonical form of `{op, expected}`. Code unchanged | documentation, vectors |
| Value digests, state hashes | Value digest defined (`rcv1` of the canonical JSON text of the value). `json_value_digest` and `action_value_digest` added; state hashes stated as opaque | documentation, two functions, vectors |
| Idempotency key | Defined as per step. `idempotency_key_violations` added | documentation, one function, vectors |
| Set ordering | The ordering rule of every set-valued field stated; the two orders (element key, canonical text) pinned where they differ | documentation, vectors |
| Integrity refusal codes | Five codes added: `ASSERTION_PROGRAM_MISMATCH`, `ASSERTION_PROGRAM_UNREGISTERED`, `ASSERTION_PIN_NOT_FOUND`, `ASSERTION_PIN_MALFORMED`, `BATCH_HALTED`. New enum `IntegrityRefusalCode`; functions `classify_refusal`, `refusal_halts_batch`, `verify_pin_well_formed`, `load_pinned_assertion_set`, `verify_check_program`, `check_batch_not_halted` | new enum, new functions, new `Code` constants |
| Recovery reason | New optional identity field `FaultRecovery.reason_code` and new closed enum `RecoveryReason`; `candidates_rejected_reasons` documented | one optional field, new enum |
| Engine limits, kill switch | Stated as outside `qa/v1` identity; tested | documentation, tests |

Files added: `golden/qa_canon_vectors_addendum.json`, `golden/qa_clarifications.json`, `golden/qa_clarifications.py`,
`tests/test_qa_clarifications.py`, `docs/QA_V1_COMPATIBILITY_REVIEW.md`. Files changed: `golden/qa.schema.json` and
`golden/qa.inventory.json` (additions only, below), `runtime_contracts/qa/{__init__,base,enums,fault,integrity,records}.py`,
`docs/QA_V1.md`, `CHANGELOG.md`, `STATUS.md`.

## Why it is additive

- **Canonicalization is `rcv1`, unchanged.** `runtime_contracts/canonical.py` is not touched.
- **No existing field changes type, requirement or identity status.** The only new record field is
  `FaultRecovery.reason_code`: optional, identity, default null. An absent optional field is null and null is dropped
  before hashing, so every `FaultRecovery` and `FaultEvent` that omits it hashes exactly as it did.
- **New enums are not the type of any existing field.** `IntegrityRefusalCode` is not the type of any field.
  `RecoveryReason` is the type of the new optional field only. No existing enum gains or loses a member.
- **No existing function changes behaviour.** `verify_assertion_set`, `check_result_matches_assertion`,
  `verify_manifest_against_spec`, `classify_coverage` and `integrity_violations` return and raise what they did,
  codes included. `value_digest` is unchanged; its docstring is expanded.
- **The new refusal codes map to the outcome the original text already gives.** They end a run
  `INCONCLUSIVE(ASSERTION_INTEGRITY)` and halt the batch, as every integrity refusal does. A consumer that does not
  know a new code treats it as an unknown code, which is the same classification, so adding a code cannot change a
  run outcome anywhere.
- **Older readers fail closed on the one new field.** A reader that predates `reason_code` refuses a record that
  carries it as an unknown field (`UNKNOWN_FIELD`), or checks it from its bytes with `verify_stored_hash`. A record
  that omits it is read exactly as before.
- **Nothing is renamed, removed, retyped, made required or moved between identity and custody.** The additive-only
  checker confirms it (below).
- **Protocols and API versions are unchanged** (`qa-adapter/1`, `qa-check-adapter/1`).

## Proof that existing fixtures are byte-identical

| File | sha256 before | sha256 after | Status |
|---|---|---|---|
| `golden/qa.json` | `2aaed7aace5b9952ef56f43f73edc1745a15da4d1f83db92c7aad5af279bf5e1` | `2aaed7aace5b9952ef56f43f73edc1745a15da4d1f83db92c7aad5af279bf5e1` | unchanged |
| `golden/qa_canon_vectors.json` | `7241c570746a63e75431591b88e42562f6604fc2a8586474a267eedb51908a13` | `7241c570746a63e75431591b88e42562f6604fc2a8586474a267eedb51908a13` | unchanged (97 vectors, 3 refusals) |
| `golden/context_view.json`, `geospatial.json`, `investigation_lifecycle.json`, `security.json` | n/a | n/a | unchanged (no diff against the earlier commit) |
| `golden/qa.schema.json` | `8d61738f488ddca2cad6a0eebd688f1d1fa2d5f2b1b7fd3904b97f93abc0cb22` | `ce1146529e2d3e31ff89083dea11f6cc2719c872c2a653a640976ecd485855c4` | additions only |
| `golden/qa.inventory.json` | `8ebd0be1488233966ba66dc2cbb7c46b42ec3973a246f405e905130a4d28ba57` | `ce8709f40642be7513bd5a80dbd8711acd1f56cce61b3403bada3ec3b5179c6e` | additions only |

New files: `golden/qa_canon_vectors_addendum.json` (`c2f5faf7c132c4cdeb14a6708676a4167ddfbd5e60ccfdb96ebe4612f72564d8`) and
`golden/qa_clarifications.json` (`a486ffcb0117e1cbb72600da1404761ac718f3d07df750db97bfa31bd88f9a3e`).

`tests/test_qa_clarifications.py` pins the two unchanged hashes, compares both files to the earlier commit byte for
byte where that commit is visible, and rebuilds every case of `golden/qa.json` from the models to confirm each still
hashes to its stored value. `tests/test_qa_released_goldens.py` and `tests/test_qa_golden.py` pass unchanged.

### The exact change to `golden/qa.schema.json`

`40 insertions, 0 deletions`:

```diff
@@ -874,2 +874,5 @@
         },
+        "reason_code": {
+          "$ref": "#/$defs/RecoveryReason"
+        },
         "result": {
@@ -942,2 +945,17 @@
     },
+    "IntegrityRefusalCode": {
+      "enum": [
+        "ASSERTION_INTEGRITY",
+        "ASSERTION_HASH_MISMATCH",
+        "EXECUTOR_MISMATCH",
+        "EXPECTED_MISMATCH",
+        "RECOVERY_PAYLOAD_REJECTED",
+        "COVERAGE_VIOLATION",
+        "ASSERTION_PROGRAM_MISMATCH",
+        "ASSERTION_PROGRAM_UNREGISTERED",
+        "ASSERTION_PIN_NOT_FOUND",
+        "ASSERTION_PIN_MALFORMED",
+        "BATCH_HALTED"
+      ]
+    },
     "LocateCandidate": {
@@ -1613,2 +1631,24 @@
     },
+    "RecoveryReason": {
+      "enum": [
+        "NO_UI_TARGET",
+        "NO_ROLE_NAME_ANCHOR",
+        "RECOVERER_ERROR",
+        "CANDIDATE_CAP_EXCEEDED",
+        "ELAPSED_CAP",
+        "KILL_SWITCH",
+        "NO_CANDIDATE",
+        "AMBIGUOUS_CANDIDATES",
+        "RECOVERY_DISABLED",
+        "BUDGET_EXHAUSTED",
+        "NOT_PERMITTED",
+        "NOT_RETRYABLE",
+        "ALREADY_APPLIED",
+        "RETRY_UNSAFE",
+        "NO_IDEMPOTENCY_OR_POSTCONDITION_GUARD",
+        "INVALID_INPUT",
+        "UNKNOWN_SIDE_EFFECT_CLASS",
+        "POSTCONDITION_NOT_VERIFIED"
+      ]
+    },
     "RecoveryResult": {
```

### The exact change to `golden/qa.inventory.json`

`38 insertions, 0 deletions`:

```diff
@@ -93,2 +93,15 @@
     ],
+    "IntegrityRefusalCode": [
+      "ASSERTION_INTEGRITY",
+      "ASSERTION_HASH_MISMATCH",
+      "EXECUTOR_MISMATCH",
+      "EXPECTED_MISMATCH",
+      "RECOVERY_PAYLOAD_REJECTED",
+      "COVERAGE_VIOLATION",
+      "ASSERTION_PROGRAM_MISMATCH",
+      "ASSERTION_PROGRAM_UNREGISTERED",
+      "ASSERTION_PIN_NOT_FOUND",
+      "ASSERTION_PIN_MALFORMED",
+      "BATCH_HALTED"
+    ],
     "LocateMode": [
@@ -140,2 +153,22 @@
     ],
+    "RecoveryReason": [
+      "NO_UI_TARGET",
+      "NO_ROLE_NAME_ANCHOR",
+      "RECOVERER_ERROR",
+      "CANDIDATE_CAP_EXCEEDED",
+      "ELAPSED_CAP",
+      "KILL_SWITCH",
+      "NO_CANDIDATE",
+      "AMBIGUOUS_CANDIDATES",
+      "RECOVERY_DISABLED",
+      "BUDGET_EXHAUSTED",
+      "NOT_PERMITTED",
+      "NOT_RETRYABLE",
+      "ALREADY_APPLIED",
+      "RETRY_UNSAFE",
+      "NO_IDEMPOTENCY_OR_POSTCONDITION_GUARD",
+      "INVALID_INPUT",
+      "UNKNOWN_SIDE_EFFECT_CLASS",
+      "POSTCONDITION_NOT_VERIFIED"
+    ],
     "RecoveryResult": [
@@ -780,2 +813,7 @@
         },
+        "reason_code": {
+          "custody": false,
+          "required": false,
+          "type": "Optional[RecoveryReason]"
+        },
         "result": {
```

### The additive-only checker

`runtime_contracts.qa.inventory.breaking_changes(old, new)` compares the inventory at the earlier commit with the
current one and returns `[]`. It reports a removed, renamed or retyped field, a field made required or moved between
identity and custody, a removed enum member and a changed protocol or API version; none is present. The same check
runs in `tests/test_qa_additive_only.py` against the committed inventory, and `tests/test_qa_clarifications.py`
runs it against the inventory of the earlier commit.

## Consumer guidance

- **Pin an exact tag and refuse an unknown major.** The contract family stays `qa/v1`; `schema_version` stays `0.1`.
- **Fail closed on an unknown refusal code.** Classify it `INCONCLUSIVE(ASSERTION_INTEGRITY)`, halt the batch, never
  report it as a pass and never skip it. `classify_refusal(code)` does this and returns `None` only for a code the
  consumer knows is not an integrity refusal.
- **Fail closed on an unknown enum value.** An unknown `reason_code` is `UNKNOWN_ENUM_VALUE` and non-certifying, like
  every other closed vocabulary.
- **Do not parse an idempotency key or a state hash.** Both are opaque. Compare state hashes only with hashes from
  the same producer.
- **Sort a set field by its own rule.** The rule is per field (element key, canonical JSON text, or value) and is
  listed in [QA_V1.md](QA_V1.md); sorting every object set by its canonical text gives another hash for
  `fixtures`, `assertion_results`, `step_results` and the sets of a plan. Check an implementation against the
  `set_ordering` section of `golden/qa_canon_vectors_addendum.json`.
- **Emit a set in canonical order.** `verify_stored_hash` hashes the bytes it receives and does not sort.
- **Read `golden/qa.json` and `golden/qa_canon_vectors.json` as before.** The addendum extends them and never edits an
  entry; its `extends.sha256` names the base file it was written against.

## Definitions: an independent implementation against the normative text

An independent implementation (the agent harness) derived the following where the earlier text was silent. This is
how each compares with the normative definition in [QA_V1.md](QA_V1.md).

| Item | Independent implementation derived | Normative definition | Result | What the implementation does |
|---|---|---|---|---|
| Predicate `expected_hash` | `rcv1` spelling of the `canon-v1` hash of the predicate's `{op, expected}` | `rcv1` of the canonical form of `{op, expected}`; `EXISTS` and `ABSENT` hash `{op}` | Same | Nothing |
| State hash | `canon-v1` hash of a `qa-state/1` form of the observation (URL, frame, DOM metadata, snapshot and screenshot digests); a distinct hash for an unobserved state | Opaque `rcv1`, identity, equal on a blocked action; derivation is the producer's | Compatible: the derivation is the producer's to define | Nothing; compare only within the producer |
| Value digest | `canon-v1` hash of `{"action_value": {value or secret_ref}, "kind": kind}` | `rcv1` of the canonical JSON text of the value alone; for a `SecretRef`, its fingerprint; the kind does not enter | **Differs** | Use `value_digest` / `action_value_digest`: hash the value itself, with no wrapper and no kind |
| Idempotency key | `idem-` plus 40 hex digits of the `canon-v1` hash of `{run_id, step_id}`: one key per step, shared by its attempts | Per step: the same key for every attempt of a step in a run, different keys for different steps; opaque; spelling is the producer's | Same rule | Nothing; the spelling stays the producer's |
| Order of object sets | Object sets sorted by the canonical JSON text of the element | By the named key for `assertions`, `fixtures`, `versions`, `assertions_skipped`, `step_results`, `assertion_results` and the sets of a plan; by canonical text only for `evidence_refs`; by value for string and enum sets | **Differs** for `fixtures`, `step_results`, `assertion_results` and the plan sets (the same for the others) | Sort each set field by its rule, as in the table in QA_V1.md |
| Scalar sets | NFC strings and enum values, in order | Unicode code point after NFC; enum member value | Same | Nothing |
| Integrity refusal codes | One code, `ASSERTION_HASH_MISMATCH`, for a malformed pin, an unknown pin, a program that differs and an unregistered program; `BATCH_HALTED` as an implementation-only code | `ASSERTION_PIN_MALFORMED`, `ASSERTION_PIN_NOT_FOUND`, `ASSERTION_PROGRAM_MISMATCH`, `ASSERTION_PROGRAM_UNREGISTERED`, `BATCH_HALTED`; `ASSERTION_HASH_MISMATCH` only for a recomputed content hash that differs | **Differs**: the vocabulary is finer | Raise the distinct codes; all map to `INCONCLUSIVE(ASSERTION_INTEGRITY)` as before |
| A pin outside the approved lineage | `ASSERTION_HASH_MISMATCH` | Not defined here: approval lineage is not part of `qa/v1` | Open | Keep the code it uses; a distinct code would be a further addition |
| Recovery-failure reasons | Reason codes in `candidates_rejected_reasons` | `candidates_rejected_reasons` is per candidate (at most one per candidate considered); `reason_code` (closed vocabulary) says why the recovery as a whole did not recover | **Differs** for reasons that arise with no candidate considered | Record those in `reason_code` |
| Engine limits, kill switch | Runner configuration, not manifest fields | Not manifest fields and not identity; the effect of the switch is `suppressed_reason = KILL_SWITCH` | Same | Nothing |

## Commands

```bash
python -m pytest -q
python scripts/docs_check.py
python -m golden.qa_clarifications        # writes the two additive fixture files
python -m runtime_contracts.qa.schema_export golden/qa.schema.json
python -m runtime_contracts.qa.inventory golden/qa.inventory.json
```
