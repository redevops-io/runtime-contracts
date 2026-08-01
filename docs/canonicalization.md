# Canonicalization

Every rule here exists to make one property reproducible rather than
approximately true:

```
same handles + same preview plan + same version pins + same contract version
    = same ContextView hash
```

Across implementations, across process restarts, across languages.

## Decisions

| Question | Decision | Why |
|---|---|---|
| Map key order | Sorted | Insertion order is a property of the builder, not the object |
| Null vs omitted | Identical — nulls dropped | An implementation that sets an optional field to null must not hash differently from one that omits it |
| Floats | **Refused** | Python, Go and JS print different digits for one double. Fractional values are decimal *strings* |
| Sets | **Refused** | No defined order; sort at the point the rule is known |
| Strings | NFC-normalized | An id typed on macOS must hash as one typed on Linux |
| Sequences | Order preserved | Lists mean order; only maps are unordered |
| Handle ordering | Sorted by `(artifact_id, projection, necessity)` | |
| Duplicate handles | **Normalized, not rejected** | Two parts of a plan may legitimately cite one artifact; rejecting pushes dedup into every caller, where some forget |
| Projection | Part of identity | The same artifact at two projections is two planned items |
| Timestamps | Excluded | When something was observed says nothing about what it is |
| Authorization outcomes | **Included** | Two views over one graph that showed different subsets are different views, even when the difference is a redaction |
| Omission counts | **Included** | A view showing a subset without saying so claims a completeness it lacks |
| Materialized content | Via pinned content hash, never bytes | Keeps the canonical form small and still comparable |
| Hash format | `rcv1:<sha256>` | A digest with no rule label is unversionable — nothing distinguishes an old digest from a wrong one |

## What participates in each hash

```
handle_hash   id · type · version · content hash · tenancy · authority · projections
plan_hash     contract version · sorted unique items · budget · omitted count
view_hash     contract version · plan hash inputs · sorted version pins
event_hash    schema version · kind · intent · stream · sequence · lineage ·
              visibility · tenancy · evidence refs · payload
```

Excluded everywhere: ids the emitter chose, clock readings, cost and latency
estimates, free-text reasons. They describe the run, not what the run saw.

## Conformance

A port reproduces [golden/context_view.json](../golden/context_view.json) from
the same inputs. Nine cases, each stating the failure it prevents. Three must
produce an identical hash to the baseline; four must differ.
