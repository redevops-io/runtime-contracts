# Decision Provider Contract

**Contract version:** `decision-provider/v1`

Decision providers are bounded proposal engines. They may score, rank, or select from an already-permitted option set, but they do not authorize actions, perform writes, bypass approvals, or replace independent readback.

The canonical implementation is `runtime_contracts.protocol.decision_provider`.

## Request

`DecisionProviderRequest` records the exact decision question and policy boundary:

- `decision_id`, `tenant_id`, `purpose`
- `question_kind`: `predicate`, `choice`, `score`, or `rubric`
- `evidence_view_ref`: approved context/evidence handle
- `permitted_options`: non-empty, duplicate-free option set supplied by deterministic policy
- `constraints_ref`: immutable policy snapshot
- `as_of`, `known_at`: event time and knowledge cutoff
- `abstain_allowed`
- `latency_budget_ms`, `max_cost`, `data_classification`
- `metadata`

The request identity is the canonical content hash of those fields plus `contract_version`.

## Result

`DecisionProviderResult` records the provider output:

- `decision_id`
- `provider_id`, `model_pin`, optional `calibration_pin`
- `output_kind`
- `option_scores`
- `score_semantics`: `class_prob`, `outcome_prob`, `rank_score`, `utility`, or `rubric_score`
- `selected_option`
- `abstained`, optional `abstain_reason`
- `input_digest`
- `response_digest`
- `uncertainty`, `usage`

## Validation Rules

The conformance suite must reject:

- missing required request identity, policy, evidence, time, tenant, or purpose fields
- empty or duplicate `permitted_options`
- non-positive latency budgets
- result/request `decision_id` mismatch
- `input_digest` mismatch
- missing provider or model pins
- selected options outside `permitted_options`
- scored unknown options
- NaN or infinite scores or uncertainty values
- probabilities outside `[0, 1]`
- `class_prob` scores that do not sum to `1.0`
- abstention when the request disallows it
- abstention without an `abstain_reason`

`outcome_prob` scores are per-option outcome estimates and are not required to sum to one. `rank_score`, `utility`, and `rubric_score` must be read according to their declared semantics, not coerced into probabilities.

## Publication Boundary

A decision-provider result is not an execution receipt. Downstream systems must still enforce policy, approval, idempotent execution, readback, and outcome verification before recording a successful decision episode or policy-learning outcome.
