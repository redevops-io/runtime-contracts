"""Deterministic ``qa/v1`` sample objects, shared by the golden generator and the tests.

No clocks and no randomness: every value is fixed, so a hash computed from these objects is the same everywhere.
The golden generator (``golden/qa.py``) and the unit tests build from here so that a test and a fixture can never
describe two different objects under one name.
"""
from __future__ import annotations

from typing import Optional

from runtime_contracts.models.capability import Idempotency, RetrySafety, SideEffect
from runtime_contracts.models.verification import Check, Determinism, Verdict
from runtime_contracts.protocol.evidence import EvidenceRef
from runtime_contracts.qa import (Action, ActionKind, ActionReceipt, ActionRecord, AssertionResult, AssertionSpec,
                                  AssertionSubject, Budget, Checkpoint, CheckProgramRef, ClaimedClass,
                                  CleanupReport, ComponentRef, CoverageContract, Counters, EvidenceLevel, Executor,
                                  FaultDetection, FaultEvent, FaultRecovery, FaultSignal, FixtureRef,
                                  LocatorCandidate, LocatorDescriptor, LocatorStrategy, LocatorUsed, ModelRef,
                                  Observation, ObservationSource, ObservedValue, Outcome, PermittedRecovery, Phase,
                                  PlanGate, PlanItem, PolicyDecisionKind, Postcondition, PostconditionResult,
                                  Predicate, PredicateOp, QAPlan, QAPolicyDecision, RecoveryCost, RecoveryResult,
                                  RecoveryStrategy, Resolution, ResourceClaim, ResourceKind, ResourceRef,
                                  ResultCode, ReviewDecision, ReviewItem, ReviewRecord, RunManifest,
                                  SkippedAssertion, SkipReason, Step, StepResult, StepTarget, SubjectKind,
                                  SuppressedReason, TestSpec, TestTarget, ToolRef, VersionPin)


def h(n: int) -> str:
    """A fixed, well-formed ``rcv1`` hash for placeholders."""
    return f"rcv1:{n:064x}"


def d(n: int) -> str:
    """A fixed, well-formed ``sha256:`` digest for placeholders."""
    return f"sha256:{n:064x}"


PLANNER = ComponentRef(id="cr-qa-planner", version="0.1.0")


def ui_assertion(assertion_id: str = "a-saved", *, expected="Saved", executor: Executor = Executor.PLAYWRIGHT,
                 requirement_ref: Optional[str] = "REQ-SAVE-1", test_id: str = "save-status",
                 op: PredicateOp = PredicateOp.EQUALS) -> AssertionSpec:
    return AssertionSpec(
        assertion_id=assertion_id, executor=executor,
        subject=AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(test_id=test_id)),
        predicate=Predicate(op, expected), verifier_id="det-verifier", verifier_version_range=">=1.0,<2",
        requirement_ref=requirement_ref)


def url_assertion(assertion_id: str = "a-url") -> AssertionSpec:
    return AssertionSpec(
        assertion_id=assertion_id, executor=Executor.PLAYWRIGHT,
        subject=AssertionSubject(kind=SubjectKind.URL, pattern="/saved$"),
        predicate=Predicate(PredicateOp.MATCHES, "/saved$"), verifier_id="det-verifier",
        verifier_version_range=">=1.0,<2")


def script_assertion(assertion_id: str = "a-image-pinned", *, program_hash: str = None,
                     requirement_ref: Optional[str] = "REQ-IMG-1") -> AssertionSpec:
    """A SCRIPT assertion over an image digest, evaluated by a registered check program."""
    return AssertionSpec(
        assertion_id=assertion_id, executor=Executor.SCRIPT,
        subject=AssertionSubject(kind=SubjectKind.RESOURCE_INPUTS,
                                 inputs=(ResourceRef(kind=ResourceKind.IMAGE_DIGEST, digest=d(5)),)),
        predicate=Predicate(PredicateOp.EQUALS, "pinned"), verifier_id="det-verifier",
        verifier_version_range=">=1.0,<2", requirement_ref=requirement_ref,
        check_program_ref=CheckProgramRef(id="image-pinned", version="1.0.0", program_hash=program_hash or d(6)))


def ui_step(step_id: str = "s1", *, name: str = "Save") -> Step:
    return Step(
        step_id=step_id, intent="Save the form", target=StepTarget.ui(LocatorDescriptor(role="button", name=name)),
        action=Action(ActionKind.CLICK), expected_transition="url ends /saved", observation_deadline_ms=5000,
        side_effect=SideEffect.WRITES_INTERNAL, idempotency=Idempotency.AT_MOST_ONCE,
        retry_safety=RetrySafety.UNSAFE,
        permitted_recovery=(PermittedRecovery.SEMANTIC_LOCATOR, PermittedRecovery.CHECKPOINT_RESUME))


def resource_step(step_id: str = "r1") -> Step:
    return Step(
        step_id=step_id, intent="Resolve the deployment manifest",
        target=StepTarget.for_resource(ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="k8s/deploy.yaml")),
        action=Action(ActionKind.RESOLVE), expected_transition="manifest resolves to a content digest",
        observation_deadline_ms=2000, side_effect=SideEffect.NONE, idempotency=Idempotency.IDEMPOTENT,
        retry_safety=RetrySafety.SAFE, permitted_recovery=(PermittedRecovery.RETRY_SAME,))


def ui_spec(spec_id: str = "checkout-save", version: int = 1, *, assertions=None, author: Optional[str] = "author-1",
            **overrides) -> TestSpec:
    kwargs = dict(
        id=spec_id, version=version, target=TestTarget(app_id="demo-app", build_sha="0123456789abcdef",
                                                      environment_profile="ci-baseline"),
        steps=(ui_step(),), assertions=assertions if assertions is not None else (ui_assertion(), url_assertion()),
        budget=Budget(deadline_ms=120000, max_retries=1, max_recovery_attempts=2),
        egress_profile="operator-default", preconditions=("user is signed in",),
        fixtures=(FixtureRef(id="seed-form", content_hash=d(7)),), allowed_side_effects=(SideEffect.WRITES_INTERNAL,),
        cleanup=("reset form fixture",), sensitivity_labels=("internal",), author=author)
    kwargs.update(overrides)
    return TestSpec(**kwargs)


def plan_for(refs, *, coverage=CoverageContract.FULL, **overrides) -> QAPlan:
    refs = list(refs)
    kwargs = dict(
        items=tuple(PlanItem(spec_ref=r, lane="lane-a" if i % 2 == 0 else "lane-b", order=i // 2,
                             budget=Budget(deadline_ms=120000, max_recovery_attempts=2), recovery_ceiling=2,
                             evidence_level=EvidenceLevel.STANDARD) for i, r in enumerate(refs)),
        lanes=("lane-a", "lane-b"), max_parallel=2, coverage_contract=coverage, planner=PLANNER,
        gates=(PlanGate(item=refs[1], after=(refs[0],)),) if len(refs) > 1 else (),
        resource_claims=(ResourceClaim(resource="browser_slots", amount=2),), action_policy_ref=h(9),
        rationale_ref=d(10))
    kwargs.update(overrides)
    return QAPlan(**kwargs)


# ── run records ────────────────────────────────────────────────────────────────────────────────────────────


ADAPTER = ComponentRef(id="qa-playwright", version="0.1.0")
VERIFIER = ComponentRef(id="det-verifier", version="1.0.0")
DETECTOR = ComponentRef(id="step-detector", version="0.1.0")


def evidence(n: int, ref: str = "shot") -> EvidenceRef:
    return EvidenceRef(ref=f"{ref}-{n}", content_hash=d(100 + n), version="1", modality="image",
                       media_type="image/png", source="qa-playwright", ref_type="artifact")


def observation(step_id: str = "s1", phase: Phase = Phase.AFTER, **kw) -> Observation:
    base = dict(
        observation_id=f"obs-{step_id}-{phase.value.lower()}", step_id=step_id, phase=phase,
        source=ObservationSource(adapter="qa-playwright", adapter_version="0.1.0", browser="chromium",
                                 browser_version="130.0.1"),
        redaction_policy_id=h(31), redaction_applied=True, url="https://app.example.test/saved", frame="main",
        a11y_snapshot_ref=evidence(1, "a11y"), screenshot_ref=evidence(2), dom_meta={"title": "Saved", "nodes": 41},
        observed_at="2026-10-30T10:00:00Z", duration_ms=120)
    base.update(kw)
    return Observation(**base)


def policy_decision(step_id: str = "s1", decision: PolicyDecisionKind = PolicyDecisionKind.ALLOW, **kw):
    base = dict(
        policy_decision_id=f"pd-{step_id}", run_id="run-1", step_id=step_id, principal="runner:qa", app="demo-app",
        decision=decision, provider="cr-policy-plane", action_kind=ActionKind.CLICK,
        side_effect=SideEffect.WRITES_INTERNAL, scope=("ui:click",), rule_id="allow-local-writes",
        reason="matched rule allow-local-writes", decided_at="2026-10-30T10:00:00Z")
    base.update(kw)
    return QAPolicyDecision(**base)


def action_receipt(step_id: str = "s1", attempt: int = 1, **kw) -> ActionReceipt:
    base = dict(
        receipt_id=f"rcpt-{step_id}-{attempt}", run_id="run-1", step_id=step_id, attempt=attempt,
        tool=ToolRef(name="qa-playwright", version="0.1.0"), action=ActionRecord(kind=ActionKind.CLICK),
        state_before_hash=h(41), state_after_hash=h(42), policy_decision_ref=policy_decision(step_id).content_hash,
        idempotency_key=f"idem-{step_id}-1",
        postcondition=Postcondition(declared="url ends /saved", observed="url ends /saved",
                                    result=PostconditionResult.SATISFIED),
        result=ResultCode.OK,
        locator_used=LocatorUsed(descriptor=LocatorDescriptor(role="button", name="Save"),
                                 strategy=LocatorStrategy.AUTHORED),
        duration_ms=340, recovery_rationale=None)
    base.update(kw)
    return ActionReceipt(**base)


def assertion_result(assertion=None, spec=None, *, verdict: Verdict = Verdict.PASS, **kw) -> AssertionResult:
    assertion = assertion or ui_assertion()
    spec_hash = (spec or ui_spec()).assertion_set_hash
    conclusive = verdict.is_conclusive
    base = dict(
        assertion_id=assertion.assertion_id, assertion_set_hash=spec_hash, expected_hash=assertion.expected_hash,
        executor=assertion.executor, verifier=VERIFIER,
        check=Check(check_id=assertion.assertion_id, verdict=verdict, determinism=Determinism.DETERMINISTIC,
                    detail="", evidence_refs=(evidence(3).pin(),)),
        reason_code=None if conclusive else "SUBJECT_UNRESOLVED", observation_id="obs-s1-after",
        actual="Saved" if conclusive else None, evaluated_at="2026-10-30T10:00:01Z")
    base.update(kw)
    return AssertionResult(**base)


def fault_event(sequence: int = 0, *, recovered: bool = True, step_id: str = "s1") -> FaultEvent:
    detection = FaultDetection(
        detected=True, signal=FaultSignal.LOCATOR_NOT_FOUND, claimed_class=ClaimedClass.BENIGN_DRIFT,
        detector=DETECTOR, evidence_refs=(evidence(4, "obs"),), detected_at_ms_into_step=250)
    recovery = FaultRecovery(
        detection_ref=detection.content_hash, attempted=True, strategy=RecoveryStrategy.SEMANTIC_LOCATOR,
        result=RecoveryResult.RECOVERED if recovered else RecoveryResult.NOT_RECOVERED,
        postcondition_verified=recovered, attempts=1, candidates_considered=2,
        candidates_rejected_reasons=("NOT_UNIQUE",), cost=RecoveryCost(tokens=0, model_calls=0, ms=180))
    return FaultEvent(fault_event_id=f"fe-{sequence}", step_id=step_id, sequence=sequence, detection=detection,
                      recovery=recovery)


def run_manifest(spec=None, **kw) -> RunManifest:
    spec = spec or ui_spec()
    ids = tuple(spec.assertion_ids)
    base = dict(
        run_id="run-1", spec_ref=spec.spec_ref, assertion_set_hash=spec.assertion_set_hash, adapter=ADAPTER,
        egress_policy_id=h(32), redaction_policy_id=h(31), trace_id="0123456789abcdef0123456789abcdef",
        recovery_enabled=True, model_recovery_enabled=False, assertions_declared=ids, assertions_executed=ids,
        assertions_skipped=(), outcome=Outcome.PASS,
        versions=(VersionPin(component="runtime-contracts", version="0.3.14", revision="403f536"),
                  VersionPin(component="agent-harness", version="0.1.0")),
        plan_hash=h(33), planner=PLANNER, browser="chromium 130.0.1", seeds=(7, 11), sandbox_image_digest=d(34),
        resource_limits={"memory_mb": 2048, "pids": 256},
        step_results=(StepResult(step_id="s1", result=ResultCode.OK, postcondition=PostconditionResult.SATISFIED,
                                 receipts=(action_receipt().content_hash,)),),
        assertion_results=tuple(assertion_result(a, spec) for a in spec.assertions),
        fault_events=(fault_event(),), counters=Counters(tokens=0, model_calls=0, infrastructure_ms=5400),
        started_at="2026-10-30T10:00:00Z", finished_at="2026-10-30T10:00:05Z")
    base.update(kw)
    return RunManifest(**base)
