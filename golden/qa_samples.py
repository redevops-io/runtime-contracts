"""Deterministic ``qa/v1`` sample objects, shared by the golden generator and the tests.

No clocks and no randomness: every value is fixed, so a hash computed from these objects is the same everywhere.
The golden generator (``golden/qa.py``) and the unit tests build from here so that a test and a fixture can never
describe two different objects under one name.
"""
from __future__ import annotations

from typing import Optional

from runtime_contracts.models.capability import Idempotency, RetrySafety, SideEffect
from runtime_contracts.qa import (Action, ActionKind, AssertionSpec, AssertionSubject, Budget, ComponentRef,
                                  CoverageContract, EvidenceLevel, Executor, FixtureRef, LocatorDescriptor,
                                  PermittedRecovery, PlanGate, PlanItem, Predicate, PredicateOp, QAPlan,
                                  ResourceClaim, ResourceKind, ResourceRef, Step, StepTarget, SubjectKind,
                                  TestSpec, TestTarget)


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
