"""``qa/v1``: the QA schema family. Contracts only: no browser, adapter implementation, scheduler or store.

``runtime-contracts`` owns these schemas; nobody else defines them. The harness executes and records, Context
Runtime plans, and the product packages and adapts. Within ``qa/v1`` the rule is additive only: new optional
fields and new schemas, no removal, rename or retype, and a consumer refuses an unknown major. Hashing is
``rcv1`` (``runtime_contracts.canonical``), unchanged.

Import from here, for example ``from runtime_contracts.qa import TestSpec, AssertionSpec, QAPlan``.
"""
from .base import (QA_CONTRACT_ID, QA_SCHEMA_VERSION, AssertionIntegrityError, Code, FrozenMap,
                   QAContractError, QARecord, QAValue, UnknownEnumValue, strip_non_identity, value_digest,
                   verify_stored_hash)
from .conformance import (check_result_matches_assertion, parse_recovery_candidate,
                          parse_recovery_candidates, verify_manifest_against_spec)
from .enums import (ActionKind, CaptureKind, CheckTier, ClaimedClass, CoverageContract, EvidenceLevel, Executor,
                    FaultSignal, LocateMode, LocatorStrategy, Outcome, PermittedRecovery, Phase,
                    PolicyDecisionKind, PostconditionResult, PredicateOp, RecoveryResult, RecoveryStrategy,
                    Resolution, ResetScope, ResourceKind, ResultCode, ReviewDecision, SkipReason, SubjectKind,
                    SuppressedReason, TargetKind)
from .fault import FaultDetection, FaultEvent, FaultRecovery, RecoveryCost
from .integrity import (assertions_changed, classify_coverage, coverage_violations, executor_certifies,
                        integrity_violations, required_approvals, verify_assertion_set)
from .manifest import (Counters, ModelRef, RunManifest, SkippedAssertion, StepResult, VersionPin)
from .records import (ActionReceipt, ActionRecord, AssertionResult, Checkpoint, CleanupReport, LocatorCandidate,
                      LocatorUsed, Observation, ObservationSource, ObservedValue, Postcondition, QAPolicyDecision,
                      ReviewItem, ReviewRecord, ToolRef)
from .outcome import OUTCOME_VERDICT, default_exit_code, outcome_to_verdict
from .plan import PlanGate, PlanItem, QAPlan, ResourceClaim
from .spec import (Action, AssertionSpec, AssertionSubject, Budget, CheckProgramRef, ComponentRef,
                   FixtureRef, LocatorDescriptor, Predicate, ResourceRef, Step, StepTarget, TestSpec,
                   TestTarget, assertion_set_hash, make_spec_ref, split_spec_ref)

__all__ = [
    "QA_CONTRACT_ID", "QA_SCHEMA_VERSION", "AssertionIntegrityError", "Code", "FrozenMap", "QAContractError",
    "QARecord", "QAValue", "UnknownEnumValue", "strip_non_identity", "value_digest", "verify_stored_hash",
    "ActionKind", "CaptureKind", "CheckTier", "ClaimedClass", "CoverageContract", "EvidenceLevel", "Executor",
    "FaultSignal", "LocateMode", "LocatorStrategy", "Outcome", "PermittedRecovery", "Phase", "PolicyDecisionKind",
    "PostconditionResult", "PredicateOp", "RecoveryResult", "RecoveryStrategy", "Resolution", "ResetScope",
    "ResourceKind", "ResultCode", "ReviewDecision", "SkipReason", "SubjectKind", "SuppressedReason", "TargetKind",
    "assertions_changed", "classify_coverage", "coverage_violations", "executor_certifies",
    "integrity_violations", "required_approvals", "verify_assertion_set",
    "check_result_matches_assertion", "parse_recovery_candidate", "parse_recovery_candidates",
    "verify_manifest_against_spec",
    "FaultDetection", "FaultEvent", "FaultRecovery", "RecoveryCost",
    "Counters", "ModelRef", "RunManifest", "SkippedAssertion", "StepResult", "VersionPin",
    "ActionReceipt", "ActionRecord", "AssertionResult", "Checkpoint", "CleanupReport", "LocatorCandidate",
    "LocatorUsed", "Observation", "ObservationSource", "ObservedValue", "Postcondition", "QAPolicyDecision",
    "ReviewItem", "ReviewRecord", "ToolRef",
    "OUTCOME_VERDICT", "default_exit_code", "outcome_to_verdict",
    "PlanGate", "PlanItem", "QAPlan", "ResourceClaim",
    "Action", "AssertionSpec", "AssertionSubject", "Budget", "CheckProgramRef", "ComponentRef", "FixtureRef",
    "LocatorDescriptor", "Predicate", "ResourceRef", "Step", "StepTarget", "TestSpec", "TestTarget",
    "assertion_set_hash", "make_spec_ref", "split_spec_ref",
]
