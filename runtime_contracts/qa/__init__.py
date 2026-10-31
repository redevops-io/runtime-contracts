"""``qa/v1``: the QA schema family. Contracts only: no browser, adapter implementation, scheduler or store.

``runtime-contracts`` owns these schemas; nobody else defines them. The harness executes and records, Context
Runtime plans, and the product packages and adapts. Within ``qa/v1`` the rule is additive only: new optional
fields and new schemas, no removal, rename or retype, and a consumer refuses an unknown major. Hashing is
``rcv1`` (``runtime_contracts.canonical``), unchanged.

Import from here, for example ``from runtime_contracts.qa import TestSpec, AssertionSpec, QAPlan``.
"""
from .base import (QA_CONTRACT_ID, QA_SCHEMA_VERSION, AssertionIntegrityError, Code, FrozenMap,
                   QAContractError, QARecord, QAValue, UnknownEnumValue, json_value_digest, strip_non_identity,
                   value_digest, verify_stored_hash)
from .adapter import (QA_ADAPTER_API_VERSION, ActionOutcome, ActionRequest, LocateCandidate, LocateResult,
                      ObserveRequest, QAAdapter, ResetResult, ResolvedTarget, SessionHandle, SessionProfile)
from .blob import BlobStore, Redactor, blob_digest, require_blob_digest, verify_blob
from .check_adapter import (CHECK_ADAPTER_API_VERSION, CheckAdapter, CheckProfile, CheckSubject,
                            ResolvedResource, WorkspaceHandle)
from .conformance import (check_result_matches_assertion, parse_recovery_candidate,
                          parse_recovery_candidates, verify_manifest_against_spec)
from .enums import (ActionKind, CaptureKind, CheckTier, ClaimedClass, CoverageContract, EvidenceLevel, Executor,
                    FaultSignal, IntegrityRefusalCode, LocateMode, LocatorStrategy, Outcome, PermittedRecovery, Phase,
                    PolicyDecisionKind, PostconditionResult, PredicateOp, RecoveryReason, RecoveryResult,
                    RecoveryStrategy, Resolution, ResetScope, ResourceKind, ResultCode, ReviewDecision, SkipReason, SubjectKind,
                    SuppressedReason, TargetKind)
from .errors import (ADAPTER_ERRORS, ActionBlockedByPolicy, ActionTimeout, AdapterCrash, BlobDigestInvalid,
                     BlobDigestMismatch, BlobNotFound, BlobStoreError, BlobTooLarge, BrowserCrash, ClassHint,
                     EnvironmentUnhealthy, ErrorCategory, LocatorAmbiguous, LocatorNotFound, NavigationDenied,
                     QAAdapterError, RedactionFailed, ResetFailed, ResourceLimitExceeded, SessionLost,
                     TargetNotActionable, UnexpectedDialog, UnsupportedOperation, error_for)
from .fault import FaultDetection, FaultEvent, FaultRecovery, RecoveryCost
from .integrity import (INTEGRITY_REFUSAL_CODES, INTEGRITY_REFUSAL_CODES_ADDED, INTEGRITY_REFUSAL_CODES_ORIGINAL,
                        assertions_changed, check_batch_not_halted, classify_coverage, classify_refusal,
                        coverage_violations, executor_certifies, idempotency_key_violations,
                        integrity_violations, load_pinned_assertion_set, refusal_halts_batch,
                        required_approvals, verify_assertion_set, verify_check_program, verify_pin_well_formed)
from .manifest import (Counters, ModelRef, RunManifest, SkippedAssertion, StepResult, VersionPin)
from .records import (ActionReceipt, ActionRecord, AssertionResult, Checkpoint, CleanupReport, LocatorCandidate,
                      LocatorUsed, Observation, ObservationSource, ObservedValue, Postcondition, QAPolicyDecision,
                      ReviewItem, ReviewRecord, ToolRef, action_value_digest)
from .outcome import OUTCOME_VERDICT, default_exit_code, outcome_to_verdict
from .plan import PlanGate, PlanItem, QAPlan, ResourceClaim
from .spec import (Action, AssertionSpec, AssertionSubject, Budget, CheckProgramRef, ComponentRef,
                   FixtureRef, LocatorDescriptor, Predicate, ResourceRef, Step, StepTarget, TestSpec,
                   TestTarget, assertion_set_hash, make_spec_ref, split_spec_ref)

__all__ = [
    "QA_CONTRACT_ID", "QA_SCHEMA_VERSION", "AssertionIntegrityError", "Code", "FrozenMap", "QAContractError",
    "QARecord", "QAValue", "UnknownEnumValue", "json_value_digest", "strip_non_identity", "value_digest",
    "verify_stored_hash",
    "ActionKind", "CaptureKind", "CheckTier", "ClaimedClass", "CoverageContract", "EvidenceLevel", "Executor",
    "FaultSignal", "IntegrityRefusalCode", "LocateMode", "LocatorStrategy", "Outcome", "PermittedRecovery", "Phase", "PolicyDecisionKind",
    "PostconditionResult", "PredicateOp", "RecoveryReason", "RecoveryResult", "RecoveryStrategy", "Resolution", "ResetScope",
    "ResourceKind", "ResultCode", "ReviewDecision", "SkipReason", "SubjectKind", "SuppressedReason", "TargetKind",
    "assertions_changed", "classify_coverage", "coverage_violations", "executor_certifies",
    "integrity_violations", "required_approvals", "verify_assertion_set",
    "INTEGRITY_REFUSAL_CODES", "INTEGRITY_REFUSAL_CODES_ADDED", "INTEGRITY_REFUSAL_CODES_ORIGINAL",
    "check_batch_not_halted", "classify_refusal", "idempotency_key_violations", "load_pinned_assertion_set",
    "refusal_halts_batch", "verify_check_program", "verify_pin_well_formed",
    "QA_ADAPTER_API_VERSION", "ActionOutcome", "ActionRequest", "LocateCandidate", "LocateResult",
    "ObserveRequest", "QAAdapter", "ResetResult", "ResolvedTarget", "SessionHandle", "SessionProfile",
    "BlobStore", "Redactor", "blob_digest", "require_blob_digest", "verify_blob",
    "CHECK_ADAPTER_API_VERSION", "CheckAdapter", "CheckProfile", "CheckSubject", "ResolvedResource",
    "WorkspaceHandle",
    "check_result_matches_assertion", "parse_recovery_candidate", "parse_recovery_candidates",
    "verify_manifest_against_spec",
    "ADAPTER_ERRORS", "ActionBlockedByPolicy", "ActionTimeout", "AdapterCrash", "BlobDigestInvalid",
    "BlobDigestMismatch", "BlobNotFound", "BlobStoreError", "BlobTooLarge", "BrowserCrash", "ClassHint",
    "EnvironmentUnhealthy", "ErrorCategory", "LocatorAmbiguous", "LocatorNotFound", "NavigationDenied",
    "QAAdapterError", "RedactionFailed", "ResetFailed", "ResourceLimitExceeded", "SessionLost",
    "TargetNotActionable", "UnexpectedDialog", "UnsupportedOperation", "error_for",
    "FaultDetection", "FaultEvent", "FaultRecovery", "RecoveryCost",
    "Counters", "ModelRef", "RunManifest", "SkippedAssertion", "StepResult", "VersionPin",
    "ActionReceipt", "ActionRecord", "AssertionResult", "Checkpoint", "CleanupReport", "LocatorCandidate",
    "LocatorUsed", "Observation", "ObservationSource", "ObservedValue", "Postcondition", "QAPolicyDecision",
    "ReviewItem", "ReviewRecord", "ToolRef", "action_value_digest",
    "OUTCOME_VERDICT", "default_exit_code", "outcome_to_verdict",
    "PlanGate", "PlanItem", "QAPlan", "ResourceClaim",
    "Action", "AssertionSpec", "AssertionSubject", "Budget", "CheckProgramRef", "ComponentRef", "FixtureRef",
    "LocatorDescriptor", "Predicate", "ResourceRef", "Step", "StepTarget", "TestSpec", "TestTarget",
    "assertion_set_hash", "make_spec_ref", "split_spec_ref",
]
