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
from .enums import (ActionKind, CheckTier, CoverageContract, EvidenceLevel, Executor, Outcome,
                    PermittedRecovery, PredicateOp, ResourceKind, SubjectKind, TargetKind)
from .integrity import (assertions_changed, executor_certifies, required_approvals,
                        verify_assertion_set)
from .outcome import OUTCOME_VERDICT, default_exit_code, outcome_to_verdict
from .plan import PlanGate, PlanItem, QAPlan, ResourceClaim
from .spec import (Action, AssertionSpec, AssertionSubject, Budget, CheckProgramRef, ComponentRef,
                   FixtureRef, LocatorDescriptor, Predicate, ResourceRef, Step, StepTarget, TestSpec,
                   TestTarget, assertion_set_hash, make_spec_ref, split_spec_ref)

__all__ = [
    "QA_CONTRACT_ID", "QA_SCHEMA_VERSION", "AssertionIntegrityError", "Code", "FrozenMap", "QAContractError",
    "QARecord", "QAValue", "UnknownEnumValue", "strip_non_identity", "value_digest", "verify_stored_hash",
    "ActionKind", "CheckTier", "CoverageContract", "EvidenceLevel", "Executor", "Outcome", "PermittedRecovery",
    "PredicateOp", "ResourceKind", "SubjectKind", "TargetKind",
    "assertions_changed", "executor_certifies", "required_approvals", "verify_assertion_set",
    "OUTCOME_VERDICT", "default_exit_code", "outcome_to_verdict",
    "PlanGate", "PlanItem", "QAPlan", "ResourceClaim",
    "Action", "AssertionSpec", "AssertionSubject", "Budget", "CheckProgramRef", "ComponentRef", "FixtureRef",
    "LocatorDescriptor", "Predicate", "ResourceRef", "Step", "StepTarget", "TestSpec", "TestTarget",
    "assertion_set_hash", "make_spec_ref", "split_spec_ref",
]
