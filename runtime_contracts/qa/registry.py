"""The complete list of ``qa/v1`` schemas, value types, vocabularies and protocols.

One place to enumerate what the contract family contains, so the JSON Schema export, the additive-only inventory
and the leak guard all see exactly the same set. A schema added to the package but not listed here is caught by a
test that walks the package.
"""
from __future__ import annotations

import enum
import inspect
from typing import Dict, List, Type

from . import adapter, blob, check_adapter, enums, errors, fault, manifest, plan, records, spec
from .base import QARecord, QAValue

RECORDS: List[Type[QARecord]] = [
    spec.AssertionSpec, spec.TestSpec, plan.QAPlan, records.Observation, records.ActionReceipt,
    records.QAPolicyDecision, records.LocatorCandidate, records.ObservedValue, records.AssertionResult,
    fault.FaultDetection, fault.FaultRecovery, fault.FaultEvent, manifest.RunManifest, records.Checkpoint,
    records.ReviewItem, records.ReviewRecord, records.CleanupReport,
]

VALUES: List[Type[QAValue]] = [
    spec.ComponentRef, spec.LocatorDescriptor, spec.ResourceRef, spec.CheckProgramRef, spec.StepTarget,
    spec.Action, spec.Step, spec.Predicate, spec.AssertionSubject, spec.TestTarget, spec.FixtureRef, spec.Budget,
    plan.PlanItem, plan.PlanGate, plan.ResourceClaim, records.ObservationSource, records.ToolRef,
    records.LocatorUsed, records.ActionRecord, records.Postcondition, fault.RecoveryCost, manifest.SkippedAssertion,
    manifest.VersionPin, manifest.ModelRef, manifest.StepResult, manifest.Counters, adapter.SessionProfile,
    adapter.SessionHandle, adapter.ObserveRequest, adapter.LocateCandidate, adapter.LocateResult,
    adapter.ResolvedTarget, adapter.ActionRequest, adapter.ActionOutcome, adapter.ResetResult,
    check_adapter.CheckProfile, check_adapter.WorkspaceHandle, check_adapter.ResolvedResource,
    check_adapter.CheckSubject,
]

PROTOCOLS = {
    "QAAdapter": adapter.QAAdapter,
    "CheckAdapter": check_adapter.CheckAdapter,
    "BlobStore": blob.BlobStore,
    "Redactor": blob.Redactor,
}


def _enums() -> Dict[str, Type[enum.Enum]]:
    found = {}
    for module in (enums, errors):
        for name, obj in vars(module).items():
            if inspect.isclass(obj) and issubclass(obj, enum.Enum) and obj.__module__ == module.__name__:
                found[name] = obj
    return dict(sorted(found.items()))


ENUMS: Dict[str, Type[enum.Enum]] = _enums()


def _referenced_enums() -> Dict[str, Type[enum.Enum]]:
    """Enums that qa/v1 schemas use but the repository defines elsewhere (``Verdict``, ``SideEffect`` ...)."""
    from typing import get_args
    from .base import _hints
    found = {}
    stack = []
    for cls in [*RECORDS, *VALUES]:
        stack.extend(_hints(cls).values())
    while stack:
        t = stack.pop()
        stack.extend(get_args(t))
        if inspect.isclass(t) and issubclass(t, enum.Enum):
            found[t.__name__] = t
        elif inspect.isclass(t) and hasattr(t, "__dataclass_fields__") and not issubclass(t, QAValue):
            stack.extend(_hints(t).values())
    return dict(sorted(found.items()))


ALL_ENUMS: Dict[str, Type[enum.Enum]] = dict(sorted({**_referenced_enums(), **ENUMS}.items()))
