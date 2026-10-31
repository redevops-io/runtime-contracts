"""Closed vocabularies for ``qa/v1``.

Every enum here is part of the contract: a member is never removed or renamed within ``qa/v1``. A new member may be
added only if consumers treat an unknown member as non-certifying, and they do: parsing an unknown value raises
``UnknownEnumValue`` and a verdict mapping for an unknown outcome is ``INDETERMINATE``.
"""
from __future__ import annotations

from enum import Enum


class Executor(str, Enum):
    """How an assertion is evaluated. Frozen with the assertion; changing it changes ``assertion_set_hash``."""

    PLAYWRIGHT = "PLAYWRIGHT"
    """Read through ``QAAdapter.assert_``."""

    SCRIPT = "SCRIPT"
    """Read through ``CheckAdapter.run_check`` with a registered, hashed check program."""


class TargetKind(str, Enum):
    UI = "ui"
    RESOURCE = "resource"


class ResourceKind(str, Enum):
    MANIFEST_PATH = "MANIFEST_PATH"
    IMAGE_DIGEST = "IMAGE_DIGEST"
    NAMESPACE_OBJECT = "NAMESPACE_OBJECT"


class CheckTier(str, Enum):
    OFFLINE = "OFFLINE"
    K = "K"
    """A disposable, isolated cluster that has passed the disposable-cluster guard."""


class ActionKind(str, Enum):
    CLICK = "click"
    FILL = "fill"
    PRESS = "press"
    SELECT = "select"
    CHECK = "check"
    UNCHECK = "uncheck"
    HOVER = "hover"
    NAVIGATE = "navigate"
    RESOLVE = "resolve"
    """Resource-target step: resolve a resource reference to its content digest. No side effects."""


UI_ACTIONS = frozenset({ActionKind.CLICK, ActionKind.FILL, ActionKind.PRESS, ActionKind.SELECT,
                        ActionKind.CHECK, ActionKind.UNCHECK, ActionKind.HOVER, ActionKind.NAVIGATE})
RESOURCE_ACTIONS = frozenset({ActionKind.RESOLVE})
#: Actions that carry a value (or a secret reference); the others carry neither.
VALUE_ACTIONS = frozenset({ActionKind.FILL, ActionKind.PRESS, ActionKind.SELECT, ActionKind.NAVIGATE})


class PermittedRecovery(str, Enum):
    """What a step allows to be tried when it meets a fault. Recovery changes how a step finds its target; it
    cannot change what is expected."""

    RETRY_SAME = "RETRY_SAME"
    SEMANTIC_LOCATOR = "SEMANTIC_LOCATOR"
    MODEL_CANDIDATE = "MODEL_CANDIDATE"
    RESET_FIXTURE = "RESET_FIXTURE"
    CHECKPOINT_RESUME = "CHECKPOINT_RESUME"


class SubjectKind(str, Enum):
    UI_ELEMENT = "UI_ELEMENT"
    URL = "URL"
    RESPONSE = "RESPONSE"
    RESOURCE_INPUTS = "RESOURCE_INPUTS"
    """Inputs of a registered check program (``executor = SCRIPT``)."""


class PredicateOp(str, Enum):
    EQUALS = "EQUALS"
    NOT_EQUALS = "NOT_EQUALS"
    CONTAINS = "CONTAINS"
    MATCHES = "MATCHES"
    EXISTS = "EXISTS"
    ABSENT = "ABSENT"
    LESS_THAN = "LESS_THAN"
    GREATER_THAN = "GREATER_THAN"


#: Predicates that take no expected value.
NO_EXPECTED_OPS = frozenset({PredicateOp.EXISTS, PredicateOp.ABSENT})


class CoverageContract(str, Enum):
    FULL = "FULL"
    """Every declared assertion of every planned spec is scheduled. The only accepted value."""

    SUBSET = "SUBSET"
    """Reserved so the schema need not break later. Every validator, runner and classifier rejects it."""


class EvidenceLevel(str, Enum):
    MINIMAL = "MINIMAL"
    STANDARD = "STANDARD"
    FULL = "FULL"


class Outcome(str, Enum):
    """Run-level outcome, decided by a pure deterministic function and never by a model."""

    PASS = "PASS"
    PRODUCT_FAIL = "PRODUCT_FAIL"
    TEST_DEFECT = "TEST_DEFECT"
    ENVIRONMENT_FAIL = "ENVIRONMENT_FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
