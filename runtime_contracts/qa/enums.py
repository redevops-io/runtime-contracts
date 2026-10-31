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


class Phase(str, Enum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"


class LocatorStrategy(str, Enum):
    AUTHORED = "AUTHORED"
    SEMANTIC_ALTERNATE = "SEMANTIC_ALTERNATE"
    MODEL_CANDIDATE = "MODEL_CANDIDATE"


class PostconditionResult(str, Enum):
    SATISFIED = "SATISFIED"
    NOT_SATISFIED = "NOT_SATISFIED"
    NOT_EVALUATED = "NOT_EVALUATED"


class ResultCode(str, Enum):
    """The raw result of an action: ``OK`` or the typed adapter error that ended it."""

    OK = "OK"
    LOCATOR_NOT_FOUND = "LOCATOR_NOT_FOUND"
    LOCATOR_AMBIGUOUS = "LOCATOR_AMBIGUOUS"
    TARGET_NOT_ACTIONABLE = "TARGET_NOT_ACTIONABLE"
    ACTION_TIMEOUT = "ACTION_TIMEOUT"
    UNEXPECTED_DIALOG = "UNEXPECTED_DIALOG"
    SESSION_LOST = "SESSION_LOST"
    NAVIGATION_DENIED = "NAVIGATION_DENIED"
    ACTION_BLOCKED_BY_POLICY = "ACTION_BLOCKED_BY_POLICY"
    ENVIRONMENT_UNHEALTHY = "ENVIRONMENT_UNHEALTHY"
    ADAPTER_CRASH = "ADAPTER_CRASH"
    BROWSER_CRASH = "BROWSER_CRASH"
    RESET_FAILED = "RESET_FAILED"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    REDACTION_FAILED = "REDACTION_FAILED"
    UNSUPPORTED_OPERATION = "UNSUPPORTED_OPERATION"


class SkipReason(str, Enum):
    NOT_REACHED = "NOT_REACHED"
    PRECONDITION_UNMET = "PRECONDITION_UNMET"
    POLICY_DENIED = "POLICY_DENIED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    SUBJECT_UNRESOLVED = "SUBJECT_UNRESOLVED"
    ENVIRONMENT = "ENVIRONMENT"
    HALTED_INTEGRITY = "HALTED_INTEGRITY"


class FaultSignal(str, Enum):
    NONE = "NONE"
    LOCATOR_NOT_FOUND = "LOCATOR_NOT_FOUND"
    LOCATOR_AMBIGUOUS = "LOCATOR_AMBIGUOUS"
    ACTION_TIMEOUT = "ACTION_TIMEOUT"
    TRANSITION_NOT_OBSERVED = "TRANSITION_NOT_OBSERVED"
    ASSERTION_FAILED = "ASSERTION_FAILED"
    ASSERTION_UNRESOLVABLE = "ASSERTION_UNRESOLVABLE"
    ENV_UNHEALTHY = "ENV_UNHEALTHY"
    POLICY_DENIED = "POLICY_DENIED"
    NETWORK_BLOCKED = "NETWORK_BLOCKED"
    UNEXPECTED_OVERLAY = "UNEXPECTED_OVERLAY"
    SESSION_LOST = "SESSION_LOST"


class ClaimedClass(str, Enum):
    BENIGN_DRIFT = "BENIGN_DRIFT"
    PRODUCT_DEFECT_SUSPECTED = "PRODUCT_DEFECT_SUSPECTED"
    ENVIRONMENT = "ENVIRONMENT"
    UNKNOWN = "UNKNOWN"


class RecoveryStrategy(str, Enum):
    NONE = "NONE"
    RETRY_SAME = "RETRY_SAME"
    SEMANTIC_LOCATOR = "SEMANTIC_LOCATOR"
    MODEL_CANDIDATE = "MODEL_CANDIDATE"
    RESET_FIXTURE = "RESET_FIXTURE"
    CHECKPOINT_RESUME = "CHECKPOINT_RESUME"
    ESCALATE_REVIEW = "ESCALATE_REVIEW"


class SuppressedReason(str, Enum):
    NONE = "NONE"
    NOT_PERMITTED = "NOT_PERMITTED"
    NON_IDEMPOTENT = "NON_IDEMPOTENT"
    POLICY_DENIED = "POLICY_DENIED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    KILL_SWITCH = "KILL_SWITCH"


class RecoveryResult(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    RECOVERED = "RECOVERED"
    NOT_RECOVERED = "NOT_RECOVERED"
    ABORTED = "ABORTED"


class PolicyDecisionKind(str, Enum):
    """The only three decisions meaningful for the ``ui_action`` phase."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ReviewDecision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    REQUEST_CHANGE = "REQUEST_CHANGE"


class Resolution(str, Enum):
    """What the adapter found when it read a subject. A fact about resolution, never a verdict."""

    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    AMBIGUOUS = "AMBIGUOUS"


class CaptureKind(str, Enum):
    SCREENSHOT = "SCREENSHOT"
    A11Y_SNAPSHOT = "A11Y_SNAPSHOT"
    DOM_META = "DOM_META"
    NETWORK_EXCERPT = "NETWORK_EXCERPT"
    CONSOLE_EXCERPT = "CONSOLE_EXCERPT"
    TRACE = "TRACE"


class ResetScope(str, Enum):
    CONTEXT = "CONTEXT"
    FIXTURE = "FIXTURE"
    ENVIRONMENT = "ENVIRONMENT"


class LocateMode(str, Enum):
    EXACT = "EXACT"
    SEMANTIC = "SEMANTIC"
