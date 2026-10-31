"""Typed adapter errors.

Every adapter error subclasses ``QAAdapterError(category, retryable, recoverable, class_hint)``. The runner, not the
adapter, decides what to do with one; these fields say what kind of fault it is and what may be tried. ``code`` is
the ``ResultCode`` an ``ActionReceipt`` records for it.

``RedactionFailed`` is shared by the browser and check adapters and by the ``Redactor`` and ``BlobStore`` seams: a
failed redaction is a typed error, never a raw artifact.
"""
from __future__ import annotations

from enum import Enum
from typing import Dict, Optional, Type

from .enums import ResultCode


class ErrorCategory(str, Enum):
    LOCATOR = "LOCATOR"
    ACTION = "ACTION"
    SESSION = "SESSION"
    NETWORK = "NETWORK"
    POLICY = "POLICY"
    ENVIRONMENT = "ENVIRONMENT"
    INTEGRITY = "INTEGRITY"
    SPEC = "SPEC"


class ClassHint(str, Enum):
    """How a fault is likely to be classified. A hint for the detector, never a verdict."""

    BENIGN_DRIFT_CANDIDATE = "BENIGN_DRIFT_CANDIDATE"
    BENIGN_DRIFT_OR_ENVIRONMENT = "BENIGN_DRIFT_OR_ENVIRONMENT"
    ENVIRONMENT_OR_BENIGN = "ENVIRONMENT_OR_BENIGN"
    ENVIRONMENT_OR_POLICY = "ENVIRONMENT_OR_POLICY"
    ENVIRONMENT = "ENVIRONMENT"
    INCONCLUSIVE = "INCONCLUSIVE"
    POLICY = "POLICY"
    INTEGRITY = "INTEGRITY"
    TEST_DEFECT = "TEST_DEFECT"


class QAAdapterError(Exception):
    code: ResultCode = ResultCode.ADAPTER_CRASH

    def __init__(self, category: ErrorCategory, retryable: bool, recoverable: bool, class_hint: ClassHint,
                 message: str = ""):
        super().__init__(message or type(self).__name__)
        self.category = category
        self.retryable = retryable
        self.recoverable = recoverable
        self.class_hint = class_hint


class LocatorNotFound(QAAdapterError):
    """Recoverable by a semantic locator or a model candidate; raises a fault event."""

    code = ResultCode.LOCATOR_NOT_FOUND

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.LOCATOR, False, True, ClassHint.BENIGN_DRIFT_CANDIDATE, message)


class LocatorAmbiguous(QAAdapterError):
    """Recoverable by a semantic locator with a uniqueness check; never auto-picks the first match."""

    code = ResultCode.LOCATOR_AMBIGUOUS

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.LOCATOR, False, True, ClassHint.INCONCLUSIVE, message)


class TargetNotActionable(QAAdapterError):
    """Hidden, disabled or obscured. Wait and re-observe, bounded by the deadline."""

    code = ResultCode.TARGET_NOT_ACTIONABLE

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ACTION, True, True, ClassHint.BENIGN_DRIFT_CANDIDATE, message)


class ActionTimeout(QAAdapterError):
    """Retried only if the step is idempotent."""

    code = ResultCode.ACTION_TIMEOUT

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ACTION, True, True, ClassHint.BENIGN_DRIFT_OR_ENVIRONMENT, message)


class UnexpectedDialog(QAAdapterError):
    """Modal, overlay or consent. Dismissed only if the spec permits."""

    code = ResultCode.UNEXPECTED_DIALOG

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ACTION, False, True, ClassHint.BENIGN_DRIFT_CANDIDATE, message)


class SessionLost(QAAdapterError):
    """Re-open the session and resume from a checkpoint. Storage state is never persisted to evidence."""

    code = ResultCode.SESSION_LOST

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.SESSION, False, True, ClassHint.ENVIRONMENT_OR_BENIGN, message)


class NavigationDenied(QAAdapterError):
    """Egress policy. Counted by host only."""

    code = ResultCode.NAVIGATION_DENIED

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.NETWORK, False, False, ClassHint.ENVIRONMENT_OR_POLICY, message)


class ActionBlockedByPolicy(QAAdapterError):
    """A ui_action decision denied it, no decision was referenced, or a guard failed."""

    code = ResultCode.ACTION_BLOCKED_BY_POLICY

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.POLICY, False, False, ClassHint.POLICY, message)


class EnvironmentUnhealthy(QAAdapterError):
    """Recoverable by a reset."""

    code = ResultCode.ENVIRONMENT_UNHEALTHY

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ENVIRONMENT, False, True, ClassHint.ENVIRONMENT, message)


class AdapterCrash(QAAdapterError):
    """Recoverable by restarting the session."""

    code = ResultCode.ADAPTER_CRASH

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ENVIRONMENT, False, True, ClassHint.ENVIRONMENT, message)


class BrowserCrash(QAAdapterError):
    """Recoverable by restarting the session."""

    code = ResultCode.BROWSER_CRASH

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ENVIRONMENT, False, True, ClassHint.ENVIRONMENT, message)


class ResetFailed(QAAdapterError):
    """Ends the run as ENVIRONMENT_FAIL."""

    code = ResultCode.RESET_FAILED

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ENVIRONMENT, False, False, ClassHint.ENVIRONMENT, message)


class ResourceLimitExceeded(QAAdapterError):
    """A request, redirect, size or time cap was hit."""

    code = ResultCode.RESOURCE_LIMIT_EXCEEDED

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.ENVIRONMENT, False, False, ClassHint.ENVIRONMENT, message)


class RedactionFailed(QAAdapterError):
    """The artifact is dropped and the run is INCONCLUSIVE; a raw artifact is never returned."""

    code = ResultCode.REDACTION_FAILED

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.INTEGRITY, False, False, ClassHint.INTEGRITY, message)


class UnsupportedOperation(QAAdapterError):
    """The spec asked for something this adapter cannot express. Reported, never passed."""

    code = ResultCode.UNSUPPORTED_OPERATION

    def __init__(self, message: str = "") -> None:
        super().__init__(ErrorCategory.SPEC, False, False, ClassHint.TEST_DEFECT, message)


ADAPTER_ERRORS: Dict[ResultCode, Type[QAAdapterError]] = {
    LocatorNotFound.code: LocatorNotFound,
    LocatorAmbiguous.code: LocatorAmbiguous,
    TargetNotActionable.code: TargetNotActionable,
    ActionTimeout.code: ActionTimeout,
    UnexpectedDialog.code: UnexpectedDialog,
    SessionLost.code: SessionLost,
    NavigationDenied.code: NavigationDenied,
    ActionBlockedByPolicy.code: ActionBlockedByPolicy,
    EnvironmentUnhealthy.code: EnvironmentUnhealthy,
    AdapterCrash.code: AdapterCrash,
    BrowserCrash.code: BrowserCrash,
    ResetFailed.code: ResetFailed,
    ResourceLimitExceeded.code: ResourceLimitExceeded,
    RedactionFailed.code: RedactionFailed,
    UnsupportedOperation.code: UnsupportedOperation,
}


def error_for(code: ResultCode, message: str = "") -> Optional[QAAdapterError]:
    """The typed error for a recorded ``ResultCode``; ``None`` for ``OK``."""
    cls = ADAPTER_ERRORS.get(code)
    return cls(message) if cls is not None else None


# ── blob store errors ──────────────────────────────────────────────────────────────────────────────────────

class BlobStoreError(Exception):
    code = "BLOB_STORE_ERROR"


class BlobDigestInvalid(BlobStoreError):
    """The digest is not ``sha256:`` and 64 lowercase hex digits. A truncated form is never accepted."""

    code = "BLOB_DIGEST_INVALID"


class BlobNotFound(BlobStoreError):
    code = "BLOB_NOT_FOUND"


class BlobDigestMismatch(BlobStoreError):
    """The bytes do not hash to the digest they were stored or requested under."""

    code = "BLOB_DIGEST_MISMATCH"


class BlobTooLarge(BlobStoreError):
    code = "BLOB_TOO_LARGE"
