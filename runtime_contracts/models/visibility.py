"""Visibility and tenancy — the types every other contract carries."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional


class Visibility(str, Enum):
    PUBLIC = "PUBLIC"
    """Impersonal. May be cited by anything."""

    PRIVATE = "PRIVATE"
    """Belongs to one tenant. May cite public artifacts; nothing public may cite it."""

    INTERNAL = "INTERNAL"
    """Operational. Neither published nor tenant-owned — build metadata, logs."""


class AuthorizationOutcome(str, Enum):
    """Why a handle was or was not included.

    Part of the ContextView hash on purpose: two views over the same graph that
    showed different subsets are not the same view, even when the difference is
    a redaction rather than a data change.
    """

    GRANTED = "GRANTED"
    DENIED_VISIBILITY = "DENIED_VISIBILITY"
    DENIED_TENANT = "DENIED_TENANT"
    DENIED_STALE = "DENIED_STALE"
    DENIED_BUDGET = "DENIED_BUDGET"

    @property
    def granted(self) -> bool:
        return self is AuthorizationOutcome.GRANTED


@dataclass(frozen=True)
class Tenancy:
    """Who an artifact belongs to.

    `tenant_id` is None only for PUBLIC artifacts. A private artifact without a
    tenant cannot be authorized against anything, so the contract refuses it
    rather than defaulting to a shared scope.
    """

    visibility: Visibility
    tenant_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.visibility is Visibility.PRIVATE and not self.tenant_id:
            raise ValueError(
                "a PRIVATE artifact must name its tenant; without one it cannot "
                "be authorized against anything and would default into a shared "
                "scope"
            )
        if self.visibility is Visibility.PUBLIC and self.tenant_id:
            raise ValueError(
                f"a PUBLIC artifact may not name tenant {self.tenant_id!r} — "
                "public artifacts are impersonal by definition, and one that "
                "carries a tenant is private data that has escaped"
            )

    def may_be_cited_by(self, other: "Tenancy") -> bool:
        """References run one way: private may cite public, never the reverse."""
        if self.visibility is Visibility.PUBLIC:
            return True
        if other.visibility is Visibility.PUBLIC:
            return False
        return self.tenant_id == other.tenant_id

    def canonical_form(self) -> Dict[str, Any]:
        return {"visibility": self.visibility.value, "tenant_id": self.tenant_id}
