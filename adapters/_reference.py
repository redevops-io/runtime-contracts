"""Shapes a product does not produce, built here so a criterion cannot be vacuous.

Everything in this module is harness scaffolding. It is never imported by a product path, and a cell is never
credited to it: the qualification matrix keeps reference variants in their own column, and the invariant
cells run only the real adapters.

The reason it exists at all is the two hardest cells in #626. Both say "the implementation has no seam" (the
epoch cache) or "the implementation records nothing" (the authority outage). Those claims are only as strong
as the demonstration that the criterion has a satisfying implementation, so each one is paired with code that
satisfies it through the same seam the scenario uses.
"""
from __future__ import annotations

from runtime_contracts.authz.decision import AuthorizationDecision, PolicyReason, roles_hash
from runtime_contracts.authz.suite import PrincipalSpec, Receipt


def _subject_parts(subject: str) -> tuple[str, str]:
    kind, _, name = subject.partition(":")
    return (kind or "user"), name


def error_denial_receipt(implementation: str, principal: PrincipalSpec, *, resource: str, action: str,
                         outage: str, seam: str) -> Receipt:
    """A refusal that leaves an auditable trace — the shape E-6 asks a plane to produce.

    The envelope is assembled here, by the harness, which is exactly why it is not a product claim. E-6 is the
    ticket that moves this construction inside ``PermissionsPlane`` / ``IdentityPlane``, where the store is
    read and where a receipt can actually be written. What this proves is narrower and still necessary: the
    ``error_is_recorded`` criterion is expressible in `authz/v1` and satisfiable through the seam the scenario
    calls, so the product's FAIL is a gap in the product and not a defect in the assertion.
    """
    kind, name = _subject_parts(principal.subject)
    decision = AuthorizationDecision(allowed=False, policy_reason=PolicyReason.NO_RESOURCE_PLANE,
                                     principal=name, principal_kind=kind,
                                     roles_digest=roles_hash(principal.roles), resource_kind="table",
                                     resource_name=resource, requested_action=action,
                                     tenant=principal.tenant, plane=implementation)
    return Receipt(allowed=False, reason=f"denied: {outage}", decision=decision, seam=seam,
                   raw={"policy_reason": decision.policy_reason.value, "outage": outage,
                        "envelope": decision.to_envelope(),
                        "built_by": "adapters._reference (harness; see E-6)"})