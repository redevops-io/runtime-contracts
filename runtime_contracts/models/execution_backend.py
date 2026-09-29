"""Execution backend seam — a pluggable executor around the existing ``ExecutionEnvelope → ExecutionReceipt``
contract, with capability negotiation so an ``EnforcementProfile`` is enforceable rather than decorative.

Phase-0/1 slice from the NVIDIA/IBM deployment-security audit. The envelope/receipt contract is unchanged; this
adds:

  * ``EnforcementProfile`` — the required isolation tier for an action (STANDARD → ISOLATED → HARDENED →
    HARDWARE_ATTESTED).
  * ``BackendCapabilities`` — what a backend can *actually* enforce (filesystem/network/resource/process isolation,
    quarantine, identity binding, attestation, hardware attestation). A backend advertises these.
  * ``ExecutionBackend`` — the executor Protocol. The in-repo membrane / LocalContainmentSandbox is backend #1;
    OpenShell, edge/device and future confidential backends are prospective adapters, not dependencies.
  * ``admit_backend`` — the admission gate: a mission's required profile must be a *subset* of the backend's
    capabilities, checked **before credentials are admitted**. A required-profile downgrade **fails closed** unless
    a deployment explicitly opts into a lower profile — so a HARDWARE_ATTESTED mission can never silently run on the
    local membrane merely because both implement the same interface.
  * ``ExecutionAdmission`` — the audit join binding {envelope, execution identity, profile, backend}; the receipt
    stays linkable to identity via ``receipt.envelope_binding → envelope.authority`` (no receipt contract change).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from ..protocol.agent_identity import ExecutionIdentity
from ..protocol.seal import content_hash
from .execution import ExecutionEnvelope, ExecutionReceipt

EXECUTION_BACKEND_CONTRACT_VERSION = "1"


class EnforcementProfile(str, Enum):
    STANDARD = "standard"                 # no special isolation demanded
    ISOLATED = "isolated"                 # process/fs/network/resource isolation
    HARDENED = "hardened"                 # + quarantine, identity binding, attestation
    HARDWARE_ATTESTED = "hardware_attested"   # + out-of-band hardware attestation


@dataclass(frozen=True)
class BackendCapabilities:
    """What a backend can enforce. A backend advertises its real capabilities; the admission gate compares a
    profile's requirements against them (``requirements ⊆ capabilities``)."""
    filesystem_isolation: bool = False
    network_egress_control: bool = False
    resource_limits: bool = False
    process_isolation: bool = False
    quarantine: bool = False
    identity_binding: bool = False
    attestation: bool = False
    hardware_attestation: bool = False

    def _fields(self) -> dict[str, bool]:
        return {
            "filesystem_isolation": self.filesystem_isolation,
            "network_egress_control": self.network_egress_control,
            "resource_limits": self.resource_limits,
            "process_isolation": self.process_isolation,
            "quarantine": self.quarantine,
            "identity_binding": self.identity_binding,
            "attestation": self.attestation,
            "hardware_attestation": self.hardware_attestation,
        }

    def satisfies(self, required: "BackendCapabilities") -> bool:
        """True iff every capability required is one this backend provides (self ⊇ required)."""
        req, have = required._fields(), self._fields()
        return all((not req[k]) or have[k] for k in req)

    def missing(self, required: "BackendCapabilities") -> tuple[str, ...]:
        req, have = required._fields(), self._fields()
        return tuple(k for k in req if req[k] and not have[k])

    def canonical_form(self) -> dict[str, Any]:
        return self._fields()


# The minimum capabilities each profile demands — this is what makes EnforcementProfile non-decorative.
def profile_requirements(profile: EnforcementProfile) -> BackendCapabilities:
    if profile == EnforcementProfile.STANDARD:
        return BackendCapabilities()
    isolated = BackendCapabilities(
        filesystem_isolation=True, network_egress_control=True, resource_limits=True, process_isolation=True)
    if profile == EnforcementProfile.ISOLATED:
        return isolated
    hardened = BackendCapabilities(
        **{**isolated._fields(), "quarantine": True, "identity_binding": True, "attestation": True})
    if profile == EnforcementProfile.HARDENED:
        return hardened
    if profile == EnforcementProfile.HARDWARE_ATTESTED:
        return BackendCapabilities(**{**hardened._fields(), "hardware_attestation": True})
    raise ValueError(f"unknown enforcement profile {profile!r}")


class EnforcementDowngrade(Exception):
    """Raised when a required enforcement profile exceeds a backend's capabilities and no explicit downgrade was
    permitted — the fail-closed rule (§10.5). Never downgrade silently."""


@dataclass(frozen=True)
class ExecutionAdmission:
    """The audit record that a specific action was admitted (or refused) for a backend under a profile + identity.
    It joins the envelope, the execution identity and the enforcement decision without mutating the frozen
    envelope/receipt contracts. The receipt remains linkable to identity via ``envelope_binding → envelope.authority``."""
    envelope_binding: str
    execution_identity: str            # ExecutionIdentity.digest()
    enforcement_profile: str
    backend_id: str
    granted: bool
    reason: str = ""                   # "" on grant; named reason otherwise (e.g. "enforcement_downgrade")

    def canonical_form(self) -> dict[str, Any]:
        return {
            "envelope_binding": self.envelope_binding, "execution_identity": self.execution_identity,
            "enforcement_profile": self.enforcement_profile, "backend_id": self.backend_id,
            "granted": self.granted, "reason": self.reason,
        }

    def admission_id(self) -> str:
        return content_hash(self.canonical_form())


@runtime_checkable
class ExecutionBackend(Protocol):
    """A pluggable executor for an approved ``ExecutionEnvelope``. Backend #1 is the in-repo membrane; OpenShell,
    edge/device and hardware-attested backends conform later. A backend must advertise honest ``capabilities()`` —
    the admission gate relies on them."""
    backend_id: str

    def capabilities(self) -> BackendCapabilities: ...
    def execute(self, envelope: ExecutionEnvelope, identity: ExecutionIdentity,
                profile: EnforcementProfile) -> ExecutionReceipt: ...
    def terminate(self, execution_id: str) -> None: ...
    def status(self, execution_id: str) -> str: ...
    def attest(self, execution_id: str) -> str: ...


def admit_backend(profile: EnforcementProfile, backend: ExecutionBackend, envelope: ExecutionEnvelope,
                  identity: ExecutionIdentity, *, allow_downgrade: bool = False) -> ExecutionAdmission:
    """Gate an execution before credentials are admitted: the backend must provide every capability the profile
    requires. On a shortfall this **fails closed** (raises ``EnforcementDowngrade``) unless the deployment
    explicitly passes ``allow_downgrade=True`` — which is recorded on the admission as an explicit, audited choice."""
    required = profile_requirements(profile)
    caps = backend.capabilities()
    binding = envelope.binding
    idd = identity.digest()
    if caps.satisfies(required):
        return ExecutionAdmission(envelope_binding=binding, execution_identity=idd,
                                  enforcement_profile=profile.value, backend_id=backend.backend_id, granted=True)
    missing = caps.missing(required)
    if not allow_downgrade:
        raise EnforcementDowngrade(
            f"backend {backend.backend_id!r} cannot satisfy {profile.value!r}: missing {', '.join(missing)}")
    return ExecutionAdmission(envelope_binding=binding, execution_identity=idd,
                              enforcement_profile=profile.value, backend_id=backend.backend_id, granted=True,
                              reason=f"explicit_downgrade:missing={','.join(missing)}")
