"""AppManifest — the registration contract for a runtime-native agentic app.

An app does not *become* governed by containing the right code; it becomes governed by **declaring** what it
runs and letting a runtime bind and check that declaration. The AppManifest is that declaration: which
decision producers the app runs, which governed capabilities it provides, which capability each verifier
reads back, what outcomes it emits, and which OSS cores it needs and at what integration level.

**Why this is a contract and not an application type.** Three parties exchange it, so none may own it:

    the app          asserts the manifest          "here is what I run and provide"
    the runtime      binds + enforces it            registers the Operator, checks every claim resolves
    the overlay      extends it                     an enterprise image adds capability under the same shape

The failure it prevents is the *phantom capability*: a producer whose candidates require a capability the app
never actually provides. Code review cannot catch that reliably because the producer and the Operator live in
different files; a contract the registry checks can. So the invariant lives here, on the manifest
(:meth:`AppManifest.unresolved_producer_capabilities`), not in whichever registry happens to consume it.

**What is NOT duplicated here.** Per-capability security flags — side-effecting, approval-required, data
classifications — belong to the capability's own descriptor (see :class:`CapabilityDescriptor`), and a
consumer reads them from there. The manifest only *names* the capabilities the app provides and adds the
app-level metadata a per-capability descriptor cannot express: producers, verifiers, outcomes, cores,
integration level, and whether the app needs a private enterprise image to meet its contract at all.

**Pure data.** No imports from any runtime, so a manifest can be declared and inspected with nothing wired.
The vocabularies below are deliberately strings, not a runtime's own enums: a manifest a reader cannot fully
interpret must still round-trip unchanged rather than be narrowed to the nearest thing the reader can say.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping, Tuple

APP_MANIFEST_CONTRACT_VERSION = "app-manifest/v1"
BUILD_MANIFEST_CONTRACT_VERSION = "runtime-build-manifest/v1"


class IntegrationLevel(str, Enum):
    """How an app integrates with the OSS core it wraps — ascending authority over the core."""

    L0_ADAPTER = "l0_adapter"            # REST/CLI client + polling; observes, cannot intercept
    L1_EXTENSION = "l1_extension"        # the core's own webhooks/plugins; native-UI actions observed
    L2_GOVERNED_FORK = "l2_governed_fork"  # outbox + envelope guard + read-back around the core
    L3_EMBEDDED = "l3_embedded"          # the runtime runs in-process inside the core


class EnterpriseRequirement(str, Enum):
    """Whether the app needs a private enterprise image to meet its contract at all."""

    OPTIONAL = "optional"   # the public seam defaults satisfy the contract; enterprise only adds capability
    REQUIRED = "required"   # an enterprise-only suite; never published as an open app


@dataclass(frozen=True)
class CapabilityClaim:
    """The app's claim that it provides capability ``name``. ``risk_tier`` is a string so a manifest written
    against a richer vocabulary than the reader's still round-trips; ``name`` must resolve to a capability the
    app's Operator actually registers (the runtime checks this)."""

    name: str
    risk_tier: str = "read"
    may_egress: bool = False


@dataclass(frozen=True)
class ProducerClaim:
    """A decision producer the app runs: domain state -> opportunity/intervention candidate.

    ``emits_capabilities`` are the capability names the producer's candidates may require. Every one must
    appear in the manifest's capabilities — a producer that emits a capability the app does not provide is a
    phantom, and :meth:`AppManifest.unresolved_producer_capabilities` names it rather than letting the
    candidate fail opaquely at bind time."""

    name: str
    opportunity_kinds: Tuple[str, ...] = ()
    emits_capabilities: Tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifierClaim:
    """A read-back verifier bound to a side-effecting capability: after the act, re-read the world and confirm
    it actually happened. ``capability`` must resolve to a provided capability; ``name`` identifies the
    verifier/connector ``observe`` reference. A side-effecting capability with no verifier can only ever
    *claim* success — the manifest makes the absence visible."""

    capability: str
    name: str = ""


@dataclass(frozen=True)
class OutcomeKind:
    """An outcome the app emits so a decision can be scored against what actually happened. ``key`` is usually
    the candidate's action kind. ``expected_delay_s`` is in SECONDS (the one time unit), so a reader never has
    to guess whether a bare number meant seconds, minutes or days."""

    key: str
    unit: str = ""
    expected_delay_s: float = 0.0
    reward_weights: Mapping[str, float] = field(default_factory=dict)


@dataclass(frozen=True)
class CoreRequirement:
    """An OSS core the app depends on, and the integration level it is reached at."""

    core: str
    integration_level: IntegrationLevel = IntegrationLevel.L0_ADAPTER


@dataclass(frozen=True)
class RuntimeBuildManifest:
    """Attributable runtime/build identity for conformance and incident review.

    A version string alone is not enough once runtimes are embedded as libraries inside app images. This
    manifest is the small, application-neutral shape every runtime can emit from `/buildinfo` or EXPLAIN:
    package version, exact source commit, image digest when containerized, and the contract-version matrix
    the running build claims to interpret.
    """

    component: str
    package_version: str = "unknown"
    source_commit: str = "unknown"
    image_digest: str = ""
    contract_matrix: Mapping[str, str] = field(default_factory=dict)
    adapter_versions: Tuple[str, ...] = ()
    contract_version: str = BUILD_MANIFEST_CONTRACT_VERSION

    def is_attributable(self) -> bool:
        return bool(self.source_commit and self.source_commit != "unknown")


@dataclass(frozen=True)
class AppManifest:
    """The runtime-native registration contract for one app.

    Identity is ``name`` + ``version``. Everything else is the declaration a runtime binds and an overlay
    extends. Construct it with nothing wired; hand it to a registry to enforce it.
    """

    name: str
    version: str = "0.0.0"
    license: str = "AGPL-3.0-or-later"
    producers: Tuple[ProducerClaim, ...] = ()
    capabilities: Tuple[CapabilityClaim, ...] = ()
    verifiers: Tuple[VerifierClaim, ...] = ()
    outcome_kinds: Tuple[OutcomeKind, ...] = ()
    obligation_kinds: Tuple[str, ...] = ()
    required_cores: Tuple[CoreRequirement, ...] = ()
    data_classifications: Tuple[str, ...] = ()           # string vocabulary; neither runtime owns the list
    enterprise: EnterpriseRequirement = EnterpriseRequirement.OPTIONAL
    contract_version: str = APP_MANIFEST_CONTRACT_VERSION

    def capability_names(self) -> frozenset[str]:
        return frozenset(c.name for c in self.capabilities)

    def producer_capabilities(self) -> frozenset[str]:
        """Every capability any producer's candidates may require."""
        return frozenset(cap for p in self.producers for cap in p.emits_capabilities)

    def verified_capabilities(self) -> frozenset[str]:
        return frozenset(v.capability for v in self.verifiers)

    def unresolved_producer_capabilities(self) -> frozenset[str]:
        """Producer-emitted capabilities the app does NOT provide — the phantom-capability check. Empty is the
        only valid state; a non-empty result is a manifest a runtime must refuse to register."""
        return self.producer_capabilities() - self.capability_names()

    def unresolved_verifier_capabilities(self) -> frozenset[str]:
        """Verifier-bound capabilities the app does NOT provide — a verifier pointed at nothing."""
        return self.verified_capabilities() - self.capability_names()


__all__ = [
    "APP_MANIFEST_CONTRACT_VERSION",
    "BUILD_MANIFEST_CONTRACT_VERSION",
    "IntegrationLevel",
    "EnterpriseRequirement",
    "CapabilityClaim",
    "ProducerClaim",
    "VerifierClaim",
    "OutcomeKind",
    "CoreRequirement",
    "RuntimeBuildManifest",
    "AppManifest",
]
