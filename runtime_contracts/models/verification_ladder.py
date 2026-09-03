"""The verification ladder — verification as a typed, ordered set of capabilities.

Verification is already part of the runtime (:class:`~.verification.VerificationResult`).
This adds what makes it *planner-selectable*: an ordered ladder of assurance, a typed
descriptor for each verifier with its cost, and a **pure sufficiency rule** that says
whether a verifier is allowed to be the gate for a given requirement.

The optimization — *pick the cheapest sufficient verifier* — is a planning algorithm and
lives in the Mission Runtime, not here (contracts own rules, not algorithms). What lives
here is the part that must be agreed and stable across implementations: the rungs, the
descriptor shape, and the two rules that keep "spend as little verification as the risk
allows" from becoming "let the model talk itself into a cheap check":

* **fail-closed** — a requirement is met only by a verifier at or above its tier; nothing
  below counts, and "no sufficient verifier" is a refusal to promote, never a pass;
* **no lone model at the final gate** — a non-deterministic (model) verdict is evidence,
  not proof (see :class:`~.verification.Determinism`), so it cannot be the *sufficient
  final gate* unless the requirement explicitly relaxes that. Deterministic checks,
  ensembles, and humans can.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict

from .capability import Estimate
from .verification import Determinism


class AssuranceTier(str, Enum):
    """Rungs of the ladder, ordered weakest→strongest (and roughly cheapest→dearest).

    The order is the contract: :func:`tier_rank` is the single source of truth, so an
    implementation cannot quietly reorder how much assurance a tier represents.
    """

    STRUCTURAL = "STRUCTURAL"
    """Shape only — schema, exit code, well-formedness. Cheap, deterministic, shallow."""
    DETERMINISTIC = "DETERMINISTIC"
    """Reproducible rules — unit tests, invariants, domain rules, numeric limits."""
    EVIDENTIAL = "EVIDENTIAL"
    """The claim is actually supported by the cited evidence."""
    SEMANTIC = "SEMANTIC"
    """A model judged it. Evidence, not proof — never a lone final gate by default."""
    ENSEMBLE = "ENSEMBLE"
    """Multiple independent witnesses must agree — a model verdict made robust."""
    HUMAN = "HUMAN"
    """A person decided. The strongest and dearest rung; the escalation floor."""


_ORDER = (
    AssuranceTier.STRUCTURAL, AssuranceTier.DETERMINISTIC, AssuranceTier.EVIDENTIAL,
    AssuranceTier.SEMANTIC, AssuranceTier.ENSEMBLE, AssuranceTier.HUMAN,
)


def tier_rank(tier: AssuranceTier) -> int:
    """The canonical strength ordering. Higher = stronger assurance."""
    return _ORDER.index(tier)


@dataclass(frozen=True)
class VerifierDescriptor:
    """One ``verify.*`` capability, judgeable by a planner before it is run."""

    verifier_id: str                 # e.g. "verify.schema", "verify.semantic_judge"
    tier: AssuranceTier
    determinism: Determinism = Determinism.DETERMINISTIC
    cost: Estimate = field(default_factory=lambda: Estimate(low="0", high="0", unit="usd"))
    latency: Estimate = field(default_factory=lambda: Estimate(low="0", high="0", unit="ms"))
    #: Pre-execution gate: a failing/indeterminate result withholds the execution envelope
    #: (no side effect), rather than annotating an action that already happened.
    gating: bool = False

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "verifier_id": self.verifier_id,
            "tier": self.tier.value,
            "determinism": self.determinism.value,
            "cost": self.cost.canonical_form(),
            "latency": self.latency.canonical_form(),
            "gating": self.gating,
        }


@dataclass(frozen=True)
class VerificationRequirement:
    """The assurance an action's risk demands. Produced by the planner's risk policy;
    consumed by the sufficiency rule. Kept declarative so the risk→requirement decision
    is itself auditable rather than buried in verifier selection."""

    min_tier: AssuranceTier
    #: The sufficient *final* gate must be deterministic, ensemble, or human — not a lone
    #: model verdict. Relax only deliberately (e.g. a low-risk, reversible extraction).
    require_deterministic_final: bool = True

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "min_tier": self.min_tier.value,
            "require_deterministic_final": self.require_deterministic_final,
        }


def is_sufficient(verifier: VerifierDescriptor, requirement: VerificationRequirement) -> bool:
    """The pure rule: may this verifier be the gate for this requirement?

    Fail-closed (must reach the tier) and no-lone-model-at-the-final-gate. A planner uses
    this to filter candidates, then optimizes cost among what remains; a conformance test
    uses it to pin the rule across implementations.
    """
    if tier_rank(verifier.tier) < tier_rank(requirement.min_tier):
        return False
    if requirement.require_deterministic_final:
        # A model verdict is evidence, not proof. Deterministic checks, ensembles, and
        # humans may close the gate; a lone SEMANTIC verifier may not.
        model_only = (verifier.determinism is Determinism.NON_DETERMINISTIC
                      and verifier.tier not in (AssuranceTier.ENSEMBLE, AssuranceTier.HUMAN))
        if model_only:
            return False
    return True
