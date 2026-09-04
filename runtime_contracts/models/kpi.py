"""Outcome / KPI linkage — the buyer's language, bound to a Mission Template.

Every other contract answers a *governance* question — should this happen, is it
authorized, is it verified, what could it physically reach. This one answers the
question a buyer actually asks: **did the work produce the outcome, safely?**

A Mission Template already declares *what outcomes to reach* (the Execution Intent).
This module lets it additionally declare *how success and safety are measured*, in
terms an operator recognises rather than infrastructure telemetry:

* :class:`KPIDeclaration` — one promised measure: a business result to maximise, a
  **safety bound that must hold** (``wash-sale violations = 0``), an autonomy rate, a
  human-effort figure, or a unit cost. Safety KPIs are hard bars, not dashboards.
* :class:`KPIMeasurement` — an observed value for a KPI over a run/window, carrying the
  evidence that supports it. Content-addressed, so a measurement cannot be silently
  restated.
* :class:`KPIOutcome` — a measurement judged against its declaration: satisfied or not,
  and — for a safety KPI — **blocking** when unmet.
* :class:`MissionKPISet` — the set a template carries. Content-addressed, so the KPIs a
  template promises are part of its identity: you cannot swap the scorecard after the
  fact without changing the template.

Primary vs. secondary (the "buyer metric first, technical drawer second" rule) is a flag
on each declaration, not two type hierarchies: safe-autonomous rate and violations-zero
are ``primary``; token budget and plan fingerprints live in the secondary drawer.

Canonical discipline (from :mod:`..canonical`): floats have no canonical form, so every
numeric value and bound is a **decimal string**. Comparison uses :class:`~decimal.Decimal`
so it is exact and reproduces byte-identically across languages.
"""
from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Dict, Tuple

from ..canonical import content_hash

CONTRACT_VERSION = "kpi/v1"


class KPIKind(Enum):
    """The five outcome families a Mission Template speaks to (buyer-facing)."""

    BUSINESS = "business"   # the result achieved — e.g. eligible losses harvested (USD)
    RISK = "risk"           # a safety bound that must hold — e.g. mandate violations = 0
    AUTONOMY = "autonomy"   # share handled without a human — e.g. safe autonomous rate
    HUMAN = "human"         # human effort spent — e.g. review minutes / unit of work
    RUNTIME = "runtime"     # unit economics — e.g. cost / verified outcome


class KPIDirection(Enum):
    """How a measurement is judged against the declaration."""

    MAXIMIZE = "maximize"                # higher is better; ``bound`` (if set) is a floor
    MINIMIZE = "minimize"                # lower is better; ``bound`` (if set) is a ceiling
    MUST_NOT_EXCEED = "must_not_exceed"  # hard ceiling — value must be <= bound
    MUST_EQUAL = "must_equal"            # hard exact — value must == bound (violations = 0)


def _dec(value: str, *, what: str) -> Decimal:
    # Decimal(0.5) is valid Python but a bare float has no canonical form — the contract
    # is a decimal *string*, so reject non-strings before parsing.
    if not isinstance(value, str):
        raise ValueError(f"{what} must be a decimal string, got {type(value).__name__}")
    try:
        return Decimal(value)
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError(f"{what} must be a decimal string, got {value!r}")


@dataclass(frozen=True)
class KPIDeclaration:
    """One measure a Mission Template promises to move — and, for safety, to hold.

    A ``MUST_EQUAL``/``MUST_NOT_EXCEED`` declaration is a *bar*: an unmet safety KPI is a
    first-class failure of the mission, not a red number on a chart. A ``MAXIMIZE``/
    ``MINIMIZE`` declaration may carry a ``bound`` as a target floor/ceiling, or leave it
    empty to mean "report it, no hard bar".
    """

    kpi_id: str
    kind: KPIKind
    #: Buyer-facing label, e.g. "Eligible losses harvested".
    name: str
    #: Unit, e.g. "USD", "ratio", "count", "minutes_per_unit", "USD_per_verified_outcome".
    unit: str
    direction: KPIDirection
    #: Threshold as a decimal string. Required for the two hard directions; optional
    #: (target) for MAXIMIZE/MINIMIZE. Empty = "no hard bar".
    bound: str = ""
    #: True = a buyer-facing metric shown first; False = secondary technical drawer.
    primary: bool = True
    description: str = ""
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.direction in (KPIDirection.MUST_NOT_EXCEED, KPIDirection.MUST_EQUAL):
            if not self.bound:
                raise ValueError(f"KPI {self.kpi_id!r} ({self.direction.value}) requires a bound")
        if self.bound:
            _dec(self.bound, what=f"KPI {self.kpi_id!r} bound")

    @property
    def is_safety(self) -> bool:
        """A hard bar whose breach must block the mission (not merely be reported)."""
        return self.direction in (KPIDirection.MUST_NOT_EXCEED, KPIDirection.MUST_EQUAL)

    def satisfied_by(self, value: str) -> bool:
        """Does an observed decimal-string ``value`` satisfy this declaration?

        For the hard directions this is the safety check. For MAXIMIZE/MINIMIZE with a
        ``bound`` it checks the target floor/ceiling; with no bound it is always True
        (the KPI is reported, not gated).
        """
        v = _dec(value, what=f"measurement for {self.kpi_id!r}")
        if self.direction is KPIDirection.MUST_EQUAL:
            return v == _dec(self.bound, what="bound")
        if self.direction is KPIDirection.MUST_NOT_EXCEED:
            return v <= _dec(self.bound, what="bound")
        if not self.bound:
            return True
        b = _dec(self.bound, what="bound")
        return v >= b if self.direction is KPIDirection.MAXIMIZE else v <= b

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "kpi_id": self.kpi_id,
            "kind": self.kind.value,
            "name": self.name,
            "unit": self.unit,
            "direction": self.direction.value,
            "bound": self.bound,
            "primary": self.primary,
            "description": self.description,
        }


@dataclass(frozen=True)
class KPIMeasurement:
    """An observed value for a KPI over a window, with the evidence that supports it.

    Content-addressed: a measurement's identity is the hash of its canonical form, so it
    cannot be silently restated after it is recorded into the ledger.
    """

    kpi_id: str
    #: Observed value as a decimal string (no bare floats — canonical discipline).
    value: str
    #: The window/scope this covers, e.g. "run:2026-09-04" or "book:v1".
    window: str = ""
    #: How many units the value aggregates over (households scanned, actions, …).
    sample_size: int = 0
    #: Evidence supporting the value, for replay/audit.
    evidence_refs: Tuple[str, ...] = ()
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        _dec(self.value, what=f"measurement for {self.kpi_id!r}")

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "kpi_id": self.kpi_id,
            "value": self.value,
            "window": self.window,
            "sample_size": self.sample_size,
            "evidence_refs": sorted(self.evidence_refs),
        }

    @property
    def measurement_id(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class KPIOutcome:
    """A measurement judged against its declaration.

    ``blocking`` is the load-bearing field: an unmet **safety** KPI blocks the mission,
    while an unmet target on a MAXIMIZE/MINIMIZE KPI is reported but does not gate. This is
    what keeps "violations = 0" a hard bar and "losses harvested" a scoreboard.
    """

    kpi_id: str
    value: str
    satisfied: bool
    blocking: bool


def judge(decl: KPIDeclaration, measurement: KPIMeasurement) -> KPIOutcome:
    """Evaluate one measurement against its declaration. Fail-closed for safety bars."""
    if measurement.kpi_id != decl.kpi_id:
        raise ValueError(
            f"measurement kpi_id {measurement.kpi_id!r} != declaration {decl.kpi_id!r}")
    ok = decl.satisfied_by(measurement.value)
    return KPIOutcome(
        kpi_id=decl.kpi_id, value=measurement.value,
        satisfied=ok, blocking=(decl.is_safety and not ok),
    )


@dataclass(frozen=True)
class MissionKPISet:
    """The KPIs a Mission Template promises. Content-addressed = part of its identity.

    You cannot substitute the scorecard after the fact without changing
    :attr:`kpi_set_id`; a template that claims a KPI set is bound to *these* measures.
    """

    kpis: Tuple[KPIDeclaration, ...] = ()
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        ids = [k.kpi_id for k in self.kpis]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate kpi_id in set: {ids}")

    def primary(self) -> Tuple[KPIDeclaration, ...]:
        """Buyer-facing measures, shown first."""
        return tuple(k for k in self.kpis if k.primary)

    def secondary(self) -> Tuple[KPIDeclaration, ...]:
        """The technical drawer, shown on request."""
        return tuple(k for k in self.kpis if not k.primary)

    def safety(self) -> Tuple[KPIDeclaration, ...]:
        """The hard bars that can block the mission."""
        return tuple(k for k in self.kpis if k.is_safety)

    def by_kind(self, kind: KPIKind) -> Tuple[KPIDeclaration, ...]:
        return tuple(k for k in self.kpis if k.kind is kind)

    def get(self, kpi_id: str) -> KPIDeclaration:
        for k in self.kpis:
            if k.kpi_id == kpi_id:
                return k
        raise KeyError(kpi_id)

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            # Sorted by kpi_id so set identity is order-independent.
            "kpis": [k.canonical_form() for k in sorted(self.kpis, key=lambda k: k.kpi_id)],
        }

    @property
    def kpi_set_id(self) -> str:
        return content_hash(self.canonical_form())
