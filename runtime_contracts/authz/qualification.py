"""How an authorization claim is qualified, and the matrix that records it.

Four verdicts, and the difference between them is the point:

``PASS``
    The scenario ran against this implementation's own enforcement seam and held.
``FAIL``
    The scenario ran and did not hold. The acceptance criterion stays in the suite until it does.
``UNSUPPORTED``
    The implementation has no seam that could satisfy the criterion — the feature is missing. This is a
    gap, not a pass and not a "not applicable": the criterion is required of the edition, so it is mapped
    to ``INDETERMINATE`` (the gap must be remediated), never to ``NOT_APPLICABLE``.
``BLOCKED``
    The implementation could not be loaded at all (no checkout, missing dependency). A statement about
    this run, not about the product.

A qualification matrix is the artifact a reviewer reads: one row per (invariant, implementation), with the
verdict, the code that was tested, the command that produced it and what has to change. The expectations
file it is diffed against is deliberate: a verdict may only move because someone changed the product or
updated the expectation on purpose.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

from ..models.verification import Verdict


class Qualification(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNSUPPORTED = "UNSUPPORTED"
    BLOCKED = "BLOCKED"

    @property
    def is_pass(self) -> bool:
        return self is Qualification.PASS

    @property
    def blocks_release(self) -> bool:
        """Anything but PASS gates. A missing feature gates exactly as a broken one does — the claim that
        the boundary holds is equally unsupported either way."""
        return self is not Qualification.PASS


def qualification_to_verdict(qualification: Qualification | str) -> Verdict:
    """Map onto the verdict every other ReDevOps verifier already speaks.

    ``UNSUPPORTED`` deliberately maps to ``INDETERMINATE`` and not to ``NOT_APPLICABLE``: the criterion is
    required of this edition, so "the seam does not exist yet" is an unmet requirement, not an inapplicable
    check. Collapsing the two is how a missing enforcement point becomes a green build.
    """
    q = Qualification(qualification) if not isinstance(qualification, Qualification) else qualification
    return {Qualification.PASS: Verdict.PASS,
            Qualification.FAIL: Verdict.FAIL,
            Qualification.UNSUPPORTED: Verdict.INDETERMINATE,
            Qualification.BLOCKED: Verdict.INDETERMINATE}[q]


class Invariant(str, Enum):
    """The seven cross-edition invariants of issue #626. The ids are stable — they are the row keys of a
    published matrix and of the expectations file that gates it."""

    CROSS_TENANT_DENIED = "cross_tenant_denied"
    NO_PRIVILEGE_LAUNDERING = "no_privilege_laundering"
    REVOCATION_DURING_QUEUE = "revocation_during_queue"
    STALE_EPOCH_REFUSAL = "stale_epoch_refusal"
    AUTHORIZATION_BEFORE_LIMIT = "authorization_before_limit"
    PERMITTED_EDGES_SURVIVE = "permitted_edges_survive"
    ADAPTER_ERROR_FAILS_CLOSED = "adapter_error_fails_closed"

    @property
    def title(self) -> str:
        return _TITLES[self]


_TITLES = {
    Invariant.CROSS_TENANT_DENIED:
        "A request that reaches another tenant's authority or data is refused, and a grant's tenant tag binds it",
    Invariant.NO_PRIVILEGE_LAUNDERING:
        "Authority cannot be acquired through a role name, a claim, or a delegated principal that never held it",
    Invariant.REVOCATION_DURING_QUEUE:
        "A grant revoked while work is queued is refused at dispatch, with no side effect",
    Invariant.STALE_EPOCH_REFUSAL:
        "A decision made under an older authorization epoch is never served",
    Invariant.AUTHORIZATION_BEFORE_LIMIT:
        "Unauthorized candidates are removed before any limit is applied, never after",
    Invariant.PERMITTED_EDGES_SURVIVE:
        "Excluding unauthorized edges keeps the permitted ones working",
    Invariant.ADAPTER_ERROR_FAILS_CLOSED:
        "A failing authority backend, gate or registry denies — it never degrades into a broader read",
}

ALL_INVARIANTS: tuple[Invariant, ...] = tuple(Invariant)


@dataclass(frozen=True)
class CaseResult:
    """One (invariant, implementation) cell of the matrix."""
    invariant: Invariant
    implementation: str
    verdict: Qualification
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def verdict_value(self) -> str:
        return self.verdict.value

    def to_dict(self) -> dict[str, Any]:
        return {"invariant": self.invariant.value, "implementation": self.implementation,
                "verdict": self.verdict.value, "detail": self.detail, "evidence": self.evidence}


@dataclass(frozen=True)
class Expectation:
    """What a matrix cell is expected to be, with the reason on record.

    ``remediation`` is required for anything that is not PASS: an unmet criterion without a named next step
    is how a known gap ages into an accepted one.
    """
    invariant: Invariant
    implementation: str
    verdict: Qualification
    reason: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"invariant": self.invariant.value, "implementation": self.implementation,
                "verdict": self.verdict.value, "reason": self.reason, "remediation": self.remediation}


@dataclass(frozen=True)
class Matrix:
    """The qualification matrix: observed cells plus the expectations they are gated against."""
    cells: tuple[CaseResult, ...]
    expectations: tuple[Expectation, ...] = ()

    def cell(self, invariant: Invariant | str, implementation: str) -> CaseResult | None:
        inv = Invariant(invariant) if not isinstance(invariant, Invariant) else invariant
        for c in self.cells:
            if c.invariant is inv and c.implementation == implementation:
                return c
        return None

    def verdicts(self, implementation: str) -> dict[str, str]:
        return {c.invariant.value: c.verdict.value for c in self.cells if c.implementation == implementation}

    def deviations(self) -> list[str]:
        """Every place the observed verdict differs from the pinned expectation, as readable messages.

        A cell with no expectation is itself a deviation: a verdict nobody agreed to is not a verdict.
        """
        pinned = {(e.invariant, e.implementation): e for e in self.expectations}
        seen = {(c.invariant, c.implementation) for c in self.cells}
        out: list[str] = []
        for c in self.cells:
            e = pinned.get((c.invariant, c.implementation))
            if e is None:
                out.append(f"{c.implementation}/{c.invariant.value}: verdict {c.verdict.value} has no "
                           "pinned expectation")
            elif e.verdict is not c.verdict:
                out.append(f"{c.implementation}/{c.invariant.value}: expected {e.verdict.value}, "
                           f"observed {c.verdict.value} ({c.detail})")
        for (inv, impl) in sorted(set(pinned) - seen, key=lambda t: (t[1], t[0].value)):
            out.append(f"{impl}/{inv.value}: expected {pinned[(inv, impl)].verdict.value} but the cell did "
                       "not run")
        return out

    def to_json(self) -> str:
        return json.dumps({"contract": "authz/v1",
                           "cells": [c.to_dict() for c in self.cells],
                           "expectations": [e.to_dict() for e in self.expectations]},
                          indent=2, sort_keys=True)


def load_expectations(path: Path | str) -> tuple[Expectation, ...]:
    """Read the pinned expectations file. Unknown verdicts or invariant ids are refused, not defaulted."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out: list[Expectation] = []
    for row in data["expectations"]:
        out.append(Expectation(invariant=Invariant(row["invariant"]), implementation=row["implementation"],
                               verdict=Qualification(row["verdict"]), reason=row["reason"],
                               remediation=row.get("remediation", "")))
    return tuple(out)


def matrix_from_cells(cells: Iterable[CaseResult], expectations: Iterable[Expectation] = ()) -> Matrix:
    return Matrix(cells=tuple(cells), expectations=tuple(expectations))