"""Every criterion must be able to fail. A green invariant with no red mutant is measuring nothing.

Two directions are checked here, both against the real implementation code:

``bad_*`` — a known-bad variant of an edition must **fail** the invariant it claims to break, and it must
fail a sub-criterion the shipped implementation passes. A mutant that fails for an unrelated reason (a
fixture mismatch, a crash) proves nothing, so the regression is pinned to a named sub-criterion.

``reference_*`` — a corrected variant, used nowhere in the product, must satisfy at least one criterion the
shipped implementation does not. That is what makes a ``FAIL`` or ``UNSUPPORTED`` a statement about the
product rather than about the test.
"""
from __future__ import annotations

import pytest

from runtime_contracts.authz.qualification import ALL_INVARIANTS, Invariant, Qualification
from runtime_contracts.authz.suite import run_invariant

from .implementations import (MUTANT_SETS, REAL_ADAPTERS, build, EXPECTATIONS, load_expectations,
                              mutants_breaking, skip_if_blocked)

REAL_BY_IMPLEMENTATION = {}
for _reference in REAL_ADAPTERS:
    try:
        REAL_BY_IMPLEMENTATION[build(_reference).implementation] = _reference
    except Exception:  # noqa: BLE001 — resolved per test so one missing checkout does not hide the others
        continue


def _sub_statuses(result) -> dict[str, str]:
    return {s["id"]: s["status"] for s in result.evidence.get("sub_criteria", [])}


def _mutant_cases(invariant: Invariant):
    return [(implementation, cls) for implementation, cls in mutants_breaking(invariant)
            if implementation in REAL_BY_IMPLEMENTATION]


@pytest.mark.parametrize("invariant", ALL_INVARIANTS, ids=lambda i: i.value)
def test_every_invariant_can_be_broken(invariant: Invariant) -> None:
    """An invariant with no mutant is an untested assertion. #626 ships a known-bad variant for each one."""
    cases = _mutant_cases(invariant)
    bad = [cls for _impl, cls in cases if cls.variant.startswith("bad_")]
    assert bad, (f"{invariant.value}: no known-bad variant is defined for this invariant, so nothing shows "
                 "the assertion can fail")


@pytest.mark.parametrize("invariant", ALL_INVARIANTS, ids=lambda i: i.value)
def test_a_known_bad_variant_fails_its_invariant(invariant: Invariant) -> None:
    checked = 0
    for implementation, cls in _mutant_cases(invariant):
        if not cls.variant.startswith("bad_"):
            continue
        mutant = skip_if_blocked(cls)
        real = skip_if_blocked(REAL_BY_IMPLEMENTATION[implementation])
        mutant_result = run_invariant(invariant, mutant)
        real_result = run_invariant(invariant, skip_if_blocked(REAL_BY_IMPLEMENTATION[implementation]))
        assert mutant_result.verdict is not Qualification.PASS, (
            f"{implementation}/{cls.variant} passed {invariant.value}: the assertion is vacuous — this "
            "defect would ship undetected")
        mutant_subs, real_subs = _sub_statuses(mutant_result), _sub_statuses(real_result)
        regressions = [name for name, status in mutant_subs.items()
                       if status == Qualification.FAIL.value and real_subs.get(name) == Qualification.PASS.value]
        # Where the shipped product has no seam at all (UNSUPPORTED), a mutant that supplies one and fails it
        # still proves the suite would catch the defect the day a seam exists — but it is the weaker claim,
        # so it is recorded separately from a genuine regression against working code.
        catches_a_missing_seam = [name for name, status in mutant_subs.items()
                                  if status == Qualification.FAIL.value
                                  and real_subs.get(name) == Qualification.UNSUPPORTED.value]
        assert regressions or catches_a_missing_seam, (
            f"{implementation}/{cls.variant} did not break any sub-criterion that {implementation} itself "
            f"passes (mutant={mutant_subs}, real={real_subs}); the control is not measuring the defect it "
            "names")
        checked += 1
    if not checked:
        pytest.skip(f"no runnable known-bad variant for {invariant.value} in this environment")


@pytest.mark.parametrize("invariant", ALL_INVARIANTS, ids=lambda i: i.value)
def test_a_reference_variant_shows_the_criterion_is_satisfiable(invariant: Invariant) -> None:
    """Every gap the matrix documents on purpose carries its proof-of-fix.

    The suite otherwise proves only that the assertion discriminates: it can say a mutant is wrong and a
    product is wrong without showing that anything could be right. A ``reference_*`` variant — a harness-only
    implementation, never a product claim — answers the same seams and does what the criterion asks, so its
    PASS shows the FAIL describes the product and not the assertion.

    Which cells count as gaps is read from ``qualification.json``, not from a live run. A cell can also go
    unmet for a reason that is not the criterion at all — a deployment with no durable replay store fails
    ``revocation_during_queue`` on configuration, and a reference variant would witness the wrong thing there.
    Deviations from a pinned verdict belong to the deviation test; this one guards the documented gaps, and
    each of them must show what meeting it looks like.
    """
    documented = [expectation for expectation in load_expectations(EXPECTATIONS)
                  if expectation.invariant is invariant
                  and expectation.verdict in (Qualification.FAIL, Qualification.UNSUPPORTED)]
    if not documented:
        pytest.skip(f"{invariant.value}: {EXPECTATIONS.name} documents no gap here, so nothing needs witnessing")
    for expectation in documented:
        implementation, expected = expectation.implementation, expectation.verdict
        real_result = run_invariant(invariant, skip_if_blocked(REAL_BY_IMPLEMENTATION[implementation]))
        references = [cls for impl, cls in mutants_breaking(invariant)
                      if impl == implementation and cls.variant.startswith("reference_")]
        assert references, (
            f"{implementation}/{invariant.value} is documented as {expected.value} with no {implementation} "
            "reference variant: nothing shows the criterion can be met, so the verdict could equally describe "
            "the assertion as the product. Either write the reference — it is the remediation sketch — or "
            f"record in {EXPECTATIONS.name} why the criterion cannot be met here. On record: "
            f"{expectation.remediation}")
        real_subs = _sub_statuses(real_result)
        satisfied: list[str] = []
        for cls in references:
            reference = skip_if_blocked(cls)
            reference_result = run_invariant(invariant, reference)
            reference_subs = _sub_statuses(reference_result)
            satisfied += [name for name, status in reference_subs.items()
                          if status == Qualification.PASS.value
                          and real_subs.get(name) != Qualification.PASS.value]
            if not satisfied and reference_result.verdict is Qualification.PASS:
                satisfied.append(f"{invariant.value} (whole cell)")
        assert satisfied, (
            f"none of {[cls.variant for cls in references]} satisfies anything that {implementation} fails "
            f"— either the product already implements it (update the matrix) or the reference is not a real "
            f"fix (reference={_sub_statuses(run_invariant(invariant, skip_if_blocked(references[0])))} vs "
            f"product={real_subs})")