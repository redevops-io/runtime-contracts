"""The seven #626 invariants, run through each edition's own enforcement seams.

Each cell's verdict is compared against the verdict pinned in ``qualification.json``. That file is the
qualification record, so a verdict may only move because the product moved or because somebody edited the
expectation with a reason in it. A cell that has no pinned expectation, or that no longer runs, fails here
rather than disappearing quietly.

Run with the checkouts on the path::

    AGENTIC_OS_ROOT=/path/to/agentic-os AGENTIC_OS_ENTERPRISE_ROOT=/path/to/agentic-os-enterprise \\
      python -m pytest tests/authz_contract -q
"""
from __future__ import annotations

import pytest

from runtime_contracts.authz.qualification import ALL_INVARIANTS, Invariant, Qualification
from runtime_contracts.authz.suite import run_invariant

from .implementations import EXPECTATIONS, REAL_ADAPTERS, cells_for, load_expectations, skip_if_blocked


def _implementation(reference: str) -> str:
    return skip_if_blocked(reference).implementation


@pytest.mark.parametrize("reference", REAL_ADAPTERS, ids=lambda r: r.split(".")[-2])
def test_every_invariant_has_a_pinned_expectation(reference: str) -> None:
    """No cell may be decided on the fly: each (invariant, implementation) pair must be written down."""
    implementation = _implementation(reference)
    pinned = {(e.invariant, e.implementation) for e in load_expectations(EXPECTATIONS)}
    missing = [inv.value for inv in ALL_INVARIANTS if (inv, implementation) not in pinned]
    assert not missing, f"{implementation}: no pinned expectation for {missing}"


@pytest.mark.parametrize("invariant", ALL_INVARIANTS, ids=lambda i: i.value)
@pytest.mark.parametrize("reference", REAL_ADAPTERS, ids=lambda r: r.split(".")[-2])
def test_cell_matches_its_pinned_verdict(invariant: Invariant, reference: str) -> None:
    adapter = skip_if_blocked(reference)
    pinned = {(e.invariant, e.implementation): e for e in load_expectations(EXPECTATIONS)}
    result = run_invariant(invariant, adapter)
    expectation = pinned.get((invariant, adapter.implementation))
    if expectation is None:
        pytest.fail(f"{adapter.implementation}/{invariant.value}: verdict {result.verdict_value} has no "
                    "pinned expectation")
    assert result.verdict is expectation.verdict, (
        f"{adapter.implementation}/{invariant.value}: expected {expectation.verdict.value}, observed "
        f"{result.verdict.value}. {result.detail}\nIf the product changed, update qualification.json with a "
        f"reason and a remediation line; do not move the verdict to make the suite green.")


@pytest.mark.parametrize("reference", REAL_ADAPTERS, ids=lambda r: r.split(".")[-2])
def test_a_non_pass_cell_carries_remediation(reference: str) -> None:
    """An unmet criterion without a named next step is how a known gap becomes an accepted one."""
    implementation = _implementation(reference)
    for expectation in load_expectations(EXPECTATIONS):
        if expectation.implementation != implementation or expectation.verdict is Qualification.PASS:
            continue
        assert expectation.remediation.strip(), (
            f"{implementation}/{expectation.invariant.value} is {expectation.verdict.value} with no "
            "remediation recorded")


@pytest.mark.parametrize("reference", REAL_ADAPTERS, ids=lambda r: r.split(".")[-2])
def test_no_unsupported_cell_is_recorded_as_a_pass(reference: str) -> None:
    """The mapping that keeps UNSUPPORTED honest: it is INDETERMINATE, never PASS, never NOT_APPLICABLE."""
    from runtime_contracts.authz.qualification import qualification_to_verdict
    from runtime_contracts.models.verification import Verdict
    for cell in cells_for(reference):
        verdict = qualification_to_verdict(cell.verdict)
        if cell.verdict is Qualification.UNSUPPORTED:
            assert verdict is Verdict.INDETERMINATE, f"{cell.invariant.value} was softened to {verdict}"
        if cell.verdict is Qualification.PASS:
            assert verdict is Verdict.PASS