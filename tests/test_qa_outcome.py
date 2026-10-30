"""The failure taxonomy and its mapping onto the existing Verdict."""
from __future__ import annotations

import pytest

from runtime_contracts.models.verification import Verdict
from runtime_contracts.qa import Outcome, default_exit_code, outcome_to_verdict
from runtime_contracts.qa.outcome import OUTCOME_VERDICT


def test_the_taxonomy_is_exactly_five_outcomes():
    assert {o.value for o in Outcome} == {"PASS", "PRODUCT_FAIL", "TEST_DEFECT", "ENVIRONMENT_FAIL", "INCONCLUSIVE"}


@pytest.mark.parametrize("outcome,verdict", [
    ("PASS", Verdict.PASS),
    ("PRODUCT_FAIL", Verdict.FAIL),
    ("TEST_DEFECT", Verdict.INDETERMINATE),
    ("ENVIRONMENT_FAIL", Verdict.INDETERMINATE),
    ("INCONCLUSIVE", Verdict.INDETERMINATE),
])
def test_outcome_maps_to_the_contract_verdict(outcome, verdict):
    assert outcome_to_verdict(outcome) is verdict
    assert outcome_to_verdict(Outcome(outcome)) is verdict


def test_every_outcome_has_a_mapping():
    assert set(OUTCOME_VERDICT) == set(Outcome)


def test_only_product_fail_is_a_fail_and_only_pass_is_a_pass():
    assert [o for o, v in OUTCOME_VERDICT.items() if v is Verdict.FAIL] == [Outcome.PRODUCT_FAIL]
    assert [o for o, v in OUTCOME_VERDICT.items() if v is Verdict.PASS] == [Outcome.PASS]


@pytest.mark.parametrize("unknown", ["MAYBE", "", "pass", None, 0])
def test_an_unknown_outcome_is_indeterminate_and_non_zero(unknown):
    assert outcome_to_verdict(unknown) is Verdict.INDETERMINATE
    assert default_exit_code(unknown) == 1


def test_only_pass_exits_zero_by_default():
    assert [o for o in Outcome if default_exit_code(o) == 0] == [Outcome.PASS]
