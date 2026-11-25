"""How sub-criteria of one invariant resolve into a verdict."""
import pytest

from runtime_contracts.authz.qualification import Invariant
from runtime_contracts.authz.suite import Criteria, InvariantFailure, Unsupported

INV = list(Invariant)[0]


def test_a_failure_is_not_erased_by_a_later_pass_under_the_same_name():
    c = Criteria(INV, ["boundary"])
    c.check("boundary", False, "variant A leaked")
    c.check("boundary", True, "")                       # variant B held: the last report used to win
    with pytest.raises(InvariantFailure, match="variant A leaked"):
        c.resolve()


def test_a_pass_then_a_failure_fails_and_a_required_criterion_nobody_reported_is_unsupported():
    c = Criteria(INV, ["boundary"])
    c.ok("boundary")
    c.fail("boundary", "second variant leaked")
    with pytest.raises(InvariantFailure):
        c.resolve()
    with pytest.raises(Unsupported, match="never reported"):
        Criteria(INV, ["boundary"]).resolve()
    ok = Criteria(INV, ["boundary"])
    ok.ok("boundary")
    assert ok.resolve()["sub_criteria"][0]["status"] == "PASS"
