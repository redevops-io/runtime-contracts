"""The golden fixtures, reproduced from the models.

A port in another language reproduces these hashes from the same inputs, or it
does not conform. Regenerating them and re-asserting would prove nothing, so the
committed file is the reference and the models are checked against it.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from golden.generate import cases

GOLDEN = json.loads(
    (pathlib.Path(__file__).parent.parent / "golden" / "context_view.json").read_text()
)


def test_the_committed_fixtures_still_reproduce():
    """Any change to canonicalization must be a deliberate fixture update."""
    assert cases() == GOLDEN["cases"]


class TestTheInvariantHolds:
    C = GOLDEN["cases"]

    def test_same_inputs_same_view_hash(self):
        assert self.C["reproducible_working_set"]["view_hash"].startswith("rcv1:")

    @pytest.mark.parametrize("case", ["order_variation",
                                      "duplicate_handle_normalization",
                                      "volatile_fields_excluded"])
    def test_these_do_not_change_the_view(self, case):
        assert self.C[case]["view_hash"] == \
            self.C["reproducible_working_set"]["view_hash"]

    @pytest.mark.parametrize("case,why", [
        ("projection_is_part_of_identity",
         "the same artifact at two projections is two planned items"),
        ("authorization_participates",
         "a redaction changes what the model was permitted to see"),
        ("omission_disclosure",
         "a view showing a subset without saying so claims completeness"),
        ("stale_version_pin",
         "a moved pin is a different working set"),
    ])
    def test_these_must_change_the_view(self, case, why):
        assert self.C[case]["view_hash"] != \
            self.C["reproducible_working_set"]["view_hash"], why

    def test_unicode_forms_agree(self):
        u = self.C["unicode_identity"]
        assert u["nfc"] == u["nfd"]

    def test_every_case_states_why_it_exists(self):
        for name, case in self.C.items():
            assert case.get("why"), f"{name} does not say what it protects"
