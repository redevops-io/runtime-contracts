"""Non-result-changing NOT_ASKED is provenance, not identity.

A reader asked about a dimension and did not answer. That is worth recording —
`absent` and `asked-but-unanswered` are different facts about how a reading was
produced, and collapsing them loses the difference between "nobody looked" and
"we looked and found nothing". It stays in the serialized artifact.

It is not part of what the request *is*. Two intents differing only in which
dimensions a reader was asked about describe the same request and execute
identically, so carrying it in `intent_hash` made identity move while execution
did not.

Demonstrated before it was changed: two implementations differing only in these
entries were compiled across a 36-case corpus and produced the identical
downstream outcome in every case.

A dimension whose openness *would* change the answer is a different matter and
stays in identity.
"""
from __future__ import annotations

from runtime_contracts import (Author, IntentField, OpenReason, Unresolved,
                               VerifiedIntent)


def _intent(*unresolved):
    return VerifiedIntent(
        objective="do the thing",
        fields={"amount": IntentField(value="500", author=Author.READER,
                                      produced_by="reader@1")},
        unresolved=tuple(unresolved),
        produced_by="reader@1")


BOOKKEEPING = Unresolved(dimension="day_rule", reason=OpenReason.NOT_ASKED,
                         detail="the reader was asked and did not answer",
                         result_changing=False)

MATERIAL = Unresolved(dimension="cadence", reason=OpenReason.NOT_ASKED,
                      detail="nobody said how often", result_changing=True)

DISPUTED = Unresolved(dimension="assets",
                      reason=OpenReason.UNRESOLVED_DISAGREEMENT,
                      detail="two readers disagreed", result_changing=False)


def test_bookkeeping_does_not_change_identity():
    assert _intent().intent_hash == _intent(BOOKKEEPING).intent_hash


def test_a_result_changing_open_dimension_does():
    """The half that keeps the rule honest.

    If openness could change the answer, two intents differing in it are
    different requests, and an identity that ignored that would let a settled
    plan and an unsettled one share a hash.
    """
    assert _intent().intent_hash != _intent(MATERIAL).intent_hash


def test_a_disagreement_is_not_bookkeeping():
    """Only NOT_ASKED is excluded, and only when immaterial.

    An unresolved *disagreement* is a fact about the request even when nothing
    downstream turns on it: two readers read the sentence differently, and an
    intent that hid that would claim a confidence it does not have.
    """
    assert _intent().intent_hash != _intent(DISPUTED).intent_hash


def test_it_is_still_in_the_artifact():
    """Excluded from identity, kept in the record."""
    intent = _intent(BOOKKEEPING)
    assert any(u["dimension"] == "day_rule"
               for u in intent.to_json()["unresolved"]), (
        "the entry was dropped from the serialized artifact, not merely from "
        "identity — that loses the difference between absent and "
        "asked-but-unanswered")


def test_sealing_is_unchanged():
    """Identity moved; the seal did not.

    `unsealable` reads `result_changing`, not `canonical_form`, so excluding an
    immaterial entry from identity must not make an intent sealable that was
    not — or the change would have quietly relaxed the guarantee it was meant
    to leave alone.
    """
    assert not _intent(BOOKKEEPING).unsealable
    assert _intent(MATERIAL).unsealable
