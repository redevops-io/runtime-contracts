"""The Discovery → Mission boundary.

Every test here corresponds to a defect that was paid for in a product, not to
a property that seemed nice. The comments say which.
"""
from __future__ import annotations

import pytest

from runtime_contracts import (
    Amendment,
    Author,
    CapabilityRefusal,
    DecisionEvidence,
    Derivation,
    IntentField,
    OpenReason,
    ReaderKind,
    RefusalKind,
    Unresolved,
    VerifiedIntent,
)


def field(value, author=Author.MODEL, **kw):
    return IntentField(value=value, author=author, **kw)


def intent(**kw):
    base = dict(objective="evaluate_investment_strategy",
                fields={"cadence": field("annual", Author.USER)})
    base.update(kw)
    return VerifiedIntent(**base)


class TestAuthorIsNotProducer:
    """`author` answers who asserted the value; `produced_by` answers which
    runtime version produced the artifact. Conflating them makes a replay that
    diverges after an upgrade undiagnosable."""

    def test_the_same_assertion_from_two_runtime_versions_is_one_intent(self):
        a = intent(produced_by="discovery-runtime@0.4.2")
        b = intent(produced_by="discovery-runtime@0.5.0")
        assert a.intent_hash == b.intent_hash

    def test_but_the_producer_is_still_recorded(self):
        """Otherwise you cannot find the intents produced by a version with a
        known reading bug."""
        assert intent(produced_by="discovery-runtime@0.4.2").to_json()[
            "produced_by"] == "discovery-runtime@0.4.2"

    def test_a_different_author_is_a_different_intent(self):
        """The discriminating half. If author did not participate in identity,
        a value the user stated and the same value a default supplied would be
        indistinguishable — which is the `execution_timing` defect exactly."""
        stated = intent(fields={"cadence": field("annual", Author.USER)})
        defaulted = intent(fields={"cadence": field("annual", Author.DEFAULT)})
        assert stated.intent_hash != defaulted.intent_hash

    def test_only_the_user_is_final(self):
        assert Author.USER.dominates
        for other in (Author.MODEL, Author.READER, Author.POLICY, Author.DEFAULT):
            assert not other.dominates


class TestHowAValueWasReachedIsNotWhatItIs:
    """Same rule `EvidenceCandidate` applies to retrieval scores: re-reading
    changes how confidently a value was reached, not what was asserted."""

    def test_confidence_does_not_change_identity(self):
        sure = intent(fields={"cadence": field("annual", Author.USER, confidence="1")})
        unsure = intent(fields={"cadence": field("annual", Author.USER, confidence="0.6")})
        assert sure.intent_hash == unsure.intent_hash

    def test_neither_does_the_span_or_the_evidence(self):
        bare = intent(fields={"cadence": field("annual", Author.USER)})
        rich = intent(fields={"cadence": field(
            "annual", Author.USER, source_span="every year",
            evidence=[DecisionEvidence("r1", ReaderKind.RULE, "annual")])})
        assert bare.intent_hash == rich.intent_hash

    def test_confidence_is_a_decimal_string_not_a_float(self):
        """Cross-language float formatting is the classic source of hashes that
        agree on one runtime and disagree on another."""
        assert field("x", confidence="1.500").confidence == "1.5"
        assert field("x", confidence="-0.0").confidence == "0"

    def test_a_contested_field_must_carry_its_evidence(self):
        """Recording that readers fought without recording the readings makes
        the fight unreviewable — and unreviewable is how a resolved
        disagreement becomes a fact nobody can question."""
        with pytest.raises(ValueError):
            IntentField(value="crossing", author=Author.USER, contested=True)

    def test_losing_readings_survive(self):
        """A field that was contested and settled is a different fact from one
        never in doubt, and only the first justifies asking again when the
        readers change."""
        f = IntentField(
            value="crossing", author=Author.USER, contested=True,
            evidence=[DecisionEvidence("rule-1", ReaderKind.RULE, "crossing"),
                      DecisionEvidence("model-1", ReaderKind.MODEL, "persistent")])
        values = {e.value for e in f.evidence}
        assert values == {"crossing", "persistent"}
        assert intent(fields={"trigger_semantics": f}).contested_dimensions == [
            "trigger_semantics"]

    def test_no_reader_kind_outranks_another(self):
        """There is deliberately no precedence on `ReaderKind`. Encoding 'the
        model wins' or 'the rule wins' is how one reader's blind spot becomes
        the system's answer."""
        assert not hasattr(ReaderKind, "precedence")
        assert not any(hasattr(k, "wins") for k in ReaderKind)


class TestAbsentUnresolvedAndSettledAreThreeStates:
    """A consumer that collapses them invents a default for a dimension the
    user deliberately left open, or reads a question nobody asked as an
    answer."""

    def test_the_three_states_are_distinguishable(self):
        i = intent(fields={"cadence": field("annual", Author.USER)},
                   unresolved=[Unresolved("day_rule", OpenReason.USER_DECLINED)])
        assert i.state_of("cadence") == "SETTLED"
        assert i.state_of("day_rule") == "OPEN"
        assert i.state_of("rebalancing") == "ABSENT"

    def test_not_asked_differs_from_declined(self):
        assert OpenReason.NOT_ASKED is not OpenReason.USER_DECLINED
        a = intent(unresolved=[Unresolved("day_rule", OpenReason.NOT_ASKED)])
        b = intent(unresolved=[Unresolved("day_rule", OpenReason.USER_DECLINED)])
        assert a.intent_hash != b.intent_hash

    def test_only_unresolved_disagreement_blocks(self):
        """The one state where proceeding means picking a reading nobody
        chose. The other two are answers."""
        assert OpenReason.UNRESOLVED_DISAGREEMENT.blocks_execution
        assert not OpenReason.NOT_ASKED.blocks_execution
        assert not OpenReason.USER_DECLINED.blocks_execution

        blocked = intent(unresolved=[
            Unresolved("trigger_semantics", OpenReason.UNRESOLVED_DISAGREEMENT)])
        assert not blocked.is_executable_in_principle
        assert [u.dimension for u in blocked.blocking] == ["trigger_semantics"]
        # Sealed, because `is_executable_in_principle` now means "closed AND
        # not disputed". A draft is not executable in principle whatever its
        # dimensions say — closure is the first half of the claim.
        assert intent().seal().is_executable_in_principle

    def test_a_dimension_cannot_be_both_settled_and_open(self):
        """A consumer reading one and not the other would act on half a
        decision."""
        with pytest.raises(ValueError) as raised:
            VerifiedIntent(
                objective="o", fields={"cadence": field("annual")},
                unresolved=[Unresolved("cadence", OpenReason.NOT_ASKED)])
        assert "cadence" in str(raised.value)


class TestAmendmentsAreHistoryNotState:
    def test_they_are_kept_in_order_and_not_collapsed(self):
        """"They asked for X" and "they asked for Y, then changed it to X" are
        different histories, and only the second explains why a saved plan does
        not match a sentence."""
        plain = intent()
        amended = intent(amendments=[Amendment("cadence", "monthly", "annual")])
        assert plain.intent_hash != amended.intent_hash

    def test_order_is_part_of_identity(self):
        one = intent(amendments=[Amendment("a", 1, 2), Amendment("b", 3, 4)])
        other = intent(amendments=[Amendment("b", 3, 4), Amendment("a", 1, 2)])
        assert one.intent_hash != other.intent_hash

    def test_when_they_changed_their_mind_is_not_what_they_asked_for(self):
        early = intent(amendments=[Amendment("cadence", "monthly", "annual",
                                             at="2026-01-01T00:00:00Z")])
        late = intent(amendments=[Amendment("cadence", "monthly", "annual",
                                            at="2026-08-08T00:00:00Z")])
        assert early.intent_hash == late.intent_hash


class TestIdentityIsStableAndDiscriminating:
    def test_a_changed_value_changes_the_hash(self):
        assert intent(fields={"cadence": field("annual", Author.USER)}).intent_hash \
            != intent(fields={"cadence": field("monthly", Author.USER)}).intent_hash

    def test_the_hash_is_order_independent_over_fields(self):
        a = VerifiedIntent(objective="o", fields={
            "cadence": field("annual"), "day_rule": field("first")})
        b = VerifiedIntent(objective="o", fields={
            "day_rule": field("first"), "cadence": field("annual")})
        assert a.intent_hash == b.intent_hash

    def test_creation_time_is_not_identity(self):
        assert intent(created_at="2026-01-01T00:00:00Z").intent_hash == \
            intent(created_at="2026-08-08T00:00:00Z").intent_hash

    def test_the_hash_is_prefixed_and_reproducible(self):
        h = intent().intent_hash
        assert h.startswith("rcv1:")
        assert h == intent().intent_hash


class TestDerivationClosesTheChain:
    def test_it_names_the_intent_by_hash_and_the_runtime_by_version(self):
        i = intent()
        d = Derivation(compiled_from=i.intent_hash,
                       compiled_by="mission-runtime@0.6.1",
                       manifest_hash="rcv1:abc")
        assert d.compiled_from == i.intent_hash
        assert d.to_json()["compiled_by"] == "mission-runtime@0.6.1"

    def test_the_manifest_is_named_too(self):
        """Two runtimes at the same version with different manifests reach
        different refusals; without this the disagreement is invisible."""
        assert "manifest_hash" in Derivation("a", "b").to_json()


class TestARefusalNamesWhatItRefused:
    def test_it_carries_the_dimension_and_the_stated_value(self):
        """"This result is unavailable" sends a reader nowhere."""
        r = CapabilityRefusal(
            kind=RefusalKind.UNSUPPORTED_VALUE, dimension="allocation_method",
            stated_value="inverse_volatility",
            executable_values=["equal_weight_at_purchase"])
        out = r.to_json()
        assert out["dimension"] == "allocation_method"
        assert out["stated_value"] == "inverse_volatility"
        assert out["executable_values"] == ["equal_weight_at_purchase"]

    def test_the_kinds_are_distinguishable(self):
        """A dimension the engine models not at all, a value it cannot run, an
        unresolved input, and no data are four different situations and four
        different things for a reader to do next."""
        assert len({RefusalKind.UNSUPPORTED_DIMENSION,
                    RefusalKind.UNSUPPORTED_VALUE,
                    RefusalKind.UNRESOLVED_INPUT,
                    RefusalKind.NO_DATA}) == 4


class TestTheConsumerContract:
    def test_reading_a_value_never_needs_the_prose(self):
        """`utterance_ref` is an id, not the text. A value recovered from
        rendered prose is a value nobody stored."""
        i = intent(utterance_ref="utt-1")
        assert i.utterance_ref == "utt-1"
        assert i.value("cadence") == "annual"
        assert i.author_of("cadence") is Author.USER

    def test_an_unknown_dimension_reads_as_a_default_not_an_error(self):
        assert intent().value("rebalancing") is None
        assert intent().author_of("rebalancing") is None

    def test_user_authored_fields_are_enumerable(self):
        """So a consumer can say "you told us X" without guessing."""
        i = VerifiedIntent(objective="o", fields={
            "cadence": field("annual", Author.USER),
            "day_rule": field("first", Author.DEFAULT)})
        assert i.user_authored == ["cadence"]


# ── sealing: Discovery may not close meaning it has not closed ──────────────

from runtime_contracts import (  # noqa: E402
    IntentState, MissionOutcome, MissionProposal, NotSealable,
)


class TestSealing:
    def test_an_intent_is_a_draft_until_sealed(self):
        """Fail-closed: an intent nobody sealed is a draft, whatever it looks
        like. A consumer executing a DRAFT is executing a guess."""
        assert intent().state is IntentState.DRAFT
        assert not intent().is_verified
        assert not intent().is_executable_in_principle

    def test_sealing_produces_a_verified_intent(self):
        sealed = intent().seal()
        assert sealed.is_verified
        assert sealed.is_executable_in_principle

    def test_sealing_does_not_change_what_it_means(self):
        """The state is about closure, not content. If sealing changed
        identity, a plan pinned before and after would not be the same plan."""
        i = intent()
        assert i.seal().intent_hash == i.intent_hash

    def test_a_result_changing_open_dimension_refuses_to_seal(self):
        """'We ran out of time asking' must not become 'the user agreed'."""
        i = intent(unresolved=[Unresolved("day_rule", OpenReason.NOT_ASKED)])
        with pytest.raises(NotSealable) as raised:
            i.seal()
        assert "day_rule" in str(raised.value)

    def test_open_is_result_changing_unless_someone_says_otherwise(self):
        """The default is the point. Marking something cosmetic is a claim
        someone has to make on purpose."""
        assert Unresolved("x", OpenReason.NOT_ASKED).result_changing

    def test_a_declared_non_result_changing_dimension_may_remain_open(self):
        """The discriminating half: a seal that refused everything would be a
        seal nobody could use, and everyone would route around it."""
        i = intent(unresolved=[Unresolved(
            "dividend_policy", OpenReason.USER_DECLINED,
            detail="engine runs on price series; cannot change a figure",
            result_changing=False)])
        assert i.seal().is_verified

    def test_an_unresolved_disagreement_never_seals(self):
        """Even marked non-result-changing. Two readers disagreeing about what
        was said is not a question about impact."""
        i = intent(unresolved=[Unresolved(
            "trigger_semantics", OpenReason.UNRESOLVED_DISAGREEMENT,
            result_changing=False)])
        with pytest.raises(NotSealable):
            i.seal()

    def test_sealing_is_the_only_route_to_verified(self):
        """A method rather than a constructor argument, so the check cannot be
        skipped by passing the field."""
        forced = VerifiedIntent(objective="o", state=IntentState.VERIFIED,
                                unresolved=[Unresolved("x", OpenReason.NOT_ASKED)])
        # Constructing it is possible — Python has no private fields — but the
        # artifact still reports the open dimension, so a consumer that checks
        # is not fooled.
        assert forced.unsealable


class TestAProposalArguesItDoesNotAuthorise:
    """Discovery ranks what is worth proposing. Mission decides what is
    admissible to execute."""

    def test_it_carries_priority_and_rationale(self):
        p = MissionProposal(intent=intent().seal(), rationale="churn moved",
                            priority="0.910")
        assert p.priority == "0.91"
        assert p.rationale

    def test_it_has_no_authorisation_affordability_or_executability(self):
        """A proposal carrying those would be a second planner wearing a
        discovery hat — which is how 'decides what deserves attention' becomes
        'decides what happens'."""
        fields = set(MissionProposal.__dataclass_fields__)
        assert not fields & {"authorized", "affordable", "executable",
                             "approved", "budget", "policy_decision"}

    def test_a_draft_intent_is_not_actionable(self):
        assert not MissionProposal(intent=intent()).is_actionable
        assert MissionProposal(intent=intent().seal()).is_actionable

    def test_priority_is_a_decimal_string_not_a_float(self):
        assert MissionProposal(intent=intent(), priority="1.0").priority == "1"


class TestWhatMissionMayAnswer:
    def test_reinterpretation_is_not_among_the_outcomes(self):
        """The missing sixth is the point. "I could not do what you meant, so
        I did something else" is not an outcome this boundary permits, and
        every expensive defect in the system that produced this contract had
        exactly that shape."""
        answers = {o.value for o in MissionOutcome}
        assert answers == {"EXECUTABLE", "UNSUPPORTED_CAPABILITY",
                           "NEEDS_APPROVAL", "POLICY_DENIED", "BUDGET_EXCEEDED"}
        assert not any("REINTERPRET" in a or "SUBSTITUT" in a for a in answers)

    def test_only_one_outcome_executes(self):
        assert MissionOutcome.EXECUTABLE.may_execute
        for other in MissionOutcome:
            if other is not MissionOutcome.EXECUTABLE:
                assert not other.may_execute

    def test_needs_approval_is_not_a_meaning_question(self):
        """Mission's gate asks "may I do this?"; Discovery's asks "what did you
        mean?". Merging them merges authorising with authoring."""
        assert MissionOutcome.NEEDS_APPROVAL is not MissionOutcome.UNSUPPORTED_CAPABILITY
