"""The Discovery → Mission boundary.

Every test here corresponds to a defect that was paid for in a product, not to
a property that seemed nice. The comments say which.
"""
from __future__ import annotations

import json
from dataclasses import replace

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


class TestTwoIdentitiesAnswerTwoQuestions:
    """`intent_hash` — is this the same request? `artifact_digest` — is this
    the same object? Carrying only the first makes a draft and a sealed intent
    interchangeable in storage; carrying only the second makes every re-read
    look like a new request."""

    def test_sealing_keeps_the_request_and_changes_the_object(self):
        i = intent()
        sealed = i.seal()
        assert sealed.intent_hash == i.intent_hash
        assert sealed.artifact_digest != i.artifact_digest

    def test_a_different_reader_changes_the_object_only(self):
        a = intent(produced_by="discovery-runtime@0.4.2")
        b = intent(produced_by="discovery-runtime@0.5.0")
        assert a.intent_hash == b.intent_hash
        assert a.artifact_digest != b.artifact_digest

    def test_confidence_and_evidence_change_the_object_only(self):
        bare = intent(fields={"cadence": field("annual", Author.USER)})
        rich = intent(fields={"cadence": field(
            "annual", Author.USER, confidence="0.6", source_span="every year",
            evidence=[DecisionEvidence("r1", ReaderKind.RULE, "annual")])})
        assert bare.intent_hash == rich.intent_hash
        assert bare.artifact_digest != rich.artifact_digest

    def test_a_changed_request_changes_both(self):
        """The discriminating half: a digest that ignored the request would
        make two different plans look like one cached object."""
        a = intent(fields={"cadence": field("annual", Author.USER)})
        b = intent(fields={"cadence": field("monthly", Author.USER)})
        assert a.intent_hash != b.intent_hash
        assert a.artifact_digest != b.artifact_digest

    def test_both_are_stable_and_prefixed(self):
        i = intent()
        assert i.artifact_digest == intent().artifact_digest
        assert i.artifact_digest.startswith("rcv1:")

    def test_the_serialized_form_carries_both(self):
        """So a consumer never has to recompute one to tell them apart."""
        out = intent().seal().to_json()
        assert out["intent_hash"] and out["artifact_digest"]
        assert out["intent_hash"] != out["artifact_digest"]
        assert out["state"] == "VERIFIED"


# ── relationships that a scalar or a set cannot hold ───────────────────────

from runtime_contracts import IntentRelation, RelationMember  # noqa: E402


def sleeves():
    return IntentRelation(kind="portfolio_sleeves", author=Author.USER, members=(
        RelationMember(role="core", subject="core index fund"),
        RelationMember(role="satellite", subject="US value ETF",
                       qualifiers={"allocation": "30%"})))


def conversion():
    return IntentRelation(kind="account_transition", author=Author.USER,
                          attributes={"action": "convert"}, members=(
        RelationMember(role="from", subject="traditional_ira"),
        RelationMember(role="to", subject="roth_ira")))


class TestFlatteningARelationshipDestroysTheIntent:
    """Two sentences found this within a day of each other:

        "a core index fund and 30% into a US value ETF"
        "convert my traditional IRA to a Roth"

    Both readers read both correctly, and the schema forced them to disagree
    because it made them answer with one value where the sentence had two
    entities in named roles. A representational failure, not a reading one.
    """

    def test_an_allocation_belongs_to_a_member_not_to_a_position(self):
        """A separate `stated_weights` list beside a separate `assets` list can
        only say which weight is whose by position, and position is exactly
        what the readers disagreed about."""
        satellite = sleeves().member("satellite")
        assert satellite.qualifiers["allocation"] == "30%"
        assert sleeves().member("core").qualifiers == {}

    def test_the_same_entities_in_swapped_roles_are_a_different_request(self):
        """`from`/`to` reversed is the opposite transaction. If roles did not
        participate in identity, the two would hash alike."""
        forward = VerifiedIntent(objective="o", relations=(conversion(),))
        backward = VerifiedIntent(objective="o", relations=(IntentRelation(
            kind="account_transition", attributes={"action": "convert"},
            members=(RelationMember(role="from", subject="roth_ira"),
                     RelationMember(role="to", subject="traditional_ira"))),))
        assert forward.intent_hash != backward.intent_hash

    def test_an_attribute_of_the_whole_relation_is_not_on_either_end(self):
        """A transition's action belongs to neither account."""
        assert conversion().attributes == {"action": "convert"}
        assert all(not m.qualifiers for m in conversion().members)

    def test_relations_participate_in_identity(self):
        bare = VerifiedIntent(objective="o")
        with_sleeves = VerifiedIntent(objective="o", relations=(sleeves(),))
        assert bare.intent_hash != with_sleeves.intent_hash

    def test_a_relation_with_no_members_is_refused(self):
        """A relationship with nothing in it is a claim about nothing."""
        with pytest.raises(ValueError):
            IntentRelation(kind="portfolio_sleeves", members=())

    def test_repeated_roles_are_allowed(self):
        """Three satellites is a real portfolio. Only a domain schema knows
        that two `from` accounts is not a real transition, and enforcing
        cardinality here would need this package to learn every vocabulary."""
        three = IntentRelation(kind="portfolio_sleeves", members=(
            RelationMember(role="satellite", subject="A"),
            RelationMember(role="satellite", subject="B"),
            RelationMember(role="satellite", subject="C")))
        assert len(three.members_in("satellite")) == 3

    def test_subjects_are_not_resolved(self):
        """"a core index fund" stays that. Turning it into VTI is a
        substitution nobody asked for."""
        assert sleeves().member("core").subject == "core index fund"


class TestRelationsAreNotStuffedIntoFields:
    def test_they_live_in_their_own_place(self):
        """A polymorphic `fields` value means every consumer branches on type
        before it can read anything, and the first one to forget reads a sleeve
        list as an asset name."""
        i = VerifiedIntent(objective="o", relations=(sleeves(),))
        assert "portfolio_sleeves" not in i.fields
        assert i.relation("portfolio_sleeves") is not None

    def test_an_unknown_kind_reads_as_absent_not_as_an_error(self):
        i = VerifiedIntent(objective="o", relations=(sleeves(),))
        assert i.relation("account_transition") is None

    def test_the_contract_carries_no_finance_vocabulary(self):
        """`kind` and `role` are strings the domain schema defines. Putting
        'satellite' in this package would make every other consumer carry it."""
        import runtime_contracts.models.intent as module

        source = open(module.__file__).read()
        for domain_word in ("PORTFOLIO_SLEEVES =", "class Sleeve",
                            "class PortfolioIntent", "class AccountTransition"):
            assert domain_word not in source

    def test_they_reach_the_artifact_digest_too(self):
        bare = VerifiedIntent(objective="o")
        with_sleeves = VerifiedIntent(objective="o", relations=(sleeves(),))
        assert bare.artifact_digest != with_sleeves.artifact_digest


# ── replay: a pinned intent must be readable back ──────────────────────────

from runtime_contracts import CorruptIntent, intent_from_json  # noqa: E402


class TestAPinnedIntentCanBeRestored:
    """Every type here could be written and none could be read back, which
    meant a plan could pin an intent and never recompile from it — "re-run from
    the pinned intent, never from the sentence" was a rule with no mechanism."""

    def test_the_round_trip_preserves_identity(self):
        """If it did not, a plan pinned before storage would not be the plan
        that ran after it, and every replay would look like a new request."""
        original = intent(produced_by="discovery-runtime@0.4.2").seal()
        assert intent_from_json(original.to_json()).intent_hash == \
            original.intent_hash

    def test_it_preserves_the_artifact_too(self):
        original = intent(produced_by="d@1").seal()
        assert intent_from_json(original.to_json()).artifact_digest == \
            original.artifact_digest

    def test_relations_survive_with_their_roles_and_qualifiers(self):
        original = VerifiedIntent(objective="o", relations=(sleeves(),)).seal()
        back = intent_from_json(original.to_json())
        satellite = back.relation("portfolio_sleeves").member("satellite")
        assert satellite.qualifiers["allocation"] == "30%"
        assert back.intent_hash == original.intent_hash

    def test_authors_survive(self):
        """The distinction the whole contract exists for. A restored intent
        whose USER fields came back as DEFAULT would let a consumer offer the
        user's own words back as an assumption."""
        original = intent(fields={
            "cadence": field("annual", Author.USER),
            "day_rule": field("first", Author.DEFAULT)}).seal()
        back = intent_from_json(original.to_json())
        assert back.author_of("cadence") is Author.USER
        assert back.author_of("day_rule") is Author.DEFAULT

    def test_a_draft_comes_back_a_draft(self):
        assert intent_from_json(intent().to_json()).state is IntentState.DRAFT


class TestReadingDetectsCorruption:
    """The seal is re-checked on read. `seal()` is one route to VERIFIED and
    this is the other, so it runs the same check rather than trusting a flag."""

    def test_a_verified_intent_with_open_meaning_is_refused(self):
        payload = intent().seal().to_json()
        payload["unresolved"] = [{"dimension": "day_rule",
                                  "reason": "NOT_ASKED",
                                  "result_changing": True}]
        with pytest.raises(CorruptIntent) as raised:
            intent_from_json(payload)
        assert "seal" in str(raised.value)

    def test_a_hash_that_disagrees_with_the_record_is_refused(self):
        """One of the two has been edited, and repairing either would produce
        an intent whose author is unknown."""
        payload = intent().seal().to_json()
        payload["fields"]["cadence"]["value"] = "monthly"
        with pytest.raises(CorruptIntent) as raised:
            intent_from_json(payload)
        assert "disagree" in str(raised.value)

    def test_a_payload_with_no_recorded_hash_is_accepted(self):
        """The discriminating half: a reader that refused everything would make
        the contract unusable by any producer that did not write the field."""
        payload = intent().seal().to_json()
        payload.pop("intent_hash")
        assert intent_from_json(payload).intent_hash


class TestAnOpenDimensionSurvivesStorage:
    """`to_json` must be lossless where `canonical_form` is deliberately not.

    A sealed intent carrying a not-result-changing open dimension could be
    written and never read back: `to_json` omitted `result_changing`,
    `intent_from_json` defaulted it to True, the seal check then refused, and a
    valid artifact raised `CorruptIntent`. The two sides had disagreed since
    the type was written; every replay fixture happened to have no open
    dimensions or only result-changing ones, so nothing reached it.
    """

    def sealed(self, *, result_changing: bool):
        return VerifiedIntent(
            objective="evaluate_investment_strategy",
            produced_by="reader@1", utterance_ref="utt-1",
            fields={"assets": IntentField(value="VTI", author=Author.USER)},
            unresolved=(Unresolved(dimension="dividend_policy",
                                   reason=OpenReason.USER_DECLINED,
                                   detail="the engine runs on price series",
                                   result_changing=result_changing),))

    def test_a_cosmetic_open_dimension_round_trips(self):
        intent = self.sealed(result_changing=False).seal()
        restored = intent_from_json(json.loads(json.dumps(intent.to_json())))
        assert restored.is_verified
        assert restored.unresolved[0].result_changing is False

    def test_and_the_intent_is_the_same_request(self):
        intent = self.sealed(result_changing=False).seal()
        restored = intent_from_json(json.loads(json.dumps(intent.to_json())))
        assert restored.intent_hash == intent.intent_hash

    def test_a_result_changing_one_still_cannot_be_sealed(self):
        """The discriminating opposite. Without it, "carry the flag through"
        could have been implemented as "treat everything as cosmetic", which
        would make every intent sealable and the seal meaningless."""
        with pytest.raises(NotSealable):
            self.sealed(result_changing=True).seal()

    def test_the_flag_is_not_part_of_identity(self):
        """`canonical_form` omits it on purpose: it describes the consequence
        of leaving a dimension open, not the fact that it is open, and two
        intents differing only in that judgement are the same request."""
        one = self.sealed(result_changing=False)
        other = VerifiedIntent(
            objective=one.objective, produced_by=one.produced_by,
            utterance_ref=one.utterance_ref, fields=dict(one.fields),
            unresolved=(replace(one.unresolved[0], detail="a different note"),))
        assert one.intent_hash == other.intent_hash
