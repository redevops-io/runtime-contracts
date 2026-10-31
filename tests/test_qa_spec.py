"""TestSpec, Step, the tagged target union and the frozen assertion rule.

The assertions are frozen structurally: frozen dataclasses holding tuples and FrozenMap, referenced by the hash of
their whole canonical form, recomputed from content on every read. These tests pin that, and pin each guard.
"""
from __future__ import annotations

import dataclasses
import unicodedata

import pytest

from golden.qa_samples import d, h, resource_step, script_assertion, ui_assertion, ui_spec, ui_step, url_assertion
from runtime_contracts import canonical
from runtime_contracts.models.capability import Idempotency, RetrySafety, SideEffect
from runtime_contracts.models.verification import Determinism, Verdict
from runtime_contracts.protocol.secrets import SecretRef
from runtime_contracts.qa import (Action, ActionKind, AssertionIntegrityError, AssertionSpec, AssertionSubject,
                                  Budget, Code, ComponentRef, Executor, FixtureRef, FrozenMap,
                                  LocatorDescriptor, PermittedRecovery, Predicate, PredicateOp, QAContractError,
                                  ResourceKind, ResourceRef, Step, StepTarget, SubjectKind, TargetKind, TestSpec,
                                  TestTarget, UnknownEnumValue, assertion_set_hash, assertions_changed,
                                  executor_certifies, make_spec_ref, required_approvals, split_spec_ref,
                                  verify_assertion_set)


def codes(exc: pytest.ExceptionInfo) -> str:
    return exc.value.code


class TestLocatorsAndResources:
    def test_an_empty_locator_is_refused(self):
        with pytest.raises(QAContractError):
            LocatorDescriptor()

    def test_frame_path_order_is_meaning(self):
        a = LocatorDescriptor(role="button", frame_path=("outer", "inner"))
        b = LocatorDescriptor(role="button", frame_path=("inner", "outer"))
        assert a.value_hash() != b.value_hash()

    @pytest.mark.parametrize("kind,fields", [
        (ResourceKind.MANIFEST_PATH, dict(path="k8s/a.yaml")),
        (ResourceKind.IMAGE_DIGEST, dict(digest=d(1))),
        (ResourceKind.NAMESPACE_OBJECT, dict(api_version="apps/v1", object_kind="Deployment", namespace="web",
                                              name="api")),
    ])
    def test_each_resource_kind_has_its_typed_fields(self, kind, fields):
        assert ResourceRef(kind=kind, **fields).kind is kind

    @pytest.mark.parametrize("kind,fields", [
        (ResourceKind.MANIFEST_PATH, dict()),
        (ResourceKind.MANIFEST_PATH, dict(path="a.yaml", digest=d(1))),
        (ResourceKind.IMAGE_DIGEST, dict(path="a.yaml")),
        (ResourceKind.IMAGE_DIGEST, dict(digest="sha256:" + "0" * 12)),
        (ResourceKind.NAMESPACE_OBJECT, dict(api_version="v1", object_kind="Pod", name="p")),
    ])
    def test_a_resource_with_the_wrong_fields_is_refused(self, kind, fields):
        with pytest.raises(QAContractError):
            ResourceRef(kind=kind, **fields)

    @pytest.mark.parametrize("path", ["/etc/passwd", "../x", "a/../b", "a//b", "./a", "C:/a", "a\\b", "a/."])
    def test_manifest_paths_stay_inside_the_case_root(self, path):
        with pytest.raises(QAContractError):
            ResourceRef(kind=ResourceKind.MANIFEST_PATH, path=path)


class TestStepTarget:
    def test_ui_target_carries_a_locator_only(self):
        t = StepTarget.ui(LocatorDescriptor(role="button"))
        assert t.kind is TargetKind.UI and t.resource is None
        with pytest.raises(QAContractError):
            StepTarget(TargetKind.UI)
        with pytest.raises(QAContractError):
            StepTarget(TargetKind.UI, locator=LocatorDescriptor(role="b"),
                       resource=ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="a"))

    def test_resource_target_carries_a_resource_only(self):
        with pytest.raises(QAContractError):
            StepTarget(TargetKind.RESOURCE, locator=LocatorDescriptor(role="b"))
        with pytest.raises(QAContractError):
            StepTarget(TargetKind.RESOURCE)

    def test_the_union_round_trips_through_json(self):
        for step in (ui_step(), resource_step()):
            assert Step.from_json(step.to_json()) == step

    def test_the_tag_is_hashed(self):
        ref = ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="a.yaml")
        assert StepTarget.for_resource(ref).canonical_form()["kind"] == "resource"
        assert StepTarget.ui(LocatorDescriptor(role="b")).canonical_form()["kind"] == "ui"


class TestStep:
    def test_action_must_fit_the_target_kind(self):
        with pytest.raises(QAContractError) as e:
            Step(step_id="x", intent="i", target=StepTarget.ui(LocatorDescriptor(role="b")),
                 action=Action(ActionKind.RESOLVE), expected_transition="t", observation_deadline_ms=10,
                 side_effect=SideEffect.NONE)
        assert codes(e) == Code.SPEC_INVALID
        with pytest.raises(QAContractError):
            Step(step_id="x", intent="i",
                 target=StepTarget.for_resource(ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="a")),
                 action=Action(ActionKind.CLICK), expected_transition="t", observation_deadline_ms=10,
                 side_effect=SideEffect.NONE)

    def test_value_actions_carry_exactly_one_of_value_or_secret(self):
        with pytest.raises(QAContractError):
            Action(ActionKind.FILL)
        with pytest.raises(QAContractError):
            Action(ActionKind.FILL, value="x", secret_ref=SecretRef(provider="env", path="P"))
        with pytest.raises(QAContractError):
            Action(ActionKind.CLICK, value="x")
        assert Action(ActionKind.FILL, secret_ref=SecretRef(provider="env", path="PASSWORD")).value is None

    def test_a_secret_action_round_trips_and_never_carries_a_value(self):
        step = dataclasses.replace(ui_step(), action=Action(ActionKind.FILL, secret_ref=SecretRef(provider="env",
                                                                                                   path="PW")))
        assert Step.from_json(step.to_json()) == step

    def test_retry_same_needs_an_idempotent_step(self):
        for idem in (Idempotency.UNKNOWN, Idempotency.AT_MOST_ONCE):
            with pytest.raises(QAContractError):
                dataclasses.replace(ui_step(), idempotency=idem, permitted_recovery=(PermittedRecovery.RETRY_SAME,))
        ok = dataclasses.replace(ui_step(), idempotency=Idempotency.IDEMPOTENT,
                                 permitted_recovery=(PermittedRecovery.RETRY_SAME,))
        assert PermittedRecovery.RETRY_SAME in ok.permitted_recovery

    def test_safe_retries_and_at_most_once_contradict(self):
        with pytest.raises(QAContractError):
            dataclasses.replace(ui_step(), idempotency=Idempotency.AT_MOST_ONCE, retry_safety=RetrySafety.SAFE)

    @pytest.mark.parametrize("rec", [PermittedRecovery.SEMANTIC_LOCATOR, PermittedRecovery.MODEL_CANDIDATE])
    def test_a_resource_step_has_no_locator_to_heal(self, rec):
        with pytest.raises(QAContractError):
            dataclasses.replace(resource_step(), permitted_recovery=(rec,))

    def test_permitted_recovery_is_an_ordered_independent_set(self):
        a = dataclasses.replace(ui_step(), permitted_recovery=(PermittedRecovery.RESET_FIXTURE,
                                                               PermittedRecovery.SEMANTIC_LOCATOR))
        b = dataclasses.replace(ui_step(), permitted_recovery=(PermittedRecovery.SEMANTIC_LOCATOR,
                                                               PermittedRecovery.RESET_FIXTURE))
        assert a == b

    def test_unknown_recovery_kind_fails_closed(self):
        with pytest.raises(UnknownEnumValue):
            dataclasses.replace(ui_step(), permitted_recovery=("TELEPORT",))

    def test_side_effect_has_no_default(self):
        with pytest.raises(TypeError):
            Step(step_id="x", intent="i", target=StepTarget.ui(LocatorDescriptor(role="b")),
                 action=Action(ActionKind.CLICK), expected_transition="t", observation_deadline_ms=10)

    def test_idempotency_defaults_to_unknown(self):
        s = Step(step_id="x", intent="i", target=StepTarget.ui(LocatorDescriptor(role="b")),
                 action=Action(ActionKind.CLICK), expected_transition="t", observation_deadline_ms=10,
                 side_effect=SideEffect.NONE)
        assert s.idempotency is Idempotency.UNKNOWN and s.retry_safety is RetrySafety.UNSAFE


class TestPredicate:
    def test_exists_and_absent_take_no_expected(self):
        assert Predicate(PredicateOp.EXISTS).expected is None
        with pytest.raises(QAContractError):
            Predicate(PredicateOp.ABSENT, "x")

    def test_other_ops_need_an_expected_value(self):
        with pytest.raises(QAContractError):
            Predicate(PredicateOp.EQUALS)

    @pytest.mark.parametrize("bad", ["1.0", "01", 5, "abc", "1e3", "+1"])
    def test_ordering_ops_take_canonical_decimal_strings(self, bad):
        with pytest.raises(QAContractError):
            Predicate(PredicateOp.GREATER_THAN, bad)

    def test_canonical_decimal_is_accepted(self):
        assert Predicate(PredicateOp.LESS_THAN, "12.5").expected == "12.5"

    def test_floats_are_refused_everywhere(self):
        with pytest.raises(QAContractError) as e:
            Predicate(PredicateOp.EQUALS, 1.5)
        assert codes(e) == Code.FLOAT_REFUSED

    def test_unknown_op_fails_closed(self):
        with pytest.raises(UnknownEnumValue):
            Predicate("ROUGHLY", "x")  # type: ignore[arg-type]


class TestAssertionSpec:
    def test_executor_is_required(self):
        j = ui_assertion().to_json()
        del j["executor"]
        j.pop("content_hash")
        with pytest.raises(QAContractError) as e:
            AssertionSpec.from_json(j)
        assert codes(e) == Code.MISSING_FIELD
        with pytest.raises(TypeError):
            AssertionSpec(assertion_id="a", subject=ui_assertion().subject, predicate=ui_assertion().predicate,
                          verifier_id="v", verifier_version_range=">=1")  # type: ignore[call-arg]

    def test_an_unknown_executor_is_non_certifying(self):
        assert executor_certifies("PLAYWRIGHT") and executor_certifies("SCRIPT")
        assert not executor_certifies("TELEPATHY")
        j = ui_assertion().to_json()
        j["executor"] = "TELEPATHY"
        j.pop("content_hash")
        with pytest.raises(UnknownEnumValue):
            AssertionSpec.from_json(j)

    def test_executor_is_part_of_the_hash(self):
        playwright = ui_assertion()
        script = dataclasses.replace(script_assertion(), assertion_id=playwright.assertion_id,
                                     predicate=playwright.predicate, requirement_ref=playwright.requirement_ref)
        assert script.assertion_hash != playwright.assertion_hash
        assert assertion_set_hash([script]) != assertion_set_hash([playwright])
        assert playwright.to_json()["executor"] == "PLAYWRIGHT"

    def test_executor_must_match_the_subject_it_reads(self):
        with pytest.raises(QAContractError):
            AssertionSpec(assertion_id="a", executor=Executor.SCRIPT,
                          subject=AssertionSubject(kind=SubjectKind.URL, pattern="/x"),
                          predicate=Predicate(PredicateOp.EXISTS), verifier_id="v", verifier_version_range=">=1")
        with pytest.raises(QAContractError):
            AssertionSpec(assertion_id="a", executor=Executor.PLAYWRIGHT,
                          subject=AssertionSubject(kind=SubjectKind.RESOURCE_INPUTS, inputs=(
                              ResourceRef(kind=ResourceKind.MANIFEST_PATH, path="a"),)),
                          predicate=Predicate(PredicateOp.EXISTS), verifier_id="v", verifier_version_range=">=1")

    def test_requirement_ref_is_hashed(self):
        assert ui_assertion(requirement_ref="REQ-1").assertion_hash != ui_assertion(requirement_ref="REQ-2").assertion_hash

    def test_an_assertion_without_requirement_ref_hashes_as_if_the_field_never_existed(self):
        a = ui_assertion(requirement_ref=None)
        form = a.canonical_form()
        assert form.get("requirement_ref") is None
        assert a.assertion_hash == canonical.content_hash({k: v for k, v in form.items() if k != "requirement_ref"})

    @pytest.mark.parametrize("bad", ["has space", "a" * 129, "REQ#1", "", "REQ\u00e9"])
    def test_requirement_ref_charset_and_length(self, bad):
        with pytest.raises(QAContractError):
            ui_assertion(requirement_ref=bad)

    def test_requirement_ref_accepts_the_documented_charset(self):
        assert ui_assertion(requirement_ref="A-z0.9_:/x").requirement_ref == "A-z0.9_:/x"
        assert ui_assertion(requirement_ref="r" * 128)

    def test_a_gating_assertion_is_deterministic(self):
        with pytest.raises(QAContractError):
            dataclasses.replace(ui_assertion(), determinism=Determinism.NON_DETERMINISTIC)

    @pytest.mark.parametrize("verdict", [Verdict.PASS, Verdict.FAIL, Verdict.NOT_APPLICABLE])
    def test_unresolvable_subject_is_indeterminate_and_nothing_else(self, verdict):
        with pytest.raises(QAContractError):
            dataclasses.replace(ui_assertion(), on_unresolvable=verdict)

    def test_the_fixed_fields_are_in_the_hash(self):
        form = ui_assertion().canonical_form()
        assert form["determinism"] == "DETERMINISTIC" and form["on_unresolvable"] == "INDETERMINATE"

    def test_expected_hash_is_the_predicate_hash(self):
        assert ui_assertion().expected_hash == Predicate(PredicateOp.EQUALS, "Saved").value_hash()
        assert ui_assertion(expected="Other").expected_hash != ui_assertion().expected_hash

    def test_subject_alternates_are_hashed_and_ordered(self):
        loc = LocatorDescriptor(test_id="a")
        base = AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=loc)
        one = AssertionSubject(kind=SubjectKind.UI_ELEMENT, locator=loc,
                               subject_alternates=(LocatorDescriptor(role="status"),))
        assert base.value_hash() != one.value_hash()

    @pytest.mark.parametrize("kwargs", [
        dict(kind=SubjectKind.UI_ELEMENT),
        dict(kind=SubjectKind.UI_ELEMENT, locator=LocatorDescriptor(role="b"), pattern="x"),
        dict(kind=SubjectKind.URL),
        dict(kind=SubjectKind.URL, pattern="/x", locator=LocatorDescriptor(role="b")),
        dict(kind=SubjectKind.RESPONSE, pattern="/x", subject_alternates=(LocatorDescriptor(role="b"),)),
        dict(kind=SubjectKind.RESOURCE_INPUTS),
    ])
    def test_subject_fields_must_match_the_kind(self, kwargs):
        with pytest.raises(QAContractError):
            AssertionSubject(**kwargs)

    def test_round_trip(self):
        a = ui_assertion()
        assert AssertionSpec.from_json(a.to_json()) == a


class TestTestSpec:
    def test_round_trip_keeps_custody_and_the_hash(self):
        spec = ui_spec(reviewer="rev-1", approved_at="2026-10-30T00:00:00Z")
        again = TestSpec.from_json(spec.to_json())
        assert again == spec and again.author == "author-1" and again.spec_hash == spec.spec_hash

    def test_custody_is_not_identity(self):
        a = ui_spec(author="a", reviewer=None)
        b = ui_spec(author="b", reviewer="r", approved_at="2026-10-30T00:00:00Z")
        assert a.spec_hash == b.spec_hash

    def test_the_spec_hash_moves_with_every_identity_part(self):
        base = ui_spec().spec_hash
        assert ui_spec(version=2).spec_hash != base
        assert ui_spec(budget=Budget(deadline_ms=1)).spec_hash != base
        assert ui_spec(assertions=(ui_assertion(expected="x"), url_assertion())).spec_hash != base
        assert ui_spec(egress_profile="other").spec_hash != base

    def test_spec_ref_format(self):
        spec = ui_spec()
        assert spec.spec_ref == f"checkout-save@{spec.spec_hash}"
        assert split_spec_ref(spec.spec_ref) == ("checkout-save", spec.spec_hash)
        with pytest.raises(QAContractError):
            make_spec_ref("x", "rcv1:abc")
        with pytest.raises(QAContractError):
            split_spec_ref("no-hash")

    def test_a_spec_with_no_assertion_is_refused(self):
        with pytest.raises(QAContractError) as e:
            ui_spec(assertions=())
        assert codes(e) == Code.SPEC_INVALID

    def test_duplicate_step_ids_are_refused(self):
        with pytest.raises(QAContractError) as e:
            ui_spec(steps=(ui_step("s1"), ui_step("s1", name="Other")))
        assert codes(e) == Code.DUPLICATE_ENTRY

    def test_duplicate_assertion_ids_are_refused(self):
        with pytest.raises(QAContractError) as e:
            ui_spec(assertions=(ui_assertion("a"), ui_assertion("a", expected="x")))
        assert codes(e) == Code.DUPLICATE_ENTRY

    def test_a_step_side_effect_must_be_allowed_by_the_spec(self):
        with pytest.raises(QAContractError):
            ui_spec(allowed_side_effects=())
        spec = ui_spec(steps=(resource_step(),), allowed_side_effects=())
        assert spec.allowed_side_effects == ()

    def test_depends_on_is_a_set_of_spec_refs_and_never_the_spec_itself(self):
        a, b = "dep-a@" + h(1), "dep-b@" + h(2)
        assert ui_spec(depends_on=(b, a)).depends_on == (a, b)
        with pytest.raises(QAContractError):
            ui_spec(depends_on=("checkout-save@" + h(3),))
        with pytest.raises(QAContractError):
            ui_spec(depends_on=("dep-a",))

    def test_assertions_are_an_order_independent_set(self):
        a, b = ui_assertion("a1"), url_assertion("a2")
        assert ui_spec(assertions=(a, b)).spec_hash == ui_spec(assertions=(b, a)).spec_hash

    def test_fixtures_carry_full_width_digests(self):
        with pytest.raises(QAContractError):
            FixtureRef(id="f", content_hash="sha256:" + "0" * 16)

    def test_version_is_a_positive_integer(self):
        for bad in (0, -1, "1", 1.0):
            with pytest.raises(QAContractError):
                ui_spec(version=bad)

    def test_budget_bounds(self):
        with pytest.raises(QAContractError):
            Budget(deadline_ms=0)
        with pytest.raises(QAContractError):
            Budget(deadline_ms=1000, max_retries=-1)
        assert Budget(deadline_ms=1000).max_model_calls == 0    # model use is off unless granted

    def test_target_build_sha(self):
        with pytest.raises(QAContractError):
            TestTarget(app_id="a", build_sha="xyz", environment_profile="e")

    def test_a_resource_only_spec(self):
        spec = ui_spec("infra-1", steps=(resource_step(),), assertions=(script_assertion(),),
                       allowed_side_effects=())
        assert TestSpec.from_json(spec.to_json()) == spec


class TestFrozenAssertionRule:
    """Assertions are referenced by hash and there is no mutation path."""

    def test_attribute_assignment_is_refused_at_every_level(self):
        spec = ui_spec()
        a = spec.assertions[0]
        for obj, name in ((spec, "assertions"), (a, "predicate"), (a.predicate, "expected"),
                          (a.subject, "locator"), (a.subject.locator, "test_id")):
            with pytest.raises(dataclasses.FrozenInstanceError):
                setattr(obj, name, None)
            with pytest.raises(dataclasses.FrozenInstanceError):
                delattr(obj, name)

    def test_containers_are_tuples_and_json_is_frozen(self):
        spec = ui_spec()
        assert isinstance(spec.assertions, tuple) and isinstance(spec.steps, tuple)
        a = ui_assertion(expected={"k": ["v"]})
        assert isinstance(a.predicate.expected, FrozenMap)
        with pytest.raises(TypeError):
            a.predicate.expected["k"] = "other"   # type: ignore[index]
        with pytest.raises(TypeError):
            spec.assertions[0] = a                # type: ignore[index]

    def test_there_is_no_method_that_returns_an_edited_assertion(self):
        verbs = ("set", "update", "replace", "with_", "mutate", "edit", "patch", "heal", "amend", "modify")
        for cls in (AssertionSpec, TestSpec, Predicate, AssertionSubject):
            public = [n for n in dir(cls) if not n.startswith("_")]
            offenders = [n for n in public if n.startswith(verbs)]
            assert not offenders, f"{cls.__name__} exposes {offenders}"

    def test_the_pinned_hash_verifies_untouched_assertions(self):
        spec = ui_spec()
        verify_assertion_set(spec.assertions, spec.assertion_set_hash)

    def test_a_changed_expected_value_is_refused_by_the_pinned_hash(self):
        spec = ui_spec()
        changed = (ui_assertion(expected="Something else"), url_assertion())
        with pytest.raises(AssertionIntegrityError) as e:
            verify_assertion_set(changed, spec.assertion_set_hash)
        assert e.value.code == Code.ASSERTION_HASH_MISMATCH
        assert (e.value.run_outcome, e.value.run_reason) == ("INCONCLUSIVE", "ASSERTION_INTEGRITY")

    def test_a_removed_or_added_assertion_is_refused(self):
        spec = ui_spec()
        with pytest.raises(AssertionIntegrityError):
            verify_assertion_set(spec.assertions[:1], spec.assertion_set_hash)
        with pytest.raises(AssertionIntegrityError):
            verify_assertion_set((*spec.assertions, ui_assertion("extra")), spec.assertion_set_hash)

    def test_bypassing_the_frozen_type_still_does_not_survive_verification(self):
        """The hash is recomputed from content on every read, never cached, so even object.__setattr__ is caught."""
        spec = ui_spec()
        pinned = spec.assertion_set_hash
        object.__setattr__(spec.assertions[0], "requirement_ref", "REQ-HACKED")
        assert spec.assertion_set_hash != pinned
        with pytest.raises(AssertionIntegrityError):
            verify_assertion_set(spec.assertions, pinned)

    def test_the_set_hash_is_stable_across_order_and_unicode_form(self):
        a = ui_assertion("a1", expected="caf\u00e9")
        b = ui_assertion("a1", expected=unicodedata.normalize("NFD", "caf\u00e9"))
        c = url_assertion("a2")
        assert assertion_set_hash([a, c]) == assertion_set_hash([c, b])

    @pytest.mark.parametrize("change", [
        dict(expected="x"), dict(requirement_ref="REQ-X"), dict(test_id="other"), dict(op=PredicateOp.CONTAINS),
    ])
    def test_the_set_hash_changes_when_any_frozen_part_changes(self, change):
        assert assertion_set_hash([ui_assertion(**change)]) != assertion_set_hash([ui_assertion()])

    def test_a_locator_descriptor_change_changes_the_set_hash(self):
        a = ui_assertion()
        b = dataclasses.replace(a, subject=AssertionSubject(kind=SubjectKind.UI_ELEMENT,
                                                            locator=LocatorDescriptor(test_id="save-status",
                                                                                      frame_path=("f",))))
        assert assertion_set_hash([a]) != assertion_set_hash([b])

    def test_the_set_hash_does_not_depend_on_spec_custody_or_steps(self):
        a, b = ui_spec(author="x"), ui_spec(author="y", steps=(ui_step(name="Submit"),))
        assert a.assertion_set_hash == b.assertion_set_hash
        assert a.spec_hash != b.spec_hash

    def test_the_set_hash_refuses_a_duplicate_id(self):
        with pytest.raises(QAContractError):
            assertion_set_hash([ui_assertion("a"), ui_assertion("a", expected="x")])

    def test_changing_an_assertion_is_a_new_version_needing_two_approvals(self):
        v1 = ui_spec(version=1)
        v2_same = ui_spec(version=2, steps=(ui_step(name="Submit"),))
        v2_changed = ui_spec(version=2, assertions=(ui_assertion(expected="x"), url_assertion()))
        assert not assertions_changed(v1, v2_same) and assertions_changed(v1, v2_changed)
        assert required_approvals(v1, v2_same) == 1
        assert required_approvals(v1, v2_changed) == 2

    def test_a_successor_is_the_same_spec_at_a_higher_version(self):
        v1 = ui_spec(version=1)
        with pytest.raises(QAContractError):
            required_approvals(v1, ui_spec(version=1))
        with pytest.raises(QAContractError):
            required_approvals(v1, ui_spec("other-spec", version=2))

    def test_the_spec_cannot_be_given_a_different_assertion_hash_by_any_codec_path(self):
        spec = ui_spec()
        j = spec.to_json()
        j["assertions"][0]["predicate"]["expected"] = "Changed"
        with pytest.raises(QAContractError) as e:
            TestSpec.from_json(j)
        assert e.value.code == Code.HASH_MISMATCH   # the nested assertion's stored hash no longer matches


def test_component_ref_format():
    assert ComponentRef(id="p", version="0.1.0").value_hash().startswith("rcv1:")
    with pytest.raises(QAContractError):
        ComponentRef(id="p", version="")
