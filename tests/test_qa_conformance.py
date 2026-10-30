"""Refusals against the frozen spec: executor, expected, manifest pins and recovery payloads."""
from __future__ import annotations

import dataclasses

import pytest

from golden.qa_samples import assertion_result, h, run_manifest, script_assertion, ui_assertion, ui_spec, url_assertion
from runtime_contracts.qa import (AssertionIntegrityError, Code, Executor, LocatorCandidate, LocatorStrategy,
                                  Outcome, QAContractError, check_result_matches_assertion,
                                  parse_recovery_candidate, parse_recovery_candidates, verify_manifest_against_spec)

SPEC = ui_spec()


class TestResultMatchesAssertion:
    def test_a_matching_result_is_accepted(self):
        for a in SPEC.assertions:
            check_result_matches_assertion(assertion_result(a, SPEC), a)

    def test_a_result_with_a_different_executor_is_refused(self):
        a = SPEC.assertions[0]
        r = dataclasses.replace(assertion_result(a, SPEC), executor=Executor.SCRIPT)
        with pytest.raises(AssertionIntegrityError) as e:
            check_result_matches_assertion(r, a)
        assert e.value.code == Code.EXECUTOR_MISMATCH
        assert (e.value.run_outcome, e.value.run_reason) == ("INCONCLUSIVE", "ASSERTION_INTEGRITY")

    def test_a_verifier_handed_a_different_expected_value_is_refused(self):
        a = SPEC.assertions[0]
        r = assertion_result(ui_assertion(expected="a different expected value"), SPEC)
        with pytest.raises(AssertionIntegrityError) as e:
            check_result_matches_assertion(r, a)
        assert e.value.code == Code.EXPECTED_MISMATCH

    def test_a_result_for_another_assertion_is_refused(self):
        with pytest.raises(AssertionIntegrityError):
            check_result_matches_assertion(assertion_result(SPEC.assertions[1], SPEC), SPEC.assertions[0])

    def test_a_script_result_for_a_script_assertion(self):
        a = script_assertion()
        spec = ui_spec(assertions=(a,), steps=(), allowed_side_effects=())
        check_result_matches_assertion(assertion_result(a, spec), a)


class TestManifestMatchesSpec:
    def test_a_run_of_the_spec_is_accepted(self):
        verify_manifest_against_spec(run_manifest(SPEC), SPEC)

    def test_a_run_that_pinned_a_different_assertion_set_is_refused(self):
        changed = ui_spec(assertions=(ui_assertion(expected="x"), url_assertion()))
        with pytest.raises(AssertionIntegrityError) as e:
            verify_manifest_against_spec(run_manifest(changed), SPEC)
        assert e.value.code == Code.ASSERTION_HASH_MISMATCH

    def test_a_manifest_that_declares_other_assertions_is_refused(self):
        m = run_manifest(SPEC, assertions_declared=("a-saved", "a-other"), assertions_executed=("a-saved",),
                         assertions_skipped=(), outcome=Outcome.INCONCLUSIVE, outcome_reason="ASSERTION_INTEGRITY",
                         assertion_results=(assertion_result(SPEC.assertions[0], SPEC),))
        with pytest.raises(AssertionIntegrityError) as e:
            verify_manifest_against_spec(m, SPEC)
        assert e.value.code == Code.COVERAGE_VIOLATION

    def test_a_manifest_for_a_different_spec_version_is_refused(self):
        newer = ui_spec(version=2)
        with pytest.raises(AssertionIntegrityError):
            verify_manifest_against_spec(run_manifest(newer), SPEC)

    def test_a_result_with_the_wrong_executor_inside_the_manifest_is_refused(self):
        bad = dataclasses.replace(assertion_result(SPEC.assertions[0], SPEC), executor=Executor.SCRIPT)
        m = run_manifest(SPEC, assertion_results=(bad, assertion_result(SPEC.assertions[1], SPEC)))
        with pytest.raises(AssertionIntegrityError) as e:
            verify_manifest_against_spec(m, SPEC)
        assert e.value.code == Code.EXECUTOR_MISMATCH


class TestRecoveryPayloads:
    GOOD = dict(strategy="SEMANTIC_ALTERNATE", role="button", name="Save")

    def test_a_strict_candidate_is_accepted(self):
        c = parse_recovery_candidate(self.GOOD)
        assert isinstance(c, LocatorCandidate) and c.strategy is LocatorStrategy.SEMANTIC_ALTERNATE
        assert c.as_descriptor().role == "button"
        assert LocatorCandidate.from_json(c.to_json()) == c

    @pytest.mark.parametrize("extra", [
        dict(expected="Anything"),
        dict(assertion={"assertion_id": "a-saved", "predicate": {"op": "EQUALS", "expected": "x"}}),
        dict(assertions=[{"assertion_id": "a"}]),
        dict(assertion_set_hash=h(1)),
        dict(predicate={"op": "EXISTS"}),
        dict(note="free form text"),
        dict(selector="#save"),
    ])
    def test_any_key_outside_the_candidate_schema_is_refused_as_an_integrity_violation(self, extra):
        with pytest.raises(AssertionIntegrityError) as e:
            parse_recovery_candidate({**self.GOOD, **extra})
        assert e.value.code == Code.RECOVERY_PAYLOAD_REJECTED
        assert (e.value.run_outcome, e.value.run_reason) == ("INCONCLUSIVE", "ASSERTION_INTEGRITY")

    @pytest.mark.parametrize("bad", ["assertion text", ["x"], 7, None])
    def test_a_candidate_must_be_an_object(self, bad):
        with pytest.raises(AssertionIntegrityError):
            parse_recovery_candidate(bad)

    def test_the_authored_strategy_is_not_a_candidate(self):
        with pytest.raises(AssertionIntegrityError):
            parse_recovery_candidate({**self.GOOD, "strategy": "AUTHORED"})

    def test_a_candidate_with_no_locator_part_is_refused(self):
        with pytest.raises(AssertionIntegrityError):
            parse_recovery_candidate({"strategy": "MODEL_CANDIDATE"})

    def test_unknown_strategy_is_refused(self):
        with pytest.raises(AssertionIntegrityError):
            parse_recovery_candidate({**self.GOOD, "strategy": "PSYCHIC"})

    def test_a_list_is_parsed_whole_or_refused_whole(self):
        ok = parse_recovery_candidates([self.GOOD, {"strategy": "MODEL_CANDIDATE", "test_id": "save"}])
        assert len(ok) == 2
        with pytest.raises(AssertionIntegrityError):
            parse_recovery_candidates([self.GOOD, {**self.GOOD, "expected": "x"}])

    @pytest.mark.parametrize("bad", ["text", b"bytes", {"strategy": "x"}, 5])
    def test_recovery_output_is_a_list(self, bad):
        with pytest.raises(AssertionIntegrityError):
            parse_recovery_candidates(bad)

    def test_the_number_of_candidates_is_bounded(self):
        with pytest.raises(AssertionIntegrityError):
            parse_recovery_candidates([self.GOOD] * 9)
        assert len(parse_recovery_candidates([self.GOOD] * 9, limit=9)) == 9

    def test_the_candidate_schema_itself_rejects_extra_keys_in_json(self):
        j = parse_recovery_candidate(self.GOOD).to_json()
        j["expected"] = "x"
        j.pop("content_hash")
        with pytest.raises(QAContractError) as e:
            LocatorCandidate.from_json(j)
        assert e.value.code == Code.UNKNOWN_FIELD

    def test_the_candidate_type_has_no_assertion_field(self):
        names = {f.name for f in dataclasses.fields(LocatorCandidate)}
        assert names == {"strategy", "role", "name", "test_id", "label"}
