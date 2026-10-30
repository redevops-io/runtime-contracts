"""QAAdapter, CheckAdapter, BlobStore and Redactor: signatures, errors and what they cannot carry."""
from __future__ import annotations

import dataclasses
import hashlib
import inspect

import pytest

from golden.qa_samples import d, h
from runtime_contracts.qa import (ADAPTER_ERRORS, CHECK_ADAPTER_API_VERSION, QA_ADAPTER_API_VERSION, ActionBlockedByPolicy,
                                  ActionOutcome, ActionRequest, Action, ActionKind, AdapterCrash, BlobDigestInvalid,
                                  BlobDigestMismatch, BlobNotFound, BlobStore, BlobStoreError, BlobTooLarge,
                                  CheckAdapter, CheckProfile, CheckProgramRef, CheckSubject, CheckTier, ClassHint,
                                  Code, ErrorCategory, LocateCandidate, LocateResult, LocatorAmbiguous,
                                  LocatorNotFound, LocatorDescriptor, LocatorStrategy, ObservedValue, QAAdapter,
                                  QAAdapterError, QAContractError, Redactor, RedactionFailed, ResolvedTarget,
                                  ResourceKind, ResourceRef, ResultCode, SessionProfile, UnsupportedOperation,
                                  blob_digest, error_for, require_blob_digest, verify_blob)

QA_METHODS = ["open_session", "observe", "locate", "act", "assert_", "capture", "reset", "close_session"]
CHECK_METHODS = ["open_workspace", "resolve", "run_check", "capture", "reset", "close_workspace"]


def public_methods(proto):
    return [n for n, v in vars(proto).items() if inspect.isfunction(v) and not n.startswith("_")]


class TestQAAdapter:
    def test_api_version_and_operations_match_the_adr(self):
        assert QA_ADAPTER_API_VERSION == "qa-adapter/1"
        assert public_methods(QAAdapter) == QA_METHODS

    def test_assert_takes_a_subject_only_and_returns_an_observed_value(self):
        sig = inspect.signature(QAAdapter.assert_)
        assert list(sig.parameters) == ["self", "s", "subject"]
        assert "ObservedValue" in str(sig.return_annotation)

    def test_no_operation_accepts_an_expected_value_or_returns_a_verdict(self):
        for proto in (QAAdapter, CheckAdapter):
            for name in public_methods(proto):
                sig = inspect.signature(getattr(proto, name))
                assert not [p for p in sig.parameters if "expect" in p or "verdict" in p], name
                assert "Verdict" not in str(sig.return_annotation) and "AssertionResult" not in str(sig.return_annotation)

    def test_act_takes_a_resolved_target_and_a_request_that_carries_a_policy_decision(self):
        assert list(inspect.signature(QAAdapter.act).parameters) == ["self", "s", "action", "target"]
        req = ActionRequest(step_id="s1", action=Action(ActionKind.CLICK), idempotency_key="k", policy_decision_ref=h(1))
        assert req.policy_decision_ref == h(1)
        with pytest.raises(TypeError):
            ActionRequest(step_id="s1", action=Action(ActionKind.CLICK), idempotency_key="k")  # type: ignore[call-arg]
        with pytest.raises(QAContractError):
            ActionRequest(step_id="s1", action=Action(ActionKind.CLICK), idempotency_key="k", policy_decision_ref="ok")

    def test_locate_returns_every_candidate_with_a_uniqueness_flag(self):
        one = LocateCandidate(candidate_ref="c1", role="button", name="Save", visible=True, enabled=True, unique=True)
        assert LocateResult(candidates=(one,)).candidates[0].unique
        a = dataclasses.replace(one, unique=False)
        b = dataclasses.replace(one, candidate_ref="c2", unique=False)
        assert len(LocateResult(candidates=(a, b)).candidates) == 2
        with pytest.raises(QAContractError):
            LocateResult(candidates=(a,))            # a lone candidate is unique
        with pytest.raises(QAContractError):
            LocateResult(candidates=(one, dataclasses.replace(one, candidate_ref="c2")))   # two claim uniqueness
        with pytest.raises(QAContractError):
            LocateResult(candidates=(a, dataclasses.replace(a)))   # duplicate refs

    def test_the_outcome_of_an_action_is_a_raw_result_not_a_verdict(self):
        names = {f.name for f in dataclasses.fields(ActionOutcome)}
        assert names == {"result", "detail"}
        assert ActionOutcome(result=ResultCode.OK).result is ResultCode.OK

    def test_a_session_denies_downloads_popups_and_file_choosers_by_default(self):
        p = SessionProfile(egress_profile="operator-default", redaction_policy_id=h(1))
        assert not (p.allow_downloads or p.allow_popups or p.allow_file_choosers)

    def test_a_structural_implementation_satisfies_the_protocol(self):
        class Fake:
            adapter_id = "fake"
            adapter_version = "0"
            api_version = QA_ADAPTER_API_VERSION

            def open_session(self, profile): ...
            def observe(self, s, req): ...
            def locate(self, s, target, *, mode): ...
            def act(self, s, action, target): ...
            def assert_(self, s, subject): ...
            def capture(self, s, kinds): ...
            def reset(self, s, scope): ...
            def close_session(self, s): ...

        assert isinstance(Fake(), QAAdapter)
        assert not isinstance(object(), QAAdapter)

    def test_resolved_target_carries_the_locator_and_strategy_used(self):
        t = ResolvedTarget(candidate_ref="c1", locator=LocatorDescriptor(role="button"),
                           strategy=LocatorStrategy.SEMANTIC_ALTERNATE)
        assert ResolvedTarget.from_json(t.to_json()) == t


class TestCheckAdapter:
    def test_api_version_and_operations_match_the_adr(self):
        assert CHECK_ADAPTER_API_VERSION == "qa-check-adapter/1"
        assert public_methods(CheckAdapter) == CHECK_METHODS

    def test_run_check_returns_the_actual_only(self):
        sig = inspect.signature(CheckAdapter.run_check)
        assert list(sig.parameters) == ["self", "w", "subject"] and "ObservedValue" in str(sig.return_annotation)

    def test_check_subject_is_program_inputs_and_tier(self):
        prog = CheckProgramRef(id="image-pinned", version="1.0.0", program_hash=d(1))
        subject = CheckSubject(check_program_ref=prog, inputs=(ResourceRef(kind=ResourceKind.IMAGE_DIGEST,
                                                                           digest=d(2)),), tier=CheckTier.OFFLINE)
        assert CheckSubject.from_json(subject.to_json()) == subject
        assert {f.name for f in dataclasses.fields(CheckSubject)} == {"check_program_ref", "inputs", "tier"}
        with pytest.raises(QAContractError):
            CheckSubject(check_program_ref=prog, inputs=(), tier=CheckTier.OFFLINE)
        with pytest.raises(QAContractError):
            CheckSubject(check_program_ref=prog, inputs=(subject.inputs[0],) * 17, tier=CheckTier.OFFLINE)

    def test_the_three_resource_kinds(self):
        assert {k.value for k in ResourceKind} == {"MANIFEST_PATH", "IMAGE_DIGEST", "NAMESPACE_OBJECT"}

    def test_tier_k_requires_a_disposable_proof(self):
        with pytest.raises(QAContractError):
            CheckProfile(tier=CheckTier.K, case_root_digest=d(1))
        ok = CheckProfile(tier=CheckTier.K, case_root_digest=d(1), disposable_proof_ref=h(2))
        assert ok.disposable_proof_ref == h(2)

    def test_an_offline_profile_carries_no_proof(self):
        assert CheckProfile(tier=CheckTier.OFFLINE, case_root_digest=d(1)).disposable_proof_ref is None
        with pytest.raises(QAContractError):
            CheckProfile(tier=CheckTier.OFFLINE, case_root_digest=d(1), disposable_proof_ref=h(2))

    def test_the_tiers(self):
        assert {t.value for t in CheckTier} == {"OFFLINE", "K"}

    def test_case_root_digest_is_full_width(self):
        with pytest.raises(QAContractError):
            CheckProfile(tier=CheckTier.OFFLINE, case_root_digest="sha256:" + "0" * 16)

    def test_a_structural_implementation_satisfies_the_protocol(self):
        class Fake:
            adapter_id = "f"
            adapter_version = "0"
            api_version = CHECK_ADAPTER_API_VERSION

            def open_workspace(self, profile): ...
            def resolve(self, w, ref): ...
            def run_check(self, w, subject): ...
            def capture(self, w, kinds): ...
            def reset(self, w, scope): ...
            def close_workspace(self, w): ...

        assert isinstance(Fake(), CheckAdapter)

    def test_an_observed_value_is_all_a_check_returns(self):
        assert not {f.name for f in dataclasses.fields(ObservedValue)} & {"verdict", "expected"}


class TestTypedErrors:
    NAMES = ["LocatorNotFound", "LocatorAmbiguous", "TargetNotActionable", "ActionTimeout", "UnexpectedDialog",
             "SessionLost", "NavigationDenied", "ActionBlockedByPolicy", "EnvironmentUnhealthy", "AdapterCrash",
             "BrowserCrash", "ResetFailed", "ResourceLimitExceeded", "RedactionFailed", "UnsupportedOperation"]

    def test_the_adr_table_is_complete_and_every_error_subclasses_the_base(self):
        import runtime_contracts.qa as qa
        for name in self.NAMES:
            cls = getattr(qa, name)
            assert issubclass(cls, QAAdapterError)
            err = cls("msg")
            assert isinstance(err.category, ErrorCategory) and isinstance(err.class_hint, ClassHint)
            assert isinstance(err.retryable, bool) and isinstance(err.recoverable, bool)
        assert len(ADAPTER_ERRORS) == len(self.NAMES)

    def test_every_error_maps_to_a_distinct_result_code(self):
        assert len({c.code for c in ADAPTER_ERRORS.values()}) == len(ADAPTER_ERRORS)
        assert set(ADAPTER_ERRORS) == {c for c in ResultCode if c is not ResultCode.OK}

    def test_error_for_round_trips_a_code(self):
        assert isinstance(error_for(ResultCode.LOCATOR_NOT_FOUND), LocatorNotFound)
        assert error_for(ResultCode.OK) is None

    def test_the_base_takes_the_four_documented_fields(self):
        e = QAAdapterError(ErrorCategory.POLICY, False, False, ClassHint.POLICY, "x")
        assert (e.category, e.retryable, e.recoverable, e.class_hint) == (ErrorCategory.POLICY, False, False,
                                                                           ClassHint.POLICY)

    def test_specific_properties_from_the_table(self):
        assert LocatorAmbiguous().class_hint is ClassHint.INCONCLUSIVE and LocatorAmbiguous().recoverable
        assert not ActionBlockedByPolicy().recoverable and not ActionBlockedByPolicy().retryable
        assert RedactionFailed().class_hint is ClassHint.INTEGRITY and not RedactionFailed().recoverable
        assert UnsupportedOperation().class_hint is ClassHint.TEST_DEFECT
        assert AdapterCrash().recoverable


class TestBlobStore:
    def test_the_identity_is_the_full_sha256(self):
        data = b"evidence bytes"
        assert blob_digest(data) == "sha256:" + hashlib.sha256(data).hexdigest()
        assert require_blob_digest(blob_digest(data)) == blob_digest(data)

    @pytest.mark.parametrize("bad", ["sha256:" + "0" * 16, "sha256:" + "A" * 64, "0" * 64, "md5:" + "0" * 32,
                                     "rcv1:" + "0" * 64, "", None])
    def test_truncated_and_foreign_digests_are_refused_by_name(self, bad):
        with pytest.raises(BlobDigestInvalid) as e:
            require_blob_digest(bad)
        assert e.value.code == "BLOB_DIGEST_INVALID"

    def test_bytes_must_hash_to_their_digest(self):
        verify_blob(blob_digest(b"x"), b"x")
        with pytest.raises(BlobDigestMismatch):
            verify_blob(blob_digest(b"x"), b"y")

    def test_the_error_family(self):
        for cls in (BlobDigestInvalid, BlobDigestMismatch, BlobNotFound, BlobTooLarge):
            assert issubclass(cls, BlobStoreError)

    def test_protocols_are_structural(self):
        class Store:
            def put(self, data, *, media_type): ...
            def get(self, digest): ...
            def exists(self, digest): ...
            def size(self, digest): ...

        class Red:
            policy_id = "p"

            def redact(self, data, *, media_type): ...

        assert isinstance(Store(), BlobStore) and isinstance(Red(), Redactor)

    def test_the_blob_store_has_no_overwrite_or_delete(self):
        assert public_methods(BlobStore) == ["put", "get", "exists", "size"]

    def test_the_redactor_returns_bytes_or_raises_and_cannot_return_the_input_on_failure(self):
        sig = inspect.signature(Redactor.redact)
        assert "bytes" in str(sig.return_annotation)
        assert RedactionFailed.code is ResultCode.REDACTION_FAILED
