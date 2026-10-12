"""AppManifest contract — the app-registration declaration a runtime binds and an overlay extends."""
from __future__ import annotations

import runtime_contracts as rc
from runtime_contracts import (
    AppManifest,
    CapabilityClaim,
    CoreRequirement,
    EnterpriseRequirement,
    IntegrationLevel,
    OutcomeKind,
    ProducerClaim,
    RuntimeBuildManifest,
    VerifierClaim,
)


def test_exported_from_the_package_root():
    # the contract is part of the shared surface, reachable the same way as the other models
    assert rc.AppManifest is AppManifest
    assert "AppManifest" in rc.__all__


def test_phantom_capability_is_named_not_hidden():
    """A producer that emits a capability the app does not provide is the failure the contract exists to
    catch — it must be NAMED, so a registry can refuse rather than let the candidate fail opaquely later."""
    m = AppManifest(
        name="agentic-billing",
        capabilities=(CapabilityClaim("billing.dunning", risk_tier="write"),),
        producers=(ProducerClaim("overdue", emits_capabilities=("billing.dunning", "billing.refund")),),
    )
    assert m.unresolved_producer_capabilities() == frozenset({"billing.refund"})

    ok = AppManifest(
        name="agentic-billing",
        capabilities=(CapabilityClaim("billing.dunning"), CapabilityClaim("billing.refund")),
        producers=(ProducerClaim("overdue", emits_capabilities=("billing.dunning", "billing.refund")),),
    )
    assert ok.unresolved_producer_capabilities() == frozenset()


def test_verifier_must_point_at_a_provided_capability():
    m = AppManifest(
        name="a",
        capabilities=(CapabilityClaim("a.act"),),
        verifiers=(VerifierClaim(capability="a.act"), VerifierClaim(capability="a.ghost")),
    )
    assert m.verified_capabilities() == frozenset({"a.act", "a.ghost"})
    assert m.unresolved_verifier_capabilities() == frozenset({"a.ghost"})


def test_pure_data_defaults_and_round_trip_vocabularies():
    """Pure data: constructs with nothing wired, carries string vocabularies verbatim, seconds for delays."""
    m = AppManifest(
        name="edge-sentinel",
        version="1.2.0",
        capabilities=(CapabilityClaim("sentinel.block_ip", risk_tier="high", may_egress=True),),
        outcome_kinds=(OutcomeKind("block", unit="ips", expected_delay_s=5.0),),
        required_cores=(CoreRequirement("crowdsec", IntegrationLevel.L2_GOVERNED_FORK),),
        data_classifications=("public", "customer-confidential"),
        enterprise=EnterpriseRequirement.OPTIONAL,
    )
    assert m.capability_names() == frozenset({"sentinel.block_ip"})
    assert m.required_cores[0].integration_level is IntegrationLevel.L2_GOVERNED_FORK
    assert m.outcome_kinds[0].expected_delay_s == 5.0           # seconds, not a bare ambiguous number
    assert "customer-confidential" in m.data_classifications     # unknown-to-reader class kept verbatim
    assert m.contract_version == "app-manifest/v1"


def test_runtime_build_manifest_makes_conformance_attributable():
    m = RuntimeBuildManifest(
        component="agentic-os",
        package_version="0.2.4",
        source_commit="abc1234",
        image_digest="sha256:deadbeef",
        contract_matrix={"execution-plan": "v8", "runtime-contracts": "0.3.13"},
        adapter_versions=("operator-sdk/v1",),
    )
    assert rc.RuntimeBuildManifest is RuntimeBuildManifest
    assert m.is_attributable()
    assert m.contract_version == "runtime-build-manifest/v1"
    assert m.contract_matrix["execution-plan"] == "v8"
