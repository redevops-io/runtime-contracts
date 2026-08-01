"""Adoption status is honest: no green check for unbuilt work, no permanent red."""
from __future__ import annotations

import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load(name):
    return yaml.safe_load((ROOT / "adoption" / name).read_text())


def test_no_implementation_claims_conformance_yet():
    """v0.1 is a proposed contract. Claiming conformance before an adapter
    exists is the dishonest green check this package is built to avoid."""
    impls = load("implementations.yaml")["implementations"]
    for name, spec in impls.items():
        assert spec.get("status") not in {"CONFORMANT", "DEPLOYED_CONFORMANT"}, (
            f"{name} claims conformance with no adapter"
        )


def test_absent_components_are_recorded_with_evidence():
    impls = load("implementations.yaml")["implementations"]
    for name, spec in impls.items():
        if spec.get("status") == "NOT_LOCATED":
            assert spec.get("evidence"), f"{name} is absent without saying how we know"


def test_every_claimed_adapter_directory_exists():
    impls = load("implementations.yaml")["implementations"]
    for name, spec in impls.items():
        if "adapter" in spec:
            assert (ROOT / spec["adapter"] / "mapping.yaml").exists(), (
                f"{name} names an adapter that is not there"
            )


def test_the_two_deployment_risks_are_gated():
    gates = {g["id"] for g in load("release-gates.yaml")["additional_gates"]}
    assert "RAG_COMMIT_OBSERVABLE" in gates
    assert "BUILD_MANIFEST_EMITTED" in gates


def test_unmet_gates_say_why():
    for gate in load("release-gates.yaml")["additional_gates"]:
        if not gate.get("currently_met"):
            assert gate.get("blocking_reason") or gate.get("proposed_shape")


def test_the_capability_gap_is_a_map_not_a_failure():
    mapping = yaml.safe_load(
        (ROOT / "adapters" / "context_runtime" / "mapping.yaml").read_text())
    capability = mapping["mappings"]["CapabilityDescriptor"]

    assert capability["status"] == "INCOMPATIBLE_PREDECESSOR"
    assert capability["supported"] and capability["missing"]
