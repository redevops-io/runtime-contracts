"""QAPlan: declarative, static lanes, FULL coverage only, no dynamic dispatch."""
from __future__ import annotations

import dataclasses
import json

import pytest

from golden.qa_samples import PLANNER, h, plan_for, ui_spec
from runtime_contracts.qa import (Budget, Code, CoverageContract, EvidenceLevel, PlanGate, PlanItem, QAContractError,
                                  QAPlan, ResourceClaim, UnknownEnumValue, make_spec_ref)

R = [make_spec_ref(f"spec-{i}", h(i + 1)) for i in range(4)]


def item(ref, lane="lane-a", order=0, **kw):
    kw.setdefault("budget", Budget(deadline_ms=1000, max_recovery_attempts=1))
    kw.setdefault("recovery_ceiling", 2)
    return PlanItem(spec_ref=ref, lane=lane, order=order, **kw)


def plan(items, **kw):
    base = dict(items=items, lanes=("lane-a", "lane-b"), max_parallel=2, coverage_contract=CoverageContract.FULL,
                planner=PLANNER)
    base.update(kw)
    return QAPlan(**base)


class TestCoverageContract:
    def test_full_is_accepted(self):
        assert plan_for(R[:2]).coverage_contract is CoverageContract.FULL

    def test_subset_is_a_reserved_value_that_every_validator_rejects(self):
        assert CoverageContract.SUBSET.value == "SUBSET"
        with pytest.raises(QAContractError) as e:
            plan_for(R[:2], coverage=CoverageContract.SUBSET)
        assert e.value.code == Code.UNSUPPORTED_COVERAGE_CONTRACT

    def test_subset_in_json_is_rejected_by_name_not_as_an_unknown_enum(self):
        j = plan_for(R[:2]).to_json()
        j["coverage_contract"] = "SUBSET"
        j.pop("content_hash")
        with pytest.raises(QAContractError) as e:
            QAPlan.from_json(j)
        assert e.value.code == Code.UNSUPPORTED_COVERAGE_CONTRACT

    def test_any_other_value_is_an_unknown_enum(self):
        j = plan_for(R[:2]).to_json()
        j["coverage_contract"] = "PARTIAL"
        j.pop("content_hash")
        with pytest.raises(UnknownEnumValue):
            QAPlan.from_json(j)

    def test_coverage_has_no_default(self):
        with pytest.raises(TypeError):
            QAPlan(items=(item(R[0]),), lanes=("lane-a",), max_parallel=1, planner=PLANNER)  # type: ignore[call-arg]


class TestStaticLanes:
    def test_no_dynamic_dispatch_field_exists_and_none_can_be_smuggled_in(self):
        names = {f.name for f in dataclasses.fields(QAPlan)}
        forbidden = ("steal", "replan", "dispatch", "dynamic", "resolve", "reorder", "schedule", "autoscale")
        assert not [n for n in names if any(w in n for w in forbidden)]
        j = plan_for(R[:2]).to_json()
        for key in ("work_stealing", "replan_on_failure", "dynamic_dispatch"):
            smuggled = {**j, key: True}
            smuggled.pop("content_hash")
            with pytest.raises(QAContractError) as e:
                QAPlan.from_json(smuggled)
            assert e.value.code == Code.UNKNOWN_FIELD

    def test_the_plan_round_trips_and_custody_is_not_identity(self):
        a = plan_for(R[:2])
        b = plan_for(R[:2], rationale_ref=h(99).replace("rcv1", "sha256"))
        assert a.plan_hash == b.plan_hash
        assert QAPlan.from_json(a.to_json()) == a

    def test_item_and_lane_order_in_the_input_do_not_matter(self):
        i0, i1 = item(R[0], "lane-a", 0), item(R[1], "lane-b", 0)
        assert plan((i0, i1)).plan_hash == plan((i1, i0), lanes=("lane-b", "lane-a")).plan_hash

    def test_identity_includes_lane_order_budget_and_evidence_level(self):
        base = plan((item(R[0]),)).plan_hash
        assert plan((item(R[0], lane="lane-b"),)).plan_hash != base
        assert plan((item(R[0], order=1),)).plan_hash != base
        assert plan((item(R[0], evidence_level=EvidenceLevel.FULL),)).plan_hash != base
        assert plan((item(R[0], budget=Budget(deadline_ms=2000)),)).plan_hash != base

    def test_an_item_must_name_a_declared_lane(self):
        with pytest.raises(QAContractError) as e:
            plan((item(R[0], lane="lane-z"),))
        assert e.value.code == Code.PLAN_INVALID

    def test_two_items_cannot_share_a_slot(self):
        with pytest.raises(QAContractError):
            plan((item(R[0], "lane-a", 0), item(R[1], "lane-a", 0)))

    def test_a_spec_appears_once(self):
        with pytest.raises(QAContractError) as e:
            plan((item(R[0], "lane-a", 0), item(R[0], "lane-b", 0)))
        assert e.value.code == Code.DUPLICATE_ENTRY

    def test_max_parallel_is_bounded_by_the_lanes(self):
        for bad in (0, 3):
            with pytest.raises(QAContractError):
                plan((item(R[0]),), max_parallel=bad)

    def test_a_plan_schedules_something(self):
        with pytest.raises(QAContractError):
            plan(())

    def test_the_budget_may_not_exceed_the_recovery_ceiling(self):
        with pytest.raises(QAContractError):
            item(R[0], budget=Budget(deadline_ms=1000, max_recovery_attempts=3), recovery_ceiling=2)


class TestGates:
    def test_a_gate_is_a_start_condition_between_items(self):
        p = plan((item(R[0], "lane-a", 0), item(R[1], "lane-b", 0)), gates=(PlanGate(item=R[1], after=(R[0],)),))
        assert p.gates[0].after == (R[0],)

    def test_a_gate_on_an_unknown_item_is_refused(self):
        with pytest.raises(QAContractError):
            plan((item(R[0]),), gates=(PlanGate(item=R[0], after=(R[3],)),))

    def test_a_gate_that_waits_for_nothing_or_itself_is_refused(self):
        with pytest.raises(QAContractError):
            PlanGate(item=R[0], after=())
        with pytest.raises(QAContractError):
            PlanGate(item=R[0], after=(R[0],))

    def test_a_gate_cycle_is_refused(self):
        with pytest.raises(QAContractError) as e:
            plan((item(R[0], "lane-a", 0), item(R[1], "lane-b", 0)),
                 gates=(PlanGate(item=R[0], after=(R[1],)), PlanGate(item=R[1], after=(R[0],))))
        assert e.value.code == Code.PLAN_INVALID

    def test_a_gate_pointing_at_a_later_item_of_its_own_lane_is_a_deadlock_and_refused(self):
        with pytest.raises(QAContractError):
            plan((item(R[0], "lane-a", 0), item(R[1], "lane-a", 1)), gates=(PlanGate(item=R[0], after=(R[1],)),))

    def test_a_gate_on_an_earlier_item_of_its_own_lane_is_fine(self):
        plan((item(R[0], "lane-a", 0), item(R[1], "lane-a", 1)), gates=(PlanGate(item=R[1], after=(R[0],)),))


def test_resource_claims_are_declarative_counts():
    with pytest.raises(QAContractError):
        ResourceClaim(resource="browser_slots", amount=0)


def test_action_policy_ref_is_a_hash_reference():
    with pytest.raises(QAContractError):
        plan_for(R[:2], action_policy_ref="policy-v1")


def test_a_plan_is_built_from_specs_by_reference(tmp_path):
    spec = ui_spec()
    p = plan_for([spec.spec_ref])
    assert json.loads(json.dumps(p.to_json()))["items"][0]["spec_ref"] == spec.spec_ref
