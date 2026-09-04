"""The Mission KPI contract — outcome linkage in the buyer's language, with hard safety bars."""
import pytest

from runtime_contracts.models import (
    KPIDeclaration,
    KPIDirection,
    KPIKind,
    KPIMeasurement,
    KPIOutcome,
    MissionKPISet,
    judge,
)


def _decl(**kw):
    base = dict(kpi_id="k", kind=KPIKind.BUSINESS, name="K", unit="USD",
                direction=KPIDirection.MAXIMIZE)
    base.update(kw)
    return KPIDeclaration(**base)


# ── safety bars are hard and fail-closed ────────────────────────────────────────

def test_must_equal_zero_blocks_on_any_violation():
    d = _decl(kpi_id="wash_sale", kind=KPIKind.RISK, unit="count",
              direction=KPIDirection.MUST_EQUAL, bound="0")
    assert d.is_safety
    breached = judge(d, KPIMeasurement(kpi_id="wash_sale", value="1"))
    assert breached == KPIOutcome("wash_sale", "1", satisfied=False, blocking=True)
    held = judge(d, KPIMeasurement(kpi_id="wash_sale", value="0"))
    assert held.satisfied and not held.blocking


def test_must_not_exceed_is_a_ceiling():
    d = _decl(kpi_id="gain_budget", kind=KPIKind.RISK, unit="USD",
              direction=KPIDirection.MUST_NOT_EXCEED, bound="60000")
    assert judge(d, KPIMeasurement(kpi_id="gain_budget", value="60000")).satisfied
    over = judge(d, KPIMeasurement(kpi_id="gain_budget", value="60000.01"))
    assert not over.satisfied and over.blocking  # safety → blocks


def test_hard_direction_requires_a_bound():
    with pytest.raises(ValueError):
        _decl(kind=KPIKind.RISK, direction=KPIDirection.MUST_EQUAL)  # no bound


# ── scoreboard KPIs report but never gate ───────────────────────────────────────

def test_maximize_target_reported_not_blocking():
    d = _decl(kpi_id="harvested", direction=KPIDirection.MAXIMIZE, bound="3700000")
    below = judge(d, KPIMeasurement(kpi_id="harvested", value="3000000"))
    assert not below.satisfied      # missed the target
    assert not below.blocking       # ... but a business miss never blocks the mission


def test_maximize_without_bound_always_satisfied():
    d = _decl(kpi_id="harvested", direction=KPIDirection.MAXIMIZE)  # report-only
    assert judge(d, KPIMeasurement(kpi_id="harvested", value="0")).satisfied


def test_minimize_ceiling():
    d = _decl(kpi_id="review_min", kind=KPIKind.HUMAN, unit="minutes_per_unit",
              direction=KPIDirection.MINIMIZE, bound="5")
    assert judge(d, KPIMeasurement(kpi_id="review_min", value="4")).satisfied
    assert not judge(d, KPIMeasurement(kpi_id="review_min", value="6")).satisfied


# ── canonical / identity discipline ─────────────────────────────────────────────

def test_no_bare_float_measurement():
    with pytest.raises(ValueError):
        KPIMeasurement(kpi_id="k", value=0.5)  # type: ignore[arg-type]


def test_set_identity_is_order_independent_but_content_sensitive():
    a = _decl(kpi_id="a")
    b = _decl(kpi_id="b", kind=KPIKind.RISK, direction=KPIDirection.MUST_EQUAL, bound="0")
    assert MissionKPISet((a, b)).kpi_set_id == MissionKPISet((b, a)).kpi_set_id
    # Changing a bound changes identity — you cannot swap the scorecard silently.
    b2 = _decl(kpi_id="b", kind=KPIKind.RISK, direction=KPIDirection.MUST_NOT_EXCEED, bound="1")
    assert MissionKPISet((a, b)).kpi_set_id != MissionKPISet((a, b2)).kpi_set_id


def test_duplicate_kpi_id_rejected():
    with pytest.raises(ValueError):
        MissionKPISet((_decl(kpi_id="x"), _decl(kpi_id="x")))


def test_primary_secondary_and_kind_partitions():
    prim = _decl(kpi_id="rate", kind=KPIKind.AUTONOMY, direction=KPIDirection.MAXIMIZE)
    tech = _decl(kpi_id="cost", kind=KPIKind.RUNTIME, direction=KPIDirection.MINIMIZE,
                 primary=False)
    s = MissionKPISet((prim, tech))
    assert [k.kpi_id for k in s.primary()] == ["rate"]
    assert [k.kpi_id for k in s.secondary()] == ["cost"]
    assert s.by_kind(KPIKind.RUNTIME) == (tech,)


def test_judge_rejects_mismatched_measurement():
    with pytest.raises(ValueError):
        judge(_decl(kpi_id="a"), KPIMeasurement(kpi_id="b", value="1"))
