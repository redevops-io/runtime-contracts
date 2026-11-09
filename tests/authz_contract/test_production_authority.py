"""Production-profile authority: what a real issued envelope changes, and what it must not change.

The pinned matrix in ``qualification.json`` is measured in the **default** profile. Under
``AGENTIC_OS_PROFILE=production`` both editions gate node dispatch on the mission's own authority envelope
(``MissionRuntime._authority_gate`` → ``AuthorityGuard.authorize``), and the contract scenarios mint no
envelope — so ``permitted_edges_survive`` used to fail in a provisioned production run with
``dispatched=[]`` and an ``AuthorityDeclined`` in the timeline. That is a *stricter* production behaviour, not
a leak, and it was never honest to fold it into the default-profile PASS or to explain it away.

This file measures it instead. Owner issuance is done through the product's own
``EnvelopeStore.put`` (see :func:`tests.authz_contract.durable_stores.issue_mission_envelope`), and it grants
only what ``Mission.policy_refs`` already declares. With that in place:

* the permitted edges really dispatch — the plan completes because the authority was issued, not because the
  gate was removed;
* the unauthorized edge is refused **by the envelope**, which is asserted at the guard itself, so the PASS
  cannot be resting on the harness's own filtering;
* revoking the envelope stops the permitted edge again, so the allow is live authority rather than a cached yes;
* and a mission with no issued envelope is still refused — the fail-closed control from
  :mod:`tests.authz_contract.test_durable_profile` stays exactly where it was.

Nothing here reclassifies the pinned matrix: the default-profile cells are untouched, and this file measures
the production cells in their own right.
"""
from __future__ import annotations

import sqlite3

import pytest

from runtime_contracts.authz.qualification import Invariant, Qualification
from runtime_contracts.authz.suite import run_invariant

from .durable_stores import (PRODUCTION_MISSION_TENANT, authority_module, durable_production,  # noqa: F401
                             family_patterns, issue_mission_envelope)
from .implementations import REAL_ADAPTERS, skip_if_blocked

AUTHORIZED = ("billing.invoice", "reports.monthly")
UNAUTHORIZED = "secret.exfiltrate"


def _subs(result) -> dict[str, dict]:
    return {s["id"]: s for s in result.evidence.get("sub_criteria", [])}


def _action(authority, capability: str, *, side_effecting: bool = False):
    return authority.Action(capability=capability, arguments={}, side_effecting=side_effecting)


def test_a_mission_without_issued_authority_is_refused(durable_production) -> None:
    """The fail-closed control, at the enforcement point: no envelope, no dispatch — in production."""
    authority = authority_module()
    decision = durable_production.guard.check("mission-never-issued", "acme", _action(authority, "billing.invoice"))
    assert decision.verdict.value == "deny", (
        f"production authorized a node with no envelope on record: {decision.verdict.value}/{decision.rule} — "
        "an unprovisioned mission must run nothing at all")
    assert decision.rule == "no_authority", (
        f"refused, but for {decision.rule!r}; 'no_authority' is the refusal that keeps an unprovisioned "
        "mission from running anything")


def test_envelope_issuance_grants_only_what_the_mission_declares(durable_production) -> None:
    """Derivation, durability and the absence of anything the principal was not given."""
    authority = authority_module()

    assert family_patterns(["billing.read", "reports.read", ""]) == ("billing.*", "reports.*")
    assert family_patterns([]) == (), "a mission that declares nothing must be granted nothing"

    class _Mission:
        id = "mission-issuance-check"
        tenant = "acme"
        principal = "service:pipeline"
        goal = "issuance check"
        policy_refs = ["billing.read"]

    envelope = issue_mission_envelope(authority, durable_production.guard, _Mission)
    assert [g.capability for g in envelope.grants] == ["billing.*"], (
        f"the issued envelope grants {[g.capability for g in envelope.grants]} for policy_refs "
        f"{_Mission.policy_refs}; it may only restate what the mission declares")
    assert envelope.expires_at > envelope.issued_at, "the product refuses an envelope with no lifetime"

    # Durable: a second store instance over the same file reads the same immutable version.
    fresh = authority.SqliteEnvelopeStore(str(durable_production.authority_path))
    stored = fresh.get(_Mission.id)
    assert stored is not None and stored.digest() == envelope.digest(), (
        "the envelope is not readable from a fresh store over the same file — the authority the run was "
        "measured against is not durable")

    guard = durable_production.guard
    assert guard.check(_Mission.id, "acme", _action(authority, "billing.invoice")).verdict.value == "allow"
    beyond = guard.check(_Mission.id, "acme", _action(authority, "reports.monthly"))
    assert beyond.verdict.value == "deny" and beyond.rule == "out_of_scope", (
        f"an envelope issued for billing.* also answered for reports.monthly ({beyond.verdict.value}/"
        f"{beyond.rule}) — issuance widened the principal's authority")


@pytest.mark.parametrize("reference", REAL_ADAPTERS, ids=lambda r: r.split(".")[-2])
def test_issued_authority_makes_permitted_edges_survive_in_production(reference, durable_production) -> None:
    """The two cells that deviated under production, measured against real issued authority.

    Both halves are required. An authorized plan that completes proves the envelope is what lets the edge
    through; an unauthorized provider that never dispatches proves the same envelope still refuses. Either
    half alone would be a different, weaker claim.
    """
    authority = authority_module()
    adapter = skip_if_blocked(reference)
    try:
        result = run_invariant(Invariant.PERMITTED_EDGES_SURVIVE, adapter)
    finally:
        try:
            adapter.close()
        except Exception:  # noqa: BLE001 — closing must neither change a verdict nor hide one
            pass

    subs = _subs(result)
    assert durable_production.issued, (
        "no mission was created, so this cell measured nothing — the adapters' plan seam is the subject here")
    assert result.verdict is Qualification.PASS, (
        f"{adapter.implementation}/permitted_edges_survive is {result.verdict.value} under production with an "
        f"issued envelope: {result.detail}\nEither the envelope does not cover the mission's own declared "
        "authority (issuance is wrong), or production really does stop a permitted edge that its own grant "
        "store allows (a product finding, and it belongs in the qualification record).")

    completes, edge = subs["authorized_plan_completes"], subs["unauthorized_edge_never_dispatches"]
    assert sorted(completes["dispatched"]) == sorted(AUTHORIZED), (
        f"the authorized plan dispatched {completes['dispatched']}, not the edges it was granted")
    assert UNAUTHORIZED not in edge["dispatched"], (
        f"{UNAUTHORIZED} dispatched under production despite being outside every grant and every envelope — "
        "this is the leak the criterion exists to catch, and no provisioning may excuse it")
    assert UNAUTHORIZED in edge["denied"], (
        f"{UNAUTHORIZED} neither ran nor was recorded as refused, so its refusal is unauditable "
        f"(dispatched={edge['dispatched']}, denied={edge['denied']})")

    # The allow came out of the envelope, and so does the refusal: checked at the guard, on the mission the
    # run created, against the durable store the runtime read.
    mission_id = durable_production.issued[-1]
    allow = durable_production.guard.check(mission_id, PRODUCTION_MISSION_TENANT, _action(authority, AUTHORIZED[0]))
    deny = durable_production.guard.check(mission_id, PRODUCTION_MISSION_TENANT, _action(authority, UNAUTHORIZED))
    assert allow.verdict.value == "allow", f"the guard refuses the permitted edge the run just dispatched: {allow.rule}"
    assert deny.verdict.value == "deny" and deny.rule == "out_of_scope", (
        f"the guard answers {UNAUTHORIZED} with {deny.verdict.value}/{deny.rule}; the envelope, not the "
        "harness, has to be what refuses it")
    assert str(completes.get("state")) == "succeeded" and str(edge.get("state")) == "succeeded", (
        f"the plans ended {completes.get('state')}/{edge.get('state')} rather than succeeding, so the edges "
        "survived only partially and the cell should not have read as a pass")


def test_revoking_the_envelope_stops_the_permitted_edge(durable_production) -> None:
    """Anti-vacuity for the PASS above: withdraw the authority and the same edge must stop."""
    authority = authority_module()
    mission_id = f"{durable_production.issued[-1] if durable_production.issued else 'mission'}-revocation"

    class _Mission:
        pass

    mission = _Mission()
    mission.id, mission.tenant, mission.policy_refs, mission.principal, mission.goal = (
        mission_id, "acme", ["billing.read"], "service:pipeline", "revocation check")
    issue_mission_envelope(authority, durable_production.guard, mission)
    guard = durable_production.guard
    assert guard.check(mission_id, "acme", _action(authority, "billing.invoice")).verdict.value == "allow"

    guard.envelopes.revoke(mission_id)
    after = guard.check(mission_id, "acme", _action(authority, "billing.invoice"))
    assert after.verdict.value == "deny", (
        "a revoked envelope still authorizes: the guard is caching authority rather than reading it")
    assert after.rule == "revoked", f"refused for {after.rule!r} rather than for the revocation itself"
    # Revocation is durable: another reader of the same file agrees.
    fresh = authority.SqliteEnvelopeStore(str(durable_production.authority_path))
    with sqlite3.connect(str(durable_production.authority_path)) as conn:
        revoked_rows = conn.execute("SELECT COUNT(*) FROM revoked WHERE mission_id = ?", (mission_id,)).fetchone()[0]
    assert revoked_rows == 1 and fresh.is_revoked(mission_id), (
        "the revocation lives only in this process — it is not a durable withdrawal")