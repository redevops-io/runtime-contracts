"""Production-profile authority: what a real issued envelope changes, and what it must not change.

The pinned matrix in ``qualification.json`` is measured in the **default** profile. Under
``AGENTIC_OS_PROFILE=production`` both editions gate node dispatch on the mission's own authority envelope
(``MissionRuntime._authority_gate`` → ``AuthorityGuard.authorize``), and the contract scenarios mint no
envelope — so ``permitted_edges_survive`` used to fail in a provisioned production run with
``dispatched=[]`` and an ``AuthorityDeclined`` in the timeline. That is a *stricter* production behaviour, not
a leak, and it was never honest to fold it into the default-profile PASS or to explain it away.

This file measures it instead. Owner issuance is done through the product's own
``EnvelopeStore.put`` (see :func:`tests.authz_contract.durable_stores.issue_mission_envelope`), and every grant it
issues names one capability: the mission's own declared names verbatim, plus the registered capabilities whose
declared permission demands the mission covers in full (see :func:`capability_grants`). No family is ever widened
by the fixture — ``billing.read`` used to be issued as ``billing.*``, which also handed over ``billing.delete``,
and a wildcard now appears only where a policy_ref spells one out. With that in place:

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

from .durable_stores import (PRODUCTION_MISSION_TENANT, authority_module, capability_grants,  # noqa: F401
                             durable_production, issue_mission_envelope, registry_fixture)
from .implementations import REAL_ADAPTERS, skip_if_blocked

AUTHORIZED = ("billing.invoice", "reports.monthly")
UNAUTHORIZED = "secret.exfiltrate"

#: A deployment inventory for issuance that has no runtime to read one from: four registered capabilities, each
#: declaring the permission it demands, exactly as an operator manifest does. Two of them share ``billing.read``
#: so exact issuance is seen naming each one separately; ``secret.exfiltrate`` demands a permission no scenario
#: grants; and ``billing.delete`` is deliberately **not** registered here, which is the name only a wildcard can
#: ever reach.
INVENTORY = (("billing.invoice", ("invoice_ok",), ("billing.read",)),
             ("billing.refund", ("invoice_reversed",), ("billing.read",)),
             ("reports.monthly", ("report_ready",), ("reports.read",)),
             ("secret.exfiltrate", ("exfiltrated",), ("secret.read",)))


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


def test_issuance_is_exact_and_covers_nothing_the_mission_does_not_declare(durable_production) -> None:
    """No expansion at all: a permission name grants no provider, and only registered, fully-covered capabilities do.

    Three claims, all of them about the issuer rather than the product. First, a ``policy_ref`` is restated
    verbatim, so ``billing.read`` buys no capability — that is the difference between an exact grant and the family
    wildcard this replaces. Second, a capability enters the envelope because the *registry* declares that it
    demands a permission the mission holds, one name at a time: the deployment registered ``billing.invoice`` and
    ``billing.refund`` under ``billing.read``, so both are named, and nothing else is. Third, everything the
    mission does not declare stays out — a name nothing registers, and a capability demanding a permission the
    mission lacks.
    """
    authority = authority_module()
    registry = registry_fixture(INVENTORY)

    assert capability_grants(["billing.read", "reports.read", ""]) == ("billing.read", "reports.read"), (
        "a declared permission must be restated verbatim; widening it to a family is a policy decision, not issuance")
    assert capability_grants([]) == (), "a mission that declares nothing must be granted nothing"
    assert capability_grants(["billing.read"], registry) == ("billing.read", "billing.invoice", "billing.refund"), (
        f"issuance from a registry gave {capability_grants(['billing.read'], registry)}; it may add only the "
        "registered capabilities whose declared permission this mission holds, and only each by name")
    assert "billing.delete" not in capability_grants(["billing.read"], registry), (
        "a capability no operator registered must not be named by issuance — the deployment's inventory is the "
        "widest thing an issuer may quote")
    assert "billing.refund" not in capability_grants(["billing.read"], ()), (
        "without an inventory a permission must buy no capability at all — an unregistered name grants nothing")

    class _Mission:
        id = "mission-issuance-check"
        tenant = "acme"
        principal = "service:pipeline"
        goal = "issuance check"
        policy_refs = ["billing.read"]

    envelope = issue_mission_envelope(authority, durable_production.guard, _Mission, registry=registry)
    assert [g.capability for g in envelope.grants] == ["billing.read", "billing.invoice", "billing.refund"], (
        f"the issued envelope grants {[g.capability for g in envelope.grants]} for policy_refs "
        f"{_Mission.policy_refs}; every grant must name one capability the mission's own authority covers")
    assert envelope.expires_at > envelope.issued_at, "the product refuses an envelope with no lifetime"

    # Durable: a second store instance over the same file reads the same immutable version.
    fresh = authority.SqliteEnvelopeStore(str(durable_production.authority_path))
    stored = fresh.get(_Mission.id)
    assert stored is not None and stored.digest() == envelope.digest(), (
        "the envelope is not readable from a fresh store over the same file — the authority the run was "
        "measured against is not durable")

    guard = durable_production.guard
    assert guard.check(_Mission.id, "acme", _action(authority, "billing.invoice")).verdict.value == "allow", (
        "the exact grant the registry justifies does not reach the capability it names — issuance is broken")
    for beyond in ("reports.monthly", "secret.exfiltrate", "billing.delete"):
        refusal = guard.check(_Mission.id, "acme", _action(authority, beyond))
        assert refusal.verdict.value == "deny" and refusal.rule == "out_of_scope", (
            f"an envelope issued for billing.invoice also answered for {beyond} ({refusal.verdict.value}/"
            f"{refusal.rule}) — issuance widened the principal's authority")


def test_a_family_wildcard_reaches_an_envelope_only_where_policy_spells_it_out(durable_production) -> None:
    """The wildcard, measured as the policy decision it is — including the reach exact issuance does not have.

    This is the case the fixture used to apply to every mission, and the reviewer's objection to it. Kept, but only
    where a policy_ref names a pattern. Both halves are measured: exact issuance covers the registered
    capabilities of the family, each by name, and stops at a name the deployment never registered; a policy that
    delegates the family reaches that unregistered name too, and still stops outside the family. The gap between
    the two is the width a fixture must not grant silently.
    """
    authority = authority_module()
    registry = registry_fixture(INVENTORY)
    guard = durable_production.guard

    class _Exact:
        id, tenant, principal, goal, policy_refs = ("mission-exact-family", "acme", "service:pipeline",
                                                   "exact issuance", ["billing.read"])

    class _Delegated:
        id, tenant, principal, goal, policy_refs = ("mission-wildcard-family", "acme", "service:pipeline",
                                                   "family delegated by policy", ["billing.*"])

    issue_mission_envelope(authority, guard, _Exact, registry=registry)
    issue_mission_envelope(authority, guard, _Delegated, registry=registry)

    assert [g.capability for g in guard.envelopes.get(_Delegated.id).grants] == ["billing.*"], (
        "a policy_ref that states a pattern must be issued as stated — the pattern is the policy's, not the fixture's")
    registered = guard.check(_Exact.id, "acme", _action(authority, "billing.refund"))
    assert registered.verdict.value == "allow", (
        f"the registry declares billing.refund demands billing.read, so exact issuance must name it — it answered "
        f"{registered.verdict.value}/{registered.rule}")
    unregistered = guard.check(_Exact.id, "acme", _action(authority, "billing.delete"))
    assert unregistered.verdict.value == "deny" and unregistered.rule == "out_of_scope", (
        f"exact issuance let {unregistered.verdict.value}/{unregistered.rule} through for billing.delete, a "
        "capability no operator ever registered")
    delegated = guard.check(_Delegated.id, "acme", _action(authority, "billing.delete"))
    assert delegated.verdict.value == "allow", (
        "a policy that delegated the whole family does not reach the family's unregistered name: the envelope is "
        "not being read as the pattern the policy wrote")
    outside = guard.check(_Delegated.id, "acme", _action(authority, "reports.monthly"))
    assert outside.verdict.value == "deny" and outside.rule == "out_of_scope", (
        f"the family wildcard also answered for reports.monthly ({outside.verdict.value}/{outside.rule}) — "
        "a wildcard must stop at its own family")


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
    # The same exact issuance a runtime gets: the registry is what turns the declared permission into the one
    # capability name the envelope may name.
    issue_mission_envelope(authority, durable_production.guard, mission, registry=registry_fixture(INVENTORY))
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