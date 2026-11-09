"""The configuration the production profile demands — real stores, product classes, nothing stubbed.

``AGENTIC_OS_PROFILE=production`` is not a stricter authorization mode; it is a demand for configuration. The
kernel refuses to start approval replay protection without a store that outlives the process, and refuses a
Mission runtime whose authority lives nowhere an enforcement point can read (``agentic_os.mission.profile``::
``assert_authority``, ``agentic_os.mission.approval.default_replay_guard``). Those refusals are what made five
matrix cells and three negative controls fail on a production-profile run: a deployment that has not been
provisioned, reported as if it were a leak.

This module provisions exactly what that profile asks for, the way an operator does — environment variables
naming private files, and the product's own SQLite classes opening them:

===================================================  =========================================================
Production requirement                               What satisfies it here
===================================================  =========================================================
``AGENTIC_OS_REPLAY_DB``                             ``SqliteReplayGuard`` (reached through the product's own
                                                     ``default_replay_guard`` factory, not by hand)
``AGENTIC_OS_AUTHORITY_DB``                          ``AuthorityGuard(SqliteEnvelopeStore, SqliteLedger)`` — the
                                                     durable pair, whose ``durable`` flag is what
                                                     ``assert_authority`` looks for
``AGENTIC_OS_APPROVAL_SECRET`` (32+ chars)           a random secret per test, never a fixed value on disk
``AGENTIC_OS_CONTROL_TOKEN``                         a random per-test token (production disables ``/invoke``
                                                     without one)
no ``AGENTIC_OS_OPERATOR_ALLOW_ANONYMOUS``           deleted from the environment, not merely unset by default
===================================================  =========================================================

Neither store needs a schema step of its own: each product class creates its tables when it opens the file, so
pointing the variable at a private path *is* the setup. Nothing here decides authorization — the tests read back
what the product wrote.
"""
from __future__ import annotations

import secrets
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

import pytest

from adapters._implementations import add_implementation_root, import_module
from runtime_contracts.authz.suite import AdapterBlocked

#: The profile and the durable stores live in the kernel; the overlay runs on the same process configuration.
KERNEL = "agentic-os"
ENTERPRISE = "agentic-os-enterprise"

ENV_PROFILE = "AGENTIC_OS_PROFILE"
ENV_REPLAY_DB = "AGENTIC_OS_REPLAY_DB"
ENV_AUTHORITY_DB = "AGENTIC_OS_AUTHORITY_DB"
ENV_REQUIRE_DURABLE_REPLAY = "AGENTIC_OS_REQUIRE_DURABLE_REPLAY"
ENV_APPROVAL_SECRET = "AGENTIC_OS_APPROVAL_SECRET"
ENV_CONTROL_TOKEN = "AGENTIC_OS_CONTROL_TOKEN"
ENV_ALLOW_ANONYMOUS = "AGENTIC_OS_OPERATOR_ALLOW_ANONYMOUS"

#: A production mission must name the tenant whose authority it runs under — the runtime refuses to key an
#: envelope for a mission that names none. The contract principals are tenant-neutral on purpose (the same
#: scenario has to run in both editions), so a production run names one here: the same default the enterprise
#: adapter already gives its missions. This is deployment configuration, not a contract change — the criteria,
#: the adapters and the pinned matrix are untouched, and a mission this fixture does not provision is still
#: refused (see ``test_production_profile_without_durable_stores_is_not_reported_as_authorization``).
PRODUCTION_MISSION_TENANT = "acme"

#: How long an envelope issued for a contract mission stays valid. The product requires every envelope to
#: state a lifetime; a contract run is minutes long.
ENVELOPE_TTL_S = 900.0

#: How a cell says "this process was not provisioned" rather than "authority leaked". The two production
#: refusals by name, plus the variables the product names when it refuses — a detail that quotes one of those
#: variables is describing setup, so it must never be read as a verdict about the product's authorization code.
CONFIG_MARKERS = ("ReplayProtectionNotDurable", "ProfileError", "not durable", "requires a durable authority",
                  ENV_REPLAY_DB, ENV_AUTHORITY_DB)


def is_configuration_failure(detail: str) -> bool:
    """True when a cell's detail describes missing deployment configuration."""
    return any(marker in (detail or "") for marker in CONFIG_MARKERS)


def product_module(module: str, implementation: str = KERNEL):
    """An implementation module, or a BLOCKED skip — a missing checkout says something about the run."""
    try:
        add_implementation_root(implementation)
        return import_module(implementation, module)
    except AdapterBlocked as exc:
        pytest.skip(f"BLOCKED — {exc}")


def profile_module():
    return product_module("agentic_os.mission.profile")


def approval_module():
    return product_module("agentic_os.mission.approval")


def authority_module():
    return product_module("agentic_os.mission.authority")


@dataclass(frozen=True)
class DurableStores:
    """Where the durable stores were put, and the objects the product opened them with."""

    replay_path: Path
    authority_path: Path
    guard: Any
    replay_guard: Any
    #: Mission ids this run issued an envelope for, in order — proof the issuance actually happened.
    issued: list[str] = field(default_factory=list)

    def tables(self, path: Path) -> set[str]:
        """The tables a store file actually holds — read the way an auditor reads it, not from the object."""
        with sqlite3.connect(str(path)) as conn:
            return {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}


def configure_production(monkeypatch, root: Path) -> dict[str, str]:
    """Point the process at a production posture whose durable stores are these temporary files.

    The paths are returned so a test can name the file it expects the product to have created; the values are
    random per test, so a secret can never leak from one run into another or into a report.
    """
    env = {
        ENV_PROFILE: "production",
        ENV_REPLAY_DB: str(root / "replay.db"),
        ENV_AUTHORITY_DB: str(root / "authority.db"),
        ENV_APPROVAL_SECRET: secrets.token_hex(32),       # the profile wants 32+ characters of it
        ENV_CONTROL_TOKEN: secrets.token_hex(16),         # production refuses /invoke with nothing set
    }
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    # Opt-outs and half-configurations are the interesting cases: a run that inherited one from the developer's
    # shell would silently weaken the posture under test.
    monkeypatch.delenv(ENV_ALLOW_ANONYMOUS, raising=False)
    monkeypatch.delenv(ENV_REQUIRE_DURABLE_REPLAY, raising=False)
    return env


def clear_durable_configuration(monkeypatch) -> None:
    """Production posture with the durable stores removed — the state the profile must refuse."""
    monkeypatch.setenv(ENV_PROFILE, "production")
    for name in (ENV_REPLAY_DB, ENV_AUTHORITY_DB, ENV_REQUIRE_DURABLE_REPLAY, ENV_ALLOW_ANONYMOUS):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def durable_production(tmp_path, monkeypatch) -> Iterator[DurableStores]:
    """A production-posture process with real, temporary, product-owned durable stores wired in.

    The replay guard comes from ``default_replay_guard()`` — the factory an operator's Operator calls — so what
    is under test is the product's own choice of store, not this file's. The authority guard is the durable pair
    the profile requires, and is installed on the runtime classes the adapters build, which is the seam a
    deployment's composition root uses: a production ``MissionRuntime`` is refused without a durable guard handed
    to it, whether or not the variable is set.
    """
    approval, authority = approval_module(), authority_module()
    root = tmp_path / "durable"
    root.mkdir()
    configure_production(monkeypatch, root)

    guard = authority.AuthorityGuard(authority.SqliteEnvelopeStore(str(root / "authority.db")),
                                     authority.SqliteLedger(str(root / "authority.db")))
    if not getattr(guard, "durable", False):
        pytest.fail(f"{authority.AuthorityGuard.__module__}: the envelope/ledger pair opened above is not durable; "
                    "the production profile can be satisfied by nothing, so this fixture cannot provision it")
    replay = approval.default_replay_guard()
    if isinstance(replay, approval.ReplayGuard):
        pytest.fail(f"{approval.ENV_REPLAY_DB} is set but default_replay_guard() still returned the per-process "
                    f"guard — durable replay protection is not configured by the variable any more")

    _install_guard_on_runtimes(monkeypatch, guard)
    issued: list[str] = []
    _install_owner_issuance(monkeypatch, guard, authority, issued)
    yield DurableStores(replay_path=root / "replay.db", authority_path=root / "authority.db",
                        guard=guard, replay_guard=replay, issued=issued)


def family_patterns(policy_refs) -> tuple[str, ...]:
    """Envelope grant patterns from the authority a mission already declares (``Mission.policy_refs``).

    A mission's ``policy_refs`` are the grants its caller resolved for it — both adapters pass the principal's
    own grants there, because the compiler's stage-2 check reads them. Turning ``billing.read`` into
    ``billing.*`` is the product's own family rule (a capability needs its family's read permission, the same
    rule the adapters document), applied in the other direction. Nothing may appear here that the principal
    does not hold: an envelope that granted a capability the mission was not given would be the harness
    laundering privilege, which is one of the invariants under test.
    """
    families = {str(ref).split(".", 1)[0] for ref in policy_refs if str(ref).strip()}
    return tuple(f"{family}.*" for family in sorted(families))


def issue_mission_envelope(authority, guard, mission, *, ttl_s: float = ENVELOPE_TTL_S) -> Any:
    """Issue and store the envelope for one mission, through the product's own owner/platform API.

    ``EnvelopeStore.put`` is what an owner's issuance path calls; ``AuthorityGuard`` then reads it back on
    every decision. The envelope states its tenant, its principal, its lifetime and only the grants the
    mission declares — so what production enforces is checked against real issued authority, not against an
    absent envelope that forces every node to be refused.
    """
    tenant = getattr(mission, "tenant", "") or PRODUCTION_MISSION_TENANT
    patterns = family_patterns(getattr(mission, "policy_refs", []) or [])
    grants = tuple(authority.Grant(capability=pattern) for pattern in patterns)
    now = time.time()
    envelope = authority.AuthorityEnvelope(
        tenant=tenant, principal=str(getattr(mission, "principal", "") or "authz-contract"),
        mission_id=str(mission.id), goal=str(getattr(mission, "goal", "") or ""), grants=grants,
        budget=authority.AutonomyBudget(usd=100.0, tokens=0, wall_clock_s=0.0, max_actions=32,
                                        max_children=0, max_depth=0, max_parallel=1),
        issued_at=now, expires_at=now + ttl_s)
    guard.envelopes.put(envelope)
    return envelope


def _install_owner_issuance(monkeypatch, guard, authority, issued: list[str]) -> None:
    """Give every mission this run creates the envelope its own declared authority allows.

    The harness has no composition root, so the issuance an Operator would perform at ``create_mission`` time
    is installed at that same call. It grants nothing beyond ``Mission.policy_refs``; a mission that declares
    no authority gets an envelope that authorizes nothing, and its nodes are refused exactly as they were
    before this existed.
    """
    for _implementation, runtime_cls in _runtime_classes():
        original = runtime_cls.create_mission

        def create(self, *args, _original=original, **kwargs):
            mission = _original(self, *args, **kwargs)
            if not getattr(mission, "tenant", ""):      # the tenant is part of the authority key, not a label
                mission.tenant = PRODUCTION_MISSION_TENANT
            issue_mission_envelope(authority, guard, mission)   # no policy_refs ⇒ no grants ⇒ no authority
            issued.append(str(mission.id))
            return mission

        monkeypatch.setattr(runtime_cls, "create_mission", create, raising=False)


def _install_guard_on_runtimes(monkeypatch, guard) -> None:
    _install_on_runtimes(monkeypatch, "authority", guard)


def _runtime_classes():
    """Each edition's ``MissionRuntime`` that this machine can import, with its implementation key."""
    found = []
    for module_name, implementation in (("agentic_os.mission.runtime", KERNEL),
                                        ("agentic_os_enterprise.mission.runtime", ENTERPRISE)):
        try:
            add_implementation_root(implementation)
            module = import_module(implementation, module_name)
        except AdapterBlocked:
            continue                                  # an overlay that is not checked out is not under test here
        runtime_cls = getattr(module, "MissionRuntime", None)
        if runtime_cls is not None and not any(runtime_cls is seen for _impl, seen in found):
            found.append((implementation, runtime_cls))
    return found


def _install_on_runtimes(monkeypatch, attribute: str, value) -> None:
    """Give every Mission runtime built in this test the durable guard a production deployment must inject.

    ``MissionRuntime.__init__`` calls ``profile.assert_authority(self.authority, …)`` and refuses to start in
    production without a durable guard. The contract adapters construct runtimes directly — a harness has no
    composition root — so the guard is installed at the class attribute that call reads. It is the product's own
    guard over a real file, reverted with the test; it decides nothing the adapters' scenarios do not already ask.
    """
    installed = []
    for _implementation, runtime_cls in _runtime_classes():
        monkeypatch.setattr(runtime_cls, attribute, value, raising=False)
        installed.append(runtime_cls)
    if not installed:
        pytest.skip("BLOCKED — no Mission runtime module importable, so there is no production posture to wire")