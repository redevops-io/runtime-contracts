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
from dataclasses import dataclass
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
    yield DurableStores(replay_path=root / "replay.db", authority_path=root / "authority.db",
                        guard=guard, replay_guard=replay)


def _install_guard_on_runtimes(monkeypatch, guard) -> None:
    """Give every Mission runtime built in this test the durable guard a production deployment must inject.

    ``MissionRuntime.__init__`` calls ``profile.assert_authority(self.authority, …)`` and refuses to start in
    production without a durable guard. The contract adapters construct runtimes directly — a harness has no
    composition root — so the guard is installed at the class attribute that call reads. It is the product's own
    guard over a real file, reverted with the test; it decides nothing the adapters' scenarios do not already ask.
    """
    installed = []
    for module_name, implementation in (("agentic_os.mission.runtime", KERNEL),
                                        ("agentic_os_enterprise.mission.runtime", ENTERPRISE)):
        try:
            add_implementation_root(implementation)
            module = import_module(implementation, module_name)
        except AdapterBlocked:
            continue                                  # an overlay that is not checked out is not under test here
        runtime_cls = getattr(module, "MissionRuntime", None)
        if runtime_cls is None or runtime_cls in installed:
            continue
        monkeypatch.setattr(runtime_cls, "authority", guard, raising=False)
        installed.append(runtime_cls)
    if not installed:
        pytest.skip("BLOCKED — no Mission runtime module importable, so there is no production posture to wire")