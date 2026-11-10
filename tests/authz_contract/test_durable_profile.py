"""The production profile: what it refuses, and what it needs in order to be worth running.

``AGENTIC_OS_PROFILE=production`` changes the *configuration an implementation insists on*, not what it decides
about a principal. Run the matrix under it with nothing provisioned and cells fail on ``ReplayProtectionNotDurable``
and ``ProfileError`` — eight failures that describe a deployment, and that read, in a report, exactly like an
authorization gap. Read the wrong way round, they could be "fixed" by translating them into PASS, which is the
mistake this file exists to make impossible from both directions:

* a configuration refusal may never be reported as a pass, and never as an authorization finding either;
* with the durable stores the profile asks for, provisioned for real (temporary SQLite files opened by the
  product's own classes — see :mod:`.durable_stores`), no cell may fail because the process was not provisioned.

What this file deliberately does **not** claim: that the pinned verdicts in ``qualification.json`` hold under
production. They are measured in the default profile. In production a mission node is checked against its owner's
authority envelope, which the contract scenarios do not mint, so a production run is a configuration statement and
a posture statement, not a substitute for the matrix — the verdicts it produces are printed, never compared.
"""
from __future__ import annotations

import time

import pytest

from runtime_contracts.authz.qualification import ALL_INVARIANTS, Qualification, qualification_to_verdict
from runtime_contracts.authz.suite import run_invariant
from runtime_contracts.models.verification import Verdict

from .durable_stores import (ENV_AUTHORITY_DB, ENV_REPLAY_DB, KERNEL, approval_module,
                             clear_durable_configuration, durable_production, is_configuration_failure,
                             profile_module)  # noqa: F401 — durable_production is a fixture, imported to be seen
from .implementations import REAL_ADAPTERS, skip_if_blocked

#: The kernel owns the profile and the durable stores; a run needs one checkout to say anything at all.
_KERNEL_REFERENCE = next((ref for ref in REAL_ADAPTERS if f".{KERNEL.replace('-', '_')}." in ref), REAL_ADAPTERS[0])


def _run_matrix(reference: str) -> tuple[list, str]:
    """Every cell for one implementation, plus the reason the adapter refused to be built.

    A refusal to construct is the interesting outcome here, so it is returned rather than raised: an adapter
    that cannot start under the production profile has told us about its configuration, not about its
    authorization. The adapter is closed afterwards — building one swaps process-wide tenancy globals, and an
    adapter that reported and stayed open would leak its registry into whatever test runs next.
    """
    try:
        adapter = skip_if_blocked(reference)
    except Exception as exc:  # noqa: BLE001 — pytest.skip raises BaseException, so a BLOCKED checkout still skips
        return [], f"{type(exc).__name__}: {exc}"
    try:
        return [run_invariant(invariant, adapter) for invariant in ALL_INVARIANTS], ""
    finally:
        try:
            adapter.close()
        except Exception:  # noqa: BLE001 — closing must neither change a verdict nor hide one
            pass


def preflight_modules():
    """The product's own ``profile`` and ``approval`` modules, taken together.

    Both arrive through :mod:`durable_stores`, which skips with the BLOCKED reason when the checkout is not on this
    machine: the production profile is the product's own code, so a run without it has no preflight to read, and a
    missing checkout is recorded as skipped rather than as a broken test.
    """
    return profile_module(), approval_module()


def _describe(cells: list) -> str:
    return "\n".join(f"  {c.invariant.value}: {c.verdict.value} — {c.detail[:160]}" for c in cells) or "  (no cells ran)"


def test_the_products_own_preflight_names_the_durable_stores(monkeypatch) -> None:
    """Production refuses for a named reason, before any authorization code is reached.

    This is the product's own preflight (``python -m agentic_os.mission.profile --require-production``), not the
    harness's guess about it: it is the list a deployer is told to satisfy.
    """
    clear_durable_configuration(monkeypatch)
    profile, _approval = preflight_modules()
    problems = profile.check_environment()
    named = [p for p in problems if ENV_REPLAY_DB in p or ENV_AUTHORITY_DB in p]
    assert named, (f"the production preflight reported {problems} without naming the durable replay and authority "
                   f"stores; the profile no longer asks for them, so this pair of tests needs revisiting")
    _profile, approval = preflight_modules()
    with pytest.raises(approval.ReplayProtectionNotDurable):
        approval.default_replay_guard()


def test_a_configuration_refusal_is_never_reported_as_authorization(monkeypatch) -> None:
    """Unprovisioned production: the matrix stops on configuration, and says so in terms of configuration.

    Two things have to hold for that to be honest. A cell that stopped on configuration is not a pass — nothing
    may read an unprovisioned process as a qualified one, through ``Qualification`` or through the verdict
    vocabulary. And it is not an authorization finding either: the detail has to name the deployment, because the
    alternative is a report that claims a plane leaked authority when nothing was ever wired.
    """
    clear_durable_configuration(monkeypatch)
    cells, refusal = _run_matrix(_KERNEL_REFERENCE)
    if refusal:
        assert is_configuration_failure(refusal), (
            f"{KERNEL} refused to start under the production profile for a reason that is not configuration: "
            f"{refusal} — that is a finding about the product, and belongs in the matrix, not here")
        return
    stopped = [c for c in cells if is_configuration_failure(c.detail)]
    if not stopped:
        pytest.skip(f"{KERNEL} no longer fails a cell on missing durable stores in production; "
                    "test_the_products_own_preflight_names_the_durable_stores still pins the preflight, and "
                    "test_production_profile_with_durable_stores_has_no_configuration_failures still runs the cells")
    for cell in stopped:
        assert cell.verdict is not Qualification.PASS, (
            f"{cell.invariant.value} passed on a process the profile refuses to start: {cell.detail}")
        assert qualification_to_verdict(cell.verdict) is not Verdict.PASS, (
            f"{cell.invariant.value}: a configuration refusal was mapped to {qualification_to_verdict(cell.verdict)}")


def test_production_profile_with_durable_stores_has_no_configuration_failures(durable_production) -> None:
    """Provision the stores the profile demands and the refusals have to disappear.

    The stores are checked before any cell runs — the files exist and hold the product's own schema, and the
    durable replay guard refuses a nonce it has already consumed. A second use of the same nonce is the whole
    point of the file: a guard that accepted it would be an in-memory set with a path in its name.
    """
    replay_tables = durable_production.tables(durable_production.replay_path)
    assert "used_nonces" in replay_tables, (
        f"{durable_production.replay_path} holds {sorted(replay_tables)}, not the product's replay schema")
    authority_tables = durable_production.tables(durable_production.authority_path)
    assert {"envelopes", "leases"} <= authority_tables, (
        f"{durable_production.authority_path} holds {sorted(authority_tables)}; the durable envelope store and "
        "usage ledger are what the production profile asks for")

    nonce = "authz-contract-nonce"
    expiry = time.time() + 60.0
    assert durable_production.replay_guard.consume(nonce, expiry), "the durable guard refused a first use"
    assert not durable_production.replay_guard.consume(nonce, expiry), (
        "the durable guard accepted the same nonce twice: replay protection is not durable, so nothing here "
        "proves the production posture")

    profile, _approval = preflight_modules()
    durable_problems = [p for p in profile.check_environment()
                        if ENV_REPLAY_DB in p or ENV_AUTHORITY_DB in p]
    assert not durable_problems, (
        f"the stores are wired but the product's own preflight still refuses: {durable_problems}")

    for reference in REAL_ADAPTERS:
        cells, refusal = _run_matrix(reference)
        implementation = reference.split(".")[-2].replace("_", "-")     # …agentic_os_kernel.adapter:… → agentic-os-kernel
        if refusal:
            assert not is_configuration_failure(refusal), (
                f"{implementation} still refuses to start with durable stores configured: {refusal}\n"
                "Either the fixture does not provide what the profile asks for (add it to durable_stores.py, "
                "with the product's own class), or the refusal is a real finding and belongs in the matrix")
            continue
        offenders = [c for c in cells if is_configuration_failure(c.detail)]
        assert not offenders, (
            f"{implementation}: {len(offenders)} cell(s) failed on configuration, not authorization:\n"
            f"{_describe(offenders)}\nThe production profile needs exactly what durable_stores.py provisions; "
            "if this is a new requirement, provision it there or record it in docs/AUTHZ_QUALIFICATION.md as a "
            "setup step. Do not move a verdict, and do not run the matrix in production to get one.")
        blocked = [c for c in cells if c.verdict is Qualification.BLOCKED]
        if len(blocked) == len(cells):
            pytest.skip(f"{implementation}: every cell is BLOCKED under the production profile — {_describe(cells)}")