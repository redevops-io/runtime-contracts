"""Measure the authorization matrix under ``AGENTIC_OS_PROFILE=production`` with the durable stores wired.

    AGENTIC_OS_ROOT=… AGENTIC_OS_ENTERPRISE_ROOT=… \
      python scripts/authz_production_matrix.py [--json OUT]

The production profile demands configuration before it says anything about authorization: a durable approval
replay store, a durable authority envelope store and ledger (``agentic_os.mission.profile.assert_authority``).
This script provides exactly what :mod:`tests.authz_contract.durable_stores` provides for a test run — the
product's own SQLite classes over temporary files, plus the owner-side envelope issuance a composition root
would perform — and then runs the same seven scenarios the default-profile matrix runs.

Its output is a *measurement*, never a pinned expectation: the verdicts in
``tests/authz_contract/qualification.json`` are the default-profile qualification, and this script compares
against them without changing them. Cells that differ are printed as deviations with the posture that produced
them, because a production run that quietly agreed with the default profile would hide how much of the
agreement was configuration.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import secrets
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from adapters._implementations import ROOT_ENV, import_module                      # noqa: E402
from runtime_contracts.authz.qualification import (ALL_INVARIANTS, CaseResult, Qualification,  # noqa: E402
                                                   load_expectations, matrix_from_cells,
                                                   qualification_to_verdict)
from runtime_contracts.authz.suite import run_invariant                             # noqa: E402

EXPECTATIONS = pathlib.Path("tests/authz_contract/qualification.json")
ADAPTERS = (("agentic-os", "adapters.agentic_os_kernel.adapter", "KernelAuthzAdapter"),
            ("agentic-os-enterprise", "adapters.agentic_os_enterprise.adapter", "EnterpriseAuthzAdapter"))
ENV = ("AGENTIC_OS_PROFILE", "AGENTIC_OS_REPLAY_DB", "AGENTIC_OS_AUTHORITY_DB", "AGENTIC_OS_APPROVAL_SECRET",
       "AGENTIC_OS_CONTROL_TOKEN")


def provision(root: pathlib.Path) -> dict[str, str]:
    """The environment the production profile asks for — temporary private files, random secrets."""
    env = {"AGENTIC_OS_PROFILE": "production",
           "AGENTIC_OS_REPLAY_DB": str(root / "replay.db"),
           "AGENTIC_OS_AUTHORITY_DB": str(root / "authority.db"),
           "AGENTIC_OS_APPROVAL_SECRET": secrets.token_hex(32),
           "AGENTIC_OS_CONTROL_TOKEN": secrets.token_hex(16)}
    for name, value in env.items():
        os.environ[name] = value
    os.environ.pop("AGENTIC_OS_OPERATOR_ALLOW_ANONYMOUS", None)
    os.environ.pop("AGENTIC_OS_REQUIRE_DURABLE_REPLAY", None)
    return env


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", metavar="PATH", help="write the production-profile matrix as JSON")
    args = parser.parse_args()

    root = pathlib.Path(tempfile.mkdtemp(prefix="rc-authz-production-"))
    env = provision(root)
    authority = import_module("agentic-os", "agentic_os.mission.authority")
    approval = import_module("agentic-os", "agentic_os.mission.approval")
    guard = authority.AuthorityGuard(authority.SqliteEnvelopeStore(env["AGENTIC_OS_AUTHORITY_DB"]),
                                     authority.SqliteLedger(env["AGENTIC_OS_AUTHORITY_DB"]))
    if not getattr(guard, "durable", False):
        print("REFUSING: the envelope/ledger pair is not durable — the production profile cannot be satisfied",
              file=sys.stderr)
        return 2
    replay = approval.default_replay_guard()
    if isinstance(replay, approval.ReplayGuard):
        print(f"REFUSING: {ROOT_ENV['agentic-os']} run without a durable replay guard ({type(replay).__name__})",
              file=sys.stderr)
        return 2

    # The composition root's two jobs a harness has to do itself: hand the runtime the durable guard, and issue
    # each mission the envelope its own declared authority allows — exact capability names, no family expansion
    # (see ``capability_grants``). Both are the provisioning that
    # tests/authz_contract/durable_stores.py performs for a pytest run, so the two measure one posture.
    sys.path.insert(0, str(REPO / "tests"))
    from authz_contract.durable_stores import (PRODUCTION_MISSION_TENANT, _runtime_classes,
                                               issue_mission_envelope)
    issued: list[str] = []
    for _implementation, runtime_cls in _runtime_classes():
        runtime_cls.authority = guard
        original = runtime_cls.create_mission

        def create(self, *a, _original=original, **kw):
            mission = _original(self, *a, **kw)
            if not getattr(mission, "tenant", ""):
                mission.tenant = PRODUCTION_MISSION_TENANT
            issue_mission_envelope(authority, guard, mission, registry=getattr(self, "registry", None))
            issued.append(str(mission.id))
            return mission

        runtime_cls.create_mission = create

    cells: list[CaseResult] = []
    for implementation, module_name, class_name in ADAPTERS:
        import importlib
        try:
            adapter = getattr(importlib.import_module(module_name), class_name)()
        except Exception as exc:  # noqa: BLE001 — an adapter that cannot start under production is a finding
            cells.extend(CaseResult(inv, implementation, Qualification.BLOCKED,
                                    f"{type(exc).__name__}: {exc}") for inv in ALL_INVARIANTS)
            continue
        for invariant in ALL_INVARIANTS:
            cells.append(run_invariant(invariant, adapter))
        adapter.close()

    expectations = load_expectations(EXPECTATIONS) if EXPECTATIONS.exists() else ()
    matrix = matrix_from_cells(cells, expectations)
    pinned = {(e.invariant, e.implementation): e for e in expectations}
    print(f"profile=production  durable_replay={type(replay).__name__}  "
          f"authority_store={type(guard.envelopes).__name__}  envelopes_issued={len(issued)}")
    print(f"{'invariant'.ljust(30)} {'implementation'.ljust(24)}  production   default-profile")
    for cell in cells:
        expectation = pinned.get((cell.invariant, cell.implementation))
        pinned_verdict = expectation.verdict.value if expectation else "(unpinned)"
        mark = "  <-- differs from the default profile" if expectation and expectation.verdict is not cell.verdict else ""
        print(f"{cell.invariant.value.ljust(30)} {cell.implementation.ljust(24)}  "
              f"{cell.verdict.value.ljust(12)}  {pinned_verdict}{mark}"
              + (f"   {cell.detail[:70]}" if cell.detail else ""))

    if args.json:
        artifact = json.loads(matrix.to_json())
        artifact["profile"] = "production"
        artifact["pinned_matrix_profile"] = "default"
        artifact["posture"] = {"durable_replay_guard": type(replay).__name__,
                               "envelope_store": type(guard.envelopes).__name__,
                               "ledger": type(guard.ledger).__name__,
                               "envelopes_issued": len(issued),
                               "stores": sorted(p.name for p in root.glob("*.db"))}
        artifact["verdict_counts"] = {v.value: sum(1 for c in cells if c.verdict is v)
                                      for v in Qualification}
        artifact["verification_counts"] = {}
        for cell in cells:
            key = qualification_to_verdict(cell.verdict).value
            artifact["verification_counts"][key] = artifact["verification_counts"].get(key, 0) + 1
        pathlib.Path(args.json).write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())