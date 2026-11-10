"""Print or write the authorization-contract qualification matrix (issue #626 / #627).

    AGENTIC_OS_ROOT=… AGENTIC_OS_ENTERPRISE_ROOT=… REDEVOPS_RAG_ROOT=… \\
      python scripts/authz_matrix.py                 # table on stdout
      python scripts/authz_matrix.py --json out.json # machine-readable artifact
      python scripts/authz_matrix.py --check         # exit non-zero if a verdict moved

The matrix is the document a reviewer signs off on, so it is generated from a run and never typed by hand.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from runtime_contracts.authz.qualification import (ALL_INVARIANTS, Qualification, load_expectations,
                                                   matrix_from_cells, qualification_to_verdict)
from runtime_contracts.authz.suite import AdapterBlocked, run_invariant

EXPECTATIONS = pathlib.Path("tests/authz_contract/qualification.json")
ADAPTERS = (("agentic-os", "adapters.agentic_os_kernel.adapter", "KernelAuthzAdapter"),
            ("agentic-os-enterprise", "adapters.agentic_os_enterprise.adapter", "EnterpriseAuthzAdapter"))
#: Where the harness keeps deliberately-broken and reference variants, per implementation.
MUTANT_MODULES = (("agentic-os", "adapters.agentic_os_kernel.mutants"),
                  ("agentic-os-enterprise", "adapters.agentic_os_enterprise.mutants"))


def _build(module_name: str, class_name: str):
    import importlib
    return getattr(importlib.import_module(module_name), class_name)()


def _witnesses() -> dict[str, str]:
    """``"invariant|implementation" -> reference variant`` for the seams the harness can prove reachable.

    A ``reference_*`` variant is a harness-only implementation of the criterion, through the same seam as the
    product. Where a cell is unmet, naming its witness says the FAIL describes the product and not an
    assertion nobody could ever satisfy; where there is none, the gap should carry its reason in prose.
    """
    import importlib

    found: dict[str, str] = {}
    for implementation, module_name in MUTANT_MODULES:
        try:
            module = importlib.import_module(module_name)
        except Exception:  # noqa: BLE001 — a missing mutant module must not stop the matrix
            continue
        for cls in getattr(module, "MUTANTS", ()):
            variant = getattr(cls, "variant", "")
            demonstrated = getattr(cls, "demonstrates", "")
            if variant.startswith("reference_") and demonstrated:
                found[f"{demonstrated}|{implementation}"] = variant
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", metavar="PATH", help="write the matrix as JSON")
    parser.add_argument("--check", action="store_true", help="fail if an observed verdict differs from the "
                                                            "pinned expectation")
    parser.add_argument("--expectations", default=str(EXPECTATIONS))
    args = parser.parse_args()

    cells, blocked = [], []
    for implementation, module_name, class_name in ADAPTERS:
        try:
            adapter = _build(module_name, class_name)
        except AdapterBlocked as exc:
            blocked.append(str(exc))
            from runtime_contracts.authz.qualification import CaseResult
            cells.extend(CaseResult(inv, implementation, Qualification.BLOCKED, str(exc))
                         for inv in ALL_INVARIANTS)
            continue
        for invariant in ALL_INVARIANTS:
            cells.append(run_invariant(invariant, adapter))
        adapter.close()

    expectations = load_expectations(args.expectations) if pathlib.Path(args.expectations).exists() else ()
    matrix = matrix_from_cells(cells, expectations)
    witnesses = _witnesses()
    # Keyed off the pinned expectations, not off this run: a cell can also go unmet for a deployment reason
    # (no durable replay store, say), where a behavioural witness would witness the wrong thing.
    unwitnessed = [f"{e.invariant.value}/{e.implementation}" for e in expectations
                   if e.verdict in (Qualification.FAIL, Qualification.UNSUPPORTED)
                   and f"{e.invariant.value}|{e.implementation}" not in witnesses]

    width = max(len(c.implementation) for c in cells)
    print(f"{'invariant'.ljust(30)} {'implementation'.ljust(width)}  verdict        verification")
    for invariant in ALL_INVARIANTS:
        for implementation, _m, _c in ADAPTERS:
            cell = matrix.cell(invariant, implementation)
            if cell is None:
                continue
            witness = witnesses.get(f"{invariant.value}|{implementation}")
            print(f"{invariant.value.ljust(30)} {implementation.ljust(width)}  "
                  f"{cell.verdict.value.ljust(12)}  {qualification_to_verdict(cell.verdict).value}"
                  + (f"   {cell.detail[:80]}" if cell.detail else "")
                  + (f"   witness={witness}" if witness else ""))
    for gap in unwitnessed:
        # Not a failure: some criteria cannot be met in this deployment at all. It is the case the matrix
        # must not let a reader mistake for a settled verdict, and tests/authz_contract guards it too.
        print(f"NOTE: {gap} is unmet with no reference variant — nothing in this run shows the criterion "
              "can be met here")
    for note in blocked:
        print(f"BLOCKED: {note}")

    if args.json:
        artifact = json.loads(matrix.to_json())
        artifact["satisfiability_witnesses"] = witnesses
        artifact["unmet_without_witness"] = sorted(unwitnessed)
        pathlib.Path(args.json).write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {args.json}")

    if args.check:
        deviations = matrix.deviations()
        for line in deviations:
            print(f"DEVIATION: {line}", file=sys.stderr)
        return 1 if deviations else 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())