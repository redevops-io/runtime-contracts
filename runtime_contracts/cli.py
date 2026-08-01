"""`contracts status` and `contracts verify` — visibility without a red build.

An absent adapter must remain visible. It must not make the suite permanently
red for components that have not entered adoption: a build that is always red
reports nothing, and the gap it was meant to surface becomes invisible for the
opposite reason.

So maturity is declared per implementation, and only a component that has
*claimed* a level is held to it.
"""
from __future__ import annotations

import argparse
import pathlib
import sys
from typing import Any, Dict

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

ORDER = ["NOT_LOCATED", "PLANNED", "SPECIFIED", "ADAPTER_STARTED", "PARTIAL",
         "CONFORMANT", "DEPLOYED_CONFORMANT"]


def _load(name: str) -> Dict[str, Any]:
    return yaml.safe_load((ROOT / "adoption" / name).read_text())


def status() -> int:
    impls = _load("implementations.yaml")["implementations"]
    gates = _load("release-gates.yaml")

    print(f"runtime-contracts v{_load('implementations.yaml')['contract_version']}"
          "  —  proposed canonical contract, adoption pending\n")
    width = max(len(k) for k in impls)
    for name, spec in sorted(impls.items()):
        state = spec.get("status", "NOT_LOCATED")
        gate = gates["release_gate"].get(name, {}).get("minimum", "NOT_LOCATED")
        meets = ORDER.index(state) >= ORDER.index(gate)
        mark = "ok " if meets else "GAP"
        print(f"  [{mark}] {name:<{width}}  {state:<20} gate {gate}")
        if spec.get("warning"):
            print(f"        ! {' '.join(spec['warning'].split())}")

    print()
    for gate in gates.get("additional_gates", []):
        mark = "ok " if gate.get("currently_met") else "GAP"
        print(f"  [{mark}] {gate['id']}: {' '.join(gate['requirement'].split())}")
        if not gate.get("currently_met") and gate.get("blocking_reason"):
            print(f"        ! {' '.join(gate['blocking_reason'].split())}")
    return 0


def verify(implementation: str) -> int:
    impls = _load("implementations.yaml")["implementations"]
    if implementation not in impls:
        print(f"unknown implementation {implementation!r}", file=sys.stderr)
        return 2

    spec = impls[implementation]
    state = spec.get("status", "NOT_LOCATED")
    gate = _load("release-gates.yaml")["release_gate"].get(
        implementation, {}).get("minimum", "NOT_LOCATED")

    if ORDER.index(state) < ORDER.index(gate):
        print(f"FAIL {implementation}: at {state}, release gate requires {gate}")
        return 1

    if ORDER.index(state) < ORDER.index("ADAPTER_STARTED"):
        print(f"ok   {implementation}: {state} — no adapter claimed, nothing to "
              "verify. This is a visible gap, not a failure.")
        return 0

    adapter = ROOT / spec["adapter"] / "mapping.yaml"
    if not adapter.exists():
        print(f"FAIL {implementation}: claims {state} but {adapter} is absent")
        return 1

    print(f"ok   {implementation}: {state}, adapter present")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="contracts")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    v = sub.add_parser("verify")
    v.add_argument("--implementation", required=True)

    args = parser.parse_args(argv)
    return status() if args.command == "status" else verify(args.implementation)


if __name__ == "__main__":
    raise SystemExit(main())
