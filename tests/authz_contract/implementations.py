"""Which implementations this machine can run, and how each one is reached.

Kept separate from the tests so the same registry drives the cells, the negative controls and the
matrix script — one definition of "what was actually tested", three consumers.
"""
from __future__ import annotations

import pathlib
from typing import Iterator, Sequence

import pytest

from adapters.agentic_os_enterprise import mutants as enterprise_mutants
from adapters.agentic_os_kernel import mutants as kernel_mutants
from runtime_contracts.authz.qualification import ALL_INVARIANTS, Expectation, Invariant, Matrix, Qualification
from runtime_contracts.authz.qualification import load_expectations, matrix_from_cells
from runtime_contracts.authz.suite import AdapterBlocked, AuthzAdapter, run_invariant

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXPECTATIONS = pathlib.Path(__file__).with_name("qualification.json")

REAL_ADAPTERS = ("adapters.agentic_os_kernel.adapter:KernelAuthzAdapter",
                 "adapters.agentic_os_enterprise.adapter:EnterpriseAuthzAdapter")

MUTANT_SETS = {"agentic-os": kernel_mutants.MUTANTS, "agentic-os-enterprise": enterprise_mutants.MUTANTS}

#: Each implementation's shipped adapter, keyed the way the matrix and the mutant sets key them. A test that
#: finds no control to run needs to say which of two reasons it has: the control does not exist (a defect in
#: this repo) or the edition is not checked out here (a defect in the run). That distinction needs the name.
ADAPTER_REFERENCE = {"agentic-os": REAL_ADAPTERS[0], "agentic-os-enterprise": REAL_ADAPTERS[1]}


def build(reference: str) -> AuthzAdapter:
    """Instantiate ``module:Class``. An unavailable implementation raises ``AdapterBlocked`` with the reason."""
    module_name, _, class_name = reference.partition(":")
    import importlib
    cls = getattr(importlib.import_module(module_name), class_name)
    return cls()


def skip_if_blocked(reference_or_cls):
    """Build an adapter or skip the test with the reason it could not run. Never a silent pass."""
    try:
        return build(reference_or_cls) if isinstance(reference_or_cls, str) else reference_or_cls()
    except AdapterBlocked as exc:
        pytest.skip(f"BLOCKED — {exc}")


def cells_for(reference: str) -> list:
    adapter = skip_if_blocked(reference)
    return [run_invariant(inv, adapter) for inv in ALL_INVARIANTS]


def observed_matrix(references: Sequence[str] | None = None) -> Matrix:
    """Run every (invariant, real implementation) cell and pair it with the pinned expectations."""
    refs = list(references or REAL_ADAPTERS)
    cells = []
    for ref in refs:
        cells.extend(cells_for(ref))
    return matrix_from_cells(cells, load_expectations(EXPECTATIONS))


def mutants_breaking(invariant: Invariant):
    """Every mutant that claims to break ``invariant``, as ``(implementation, class)`` pairs."""
    out = []
    for implementation, mutants in MUTANT_SETS.items():
        for cls in mutants:
            if getattr(cls, "breaks", None) == invariant.value:
                out.append((implementation, cls))
            elif getattr(cls, "demonstrates", None) == invariant.value:
                out.append((implementation, cls))
    return out