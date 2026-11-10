"""The shared authorization-contract suite (issue #626).

The suite runs the seven invariants through each edition's own enforcement seams and reports a verdict per
cell. It lives in ``tests/`` because it is a test suite; the contract, the scenario definitions and the
verdict vocabulary live in ``runtime_contracts.authz`` so an edition's CI can import them from the package
rather than from this directory.

Adapters are constructed lazily, and a missing implementation checkout is reported as ``BLOCKED`` — the
tests skip with the reason, and no cell is ever satisfied by the absence of a product.
"""