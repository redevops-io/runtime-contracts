"""The two places that state the version must agree.

`pyproject.toml` and `runtime_contracts.__version__` are both read by
consumers — one to pin, one to check what is running — and a package whose two
version strings differ can satisfy a pin while running something else. That is
not hypothetical: v0.2.3 shipped its `canonical_form` change with the module
still reporting 0.2.2, and a downstream test caught it as "the pin says 0.2.3,
0.2.2 is installed".
"""
from __future__ import annotations

import pathlib
import tomllib

import runtime_contracts

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_the_declared_and_reported_versions_agree():
    declared = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert runtime_contracts.__version__ == declared["project"]["version"], (
        f"pyproject says {declared['project']['version']} and the module says "
        f"{runtime_contracts.__version__}")
