"""The enterprise overlay adapter (see :mod:`adapters.agentic_os_enterprise.adapter`).

Lazy attribute access so a machine without the overlay checkout reaches the adapter's ``AdapterBlocked``
message instead of an ``ImportError`` while importing this package.
"""

__all__ = ["EnterpriseAuthzAdapter", "mutants"]


def __getattr__(name):  # PEP 562
    if name == "EnterpriseAuthzAdapter":
        from .adapter import EnterpriseAuthzAdapter
        return EnterpriseAuthzAdapter
    if name == "mutants":
        # import_module, not ``from . import`` — the latter re-enters this __getattr__ and recurses.
        from importlib import import_module
        return import_module(f"{__name__}.mutants")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")