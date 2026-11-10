"""The AGPL kernel adapter (see :mod:`adapters.agentic_os_kernel.adapter`).

The adapter is imported lazily: a machine without the kernel checkout must reach the adapter's own
``AdapterBlocked`` message, not an ``ImportError`` raised while importing this package.
"""

__all__ = ["KernelAuthzAdapter", "mutants"]


def __getattr__(name):  # PEP 562 — lazy so a missing checkout degrades to BLOCKED, not to a broken import
    if name == "KernelAuthzAdapter":
        from .adapter import KernelAuthzAdapter
        return KernelAuthzAdapter
    if name == "mutants":
        # import_module rather than ``from . import mutants``: the latter re-enters this __getattr__ while
        # the submodule is still being bound, which recurses.
        from importlib import import_module
        return import_module(f"{__name__}.mutants")
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")