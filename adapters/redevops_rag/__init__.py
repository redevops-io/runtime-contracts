"""redevops-rag retrieval adapter for the authorization contract (issue #627).

Lazy so a machine without the checkout — or without ``duckdb`` — reaches the probe's own ``AdapterBlocked``
message instead of an ``ImportError`` at package import.
"""

__all__ = ["RetrievalProbe"]


def __getattr__(name):  # PEP 562
    if name == "RetrievalProbe":
        from importlib import import_module
        return import_module(f"{__name__}.adapter").RetrievalProbe
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")