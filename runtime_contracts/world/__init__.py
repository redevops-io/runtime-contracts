"""Dataset worlds — the canonical entry contract for reproducible demo/product scenarios.

A dataset world enters the runtime as :class:`WorldEvent`s carrying canonical entities, content-addressed
evidence, an explicit realism class, and optional ground truth; the :class:`IdentityGraph` keeps one
identity across every app projection; the :class:`WorldRegistry` catalogs the worlds; and
:class:`VisualTrace` is the presentation stream the animated execution canvas renders. This replaces the
fictional single-tenant demo object with reproducible, provenance-preserving worlds.
"""
from __future__ import annotations

from .event import (
    KNOWN_EVENT_TYPES,
    EntityKind,
    EntityRef,
    GroundTruth,
    RealismClass,
    WorldEvent,
    LEAD_RECEIVED, TICKET_OPENED, INVOICE_OVERDUE, USAGE_CHANGED, THREAT_DETECTED,
    SIGNAL_OBSERVED, ONBOARDING_REQUESTED, DEPLOYMENT_EVENT,
)
from .identity import IdentityGraph
from .registry import WorldDescriptor, WorldRegistry, default_registry
from .trace import (
    BusinessBlock,
    Capsule,
    MilestoneKind,
    NeedsYouReason,
    TraceMilestone,
    VisualTrace,
)

__all__ = [
    "WorldEvent", "EntityRef", "EntityKind", "GroundTruth", "RealismClass", "KNOWN_EVENT_TYPES",
    "LEAD_RECEIVED", "TICKET_OPENED", "INVOICE_OVERDUE", "USAGE_CHANGED", "THREAT_DETECTED",
    "SIGNAL_OBSERVED", "ONBOARDING_REQUESTED", "DEPLOYMENT_EVENT",
    "IdentityGraph",
    "WorldDescriptor", "WorldRegistry", "default_registry",
    "BusinessBlock", "Capsule", "MilestoneKind", "NeedsYouReason", "TraceMilestone", "VisualTrace",
]
