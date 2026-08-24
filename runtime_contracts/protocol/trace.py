"""Mission-native trace identity (0.3.x) — the semantic source of truth OpenTelemetry exports.

A ReDevOps Mission is the **root trace**. Discovery, planner decisions, context/evidence choices,
governance verdicts, capability invocations and reconciliation are spans in one causal tree rooted at the
Mission; a deployment substrate (Argo Workflows, raw Kubernetes, Terraform, an app's own spans) nests
**underneath** the Mission node that caused it — never the other way around. That ordering is the whole
point: it lets one causal tree answer both *"why did we decide to deploy?"* and *"which pod/artifact took
4 seconds?"*.

``TraceContext`` is that identity in a W3C-Trace-Context-compatible form, so any OTel exporter can carry it
and any substrate can be told to parent its spans under ours. Two invariants make the tree sound:

  * **The Mission mints the trace_id (``root``); it is only ever propagated *down* (``child``).** ``child``
    keeps the trace_id and parents the new span to the current one — there is no operation that adopts an
    incoming substrate trace_id as the root, so Argo/K8s spans can only ever nest beneath a Mission node.
  * **IDs are content-addressed, not random.** The trace/span ids derive from the Mission and the node
    path via the same canonical hash as every other runtime identity, so a replay reproduces the exact
    trace — telemetry is replayable, not a fresh random tree each run.

This module has **no OpenTelemetry dependency**: it is the canonical identity + the pure projection of a
runtime event to an OTel-shaped span dict. The actual OTLP export and the Argo adapter are plugins that
consume this — the native record stays the source of truth, OTel stays the interoperability layer.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .seal import content_hash

_MISSION_ATTR = "redevops.mission_id"
_NODE_ATTR = "redevops.node_id"
_CAP_ATTR = "redevops.capability"
_INTENT_ATTR = "redevops.intent_id"


def _hexn(seed, n: int) -> str:
    # Content-addressed id of n hex chars, from the canonical hash (deterministic → replay-stable).
    return content_hash(seed).split(":", 1)[-1][:n]


@dataclass(frozen=True)
class TraceContext:
    """A W3C-compatible trace identity carrying the Mission semantics down the causal tree.

    ``trace_id`` (128-bit / 32 hex) is minted once by the Mission root; ``span_id`` (64-bit / 16 hex)
    identifies this node/step; ``parent_span_id`` links it to its cause. The semantic refs (mission/node/
    capability/intent) travel as OTel baggage so a substrate span can be attributed back to the Mission."""
    trace_id: str
    span_id: str
    parent_span_id: str = ""
    mission_id: str = ""
    node_id: str = ""
    capability: str = ""
    intent_id: str = ""
    flags: str = "01"                     # W3C trace-flags; "01" = sampled

    # ── minting: Mission is the root; identity only ever flows downward ──

    @staticmethod
    def root(mission_id: str, *, intent_id: str = "", trace_id: str | None = None) -> "TraceContext":
        """The Mission's root span. ``trace_id`` is derived from the mission id (content-addressed, so a
        replay reproduces it) unless one is supplied — e.g. an *outer* ReDevOps mission threading its own
        trace in. A substrate trace is never passed here; it can only ``child`` under a node."""
        tid = trace_id or _hexn({"kind": "trace", "mission": mission_id}, 32)
        sid = _hexn({"kind": "span", "trace": tid, "step": "root"}, 16)
        return TraceContext(trace_id=tid, span_id=sid, mission_id=mission_id, intent_id=intent_id)

    def child(self, *, node_id: str = "", capability: str = "", step: str = "") -> "TraceContext":
        """Derive a child span under this one: **same trace_id**, parent = this span. Used for every
        descent — Mission → plan node → capability invocation → substrate. ``step`` disambiguates sibling
        spans that share node/capability (e.g. sequence or phase)."""
        seed = {"trace": self.trace_id, "parent": self.span_id,
                "node": node_id, "cap": capability, "step": step}
        sid = _hexn(seed, 16)
        return TraceContext(
            trace_id=self.trace_id, span_id=sid, parent_span_id=self.span_id, mission_id=self.mission_id,
            node_id=node_id or self.node_id, capability=capability or self.capability,
            intent_id=self.intent_id, flags=self.flags)

    # ── propagation: hand our identity to a substrate so its spans nest under us ──

    def traceparent(self) -> str:
        """W3C ``traceparent`` header: ``00-<trace_id>-<span_id>-<flags>``. Propagate this into Argo /
        the OTel collector / a downstream so that substrate's spans parent to *this* span."""
        return f"00-{self.trace_id}-{self.span_id}-{self.flags}"

    def baggage(self) -> dict:
        """OTel baggage / span attributes carrying the Mission semantics into substrate spans, so an Argo
        pod span can be attributed back to the Mission node that caused it."""
        b = {_MISSION_ATTR: self.mission_id}
        if self.node_id:
            b[_NODE_ATTR] = self.node_id
        if self.capability:
            b[_CAP_ATTR] = self.capability
        if self.intent_id:
            b[_INTENT_ATTR] = self.intent_id
        return b

    @staticmethod
    def parse_traceparent(traceparent: str, **semantic) -> "TraceContext":
        """Read a propagated ``traceparent`` back into a context (for a receiver continuing the trace).
        Extra kwargs (mission_id/node_id/…) re-attach the semantic refs the header does not carry."""
        parts = traceparent.strip().split("-")
        if len(parts) != 4 or parts[0] != "00":
            raise ValueError(f"not a W3C traceparent: {traceparent!r}")
        _, tid, sid, flags = parts
        return TraceContext(trace_id=tid, span_id=sid, flags=flags, **semantic)

    def canonical_form(self) -> dict:
        d = {"trace_id": self.trace_id, "span_id": self.span_id, "flags": self.flags}
        for k, v in (("parent_span_id", self.parent_span_id), ("mission_id", self.mission_id),
                     ("node_id", self.node_id), ("capability", self.capability),
                     ("intent_id", self.intent_id)):
            if v:
                d[k] = v
        return d


# ── pure projection: a runtime event → an OTel-shaped span dict (no OTel dependency) ──

# Which GovernanceDisposition / result maps to an OTel span status.
def _status(result: str) -> str:
    return "ERROR" if result == "error" else "OK"


def span_of(event, ctx: TraceContext) -> dict:
    """Project one ``RuntimeSecurityEvent`` (duck-typed) onto an OpenTelemetry-shaped span dict, under the
    span identity ``ctx``. Attributes carry the Mission baggage plus the event's declared surface — network,
    classifications, permissions, authority chain — as **references and hashes, never payloads**, honouring
    the telemetry invariant. An exporter plugin turns this dict into a real OTLP span."""
    name = f"{getattr(event, 'capability', '') or getattr(event, 'event_type', 'event')}"
    attrs = dict(ctx.baggage())
    attrs["redevops.event_id"] = getattr(event, "event_id", "")
    attrs["redevops.event_type"] = getattr(event, "event_type", "")
    attrs["redevops.kind"] = getattr(getattr(event, "kind", None), "value", "")
    net = tuple(getattr(event, "network", ()) or ())
    cls = tuple(getattr(event, "data_classifications", ()) or ())
    perms = tuple(getattr(event, "permissions_exercised", ()) or ())
    chain = getattr(event, "authority_chain_ref", "")
    if net:
        attrs["redevops.network"] = list(net)
    if cls:
        attrs["redevops.data_classifications"] = list(cls)
    if perms:
        attrs["redevops.permissions"] = list(perms)
    if chain:
        attrs["redevops.authority_chain_ref"] = chain
    return {
        "name": name,
        "trace_id": ctx.trace_id,
        "span_id": ctx.span_id,
        "parent_span_id": ctx.parent_span_id,
        "kind": "INTERNAL",
        "status": _status(getattr(event, "result", "ok")),
        "attributes": attrs,
    }
