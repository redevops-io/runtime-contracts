"""Security Telemetry Protocol (0.3.x) — the canonical ``RuntimeSecurityEvent``.

Security-relevant behaviour is part of the runtime *protocol*, not a log stream bolted on afterwards. A
consequential runtime action emits a ``RuntimeSecurityEvent``; events form an **append-only, causally
ordered stream**; a runtime projection folds them into trajectory state; and the Governance Plane
correlates the trajectory into a disposition (ALLOW / REQUIRE_REVIEW / NO_OVERRIDE / DENY). The event is
the evidence a later investigation or replay reads.

Three telemetry levels share **one envelope** rather than becoming three unrelated systems:

  * ``DECISION``  — why the runtime decided this (plan, candidates, evidence, model, policy, confidence).
  * ``EXECUTION`` — what actually happened (tool/API calls, files, subprocesses, network, resources, result).
  * ``SECURITY``  — the security-relevant transition (authority/privilege change, trust-boundary crossing,
    data movement, unusual fan-out, policy violation, plan-vs-observed divergence, containment).

Two invariants make this trustworthy rather than decorative:

  1. **Hashes, not raw payloads.** The envelope carries content-hashes of inputs/outputs and evidence refs
     — never raw sensitive data — so the stream is safe to persist, replay, and correlate across boundaries.
  2. **Not agent-reported.** These are emitted at the runtime/capability boundary, outside the model's
     control, so a compromised or misbehaving agent cannot lie by omission.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum

from ..canonical import content_hash, decimal_string
from .security import PrincipalRef


class CausalCycle(ValueError):
    """The append-only security-telemetry stream referenced a parent that forms a cycle — impossible for a
    causally-ordered append-only stream, so it is refused rather than silently reordered."""


class TelemetryKind(str, Enum):
    """Which of the three telemetry levels this event carries (they share one envelope)."""
    DECISION = "DECISION"
    EXECUTION = "EXECUTION"
    SECURITY = "SECURITY"


class SecurityEventType(str, Enum):
    """The security-relevant transition an event records (populated for the SECURITY level; other levels
    may carry a domain event_type string). The runtime/capability boundary produces these, not the agent."""
    AUTHORITY_GRANTED = "AUTHORITY_GRANTED"
    AUTHORITY_DELEGATED = "AUTHORITY_DELEGATED"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    TRUST_BOUNDARY_CROSSED = "TRUST_BOUNDARY_CROSSED"
    DATA_MOVEMENT = "DATA_MOVEMENT"
    NETWORK_ACCESS = "NETWORK_ACCESS"
    CAPABILITY_INVOKED = "CAPABILITY_INVOKED"
    POLICY_DECISION = "POLICY_DECISION"
    APPROVAL_GATE = "APPROVAL_GATE"
    PLAN_DIVERGENCE = "PLAN_DIVERGENCE"          # observed execution left the planned graph — a strong signal
    ANOMALOUS_FANOUT = "ANOMALOUS_FANOUT"        # unusual spawning / cross-series volume
    SANDBOX_VIOLATION = "SANDBOX_VIOLATION"
    CONTAINMENT = "CONTAINMENT"
    RECOVERY = "RECOVERY"
    # credential brokerage — authority to use a secret was granted/redeemed/revoked/denied (never the secret)
    CREDENTIAL_GRANT_ISSUED = "CREDENTIAL_GRANT_ISSUED"
    CREDENTIAL_REDEEMED = "CREDENTIAL_REDEEMED"
    CREDENTIAL_GRANT_REVOKED = "CREDENTIAL_GRANT_REVOKED"
    CREDENTIAL_GRANT_DENIED = "CREDENTIAL_GRANT_DENIED"


class GovernanceDisposition(str, Enum):
    """The Governance Plane's correlated disposition over a trajectory. Deny-wins by severity; NO_OVERRIDE
    is a DENY a human gate cannot lift."""
    ALLOW = "ALLOW"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"
    NO_OVERRIDE = "NO_OVERRIDE"
    DENY = "DENY"

    @property
    def rank(self) -> int:
        return {GovernanceDisposition.ALLOW: 0, GovernanceDisposition.REQUIRE_REVIEW: 1,
                GovernanceDisposition.NO_OVERRIDE: 2, GovernanceDisposition.DENY: 3}[self]


@dataclass(frozen=True)
class RuntimeSecurityEvent:
    """One canonical, content-addressed security-telemetry event. Most fields are optional so a DECISION,
    EXECUTION, or SECURITY event populates the subset it needs while sharing this envelope. ``canonical_form``
    carries hashes and refs — never raw payloads — and ``event_hash`` is the tamper-evident identity."""
    # ── identity ──
    event_id: str
    kind: TelemetryKind
    event_type: str                              # a SecurityEventType value, or a domain event name
    sequence: int = 0                            # monotonic per stream — total order fallback
    occurred_at: str = ""                        # ISO instant (transaction time)
    # ── runtime / mission / agent / capability identity ──
    runtime_id: str = ""
    mission_id: str = ""
    agent_id: str = ""
    capability: str = ""
    # ── causal ordering (partial order over the append-only stream) ──
    parent_event_id: str = ""
    causal_id: str = ""                          # groups a fan-out under one cause
    depth: int = 0
    # ── authority / identity / trust ──
    principal: PrincipalRef | None = None
    authority_chain_ref: str = ""                # AuthorityContext.chain_ref — the one chain a side effect resolves to
    permissions_requested: tuple[str, ...] = ()
    permissions_exercised: tuple[str, ...] = ()
    data_classifications: tuple[str, ...] = ()   # classifications touched
    trust_boundaries: tuple[str, ...] = ()       # boundaries crossed
    network: tuple[str, ...] = ()                # external endpoints/hosts accessed
    # ── selection ──
    model: str = ""
    tools: tuple[str, ...] = ()
    apis: tuple[str, ...] = ()
    # ── policy / gate ──
    policy_ref: str = ""
    policy_version: str = ""
    decision: str = ""                           # SecurityVerdict or GovernanceDisposition value for this event
    approvals: tuple[str, ...] = ()              # approval/gate event refs
    # ── artifacts: HASHES, never raw payloads ──
    evidence_refs: tuple[str, ...] = ()
    input_hash: str = ""
    output_hash: str = ""
    # ── resource consumption ──
    tokens: int = 0
    cost_usd: Decimal | None = None
    latency_ms: int = 0
    # ── result / side effects / verification ──
    result: str = ""                             # a status string, not a raw payload
    side_effects: tuple[str, ...] = ()
    verification: str = ""

    def canonical_form(self) -> dict:
        d: dict = {"event_id": self.event_id, "kind": self.kind.value, "event_type": self.event_type,
                   "sequence": self.sequence, "depth": self.depth}
        # only-when-set for every optional field, so events of different levels hash tightly and two
        # events that differ in any recorded fact are different events.
        for k, v in (("occurred_at", self.occurred_at), ("runtime_id", self.runtime_id),
                     ("mission_id", self.mission_id), ("agent_id", self.agent_id),
                     ("capability", self.capability), ("parent_event_id", self.parent_event_id),
                     ("causal_id", self.causal_id), ("authority_chain_ref", self.authority_chain_ref),
                     ("model", self.model), ("policy_ref", self.policy_ref),
                     ("policy_version", self.policy_version), ("decision", self.decision),
                     ("input_hash", self.input_hash), ("output_hash", self.output_hash),
                     ("result", self.result), ("verification", self.verification)):
            if v:
                d[k] = v
        for k, seq in (("permissions_requested", self.permissions_requested),
                       ("permissions_exercised", self.permissions_exercised),
                       ("data_classifications", self.data_classifications),
                       ("trust_boundaries", self.trust_boundaries), ("network", self.network),
                       ("tools", self.tools), ("apis", self.apis), ("approvals", self.approvals),
                       ("evidence_refs", self.evidence_refs), ("side_effects", self.side_effects)):
            if seq:
                d[k] = sorted(set(seq))
        if self.principal is not None:
            d["principal"] = self.principal.canonical_form()
        if self.tokens:
            d["tokens"] = self.tokens
        if self.latency_ms:
            d["latency_ms"] = self.latency_ms
        if self.cost_usd is not None:
            d["cost_usd"] = decimal_string(self.cost_usd)
        return d

    @property
    def event_hash(self) -> str:
        return content_hash(self.canonical_form())


def causal_order_events(events: "list[RuntimeSecurityEvent]") -> "list[RuntimeSecurityEvent]":
    """Deterministic stream order for security-telemetry events: topological by ``parent_event_id`` when
    present, breaking ties (and ordering roots) by ``sequence`` then ``event_id``. Events whose parent is
    absent from the set are treated as roots so a partial stream still orders.

    Named ``causal_order_events`` (not ``causal_order``) to stay distinct from the investigation-transition
    ``causal_order`` in ``runtime_contracts.models`` — the two order different event types and both are
    exported at the package root."""
    by_id = {e.event_id: e for e in events}
    indeg: dict[str, int] = {e.event_id: 0 for e in events}
    children: dict[str, list[str]] = {e.event_id: [] for e in events}
    for e in events:
        if e.parent_event_id and e.parent_event_id in by_id:
            indeg[e.event_id] += 1
            children[e.parent_event_id].append(e.event_id)
    tiebreak = lambda eid: (by_id[eid].sequence, by_id[eid].event_id)  # noqa: E731
    ready = sorted((eid for eid, d in indeg.items() if d == 0), key=tiebreak)
    out: list[RuntimeSecurityEvent] = []
    seen: set[str] = set()
    while ready:
        eid = ready.pop(0)
        if eid in seen:
            continue
        seen.add(eid)
        out.append(by_id[eid])
        for c in sorted(children[eid], key=tiebreak):
            indeg[c] -= 1
            if indeg[c] == 0:
                ready.append(c)
        ready.sort(key=tiebreak)
    if len(out) != len(events):
        raise CausalCycle("security-telemetry stream has a causal cycle")
    return out


# ──────────────────────────── projection + correlation (the trajectory, not the logs) ────────────────────────────


@dataclass
class SecurityTrajectory:
    """A runtime/local projection of the append-only event stream — the trajectory the Governance Plane
    correlates. Individually-permissible events fold into a series that is itself the security signal
    (the τ-bench insight): *read 2,000 records → archive → external upload* is three ALLOWs and one DENY.
    Additive and deterministic; hold one per mission/agent (or per correlation scope)."""
    events: list[RuntimeSecurityEvent] = field(default_factory=list)

    def add(self, event: RuntimeSecurityEvent) -> "SecurityTrajectory":
        self.events.append(event)
        return self

    def _union(self, attr: str) -> set[str]:
        out: set[str] = set()
        for e in self.events:
            out |= set(getattr(e, attr))
        return out

    @property
    def capabilities(self) -> set[str]:
        return {e.capability for e in self.events if e.capability}

    @property
    def network_endpoints(self) -> set[str]:
        return self._union("network")

    @property
    def data_classifications(self) -> set[str]:
        return self._union("data_classifications")

    @property
    def permissions_exercised(self) -> set[str]:
        return self._union("permissions_exercised")

    @property
    def event_types(self) -> set[str]:
        return {e.event_type for e in self.events}

    def records_read(self) -> int:
        """Total records read across the trajectory — read from a ``records_read`` side-effect token
        (``records_read=<n>``) so the count is produced at the capability boundary, not self-reported prose."""
        total = 0
        for e in self.events:
            for s in e.side_effects:
                if s.startswith("records_read="):
                    try:
                        total += int(s.split("=", 1)[1])
                    except ValueError:
                        pass
        return total

    def fanout(self) -> int:
        """Max children under any single cause — an unusual spawning / cross-series volume signal."""
        by_cause: dict[str, int] = {}
        for e in self.events:
            if e.causal_id:
                by_cause[e.causal_id] = by_cause.get(e.causal_id, 0) + 1
        return max(by_cause.values(), default=0)

    def divergence(self, planned_capabilities: "tuple[str, ...] | set[str]") -> set[str]:
        """Plan-vs-observed: capabilities that actually ran but were NOT in the planned execution graph.
        The runtime *knows* the intended graph, so this is a first-class intrinsic-security signal — no
        need to infer intent from telemetry the way an external product must."""
        return {c for c in self.capabilities if c not in set(planned_capabilities)}


# Sensitive-by-default classifications that make bulk read + external egress an exfiltration shape.
SENSITIVE_CLASSIFICATIONS = frozenset({"pii", "phi", "pci", "secret", "confidential", "restricted"})


def correlate(traj: SecurityTrajectory, *, planned_capabilities: "tuple[str, ...] | set[str]" = (),
              max_external_records: int = 100, max_fanout: int = 50) -> "tuple[GovernanceDisposition, list[str]]":
    """The reference Governance-Plane correlation: fold the trajectory into a disposition, deny-wins, with
    reasons. Deterministic and parametric — a deployment tightens the thresholds, the *shape* is fixed:

      * a hard SECURITY transition (privilege escalation / sandbox violation) → NO_OVERRIDE;
      * plan-vs-observed divergence (something ran that was never planned) → REQUIRE_REVIEW;
      * the exfiltration shape — sensitive data + external egress + bulk read → DENY;
      * anomalous fan-out over the cap → REQUIRE_REVIEW.

    Returns the most severe disposition and every reason that fired (empty reasons ⇒ ALLOW)."""
    reasons: list[tuple[GovernanceDisposition, str]] = []
    types = traj.event_types

    if SecurityEventType.PRIVILEGE_ESCALATION.value in types:
        reasons.append((GovernanceDisposition.NO_OVERRIDE, "privilege escalation observed"))
    if SecurityEventType.SANDBOX_VIOLATION.value in types:
        reasons.append((GovernanceDisposition.NO_OVERRIDE, "sandbox violation observed"))

    diverged = traj.divergence(planned_capabilities) if planned_capabilities else set()
    if diverged:
        reasons.append((GovernanceDisposition.REQUIRE_REVIEW,
                        f"plan-vs-observed divergence: {sorted(diverged)} ran but were not planned"))

    sensitive = traj.data_classifications & SENSITIVE_CLASSIFICATIONS
    external = traj.network_endpoints
    if sensitive and external and traj.records_read() > max_external_records:
        reasons.append((GovernanceDisposition.DENY,
                        f"exfiltration shape: {traj.records_read()} {sorted(sensitive)} records read + "
                        f"external egress to {sorted(external)}"))

    if traj.fanout() > max_fanout:
        reasons.append((GovernanceDisposition.REQUIRE_REVIEW, f"anomalous fan-out {traj.fanout()} > {max_fanout}"))

    if not reasons:
        return GovernanceDisposition.ALLOW, []
    worst = max(reasons, key=lambda r: r[0].rank)[0]
    return worst, [msg for _, msg in reasons]


# ──────────────────────────── containment state machine ────────────────────────────


class ContainmentState(str, Enum):
    """Explicit trajectory containment. A correlated disposition drives the state; transitions are
    monotonic toward containment (deny-wins) and only relax through an explicit review/recovery."""
    RUNNING = "RUNNING"
    CONTAINING = "CONTAINING"           # containment initiated (revoke authority, stop new side effects)
    CONTAINED = "CONTAINED"             # confined; no further consequential action proceeds
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    RECOVERED = "RECOVERED"


_CONTAINMENT_TRANSITIONS: dict[ContainmentState, set[ContainmentState]] = {
    ContainmentState.RUNNING: {ContainmentState.RUNNING, ContainmentState.REVIEW_REQUIRED,
                               ContainmentState.CONTAINING},
    ContainmentState.REVIEW_REQUIRED: {ContainmentState.REVIEW_REQUIRED, ContainmentState.RUNNING,
                                       ContainmentState.CONTAINING},
    ContainmentState.CONTAINING: {ContainmentState.CONTAINED},
    ContainmentState.CONTAINED: {ContainmentState.CONTAINED, ContainmentState.RECOVERED},
    ContainmentState.RECOVERED: {ContainmentState.RECOVERED, ContainmentState.RUNNING},
}


class ContainmentRefused(ValueError):
    """An invalid containment transition, or an attempt to recover a NO_OVERRIDE containment."""


@dataclass
class Containment:
    """Drives containment from correlated dispositions. ``on_disposition`` is the runtime hook: ALLOW keeps
    RUNNING; REQUIRE_REVIEW parks at REVIEW_REQUIRED; DENY contains; NO_OVERRIDE contains and refuses any
    later recovery. ``history`` records every transition for the audit/replay trail."""
    state: ContainmentState = ContainmentState.RUNNING
    no_override: bool = False
    history: list[tuple[str, str]] = field(default_factory=list)   # (from, to)

    def _to(self, target: ContainmentState) -> None:
        if target != self.state and target not in _CONTAINMENT_TRANSITIONS[self.state]:
            raise ContainmentRefused(f"{self.state.value} → {target.value} is not a valid transition")
        if target != self.state:
            self.history.append((self.state.value, target.value))
            self.state = target

    def on_disposition(self, disposition: GovernanceDisposition) -> ContainmentState:
        if disposition is GovernanceDisposition.ALLOW:
            return self.state                                     # nothing to contain
        if disposition is GovernanceDisposition.REQUIRE_REVIEW:
            self._to(ContainmentState.REVIEW_REQUIRED)
        else:                                                     # DENY or NO_OVERRIDE → contain
            if disposition is GovernanceDisposition.NO_OVERRIDE:
                self.no_override = True
            self._to(ContainmentState.CONTAINING)
            self._to(ContainmentState.CONTAINED)
        return self.state

    def resolve_review(self, *, approved: bool) -> ContainmentState:
        if self.state is not ContainmentState.REVIEW_REQUIRED:
            raise ContainmentRefused("no review is pending")
        if approved:
            self._to(ContainmentState.RUNNING)
        else:
            self._to(ContainmentState.CONTAINING)
            self._to(ContainmentState.CONTAINED)
        return self.state

    def recover(self) -> ContainmentState:
        if self.no_override:
            raise ContainmentRefused("a NO_OVERRIDE containment cannot be recovered by a human gate")
        self._to(ContainmentState.RECOVERED)
        return self.state