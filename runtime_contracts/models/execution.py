"""The side-effect boundary — where an approved decision becomes a contained action.

The rest of the stack answers *"should this happen?"* (mission, evidence, authority,
policy). This module carries the value that crosses the last boundary and answers a
second question the semantic plane cannot: *"even if the agent is wrong or compromised,
what can it physically reach?"*

Three types, no infrastructure:

* :class:`ExecutionConstraint` — the containment envelope: filesystem, network egress,
  and resource limits. **Deny by default** — an empty constraint grants nothing.
* :class:`ExecutionEnvelope` — a canonical, content-addressed authorization bound to a
  mission, plan, capability, authority, parameters, credential *references* (never
  values), a target, an idempotency key, and an expiry. Its identity **is** the hash of
  its canonical form, so changing any field yields a different envelope — tamper-evidence
  is intrinsic, not bolted on. A signer may add a detached :attr:`signature` over that
  binding; the contract itself guarantees only the binding.
* :class:`ExecutionReceipt` — what actually happened, **bound to the envelope by hash**.
  A replaceable — and eventually untrusted — executor must not self-certify: receipt
  trust derives from ``envelope_binding`` plus an optional ``attestation`` from the
  containment layer, never from the executor's word.

Credential blindness is expressed here as *reference, not value*: the envelope names
credentials (:attr:`credential_refs` → ``SecretRef`` ids the gateway resolves after
authority + policy); the model, agent, and this contract never see a secret.

Canonical discipline (from :mod:`..canonical`): floats have no canonical form, so
resource limits are integers and any numeric ``parameters`` must be decimal strings.
That is what makes an envelope reproduce and compare byte-identically across languages.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

from ..canonical import content_hash
from .capability import Idempotency

CONTRACT_VERSION = "execution/v1"


class EnvelopeInvalid(ValueError):
    """An execution envelope cannot be honoured as presented.

    Raised — never degraded. A partially-valid envelope executed "best effort" is
    exactly the ambient-authority failure the boundary exists to remove.
    """


@dataclass(frozen=True)
class ExecutionConstraint:
    """The physical containment an approved action runs inside. Deny-by-default.

    Every field is an *allow-list* or a *ceiling*: what is not granted is not reachable.
    An ``ExecutionConstraint()`` with no grants is the tightest possible — no filesystem,
    no network, minimal resources — and callers widen it deliberately.
    """

    #: Host paths the action may read. Empty = no filesystem reads.
    read_paths: Tuple[str, ...] = ()
    #: Host paths the action may write. Empty = no filesystem writes.
    write_paths: Tuple[str, ...] = ()
    #: Outbound destinations (host, host:port, or CIDR) the action may reach.
    #: Empty = no network egress (the default; ambient network is never implied).
    allow_egress: Tuple[str, ...] = ()
    #: Resource ceilings. Integers only — floats have no canonical form.
    max_cpu_millis: int = 0
    max_memory_mb: int = 0
    max_duration_seconds: int = 0
    max_processes: int = 1
    max_concurrency: int = 1

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "read_paths": sorted(self.read_paths),
            "write_paths": sorted(self.write_paths),
            "allow_egress": sorted(self.allow_egress),
            "max_cpu_millis": self.max_cpu_millis,
            "max_memory_mb": self.max_memory_mb,
            "max_duration_seconds": self.max_duration_seconds,
            "max_processes": self.max_processes,
            "max_concurrency": self.max_concurrency,
        }


@dataclass(frozen=True)
class ExecutionEnvelope:
    """A canonical, content-addressed authorization to perform one contained action.

    The envelope is a *value*: it is issued by the control plane after governance, it may
    be cached and transported, and it is honoured by whichever executor is eligible. Its
    identity is :attr:`binding` — the content hash of its canonical form — so any change
    to any field (parameters, capability, authority, target, expiry, …) produces a
    different envelope that no authority ever issued. Tamper-evidence is therefore a
    property of the type, not of a wrapper around it.
    """

    mission_id: str
    plan_fingerprint: str
    capability_id: str
    #: The authority grant this action is exercised under (a grant id / token ref).
    authority: str
    #: Where the action may run — a neutral ExecutionTarget id, not a cloud/K8s type.
    target: str
    #: The contained call arguments. Must be canonicalizable: no bare floats
    #: (use decimal strings), so the envelope reproduces byte-identically.
    parameters: Mapping[str, Any] = field(default_factory=dict)
    #: SecretRef ids the gateway resolves *after* authority + policy. The agent and this
    #: contract never carry the secret value — credential blindness by construction.
    credential_refs: Tuple[str, ...] = ()
    #: Evidence supporting admissibility, for the receipt/replay trail.
    evidence_refs: Tuple[str, ...] = ()
    constraint: ExecutionConstraint = field(default_factory=ExecutionConstraint)
    idempotency: Idempotency = Idempotency.UNKNOWN
    #: Exactly-once key. The executor dedupes side effects on this across retries/replay.
    idempotency_key: str = ""
    #: Expiry as a canonical string (RFC3339 UTC or epoch-seconds string). An expired
    #: envelope is refused even if otherwise valid — authority is not indefinite.
    not_after: str = ""
    #: Detached signature over :attr:`binding`, filled by a signer. Optional: the contract
    #: guarantees the canonical binding; cryptographic non-repudiation is an executor-plane
    #: concern layered on top, never trusted *instead* of the binding.
    signature: str = ""
    contract_version: str = CONTRACT_VERSION

    def canonical_form(self) -> Dict[str, Any]:
        # `signature` is deliberately excluded: it signs the binding, so it cannot be
        # part of what is signed. Everything else is load-bearing and included.
        return {
            "contract_version": self.contract_version,
            "mission_id": self.mission_id,
            "plan_fingerprint": self.plan_fingerprint,
            "capability_id": self.capability_id,
            "authority": self.authority,
            "target": self.target,
            "parameters": dict(self.parameters),
            "credential_refs": sorted(self.credential_refs),
            "evidence_refs": sorted(self.evidence_refs),
            "constraint": self.constraint.canonical_form(),
            "idempotency": self.idempotency.value,
            "idempotency_key": self.idempotency_key,
            "not_after": self.not_after,
        }

    @property
    def binding(self) -> str:
        """The envelope's identity: a prefixed SHA-256 over its canonical form.

        This is what an executor validates against — recompute it and refuse anything
        whose presented binding does not match (Benchmark D). A detached
        :attr:`signature`, when present, signs *this* value.
        """
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class ExecutionReceipt:
    """What actually happened, provably bound to the envelope that authorized it.

    The receipt closes the loop into the mission ledger. It never claims more than the
    envelope authorized: it names the :attr:`envelope_binding` it discharges, the
    idempotency key it consumed, the outcome (or the *named* refusal), and a digest of
    the real side effect. For an untrusted executor, :attr:`attestation` is what makes
    the receipt believable — without it, a receipt is only as trustworthy as the host.
    """

    #: The `binding` of the ExecutionEnvelope this receipt discharges.
    envelope_binding: str
    mission_id: str
    capability_id: str
    idempotency_key: str
    #: "executed" | "refused" | "failed". A refusal is a first-class, recorded outcome.
    outcome: str
    #: Named reason when outcome != "executed" (e.g. "envelope_expired",
    #: "binding_mismatch", "egress_denied"). Empty on success.
    reason: str = ""
    #: Content hash of the actual effect/result — provable, comparable across replays.
    side_effect_digest: str = ""
    started_at: str = ""
    finished_at: str = ""
    #: Containment/host attestation for a replaceable or remote executor. Empty is
    #: honest for a trusted local membrane; required to trust a remote one.
    attestation: str = ""
    contract_version: str = CONTRACT_VERSION

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "envelope_binding": self.envelope_binding,
            "mission_id": self.mission_id,
            "capability_id": self.capability_id,
            "idempotency_key": self.idempotency_key,
            "outcome": self.outcome,
            "reason": self.reason,
            "side_effect_digest": self.side_effect_digest,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "attestation": self.attestation,
        }

    @property
    def receipt_id(self) -> str:
        """Content-addressed identity of the receipt."""
        return content_hash(self.canonical_form())
