"""Email delivery execution + receipt contract (moat plan §3.11, §6 P1).

Email delivery is an EXECUTION, not read-only evidence: the Runtime hands a message to a delivery provider (SES /
Postmark / SendGrid / …) and gets back a receipt whose lifecycle — accepted → delivered → bounced / complaint /
unsubscribe — is what Listmonk cannot reproduce on its own. So it gets its own contract rather than being forced
into the EvidenceArtifact shape (which is for things the Runtime *learns*, not things it *does*).

Two invariants distinguish it from intelligence acquisition:
  1. it is idempotent by an explicit key — a retried send must not double-deliver;
  2. its terminal states drive SUPPRESSION (bounce/complaint/unsubscribe suppress the recipient), which is a
     governed side effect, not an inference.

The receipt still carries provenance (provider + raw_response_digest) and cost, and later joins Experience so the
moat `campaign → delivered → order/invoice → retention` can be measured. Domain-neutral contract only — no SDKs,
no network; adapters implement `EmailDeliveryProvider`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional, Protocol, runtime_checkable

from .seal import content_hash

EMAIL_DELIVERY_CONTRACT_VERSION = "1"


class EmailDeliveryStatus(str, Enum):
    """Normalized delivery lifecycle (§3.11). Provider-specific events map onto these."""
    QUEUED = "queued"              # accepted by us, not yet handed to the provider
    ACCEPTED = "accepted"         # provider accepted the message for delivery
    DELIVERED = "delivered"       # provider confirmed delivery to the recipient MTA/inbox
    DEFERRED = "deferred"         # temporary/soft failure; provider will retry
    BOUNCED = "bounced"           # permanent/hard failure
    COMPLAINED = "complained"     # recipient marked as spam
    UNSUBSCRIBED = "unsubscribed" # recipient opted out
    DROPPED = "dropped"           # provider dropped (suppression list / policy) before send
    FAILED = "failed"             # submission failed (auth/quota/transport) — nothing was sent


# Terminal states: no further transition is expected for this message.
_TERMINAL = frozenset({
    EmailDeliveryStatus.DELIVERED, EmailDeliveryStatus.BOUNCED, EmailDeliveryStatus.COMPLAINED,
    EmailDeliveryStatus.UNSUBSCRIBED, EmailDeliveryStatus.DROPPED, EmailDeliveryStatus.FAILED,
})
# States that must suppress future sends to the recipient (a governed side effect, §10 PII/consent).
_SUPPRESSING = frozenset({
    EmailDeliveryStatus.BOUNCED, EmailDeliveryStatus.COMPLAINED, EmailDeliveryStatus.UNSUBSCRIBED,
    EmailDeliveryStatus.DROPPED,
})


class EmailSubmitFailure(str, Enum):
    """Why a *submission* failed (distinct from a delivery-time bounce). Mirrors the acquisition taxonomy so the
    fallback ladder can reason about it uniformly."""
    UNAVAILABLE = "unavailable"           # provider/API down (≥500 / network)
    RATE_LIMITED = "rate_limited"         # 429 / provider throttle
    QUOTA_EXCEEDED = "quota_exceeded"     # sending quota exhausted
    NOT_ENTITLED = "not_entitled"         # missing/invalid credential (401/403)
    SUPPRESSED = "suppressed"             # recipient on a suppression list — refused by policy, not an error
    INVALID_RECIPIENT = "invalid_recipient"
    REJECTED = "rejected"                 # provider rejected content/sender (spam policy, unverified domain)


@dataclass(frozen=True)
class EmailMessageRef:
    """A non-secret reference to the message to send. The bytes/PII live behind refs; this contract never carries a
    credential and treats the recipient as data the caller is authorized to send to."""
    recipient: str                     # recipient address (PII — caller must hold consent; drives suppression)
    sender_domain: str                 # the (verified) sending domain — reputation attaches here
    subject_ref: str = ""              # content hash / template id of the subject
    body_ref: str = ""                 # content hash / template id of the rendered body
    stream: str = ""                   # provider message stream / pool (e.g. "broadcast" vs "transactional")

    def canonical_form(self) -> dict[str, Any]:
        return {
            "recipient": self.recipient, "sender_domain": self.sender_domain,
            "subject_ref": self.subject_ref, "body_ref": self.body_ref, "stream": self.stream,
        }


@dataclass(frozen=True)
class EmailSendRequest:
    """An execution-scoped ask to deliver one message. `idempotency_key` makes a retry safe — a provider (or the
    Runtime) must not deliver the same key twice."""
    tenant: str
    campaign_id: str                   # the campaign / flow / decision this send belongs to
    message: EmailMessageRef
    idempotency_key: str               # stable per logical message; a retry reuses it
    max_cost: float = 0.0              # money ceiling for this send; 0 ⇒ free-only
    metadata: tuple[tuple[str, str], ...] = ()   # opaque non-secret tags (e.g. list_id) as sorted pairs

    def canonical_form(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant, "campaign_id": self.campaign_id, "message": self.message.canonical_form(),
            "idempotency_key": self.idempotency_key, "max_cost": self.max_cost,
            "metadata": [list(p) for p in self.metadata],
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class EmailDeliveryReceipt:
    """The governed result of a send. Carries provenance (provider + raw_response_digest) and cost so it can join
    Experience. A send that never reached the provider has status FAILED and a `submit_failure`."""
    provider: str
    tenant: str
    idempotency_key: str               # correlates back to the request
    status: EmailDeliveryStatus
    provider_message_id: str = ""      # the provider-side id, for later status callbacks/webhooks
    submit_failure: Optional[EmailSubmitFailure] = None
    bounce_type: str = ""              # "hard" | "soft" | "" when N/A
    reason: str = ""                   # human-readable provider reason (never a secret)
    cost: float = 0.0
    accepted_at: str = ""
    delivered_at: str = ""
    observed_at: str = ""              # when this receipt state was observed
    raw_response_digest: str = ""      # content hash of the raw provider payload (provenance, §4.2/§15)

    def canonical_form(self) -> dict[str, Any]:
        return {
            "provider": self.provider, "tenant": self.tenant, "idempotency_key": self.idempotency_key,
            "status": self.status.value,
            "provider_message_id": self.provider_message_id,
            "submit_failure": self.submit_failure.value if self.submit_failure else None,
            "bounce_type": self.bounce_type, "reason": self.reason, "cost": self.cost,
            "accepted_at": self.accepted_at, "delivered_at": self.delivered_at, "observed_at": self.observed_at,
            "raw_response_digest": self.raw_response_digest,
        }

    def identity(self) -> str:
        return content_hash(self.canonical_form())

    def is_terminal(self) -> bool:
        return self.status in _TERMINAL

    def is_success(self) -> bool:
        return self.status in (EmailDeliveryStatus.ACCEPTED, EmailDeliveryStatus.DELIVERED)

    def should_suppress(self) -> bool:
        """Whether this receipt must add the recipient to the suppression list (a governed side effect)."""
        return self.status in _SUPPRESSING

    def has_provenance(self) -> bool:
        # a delivery that reached the provider must carry a provider id or a raw-response digest.
        if self.status == EmailDeliveryStatus.FAILED:
            return True
        return bool(self.provider_message_id) or bool(self.raw_response_digest)


@runtime_checkable
class EmailDeliveryProvider(Protocol):
    """An email delivery adapter (SES / Postmark / SendGrid / …). BYO credential — an unentitled provider is not
    registered, so the open stack keeps Listmonk's own sending unchanged."""
    provider_id: str

    def check_entitlement(self, tenant: str) -> bool: ...

    def cost_estimate(self, request: EmailSendRequest) -> float: ...

    def send(self, request: EmailSendRequest) -> EmailDeliveryReceipt: ...

    def poll(self, tenant: str, provider_message_id: str) -> Optional[EmailDeliveryReceipt]:
        """Fetch the latest delivery state for an already-submitted message (webhook-free reconciliation)."""
        ...
