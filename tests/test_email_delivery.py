"""Contract tests for the email-delivery execution/receipt layer (moat plan §3.11, §6 P1, §15).

Pins the guarantees email delivery relies on: it is idempotent by key, the receipt lifecycle is normalized,
terminal/suppression states are explicit and drive a governed side effect, provenance is never omitted, and a
provider is replaceable behind the EmailDeliveryProvider Protocol.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from runtime_contracts.protocol import (
    EmailDeliveryProvider, EmailDeliveryReceipt, EmailDeliveryStatus, EmailMessageRef, EmailSendRequest,
    EmailSubmitFailure, content_hash,
)


def _req(key="k1", recipient="a@example.com", cost=0.0):
    return EmailSendRequest(
        tenant="t", campaign_id="c1", idempotency_key=key, max_cost=cost,
        message=EmailMessageRef(recipient=recipient, sender_domain="mg.acme.com",
                                subject_ref="s#1", body_ref="b#1", stream="broadcast"),
        metadata=(("list_id", "42"),))


# ── a fake provider (the plan's fake-adapter pattern) ─────────────────────────────────────────────────────
@dataclass
class FakeDeliveryProvider:
    provider_id: str = "fake_ses"
    credential: str = "k"
    price: float = 0.001
    sent: list = field(default_factory=list)            # idempotency keys already delivered
    suppressed: set = field(default_factory=set)         # recipients on the suppression list

    def check_entitlement(self, tenant: str) -> bool:
        return bool(self.credential)

    def cost_estimate(self, request: EmailSendRequest) -> float:
        return self.price

    def send(self, request: EmailSendRequest) -> EmailDeliveryReceipt:
        r = request.message.recipient
        if r in self.suppressed:
            return EmailDeliveryReceipt(
                provider=self.provider_id, tenant=request.tenant, idempotency_key=request.idempotency_key,
                status=EmailDeliveryStatus.DROPPED, submit_failure=EmailSubmitFailure.SUPPRESSED,
                reason="on suppression list", raw_response_digest=content_hash({"drop": r}))
        if request.idempotency_key in self.sent:
            # a retry must NOT double-deliver: return the prior accepted receipt, don't send again.
            return EmailDeliveryReceipt(
                provider=self.provider_id, tenant=request.tenant, idempotency_key=request.idempotency_key,
                status=EmailDeliveryStatus.ACCEPTED, provider_message_id=f"pm-{request.idempotency_key}",
                cost=0.0, reason="idempotent replay", raw_response_digest=content_hash({"replay": request.idempotency_key}))
        self.sent.append(request.idempotency_key)
        return EmailDeliveryReceipt(
            provider=self.provider_id, tenant=request.tenant, idempotency_key=request.idempotency_key,
            status=EmailDeliveryStatus.ACCEPTED, provider_message_id=f"pm-{request.idempotency_key}",
            cost=self.price, accepted_at="2026-09-25T00:00:00Z",
            raw_response_digest=content_hash({"pm": request.idempotency_key}))

    def poll(self, tenant: str, provider_message_id: str) -> Optional[EmailDeliveryReceipt]:
        return EmailDeliveryReceipt(
            provider=self.provider_id, tenant=tenant, idempotency_key=provider_message_id.removeprefix("pm-"),
            status=EmailDeliveryStatus.DELIVERED, provider_message_id=provider_message_id,
            delivered_at="2026-09-25T00:01:00Z", raw_response_digest=content_hash({"delivered": provider_message_id}))


def test_provider_satisfies_protocol():
    assert isinstance(FakeDeliveryProvider(), EmailDeliveryProvider)


def test_send_produces_receipt_with_provenance_and_cost():
    p = FakeDeliveryProvider()
    r = p.send(_req())
    assert r.is_success() and r.status == EmailDeliveryStatus.ACCEPTED
    assert r.provider_message_id and r.has_provenance() and r.cost == p.price
    assert r.idempotency_key == "k1"


def test_idempotent_retry_does_not_double_deliver():
    p = FakeDeliveryProvider()
    first = p.send(_req(key="dup"))
    second = p.send(_req(key="dup"))
    assert first.is_success() and second.is_success()
    assert p.sent.count("dup") == 1               # only delivered once
    assert second.cost == 0.0                       # the replay isn't billed again


def test_suppression_state_is_explicit_and_governed():
    p = FakeDeliveryProvider(suppressed={"blocked@example.com"})
    r = p.send(_req(recipient="blocked@example.com"))
    assert r.status == EmailDeliveryStatus.DROPPED
    assert r.should_suppress() and r.is_terminal()
    assert r.submit_failure == EmailSubmitFailure.SUPPRESSED


def test_bounce_and_complaint_suppress_but_accepted_does_not():
    def rcpt(status):
        return EmailDeliveryReceipt(provider="p", tenant="t", idempotency_key="k", status=status,
                                    provider_message_id="pm")
    assert rcpt(EmailDeliveryStatus.BOUNCED).should_suppress()
    assert rcpt(EmailDeliveryStatus.COMPLAINED).should_suppress()
    assert rcpt(EmailDeliveryStatus.UNSUBSCRIBED).should_suppress()
    assert not rcpt(EmailDeliveryStatus.ACCEPTED).should_suppress()
    assert not rcpt(EmailDeliveryStatus.DELIVERED).should_suppress()


def test_terminal_vs_nonterminal():
    def rcpt(status):
        return EmailDeliveryReceipt(provider="p", tenant="t", idempotency_key="k", status=status)
    assert rcpt(EmailDeliveryStatus.DELIVERED).is_terminal()
    assert rcpt(EmailDeliveryStatus.FAILED).is_terminal()
    assert not rcpt(EmailDeliveryStatus.ACCEPTED).is_terminal()   # awaiting delivery/bounce
    assert not rcpt(EmailDeliveryStatus.QUEUED).is_terminal()


def test_failed_submission_has_provenance_without_provider_id():
    r = EmailDeliveryReceipt(provider="p", tenant="t", idempotency_key="k",
                             status=EmailDeliveryStatus.FAILED, submit_failure=EmailSubmitFailure.NOT_ENTITLED)
    assert r.is_terminal() and not r.is_success() and r.has_provenance()


def test_poll_reconciles_to_delivered():
    p = FakeDeliveryProvider()
    acc = p.send(_req(key="poll1"))
    later = p.poll("t", acc.provider_message_id)
    assert later.status == EmailDeliveryStatus.DELIVERED and later.is_terminal()
    assert later.idempotency_key == "poll1"


def test_request_identity_is_stable_and_content_addressed():
    assert _req().identity() == _req().identity()
    assert _req(key="a").identity() != _req(key="b").identity()


def test_receipt_canonical_form_roundtrips_enums():
    r = FakeDeliveryProvider().send(_req())
    cf = r.canonical_form()
    assert cf["status"] == "accepted" and cf["submit_failure"] is None
