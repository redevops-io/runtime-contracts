"""Adversarial evidence validators (0.3.x) — the epistemic security layer.

Discovery may let evidence *influence belief*, but a canonical rule bounds it:

    **Evidence may influence belief; evidence may not grant itself authority.**

These validators screen a retrieved evidence item for the adversarial patterns that try to cross that
line — prompt/instruction injection, evidence that grants itself authority, source spoofing, poisoned tool
metadata, classification escalation, cross-source contradiction, and hidden retrieved instructions. Each
returns a :class:`SecurityDecision`; :func:`validate_evidence` runs them all and combines deny-wins.

They score the *outcome* (does this evidence try to gain authority / execute instructions), not a detection
label — a deployment tunes the patterns, the rule is fixed. Conservative: a match is REQUIRE_REVIEW or DENY,
never a silent pass, because a false negative here is an agent taking instructions from its inputs.
"""
from __future__ import annotations

import re

from .security import SecurityDecision, SecurityVerdict

# ── pattern libraries (starter set; extend per deployment / OWASP LLM corpus) ──

_INJECTION = re.compile(
    r"\b(ignore (all|previous|above)|disregard (the|all|previous)|forget (your|the) (instructions|rules)|"
    r"you are now|new instructions?:|system prompt|jailbreak|do anything now|override (the|your))\b", re.I)

_SELF_AUTHORITY = re.compile(
    r"\b(grant (me|yourself|the agent) (access|admin|root|permission)|you (now )?have (admin|root|full) "
    r"(access|authority|permission)|elevate (your|my) (privileges?|access)|add (me|yourself) to|"
    r"assume the role of (admin|root|superuser)|bypass (the )?(policy|approval|authorization))\b", re.I)

_HIDDEN_INSTRUCTION = re.compile(
    r"(<!--.*?(instruction|prompt|ignore|system).*?-->|\[//\]:\s*#|​|"
    r"\bto the (ai|assistant|agent|model)\b|\bassistant\s*:\s*)", re.I | re.S)


def _get(evidence, key, default=""):
    if isinstance(evidence, dict):
        return evidence.get(key, default)
    return getattr(evidence, key, default)


def _text_of(evidence) -> str:
    return str(_get(evidence, "text", "") or _get(evidence, "content", ""))


# ── individual validators (each returns a SecurityDecision) ──

def check_injection(evidence) -> SecurityDecision:
    if _INJECTION.search(_text_of(evidence)):
        return SecurityDecision(SecurityVerdict.DENY, resource=str(_get(evidence, "source", "evidence")),
                                reason="prompt/instruction injection in retrieved content",
                                obligations=("quarantine_evidence",), decided_by="adversarial:injection")
    return SecurityDecision(SecurityVerdict.ALLOW)


def check_self_granted_authority(evidence) -> SecurityDecision:
    if _SELF_AUTHORITY.search(_text_of(evidence)):
        return SecurityDecision(SecurityVerdict.DENY, resource=str(_get(evidence, "source", "evidence")),
                                reason="evidence attempts to grant itself authority — evidence may inform "
                                       "belief, never confer permission", obligations=("quarantine_evidence",),
                                decided_by="adversarial:self_authority")
    return SecurityDecision(SecurityVerdict.ALLOW)


def check_hidden_instructions(evidence) -> SecurityDecision:
    if _HIDDEN_INSTRUCTION.search(_text_of(evidence)):
        return SecurityDecision(SecurityVerdict.REQUIRE_REVIEW,
                                resource=str(_get(evidence, "source", "evidence")),
                                reason="hidden/embedded instruction addressed to the agent in retrieved content",
                                decided_by="adversarial:hidden_instructions")
    return SecurityDecision(SecurityVerdict.ALLOW)


def check_source_spoofing(evidence, *, trusted_sources: "frozenset[str] | set[str]" = frozenset()) -> SecurityDecision:
    """An evidence item CLAIMING a trusted source it cannot prove (no content hash / signature) is spoofing."""
    claimed = str(_get(evidence, "source", ""))
    proven = bool(_get(evidence, "content_hash", "") or _get(evidence, "signature", ""))
    if claimed and trusted_sources and claimed in trusted_sources and not proven:
        return SecurityDecision(SecurityVerdict.DENY, resource=claimed,
                                reason=f"claims trusted source {claimed!r} without a verifiable hash/signature",
                                decided_by="adversarial:source_spoofing")
    return SecurityDecision(SecurityVerdict.ALLOW)


def check_poisoned_tool_metadata(evidence) -> SecurityDecision:
    """Tool/capability metadata carrying instructions or authority claims (a poisoned descriptor)."""
    meta = _get(evidence, "tool_metadata", "") or _get(evidence, "metadata", "")
    text = meta if isinstance(meta, str) else str(meta)
    if text and (_INJECTION.search(text) or _SELF_AUTHORITY.search(text)):
        return SecurityDecision(SecurityVerdict.DENY, resource=str(_get(evidence, "source", "tool")),
                                reason="tool metadata carries instructions/authority claims (poisoned)",
                                obligations=("quarantine_capability",), decided_by="adversarial:poisoned_metadata")
    return SecurityDecision(SecurityVerdict.ALLOW)


def check_classification_escalation(evidence, *, context_classification: str = "") -> SecurityDecision:
    """Evidence whose own classification is more sensitive than the context it is being pulled into — a
    boundary the runtime must not silently cross."""
    _rank = {"": 0, "public": 0, "internal": 1, "confidential": 2, "restricted": 3, "pii": 3, "secret": 4}
    ev_c = str(_get(evidence, "classification", "") or "").lower()
    if ev_c and _rank.get(ev_c, 0) > _rank.get(context_classification.lower(), 0):
        return SecurityDecision(SecurityVerdict.REQUIRE_REVIEW,
                                resource=str(_get(evidence, "source", "evidence")),
                                reason=f"classification escalation: {ev_c} evidence into a "
                                       f"{context_classification or 'public'} context",
                                decided_by="adversarial:classification_escalation")
    return SecurityDecision(SecurityVerdict.ALLOW)


def check_cross_source_contradiction(evidence_items: "list") -> SecurityDecision:
    """When independent sources assert contradictory values for the same field, belief must not silently
    pick one — surface for review (a spoofed/poisoned source manifests as a lone contradiction)."""
    by_field: dict[str, set] = {}
    for e in evidence_items:
        field = str(_get(e, "field", ""))
        value = str(_get(e, "value", _text_of(e)))
        if field:
            by_field.setdefault(field, set()).add(value)
    conflicted = [f for f, vs in by_field.items() if len(vs) > 1]
    if conflicted:
        return SecurityDecision(SecurityVerdict.REQUIRE_REVIEW, resource=",".join(sorted(conflicted)),
                                reason=f"cross-source contradiction on {sorted(conflicted)}",
                                decided_by="adversarial:cross_source_contradiction")
    return SecurityDecision(SecurityVerdict.ALLOW)


def validate_evidence(evidence, *, trusted_sources: "frozenset[str] | set[str]" = frozenset(),
                      context_classification: str = "") -> SecurityDecision:
    """Run every single-item validator on one evidence item and combine deny-wins. The result's verdict is
    ALLOW only if the evidence trips none of them."""
    decisions = [
        check_injection(evidence),
        check_self_granted_authority(evidence),
        check_hidden_instructions(evidence),
        check_source_spoofing(evidence, trusted_sources=trusted_sources),
        check_poisoned_tool_metadata(evidence),
        check_classification_escalation(evidence, context_classification=context_classification),
    ]
    return SecurityDecision.combine(decisions)
