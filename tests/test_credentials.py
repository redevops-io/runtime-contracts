"""JIT credentials + redaction. A credential is a reference bound to an authority scope, never the secret;
a lease can never widen authority; and nothing that leaves the runtime carries a raw secret."""
from runtime_contracts import (
    AuthorityContext,
    PrincipalRef,
    CredentialGrant,
    SecurityVerdict,
    lease_decision,
    redact,
)


def _authority(scope):
    return AuthorityContext(authority_id="a1", principal=PrincipalRef(id="svc:reel", kind="service"),
                            purpose="render", scope=tuple(scope))


def test_lease_within_authority_is_allowed():
    d = lease_decision(requested_scope=("read:vault",), resource="vault:fal/api_key",
                       authority=_authority(("read:vault", "render:video")))
    assert d.verdict is SecurityVerdict.ALLOW


def test_lease_cannot_widen_authority():
    d = lease_decision(requested_scope=("read:vault", "admin:vault"), resource="vault:fal/api_key",
                       authority=_authority(("read:vault",)))
    assert d.verdict is SecurityVerdict.DENY and "admin:vault" in d.reason


def test_grant_canonical_form_omits_the_handle_and_secret():
    g = CredentialGrant(grant_id="g1", principal="svc:reel", resource="vault:fal/api_key",
                        scope=("read:vault",), authority_ref="rcv1:auth", material_hash="rcv1:mat",
                        handle="live-redeem-token-xyz")
    form = g.canonical_form()
    assert "handle" not in form                      # live redemption token never enters identity/seal
    assert form["scope"] == ["read:vault"]
    assert g.ref.startswith("rcv1:")                 # stable identity from the reference, not the secret


def test_redact_masks_secret_keys_and_value_shapes():
    payload = {
        "user": "alex",
        "api_key": "sk-abcdefghijklmnopqrstuvwx",
        "note": "call with Authorization: Bearer eyJabc.def.ghijkl then retry",
        "nested": {"password": "hunter2", "ok": "public value"},
    }
    red = redact(payload)
    assert red["user"] == "alex" and red["nested"]["ok"] == "public value"
    assert red["api_key"].startswith("rcv1:redacted:")
    assert red["nested"]["password"].startswith("rcv1:redacted:")
    assert "Bearer eyJabc.def.ghijkl" not in red["note"] and "rcv1:redacted:" in red["note"]


def test_redact_is_stable_and_correlatable():
    # same secret → same placeholder (correlatable) but never the value
    a = redact({"token": "hvs.AABBCCDDEEFFGGHHIIJJKKLL"})
    b = redact({"token": "hvs.AABBCCDDEEFFGGHHIIJJKKLL"})
    assert a["token"] == b["token"] and a["token"] != "hvs.AABBCCDDEEFFGGHHIIJJKKLL"
