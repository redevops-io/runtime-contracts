"""Acceptance tests for the secret/credential contracts + AGPL local providers (§26)."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

from runtime_contracts import (
    AuthorityContext,
    CredentialDenied,
    CredentialGrant,
    CredentialRequest,
    CredentialRequirement,
    DenyReason,
    EnvironmentSecretStore,
    FileSecretStore,
    LocalCredentialBroker,
    PrincipalRef,
    SecretAccessError,
    SecretMaterial,
    SecretRef,
    SecurityVerdict,
    admit_credentials,
    authorize_request,
    canonical_json,
    content_hash,
)


def _authority(scopes=("repo:deploy",), tenant="acme"):
    return AuthorityContext(authority_id="a1", principal=PrincipalRef(id="p1", tenant=tenant),
                            purpose="deploy", scope=tuple(scopes))


def _request(scopes=("repo:deploy",), *, tenant="acme", production=False, ttl=None, max_ttl=None,
             secret_ref=None, name="github-deployer"):
    req = CredentialRequirement(name=name, required_scopes=tuple(scopes),
                                production_broker_required=production, max_ttl_seconds=max_ttl,
                                secret_ref=secret_ref)
    return CredentialRequest(request_id="r1", mission_id="m1", node_id="n1", capability_id="deploy.github",
                             tenant_id=tenant, authority_context_id="a1", requirement=req,
                             requested_ttl_seconds=ttl)


def _fixed_clock():
    return lambda: datetime(2026, 1, 1, tzinfo=timezone.utc)


# ── contract tests ───────────────────────────────────────────────────────────────────────────────────

def test_secret_ref_fingerprint_is_stable_and_pathless_in_redaction():
    r = SecretRef(provider="vault", namespace="acme", path="kv/prod/github", key="token", version="42")
    assert r.fingerprint().startswith("rcv1:")
    assert r.fingerprint() == SecretRef(provider="vault", namespace="acme", path="kv/prod/github",
                                        key="token", version="42").fingerprint()
    assert "path" not in r.redacted()          # the raw path is withheld from telemetry views


def test_raw_secret_cannot_enter_canonical_json():
    # a SecretMaterial has no canonical_form -> the serializer rejects it (a secret can never be hashed in)
    with pytest.raises(Exception):
        canonical_json({"material": SecretMaterial(b"ghp_realsecret")})
    with pytest.raises(Exception):
        content_hash({"token": SecretMaterial(b"ghp_realsecret")})


def test_secret_material_is_redacted_and_destroyable():
    m = SecretMaterial(b"hunter2")
    assert repr(m) == "<SecretMaterial redacted>" and str(m) == "<redacted>"
    assert m.bytes() == b"hunter2"
    m.destroy()
    with pytest.raises(RuntimeError):
        m.bytes()


def test_grant_canonical_identity_is_additive_and_excludes_live_handle():
    base = CredentialGrant(grant_id="g1", principal="p1", resource="github", scope=("repo:deploy",))
    # adding a live handle must not change identity
    assert base.ref == CredentialGrant(grant_id="g1", principal="p1", resource="github",
                                       scope=("repo:deploy",), handle="live-token-xyz").ref


# ── authority tests ──────────────────────────────────────────────────────────────────────────────────

def test_authority_narrower_and_equal_scope_allow_wider_denies():
    auth = _authority(scopes=("repo:deploy", "repo:read"))
    assert authorize_request(_request(("repo:deploy",)), auth).verdict == SecurityVerdict.ALLOW
    assert authorize_request(_request(("repo:deploy", "repo:read")), auth).verdict == SecurityVerdict.ALLOW
    wide = authorize_request(_request(("repo:admin",)), auth)
    assert wide.verdict == SecurityVerdict.DENY and DenyReason.INSUFFICIENT_AUTHORITY in wide.reason


def test_ttl_over_policy_denies():
    d = authorize_request(_request(("repo:deploy",), ttl=1800, max_ttl=900), _authority())
    assert d.verdict == SecurityVerdict.DENY and DenyReason.TTL_EXCEEDS_POLICY in d.reason


# ── fail-closed tests ────────────────────────────────────────────────────────────────────────────────

def test_production_requirement_denied_by_development_broker():
    d = authorize_request(_request(production=True), _authority(), broker_assurance="development")
    assert d.verdict == SecurityVerdict.DENY and d.reason == DenyReason.PRODUCTION_BROKER_REQUIRED


def test_admit_fails_closed_without_a_production_broker():
    reqs = (CredentialRequirement(name="db", required_scopes=("db:read",), production_broker_required=True),)
    # no broker wired
    assert admit_credentials(reqs, None).verdict == SecurityVerdict.DENY
    # a development broker cannot satisfy a production requirement
    dev = LocalCredentialBroker(EnvironmentSecretStore())
    assert admit_credentials(reqs, dev).verdict == SecurityVerdict.DENY
    # non-production requirement is admitted
    ok = (CredentialRequirement(name="x", required_scopes=("x",)),)
    assert admit_credentials(ok, dev).verdict == SecurityVerdict.ALLOW


def test_local_broker_denies_production_requirement():
    dev = LocalCredentialBroker(EnvironmentSecretStore())
    with pytest.raises(CredentialDenied):
        dev.grant(_request(production=True), authority_context=_authority())


# ── local broker grant / redeem binding ────────────────────────────────────────────────────────────────

def test_grant_and_redeem_only_within_binding(monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_devonly")
    store = EnvironmentSecretStore()
    ref = SecretRef(provider="env", path="GITHUB_TOKEN")
    broker = LocalCredentialBroker(store, clock=_fixed_clock())
    grant = broker.grant(_request(("repo:deploy",), secret_ref=ref), authority_context=_authority())
    # correct binding redeems
    mat = broker.redeem(grant, capability_id="deploy.github", mission_id="m1")
    assert mat.bytes() == b"ghp_devonly"
    # wrong capability / wrong mission are refused
    with pytest.raises(CredentialDenied):
        broker.redeem(grant, capability_id="other.cap", mission_id="m1")
    with pytest.raises(CredentialDenied):
        broker.redeem(grant, capability_id="deploy.github", mission_id="other-mission")


def test_expired_and_revoked_grants_cannot_redeem(monkeypatch):
    monkeypatch.setenv("TK", "v")
    ref = SecretRef(provider="env", path="TK")
    t = {"now": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    broker = LocalCredentialBroker(EnvironmentSecretStore(), clock=lambda: t["now"])
    grant = broker.grant(_request(("repo:deploy",), secret_ref=ref, ttl=60, max_ttl=60),
                         authority_context=_authority())
    t["now"] = t["now"] + timedelta(seconds=120)   # advance past TTL
    with pytest.raises(CredentialDenied):
        broker.redeem(grant, capability_id="deploy.github", mission_id="m1")
    # revoke also blocks a fresh grant
    g2 = broker.grant(_request(("repo:deploy",), secret_ref=ref), authority_context=_authority())
    broker.revoke_grant(g2.grant_id, reason="done")
    with pytest.raises(CredentialDenied):
        broker.redeem(g2, capability_id="deploy.github", mission_id="m1")


def test_revoke_mission_drops_all_its_grants(monkeypatch):
    monkeypatch.setenv("TK", "v")
    ref = SecretRef(provider="env", path="TK")
    broker = LocalCredentialBroker(EnvironmentSecretStore(), clock=_fixed_clock())
    broker.grant(_request(("repo:deploy",), secret_ref=ref), authority_context=_authority())
    broker.grant(_request(("repo:deploy",), secret_ref=ref), authority_context=_authority())
    assert broker.revoke_mission("m1") == 2


# ── file provider hardening ──────────────────────────────────────────────────────────────────────────

def test_file_store_round_trip_and_refuses_world_readable(tmp_path):
    store = FileSecretStore(root=str(tmp_path))
    ref = store.put(namespace="acme", path="github/deploy", value=b"tok")
    assert ref.provider == "file"
    assert store._read(ref) == b"tok"
    # loosen perms -> refused
    import os as _os
    target = _os.path.realpath(_os.path.join(str(tmp_path), "acme", "github/deploy"))
    _os.chmod(target, 0o644)
    with pytest.raises(SecretAccessError):
        store._read(ref)


def test_file_store_refuses_traversal_and_symlink(tmp_path):
    store = FileSecretStore(root=str(tmp_path))
    with pytest.raises(SecretAccessError):
        store._read(SecretRef(provider="file", namespace="acme", path="../../etc/passwd"))
    # symlink escape refused
    store.put(namespace="t", path="real", value=b"s")
    link = os.path.join(str(tmp_path), "t", "link")
    os.symlink("/etc/hostname", link)
    with pytest.raises(SecretAccessError):
        store._read(SecretRef(provider="file", namespace="t", path="link"))


def test_file_store_tenant_namespace_confined(tmp_path):
    store = FileSecretStore(root=str(tmp_path))
    store.put(namespace="tenant-a", path="db/password", value=b"a")
    # a ref pointing outside the root is rejected before any backend read
    with pytest.raises(SecretAccessError):
        store._read(SecretRef(provider="file", namespace="..", path="../secret"))


# ── expiry / binding / tenant ────────────────────────────────────────────────────────────────────────

def _expiring(expires_at):
    return AuthorityContext(authority_id="a1", principal=PrincipalRef(id="p1", tenant="acme"),
                            purpose="deploy", scope=("repo:deploy",), expires_at=expires_at)


def test_expired_authority_is_denied():
    d = authorize_request(_request(), _expiring("2025-12-31T23:59:59Z"), clock=_fixed_clock())
    assert d.verdict == SecurityVerdict.DENY and d.reason == DenyReason.AUTHORITY_EXPIRED


def test_authority_expiring_exactly_now_is_denied_and_future_is_allowed():
    assert authorize_request(_request(), _expiring("2026-01-01T00:00:00+00:00"),
                             clock=_fixed_clock()).verdict == SecurityVerdict.DENY
    assert authorize_request(_request(), _expiring("2026-01-01T01:00:00+01:00"),
                             clock=_fixed_clock()).verdict == SecurityVerdict.DENY
    assert authorize_request(_request(), _expiring("2026-01-01T00:00:01Z"),
                             clock=_fixed_clock()).verdict == SecurityVerdict.ALLOW
    assert authorize_request(_request(), _expiring(""), clock=_fixed_clock()).verdict == SecurityVerdict.ALLOW


@pytest.mark.parametrize("bad", ["not-a-date", "2026-01-01T00:00:00", "tomorrow"])
def test_unparsable_or_naive_expiry_is_denied(bad):
    d = authorize_request(_request(), _expiring(bad), clock=_fixed_clock())
    assert d.verdict == SecurityVerdict.DENY and d.reason == DenyReason.AUTHORITY_EXPIRED


def test_authority_context_id_must_match_the_supplied_authority():
    other = CredentialRequest(**{**_request().__dict__, "authority_context_id": "someone-else"})
    d = authorize_request(other, _authority())
    assert d.verdict == SecurityVerdict.DENY and d.reason == DenyReason.AUTHORITY_MISMATCH
    chained = CredentialRequest(**{**_request().__dict__, "authority_context_id": _authority().chain_ref})
    assert authorize_request(chained, _authority()).verdict == SecurityVerdict.ALLOW


def test_secret_namespace_must_match_request_tenant():
    ref = SecretRef(provider="env", key="X", namespace="other")
    d = authorize_request(_request(secret_ref=ref), _authority())
    assert d.verdict == SecurityVerdict.DENY and d.reason == DenyReason.TENANT_MISMATCH
    same = SecretRef(provider="env", key="X", namespace="acme")
    assert authorize_request(_request(secret_ref=same), _authority()).verdict == SecurityVerdict.ALLOW


def test_local_broker_refuses_expired_authority_and_cross_tenant_reference(monkeypatch):
    monkeypatch.setenv("RC_TEST_SECRET", "value")
    broker = LocalCredentialBroker(EnvironmentSecretStore(), clock=_fixed_clock())
    ref = SecretRef(provider="env", key="RC_TEST_SECRET", namespace="acme")
    with pytest.raises(CredentialDenied) as e:
        broker.grant(_request(secret_ref=ref), authority_context=_expiring("2025-01-01T00:00:00Z"))
    assert DenyReason.AUTHORITY_EXPIRED in e.value.reason
    cross = SecretRef(provider="env", key="RC_TEST_SECRET", namespace="other")
    with pytest.raises(CredentialDenied) as e:
        broker.grant(_request(secret_ref=cross), authority_context=_authority())
    assert DenyReason.TENANT_MISMATCH in e.value.reason
    grant = broker.grant(_request(secret_ref=ref), authority_context=_authority())
    with broker.redeem(grant, capability_id="deploy.github", mission_id="m1") as m:
        assert m.bytes() == b"value"


# ── tenant binding vectors ───────────────────────────────────────────────────────────────────────────

import json
from pathlib import Path

_TENANT_VECTORS = json.loads((Path(__file__).parent / "credential_tenant_vectors.json").read_text())["cases"]


@pytest.mark.parametrize("case", _TENANT_VECTORS, ids=[c["name"] for c in _TENANT_VECTORS])
def test_tenant_binding_vectors(case):
    ref = SecretRef(provider="env", key="X", namespace=case["secret_namespace"]) if case["secret_namespace"] else None
    auth = AuthorityContext(authority_id="a1", principal=PrincipalRef(id="p1", tenant=case["authority_tenant"]),
                            purpose="deploy", scope=("repo:deploy",))
    d = authorize_request(_request(tenant=case["request_tenant"], secret_ref=ref), auth)
    assert d.verdict.value == case["expect"] if hasattr(d.verdict, "value") else d.verdict == case["expect"]
    if "reason" in case:
        assert d.reason == getattr(DenyReason, case["reason"])
