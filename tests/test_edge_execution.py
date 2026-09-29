"""Execution-locality contract (edge browser-native plan, Phase 1): deterministic, fail-closed target selection —
prefer local, never silently send raw sensitive data remote, defer or require approval when no permitted target."""
from __future__ import annotations

from runtime_contracts.protocol import (
    Availability, DEFERRED, ExecutionLocality, LocalCapabilityDescriptor, LocalityPolicy, REQUIRES_APPROVAL,
    SELECTED, select_execution_target,
)


def _cap(cid, locality, avail=Availability.AVAILABLE, offline=False, raw_leaves=None):
    if raw_leaves is None:
        raw_leaves = locality.is_remote        # remote sends raw off-device; local keeps it
    return LocalCapabilityDescriptor(capability_id=cid, locality=locality, availability=avail,
                                     offline_capable=offline, raw_data_may_leave_device=raw_leaves)


BROWSER = lambda **k: _cap("chrome.prompt", ExecutionLocality.BROWSER_LOCAL, **k)
DEVICE = lambda **k: _cap("pair.local", ExecutionLocality.DEVICE_LOCAL, **k)
SERVER = lambda **k: _cap("cloud.model", ExecutionLocality.SERVER, **k)


def test_locality_axes():
    assert ExecutionLocality.BROWSER_LOCAL.is_local and not ExecutionLocality.BROWSER_LOCAL.is_remote
    assert ExecutionLocality.SERVER.is_remote and not ExecutionLocality.SERVER.is_local


def test_prefers_local_when_available():
    d = select_execution_target([BROWSER(), SERVER()], LocalityPolicy.LOCAL_PREFERRED)
    assert d.outcome == SELECTED and d.selected.locality is ExecutionLocality.BROWSER_LOCAL


def test_local_fallback_to_device_when_browser_unavailable():   # E2E #3
    d = select_execution_target([BROWSER(avail=Availability.UNAVAILABLE), DEVICE(), SERVER()],
                                LocalityPolicy.LOCAL_PREFERRED)
    assert d.outcome == SELECTED and d.selected.locality is ExecutionLocality.DEVICE_LOCAL


def test_no_silent_remote_for_sensitive_data():                 # E2E #4 / §10
    # local unavailable, only remote available, but raw data must not leave the device → DEFER, never remote
    d = select_execution_target([BROWSER(avail=Availability.UNAVAILABLE), SERVER()],
                                LocalityPolicy.LOCAL_PREFERRED, prohibit_raw_remote=True)
    assert d.outcome == DEFERRED and d.selected is None and "remote prohibited" in d.reason


def test_remote_permitted_when_not_sensitive():
    d = select_execution_target([BROWSER(avail=Availability.UNAVAILABLE), SERVER()],
                                LocalityPolicy.LOCAL_PREFERRED, prohibit_raw_remote=False)
    assert d.outcome == SELECTED and d.selected.locality is ExecutionLocality.SERVER


def test_remote_requires_approval_never_auto_selects():         # E2E #8
    d = select_execution_target([SERVER()], LocalityPolicy.REMOTE_REQUIRES_APPROVAL)
    assert d.outcome == REQUIRES_APPROVAL and d.selected.locality is ExecutionLocality.SERVER


def test_local_only_defers_when_no_local():
    d = select_execution_target([SERVER()], LocalityPolicy.LOCAL_ONLY)
    assert d.outcome == DEFERRED


def test_defer_if_local_unavailable_ignores_remote():
    d = select_execution_target([SERVER()], LocalityPolicy.DEFER_IF_LOCAL_UNAVAILABLE)
    assert d.outcome == DEFERRED


def test_privacy_gate_excludes_remote_but_keeps_local():
    d = select_execution_target([SERVER(), BROWSER()], LocalityPolicy.REMOTE_ALLOWED, prohibit_raw_remote=True)
    assert d.outcome == SELECTED and d.selected.locality is ExecutionLocality.BROWSER_LOCAL


def test_require_offline_filters_online_only_candidates():
    # browser is online-only; device is offline-capable → offline requirement picks device
    d = select_execution_target([BROWSER(offline=False), DEVICE(offline=True)],
                                LocalityPolicy.LOCAL_PREFERRED, require_offline=True)
    assert d.outcome == SELECTED and d.selected.locality is ExecutionLocality.DEVICE_LOCAL


def test_only_available_is_selectable():
    for state in (Availability.DOWNLOADABLE, Availability.DOWNLOADING, Availability.UNAVAILABLE):
        d = select_execution_target([BROWSER(avail=state)], LocalityPolicy.LOCAL_ONLY)
        assert d.outcome == DEFERRED, state


def test_descriptor_identity_is_content_addressed():
    assert BROWSER().identity() == BROWSER().identity()
    assert BROWSER().identity() != DEVICE().identity()


def test_decision_is_explainable():
    d = select_execution_target([BROWSER(), DEVICE(), SERVER()], LocalityPolicy.LOCAL_PREFERRED)
    cf = d.canonical_form()
    assert cf["selected_locality"] == "browser_local" and set(cf["considered"]) == {"chrome.prompt", "pair.local", "cloud.model"}
