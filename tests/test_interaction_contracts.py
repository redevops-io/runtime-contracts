"""Multimodal customer-interaction contracts (AGPL base) — content-addressed, SDK-free."""
from runtime_contracts import (
    Channel,
    ChannelAdapter,
    ChannelRef,
    ConversationRef,
    DeliveryReceipt,
    InteractionConfidence,
    InteractionEvent,
    MediaArtifact,
    Modality,
    SpeakerRef,
    SpeechProvider,
    SpeechSegment,
    TranscriptArtifact,
    VoiceSessionProvider,
)


def _event(**kw):
    base = dict(interaction_id="i1", conversation_id="c1", channel=Channel.PHONE,
                modality=Modality.AUDIO)
    base.update(kw)
    return InteractionEvent(**base)


def test_interaction_event_is_content_addressed_and_order_independent():
    e = _event(derived_artifact_refs=("t2", "t1"), timestamp="2026-09-05T00:00:00Z")
    assert e.content_hash.startswith("rcv1:")
    assert e.content_hash == e.interaction_hash
    # derived_artifact_refs order does not change identity
    e2 = _event(derived_artifact_refs=("t1", "t2"), timestamp="2026-09-05T00:00:00Z")
    assert e.content_hash == e2.content_hash
    # a material change ⇒ new id
    assert _event(text="hi").content_hash != e.content_hash


def test_channel_and_modality_vocab():
    assert Channel.WHATSAPP.value == "whatsapp"
    assert {m.value for m in Modality} == {"text", "audio", "image", "document", "structured"}
    assert {Channel.PHONE, Channel.SLACK, Channel.WEB} <= set(Channel)


def test_confidence_is_carried_as_a_decimal_string_not_a_float():
    e = _event(confidence="0.87")
    assert e.canonical_form()["confidence"] == "0.87"
    # absent confidence is simply dropped from the canonical form (absent == null)
    assert "confidence" not in _event().canonical_form()


def test_transcript_is_derived_evidence_bound_to_source_audio():
    audio = MediaArtifact(artifact_id="a1", modality=Modality.AUDIO, media_hash="sha256:abc",
                          media_type="audio/wav", duration_ms=4200)
    tr = TranscriptArtifact(
        artifact_id="t1", source_media_hash=audio.media_hash, asr_model="parakeet", asr_version="1.2",
        segments=(SpeechSegment(text="hello", start_ms=0, end_ms=900,
                                speaker=SpeakerRef("s1", role="customer"), confidence="0.9"),
                  SpeechSegment(text="I need a refund", start_ms=900, end_ms=2100)),
    )
    assert tr.source_media_hash == audio.media_hash          # bound to the original audio by hash
    assert tr.text == "hello I need a refund"
    assert tr.content_hash.startswith("rcv1:")
    # re-transcribing with a newer model is a DISTINCT computation (different identity)
    tr_v2 = TranscriptArtifact(artifact_id="t1", source_media_hash=audio.media_hash,
                               asr_model="canary", asr_version="2.0", segments=tr.segments)
    assert tr_v2.content_hash != tr.content_hash


def test_media_artifact_pins_bytes_by_hash_not_payload():
    m = MediaArtifact(artifact_id="a1", modality=Modality.IMAGE, media_hash="sha256:deadbeef",
                      media_type="image/png", bytes_len=1024)
    cf = m.canonical_form()
    assert cf["media_hash"] == "sha256:deadbeef"
    assert "payload" not in cf and "bytes" not in cf  # never the bytes themselves


def test_conversation_spans_channels():
    conv = ConversationRef(conversation_id="c1", subject_ref="cust:acme",
                           channels=(ChannelRef(Channel.PHONE, endpoint="+15551234"),
                                     ChannelRef(Channel.SLACK, endpoint="T0/C0")))
    assert conv.content_hash.startswith("rcv1:")
    assert len(conv.canonical_form()["channels"]) == 2


def test_delivery_receipt_and_confidence_helpers():
    r = DeliveryReceipt(interaction_id="i1", channel=Channel.WHATSAPP, status="delivered",
                        provider_ref="wamid.X")
    assert r.content_hash.startswith("rcv1:")
    ic = InteractionConfidence(score="0.5", method="intent_classifier", model="qwen")
    assert ic.canonical_form()["score"] == "0.5"


def test_provider_seams_are_dependency_free_documented_interfaces():
    # they exist as documented seams — an implementation just provides the methods; no SDK import here
    for seam in (ChannelAdapter, VoiceSessionProvider, SpeechProvider):
        assert isinstance(seam, type)


def test_no_channel_sdk_imports_in_the_contract_module():
    import runtime_contracts.protocol.interaction as mod
    # only actual import statements count — SDK names may appear in docstrings as explanation
    import_lines = [ln.strip().lower() for ln in open(mod.__file__)
                    if ln.strip().startswith(("import ", "from "))]
    for banned in ("pipecat", "twilio", "slack_sdk", "nemo", "telethon", "discord", "telegram"):
        assert not any(banned in ln for ln in import_lines), f"{banned} imported in contract module"
