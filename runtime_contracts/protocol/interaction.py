"""Multimodal customer-interaction contracts (AGPL base).

A customer interaction is one *conversation* that may arrive over any channel — a phone call, a
WhatsApp voice note, a Telegram message, a Slack approval, a web chat — and in any modality — text,
audio, image, document, structured event. No external framework (NeMo Voice Agent, Pipecat, a channel
SDK) owns the canonical conversation: the Runtime does. This module is the shape every channel and
speech provider projects INTO, so a phone call and a Slack approval can append evidence to the *same*
Mission without either SDK's vocabulary leaking into the Runtime.

Two rules that shape the contracts:
  * **A transcript is derived evidence, never a replacement for the original audio.** A
    ``TranscriptArtifact`` pins the source ``MediaArtifact`` by content hash and records the ASR
    model/version that produced it; exact replay binds to the sealed audio, and re-transcribing with a
    newer model is a *distinct* computation, not a mutation.
  * **No channel/speech SDK dependencies here.** Providers and adapters are duck-typed seams (below);
    their SDKs terminate at the adapter boundary, exactly as ``VoiceSessionProvider`` /
    ``SpeechProvider`` / ``ChannelAdapter`` implementations live outside ``runtime-contracts``.

``content_hash`` on the frozen artifacts is the ``rcv1`` hash of the canonical form — tamper-evident
and de-duplicable like every other contract here. Fractional values (confidence) are carried as
decimal *strings*, never floats, so the hash agrees across languages.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional, Sequence, Tuple

try:  # match the import style used across protocol/ (falls back to the seal helper)
    from ..canonical import content_hash, decimal_string
except Exception:  # pragma: no cover
    from .seal import content_hash  # type: ignore
    def decimal_string(value: Any) -> str:  # type: ignore
        return str(value)

CONTRACT_VERSION = "interaction-event/v1"


class Channel(str, Enum):
    """Where an interaction arrived. The channel SDK stops at the adapter; only this enum crosses in."""

    PHONE = "phone"
    WHATSAPP = "whatsapp"
    TELEGRAM = "telegram"
    SLACK = "slack"
    DISCORD = "discord"
    WEB = "web"
    EMAIL = "email"
    APP_EVENT = "app_event"       # an application event / webhook
    SCHEDULED = "scheduled"       # a scheduled trigger


class Modality(str, Enum):
    """What kind of content the interaction carried."""

    TEXT = "text"
    AUDIO = "audio"
    IMAGE = "image"
    DOCUMENT = "document"
    STRUCTURED = "structured"


def _norm_conf(value: Optional[Any]) -> Optional[str]:
    """A confidence in [0,1] carried as a decimal string (floats are refused in canonical form)."""
    if value is None:
        return None
    return decimal_string(value if isinstance(value, str) else repr(value))


@dataclass(frozen=True)
class ChannelRef:
    """A stable reference to a channel endpoint (a phone line, a Slack workspace, a WA number)."""

    channel: Channel
    endpoint: str = ""            # opaque, non-secret endpoint id (never a token)
    display: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {"channel": self.channel.value, "endpoint": self.endpoint, "display": self.display}


@dataclass(frozen=True)
class SpeakerRef:
    """A diarized speaker within a conversation. Identity resolution is a separate, evidenced step."""

    speaker_id: str
    role: str = ""               # e.g. "customer" / "agent" — free-form, resolved elsewhere
    display: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {"speaker_id": self.speaker_id, "role": self.role, "display": self.display}


@dataclass(frozen=True)
class ConversationRef:
    """The thread a set of interactions belong to. One conversation can span many channels."""

    conversation_id: str
    subject_ref: str = ""        # the customer/participant this conversation is about
    channels: Tuple[ChannelRef, ...] = ()

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "subject_ref": self.subject_ref,
            "channels": [c.canonical_form() for c in self.channels],
        }

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class MediaArtifact:
    """A raw inbound/outbound media object (audio/image/document), pinned by its content hash.

    ``media_hash`` is the hash of the *bytes* (supplied by the producer); the artifact itself is
    small and comparable without carrying the payload — the canonical rule for materialized content.
    """

    artifact_id: str
    modality: Modality
    media_hash: str              # content hash of the underlying bytes (e.g. "sha256:…")
    media_type: str = ""         # MIME, e.g. "audio/wav"
    uri: str = ""                # where the bytes live (not the bytes themselves)
    duration_ms: int = 0
    bytes_len: int = 0

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "modality": self.modality.value,
            "media_hash": self.media_hash,
            "media_type": self.media_type,
            "uri": self.uri,
            "duration_ms": self.duration_ms,
            "bytes_len": self.bytes_len,
        }

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class SpeechSegment:
    """One transcribed span of audio: text, timing, speaker, and per-segment confidence."""

    text: str
    start_ms: int = 0
    end_ms: int = 0
    speaker: Optional[SpeakerRef] = None
    confidence: Optional[str] = None   # decimal string in [0,1]

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", _norm_conf(self.confidence))

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "text": self.text, "start_ms": self.start_ms, "end_ms": self.end_ms,
        }
        if self.speaker is not None:
            d["speaker"] = self.speaker.canonical_form()
        if self.confidence is not None:
            d["confidence"] = self.confidence
        return d


@dataclass(frozen=True)
class TranscriptArtifact:
    """A transcript — DERIVED evidence over a source ``MediaArtifact``, never a replacement for it.

    Binds the source audio by hash and records the ASR model/version, so replay is exact and a later
    re-transcription with a newer model is a distinct, separately-hashed computation.
    """

    artifact_id: str
    source_media_hash: str            # the MediaArtifact.media_hash this transcript derives from
    segments: Tuple[SpeechSegment, ...] = ()
    asr_model: str = ""               # model id
    asr_version: str = ""             # pinned version/commit
    language: str = ""
    confidence: Optional[str] = None  # overall, decimal string in [0,1]
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", _norm_conf(self.confidence))

    @property
    def text(self) -> str:
        return " ".join(s.text for s in self.segments).strip()

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "contract_version": self.contract_version,
            "artifact_id": self.artifact_id,
            "source_media_hash": self.source_media_hash,
            "segments": [s.canonical_form() for s in self.segments],
            "asr_model": self.asr_model,
            "asr_version": self.asr_version,
            "language": self.language,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        return d

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class InteractionConfidence:
    """Confidence in a derived interpretation (intent/transcription), with how it was obtained."""

    score: str                        # decimal string in [0,1]
    method: str = ""                  # e.g. "asr" / "intent_classifier" / "llm_judge"
    model: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "score", _norm_conf(self.score) or "0")

    def canonical_form(self) -> Dict[str, Any]:
        return {"score": self.score, "method": self.method, "model": self.model}


@dataclass(frozen=True)
class DeliveryReceipt:
    """Proof an outbound response reached a channel — the send side's evidence."""

    interaction_id: str
    channel: Channel
    status: str = "sent"              # sent | delivered | read | failed
    provider_ref: str = ""           # provider-side message id
    observed_at: str = ""

    def canonical_form(self) -> Dict[str, Any]:
        return {
            "interaction_id": self.interaction_id,
            "channel": self.channel.value,
            "status": self.status,
            "provider_ref": self.provider_ref,
            "observed_at": self.observed_at,
        }

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())


@dataclass(frozen=True)
class InteractionEvent:
    """One thing that happened in a conversation, on some channel, in some modality.

    The canonical unit the Runtime reasons over. Raw media and transcripts are referenced by hash, not
    inlined; ``interaction_id`` is the caller-facing id while ``content_hash`` is the tamper-evident,
    content-addressed identity of what the event *says*.
    """

    interaction_id: str
    conversation_id: str
    channel: Channel
    modality: Modality
    participant_ref: str = ""
    artifact_ref: str = ""                       # primary artifact (MediaArtifact/Transcript) hash/id
    derived_artifact_refs: Tuple[str, ...] = ()  # e.g. transcript derived from an audio artifact
    text: str = ""                               # inline text for TEXT modality (else "")
    timestamp: str = ""
    reply_to: str = ""                           # interaction_id this replies to, if any
    confidence: Optional[str] = None             # decimal string in [0,1]
    provenance: str = ""                         # who/what produced it (channel adapter / provider)
    contract_version: str = CONTRACT_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", _norm_conf(self.confidence))

    def canonical_form(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "contract_version": self.contract_version,
            "interaction_id": self.interaction_id,
            "conversation_id": self.conversation_id,
            "channel": self.channel.value,
            "modality": self.modality.value,
            "participant_ref": self.participant_ref,
            "artifact_ref": self.artifact_ref,
            "derived_artifact_refs": sorted(self.derived_artifact_refs),
            "text": self.text,
            "timestamp": self.timestamp,
            "reply_to": self.reply_to,
            "provenance": self.provenance,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        return d

    @property
    def content_hash(self) -> str:
        return content_hash(self.canonical_form())

    @property
    def interaction_hash(self) -> str:
        """Alias for ``content_hash`` — the content-addressed identity of this interaction."""
        return self.content_hash


# --- Provider / adapter seams (duck-typed; SDKs live outside runtime-contracts) --------------------
#
# These are documented structural interfaces, not ABCs the base depends on — an implementation just
# has to provide the methods. Kept dependency-free so no channel/speech SDK is pulled into contracts.


class ChannelAdapter:
    """Terminates a channel SDK and speaks ``InteractionEvent``. Implementations live per-channel.

    Contract (all optional to implement beyond ``capabilities``):
      * ``receive() -> Iterable[InteractionEvent]``            — inbound, normalized to events
      * ``send_text(conversation_id, text) -> DeliveryReceipt``
      * ``send_audio(conversation_id, media) -> DeliveryReceipt``
      * ``send_file(conversation_id, media) -> DeliveryReceipt``
      * ``acknowledge(interaction_id) -> None``
      * ``capabilities() -> Mapping[str, Any]``                — modalities/features this channel supports
    """


class VoiceSessionProvider:
    """A full voice-agent session (VAD/endpointing/ASR/diarization/turn-taking), e.g. NeMo Voice Agent.

    Contract:
      * ``start_session(conversation_id, *, config) -> session``
      * ``events(session) -> Iterable[InteractionEvent]``      — session → InteractionEvents
      * ``send(session, media_or_text) -> DeliveryReceipt``
      * ``end_session(session) -> None``
      * ``capabilities() -> Mapping[str, Any]``
    """


class SpeechProvider:
    """The speech substrate (ASR/TTS/diarization), e.g. NeMo Speech / NeMo-Speech.cpp.

    Contract:
      * ``transcribe(media: MediaArtifact, *, language=None) -> TranscriptArtifact``
      * ``synthesize(text: str, *, voice=None) -> MediaArtifact``
      * ``capabilities() -> Mapping[str, Any]``
    """
