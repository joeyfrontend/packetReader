from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

LogLevel = Literal["info", "warning", "recoverable_error", "fatal_error", "trace"]


@dataclass(slots=True)
class SignatureHit:
    kind: str
    offset: int
    description: str
    confidence: float = 0.5


@dataclass(slots=True)
class InspectionResult:
    source_file: str
    size_bytes: int
    sha256: str
    entropy: float
    printable_ratio: float
    magic_hex: str
    version_hints: list[str] = field(default_factory=list)
    signatures: list[SignatureHit] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TextFragment:
    id: str
    source: str
    offset: int
    length: int
    encoding: str
    classification: str
    confidence: float
    text: str
    preview: str
    raw_hex_preview: str
    markers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DecodedChunk:
    id: str
    source_type: str
    offset: int
    length: int
    classification: str
    encoding: str | None
    confidence: float
    preview: str
    text: str | None
    raw_hex_preview: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class DecodeResult:
    chunks: list[DecodedChunk] = field(default_factory=list)
    text_fragments: list[TextFragment] = field(default_factory=list)
    recovered_text: str = ""
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class InterfaceCandidate:
    name: str | None = None
    ip: str | None = None
    mask: str | None = None
    mac: str | None = None
    status: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass(slots=True)
class DeviceCandidate:
    name: str | None = None
    device_type: str | None = None
    subtype: str | None = None
    model: str | None = None
    position: dict[str, float | int | None] = field(
        default_factory=lambda: {"x": None, "y": None}
    )
    interfaces: list[InterfaceCandidate] = field(default_factory=list)
    config_text: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    source: str = "unknown"


@dataclass(slots=True)
class LinkCandidate:
    from_device_name: str | None = None
    from_interface_name: str | None = None
    to_device_name: str | None = None
    to_interface_name: str | None = None
    link_type: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass(slots=True)
class NoteCandidate:
    text: str
    raw: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0


@dataclass(slots=True)
class UnmappedBlock:
    block_id: str
    source: str
    classification: str
    preview: str
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ExtractionResult:
    version_hints: list[str] = field(default_factory=list)
    devices: list[DeviceCandidate] = field(default_factory=list)
    links: list[LinkCandidate] = field(default_factory=list)
    notes: list[NoteCandidate] = field(default_factory=list)
    unmapped_blocks: list[UnmappedBlock] = field(default_factory=list)
    observables: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ReportEvent:
    level: LogLevel
    message: str
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


@dataclass(slots=True)
class PipelineArtifacts:
    raw_dump: dict[str, Any]
    normalized_topology: dict[str, Any]
    extraction_report: dict[str, Any]
    recovered_text: str
    exit_code: int
