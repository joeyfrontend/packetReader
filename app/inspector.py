from __future__ import annotations

import re

from .models import InspectionResult, SignatureHit
from .report import ReportBuilder
from .utils import printable_ratio, shannon_entropy, sha256_hex


SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\x1f\x8b", "gzip", "GZIP compressed stream"),
    (b"PK\x03\x04", "zip", "ZIP local file header"),
    (b"BZh", "bzip2", "BZip2 compressed stream"),
    (b"\xfd7zXZ\x00", "xz", "XZ compressed stream"),
    (b"x\x9c", "zlib", "Zlib compressed block"),
    (b"<?xml", "xml", "XML declaration"),
]

VERSION_PATTERNS = [
    re.compile(r"Packet\s+Tracer(?:\s+Version)?\s*([0-9]+(?:\.[0-9]+)+)", re.IGNORECASE),
    re.compile(r"packetTracerVersion\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
    re.compile(r"version\s*=\s*['\"]([^'\"]+)['\"]", re.IGNORECASE),
]


def inspect_bytes(data: bytes, source_file: str, report: ReportBuilder) -> InspectionResult:
    null_byte_ratio = round(data.count(0) / len(data), 4) if data else 0.0
    report.info("Inspecting input bytes", source_file=source_file, size_bytes=len(data))
    inspection = InspectionResult(
        source_file=source_file,
        size_bytes=len(data),
        sha256=sha256_hex(data),
        entropy=shannon_entropy(data),
        printable_ratio=printable_ratio(data),
        magic_hex=data[:16].hex(),
        null_byte_ratio=null_byte_ratio,
    )

    if data:
        segment_count = min(4, max(1, len(data) // 4096))
        segment_size = max(1, len(data) // segment_count)
        for index in range(segment_count):
            start = index * segment_size
            end = len(data) if index == segment_count - 1 else min(len(data), start + segment_size)
            chunk = data[start:end]
            inspection.segment_entropies.append(
                {
                    "index": index,
                    "start": start,
                    "end": end,
                    "entropy": shannon_entropy(chunk),
                    "printable_ratio": printable_ratio(chunk),
                }
            )

    for signature, kind, description in SIGNATURES:
        search_from = 0
        offsets: list[int] = []
        while True:
            offset = data.find(signature, search_from)
            if offset < 0:
                break
            confidence = 0.95 if offset == 0 else 0.7
            inspection.signatures.append(
                SignatureHit(
                    kind=kind,
                    offset=offset,
                    description=description,
                    confidence=confidence,
                )
            )
            report.trace(
                "Detected signature",
                kind=kind,
                offset=offset,
                confidence=confidence,
            )
            offsets.append(offset)
            search_from = offset + 1
        if offsets:
            inspection.candidate_offsets[kind] = offsets[:32]

    text_probe = data[: min(len(data), 250_000)].decode("latin-1", errors="ignore")
    if "Cisco Packet Tracer" in text_probe or "Packet Tracer" in text_probe:
        inspection.signatures.append(
            SignatureHit(
                kind="packet_tracer_text",
                offset=text_probe.find("Packet Tracer"),
                description="Packet Tracer text marker",
                confidence=0.85,
            )
        )
        report.trace("Detected Packet Tracer textual marker")

    for pattern in VERSION_PATTERNS:
        for match in pattern.finditer(text_probe):
            hint = match.group(1).strip()
            if hint not in inspection.version_hints:
                inspection.version_hints.append(hint)
                report.trace("Detected version hint", version_hint=hint)

    if inspection.entropy > 7.6:
        inspection.warnings.append("High entropy suggests packed or compressed binary content.")
        report.warning("High entropy file content detected", entropy=inspection.entropy)
    if inspection.null_byte_ratio > 0.1:
        inspection.warnings.append("Significant null-byte ratio suggests a structured binary container.")
        report.warning("Null-byte-heavy binary structure detected", null_byte_ratio=inspection.null_byte_ratio)
    if inspection.printable_ratio < 0.05:
        inspection.warnings.append("Very low printable ratio; extraction will rely heavily on heuristics.")
        report.warning(
            "Low printable ratio detected",
            printable_ratio=inspection.printable_ratio,
        )

    return inspection
