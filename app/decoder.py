from __future__ import annotations

import bz2
import gzip
import io
import zipfile
import zlib
from pathlib import Path

from .heuristics import classify_text_fragment
from .models import DecodeResult, DecodedChunk, InspectionResult, TextFragment
from .report import ReportBuilder
from .utils import decode_bytes, ensure_directory, hex_preview, iter_printable_spans, text_preview


SUPPORTED_COMPRESSION_KINDS = {"gzip", "zlib", "bzip2", "zip"}


def decode_payloads(
    data: bytes,
    inspection: InspectionResult,
    report: ReportBuilder,
    *,
    debug_dir: Path | None = None,
    max_text_fragments: int = 5000,
) -> DecodeResult:
    result = DecodeResult()
    fragment_counter = 0

    if debug_dir:
        ensure_directory(debug_dir)

    def add_span(source: str, offset: int, raw: bytes, metadata: dict[str, object] | None = None) -> None:
        nonlocal fragment_counter
        fragment_counter += 1
        text, encoding = decode_bytes(raw)
        classification, confidence, markers = classify_text_fragment(text)
        fragment_id = f"text_{fragment_counter:04d}"
        preview = text_preview(text)
        hex_value = hex_preview(raw)

        result.text_fragments.append(
            TextFragment(
                id=fragment_id,
                source=source,
                offset=offset,
                length=len(raw),
                encoding=encoding,
                classification=classification,
                confidence=confidence,
                text=text,
                preview=preview,
                raw_hex_preview=hex_value,
                markers=markers,
            )
        )
        result.chunks.append(
            DecodedChunk(
                id=fragment_id,
                source_type=source,
                offset=offset,
                length=len(raw),
                classification=classification,
                encoding=encoding,
                confidence=confidence,
                preview=preview,
                text=text,
                raw_hex_preview=hex_value,
                metadata=metadata or {},
            )
        )
        report.trace(
            "Decoded text fragment",
            fragment_id=fragment_id,
            source=source,
            offset=offset,
            classification=classification,
        )

        if debug_dir and classification in {"xml", "config", "structured_text"}:
            suffix = "xml" if classification == "xml" else "txt"
            file_name = f"{fragment_id}_{classification}.{suffix}"
            (debug_dir / file_name).write_text(text, encoding="utf-8")

    spans, truncated = iter_printable_spans(data, min_run=8, max_fragments=max_text_fragments)
    for offset, raw in spans:
        add_span("file", offset, raw)

    if truncated:
        warning = "Printable text extraction hit the fragment limit and was truncated."
        result.warnings.append(warning)
        report.warning(warning, max_text_fragments=max_text_fragments)

    seen_offsets: set[tuple[str, int]] = set()
    for signature in inspection.signatures:
        if signature.kind not in SUPPORTED_COMPRESSION_KINDS:
            continue
        signature_key = (signature.kind, signature.offset)
        if signature_key in seen_offsets:
            continue
        seen_offsets.add(signature_key)

        payload = data[signature.offset :]
        try:
            if signature.kind == "gzip":
                decompressed = gzip.decompress(payload)
            elif signature.kind == "zlib":
                decompressed = zlib.decompress(payload)
            elif signature.kind == "bzip2":
                decompressed = bz2.decompress(payload)
            else:
                with zipfile.ZipFile(io.BytesIO(payload)) as archive:
                    for name in archive.namelist():
                        try:
                            member = archive.read(name)
                        except Exception as exc:  # pragma: no cover
                            report.error(
                                "Failed to read ZIP member",
                                member=name,
                                offset=signature.offset,
                                error=str(exc),
                            )
                            continue
                        member_spans, _ = iter_printable_spans(member, min_run=8, max_fragments=100)
                        for inner_offset, raw in member_spans:
                            add_span(
                                f"zip:{name}",
                                inner_offset,
                                raw,
                                metadata={
                                    "compressed_offset": signature.offset,
                                    "archive_member": name,
                                },
                            )
                        if debug_dir:
                            (debug_dir / f"zip_{name.replace('/', '_')}").write_bytes(member)
                continue

            report.trace(
                "Decompressed candidate payload",
                kind=signature.kind,
                offset=signature.offset,
                decompressed_size=len(decompressed),
            )
            inner_spans, _ = iter_printable_spans(decompressed, min_run=8, max_fragments=250)
            for inner_offset, raw in inner_spans:
                add_span(
                    f"decompressed:{signature.kind}",
                    inner_offset,
                    raw,
                    metadata={
                        "compressed_offset": signature.offset,
                        "compression_kind": signature.kind,
                    },
                )
            if debug_dir:
                (debug_dir / f"decompressed_{signature.kind}_{signature.offset:08d}.bin").write_bytes(
                    decompressed
                )
        except Exception as exc:
            message = "Failed to decompress candidate payload"
            result.errors.append(f"{message}: {signature.kind}@{signature.offset}: {exc}")
            report.error(
                message,
                kind=signature.kind,
                offset=signature.offset,
                error=str(exc),
            )

    result.recovered_text = "\n\n".join(fragment.text for fragment in result.text_fragments)
    return result
