from __future__ import annotations

import zlib
from pathlib import Path

from ..models import DecodedPktResult
from ..report import ReportBuilder
from ..utils import hex_preview
from .base import DecoderStrategy
from .common import decode_xml_bytes, preview_text, write_debug_xml


def _xor_decode(data: bytes) -> bytes:
    key = len(data)
    decoded = bytearray()
    for value in data:
        decoded.append((value ^ key) & 0xFF)
        key -= 1
    return bytes(decoded)


class LegacyXorZlibDecoder(DecoderStrategy):
    name = "legacy_xor_zlib"
    used_algorithm = "xor+zlib"

    def decode(
        self,
        data: bytes,
        source_file: str,
        *,
        report: ReportBuilder | None = None,
        debug_dir: Path | None = None,
    ) -> DecodedPktResult:
        result = DecodedPktResult(
            source_file=source_file,
            success=False,
            raw_size_bytes=len(data),
            strategy_name=self.name,
            used_algorithm=self.used_algorithm,
            debug_info={"raw_hex_preview": hex_preview(data)},
        )

        if len(data) < 5:
            result.errors.append("Input is too small to contain a Packet Tracer XOR+zlib payload.")
            return result

        if report:
            report.trace("Starting legacy XOR decode step", source_file=source_file)

        try:
            xor_decoded = _xor_decode(data)
        except Exception as exc:  # pragma: no cover
            result.errors.append(f"XOR decode failed: {exc}")
            return result

        result.xor_decoded_size_bytes = len(xor_decoded)
        result.debug_info["xor_hex_preview"] = hex_preview(xor_decoded)

        declared_size = int.from_bytes(xor_decoded[:4], byteorder="big")
        result.declared_uncompressed_size = declared_size
        result.debug_info["zlib_hex_preview"] = hex_preview(xor_decoded[4:])

        try:
            xml_bytes = zlib.decompress(xor_decoded[4:])
        except zlib.error as exc:
            result.errors.append(f"Zlib decompression failed: {exc}")
            return result

        result.xml_size_bytes = len(xml_bytes)
        result.debug_info["decompressed_hex_preview"] = hex_preview(xml_bytes)
        if declared_size != len(xml_bytes):
            result.warnings.append(
                "Declared uncompressed size does not match decompressed payload length."
            )

        xml_content, encoding = decode_xml_bytes(xml_bytes)
        result.debug_info["xml_encoding"] = encoding
        result.xml_preview = preview_text(xml_content)

        if not xml_content.lstrip().startswith("<"):
            result.errors.append("Decoded payload does not look like XML.")
            return result

        result.success = True
        result.xml_content = xml_content
        path = write_debug_xml(debug_dir, xml_content)
        if path:
            result.debug_info["debug_xml_path"] = str(path)
        return result
