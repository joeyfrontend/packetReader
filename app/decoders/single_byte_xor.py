from __future__ import annotations

import zlib
from pathlib import Path
import xml.etree.ElementTree as ET

from ..models import DecodedPktResult
from ..report import ReportBuilder
from ..utils import hex_preview
from .base import DecoderStrategy
from .common import extract_xml_text_from_payload, preview_text, write_debug_xml


ZLIB_HEADERS = (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda")


def _is_well_formed_xml(text: str | None) -> bool:
    if not text:
        return False
    try:
        ET.fromstring(text)
    except ET.ParseError:
        return False
    return True


class SingleByteXorProbeDecoder(DecoderStrategy):
    name = "single_byte_xor_probe"
    used_algorithm = "single-byte-xor-probe"

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

        successful_probe: dict[str, int | str] | None = None

        for key in range(256):
            transformed = bytes(value ^ key for value in data)
            xml_content, encoding, xml_offset = extract_xml_text_from_payload(transformed)
            if xml_content and _is_well_formed_xml(xml_content):
                result.success = True
                result.xml_content = xml_content
                result.xml_size_bytes = len(xml_content.encode("utf-8", errors="ignore"))
                result.xml_preview = preview_text(xml_content)
                successful_probe = {
                    "xor_key": key,
                    "mode": "direct_xml",
                    "xml_offset": xml_offset or 0,
                    "xml_encoding": encoding or "unknown",
                }
                break

            for header in ZLIB_HEADERS:
                start = 0
                while True:
                    offset = transformed.find(header, start)
                    if offset < 0:
                        break
                    start = offset + 1
                    try:
                        payload = zlib.decompress(transformed[offset:])
                    except zlib.error:
                        try:
                            obj = zlib.decompressobj()
                            payload = obj.decompress(transformed[offset:])
                        except zlib.error:
                            continue
                    xml_content, encoding, xml_offset = extract_xml_text_from_payload(payload)
                    if not xml_content or not _is_well_formed_xml(xml_content):
                        continue
                    result.success = True
                    result.xml_content = xml_content
                    result.xml_size_bytes = len(xml_content.encode("utf-8", errors="ignore"))
                    result.xml_preview = preview_text(xml_content)
                    successful_probe = {
                        "xor_key": key,
                        "mode": "xor_then_zlib",
                        "zlib_offset": offset,
                        "xml_offset": xml_offset or 0,
                        "xml_encoding": encoding or "unknown",
                    }
                    break
                if result.success:
                    break
            if result.success:
                break

        if not result.success:
            result.errors.append("No XML-bearing single-byte XOR transform was detected.")
            return result

        result.debug_info.update(successful_probe or {})
        path = write_debug_xml(debug_dir, result.xml_content or "")
        if path:
            result.debug_info["debug_xml_path"] = str(path)
        if report:
            report.trace(
                "Single-byte XOR probe succeeded",
                source_file=source_file,
                xor_key=result.debug_info.get("xor_key"),
                mode=result.debug_info.get("mode"),
            )
        return result
