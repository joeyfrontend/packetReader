from __future__ import annotations

import gzip
from pathlib import Path

from ..models import DecodedPktResult
from ..report import ReportBuilder
from ..utils import hex_preview
from .base import DecoderStrategy
from .common import extract_xml_text_from_payload, preview_text, write_debug_xml


class GzipCarvingDecoder(DecoderStrategy):
    name = "gzip_carve"
    used_algorithm = "gzip-carve"

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

        attempted_offsets: list[int] = []
        search_from = 0
        while True:
            offset = data.find(b"\x1f\x8b", search_from)
            if offset < 0:
                break
            attempted_offsets.append(offset)
            search_from = offset + 1
            payload = data[offset:]
            try:
                decompressed = gzip.decompress(payload)
            except OSError:
                continue
            xml_content, encoding, xml_offset = extract_xml_text_from_payload(decompressed)
            if not xml_content:
                continue
            result.success = True
            result.xml_content = xml_content
            result.xml_size_bytes = len(xml_content.encode("utf-8", errors="ignore"))
            result.xml_preview = preview_text(xml_content)
            result.debug_info.update(
                {
                    "carved_gzip_offset": offset,
                    "decompressed_hex_preview": hex_preview(decompressed),
                    "xml_encoding": encoding,
                    "xml_offset_inside_payload": xml_offset,
                }
            )
            path = write_debug_xml(debug_dir, xml_content)
            if path:
                result.debug_info["debug_xml_path"] = str(path)
            if report:
                report.trace(
                    "Gzip carving decoder succeeded",
                    source_file=source_file,
                    carved_offset=offset,
                )
            return result

        result.errors.append("No gzip-compressed XML payload found by carving strategy.")
        result.debug_info["attempted_offsets"] = attempted_offsets[:128]
        return result
