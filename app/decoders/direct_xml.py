from __future__ import annotations

from pathlib import Path

from ..models import DecodedPktResult
from ..report import ReportBuilder
from ..utils import decode_bytes, hex_preview
from .base import DecoderStrategy
from .common import preview_text, write_debug_xml


class DirectXmlDecoder(DecoderStrategy):
    name = "direct_xml"
    used_algorithm = "direct-xml"

    def decode(
        self,
        data: bytes,
        source_file: str,
        *,
        report: ReportBuilder | None = None,
        debug_dir: Path | None = None,
    ) -> DecodedPktResult:
        text, encoding = decode_bytes(data)
        stripped = text.lstrip("\ufeff\r\n\t ")
        result = DecodedPktResult(
            source_file=source_file,
            success=False,
            raw_size_bytes=len(data),
            strategy_name=self.name,
            used_algorithm=self.used_algorithm,
            debug_info={
                "raw_hex_preview": hex_preview(data),
                "text_encoding": encoding,
            },
        )
        if not stripped.startswith("<"):
            result.errors.append("File does not begin with XML content.")
            return result

        result.success = True
        result.xml_content = stripped
        result.xml_size_bytes = len(stripped.encode("utf-8", errors="ignore"))
        result.xml_preview = preview_text(stripped)
        path = write_debug_xml(debug_dir, stripped)
        if path:
            result.debug_info["debug_xml_path"] = str(path)
        if report:
            report.trace("Direct XML decoder matched file bytes", source_file=source_file)
        return result
