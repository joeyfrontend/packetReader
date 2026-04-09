from __future__ import annotations

import re
from pathlib import Path

from ..utils import decode_bytes, ensure_directory, text_preview


XML_ENCODING_PATTERN = re.compile(r'encoding=["\']([^"\']+)["\']', re.IGNORECASE)


def decode_xml_bytes(xml_bytes: bytes) -> tuple[str, str]:
    prefix = xml_bytes[:200].decode("latin-1", errors="ignore")
    match = XML_ENCODING_PATTERN.search(prefix)
    if match:
        encoding = match.group(1)
        try:
            return xml_bytes.decode(encoding), encoding
        except (LookupError, UnicodeDecodeError):
            pass
    content, encoding = decode_bytes(xml_bytes)
    return content, encoding


def extract_xml_text_from_payload(payload: bytes) -> tuple[str | None, str | None, int | None]:
    xml_offset = payload.find(b"<?xml")
    if xml_offset < 0:
        stripped = payload.lstrip()
        if stripped.startswith(b"<"):
            xml_offset = len(payload) - len(stripped)
        else:
            return None, None, None

    xml_bytes = payload[xml_offset:]
    xml_content, encoding = decode_xml_bytes(xml_bytes)
    if not xml_content.lstrip().startswith("<"):
        return None, None, None
    return xml_content, encoding, xml_offset


def write_debug_xml(debug_dir: Path | None, xml_content: str) -> Path | None:
    if debug_dir is None:
        return None
    ensure_directory(debug_dir)
    path = debug_dir / "decoded.xml"
    path.write_text(xml_content, encoding="utf-8")
    return path


def preview_text(text: str | None) -> str | None:
    if text is None:
        return None
    return text_preview(text)
