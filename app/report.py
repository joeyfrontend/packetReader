from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from . import __version__
from .models import DecodeResult, ExtractionResult, InspectionResult, ReportEvent
from .utils import current_timestamp


LEVEL_TO_LOGGING = {
    "info": logging.INFO,
    "warning": logging.WARNING,
    "recoverable_error": logging.ERROR,
    "fatal_error": logging.CRITICAL,
    "trace": logging.DEBUG,
}


class ReportBuilder:
    def __init__(self, logger: logging.Logger | None = None, *, debug: bool = False) -> None:
        self.logger = logger or logging.getLogger("pkt_converter")
        self.debug = debug
        self.events: list[ReportEvent] = []

    def _add(self, level: str, message: str, context: dict[str, Any] | None = None) -> None:
        entry = ReportEvent(
            level=level,
            message=message,
            context=context or {},
            timestamp=current_timestamp(),
        )
        self.events.append(entry)
        self.logger.log(LEVEL_TO_LOGGING[level], message, extra={"context": entry.context})

    def info(self, message: str, **context: Any) -> None:
        self._add("info", message, context)

    def warning(self, message: str, **context: Any) -> None:
        self._add("warning", message, context)

    def error(self, message: str, **context: Any) -> None:
        self._add("recoverable_error", message, context)

    def fatal(self, message: str, **context: Any) -> None:
        self._add("fatal_error", message, context)

    def trace(self, message: str, **context: Any) -> None:
        if self.debug:
            self._add("trace", message, context)

    @property
    def has_fatal(self) -> bool:
        return any(event.level == "fatal_error" for event in self.events)

    def messages(self, level: str) -> list[dict[str, Any]]:
        return [
            {"message": event.message, "context": event.context, "timestamp": event.timestamp}
            for event in self.events
            if event.level == level
        ]

    def to_payload(
        self,
        *,
        source_file: str,
        inspection: InspectionResult | None,
        decode_result: DecodeResult | None,
        extraction: ExtractionResult | None,
        normalized_topology: dict[str, Any] | None,
    ) -> dict[str, Any]:
        decoded_chunks = len(decode_result.chunks) if decode_result else 0
        text_fragments = len(decode_result.text_fragments) if decode_result else 0
        device_candidates = len(extraction.devices) if extraction else 0
        link_candidates = len(extraction.links) if extraction else 0
        notes = len(extraction.notes) if extraction else 0
        unmapped = len(extraction.unmapped_blocks) if extraction else 0
        normalized_devices = len(normalized_topology.get("devices", [])) if normalized_topology else 0
        normalized_links = len(normalized_topology.get("links", [])) if normalized_topology else 0

        fields_extracted = {
            "device_names": 0,
            "device_types": 0,
            "device_positions": 0,
            "interface_names": 0,
            "interface_ips": 0,
            "config_texts": 0,
            "link_endpoints": 0,
        }
        missing_fields = {
            "devices_without_name": 0,
            "devices_without_type": 0,
            "devices_without_position": 0,
            "interfaces_without_ip": 0,
            "links_with_missing_endpoints": 0,
        }

        if normalized_topology:
            for device in normalized_topology.get("devices", []):
                if device.get("name"):
                    fields_extracted["device_names"] += 1
                else:
                    missing_fields["devices_without_name"] += 1
                if device.get("type"):
                    fields_extracted["device_types"] += 1
                else:
                    missing_fields["devices_without_type"] += 1
                position = device.get("position") or {}
                if position.get("x") is not None or position.get("y") is not None:
                    fields_extracted["device_positions"] += 1
                else:
                    missing_fields["devices_without_position"] += 1
                if device.get("config_text"):
                    fields_extracted["config_texts"] += 1
                for interface in device.get("interfaces", []):
                    if interface.get("name"):
                        fields_extracted["interface_names"] += 1
                    if interface.get("ip"):
                        fields_extracted["interface_ips"] += 1
                    else:
                        missing_fields["interfaces_without_ip"] += 1
            for link in normalized_topology.get("links", []):
                if link.get("from_device_id") and link.get("to_device_id"):
                    fields_extracted["link_endpoints"] += 1
                else:
                    missing_fields["links_with_missing_endpoints"] += 1

        suspicious_sections: list[dict[str, Any]] = []
        if extraction:
            suspicious_sections.extend(
                {
                    "block_id": block.block_id,
                    "classification": block.classification,
                    "preview": block.preview,
                    "source": block.source,
                }
                for block in extraction.unmapped_blocks
            )
        if inspection:
            counts = Counter(signature.kind for signature in inspection.signatures)
            suspicious_sections.extend(
                {
                    "kind": kind,
                    "count": count,
                    "reason": "Detected signature requires future reverse-engineering support"
                    if kind in {"gzip", "zlib", "bzip2", "zip", "xz"}
                    else "Observed file marker",
                }
                for kind, count in counts.items()
            )

        return {
            "meta": {
                "source_file": source_file,
                "parser_version": __version__,
                "generated_at": current_timestamp(),
            },
            "status": {
                "success": not self.has_fatal,
                "partial": any(
                    event.level in {"warning", "recoverable_error"} for event in self.events
                ),
                "fatal_error": next(
                    (event.message for event in self.events if event.level == "fatal_error"),
                    None,
                ),
            },
            "counts": {
                "signatures_detected": len(inspection.signatures) if inspection else 0,
                "decoded_chunks": decoded_chunks,
                "text_fragments": text_fragments,
                "device_candidates": device_candidates,
                "link_candidates": link_candidates,
                "notes": notes,
                "unmapped_blocks": unmapped,
                "normalized_devices": normalized_devices,
                "normalized_links": normalized_links,
            },
            "fields_extracted": fields_extracted,
            "missing_fields": missing_fields,
            "suspicious_sections": suspicious_sections,
            "events": {
                "info": self.messages("info"),
                "warnings": self.messages("warning"),
                "recoverable_errors": self.messages("recoverable_error"),
                "fatal_errors": self.messages("fatal_error"),
                "trace": self.messages("trace") if self.debug else [],
            },
        }
