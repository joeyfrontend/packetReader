from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from . import __version__
from .decoder import decode_payloads
from .heuristics import (
    extract_devices_from_config,
    extract_loose_candidates,
    extract_observables,
    find_embedded_xml_blocks,
    extract_xml_entities,
)
from .inspector import inspect_bytes
from .models import ExtractionResult, PipelineArtifacts, UnmappedBlock
from .normalizer import normalize_topology
from .report import ReportBuilder
from .utils import current_timestamp


LOGGER = logging.getLogger("pkt_converter")


def _build_empty_normalized(source_file: str) -> dict[str, Any]:
    return {
        "meta": {
            "source_file": source_file,
            "parser_version": __version__,
            "packet_tracer_version_hint": None,
            "parsed_at": current_timestamp(),
            "warnings": [],
        },
        "devices": [],
        "links": [],
        "notes": [],
        "unmapped_blocks": [],
    }


def _merge_observables(target: dict[str, list[str]], source: dict[str, list[str]]) -> None:
    for key, values in source.items():
        bucket = set(target.get(key, []))
        bucket.update(values)
        target[key] = sorted(bucket)


def _extract_entities(
    source_file: str,
    decode_result,
    report: ReportBuilder,
    *,
    strings_only: bool = False,
) -> ExtractionResult:
    extraction = ExtractionResult()

    for fragment in decode_result.text_fragments:
        report.trace(
            "Analyzing text fragment",
            fragment_id=fragment.id,
            classification=fragment.classification,
            source=fragment.source,
        )
        _merge_observables(extraction.observables, extract_observables(fragment.text))

        if strings_only:
            continue

        found_any = False

        xml_blocks = [fragment.text] if fragment.classification == "xml" else find_embedded_xml_blocks(fragment.text)
        for xml_index, xml_block in enumerate(xml_blocks, start=1):
            xml_fragment_id = fragment.id if fragment.classification == "xml" else f"{fragment.id}:xml_{xml_index}"
            devices, links, notes, version_hints, warnings = extract_xml_entities(
                xml_block,
                xml_fragment_id,
            )
            extraction.devices.extend(devices)
            extraction.links.extend(links)
            extraction.notes.extend(notes)
            found_any = found_any or bool(devices or links or notes)
            for hint in version_hints:
                if hint not in extraction.version_hints:
                    extraction.version_hints.append(hint)
            for warning in warnings:
                extraction.warnings.append(warning)
                report.warning(warning, fragment_id=xml_fragment_id)

        config_devices = []
        if fragment.classification == "config" or "hostname " in fragment.text.lower():
            config_devices = extract_devices_from_config(fragment.text, fragment.id)
            extraction.devices.extend(config_devices)
            found_any = found_any or bool(config_devices)

        if fragment.classification != "xml":
            devices, links, notes = extract_loose_candidates(fragment.text, fragment.id)
            if fragment.classification != "config" or not config_devices:
                extraction.devices.extend(devices)
                found_any = found_any or bool(devices)
            extraction.links.extend(links)
            extraction.notes.extend(notes)
            found_any = found_any or bool(links or notes)

        if fragment.classification in {"config", "xml", "structured_text"} and not found_any:
            extraction.unmapped_blocks.append(
                UnmappedBlock(
                    block_id=fragment.id,
                    source=fragment.source,
                    classification=fragment.classification,
                    preview=fragment.preview,
                    raw={"reason": "structured fragment did not yield entity matches"},
                )
            )

    if not extraction.version_hints:
        report.info("No in-band Packet Tracer version hint extracted", source_file=source_file)

    return extraction


def _build_raw_dump(
    source_file: str,
    inspection,
    decode_result,
    extraction: ExtractionResult,
    report: ReportBuilder,
) -> dict[str, Any]:
    config_like_strings = [
        {
            "fragment_id": fragment.id,
            "source": fragment.source,
            "preview": fragment.preview,
            "text": fragment.text,
        }
        for fragment in decode_result.text_fragments
        if fragment.classification == "config"
    ]

    xml_like_blocks = [
        {
            "fragment_id": fragment.id,
            "source": fragment.source,
            "preview": fragment.preview,
            "text": fragment.text,
        }
        for fragment in decode_result.text_fragments
        if fragment.classification == "xml"
    ]

    return {
        "meta": {
            "source_file": source_file,
            "parser_version": __version__,
            "parsed_at": current_timestamp(),
        },
        "inspection": inspection,
        "decoded": {
            "chunks": decode_result.chunks,
            "text_fragments": decode_result.text_fragments,
            "recovered_text_length": len(decode_result.recovered_text),
        },
        "observables": extraction.observables,
        "raw_xml_blocks": xml_like_blocks,
        "config_like_strings": config_like_strings,
        "entities": {
            "devices": extraction.devices,
            "links": extraction.links,
            "notes": extraction.notes,
        },
        "unmapped_blocks": extraction.unmapped_blocks,
        "warnings": [event["message"] for event in report.messages("warning")],
        "errors": [event["message"] for event in report.messages("recoverable_error")],
    }


def run_pipeline(
    input_path: Path,
    *,
    output_dir: Path | None = None,
    debug: bool = False,
    strings_only: bool = False,
) -> PipelineArtifacts:
    report = ReportBuilder(LOGGER, debug=debug)
    raw_dump: dict[str, Any] = {
        "meta": {
            "source_file": input_path.name,
            "parser_version": __version__,
            "parsed_at": current_timestamp(),
        },
        "warnings": [],
        "errors": [],
    }
    normalized_topology = _build_empty_normalized(input_path.name)

    try:
        data = input_path.read_bytes()
    except FileNotFoundError:
        report.fatal("Input file does not exist", path=str(input_path))
        report_payload = report.to_payload(
            source_file=input_path.name,
            inspection=None,
            decode_result=None,
            extraction=None,
            normalized_topology=normalized_topology,
        )
        return PipelineArtifacts(
            raw_dump=raw_dump,
            normalized_topology=normalized_topology,
            extraction_report=report_payload,
            recovered_text="",
            exit_code=1,
        )
    except OSError as exc:
        report.fatal("Failed to read input file", path=str(input_path), error=str(exc))
        report_payload = report.to_payload(
            source_file=input_path.name,
            inspection=None,
            decode_result=None,
            extraction=None,
            normalized_topology=normalized_topology,
        )
        return PipelineArtifacts(
            raw_dump=raw_dump,
            normalized_topology=normalized_topology,
            extraction_report=report_payload,
            recovered_text="",
            exit_code=1,
        )

    inspection = inspect_bytes(data, input_path.name, report)
    debug_dir = output_dir / "debug" if debug and output_dir else None
    decode_result = decode_payloads(
        data,
        inspection,
        report,
        debug_dir=debug_dir,
    )
    extraction = _extract_entities(
        input_path.name,
        decode_result,
        report,
        strings_only=strings_only,
    )
    if not extraction.version_hints:
        extraction.version_hints.extend(inspection.version_hints)
    if strings_only:
        report.info("Strings-only mode enabled; skipping normalization extraction")
        normalized_topology = _build_empty_normalized(input_path.name)
    else:
        normalized_topology = normalize_topology(input_path.name, extraction)

    raw_dump = _build_raw_dump(
        input_path.name,
        inspection,
        decode_result,
        extraction,
        report,
    )
    report_payload = report.to_payload(
        source_file=input_path.name,
        inspection=inspection,
        decode_result=decode_result,
        extraction=extraction,
        normalized_topology=normalized_topology,
    )

    return PipelineArtifacts(
        raw_dump=raw_dump,
        normalized_topology=normalized_topology,
        extraction_report=report_payload,
        recovered_text=decode_result.recovered_text,
        exit_code=1 if report.has_fatal else 0,
    )
