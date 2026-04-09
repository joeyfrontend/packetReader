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
from .models import DecodeResult, DecodedPktResult, ExtractionResult, PipelineArtifacts, UnmappedBlock, XmlParseResult
from .normalizer import normalize_topology
from .pkt_decoder import decode_pkt_bytes
from .report import ReportBuilder
from .utils import current_timestamp
from .xml_parser import parse_xml_content


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


def _observables_from_xml_extraction(extraction: ExtractionResult) -> dict[str, list[str]]:
    observables: dict[str, list[str]] = {
        "ip_addresses": [],
        "interfaces": [],
        "hostnames": [],
        "mac_addresses": [],
        "config_markers": [],
    }
    for device in extraction.devices:
        if device.name:
            observables["hostnames"].append(device.name)
        if device.config_text:
            _merge_observables(observables, extract_observables(device.config_text))
        for interface in device.interfaces:
            if interface.name:
                observables["interfaces"].append(interface.name)
            if interface.ip:
                observables["ip_addresses"].append(interface.ip)
            if interface.mac:
                observables["mac_addresses"].append(interface.mac)
    for key, values in list(observables.items()):
        observables[key] = sorted(set(values))
    return observables


def _build_extraction_from_xml(xml_result: XmlParseResult) -> ExtractionResult:
    extraction = ExtractionResult(
        version_hints=list(xml_result.version_hints),
        devices=list(xml_result.devices),
        links=list(xml_result.links),
        notes=list(xml_result.notes),
        warnings=list(xml_result.warnings),
        errors=list(xml_result.errors),
    )
    extraction.observables = _observables_from_xml_extraction(extraction)
    if not extraction.devices and not extraction.links and not extraction.notes:
        extraction.unmapped_blocks.append(
            UnmappedBlock(
                block_id="decoded_xml",
                source="deterministic_decoder",
                classification="xml",
                preview="Decoded XML parsed but yielded no high-level entities.",
                raw={"root_tag": xml_result.root_tag},
            )
        )
    return extraction


def _extract_entities_from_heuristics(
    source_file: str,
    decode_result: DecodeResult,
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
    extraction: ExtractionResult,
    report: ReportBuilder,
    *,
    parser_path: str,
    pkt_decode: DecodedPktResult | None = None,
    xml_parse: XmlParseResult | None = None,
    decode_result: DecodeResult | None = None,
) -> dict[str, Any]:
    config_like_strings: list[dict[str, Any]] = []
    xml_like_blocks: list[dict[str, Any]] = []

    if pkt_decode and pkt_decode.xml_content:
        xml_like_blocks.append(
            {
                "fragment_id": "decoded_xml",
                "source": pkt_decode.strategy_name or "deterministic_decoder",
                "preview": pkt_decode.xml_preview,
                "text": pkt_decode.xml_content,
            }
        )
    if decode_result:
        config_like_strings.extend(
            {
                "fragment_id": fragment.id,
                "source": fragment.source,
                "preview": fragment.preview,
                "text": fragment.text,
            }
            for fragment in decode_result.text_fragments
            if fragment.classification == "config"
        )
        xml_like_blocks.extend(
            {
                "fragment_id": fragment.id,
                "source": fragment.source,
                "preview": fragment.preview,
                "text": fragment.text,
            }
            for fragment in decode_result.text_fragments
            if fragment.classification == "xml"
        )

    if not config_like_strings:
        for index, device in enumerate(extraction.devices, start=1):
            if device.config_text:
                config_like_strings.append(
                    {
                        "fragment_id": f"device_config_{index}",
                        "source": device.source,
                        "preview": device.config_text[:180],
                        "text": device.config_text,
                    }
                )

    return {
        "meta": {
            "source_file": source_file,
            "parser_version": __version__,
            "parsed_at": current_timestamp(),
            "parser_path": parser_path,
        },
        "inspection": inspection,
        "deterministic_decode": pkt_decode,
        "decoder_attempts": pkt_decode.attempts if pkt_decode else [],
        "xml_parse": xml_parse,
        "decoded": {
            "chunks": decode_result.chunks if decode_result else [],
            "text_fragments": decode_result.text_fragments if decode_result else [],
            "recovered_text_length": len(decode_result.recovered_text) if decode_result else 0,
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
            pkt_decode=None,
            xml_parse=None,
            parser_path="read_error",
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
            pkt_decode=None,
            xml_parse=None,
            parser_path="read_error",
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

    pkt_decode = decode_pkt_bytes(
        data,
        input_path.name,
        report=report,
        debug_dir=debug_dir,
    )
    xml_parse: XmlParseResult | None = None
    decode_result: DecodeResult | None = None
    parser_path = "deterministic_xml"
    if pkt_decode.strategy_name:
        parser_path = pkt_decode.strategy_name

    if pkt_decode.success and pkt_decode.xml_content:
        xml_parse = parse_xml_content(pkt_decode.xml_content, source_fragment="decoded_xml")
        if xml_parse.success:
            report.info(
                "Decoded XML parsed successfully",
                source_file=input_path.name,
                strategy_name=pkt_decode.strategy_name,
                root_tag=xml_parse.root_tag,
                device_count=len(xml_parse.devices),
                link_count=len(xml_parse.links),
            )
            extraction = _build_extraction_from_xml(xml_parse)
        else:
            parser_path = "heuristic_fallback"
            for warning in xml_parse.warnings:
                report.warning(warning, source_file=input_path.name)
            for error in xml_parse.errors:
                report.error("Decoded XML parse failed", source_file=input_path.name, error=error)
            decode_result = decode_payloads(
                data,
                inspection,
                report,
                debug_dir=debug_dir,
            )
            extraction = _extract_entities_from_heuristics(
                input_path.name,
                decode_result,
                report,
                strings_only=strings_only,
            )
    else:
        parser_path = "heuristic_fallback"
        decode_result = decode_payloads(
            data,
            inspection,
            report,
            debug_dir=debug_dir,
        )
        extraction = _extract_entities_from_heuristics(
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
        extraction,
        report,
        parser_path=parser_path,
        pkt_decode=pkt_decode,
        xml_parse=xml_parse,
        decode_result=decode_result,
    )
    report_payload = report.to_payload(
        source_file=input_path.name,
        inspection=inspection,
        decode_result=decode_result,
        extraction=extraction,
        normalized_topology=normalized_topology,
        pkt_decode=pkt_decode,
        xml_parse=xml_parse,
        parser_path=parser_path,
    )

    recovered_text = (
        pkt_decode.xml_content
        if pkt_decode and pkt_decode.success and pkt_decode.xml_content
        else (decode_result.recovered_text if decode_result else "")
    )

    return PipelineArtifacts(
        raw_dump=raw_dump,
        normalized_topology=normalized_topology,
        extraction_report=report_payload,
        recovered_text=recovered_text,
        exit_code=1 if report.has_fatal else 0,
    )
