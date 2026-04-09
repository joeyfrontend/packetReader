from __future__ import annotations

import ipaddress
from typing import Any

from .models import DecodedPktResult, ExtractionResult, InspectionResult, XmlParseResult
from .oracle import OracleInterface, OracleTopology, get_oracle_for_file


def _normalize_interface_name(name: str | None) -> str | None:
    if not name:
        return None
    normalized = name.lower().replace(" ", "")
    for prefix, alias in (
        ("gigabitethernet", "gi"),
        ("fastethernet", "fa"),
        ("serial", "se"),
        ("ethernet", "eth"),
    ):
        if normalized.startswith(prefix):
            return alias + normalized[len(prefix) :]
    return normalized


def _subnet_from_ip_mask(ip: str | None, mask: str | None) -> str | None:
    if not ip or not mask:
        return None
    try:
        return str(ipaddress.IPv4Network(f"{ip}/{mask}", strict=False))
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return None


def _device_names_from_normalized(normalized_topology: dict[str, Any]) -> list[str]:
    return [device.get("name") for device in normalized_topology.get("devices", []) if device.get("name")]


def _device_index_from_normalized(normalized_topology: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        device["name"]: device
        for device in normalized_topology.get("devices", [])
        if device.get("name")
    }


def _link_names_from_normalized(normalized_topology: dict[str, Any]) -> list[tuple[str, str]]:
    device_by_id = {
        device.get("id"): device.get("name")
        for device in normalized_topology.get("devices", [])
        if device.get("id") and device.get("name")
    }
    links: list[tuple[str, str]] = []
    for link in normalized_topology.get("links", []):
        left = device_by_id.get(link.get("from_device_id"))
        right = device_by_id.get(link.get("to_device_id"))
        if left and right:
            links.append(tuple(sorted((left, right))))
    return links


def _ip_entries_from_normalized(normalized_topology: dict[str, Any]) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for device in normalized_topology.get("devices", []):
        name = device.get("name")
        if not name:
            continue
        for interface in device.get("interfaces", []):
            ip = interface.get("ip")
            if ip:
                entries.append((name, ip))
    return entries


def _interface_entries_from_normalized(normalized_topology: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for device in normalized_topology.get("devices", []):
        device_name = device.get("name")
        if not device_name:
            continue
        for interface in device.get("interfaces", []):
            entries.append(
                {
                    "device": device_name,
                    "name": interface.get("name"),
                    "normalized_name": _normalize_interface_name(interface.get("name")),
                    "ip": interface.get("ip"),
                    "mask": interface.get("mask"),
                    "subnet": _subnet_from_ip_mask(interface.get("ip"), interface.get("mask")),
                }
            )
    return entries


def _subnet_entries_from_normalized(normalized_topology: dict[str, Any]) -> list[tuple[str, str]]:
    return [
        (entry["device"], entry["subnet"])
        for entry in _interface_entries_from_normalized(normalized_topology)
        if entry["subnet"]
    ]


def _device_index_from_extraction(extraction: ExtractionResult | None) -> dict[str, Any]:
    if extraction is None:
        return {}
    index: dict[str, Any] = {}
    for device in extraction.devices:
        if device.name and device.name not in index:
            index[device.name] = device
    return index


def _link_set_from_extraction(extraction: ExtractionResult | None) -> set[tuple[str, str]]:
    if extraction is None:
        return set()
    links: set[tuple[str, str]] = set()
    for link in extraction.links:
        if link.from_device_name and link.to_device_name:
            links.add(tuple(sorted((link.from_device_name, link.to_device_name))))
    return links


def _ip_set_from_extraction(extraction: ExtractionResult | None) -> set[tuple[str, str]]:
    if extraction is None:
        return set()
    entries: set[tuple[str, str]] = set()
    for device in extraction.devices:
        if not device.name:
            continue
        for interface in device.interfaces:
            if interface.ip:
                entries.add((device.name, interface.ip))
    return entries


def _interface_entries_from_extraction(extraction: ExtractionResult | None) -> list[dict[str, Any]]:
    if extraction is None:
        return []
    entries: list[dict[str, Any]] = []
    for device in extraction.devices:
        if not device.name:
            continue
        for interface in device.interfaces:
            entries.append(
                {
                    "device": device.name,
                    "name": interface.name,
                    "normalized_name": _normalize_interface_name(interface.name),
                    "ip": interface.ip,
                    "mask": interface.mask,
                    "subnet": _subnet_from_ip_mask(interface.ip, interface.mask),
                }
            )
    return entries


def _subnet_entries_from_extraction(extraction: ExtractionResult | None) -> set[tuple[str, str]]:
    return {
        (entry["device"], entry["subnet"])
        for entry in _interface_entries_from_extraction(extraction)
        if entry["subnet"]
    }


def _infer_failure_stage(
    *,
    pkt_decode: DecodedPktResult | None,
    xml_parse: XmlParseResult | None,
    extraction_has_entity: bool = False,
    extraction_has_field: bool = False,
    normalized_has_entity: bool = False,
    normalized_has_field: bool = False,
) -> str:
    if extraction_has_field and not normalized_has_field:
        return "normalization stage"
    if extraction_has_entity and not normalized_has_entity:
        return "normalization stage"
    if pkt_decode is None or not pkt_decode.success:
        return "decode stage"
    if xml_parse is None or not xml_parse.success:
        return "XML parse stage"
    return "XML parse stage"


def _build_empty_validation(source_file: str) -> dict[str, Any]:
    return {
        "oracle_validation": {
            "oracle_available": False,
            "source_file": source_file,
            "oracle_source": "internal_manual_oracle",
            "notes": ["No oracle data registered for this sample."],
        },
        "expected_vs_found": {},
        "missing_expected_entities": {"devices": [], "interfaces": [], "links": []},
        "unexpected_extracted_entities": {"devices": [], "interfaces": [], "links": [], "ips": []},
        "missing_expected_fields": [],
    }


def _oracle_exact_ip_entries(oracle: OracleTopology) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for device in oracle.devices:
        entries.extend((device.name, ip) for ip in device.ips)
        entries.extend((device.name, interface.ip) for interface in device.interfaces if interface.ip)
    return entries


def _oracle_exact_ip_map(oracle: OracleTopology) -> dict[str, set[str]]:
    entries: dict[str, set[str]] = {}
    for device_name, ip in _oracle_exact_ip_entries(oracle):
        entries.setdefault(device_name, set()).add(ip)
    return entries


def _oracle_interface_entries(oracle: OracleTopology) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for device in oracle.devices:
        for interface in device.interfaces:
            entries.append(
                {
                    "device": device.name,
                    "name": interface.name,
                    "normalized_name": _normalize_interface_name(interface.name),
                    "ip": interface.ip,
                    "mask": interface.mask,
                    "subnet": interface.subnet,
                }
            )
    return entries


def _oracle_subnet_entries(oracle: OracleTopology) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for device in oracle.devices:
        for subnet in device.subnets:
            entry = (device.name, subnet)
            if entry not in seen:
                seen.add(entry)
                entries.append(entry)
        for interface in device.interfaces:
            if not interface.subnet:
                continue
            entry = (device.name, interface.subnet)
            if entry not in seen:
                seen.add(entry)
                entries.append(entry)
    return entries


def _match_interface_entry(
    *,
    expected: OracleInterface,
    device_name: str,
    candidates: list[dict[str, Any]],
) -> dict[str, Any] | None:
    device_candidates = [candidate for candidate in candidates if candidate["device"] == device_name]
    if expected.name:
        target_name = _normalize_interface_name(expected.name)
        for candidate in device_candidates:
            if candidate["normalized_name"] == target_name:
                return candidate
    if expected.ip:
        for candidate in device_candidates:
            if candidate["ip"] == expected.ip:
                return candidate
    if expected.subnet:
        for candidate in device_candidates:
            if candidate["subnet"] == expected.subnet:
                return candidate
    return None


def _build_oracle_state_delta(
    *,
    oracle: OracleTopology,
    normalized_topology: dict[str, Any],
) -> dict[str, Any] | None:
    if not oracle.baseline_source_file:
        return None

    baseline = get_oracle_for_file(oracle.baseline_source_file)
    if baseline is None:
        return {
            "baseline_source_file": oracle.baseline_source_file,
            "notes": ["Baseline oracle was not available for state comparison."],
        }

    baseline_device_names = {device.name for device in baseline.devices}
    current_device_names = {device.name for device in oracle.devices}
    baseline_links = {tuple(sorted((link.left, link.right))) for link in baseline.links}
    current_links = {tuple(sorted((link.left, link.right))) for link in oracle.links}
    baseline_ips = set(_oracle_exact_ip_entries(baseline))
    current_ips = set(_oracle_exact_ip_entries(oracle))
    baseline_ip_map = _oracle_exact_ip_map(baseline)
    current_ip_map = _oracle_exact_ip_map(oracle)
    baseline_interfaces = {
        (entry["device"], entry["normalized_name"] or entry["name"])
        for entry in _oracle_interface_entries(baseline)
    }
    current_interfaces = {
        (entry["device"], entry["normalized_name"] or entry["name"])
        for entry in _oracle_interface_entries(oracle)
    }
    baseline_subnets = set(_oracle_subnet_entries(baseline))
    current_subnets = set(_oracle_subnet_entries(oracle))

    normalized_devices = set(_device_names_from_normalized(normalized_topology))
    normalized_links = set(_link_names_from_normalized(normalized_topology))
    normalized_ips = set(_ip_entries_from_normalized(normalized_topology))
    normalized_interfaces = {
        (entry["device"], entry["normalized_name"] or entry["name"])
        for entry in _interface_entries_from_normalized(normalized_topology)
    }
    normalized_subnets = set(_subnet_entries_from_normalized(normalized_topology))

    added_ips = []
    removed_ips = []
    for device_name, current_values in current_ip_map.items():
        baseline_values = baseline_ip_map.get(device_name, set())
        added_ips.extend(
            {"device": device_name, "ip": ip}
            for ip in sorted(current_values - baseline_values)
        )
        removed_ips.extend(
            {"device": device_name, "ip": ip}
            for ip in sorted(baseline_values - current_values)
        )

    return {
        "baseline_source_file": baseline.source_file,
        "expected_changes": {
            "added_devices": sorted(current_device_names - baseline_device_names),
            "removed_devices": sorted(baseline_device_names - current_device_names),
            "added_links": [list(link) for link in sorted(current_links - baseline_links)],
            "removed_links": [list(link) for link in sorted(baseline_links - current_links)],
            "added_interfaces": [{"device": device, "name": name} for device, name in sorted(current_interfaces - baseline_interfaces)],
            "removed_interfaces": [{"device": device, "name": name} for device, name in sorted(baseline_interfaces - current_interfaces)],
            "added_ips": added_ips,
            "removed_ips": removed_ips,
            "added_subnets": [{"device": device, "subnet": subnet} for device, subnet in sorted(current_subnets - baseline_subnets)],
            "removed_subnets": [{"device": device, "subnet": subnet} for device, subnet in sorted(baseline_subnets - current_subnets)],
        },
        "observed_extracted_delta_vs_baseline_oracle": {
            "added_devices": sorted(normalized_devices - baseline_device_names),
            "removed_devices": sorted(baseline_device_names - normalized_devices),
            "added_links": [list(link) for link in sorted(normalized_links - baseline_links)],
            "removed_links": [list(link) for link in sorted(baseline_links - normalized_links)],
            "added_interfaces": [{"device": device, "name": name} for device, name in sorted(normalized_interfaces - baseline_interfaces)],
            "removed_interfaces": [{"device": device, "name": name} for device, name in sorted(baseline_interfaces - normalized_interfaces)],
            "added_ips": [{"device": device, "ip": ip} for device, ip in sorted(normalized_ips - baseline_ips)],
            "removed_ips": [{"device": device, "ip": ip} for device, ip in sorted(baseline_ips - normalized_ips)],
            "added_subnets": [{"device": device, "subnet": subnet} for device, subnet in sorted(normalized_subnets - baseline_subnets)],
            "removed_subnets": [{"device": device, "subnet": subnet} for device, subnet in sorted(baseline_subnets - normalized_subnets)],
        },
    }


def build_oracle_validation(
    *,
    source_file: str,
    normalized_topology: dict[str, Any],
    extraction: ExtractionResult | None,
    pkt_decode: DecodedPktResult | None,
    xml_parse: XmlParseResult | None,
    inspection: InspectionResult | None = None,
) -> dict[str, Any]:
    oracle = get_oracle_for_file(source_file)
    if oracle is None:
        return _build_empty_validation(source_file)

    normalized_devices = _device_index_from_normalized(normalized_topology)
    normalized_links = set(_link_names_from_normalized(normalized_topology))
    normalized_ips = set(_ip_entries_from_normalized(normalized_topology))
    normalized_interfaces = _interface_entries_from_normalized(normalized_topology)
    normalized_subnets = set(_subnet_entries_from_normalized(normalized_topology))

    extraction_devices = _device_index_from_extraction(extraction)
    extraction_links = _link_set_from_extraction(extraction)
    extraction_ips = _ip_set_from_extraction(extraction)
    extraction_interfaces = _interface_entries_from_extraction(extraction)
    extraction_subnets = _subnet_entries_from_extraction(extraction)

    expected_device_names = [device.name for device in oracle.devices]
    found_device_names = sorted(normalized_devices.keys())
    expected_links = [tuple(sorted((link.left, link.right))) for link in oracle.links]
    found_links = sorted(normalized_links)
    expected_ips = _oracle_exact_ip_entries(oracle)
    found_ips = sorted(normalized_ips)
    expected_interfaces = _oracle_interface_entries(oracle)
    found_interfaces = [
        {
            "device": entry["device"],
            "name": entry["name"],
            "ip": entry["ip"],
            "mask": entry["mask"],
            "subnet": entry["subnet"],
        }
        for entry in normalized_interfaces
    ]
    expected_subnets = _oracle_subnet_entries(oracle)
    found_subnets = sorted(normalized_subnets)

    missing_devices: list[dict[str, Any]] = []
    missing_interfaces: list[dict[str, Any]] = []
    missing_links: list[dict[str, Any]] = []
    missing_fields: list[dict[str, Any]] = []

    for device in oracle.devices:
        normalized_device = normalized_devices.get(device.name)
        extraction_device = extraction_devices.get(device.name)
        if normalized_device is None:
            missing_stage = _infer_failure_stage(
                pkt_decode=pkt_decode,
                xml_parse=xml_parse,
                extraction_has_entity=extraction_device is not None,
                normalized_has_entity=False,
            )
            missing_devices.append(
                {
                    "name": device.name,
                    "expected_type": device.device_type,
                    "expected_model": device.model,
                    "likely_failure_stage": missing_stage,
                }
            )
            missing_fields.append(
                {
                    "entity": device.name,
                    "field": "type",
                    "expected": device.device_type,
                    "found": None,
                    "likely_failure_stage": missing_stage,
                }
            )
            missing_fields.append(
                {
                    "entity": device.name,
                    "field": "model",
                    "expected": device.model,
                    "found": None,
                    "likely_failure_stage": missing_stage,
                }
            )
            for ip in device.ips:
                missing_fields.append(
                    {
                        "entity": device.name,
                        "field": "ip",
                        "expected": ip,
                        "found": None,
                        "likely_failure_stage": missing_stage,
                    }
                )
            for subnet in device.subnets:
                missing_fields.append(
                    {
                        "entity": device.name,
                        "field": "subnet",
                        "expected": subnet,
                        "found": None,
                        "likely_failure_stage": missing_stage,
                    }
                )
            for interface in device.interfaces:
                interface_name = interface.name or interface.ip or interface.subnet or "unknown"
                missing_interfaces.append(
                    {
                        "device": device.name,
                        "name": interface.name,
                        "expected_ip": interface.ip,
                        "expected_subnet": interface.subnet,
                        "likely_failure_stage": missing_stage,
                    }
                )
                missing_fields.append(
                    {
                        "entity": f"{device.name}:{interface_name}",
                        "field": "interface",
                        "expected": interface.name or interface.ip or interface.subnet,
                        "found": None,
                        "likely_failure_stage": missing_stage,
                    }
                )
                if interface.ip:
                    missing_fields.append(
                        {
                            "entity": f"{device.name}:{interface_name}",
                            "field": "ip",
                            "expected": interface.ip,
                            "found": None,
                            "likely_failure_stage": missing_stage,
                        }
                    )
                if interface.subnet:
                    missing_fields.append(
                        {
                            "entity": f"{device.name}:{interface_name}",
                            "field": "subnet",
                            "expected": interface.subnet,
                            "found": None,
                            "likely_failure_stage": missing_stage,
                        }
                    )
            continue

        found_type = normalized_device.get("type")
        found_model = normalized_device.get("model")
        extraction_has_type = bool(extraction_device and extraction_device.device_type)
        extraction_has_model = bool(extraction_device and extraction_device.model)
        if found_type != device.device_type:
            missing_fields.append(
                {
                    "entity": device.name,
                    "field": "type",
                    "expected": device.device_type,
                    "found": found_type,
                    "likely_failure_stage": _infer_failure_stage(
                        pkt_decode=pkt_decode,
                        xml_parse=xml_parse,
                        extraction_has_entity=extraction_device is not None,
                        extraction_has_field=extraction_has_type,
                        normalized_has_entity=True,
                        normalized_has_field=bool(found_type),
                    ),
                }
            )
        if found_model != device.model:
            missing_fields.append(
                {
                    "entity": device.name,
                    "field": "model",
                    "expected": device.model,
                    "found": found_model,
                    "likely_failure_stage": _infer_failure_stage(
                        pkt_decode=pkt_decode,
                        xml_parse=xml_parse,
                        extraction_has_entity=extraction_device is not None,
                        extraction_has_field=extraction_has_model,
                        normalized_has_entity=True,
                        normalized_has_field=bool(found_model),
                    ),
                }
            )

        found_ip_values = {
            interface.get("ip")
            for interface in normalized_device.get("interfaces", [])
            if interface.get("ip")
        }
        extraction_ip_values = {
            interface.ip
            for interface in (extraction_device.interfaces if extraction_device else [])
            if interface.ip
        }
        for ip in device.ips:
            if ip not in found_ip_values:
                missing_fields.append(
                    {
                        "entity": device.name,
                        "field": "ip",
                        "expected": ip,
                        "found": sorted(found_ip_values) or None,
                        "likely_failure_stage": _infer_failure_stage(
                            pkt_decode=pkt_decode,
                            xml_parse=xml_parse,
                            extraction_has_entity=extraction_device is not None,
                            extraction_has_field=ip in extraction_ip_values,
                            normalized_has_entity=True,
                            normalized_has_field=ip in found_ip_values,
                        ),
                    }
                )

        found_subnet_values = {
            subnet
            for subnet in (
                _subnet_from_ip_mask(interface.get("ip"), interface.get("mask"))
                for interface in normalized_device.get("interfaces", [])
            )
            if subnet
        }
        extraction_subnet_values = {
            subnet
            for subnet in (
                _subnet_from_ip_mask(interface.ip, interface.mask)
                for interface in (extraction_device.interfaces if extraction_device else [])
            )
            if subnet
        }
        for subnet in device.subnets:
            if subnet not in found_subnet_values:
                missing_fields.append(
                    {
                        "entity": device.name,
                        "field": "subnet",
                        "expected": subnet,
                        "found": sorted(found_subnet_values) or None,
                        "likely_failure_stage": _infer_failure_stage(
                            pkt_decode=pkt_decode,
                            xml_parse=xml_parse,
                            extraction_has_entity=extraction_device is not None,
                            extraction_has_field=subnet in extraction_subnet_values,
                            normalized_has_entity=True,
                            normalized_has_field=subnet in found_subnet_values,
                        ),
                    }
                )

        for expected_interface in device.interfaces:
            normalized_interface = _match_interface_entry(
                expected=expected_interface,
                device_name=device.name,
                candidates=normalized_interfaces,
            )
            extraction_interface = _match_interface_entry(
                expected=expected_interface,
                device_name=device.name,
                candidates=extraction_interfaces,
            )
            interface_name = expected_interface.name or expected_interface.ip or expected_interface.subnet or "unknown"
            if normalized_interface is None:
                missing_stage = _infer_failure_stage(
                    pkt_decode=pkt_decode,
                    xml_parse=xml_parse,
                    extraction_has_entity=extraction_interface is not None,
                    normalized_has_entity=False,
                )
                missing_interfaces.append(
                    {
                        "device": device.name,
                        "name": expected_interface.name,
                        "expected_ip": expected_interface.ip,
                        "expected_subnet": expected_interface.subnet,
                        "likely_failure_stage": missing_stage,
                    }
                )
                missing_fields.append(
                    {
                        "entity": f"{device.name}:{interface_name}",
                        "field": "interface",
                        "expected": expected_interface.name or expected_interface.ip or expected_interface.subnet,
                        "found": None,
                        "likely_failure_stage": missing_stage,
                    }
                )
                if expected_interface.ip:
                    missing_fields.append(
                        {
                            "entity": f"{device.name}:{interface_name}",
                            "field": "ip",
                            "expected": expected_interface.ip,
                            "found": None,
                            "likely_failure_stage": missing_stage,
                        }
                    )
                if expected_interface.subnet:
                    missing_fields.append(
                        {
                            "entity": f"{device.name}:{interface_name}",
                            "field": "subnet",
                            "expected": expected_interface.subnet,
                            "found": None,
                            "likely_failure_stage": missing_stage,
                        }
                    )
                continue

            if expected_interface.ip and normalized_interface["ip"] != expected_interface.ip:
                missing_fields.append(
                    {
                        "entity": f"{device.name}:{interface_name}",
                        "field": "ip",
                        "expected": expected_interface.ip,
                        "found": normalized_interface["ip"],
                        "likely_failure_stage": _infer_failure_stage(
                            pkt_decode=pkt_decode,
                            xml_parse=xml_parse,
                            extraction_has_entity=extraction_interface is not None,
                            extraction_has_field=bool(extraction_interface and extraction_interface["ip"]),
                            normalized_has_entity=True,
                            normalized_has_field=bool(normalized_interface["ip"]),
                        ),
                    }
                )
            if expected_interface.subnet and normalized_interface["subnet"] != expected_interface.subnet:
                missing_fields.append(
                    {
                        "entity": f"{device.name}:{interface_name}",
                        "field": "subnet",
                        "expected": expected_interface.subnet,
                        "found": normalized_interface["subnet"],
                        "likely_failure_stage": _infer_failure_stage(
                            pkt_decode=pkt_decode,
                            xml_parse=xml_parse,
                            extraction_has_entity=extraction_interface is not None,
                            extraction_has_field=bool(extraction_interface and extraction_interface["subnet"]),
                            normalized_has_entity=True,
                            normalized_has_field=bool(normalized_interface["subnet"]),
                        ),
                    }
                )

    for link in expected_links:
        if link not in normalized_links:
            missing_links.append(
                {
                    "endpoints": list(link),
                    "likely_failure_stage": _infer_failure_stage(
                        pkt_decode=pkt_decode,
                        xml_parse=xml_parse,
                        extraction_has_entity=link in extraction_links,
                        normalized_has_entity=False,
                    ),
                }
            )

    expected_link_set = set(expected_links)
    expected_ip_set = set(expected_ips)
    expected_interface_key_set = {
        (entry["device"], entry["normalized_name"] or entry["name"])
        for entry in expected_interfaces
    }

    unexpected_devices = [
        {
            "name": name,
            "found_type": normalized_devices[name].get("type"),
            "found_model": normalized_devices[name].get("model"),
        }
        for name in found_device_names
        if name not in expected_device_names
    ]
    unexpected_interfaces = [
        {
            "device": entry["device"],
            "name": entry["name"],
            "ip": entry["ip"],
            "mask": entry["mask"],
            "subnet": entry["subnet"],
        }
        for entry in normalized_interfaces
        if (entry["device"], entry["normalized_name"] or entry["name"]) not in expected_interface_key_set
    ]
    unexpected_links = [
        {"endpoints": list(link)}
        for link in sorted(normalized_links)
        if link not in expected_link_set
    ]
    unexpected_ips = [
        {"device": device_name, "ip": ip}
        for device_name, ip in sorted(normalized_ips)
        if (device_name, ip) not in expected_ip_set
    ]

    device_type_model_rows = []
    for device in oracle.devices:
        found = normalized_devices.get(device.name)
        device_type_model_rows.append(
            {
                "device": device.name,
                "expected_type": device.device_type,
                "found_type": found.get("type") if found else None,
                "expected_model": device.model,
                "found_model": found.get("model") if found else None,
            }
        )

    validation = {
        "oracle_validation": {
            "oracle_available": True,
            "source_file": oracle.source_file,
            "oracle_source": "internal_manual_oracle",
            "packet_tracer_version": oracle.packet_tracer_version,
            "saved_on_os": oracle.saved_on_os,
            "baseline_source_file": oracle.baseline_source_file,
            "vlan_context": oracle.vlan_context,
            "notes": list(oracle.notes)
            + [
                "Oracle data is for validation only and is never injected into extracted topology output.",
                "Interface checks only cover explicitly known oracle interfaces and never assume unlabeled Packet Tracer interface numbers.",
            ],
        },
        "expected_vs_found": {
            "devices": {
                "expected_count": len(expected_device_names),
                "found_count": len(found_device_names),
                "expected_names": expected_device_names,
                "found_names": found_device_names,
            },
            "interfaces": {
                "expected_count": len(expected_interfaces),
                "found_count": len(found_interfaces),
                "expected": [
                    {
                        "device": entry["device"],
                        "name": entry["name"],
                        "ip": entry["ip"],
                        "mask": entry["mask"],
                        "subnet": entry["subnet"],
                    }
                    for entry in expected_interfaces
                ],
                "found": found_interfaces,
            },
            "links": {
                "expected_count": len(expected_links),
                "found_count": len(found_links),
                "expected": [list(link) for link in expected_links],
                "found": [list(link) for link in found_links],
            },
            "ips": {
                "expected_count": len(expected_ips),
                "found_count": len(found_ips),
                "expected": [{"device": device_name, "ip": ip} for device_name, ip in expected_ips],
                "found": [{"device": device_name, "ip": ip} for device_name, ip in found_ips],
            },
            "subnets": {
                "expected_count": len(expected_subnets),
                "found_count": len(found_subnets),
                "expected": [{"device": device_name, "subnet": subnet} for device_name, subnet in expected_subnets],
                "found": [{"device": device_name, "subnet": subnet} for device_name, subnet in found_subnets],
            },
            "device_types_models": device_type_model_rows,
        },
        "missing_expected_entities": {
            "devices": missing_devices,
            "interfaces": missing_interfaces,
            "links": missing_links,
        },
        "unexpected_extracted_entities": {
            "devices": unexpected_devices,
            "interfaces": unexpected_interfaces,
            "links": unexpected_links,
            "ips": unexpected_ips,
        },
        "missing_expected_fields": missing_fields,
    }

    state_delta = _build_oracle_state_delta(oracle=oracle, normalized_topology=normalized_topology)
    if state_delta is not None:
        validation["oracle_state_delta"] = state_delta

    if inspection is not None:
        validation["oracle_validation"]["inspection_context"] = {
            "entropy": inspection.entropy,
            "printable_ratio": inspection.printable_ratio,
            "candidate_offsets": inspection.candidate_offsets,
        }

    return validation
