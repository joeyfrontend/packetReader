from __future__ import annotations

from typing import Any

from . import __version__
from .models import DeviceCandidate, ExtractionResult, InterfaceCandidate
from .utils import current_timestamp


INTERFACE_CANONICAL_PREFIXES = {
    "fa": "FastEthernet",
    "fastethernet": "FastEthernet",
    "gi": "GigabitEthernet",
    "gigabitethernet": "GigabitEthernet",
    "se": "Serial",
    "serial": "Serial",
    "eth": "Ethernet",
    "ethernet": "Ethernet",
    "lo": "Loopback",
    "loopback": "Loopback",
    "vl": "Vlan",
    "vlan": "Vlan",
    "po": "Port-channel",
    "port-channel": "Port-channel",
}


def _canonical_interface_name(name: str | None) -> str:
    if not name:
        return ""
    compact = "".join(name.split())
    lowered = compact.lower()
    for prefix, canonical in sorted(
        INTERFACE_CANONICAL_PREFIXES.items(),
        key=lambda item: len(item[0]),
        reverse=True,
    ):
        if lowered.startswith(prefix):
            suffix = compact[len(prefix) :]
            return f"{canonical}{suffix}"
    return compact


def _merge_interface(existing: dict[str, Any], candidate: InterfaceCandidate) -> None:
    if candidate.name and not existing.get("name"):
        existing["name"] = candidate.name
    for field in ("ip", "mask", "mac", "status"):
        if getattr(candidate, field) and not existing.get(field):
            existing[field] = getattr(candidate, field)
    existing["confidence"] = max(existing.get("confidence", 0.0), candidate.confidence)
    existing.setdefault("raw", {"evidence": []})
    existing["raw"]["evidence"].append(candidate.raw)


def _merge_device(existing: dict[str, Any], candidate: DeviceCandidate) -> None:
    if candidate.name and not existing.get("name"):
        existing["name"] = candidate.name
    if candidate.device_type and not existing.get("type"):
        existing["type"] = candidate.device_type
    if candidate.subtype and not existing.get("subtype"):
        existing["subtype"] = candidate.subtype
    if candidate.model and not existing.get("model"):
        existing["model"] = candidate.model
    if candidate.config_text and (
        not existing.get("config_text") or len(candidate.config_text) > len(existing["config_text"])
    ):
        existing["config_text"] = candidate.config_text
    position = existing.setdefault("position", {"x": None, "y": None})
    if candidate.position.get("x") is not None and position.get("x") is None:
        position["x"] = candidate.position["x"]
    if candidate.position.get("y") is not None and position.get("y") is None:
        position["y"] = candidate.position["y"]
    existing["confidence"] = max(existing.get("confidence", 0.0), candidate.confidence)
    existing.setdefault("raw", {"evidence": []})
    existing["raw"]["evidence"].append(candidate.raw)

    interface_map = existing.setdefault("_interfaces", {})
    for interface in candidate.interfaces:
        key = (interface.name or f"interface_{len(interface_map) + 1}").lower()
        target = interface_map.setdefault(
            key,
            {
                "name": interface.name,
                "ip": None,
                "mask": None,
                "mac": None,
                "status": None,
                "confidence": 0.0,
                "raw": {"evidence": []},
            },
        )
        _merge_interface(target, interface)


def normalize_topology(
    source_file: str,
    extraction: ExtractionResult,
) -> dict[str, Any]:
    device_map: dict[str, dict[str, Any]] = {}
    insertion_order: list[str] = []

    for index, candidate in enumerate(extraction.devices, start=1):
        key = (candidate.name or f"anon_device_{index}").lower()
        if key not in device_map:
            insertion_order.append(key)
            device_map[key] = {
                "id": "",
                "name": candidate.name,
                "type": None,
                "subtype": None,
                "model": None,
                "position": {"x": None, "y": None},
                "interfaces": [],
                "_interfaces": {},
                "config_text": None,
                "raw": {"evidence": []},
                "confidence": 0.0,
            }
        _merge_device(device_map[key], candidate)

    def ensure_placeholder(name: str | None) -> None:
        if not name:
            return
        key = name.lower()
        if key in device_map:
            return
        insertion_order.append(key)
        device_map[key] = {
            "id": "",
            "name": name,
            "type": None,
            "subtype": None,
            "model": None,
            "position": {"x": None, "y": None},
            "interfaces": [],
            "_interfaces": {},
            "config_text": None,
            "raw": {"evidence": [{"placeholder_from_link": True}]},
            "confidence": 0.2,
        }

    for link in extraction.links:
        ensure_placeholder(link.from_device_name)
        ensure_placeholder(link.to_device_name)

    device_id_map: dict[str, str] = {}
    normalized_devices: list[dict[str, Any]] = []
    interface_counter = 0
    for device_counter, key in enumerate(insertion_order, start=1):
        device = device_map[key]
        device_id = f"dev_{device_counter}"
        device["id"] = device_id
        device_id_map[key] = device_id
        normalized_interfaces: list[dict[str, Any]] = []
        for interface in device.pop("_interfaces").values():
            interface_counter += 1
            interface["id"] = f"int_{interface_counter}"
            normalized_interfaces.append(interface)
        device["interfaces"] = normalized_interfaces
        normalized_devices.append(device)

    link_map: dict[tuple[str, str, str, str, str], dict[str, Any]] = {}
    for link in extraction.links:
        from_key = (link.from_device_name or "").lower()
        to_key = (link.to_device_name or "").lower()
        dedupe_key = (
            from_key,
            _canonical_interface_name(link.from_interface_name).lower(),
            to_key,
            _canonical_interface_name(link.to_interface_name).lower(),
        )
        entry = link_map.setdefault(
            dedupe_key,
            {
                "id": "",
                "from_device_id": device_id_map.get(from_key),
                "from_interface_name": link.from_interface_name,
                "to_device_id": device_id_map.get(to_key),
                "to_interface_name": link.to_interface_name,
                "link_type": link.link_type,
                "confidence": 0.0,
                "raw": {"evidence": []},
            },
        )
        if link.link_type and not entry.get("link_type"):
            entry["link_type"] = link.link_type
        if link.from_interface_name and (
            not entry.get("from_interface_name")
            or len(link.from_interface_name) > len(entry["from_interface_name"])
        ):
            entry["from_interface_name"] = link.from_interface_name
        if link.to_interface_name and (
            not entry.get("to_interface_name")
            or len(link.to_interface_name) > len(entry["to_interface_name"])
        ):
            entry["to_interface_name"] = link.to_interface_name
        entry["confidence"] = max(entry["confidence"], link.confidence)
        entry["raw"]["evidence"].append(link.raw)

    normalized_links: list[dict[str, Any]] = []
    for link_counter, entry in enumerate(link_map.values(), start=1):
        entry["id"] = f"link_{link_counter}"
        normalized_links.append(entry)

    normalized_notes = [
        {
            "text": note.text,
            "confidence": note.confidence,
            "raw": note.raw,
        }
        for note in extraction.notes
    ]

    return {
        "meta": {
            "source_file": source_file,
            "parser_version": __version__,
            "packet_tracer_version_hint": extraction.version_hints[0]
            if extraction.version_hints
            else None,
            "parsed_at": current_timestamp(),
            "warnings": extraction.warnings,
        },
        "devices": normalized_devices,
        "links": normalized_links,
        "notes": normalized_notes,
        "unmapped_blocks": [
            {
                "block_id": block.block_id,
                "source": block.source,
                "classification": block.classification,
                "preview": block.preview,
                "raw": block.raw,
            }
            for block in extraction.unmapped_blocks
        ],
    }
