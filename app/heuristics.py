from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

from .models import DeviceCandidate, InterfaceCandidate, LinkCandidate, NoteCandidate
from .utils import normalize_key, text_preview


IP_PATTERN = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b"
)
MAC_PATTERN = re.compile(
    r"\b[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}\b|\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b"
)
INTERFACE_PATTERN = re.compile(
    r"\b(?:FastEthernet|GigabitEthernet|Serial|Ethernet|Loopback|Vlan|Port-channel|Fa|Gi|Se|Eth|Lo|Vl|Po)\s*\d+(?:/\d+){0,3}\b",
    re.IGNORECASE,
)
HOSTNAME_PATTERN = re.compile(
    r"\b(?:R|SW|S|PC|Server|AP|RTR|Router|Switch)\d+\b",
    re.IGNORECASE,
)
CONFIG_HOSTNAME_PATTERN = re.compile(r"(?mi)^hostname\s+([^\s]+)")
CONFIG_INTERFACE_PATTERN = re.compile(r"(?mi)^interface\s+([A-Za-z][\w/-]+)\s*$")
IP_ADDRESS_LINE_PATTERN = re.compile(r"(?mi)^\s*ip address\s+(\S+)\s+(\S+)")
LINK_TEXT_PATTERN = re.compile(
    r"(?P<from_device>[A-Za-z][\w-]*)\s+(?P<from_interface>(?:FastEthernet|GigabitEthernet|Serial|Fa|Gi|Se)\S+)\s*(?:<->|->|--)\s*(?P<to_device>[A-Za-z][\w-]*)\s+(?P<to_interface>(?:FastEthernet|GigabitEthernet|Serial|Fa|Gi|Se)\S+)",
    re.IGNORECASE,
)
NOTE_LINE_PATTERN = re.compile(r"(?mi)^(?:note|label)\s*:\s*(.+)$")
XML_BLOCK_PATTERN = re.compile(
    r"(?s)(<\?xml[^>]*\?>\s*)?(<(?P<tag>[A-Za-z_][\w:.-]*)(?:\s[^<>]*)?>.*?</(?P=tag)>)"
)

CONFIG_MARKERS = [
    "hostname",
    "interface",
    "ip address",
    "router ospf",
    "network",
    "vlan",
    "switchport",
    "default-gateway",
]


def classify_text_fragment(text: str) -> tuple[str, float, list[str]]:
    stripped = text.strip()
    lowered = stripped.lower()
    markers = [marker for marker in CONFIG_MARKERS if marker in lowered]

    if stripped.startswith("<") and ">" in stripped:
        return "xml", 0.95, markers
    if len(markers) >= 2 or CONFIG_HOSTNAME_PATTERN.search(stripped):
        return "config", min(0.98, 0.55 + (0.1 * len(markers))), markers
    if (
        IP_PATTERN.search(stripped)
        or INTERFACE_PATTERN.search(stripped)
        or HOSTNAME_PATTERN.search(stripped)
    ):
        return "structured_text", 0.6, markers
    return "text", 0.3, markers


def extract_observables(text: str) -> dict[str, list[str]]:
    lowered = text.lower()
    return {
        "ip_addresses": sorted(set(IP_PATTERN.findall(text))),
        "interfaces": sorted(
            set(match.group(0).strip() for match in INTERFACE_PATTERN.finditer(text))
        ),
        "hostnames": sorted(set(match.group(0).strip() for match in HOSTNAME_PATTERN.finditer(text))),
        "mac_addresses": sorted(
            set(match.group(0).strip() for match in MAC_PATTERN.finditer(text))
        ),
        "config_markers": [marker for marker in CONFIG_MARKERS if marker in lowered],
    }


def infer_device_type(
    name: str | None,
    evidence_text: str = "",
    attrs: dict[str, Any] | None = None,
) -> str | None:
    attrs = attrs or {}
    explicit = attrs.get("type") or attrs.get("devicetype") or attrs.get("class")
    if explicit:
        return str(explicit).lower()

    lowered = evidence_text.lower()
    if "switchport" in lowered or "spanning-tree" in lowered or "vlan" in lowered:
        return "switch"
    if "router ospf" in lowered or "router eigrp" in lowered or "router bgp" in lowered:
        return "router"
    if name:
        upper = name.upper()
        if upper.startswith("SW") or upper.startswith("S"):
            return "switch"
        if upper.startswith("R"):
            return "router"
        if upper.startswith("PC"):
            return "pc"
        if upper.startswith("SERVER"):
            return "server"
        if upper.startswith("AP"):
            return "access-point"
    return None


def extract_interfaces_from_config(config_text: str, source_fragment: str) -> list[InterfaceCandidate]:
    interfaces: list[InterfaceCandidate] = []
    matches = list(CONFIG_INTERFACE_PATTERN.finditer(config_text))
    for index, match in enumerate(matches):
        name = match.group(1).strip()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(config_text)
        block = config_text[match.start() : end]
        ip_match = IP_ADDRESS_LINE_PATTERN.search(block)
        mac_match = MAC_PATTERN.search(block)
        status = None
        if re.search(r"(?mi)^\s*shutdown\s*$", block):
            status = "shutdown"
        elif re.search(r"(?mi)^\s*no shutdown\s*$", block):
            status = "up"
        interfaces.append(
            InterfaceCandidate(
                name=name,
                ip=ip_match.group(1) if ip_match else None,
                mask=ip_match.group(2) if ip_match else None,
                mac=mac_match.group(0) if mac_match else None,
                status=status,
                raw={
                    "source_fragment": source_fragment,
                    "config_block": block.strip(),
                },
                confidence=0.88 if ip_match else 0.72,
            )
        )
    return interfaces


def extract_devices_from_config(config_text: str, source_fragment: str) -> list[DeviceCandidate]:
    hostnames = list(CONFIG_HOSTNAME_PATTERN.finditer(config_text))
    if not hostnames:
        return []

    devices: list[DeviceCandidate] = []
    for index, match in enumerate(hostnames):
        name = match.group(1).strip()
        end = hostnames[index + 1].start() if index + 1 < len(hostnames) else len(config_text)
        block = config_text[match.start() : end].strip()
        interfaces = extract_interfaces_from_config(block, source_fragment)
        devices.append(
            DeviceCandidate(
                name=name,
                device_type=infer_device_type(name, block),
                interfaces=interfaces,
                config_text=block,
                raw={
                    "source_fragment": source_fragment,
                    "extraction": "config",
                    "markers": [marker for marker in CONFIG_MARKERS if marker in block.lower()],
                },
                confidence=0.92,
                source="config",
            )
        )
    return devices


def find_embedded_xml_blocks(text: str) -> list[str]:
    matches: list[str] = []
    for match in XML_BLOCK_PATTERN.finditer(text):
        xml_text = "".join(part for part in match.groups(default="")[:2] if part)
        xml_text = xml_text.strip()
        if xml_text:
            matches.append(xml_text)
    return matches


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1].lower()


def _attrs(element: ET.Element) -> dict[str, str]:
    return {_local_name(key): value for key, value in element.attrib.items()}


def _get_attr(attrs: dict[str, str], *names: str) -> str | None:
    for name in names:
        if name in attrs:
            return attrs[name]
    normalized = {normalize_key(key): value for key, value in attrs.items()}
    for name in names:
        compact = normalize_key(name)
        if compact in normalized:
            return normalized[compact]
    return None


def _coerce_number(value: str | None) -> float | int | None:
    if value is None or value == "":
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    if number.is_integer():
        return int(number)
    return number


def extract_xml_entities(
    xml_text: str,
    source_fragment: str,
) -> tuple[list[DeviceCandidate], list[LinkCandidate], list[NoteCandidate], list[str], list[str]]:
    devices: list[DeviceCandidate] = []
    links: list[LinkCandidate] = []
    notes: list[NoteCandidate] = []
    version_hints: list[str] = []
    warnings: list[str] = []

    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        warnings.append(f"XML parse error in {source_fragment}: {exc}")
        return devices, links, notes, version_hints, warnings

    root_attrs = _attrs(root)
    version_hint = _get_attr(root_attrs, "packetTracerVersion", "version")
    if version_hint:
        version_hints.append(version_hint)

    device_map: dict[str, DeviceCandidate] = {}

    def walk(element: ET.Element, current_device: DeviceCandidate | None = None) -> None:
        tag = _local_name(element.tag)
        attrs = _attrs(element)
        text_value = (element.text or "").strip()

        device_like = tag in {
            "device",
            "node",
            "router",
            "switch",
            "pc",
            "server",
            "host",
        } or (
            _get_attr(attrs, "name")
            and (_get_attr(attrs, "type", "model", "class") or _get_attr(attrs, "x", "y"))
        )

        if device_like:
            name = _get_attr(attrs, "name", "hostname", "label") or text_value or None
            candidate = DeviceCandidate(
                name=name,
                device_type=infer_device_type(name, text_value, attrs),
                subtype=tag if tag not in {"device", "node"} else None,
                model=_get_attr(attrs, "model", "sku"),
                position={
                    "x": _coerce_number(_get_attr(attrs, "x", "posx")),
                    "y": _coerce_number(_get_attr(attrs, "y", "posy")),
                },
                raw={
                    "source_fragment": source_fragment,
                    "tag": tag,
                    "attrs": attrs,
                },
                confidence=0.86,
                source="xml",
            )
            if name:
                existing = device_map.get(name)
                if existing:
                    if candidate.position["x"] is not None:
                        existing.position["x"] = candidate.position["x"]
                    if candidate.position["y"] is not None:
                        existing.position["y"] = candidate.position["y"]
                    if candidate.device_type and not existing.device_type:
                        existing.device_type = candidate.device_type
                    current_device = existing
                else:
                    device_map[name] = candidate
                    devices.append(candidate)
                    current_device = candidate
            else:
                devices.append(candidate)
                current_device = candidate

        interface_like = tag in {"interface", "port", "adapter", "nic"} or (
            current_device is not None
            and _get_attr(attrs, "name")
            and INTERFACE_PATTERN.search(_get_attr(attrs, "name") or "")
        )
        if interface_like and current_device is not None:
            interface = InterfaceCandidate(
                name=_get_attr(attrs, "name", "port", "label"),
                ip=_get_attr(attrs, "ip", "ipaddress"),
                mask=_get_attr(attrs, "mask", "subnetmask"),
                mac=_get_attr(attrs, "mac", "macaddress"),
                status=_get_attr(attrs, "status", "state"),
                raw={
                    "source_fragment": source_fragment,
                    "tag": tag,
                    "attrs": attrs,
                },
                confidence=0.84,
            )
            if interface.name:
                current_device.interfaces.append(interface)

        link_like = tag in {"link", "connection", "edge", "cable"} or (
            _get_attr(attrs, "from", "fromdevice", "source", "srcdevice")
            and _get_attr(attrs, "to", "todevice", "target", "dstdevice")
        )
        if link_like:
            link = LinkCandidate(
                from_device_name=_get_attr(attrs, "fromdevice", "from", "source", "srcdevice"),
                from_interface_name=_get_attr(
                    attrs,
                    "frominterface",
                    "sourceinterface",
                    "srcinterface",
                    "fromport",
                ),
                to_device_name=_get_attr(attrs, "todevice", "to", "target", "dstdevice"),
                to_interface_name=_get_attr(
                    attrs,
                    "tointerface",
                    "targetinterface",
                    "dstinterface",
                    "toport",
                ),
                link_type=_get_attr(attrs, "type", "medium", "cabletype"),
                raw={
                    "source_fragment": source_fragment,
                    "tag": tag,
                    "attrs": attrs,
                },
                confidence=0.85,
            )
            if link.from_device_name or link.to_device_name:
                links.append(link)

        note_like = tag in {"note", "label", "annotation", "text"}
        if note_like and text_value:
            notes.append(
                NoteCandidate(
                    text=text_value,
                    raw={
                        "source_fragment": source_fragment,
                        "tag": tag,
                        "attrs": attrs,
                    },
                    confidence=0.75,
                )
            )

        for child in element:
            walk(child, current_device)

    walk(root)
    return devices, links, notes, version_hints, warnings


def extract_loose_candidates(
    text: str,
    source_fragment: str,
) -> tuple[list[DeviceCandidate], list[LinkCandidate], list[NoteCandidate]]:
    devices: list[DeviceCandidate] = []
    links: list[LinkCandidate] = []
    notes: list[NoteCandidate] = []

    observables = extract_observables(text)
    for hostname in observables["hostnames"]:
        devices.append(
            DeviceCandidate(
                name=hostname,
                device_type=infer_device_type(hostname, text),
                raw={
                    "source_fragment": source_fragment,
                    "heuristic": "loose_hostname",
                    "preview": text_preview(text),
                },
                confidence=0.42,
                source="heuristic",
            )
        )

    for match in LINK_TEXT_PATTERN.finditer(text):
        links.append(
            LinkCandidate(
                from_device_name=match.group("from_device"),
                from_interface_name=match.group("from_interface"),
                to_device_name=match.group("to_device"),
                to_interface_name=match.group("to_interface"),
                raw={
                    "source_fragment": source_fragment,
                    "heuristic": "loose_link_pattern",
                },
                confidence=0.58,
            )
        )

    for match in NOTE_LINE_PATTERN.finditer(text):
        notes.append(
            NoteCandidate(
                text=match.group(1).strip(),
                raw={
                    "source_fragment": source_fragment,
                    "heuristic": "loose_note",
                },
                confidence=0.55,
            )
        )

    return devices, links, notes
