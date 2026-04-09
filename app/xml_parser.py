from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Iterable

from .heuristics import extract_interfaces_from_config, infer_device_type
from .models import DeviceCandidate, InterfaceCandidate, LinkCandidate, NoteCandidate, XmlParseResult


INTERFACE_NAME_PATTERN = re.compile(
    r"^(?:FastEthernet|GigabitEthernet|Serial|Ethernet|Loopback|Vlan|Port-channel|Fa|Gi|Se|Eth|Lo|Vl|Po)\d+(?:/\d+){0,3}$",
    re.IGNORECASE,
)


def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1].lower()


def _clean_text(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = " ".join(value.split())
    return cleaned or None


def _direct_children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(element) if _local_name(child.tag) == name]


def _first_direct_child(element: ET.Element, name: str) -> ET.Element | None:
    children = _direct_children(element, name)
    return children[0] if children else None


def _first_descendant(element: ET.Element, names: Iterable[str]) -> ET.Element | None:
    wanted = set(names)
    for child in element.iter():
        if child is element:
            continue
        if _local_name(child.tag) in wanted:
            return child
    return None


def _find_text(element: ET.Element, *names: str) -> str | None:
    descendant = _first_descendant(element, names)
    if descendant is None:
        return None
    return _clean_text(descendant.text)


def _attrs(element: ET.Element) -> dict[str, str]:
    return {_local_name(key): value for key, value in element.attrib.items()}


def _find_attr(element: ET.Element, *names: str) -> str | None:
    attrs = _attrs(element)
    for name in names:
        if name.lower() in attrs:
            return attrs[name.lower()]
    return None


def _coerce_number(value: str | None) -> float | int | None:
    if not value:
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    if number.is_integer():
        return int(number)
    return number


def _collect_config_texts(device_element: ET.Element) -> list[str]:
    config_blocks: list[str] = []
    for descendant in device_element.iter():
        tag = _local_name(descendant.tag)
        if "config" in tag or tag in {"cli", "ios", "running", "startup"}:
            text = (descendant.text or "").strip()
            if text:
                config_blocks.append(text)
    deduped: list[str] = []
    seen = set()
    for block in config_blocks:
        if block not in seen:
            deduped.append(block)
            seen.add(block)
    return deduped


def _parse_interface_candidates(
    device_element: ET.Element,
    source_fragment: str,
    config_text: str | None,
) -> list[InterfaceCandidate]:
    interfaces: list[InterfaceCandidate] = []
    seen: set[str] = set()

    for descendant in device_element.iter():
        tag = _local_name(descendant.tag)
        attrs = _attrs(descendant)
        name = (
            attrs.get("name")
            or attrs.get("port")
            or attrs.get("label")
            or _find_text(descendant, "name", "port", "label")
        )
        ip = attrs.get("ip") or attrs.get("ipaddress") or _find_text(descendant, "ip", "ipaddress")
        mask = attrs.get("mask") or attrs.get("subnetmask") or _find_text(descendant, "mask", "subnetmask")
        mac = attrs.get("mac") or attrs.get("macaddress") or _find_text(descendant, "mac", "macaddress")
        status = attrs.get("status") or attrs.get("state") or _find_text(descendant, "status", "state")

        looks_like_interface = tag in {"interface", "port", "adapter", "nic"} or (
            name is not None and INTERFACE_NAME_PATTERN.match(name) is not None
        )
        if not looks_like_interface or not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        interfaces.append(
            InterfaceCandidate(
                name=name,
                ip=ip,
                mask=mask,
                mac=mac,
                status=status,
                raw={
                    "source_fragment": source_fragment,
                    "tag": tag,
                    "attrs": attrs,
                },
                confidence=0.95,
            )
        )

    if config_text:
        config_interfaces = extract_interfaces_from_config(config_text, source_fragment)
        for interface in config_interfaces:
            if not interface.name:
                continue
            key = interface.name.lower()
            existing = next((item for item in interfaces if (item.name or "").lower() == key), None)
            if existing is None:
                interface.confidence = max(interface.confidence, 0.88)
                interfaces.append(interface)
                seen.add(key)
                continue
            if interface.ip and not existing.ip:
                existing.ip = interface.ip
            if interface.mask and not existing.mask:
                existing.mask = interface.mask
            if interface.mac and not existing.mac:
                existing.mac = interface.mac
            if interface.status and not existing.status:
                existing.status = interface.status
            existing.confidence = max(existing.confidence, interface.confidence)
            existing.raw.setdefault("config_evidence", []).append(interface.raw)

    return interfaces


def _parse_device_candidate(device_element: ET.Element, source_fragment: str) -> DeviceCandidate:
    attrs = _attrs(device_element)
    engine = _first_descendant(device_element, {"engine"})
    engine_attrs = _attrs(engine) if engine is not None else {}
    name = attrs.get("name") or attrs.get("hostname")
    if not name and engine is not None:
        name = _find_text(engine, "name")
    if not name:
        name = _find_text(device_element, "name", "hostname", "label")

    type_element = _first_descendant(engine, {"type"}) if engine is not None else None
    if type_element is None:
        type_element = _first_descendant(device_element, {"type"})
    type_text = _clean_text(type_element.text) if type_element is not None else None
    model = None
    if type_element is not None:
        type_attrs = _attrs(type_element)
        model = type_attrs.get("model") or type_attrs.get("sku")
    model = model or attrs.get("model")

    config_blocks = _collect_config_texts(device_element)
    config_text = "\n\n".join(config_blocks) if config_blocks else None
    interfaces = _parse_interface_candidates(device_element, source_fragment, config_text)

    x_value = (
        attrs.get("x")
        or attrs.get("posx")
        or _find_text(device_element, "x", "posx")
        or engine_attrs.get("x")
    )
    y_value = (
        attrs.get("y")
        or attrs.get("posy")
        or _find_text(device_element, "y", "posy")
        or engine_attrs.get("y")
    )

    return DeviceCandidate(
        name=name,
        device_type=infer_device_type(name, config_text or type_text or "", attrs),
        subtype=type_text,
        model=model,
        position={"x": _coerce_number(x_value), "y": _coerce_number(y_value)},
        interfaces=interfaces,
        config_text=config_text,
        raw={
            "source_fragment": source_fragment,
            "tag": _local_name(device_element.tag),
            "attrs": attrs,
        },
        confidence=0.97,
        source="xml",
    )


def _parse_link_candidates(root: ET.Element, source_fragment: str) -> list[LinkCandidate]:
    links: list[LinkCandidate] = []
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag not in {"link", "connection", "edge", "cable"}:
            continue
        attrs = _attrs(element)
        from_device = (
            attrs.get("fromdevice")
            or attrs.get("from")
            or attrs.get("source")
            or attrs.get("srcdevice")
            or _find_text(element, "fromdevice", "from", "source", "srcdevice", "startdevice")
        )
        to_device = (
            attrs.get("todevice")
            or attrs.get("to")
            or attrs.get("target")
            or attrs.get("dstdevice")
            or _find_text(element, "todevice", "to", "target", "dstdevice", "enddevice")
        )
        from_interface = (
            attrs.get("frominterface")
            or attrs.get("sourceinterface")
            or attrs.get("srcinterface")
            or attrs.get("fromport")
            or _find_text(element, "frominterface", "sourceinterface", "srcinterface", "fromport")
        )
        to_interface = (
            attrs.get("tointerface")
            or attrs.get("targetinterface")
            or attrs.get("dstinterface")
            or attrs.get("toport")
            or _find_text(element, "tointerface", "targetinterface", "dstinterface", "toport")
        )
        if not (from_device or to_device):
            continue
        links.append(
            LinkCandidate(
                from_device_name=from_device,
                from_interface_name=from_interface,
                to_device_name=to_device,
                to_interface_name=to_interface,
                link_type=attrs.get("type") or attrs.get("medium") or attrs.get("cabletype"),
                raw={
                    "source_fragment": source_fragment,
                    "tag": tag,
                    "attrs": attrs,
                },
                confidence=0.95,
            )
        )
    return links


def _parse_notes(root: ET.Element, source_fragment: str) -> list[NoteCandidate]:
    notes: list[NoteCandidate] = []
    for element in root.iter():
        tag = _local_name(element.tag)
        if tag not in {"note", "annotation", "label"}:
            continue
        text = _clean_text(element.text)
        if not text:
            continue
        notes.append(
            NoteCandidate(
                text=text,
                raw={
                    "source_fragment": source_fragment,
                    "tag": tag,
                    "attrs": _attrs(element),
                },
                confidence=0.92,
            )
        )
    return notes


def parse_xml_content(xml_content: str, source_fragment: str = "decoded_xml") -> XmlParseResult:
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError as exc:
        return XmlParseResult(
            success=False,
            errors=[f"XML parse error: {exc}"],
            debug_info={"source_fragment": source_fragment},
        )

    root_tag = _local_name(root.tag)
    result = XmlParseResult(
        success=True,
        root_tag=root_tag,
        debug_info={"source_fragment": source_fragment},
    )

    version_hint = _find_text(root, "version")
    if version_hint:
        result.version_hints.append(version_hint)
    root_attrs = _attrs(root)
    if "packettracerversion" in root_attrs:
        result.version_hints.append(root_attrs["packettracerversion"])
    if "version" in root_attrs:
        result.version_hints.append(root_attrs["version"])
    result.version_hints = list(dict.fromkeys(result.version_hints))

    devices: list[DeviceCandidate] = []
    for element in root.iter():
        if _local_name(element.tag) != "device":
            continue
        candidate = _parse_device_candidate(element, source_fragment)
        if candidate.name or candidate.model or candidate.interfaces or candidate.config_text:
            devices.append(candidate)
    result.devices = devices

    result.links = _parse_link_candidates(root, source_fragment)
    result.notes = _parse_notes(root, source_fragment)

    result.debug_info.update(
        {
            "device_count": len(result.devices),
            "link_count": len(result.links),
            "note_count": len(result.notes),
        }
    )
    return result
