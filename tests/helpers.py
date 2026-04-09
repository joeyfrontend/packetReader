from __future__ import annotations

import gzip
import io
import zipfile
import zlib


LEGACY_PACKET_TRACER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<PACKETTRACER5>
  <VERSION>5.2.0.0068</VERSION>
  <NETWORK>
    <DEVICES>
      <DEVICE id="1" x="120" y="240">
        <ENGINE>
          <TYPE model="1841">Router</TYPE>
          <NAME>R1</NAME>
        </ENGINE>
        <INTERFACES>
          <INTERFACE name="GigabitEthernet0/0" ip="10.0.0.1" mask="255.255.255.0" />
        </INTERFACES>
        <RUNNINGCONFIG>hostname R1
interface GigabitEthernet0/0
 ip address 10.0.0.1 255.255.255.0
 no shutdown
!</RUNNINGCONFIG>
      </DEVICE>
      <DEVICE id="2" x="300" y="240">
        <ENGINE>
          <TYPE model="2960">Switch</TYPE>
          <NAME>SW1</NAME>
        </ENGINE>
        <INTERFACES>
          <INTERFACE name="FastEthernet0/1" />
        </INTERFACES>
      </DEVICE>
    </DEVICES>
    <LINKS>
      <LINK fromDevice="R1" fromInterface="GigabitEthernet0/0" toDevice="SW1" toInterface="FastEthernet0/1" type="copper" />
    </LINKS>
    <ANNOTATION>Legacy decoded lab</ANNOTATION>
  </NETWORK>
</PACKETTRACER5>
"""


def encode_pkt_bytes(xml_content: str) -> bytes:
    xml_bytes = xml_content.encode("utf-8")
    payload = len(xml_bytes).to_bytes(4, "big") + zlib.compress(xml_bytes)
    key = len(payload)
    encoded = bytearray()
    for value in payload:
        encoded.append((value ^ key) & 0xFF)
        key -= 1
    return bytes(encoded)


def build_zlib_carved_bytes(xml_content: str, prefix: bytes = b"RANDOMHDR") -> bytes:
    return prefix + zlib.compress(xml_content.encode("utf-8"))


def build_gzip_carved_bytes(xml_content: str, prefix: bytes = b"RANDOMHDR") -> bytes:
    return prefix + gzip.compress(xml_content.encode("utf-8"))


def build_single_byte_xor_bytes(xml_content: str, key: int = 0x5A) -> bytes:
    data = xml_content.encode("utf-8")
    return bytes(value ^ key for value in data)


def build_pkz_bytes(pkt_name: str, pkt_payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(pkt_name, pkt_payload)
    return buffer.getvalue()
