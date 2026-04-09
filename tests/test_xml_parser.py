from __future__ import annotations

import unittest

from app.xml_parser import parse_xml_content
from tests.helpers import LEGACY_PACKET_TRACER_XML


class XmlParserTests(unittest.TestCase):
    def test_parse_packet_tracer_style_xml(self) -> None:
        result = parse_xml_content(LEGACY_PACKET_TRACER_XML)

        self.assertTrue(result.success)
        self.assertIn("5.2.0.0068", result.version_hints)
        self.assertEqual(len(result.devices), 2)
        self.assertEqual(len(result.links), 1)
        self.assertEqual(len(result.notes), 1)
        r1 = next(device for device in result.devices if device.name == "R1")
        self.assertEqual(r1.device_type, "router")
        self.assertEqual(r1.model, "1841")
        self.assertEqual(r1.interfaces[0].ip, "10.0.0.1")

    def test_parse_xml_handles_missing_fields(self) -> None:
        xml = "<PACKETTRACER5><NETWORK><DEVICES><DEVICE><ENGINE><NAME>R2</NAME></ENGINE></DEVICE></DEVICES></NETWORK></PACKETTRACER5>"
        result = parse_xml_content(xml)

        self.assertTrue(result.success)
        self.assertEqual(len(result.devices), 1)
        self.assertEqual(result.devices[0].name, "R2")


if __name__ == "__main__":
    unittest.main()
