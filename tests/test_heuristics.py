from __future__ import annotations

import unittest

from app.heuristics import (
    extract_devices_from_config,
    extract_loose_candidates,
    extract_xml_entities,
)


class HeuristicTests(unittest.TestCase):
    def test_extract_devices_from_config(self) -> None:
        config = """
hostname R1
interface GigabitEthernet0/0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
router ospf 1
 network 192.168.1.0 0.0.0.255 area 0
""".strip()

        devices = extract_devices_from_config(config, "fragment_1")

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].name, "R1")
        self.assertEqual(devices[0].device_type, "router")
        self.assertEqual(devices[0].interfaces[0].ip, "192.168.1.1")

    def test_extract_xml_entities(self) -> None:
        xml = """
<topology packetTracerVersion="8.2.1">
  <device id="d1" name="R1" type="router" x="100" y="200">
    <interface name="GigabitEthernet0/0" ip="192.168.1.1" mask="255.255.255.0" />
  </device>
  <device id="d2" name="SW1" type="switch" x="240" y="200">
    <interface name="FastEthernet0/1" />
  </device>
  <link fromDevice="R1" fromInterface="GigabitEthernet0/0" toDevice="SW1" toInterface="FastEthernet0/1" />
</topology>
""".strip()

        devices, links, notes, versions, warnings = extract_xml_entities(xml, "fragment_2")

        self.assertEqual(len(devices), 2)
        self.assertEqual(len(links), 1)
        self.assertIn("8.2.1", versions)
        self.assertFalse(notes)
        self.assertFalse(warnings)

    def test_extract_loose_candidates(self) -> None:
        text = "R1 Gi0/0 -> SW1 Fa0/1\nnote: branch office uplink"

        devices, links, notes = extract_loose_candidates(text, "fragment_3")

        self.assertTrue(any(device.name == "R1" for device in devices))
        self.assertEqual(len(links), 1)
        self.assertEqual(notes[0].text, "branch office uplink")


if __name__ == "__main__":
    unittest.main()
