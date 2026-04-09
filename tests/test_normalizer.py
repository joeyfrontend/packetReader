from __future__ import annotations

import unittest

from app.models import DeviceCandidate, ExtractionResult, InterfaceCandidate, LinkCandidate
from app.normalizer import normalize_topology


class NormalizerTests(unittest.TestCase):
    def test_normalizer_merges_duplicate_devices(self) -> None:
        extraction = ExtractionResult(
            devices=[
                DeviceCandidate(
                    name="R1",
                    device_type="router",
                    interfaces=[
                        InterfaceCandidate(
                            name="GigabitEthernet0/0",
                            ip="10.0.0.1",
                            mask="255.255.255.0",
                            confidence=0.9,
                        )
                    ],
                    confidence=0.9,
                ),
                DeviceCandidate(
                    name="R1",
                    position={"x": 100, "y": 200},
                    confidence=0.7,
                ),
            ],
            links=[
                LinkCandidate(
                    from_device_name="R1",
                    from_interface_name="GigabitEthernet0/0",
                    to_device_name="SW1",
                    to_interface_name="FastEthernet0/1",
                    confidence=0.6,
                )
            ],
        )

        topology = normalize_topology("fixture.pkt", extraction)

        self.assertEqual(len(topology["devices"]), 2)
        r1 = next(device for device in topology["devices"] if device["name"] == "R1")
        self.assertEqual(r1["type"], "router")
        self.assertEqual(r1["position"]["x"], 100)
        self.assertEqual(r1["interfaces"][0]["ip"], "10.0.0.1")

    def test_normalizer_prioritizes_higher_confidence_xml_fields(self) -> None:
        extraction = ExtractionResult(
            devices=[
                DeviceCandidate(
                    name="R1",
                    device_type="switch",
                    model="WrongModel",
                    confidence=0.35,
                    source="heuristic",
                ),
                DeviceCandidate(
                    name="R1",
                    device_type="router",
                    model="1841",
                    confidence=0.97,
                    source="xml",
                ),
            ]
        )

        topology = normalize_topology("fixture.pkt", extraction)

        r1 = topology["devices"][0]
        self.assertEqual(r1["type"], "router")
        self.assertEqual(r1["model"], "1841")


if __name__ == "__main__":
    unittest.main()
