from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from app.models import DecodedPktResult, DeviceCandidate, ExtractionResult, XmlParseResult
from app.parser import run_pipeline
from app.validator import build_oracle_validation


class OracleValidationTests(unittest.TestCase):
    def test_trial_sample_reports_oracle_comparison(self) -> None:
        sample = Path(__file__).resolve().parent.parent / "samples" / "trial.pkt"
        output_dir = Path("output") / "test_trial_oracle"
        shutil.rmtree(output_dir, ignore_errors=True)

        artifacts = run_pipeline(sample, output_dir=output_dir, debug=False)
        report = artifacts.extraction_report

        self.assertTrue(report["oracle_validation"]["oracle_available"])
        self.assertEqual(report["oracle_validation"]["packet_tracer_version"], "9.0.0")
        self.assertEqual(report["expected_vs_found"]["devices"]["expected_count"], 4)
        self.assertEqual(report["expected_vs_found"]["interfaces"]["expected_count"], 0)
        self.assertEqual(report["expected_vs_found"]["devices"]["found_count"], 0)
        self.assertTrue(
            any(
                item["name"] == "Switch0" and item["likely_failure_stage"] == "decode stage"
                for item in report["missing_expected_entities"]["devices"]
            )
        )
        self.assertTrue(
            any(
                item["entity"] == "PC0"
                and item["field"] == "ip"
                and item["expected"] == "192.168.1.1"
                and item["likely_failure_stage"] == "decode stage"
                for item in report["missing_expected_fields"]
            )
        )
        shutil.rmtree(output_dir, ignore_errors=True)

    def test_missing_normalized_field_is_classified_as_normalization_stage(self) -> None:
        normalized_topology = {
            "devices": [
                {
                    "id": "dev_1",
                    "name": "Switch0",
                    "type": None,
                    "model": None,
                    "interfaces": [],
                    "position": {"x": None, "y": None},
                    "raw": {},
                }
            ],
            "links": [],
            "notes": [],
            "unmapped_blocks": [],
        }
        extraction = ExtractionResult(
            devices=[
                DeviceCandidate(
                    name="Switch0",
                    device_type="switch",
                    model="Cisco 2960-24TT",
                    confidence=0.9,
                    source="xml",
                )
            ]
        )
        validation = build_oracle_validation(
            source_file="trial.pkt",
            normalized_topology=normalized_topology,
            extraction=extraction,
            pkt_decode=DecodedPktResult(
                source_file="trial.pkt",
                success=True,
                raw_size_bytes=1,
                strategy_name="legacy_xor_zlib",
                xml_content="<root/>",
                xml_size_bytes=7,
            ),
            xml_parse=XmlParseResult(success=True, root_tag="packettracer"),
        )

        self.assertTrue(
            any(
                item["entity"] == "Switch0"
                and item["field"] == "type"
                and item["likely_failure_stage"] == "normalization stage"
                for item in validation["missing_expected_fields"]
            )
        )
        self.assertTrue(
            any(
                item["entity"] == "Switch0"
                and item["field"] == "model"
                and item["likely_failure_stage"] == "normalization stage"
                for item in validation["missing_expected_fields"]
            )
        )

    def test_trial_router_reports_router_interfaces_and_state_delta(self) -> None:
        validation = build_oracle_validation(
            source_file="trial-router.pkt",
            normalized_topology={
                "devices": [],
                "links": [],
                "notes": [],
                "unmapped_blocks": [],
            },
            extraction=ExtractionResult(),
            pkt_decode=DecodedPktResult(
                source_file="trial-router.pkt",
                success=False,
                raw_size_bytes=1,
            ),
            xml_parse=XmlParseResult(success=False),
        )

        self.assertEqual(validation["expected_vs_found"]["devices"]["expected_count"], 5)
        self.assertEqual(validation["expected_vs_found"]["interfaces"]["expected_count"], 2)
        self.assertTrue(
            any(
                item["device"] == "Router0"
                and item["name"] == "GigabitEthernet0/0"
                and item["likely_failure_stage"] == "decode stage"
                for item in validation["missing_expected_entities"]["interfaces"]
            )
        )
        self.assertIn("oracle_state_delta", validation)
        self.assertEqual(
            validation["oracle_state_delta"]["expected_changes"]["added_devices"],
            ["Router0"],
        )
        self.assertEqual(
            validation["oracle_state_delta"]["expected_changes"]["added_interfaces"],
            [
                {"device": "Router0", "name": "gi0/0"},
                {"device": "Router0", "name": "gi0/1"},
            ],
        )
        self.assertEqual(
            validation["oracle_state_delta"]["expected_changes"]["removed_ips"],
            [],
        )

    def test_trial_ipchange_reports_expected_ip_delta(self) -> None:
        validation = build_oracle_validation(
            source_file="trial-ipchange.pkt",
            normalized_topology={
                "devices": [],
                "links": [],
                "notes": [],
                "unmapped_blocks": [],
            },
            extraction=ExtractionResult(),
            pkt_decode=DecodedPktResult(
                source_file="trial-ipchange.pkt",
                success=False,
                raw_size_bytes=1,
            ),
            xml_parse=XmlParseResult(success=False),
        )

        self.assertEqual(
            validation["oracle_state_delta"]["expected_changes"]["added_ips"],
            [{"device": "PC1", "ip": "192.168.1.3"}],
        )
        self.assertEqual(
            validation["oracle_state_delta"]["expected_changes"]["removed_ips"],
            [{"device": "PC1", "ip": "192.168.1.2"}],
        )


if __name__ == "__main__":
    unittest.main()
