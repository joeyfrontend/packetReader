from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from app.cli import main
from app.parser import run_pipeline
from tests.helpers import LEGACY_PACKET_TRACER_XML, encode_pkt_bytes


class IntegrationTests(unittest.TestCase):
    def test_pipeline_prefers_deterministic_decode(self) -> None:
        output_dir = Path("output") / "test_pipeline_deterministic"
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        sample = output_dir / "deterministic_sample.pkt"
        sample.write_bytes(encode_pkt_bytes(LEGACY_PACKET_TRACER_XML))

        artifacts = run_pipeline(sample, output_dir=output_dir, debug=True)

        self.assertEqual(artifacts.exit_code, 0)
        self.assertEqual(artifacts.extraction_report["decode_pipeline"]["path_used"], "legacy_xor_zlib")
        self.assertTrue(artifacts.extraction_report["decode_pipeline"]["deterministic_success"])
        self.assertEqual(artifacts.extraction_report["decode_pipeline"]["successful_strategy"], "legacy_xor_zlib")
        self.assertGreaterEqual(len(artifacts.normalized_topology["devices"]), 2)
        self.assertGreaterEqual(len(artifacts.normalized_topology["links"]), 1)
        self.assertTrue((output_dir / "debug" / "decoded.xml").exists())
        shutil.rmtree(output_dir, ignore_errors=True)

    def test_pipeline_falls_back_when_pkt_decode_fails(self) -> None:
        sample = Path(__file__).resolve().parent.parent / "samples" / "mock_lab.pkt"
        output_dir = Path("output") / "test_pipeline_fallback"
        shutil.rmtree(output_dir, ignore_errors=True)

        artifacts = run_pipeline(sample, output_dir=output_dir, debug=True)

        self.assertEqual(artifacts.exit_code, 0)
        self.assertEqual(artifacts.extraction_report["decode_pipeline"]["path_used"], "heuristic_fallback")
        self.assertFalse(artifacts.extraction_report["decode_pipeline"]["deterministic_success"])
        self.assertGreaterEqual(len(artifacts.extraction_report["decode_pipeline"]["attempts"]), 4)
        self.assertGreaterEqual(len(artifacts.normalized_topology["devices"]), 2)
        shutil.rmtree(output_dir, ignore_errors=True)

    def test_cli_writes_output_files(self) -> None:
        output_dir = Path("output") / "test_cli_run"
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)
        sample = output_dir / "cli_sample.pkt"
        sample.write_bytes(encode_pkt_bytes(LEGACY_PACKET_TRACER_XML))

        exit_code = main([str(sample), "--out", str(output_dir), "--pretty", "--debug"])

        self.assertEqual(exit_code, 0)
        self.assertTrue((output_dir / "raw_dump.json").exists())
        self.assertTrue((output_dir / "normalized_topology.json").exists())
        self.assertTrue((output_dir / "extraction_report.json").exists())
        self.assertTrue((output_dir / "debug" / "decoded.xml").exists())
        shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
