from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from app.pkt_decoder import decode_pkt, decode_pkt_bytes
from app.report import ReportBuilder
from tests.helpers import (
    LEGACY_PACKET_TRACER_XML,
    build_gzip_carved_bytes,
    build_zlib_carved_bytes,
    encode_pkt_bytes,
)


class PktDecoderTests(unittest.TestCase):
    def test_successful_decode_with_debug_output(self) -> None:
        output_dir = Path("output") / "test_pkt_decoder"
        shutil.rmtree(output_dir, ignore_errors=True)
        output_dir.mkdir(parents=True, exist_ok=True)

        pkt_path = output_dir / "legacy_sample.pkt"
        pkt_path.write_bytes(encode_pkt_bytes(LEGACY_PACKET_TRACER_XML))

        report = ReportBuilder(debug=True)
        result = decode_pkt(pkt_path, report=report, debug_dir=output_dir / "debug")

        self.assertTrue(result.success)
        self.assertEqual(result.strategy_name, "legacy_xor_zlib")
        self.assertIn("<PACKETTRACER5>", result.xml_content or "")
        self.assertEqual(result.declared_uncompressed_size, len(LEGACY_PACKET_TRACER_XML.encode("utf-8")))
        self.assertTrue((output_dir / "debug" / "decoded.xml").exists())
        self.assertGreaterEqual(len(result.attempts), 1)
        shutil.rmtree(output_dir, ignore_errors=True)

    def test_zlib_carving_strategy_can_recover_xml(self) -> None:
        report = ReportBuilder(debug=False)
        result = decode_pkt_bytes(
            build_zlib_carved_bytes(LEGACY_PACKET_TRACER_XML),
            "carved.pkt",
            report=report,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.strategy_name, "zlib_carve")
        self.assertTrue(any(attempt.strategy_name == "legacy_xor_zlib" for attempt in result.attempts))
        self.assertTrue(any(attempt.strategy_name == "zlib_carve" and attempt.success for attempt in result.attempts))

    def test_gzip_carving_strategy_can_recover_xml(self) -> None:
        report = ReportBuilder(debug=False)
        result = decode_pkt_bytes(
            build_gzip_carved_bytes(LEGACY_PACKET_TRACER_XML),
            "gzip-carved.pkt",
            report=report,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.strategy_name, "gzip_carve")
        self.assertTrue(any(attempt.strategy_name == "gzip_carve" and attempt.success for attempt in result.attempts))

    def test_corrupted_input_returns_failure(self) -> None:
        report = ReportBuilder(debug=False)
        result = decode_pkt_bytes(b"not-a-real-pkt", "corrupted.pkt", report=report)

        self.assertFalse(result.success)
        self.assertTrue(result.errors)
        self.assertGreaterEqual(len(result.attempts), 1)


if __name__ == "__main__":
    unittest.main()
