from __future__ import annotations

import unittest

from app.decoder import decode_payloads
from app.inspector import inspect_bytes
from app.report import ReportBuilder


class DecoderTests(unittest.TestCase):
    def test_decoder_extracts_strings(self) -> None:
        data = (
            b"\x00\x01hostname R1\ninterface GigabitEthernet0/0\n ip address 10.0.0.1 255.255.255.0\n"
        )
        report = ReportBuilder(debug=False)
        inspection = inspect_bytes(data, "fixture.pkt", report)

        decoded = decode_payloads(data, inspection, report)

        self.assertGreaterEqual(len(decoded.text_fragments), 1)
        self.assertEqual(decoded.text_fragments[0].classification, "config")
        self.assertIn("hostname R1", decoded.recovered_text)

    def test_decoder_handles_bad_compression_without_crashing(self) -> None:
        data = b"\x1f\x8bnot-really-gzip-data-but-signature-is-present"
        report = ReportBuilder(debug=False)
        inspection = inspect_bytes(data, "bad-gzip.pkt", report)

        decoded = decode_payloads(data, inspection, report)

        self.assertIsNotNone(decoded)
        self.assertTrue(report.messages("recoverable_error"))


if __name__ == "__main__":
    unittest.main()
