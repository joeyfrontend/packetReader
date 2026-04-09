from __future__ import annotations

import unittest

from app.inspector import inspect_bytes
from app.report import ReportBuilder


class InspectorTests(unittest.TestCase):
    def test_inspector_detects_signatures_and_version(self) -> None:
        data = b"PKT\x00<?xml version='1.0'?><lab packetTracerVersion='8.2.1'></lab>"
        report = ReportBuilder(debug=True)

        inspection = inspect_bytes(data, "sample.pkt", report)

        self.assertEqual(inspection.source_file, "sample.pkt")
        self.assertTrue(any(signature.kind == "xml" for signature in inspection.signatures))
        self.assertIn("8.2.1", inspection.version_hints)


if __name__ == "__main__":
    unittest.main()
