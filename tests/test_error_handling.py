from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from app.parser import run_pipeline


class ErrorHandlingTests(unittest.TestCase):
    def test_missing_file_returns_failure_report(self) -> None:
        output_dir = Path("output") / "test_missing_file"
        shutil.rmtree(output_dir, ignore_errors=True)
        artifacts = run_pipeline(
            output_dir / "missing.pkt",
            output_dir=output_dir,
        )

        self.assertEqual(artifacts.exit_code, 1)
        self.assertFalse(artifacts.extraction_report["status"]["success"])
        self.assertTrue(artifacts.extraction_report["events"]["fatal_errors"])
        shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
