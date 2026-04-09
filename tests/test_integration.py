from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from app.cli import main
from app.parser import run_pipeline


class IntegrationTests(unittest.TestCase):
    def test_pipeline_runs_on_sample_fixture(self) -> None:
        sample = Path(__file__).resolve().parent.parent / "samples" / "mock_lab.pkt"
        output_dir = Path("output") / "test_pipeline_run"
        shutil.rmtree(output_dir, ignore_errors=True)
        artifacts = run_pipeline(sample, output_dir=output_dir, debug=True)

        self.assertEqual(artifacts.exit_code, 0)
        self.assertGreaterEqual(len(artifacts.normalized_topology["devices"]), 2)
        self.assertGreaterEqual(len(artifacts.normalized_topology["links"]), 1)
        shutil.rmtree(output_dir, ignore_errors=True)

    def test_cli_writes_output_files(self) -> None:
        sample = Path(__file__).resolve().parent.parent / "samples" / "mock_lab.pkt"
        output_dir = Path("output") / "test_cli_run"
        shutil.rmtree(output_dir, ignore_errors=True)
        exit_code = main([str(sample), "--out", str(output_dir), "--pretty"])

        self.assertEqual(exit_code, 0)
        self.assertTrue((output_dir / "raw_dump.json").exists())
        self.assertTrue((output_dir / "normalized_topology.json").exists())
        self.assertTrue((output_dir / "extraction_report.json").exists())
        shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
