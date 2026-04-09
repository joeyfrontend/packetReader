from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from app.investigation.binary_diff import FileSample, analyze_pair, analyze_trial_family


class BinaryDiffTests(unittest.TestCase):
    def test_analyze_pair_detects_localized_change(self) -> None:
        prefix = bytes(range(256)) * 2
        suffix = bytes(reversed(range(256))) * 2
        left = FileSample(
            name="trial.pkt",
            path=Path("trial.pkt"),
            data=prefix + b"192.168.1.2" + suffix,
        )
        right = FileSample(
            name="trial-ipchange.pkt",
            path=Path("trial-ipchange.pkt"),
            data=prefix + b"192.168.1.3" + suffix,
        )

        report = analyze_pair(left, right)

        self.assertEqual(report["comparison_stats"]["changes_look"], "local")
        self.assertGreaterEqual(report["comparison_stats"]["changed_region_count"], 1)
        self.assertTrue(report["investigator_notes"]["likely_ip_change_regions"])

    def test_trial_family_writes_machine_readable_reports(self) -> None:
        sample_dir = Path(__file__).resolve().parent.parent / "samples"
        output_dir = Path("output") / "test_investigation"
        shutil.rmtree(output_dir, ignore_errors=True)

        summary = analyze_trial_family(sample_dir, output_dir=output_dir, pretty=True)

        self.assertIn("investigator_summary", summary)
        self.assertTrue((output_dir / "trial_vs_ipchange.json").exists())
        self.assertTrue((output_dir / "trial_vs_router.json").exists())
        self.assertTrue((output_dir / "ipchange_vs_router.json").exists())
        self.assertTrue((output_dir / "trial_family_summary.json").exists())

        payload = json.loads((output_dir / "trial_vs_router.json").read_text(encoding="utf-8"))
        self.assertIn("changed_regions", payload)
        self.assertIn("high_change_windows", payload)
        self.assertIn("investigator_notes", payload)

        shutil.rmtree(output_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
