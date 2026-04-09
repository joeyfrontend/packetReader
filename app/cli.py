from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .parser import run_pipeline
from .utils import ensure_directory, write_json, write_text


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert Cisco Packet Tracer .pkt files into raw structured JSON."
    )
    parser.add_argument("input", help="Path to the .pkt file to inspect and extract.")
    parser.add_argument(
        "--out",
        default="output",
        help="Output directory for JSON reports and debug artifacts.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable verbose logging and write intermediate decoded chunks to output/debug.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    parser.add_argument(
        "--raw-only",
        action="store_true",
        help="Write raw_dump.json and extraction_report.json only.",
    )
    parser.add_argument(
        "--normalized-only",
        action="store_true",
        help="Write normalized_topology.json and extraction_report.json only.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Write extraction_report.json only.",
    )
    parser.add_argument(
        "--strings",
        action="store_true",
        help="Readable-string extraction mode. Writes recovered_text.txt and skips structured normalization.",
    )
    return parser


def configure_logging(debug: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.raw_only and args.normalized_only:
        parser.error("--raw-only and --normalized-only cannot be used together.")

    configure_logging(args.debug)

    input_path = Path(args.input)
    output_dir = ensure_directory(Path(args.out))
    artifacts = run_pipeline(
        input_path,
        output_dir=output_dir,
        debug=args.debug,
        strings_only=args.strings,
    )

    write_json(output_dir / "extraction_report.json", artifacts.extraction_report, pretty=args.pretty)

    if not args.report_only and not args.normalized_only:
        write_json(output_dir / "raw_dump.json", artifacts.raw_dump, pretty=args.pretty)

    if not args.report_only and not args.raw_only and not args.strings:
        write_json(
            output_dir / "normalized_topology.json",
            artifacts.normalized_topology,
            pretty=args.pretty,
        )

    if args.strings:
        write_text(output_dir / "recovered_text.txt", artifacts.recovered_text)

    return artifacts.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
