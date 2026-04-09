from __future__ import annotations

from pathlib import Path

from .decoders import run_decoder_strategies
from .models import DecodedPktResult
from .report import ReportBuilder


def decode_pkt_bytes(
    data: bytes,
    source_file: str,
    *,
    report: ReportBuilder | None = None,
    debug_dir: Path | None = None,
) -> DecodedPktResult:
    result = run_decoder_strategies(
        data,
        source_file,
        report=report,
        debug_dir=debug_dir,
    )
    if report:
        if result.success:
            report.info(
                "Deterministic Packet Tracer decode succeeded",
                source_file=source_file,
                strategy_name=result.strategy_name,
                xml_size_bytes=result.xml_size_bytes,
            )
        else:
            for attempt in result.attempts:
                report.trace(
                    "Decoder strategy result",
                    source_file=source_file,
                    strategy_name=attempt.strategy_name,
                    success=attempt.success,
                    errors=attempt.errors,
                )
            report.error(
                "All deterministic decoder strategies failed",
                source_file=source_file,
                attempts=[attempt.strategy_name for attempt in result.attempts],
            )
    return result


def decode_pkt(
    path: Path,
    *,
    report: ReportBuilder | None = None,
    debug_dir: Path | None = None,
) -> DecodedPktResult:
    try:
        data = path.read_bytes()
    except OSError as exc:
        result = DecodedPktResult(
            source_file=path.name,
            success=False,
            raw_size_bytes=0,
            errors=[f"Failed to read file: {exc}"],
        )
        if report:
            report.error("Packet Tracer decode read failed", path=str(path), error=str(exc))
        return result
    return decode_pkt_bytes(data, path.name, report=report, debug_dir=debug_dir)
