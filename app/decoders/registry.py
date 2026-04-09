from __future__ import annotations

from pathlib import Path

from ..models import DecodedPktResult, DecoderAttempt
from ..report import ReportBuilder
from ..utils import ensure_directory
from .base import DecoderStrategy
from .direct_xml import DirectXmlDecoder
from .gzip_carver import GzipCarvingDecoder
from .legacy_xor_zlib import LegacyXorZlibDecoder
from .zlib_carver import ZlibCarvingDecoder


def get_decoder_strategies() -> list[DecoderStrategy]:
    return [
        LegacyXorZlibDecoder(),
        DirectXmlDecoder(),
        GzipCarvingDecoder(),
        ZlibCarvingDecoder(),
    ]


def run_decoder_strategies(
    data: bytes,
    source_file: str,
    *,
    report: ReportBuilder | None = None,
    debug_dir: Path | None = None,
) -> DecodedPktResult:
    if debug_dir:
        ensure_directory(debug_dir)
        (debug_dir / "decoded.xml").unlink(missing_ok=True)

    attempts: list[DecoderAttempt] = []
    for strategy in get_decoder_strategies():
        if report:
            report.info(
                "Attempting decoder strategy",
                source_file=source_file,
                strategy_name=strategy.name,
            )
        result = strategy.decode(
            data,
            source_file,
            report=report,
            debug_dir=debug_dir,
        )
        attempts.append(
            DecoderAttempt(
                strategy_name=strategy.name,
                success=result.success,
                xml_size_bytes=result.xml_size_bytes,
                xml_preview=result.xml_preview,
                warnings=list(result.warnings),
                errors=list(result.errors),
                debug_info=dict(result.debug_info),
            )
        )
        if result.success:
            result.attempts = attempts
            return result

    fallback = DecodedPktResult(
        source_file=source_file,
        success=False,
        raw_size_bytes=len(data),
        strategy_name=None,
        used_algorithm="none",
        errors=["No deterministic decoder strategy succeeded."],
        attempts=attempts,
    )
    return fallback
