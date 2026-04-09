from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from ..models import DecodedPktResult
from ..report import ReportBuilder


class DecoderStrategy(ABC):
    name: str
    used_algorithm: str

    @abstractmethod
    def decode(
        self,
        data: bytes,
        source_file: str,
        *,
        report: ReportBuilder | None = None,
        debug_dir: Path | None = None,
    ) -> DecodedPktResult:
        raise NotImplementedError
