from __future__ import annotations

import zipfile
from pathlib import Path

from .models import InputLoadResult
from .report import ReportBuilder
from .utils import ensure_directory


def load_input_bytes(
    path: Path,
    *,
    report: ReportBuilder | None = None,
    debug_dir: Path | None = None,
) -> InputLoadResult:
    suffix = path.suffix.lower()
    if suffix != ".pkz":
        data = path.read_bytes()
        return InputLoadResult(
            source_file=path.name,
            display_source=path.name,
            payload_name=path.name,
            raw_size_bytes=len(data),
            data=data,
            container="file",
        )

    with zipfile.ZipFile(path) as archive:
        pkt_members = [
            info for info in archive.infolist() if info.filename.lower().endswith(".pkt")
        ]
        if not pkt_members:
            raise ValueError("PKZ archive does not contain a .pkt member.")
        member = pkt_members[0]
        data = archive.read(member.filename)
        if report:
            report.info(
                "Loaded PKZ archive member",
                source_file=path.name,
                payload_name=member.filename,
                compressed_size=member.compress_size,
                uncompressed_size=member.file_size,
            )
        if debug_dir:
            ensure_directory(debug_dir)
            (debug_dir / "extracted_from_pkz.pkt").write_bytes(data)
        return InputLoadResult(
            source_file=path.name,
            display_source=path.name,
            payload_name=member.filename,
            raw_size_bytes=len(data),
            data=data,
            container="pkz",
            metadata={
                "archive_member": member.filename,
                "compressed_size": member.compress_size,
                "uncompressed_size": member.file_size,
                "member_count": len(archive.infolist()),
            },
        )
