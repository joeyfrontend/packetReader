from __future__ import annotations

import hashlib
import json
import math
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PRINTABLE_BYTES = set(range(32, 127)) | {9, 10, 13}


def current_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    entropy = 0.0
    size = len(data)
    for count in counts:
        if count == 0:
            continue
        probability = count / size
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(1 for value in data if value in PRINTABLE_BYTES)
    return round(printable / len(data), 4)


def hex_preview(data: bytes, limit: int = 64) -> str:
    return data[:limit].hex()


def text_preview(text: str, limit: int = 180) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def decode_bytes(raw: bytes) -> tuple[str, str]:
    try:
        return raw.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace"), "latin-1"


def iter_printable_spans(
    data: bytes,
    *,
    min_run: int = 8,
    max_fragments: int = 5000,
) -> tuple[list[tuple[int, bytes]], bool]:
    spans: list[tuple[int, bytes]] = []
    start: int | None = None
    current = bytearray()
    truncated = False

    for offset, value in enumerate(data):
        if value in PRINTABLE_BYTES:
            if start is None:
                start = offset
            current.append(value)
            continue
        if start is not None and len(current) >= min_run:
            spans.append((start, bytes(current)))
            if len(spans) >= max_fragments:
                truncated = True
                break
        start = None
        current.clear()

    if not truncated and start is not None and len(current) >= min_run:
        spans.append((start, bytes(current)))
        if len(spans) > max_fragments:
            spans = spans[:max_fragments]
            truncated = True

    return spans, truncated


def normalize_key(value: str) -> str:
    return "".join(character.lower() for character in value if character.isalnum())


def to_jsonable(value: Any) -> Any:
    if is_dataclass(value):
        return to_jsonable(asdict(value))
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


def write_json(path: Path, payload: Any, pretty: bool = False) -> None:
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8") as handle:
        if pretty:
            json.dump(to_jsonable(payload), handle, indent=2, sort_keys=False)
        else:
            json.dump(
                to_jsonable(payload),
                handle,
                separators=(",", ":"),
                sort_keys=False,
            )
        handle.write("\n")


def write_text(path: Path, content: str) -> None:
    ensure_directory(path.parent)
    path.write_text(content, encoding="utf-8")
