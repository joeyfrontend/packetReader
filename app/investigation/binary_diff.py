from __future__ import annotations

import argparse
import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..oracle import get_oracle_for_file
from ..utils import (
    current_timestamp,
    ensure_directory,
    hex_preview,
    iter_printable_spans,
    printable_ratio,
    shannon_entropy,
    write_json,
)


WINDOW_SIZE = 256
NEARBY_CONTEXT = 96
TOP_REGION_COUNT = 8


@dataclass(frozen=True, slots=True)
class FileSample:
    name: str
    path: Path
    data: bytes


def _detect_signatures(data: bytes, *, base_offset: int = 0) -> list[dict[str, Any]]:
    signatures: list[dict[str, Any]] = []
    probes = (
        (b"\x1f\x8b", "gzip"),
        (b"\x78\x01", "zlib"),
        (b"\x78\x9c", "zlib"),
        (b"\x78\xda", "zlib"),
        (b"PK\x03\x04", "zip"),
        (b"BZh", "bzip2"),
        (b"<?xml", "xml"),
    )
    for needle, kind in probes:
        offset = data.find(needle)
        if offset >= 0:
            signatures.append(
                {
                    "kind": kind,
                    "offset": offset,
                    "absolute_offset": base_offset + offset,
                }
            )
    return signatures


def _collect_printable_strings(data: bytes, *, limit: int = 6) -> list[str]:
    spans, _ = iter_printable_spans(data, min_run=4, max_fragments=64)
    strings: list[str] = []
    for _, raw in spans[:limit]:
        text = raw.decode("latin-1", errors="replace").strip()
        if text:
            strings.append(text[:80])
    return strings


def _byte_difference_ratio(left: bytes, right: bytes) -> float:
    if not left and not right:
        return 0.0
    overlap = min(len(left), len(right))
    mismatches = 0
    for index in range(overlap):
        if left[index] != right[index]:
            mismatches += 1
    mismatches += abs(len(left) - len(right))
    return round(mismatches / max(len(left), len(right)), 4)


def _extract_region(data: bytes, start: int, end: int) -> bytes:
    return data[max(0, start) : max(0, end)]


def _summarize_region_bytes(data: bytes, *, base_offset: int = 0) -> dict[str, Any]:
    return {
        "size": len(data),
        "entropy": shannon_entropy(data),
        "printable_ratio": printable_ratio(data),
        "nearby_printable_strings": _collect_printable_strings(data),
        "nearby_hex_preview": hex_preview(data, limit=64),
        "signatures": _detect_signatures(data, base_offset=base_offset),
    }


def _classify_region(
    *,
    start_offset: int,
    size: int,
    entropy: float,
    printable: float,
    signatures: list[dict[str, Any]],
    strings: list[str],
    pair_focus: str,
) -> str:
    lower_strings = " ".join(strings).lower()
    if start_offset < 256 and size <= 256:
        return "metadata"
    if any(item["kind"] in {"gzip", "zlib", "zip", "bzip2"} for item in signatures):
        return "compressed_payload"
    if printable >= 0.55 and any(
        marker in lower_strings
        for marker in ("ip", "mask", "gateway", "router", "switch", "gigabit", "fastethernet")
    ):
        return "config_payload"
    if pair_focus == "single_ip_change" and size <= 256:
        return "config_payload"
    if pair_focus == "topology_expansion" and size >= 128:
        return "topology_payload"
    if entropy >= 7.4 and printable <= 0.2:
        return "compressed_payload"
    return "unknown"


def _window_change_density(left: bytes, right: bytes) -> list[dict[str, Any]]:
    windows: list[dict[str, Any]] = []
    max_size = max(len(left), len(right))
    for start in range(0, max_size, WINDOW_SIZE):
        left_window = left[start : start + WINDOW_SIZE]
        right_window = right[start : start + WINDOW_SIZE]
        ratio = _byte_difference_ratio(left_window, right_window)
        if ratio == 0.0:
            continue
        windows.append(
            {
                "start_offset": start,
                "end_offset": start + max(len(left_window), len(right_window)),
                "size": max(len(left_window), len(right_window)),
                "percent_changed": round(ratio * 100, 2),
                "left_entropy": shannon_entropy(left_window),
                "right_entropy": shannon_entropy(right_window),
            }
        )
    windows.sort(key=lambda item: (-item["percent_changed"], item["start_offset"]))
    return windows


def _pair_focus(left_name: str, right_name: str) -> str:
    names = {left_name.lower(), right_name.lower()}
    if names == {"trial.pkt", "trial-ipchange.pkt"}:
        return "single_ip_change"
    if "trial-router.pkt" in names and "trial.pkt" in names:
        return "topology_expansion"
    if "trial-router.pkt" in names and "trial-ipchange.pkt" in names:
        return "router_and_ip_change"
    return "general"


def _oracle_delta(left_name: str, right_name: str) -> dict[str, Any]:
    left = get_oracle_for_file(left_name)
    right = get_oracle_for_file(right_name)
    if left is None or right is None:
        return {}

    left_devices = {device.name for device in left.devices}
    right_devices = {device.name for device in right.devices}
    left_links = {tuple(sorted((link.left, link.right))) for link in left.links}
    right_links = {tuple(sorted((link.left, link.right))) for link in right.links}

    def exact_ips(oracle_name: str) -> set[tuple[str, str]]:
        oracle = get_oracle_for_file(oracle_name)
        if oracle is None:
            return set()
        values: set[tuple[str, str]] = set()
        for device in oracle.devices:
            values.update((device.name, ip) for ip in device.ips)
            values.update((device.name, interface.ip) for interface in device.interfaces if interface.ip)
        return values

    return {
        "added_devices": sorted(right_devices - left_devices),
        "removed_devices": sorted(left_devices - right_devices),
        "added_links": [list(item) for item in sorted(right_links - left_links)],
        "removed_links": [list(item) for item in sorted(left_links - right_links)],
        "added_ips": [
            {"device": device, "ip": ip}
            for device, ip in sorted(exact_ips(right_name) - exact_ips(left_name))
        ],
        "removed_ips": [
            {"device": device, "ip": ip}
            for device, ip in sorted(exact_ips(left_name) - exact_ips(right_name))
        ],
    }


def _local_vs_global(changed_regions: list[dict[str, Any]], left_size: int, right_size: int) -> str:
    if not changed_regions:
        return "no_change"
    left_changed = sum(region["left"]["size"] for region in changed_regions)
    right_changed = sum(region["right"]["size"] for region in changed_regions)
    coverage = max(
        left_changed / max(left_size, 1),
        right_changed / max(right_size, 1),
    )
    if len(changed_regions) <= 3 and coverage <= 0.08:
        return "local"
    if coverage <= 0.2:
        return "mixed"
    return "global"


def analyze_pair(left_sample: FileSample, right_sample: FileSample) -> dict[str, Any]:
    matcher = difflib.SequenceMatcher(a=left_sample.data, b=right_sample.data)
    opcodes = matcher.get_opcodes()
    focus = _pair_focus(left_sample.name, right_sample.name)

    changed_regions: list[dict[str, Any]] = []
    inserted_regions: list[dict[str, Any]] = []
    deleted_regions: list[dict[str, Any]] = []
    identical_regions: list[dict[str, Any]] = []
    shifted_regions: list[dict[str, Any]] = []

    for tag, left_start, left_end, right_start, right_end in opcodes:
        if tag == "equal":
            size = left_end - left_start
            region = {
                "left_start_offset": left_start,
                "left_end_offset": left_end,
                "right_start_offset": right_start,
                "right_end_offset": right_end,
                "size": size,
                "offset_delta": right_start - left_start,
            }
            identical_regions.append(region)
            if size >= WINDOW_SIZE and left_start != right_start:
                shifted_regions.append(region)
            continue

        left_bytes = _extract_region(left_sample.data, left_start, left_end)
        right_bytes = _extract_region(right_sample.data, right_start, right_end)
        left_near = _extract_region(
            left_sample.data,
            max(0, left_start - NEARBY_CONTEXT),
            min(len(left_sample.data), left_end + NEARBY_CONTEXT),
        )
        right_near = _extract_region(
            right_sample.data,
            max(0, right_start - NEARBY_CONTEXT),
            min(len(right_sample.data), right_end + NEARBY_CONTEXT),
        )
        left_summary = _summarize_region_bytes(
            left_near,
            base_offset=max(0, left_start - NEARBY_CONTEXT),
        )
        right_summary = _summarize_region_bytes(
            right_near,
            base_offset=max(0, right_start - NEARBY_CONTEXT),
        )
        changed = {
            "change_type": tag,
            "left": {
                "start_offset": left_start,
                "end_offset": left_end,
                "size": len(left_bytes),
                "entropy": shannon_entropy(left_bytes),
                "printable_ratio": printable_ratio(left_bytes),
                "nearby_printable_strings": left_summary["nearby_printable_strings"],
                "nearby_hex_preview": left_summary["nearby_hex_preview"],
                "signatures": left_summary["signatures"],
            },
            "right": {
                "start_offset": right_start,
                "end_offset": right_end,
                "size": len(right_bytes),
                "entropy": shannon_entropy(right_bytes),
                "printable_ratio": printable_ratio(right_bytes),
                "nearby_printable_strings": right_summary["nearby_printable_strings"],
                "nearby_hex_preview": right_summary["nearby_hex_preview"],
                "signatures": right_summary["signatures"],
            },
            "percent_changed": round(_byte_difference_ratio(left_bytes, right_bytes) * 100, 2),
        }
        changed["candidate_type"] = _classify_region(
            start_offset=min(left_start, right_start),
            size=max(left_summary["size"], right_summary["size"]),
            entropy=max(left_summary["entropy"], right_summary["entropy"]),
            printable=max(left_summary["printable_ratio"], right_summary["printable_ratio"]),
            signatures=left_summary["signatures"] + right_summary["signatures"],
            strings=left_summary["nearby_printable_strings"] + right_summary["nearby_printable_strings"],
            pair_focus=focus,
        )
        changed_regions.append(changed)
        if tag == "insert":
            inserted_regions.append(changed)
        elif tag == "delete":
            deleted_regions.append(changed)

    changed_regions.sort(
        key=lambda item: (
            -(item["percent_changed"]),
            min(item["left"]["start_offset"], item["right"]["start_offset"]),
        )
    )
    identical_regions.sort(key=lambda item: (-item["size"], item["left_start_offset"]))
    shifted_regions.sort(key=lambda item: (-item["size"], item["left_start_offset"]))

    windows = _window_change_density(left_sample.data, right_sample.data)
    oracle_delta = _oracle_delta(left_sample.name, right_sample.name)
    local_vs_global = _local_vs_global(changed_regions, len(left_sample.data), len(right_sample.data))

    summary = {
        "pair_name": f"{left_sample.path.stem}_vs_{right_sample.path.stem}",
        "generated_at": current_timestamp(),
        "left_file": {"name": left_sample.name, "path": str(left_sample.path), "size": len(left_sample.data)},
        "right_file": {"name": right_sample.name, "path": str(right_sample.path), "size": len(right_sample.data)},
        "oracle_delta": oracle_delta,
        "comparison_stats": {
            "exact_common_prefix_bytes": sum(
                left_end - left_start
                for tag, left_start, left_end, _, _ in opcodes
                if tag == "equal" and left_start == 0
            ),
            "changed_region_count": len(changed_regions),
            "inserted_region_count": len(inserted_regions),
            "deleted_region_count": len(deleted_regions),
            "shifted_region_count": len(shifted_regions),
            "changed_coverage_left_percent": round(
                100 * sum(region["left"]["size"] for region in changed_regions) / max(len(left_sample.data), 1),
                2,
            ),
            "changed_coverage_right_percent": round(
                100 * sum(region["right"]["size"] for region in changed_regions) / max(len(right_sample.data), 1),
                2,
            ),
            "changes_look": local_vs_global,
        },
        "identical_regions": identical_regions[:TOP_REGION_COUNT],
        "shifted_regions": shifted_regions[:TOP_REGION_COUNT],
        "inserted_regions": inserted_regions[:TOP_REGION_COUNT],
        "deleted_regions": deleted_regions[:TOP_REGION_COUNT],
        "changed_regions": changed_regions[:TOP_REGION_COUNT],
        "high_change_windows": windows[:TOP_REGION_COUNT],
        "investigator_notes": _investigator_notes(
            left_sample=left_sample,
            right_sample=right_sample,
            changed_regions=changed_regions,
            windows=windows,
            focus=focus,
            local_vs_global=local_vs_global,
            oracle_delta=oracle_delta,
        ),
    }
    return summary


def _investigator_notes(
    *,
    left_sample: FileSample,
    right_sample: FileSample,
    changed_regions: list[dict[str, Any]],
    windows: list[dict[str, Any]],
    focus: str,
    local_vs_global: str,
    oracle_delta: dict[str, Any],
) -> dict[str, Any]:
    small_local = [
        region
        for region in changed_regions
        if max(region["left"]["size"], region["right"]["size"]) <= 512
    ]
    large_structural = [
        region
        for region in changed_regions
        if max(region["left"]["size"], region["right"]["size"]) >= 512
    ]

    likely_ip_regions = [
        {
            "left_start_offset": region["left"]["start_offset"],
            "right_start_offset": region["right"]["start_offset"],
            "candidate_type": region["candidate_type"],
            "left_strings": region["left"]["nearby_printable_strings"][:3],
            "right_strings": region["right"]["nearby_printable_strings"][:3],
        }
        for region in small_local[:3]
    ]
    likely_router_regions = [
        {
            "left_start_offset": region["left"]["start_offset"],
            "right_start_offset": region["right"]["start_offset"],
            "candidate_type": region["candidate_type"],
            "size": max(region["left"]["size"], region["right"]["size"]),
        }
        for region in large_structural[:3]
    ]

    if focus == "single_ip_change":
        pair_answer = "Small localized change windows are the strongest candidate for the PC IP delta."
    elif focus == "topology_expansion":
        pair_answer = "Large structural regions and inserted coverage are the strongest candidate for router/topology representation."
    else:
        pair_answer = "The pair mixes topology and addressing changes; inspect both localized and structural regions."

    if local_vs_global == "local":
        structure_hypothesis = "multiple_embedded_blocks"
        next_hypothesis = "Look for a nested or indexed payload block near the localized change windows rather than a whole-file transform."
    elif local_vs_global == "global":
        structure_hypothesis = "one_monolithic_encoded_payload"
        next_hypothesis = "Focus on whole-file container transforms or chunk tables before trying finer-grained extraction."
    else:
        structure_hypothesis = "modern_containerized_sections"
        next_hypothesis = "Look for a container with stable headers plus one or more movable payload sections, then test per-section transforms."

    return {
        "pair_focus": focus,
        "semantic_oracle_delta": oracle_delta,
        "likely_ip_change_regions": likely_ip_regions,
        "likely_topology_change_regions": likely_router_regions,
        "change_pattern_assessment": pair_answer,
        "structure_hypothesis": structure_hypothesis,
        "next_decoder_hypothesis": next_hypothesis,
        "top_windows": windows[:3],
        "pair_samples": [left_sample.name, right_sample.name],
    }


def analyze_trial_family(
    sample_dir: Path,
    *,
    output_dir: Path,
    pretty: bool = True,
) -> dict[str, Any]:
    sample_names = ("trial.pkt", "trial-ipchange.pkt", "trial-router.pkt")
    samples = {
        name: FileSample(name=name, path=sample_dir / name, data=(sample_dir / name).read_bytes())
        for name in sample_names
    }
    pairs = (
        ("trial.pkt", "trial-ipchange.pkt", "trial_vs_ipchange.json"),
        ("trial.pkt", "trial-router.pkt", "trial_vs_router.json"),
        ("trial-ipchange.pkt", "trial-router.pkt", "ipchange_vs_router.json"),
    )

    ensure_directory(output_dir)
    pair_reports: dict[str, dict[str, Any]] = {}
    for left_name, right_name, file_name in pairs:
        report = analyze_pair(samples[left_name], samples[right_name])
        pair_reports[file_name] = report
        write_json(output_dir / file_name, report, pretty=pretty)

    family_summary = _build_family_summary(pair_reports)
    write_json(output_dir / "trial_family_summary.json", family_summary, pretty=pretty)
    return family_summary


def _build_family_summary(pair_reports: dict[str, dict[str, Any]]) -> dict[str, Any]:
    ip_report = pair_reports["trial_vs_ipchange.json"]
    router_report = pair_reports["trial_vs_router.json"]
    mixed_report = pair_reports["ipchange_vs_router.json"]

    return {
        "generated_at": current_timestamp(),
        "pair_reports": {
            "trial_vs_ipchange": "trial_vs_ipchange.json",
            "trial_vs_router": "trial_vs_router.json",
            "ipchange_vs_router": "ipchange_vs_router.json",
        },
        "investigator_summary": {
            "likely_pc1_ip_change_regions": ip_report["investigator_notes"]["likely_ip_change_regions"],
            "likely_router_insertion_regions": router_report["investigator_notes"]["likely_topology_change_regions"],
            "change_pattern_hypothesis": {
                "trial_vs_ipchange": ip_report["investigator_notes"]["structure_hypothesis"],
                "trial_vs_router": router_report["investigator_notes"]["structure_hypothesis"],
                "ipchange_vs_router": mixed_report["investigator_notes"]["structure_hypothesis"],
            },
            "overall_structure_assessment": _overall_structure_assessment(
                ip_report=ip_report,
                router_report=router_report,
                mixed_report=mixed_report,
            ),
            "next_decoder_hypothesis": _overall_decoder_hypothesis(
                ip_report=ip_report,
                router_report=router_report,
                mixed_report=mixed_report,
            ),
        },
    }


def _overall_structure_assessment(
    *,
    ip_report: dict[str, Any],
    router_report: dict[str, Any],
    mixed_report: dict[str, Any],
) -> str:
    patterns = {
        ip_report["investigator_notes"]["structure_hypothesis"],
        router_report["investigator_notes"]["structure_hypothesis"],
        mixed_report["investigator_notes"]["structure_hypothesis"],
    }
    if len(patterns) == 1:
        return next(iter(patterns))
    if "modern_containerized_sections" in patterns:
        return "modern_containerized_sections"
    return "mixed_or_inconclusive"


def _overall_decoder_hypothesis(
    *,
    ip_report: dict[str, Any],
    router_report: dict[str, Any],
    mixed_report: dict[str, Any],
) -> str:
    if ip_report["comparison_stats"]["changes_look"] == "local" and router_report["comparison_stats"]["changes_look"] != "local":
        return (
            "The evidence favors a modern container with stable framing and one or more inner payload sections. "
            "Next, carve candidate sections around localized IP-change offsets and compare whether the same outer bytes stay fixed while one inner block mutates."
        )
    if router_report["comparison_stats"]["changes_look"] == "global":
        return (
            "The evidence still allows a whole-file encoded payload. "
            "Next, test chunk tables, length-prefixed sections, or versioned container records before adding new topology heuristics."
        )
    return (
        "The evidence points to multiple encoded sections rather than a pure legacy monolithic XML blob. "
        "Next, inspect repeated headers and offset-stable blocks across the three files, then attempt per-block transforms at the highest-change windows."
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Investigate Packet Tracer trial-family binaries by comparing byte-level changes."
    )
    parser.add_argument(
        "--samples-dir",
        default="samples",
        help="Directory containing trial.pkt, trial-ipchange.pkt, and trial-router.pkt.",
    )
    parser.add_argument(
        "--out",
        default="output/investigation",
        help="Output directory for investigation JSON reports.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print investigation JSON files.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    analyze_trial_family(
        Path(args.samples_dir),
        output_dir=Path(args.out),
        pretty=args.pretty,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
