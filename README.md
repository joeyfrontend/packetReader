# Packet Tracer `.pkt` Converter

This project converts a Cisco Packet Tracer `.pkt` file into raw structured JSON that later systems can consume for visualization, validation, search, diffing, or AI-assisted analysis.

The current focus is a defensive extraction pipeline, not perfect fidelity for every Packet Tracer release. `.pkt` is treated as an opaque, version-variable container, so the parser is designed to recover as much useful structure as possible while preserving unknown data for later reverse-engineering.

## What It Produces

By default the CLI writes:

- `output/raw_dump.json`
- `output/normalized_topology.json`
- `output/extraction_report.json`

Optional debug and helper outputs:

- `output/debug/` intermediate decoded chunks and decompressed payloads when `--debug` is enabled
- `output/recovered_text.txt` when `--strings` is enabled

## Quick Start

Run the converter:

```bash
python -m app.cli samples/mock_lab.pkt --out output --debug --pretty
```

Readable-strings-only mode:

```bash
python -m app.cli samples/mock_lab.pkt --out output --strings --pretty
```

Run tests:

```bash
python -m unittest discover -s tests -v
```

## CLI Options

- positional input path to the `.pkt` file
- `--out` output directory
- `--debug` enable verbose logging and intermediate debug artifacts
- `--pretty` pretty-print JSON
- `--raw-only` skip normalized topology output
- `--normalized-only` skip raw dump output
- `--report-only` only write the extraction report
- `--strings` extract readable text and write `recovered_text.txt`, skipping topology normalization

## Architecture

The package is split into extendable stages:

- [`app/cli.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/cli.py) command-line entrypoint
- [`app/inspector.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/inspector.py) file metadata, signatures, entropy, version hints
- [`app/decoder.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/decoder.py) printable string recovery, XML/config classification, safe decompression attempts
- [`app/heuristics.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/heuristics.py) device/interface/link/config extraction heuristics
- [`app/parser.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/parser.py) end-to-end orchestration and raw dump assembly
- [`app/normalizer.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/normalizer.py) normalized topology schema generation
- [`app/report.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/report.py) structured report events and extraction summary
- [`app/models.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/models.py) typed dataclasses for pipeline payloads
- [`tests/`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/tests) unit and integration coverage

## Parsing Strategy

### Stage A: Inspection

- file size
- SHA-256
- entropy
- printable-ratio heuristic
- magic/signature scanning
- Packet Tracer version hints if visible in text or XML

### Stage B: Decoding

- printable ASCII/UTF-8/Latin-1 span extraction
- XML/config/structured-text classification
- safe attempts to decompress gzip, zlib, bzip2, and zip-like blocks
- debug artifact export for decoded spans and decompressed payloads

### Stage C: Extraction

- device candidates
- interface candidates
- config text blocks
- XML-derived nodes and links
- loose text heuristics for hostnames, interfaces, IPs, and note-like content
- unmapped blocks retained for follow-up reverse engineering

### Stage D: Normalization

- merge duplicate device evidence
- preserve raw evidence under `raw`
- create placeholder devices when links mention endpoints not yet defined
- assign stable synthetic IDs such as `dev_1`, `int_1`, `link_1`

## Output Semantics

### `raw_dump.json`

Closest-to-source recovered structure before aggressive interpretation:

- inspection metadata
- decoded chunks and text fragments
- observed XML/config fragments
- raw heuristic observables
- extracted device/link/note candidates
- warnings and recoverable errors

### `normalized_topology.json`

Normalized topology model for downstream tools:

- `meta`
- `devices`
- `links`
- `notes`
- `unmapped_blocks`

Unknown or uncertain values are left as `null`, placeholders, or low-confidence entries with raw evidence preserved.

### `extraction_report.json`

Operational summary of the run:

- success or partial failure
- recognized object counts
- missing field counts
- suspicious sections
- warnings, recoverable errors, fatal errors
- verbose trace entries when debug mode is on

## Current Limitations

- `.pkt` internals are not officially documented, so support is heuristic-first
- binary object models are not fully reverse-engineered
- compressed substructures are only probed using common signatures
- XML extraction expects decodable fragments and does not yet reconstruct every nested Packet Tracer object type
- link inference from plain text is intentionally conservative
- positions, models, and protocol detail may be absent if not directly recoverable

## Known Version-Compatibility Risks

- Packet Tracer may change serialization layout across releases
- text and XML fragments may move, compress differently, or disappear entirely
- object and attribute naming may vary between versions
- some labs may contain mostly binary records, reducing heuristic recovery quality

The extraction report and raw dump are meant to make those differences visible instead of hiding them.

## Extending The Parser

Good next steps:

- add dedicated binary record parsers for specific Packet Tracer versions
- improve compressed-block carving and nested container decoding
- enrich device model inference
- add VLAN, routing protocol, subnet, and note extraction
- support diffing two normalized outputs
- build a visualization layer on top of `normalized_topology.json`

## Sample Fixture

A synthetic reverse-engineering fixture lives at [`samples/mock_lab.pkt`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/samples/mock_lab.pkt). It is not a real Packet Tracer export, but it gives the pipeline an end-to-end sample with XML, config text, a link hint, and note content.
