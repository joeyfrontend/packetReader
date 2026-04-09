# Packet Tracer `.pkt` Converter

This project converts a Cisco Packet Tracer `.pkt` file into raw structured JSON that later systems can consume for visualization, validation, search, diffing, or AI-assisted analysis.

The current focus is a deterministic decode pipeline first, with heuristics only as a fallback. For Packet Tracer files that match the known reverse-engineered format, the parser follows the `ptexplorer` decoding model: XOR deobfuscation, 4-byte uncompressed-size header, zlib decompression, XML parse, then structured extraction.

The decoder is now registry-based, so the tool can try multiple deterministic strategies before giving up and falling back:

- legacy XOR + zlib + XML
- direct XML detection
- gzip stream carving
- zlib stream carving

When a `.pkt` file does not match any current deterministic strategy, the project falls back to the heuristic recovery path so extraction still degrades gracefully instead of crashing.

## What It Produces

By default the CLI writes:

- `output/raw_dump.json`
- `output/normalized_topology.json`
- `output/extraction_report.json`

Optional debug and helper outputs:

- `output/debug/decoded.xml` when deterministic `.pkt` decoding succeeds in `--debug` mode
- `output/debug/` intermediate decoded chunks and decompressed payloads from the fallback heuristic scanner when `--debug` is enabled
- `output/recovered_text.txt` when `--strings` is enabled
- `output/investigation/` pairwise trial-family binary diff reports when running `app.investigation.binary_diff`

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

Run the trial-family binary investigation pass:

```bash
python -m app.investigation.binary_diff --out output/investigation --pretty
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
- [`app/decoders/`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/decoders) pluggable deterministic decoder strategies and registry
- [`app/inspector.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/inspector.py) file metadata, signatures, entropy, version hints
- [`app/pkt_decoder.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/pkt_decoder.py) deterministic Packet Tracer XOR + zlib decode path
- [`app/xml_parser.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/xml_parser.py) XML-first device/interface/link/config extraction
- [`app/decoder.py`](/c:/Users/HMI/Desktop/vibeCoding/windowsApps/packetReader/app/decoder.py) fallback printable string recovery, XML/config classification, safe decompression attempts
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

Primary path:

- try registered deterministic decoders in order
- reverse Packet Tracer XOR obfuscation using decreasing file-size keying
- read the first 4 decoded bytes as the uncompressed XML size header
- zlib decompress the remaining payload
- attempt direct XML detection for XML-like files
- carve gzip or zlib streams that may contain embedded XML
- decode the XML text and persist `output/debug/decoded.xml` in debug mode when a strategy succeeds

Fallback path:

- printable ASCII/UTF-8/Latin-1 span extraction
- XML/config/structured-text classification
- safe attempts to decompress gzip, zlib, bzip2, and zip-like blocks
- debug artifact export for decoded spans and decompressed payloads

### Stage C: Extraction

- XML-first extraction for Packet Tracer device, interface, config, link, and note structures
- device candidates
- interface candidates
- config text blocks
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
- deterministic decode details and decoded XML when available
- decoded chunks and text fragments from the fallback path when used
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
- decode pipeline path used: deterministic XML or heuristic fallback
- deterministic strategy attempts with success/failure reasons
- recognized object counts
- missing field counts
- suspicious sections
- warnings, recoverable errors, fatal errors
- verbose trace entries when debug mode is on

## Current Limitations

- the deterministic XOR+zlib path is based on known reverse-engineering work and may not match every Packet Tracer generation
- current deterministic strategies still do not decode every modern `.pkt` file
- some `.pkt` files may still require the heuristic fallback path
- binary object models are not fully reverse-engineered beyond the XML container decode
- XML extraction is defensive and does not yet reconstruct every nested Packet Tracer object type
- positions, models, and protocol detail may still be absent if not directly recoverable from XML or config blocks

## Known Version-Compatibility Risks

- Packet Tracer may change serialization layout across releases
- text and XML fragments may move, compress differently, or disappear entirely
- object and attribute naming may vary between versions
- some labs may contain mostly binary records, reducing heuristic recovery quality

The extraction report and raw dump are meant to make those differences visible instead of hiding them.

## Reverse-Engineering Reference

The deterministic decode implementation is informed by `axcheron/ptexplorer`, which documents the known Packet Tracer XOR + zlib + size-header format for older `.pkt/.pka` files:

- GitHub repository: https://github.com/axcheron/ptexplorer
- Reverse-engineering notes: the README describes each byte being XORed with a decreasing file-size key and notes that the first 4 decoded bytes hold the uncompressed XML size

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
