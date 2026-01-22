# Changelog
All notable changes to this project will be documented in this file.

This project follows a pragmatic versioning approach suitable for standalone
scripts used in controlled environments.

---

## [1.0.0] – Initial Public Release
### Added
- Standalone CLI script `stig_patch_cycle_analyzer.py`
- Parsing of DISA STIG manuals in XCCDF (Extensible Configuration Checklist Description Format)
- Recursive parsing of:
  - Standalone STIG ZIP files
  - Nested ZIPs inside STIG libraries
- Generation of:
  - `STIG_MANUALS_OVERVIEW.csv`
  - `STIG_MANUALS_SPECIFICATIONS.csv`
- Normalization of:
  - Benchmark dates
  - Severity weights
  - Rule identifiers
- Deterministic run folders with optional user-supplied run IDs
- `LATEST_RUN.txt` pointer file
- Delta comparison mode between previous and current runs
- Delta outputs:
  - `DELTA_OVERVIEW.csv`
  - `DELTA_VULNS.csv`
- JSON equivalents:
  - `DELTA_OVERVIEW.json`
  - `DELTA_VULNS.json`
- Delta-only execution mode (no library crawl required)
- Field-level change detection for:
  - Versions
  - Revisions
  - Benchmark dates
  - Vulnerability counts
  - Severity, weight, rule title
  - CCI references and legacy IDs (order-insensitive)
- Executive patch-cycle summary generation:
  - `RUN_SUMMARY.txt`
  - `DELTA_ONLY_SUMMARY.txt`
- SHA-256 checksum generation:
  - `CHECKSUMS.sha256`
- Checksums include:
  - Script file
  - CSV outputs
  - JSON and JSONL outputs
  - Summary files
- Support for CSV comment preambles
- Robust CSV parsing with header detection
- Documentation updates for:
  - XCCDF format scope
  - Federal environment constraints
  - Distribution without installation

### Notes
- Script intentionally avoids packaging, installation, or external dependencies
- Designed for controlled and air-gapped environments
- Compatible with change-control and security review processes

---
