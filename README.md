# Epochalypse Network Scanner

Epochalypse is an enhanced Y2K38/epoch rollover vulnerability scanner that inventories your network and highlights hosts that are still likely to be running 32‑bit time implementations. It combines targeted TCP/UDP probing, SNMP and SMB interrogation, banner analysis, heuristics about operating system age, and optional LLM-based reasoning to prioritize which systems need remediation before January 2038.

## Features
- Multi-protocol fingerprinting across curated TCP (`21,22,23,25,80,110,143,443,445,3306,3389,5432,8080,8443`) and UDP (`53,123,161,500,514,1900`) ports
- SNMPv2c inventory gathering (`sysDescr`, `sysUpTime`, etc.) and SMB OS metadata extraction to improve attribution
- Embedded device/legacy OS heuristics, risk scoring (0‑100), and vulnerability level classification
- Progress reporting to stderr plus selectable text, JSON, or CSV reports for downstream tooling
- Optional LLM (OpenAI-compatible) assessment for high-risk hosts to provide mitigation context

## Requirements
- Python 3.10+ (uses modern typing features such as `list[int]`)
- Network reachability to the target CIDR range and permissions for the probes you enable
- Dependencies (install via `pip install pysnmp impacket requests`)
  - `pysnmp` for async SNMP queries
  - `impacket` for SMB negotiation
  - `requests` for the LLM integration

## Quick Start
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install pysnmp impacket requests
python epochalypse_scanner.py 192.168.1.0/24 --snmp-community public --format text
```

The script prints progress updates to stderr and the selected report format to stdout (or to `--output` if provided). The exit code is `1` when any host is classified as `vulnerable` or `critical`, making it easy to integrate into CI/pipeline checks.

## Key Arguments

| Flag | Description |
| --- | --- |
| `cidr` | Required. Target range, e.g., `10.0.0.0/24` or `192.0.2.10/32`. |
| `--tcp-ports` / `--udp-ports` | Comma-separated overrides for the default curated lists. Use `--disable-udp` to skip UDP entirely. |
| `--workers` | Thread pool size for concurrent host scans (default 50). |
| `--snmp-community` | Enables SNMPv2c queries with the supplied community string. |
| `--disable-smb` | Skip SMB OS fingerprinting (enabled by default). |
| `--format` | `text`, `json`, or `csv` (default `text`). |
| `--output` | Path to save the report; otherwise the report prints to stdout. |
| `--llm-api-key` / `--llm-model` | Adds LLM-based reasoning for any host rated potentially vulnerable or worse. Requires an OpenAI-compatible API endpoint. |

See `python epochalypse_scanner.py --help` for the full option list and in-script documentation.

## Output Overview
- **Text:** Human-friendly report sorted by risk score, showing discovered services, SNMP/SMB details, heuristics, and remediation pointers.
- **JSON:** Structured array of host fingerprints (matches `HostFingerprint.to_dict`) suitable for ingestion into SIEM/CMDB workflows.
- **CSV:** Tabular summary with key risk fields for spreadsheet review.

## LLM Integration
Provide `--llm-api-key` (and optionally `--llm-model`) to have high-risk hosts summarized by an LLM regarding probability, confidence, risk factors, and recommendations. The scanner only shares truncated banners/metadata and never raw packet data. Disable this option if outbound API calls are not permitted in your environment.

## Responsible Use
Only scan networks that you own or have explicit permission to assess. Some probes (especially SNMP/SMB) may trigger alerts on monitored systems; coordinate with your operations or security team before running large sweeps.

