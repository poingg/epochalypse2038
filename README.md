# Epochalypse Network Scanner

Epochalypse is a comprehensive Y2K38/epoch rollover vulnerability scanner that performs deep inventory analysis of your network to identify hosts running 32‑bit time implementations. It combines multi-layered detection techniques including TCP/UDP probing, SNMP HOST-RESOURCES-MIB querying, SMB interrogation, TLS protocol analysis, MAC vendor lookup, IPMI detection, banner analysis, hardware heuristics, and optional LLM-based reasoning to accurately prioritize which systems need remediation before January 2038.

## Versions

Please check file [VERSIONS.md](VERSIONS.md)

## Features

### Core Scanning Capabilities

- **Multi-protocol fingerprinting** across curated TCP (`21,22,23,25,80,110,143,443,445,3306,3389,5432,8080,8443`) and UDP (`53,123,161,500,514,623,1900`) ports
- **Enhanced SNMP querying** including HOST-RESOURCES-MIB for CPU detection (hrDeviceDescr), RAM size (hrMemorySize), and hardware metrics
- **SMB OS metadata extraction** with Windows version parsing (NT 5.x detection) and Samba version analysis
- **TLS/SSL protocol version detection** to identify legacy-only endpoints (SSLv3/TLS1.0)
- **MAC address vendor lookup** using macvendors.com API with local caching to identify legacy hardware manufacturers
- **IPMI/BMC detection** for server management interfaces (port 623 UDP)
- **HTTP header analysis** extracting Server, X-Powered-By, and other version indicators
- **NTP behavioral analysis** checking version, REFID patterns, and stratum for legacy firmware

### Advanced Detection Heuristics

- **Expanded architecture detection** with 60+ patterns including ELF 32/64-bit, ARMv5tel, MIPS32, uClibc, Windows NT 5.x, WOW64
- **Memory limit analysis** flagging systems with ≤4GB RAM as likely 32-bit
- **SNMP sysObjectID mapping** to 19+ known embedded device families (Cisco, Linksys, HP, etc.)
- **Service version-to-year mapping** for 50+ service versions (Postfix, Exchange, ProFTPD, Samba, nginx, OpenSSL, etc.)
- **Hostname hint extraction** analyzing DNS names for OS/device clues
- **Refined confidence scoring** weighted by evidence quality (MAC vendor: 0.10, HR-MIB: 0.25, direct architecture: 0.30, etc.)

### Reporting & Integration

- **Risk scoring (0‑100)** with vulnerability level classification (safe → critical)
- **Progress reporting** to stderr with detailed text, JSON, or CSV reports for downstream tooling
- **Optional LLM assessment** (OpenAI-compatible) for high-risk hosts to provide mitigation context
- **Exit code integration** (exits 1 when vulnerable/critical hosts found) for CI/pipeline checks

## Requirements

- **Python 3.10+** (uses modern typing features such as `list[int]`)
- **Network reachability** to the target CIDR range and permissions for the probes you enable
- **System tools**: `arp` command for MAC address discovery (present on macOS/Linux/Windows)
- **Dependencies** (install via `pip install -r requirements.txt`):
  - `pysnmp` - async SNMP queries including HOST-RESOURCES-MIB
  - `impacket` - SMB negotiation and OS detection
  - `requests` - LLM integration and MAC vendor API calls

## Quick Start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python epochalypse_scanner.py 192.168.1.0/24 --snmp-community public --format text
```

The script prints progress updates to stderr and the selected report format to stdout (or to `--output` if provided). The exit code is `1` when any host is classified as `vulnerable` or `critical`, making it easy to integrate into CI/pipeline checks.

## Key Arguments

| Flag | Description |
| --- | --- |
| `cidr` | Required. Target range, e.g., `10.0.0.0/24` or `192.0.2.10/32`. |
| `--tcp-ports` / `--udp-ports` | Comma-separated overrides for the default curated lists. Use `--disable-udp` to skip UDP entirely. |
| `--workers` | Thread pool size for concurrent host scans (default 50). |
| `--snmp-community` | Enables SNMPv2c queries with the supplied community string. **Highly recommended** for best detection. |
| `--disable-smb` | Skip SMB OS fingerprinting (enabled by default). |
| `--format` | `text`, `json`, or `csv` (default `text`). |
| `--output` | Path to save the report; otherwise the report prints to stdout. |
| `--llm-api-key` | Optional LLM-based reasoning for any host rated potentially vulnerable or worse. |
| `--llm-model` | LLM model to use (default: `gpt-4.1-mini`). |

See `python epochalypse_scanner.py --help` for the full option list and in-script documentation.

## Output Overview

- **Text:** Human-friendly report sorted by risk score, showing discovered services, SNMP/SMB details, TLS configuration, MAC vendor, memory size, CPU info, heuristics, and remediation pointers.
- **JSON:** Structured array of host fingerprints (matches `HostFingerprint.to_dict`) suitable for ingestion into SIEM/CMDB workflows.
- **CSV:** Tabular summary with key risk fields including MAC vendor, TLS legacy status, IPMI detection, and confidence scores for spreadsheet review.

## Detection Methods & Accuracy

The scanner uses a multi-layered approach to maximize detection accuracy:

1. **Architecture Detection** (30% confidence weight): Direct evidence from banners, SNMP sysDescr, SMB NativeOS
2. **SNMP HOST-RESOURCES-MIB** (25% weight): CPU type, memory size, storage capacity - strongest evidence
3. **Service Version Dating** (15% weight): 50+ version→year mappings across common services
4. **MAC Vendor Lookup** (10% weight): Identifies legacy hardware manufacturers correlated with 32-bit systems
5. **TLS/Protocol Behavior** (10% weight): Legacy SSL/TLS indicates old crypto libraries (typically 32-bit)
6. **Memory/Resource Limits** (automatic upgrade): Systems with <4GB RAM are almost certainly 32-bit
7. **OID-based Device Identification**: Known embedded hardware patterns from SNMP sysObjectID

**Confidence Thresholds:**

- **High (≥70%)**: Direct architecture evidence + SNMP HR-MIB + service versions
- **Medium (40-70%)**: Architecture detection + multiple service fingerprints
- **Low (<40%)**: Limited banner information or unknown architecture

## MAC Vendor Lookup

The scanner integrates with the **macvendors.com API** (free tier: 1000 requests/day, 1 req/sec) to identify hardware manufacturers. Results are cached locally in `.mac_vendor_cache.json` to minimize API calls. Legacy vendors (3Com, Linksys, Netgear, D-Link, older Cisco) correlate strongly with 32-bit embedded systems.

No API key required for basic usage.

## LLM Integration

Provide `--llm-api-key` (and optionally `--llm-model`) to have high-risk hosts analyzed by an LLM for probability assessment, confidence evaluation, risk factors, and specific recommendations. The scanner only shares truncated banners/metadata and never raw packet data. Disable this option if outbound API calls are not permitted in your environment.

## Responsible Use

**Only scan networks that you own or have explicit permission to assess.** Some probes (especially SNMP/SMB/IPMI) may trigger alerts on monitored systems; coordinate with your operations or security team before running large sweeps.

**Privacy Notice:** The MAC vendor lookup feature makes outbound HTTPS requests to macvendors.com. Disable this by commenting out the MAC lookup code if this violates your network policies.
