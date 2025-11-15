# Epochalypse Scanner - Project Structure

## File Structure

```text
epochalypse2038/
├── epochalypse_scanner.py    # Main entry point and orchestration
├── config.py                  # All configuration constants
├── models.py                  # Data models (HostFingerprint, VulnerabilityLevel)
├── scanning.py                # Network scanning functions
├── risk_scoring.py            # Risk analysis and scoring
├── llm_integration.py         # LLM-based assessment
├── reporting.py               # Report generation (text/JSON/CSV)
└── requirements.txt           # Python dependencies
```

## Module Overview

### `config.py`

Central configuration file containing:

- **Port lists**: DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS (easily add/remove ports)
- **SNMP OIDs**: SNMP_OIDS dictionary, KNOWN_DEVICE_OIDS (add new device signatures)
- **Service versions**: SERVICE_VERSION_YEARS (add version→year mappings)
- **Architecture patterns**: ARCH_64BIT_PATTERNS, ARCH_32BIT_PATTERNS
- **Detection keywords**: EMBEDDED_DEVICE_KEYWORDS, OS_PATTERNS
- **Risk thresholds**: RISK_THRESHOLDS, CONFIDENCE_WEIGHTS
- **Timeout settings**: CONNECT_TIMEOUT, READ_TIMEOUT, UDP_TIMEOUT

### `models.py`

Data structures:

- `VulnerabilityLevel`: Enum for risk levels
- `HostFingerprint`: Complete host scan results

### `scanning.py`

Network scanning functions:

- TCP/UDP port scanning
- SNMP querying
- SMB probing
- MAC address lookup
- TLS/SSL analysis
- IPMI detection
- HTTP header extraction

### `risk_scoring.py`

Risk analysis functions:

- Architecture detection
- OS type detection
- Service version aging
- Risk score calculation
- Confidence scoring

### `llm_integration.py`

Optional LLM-enhanced assessment:

- OpenAI-compatible API integration
- Structured vulnerability analysis

### `reporting.py`

Report generation:

- Text report (human-readable)
- JSON report (machine-readable)
- CSV report (spreadsheet-ready)

### `epochalypse_scanner.py`

Main orchestration:

- Command-line interface
- Multi-threaded scanning
- Report generation and output

## How to Extend

### Adding New Ports

Edit `config.py`:

```python
DEFAULT_TCP_PORTS = [
    21, 22, 23, 25, 80, 443, 445,
    3306,  # MySQL
    5900,  # VNC - ADD THIS
]
```

### Adding New SNMP Device Signatures

Edit `config.py`:

```python
KNOWN_DEVICE_OIDS = {
    "1.3.6.1.4.1.9.1.107": ("cisco_router", True, "Cisco 2600 series router"),
    # Add new device:
    "1.3.6.1.4.1.XXXX": ("device_type", is_32bit, "Description"),
}
```

### Adding New Service Version Mappings

Edit `config.py`:

```python
SERVICE_VERSION_YEARS = {
    "nginx/1.0": 2011,
    # Add new mapping:
    "apache/2.4": 2012,
}
```

### Adding New Architecture Detection Patterns

Edit `config.py`:

```python
ARCH_32BIT_PATTERNS = [
    "i386", "i486", "i686",
    # Add new pattern:
    "armv7l",
]
```

### Modifying Risk Scoring Logic

Edit `risk_scoring.py` in the `calculate_risk_score()` function to add new detection methods or adjust scoring weights.

### Adding New Scanning Methods

1. Add function to `scanning.py`
2. Call it from `scan_host()` in `epochalypse_scanner.py`
3. Use results in `calculate_risk_score()` in `risk_scoring.py`

## Usage

No changes to usage - the command-line interface is identical:

```bash
# Basic scan
python epochalypse_scanner.py 192.168.1.0/24

# Full scan with all options
python epochalypse_scanner.py 192.168.1.0/24 \
  --snmp-community public \
  --workers 16 \
  --format json \
  --output report.json
```
