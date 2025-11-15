#!/usr/bin/env python3
"""
Data models for Epochalypse Scanner
"""

from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Any


class VulnerabilityLevel(Enum):
    """Risk levels for Y2K38 vulnerability"""
    SAFE = "safe"
    LIKELY_SAFE = "likely_safe"
    UNKNOWN = "unknown"
    POTENTIALLY_VULNERABLE = "potentially_vulnerable"
    VULNERABLE = "vulnerable"
    CRITICAL = "critical"


@dataclass
class HostFingerprint:
    """Complete fingerprint of a scanned host"""
    ip: str
    hostname: str | None = None
    mac_address: str | None = None
    mac_vendor: str | None = None
    discovered_ports: set[int] = field(default_factory=set)
    tcp_services: list[dict[str, Any]] = field(default_factory=list)
    udp_services: list[dict[str, Any]] = field(default_factory=list)
    snmp_info: dict[str, Any] | None = None
    smb_info: dict[str, Any] | None = None
    ntp_info: dict[str, Any] | None = None
    tls_info: dict[str, Any] | None = None
    ipmi_info: dict[str, Any] | None = None
    http_headers: dict[str, Any] | None = None
    architecture: str = "unknown"
    cpu_info: str | None = None
    os_type: str | None = None
    os_version: str | None = None
    approx_age_year: int | None = None
    embedded_device: bool = False
    hostname_hints: list[str] = field(default_factory=list)
    vulnerability_level: VulnerabilityLevel = VulnerabilityLevel.UNKNOWN
    risk_score: int = 50
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    llm_assessment: dict[str, Any] | None = None
    scan_timestamp: str = field(
        default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        data = asdict(self)
        data['vulnerability_level'] = self.vulnerability_level.value
        # Convert set to list for JSON serialization
        data['discovered_ports'] = list(data['discovered_ports'])
        return data
