#!/usr/bin/env python3
# pylint: disable=W0718, C0301, W0702
"""
Risk scoring and analysis functions for Epochalypse Scanner
Architecture detection, vulnerability assessment, and confidence calculation
"""

import re
from typing import Any

from models import HostFingerprint, VulnerabilityLevel
from config import (
    KNOWN_DEVICE_OIDS, SERVICE_VERSION_YEARS,
    ARCH_64BIT_PATTERNS, ARCH_32BIT_PATTERNS,
    EMBEDDED_DEVICE_KEYWORDS, OS_PATTERNS,
    TIME_CRITICAL_PORTS, LEGACY_VENDORS,
    RISK_THRESHOLDS, CONFIDENCE_WEIGHTS
)


# ============================================================================
# Architecture Detection
# ============================================================================

def guess_architecture(text: str) -> str:
    """Guess system architecture from text with enhanced pattern matching"""
    t = text.lower()

    # Check 64-bit indicators
    if any(x in t for x in ARCH_64BIT_PATTERNS):
        return "likely_64bit"

    # Check 32-bit indicators
    if any(x in t for x in ARCH_32BIT_PATTERNS):
        return "likely_32bit"

    return "unknown"


def detect_embedded_device(text: str) -> bool:
    """Detect if system appears to be an embedded device"""
    t = text.lower()
    return any(k in t for k in EMBEDDED_DEVICE_KEYWORDS)


def detect_os_type(text: str) -> str | None:
    """Detect operating system from text"""
    t = text.lower()

    for os_name, patterns in OS_PATTERNS.items():
        if any(p in t for p in patterns):
            return os_name

    return None


# ============================================================================
# Version Analysis
# ============================================================================

def extract_ssh_version(banner: str) -> dict[str, Any] | None:
    """Extract SSH implementation and version"""
    m = re.search(r"SSH-\d+\.\d+-([^\s]+)", banner)
    if not m:
        return None

    impl = m.group(1)
    info = {"implementation": impl}

    # Parse OpenSSH version
    openssh_match = re.search(r"OpenSSH[_-]?([0-9]+\.[0-9]+)", impl)
    if openssh_match:
        info["version"] = openssh_match.group(1)
        info["software"] = "OpenSSH"

    # Parse Dropbear version
    dropbear_match = re.search(
        r"dropbear[_-]?([0-9]+\.[0-9]+)", impl, re.IGNORECASE)
    if dropbear_match:
        info["version"] = dropbear_match.group(1)
        info["software"] = "Dropbear"

    return info


def estimate_service_age(fingerprint: HostFingerprint) -> int | None:
    """Estimate approximate age of services based on version detection"""
    year = None
    all_text = []

    # Collect all banners
    for svc in fingerprint.tcp_services + fingerprint.udp_services:
        if svc.get("banner"):
            all_text.append(svc["banner"])

    # Add SNMP description
    if fingerprint.snmp_info and fingerprint.snmp_info.get("sysDescr"):
        all_text.append(fingerprint.snmp_info["sysDescr"])

    # Add SMB OS info
    if fingerprint.smb_info and fingerprint.smb_info.get("os"):
        all_text.append(fingerprint.smb_info["os"])

    # Add HTTP headers if available
    if fingerprint.http_headers:
        if fingerprint.http_headers.get("server"):
            all_text.append(fingerprint.http_headers["server"])
        if fingerprint.http_headers.get("x-powered-by"):
            all_text.append(fingerprint.http_headers["x-powered-by"])

    full_text = "\n".join(all_text).lower()

    # Check against SERVICE_VERSION_YEARS database
    for version_string, release_year in SERVICE_VERSION_YEARS.items():
        if version_string in full_text:
            year = min(year, release_year) if year else release_year

    # OpenSSH version mapping
    for svc in fingerprint.tcp_services:
        if svc.get("port") == 22 and svc.get("banner"):
            ssh_info = extract_ssh_version(svc["banner"])
            if ssh_info and ssh_info.get("software") == "OpenSSH":
                try:
                    version = ssh_info.get("version", "")
                    major = int(version.split(".")[0])

                    # Rough OpenSSH release year mapping
                    if major <= 3:
                        year = min(year, 2002) if year else 2002
                    elif major == 4:
                        year = min(year, 2005) if year else 2005
                    elif major == 5:
                        year = min(year, 2008) if year else 2008
                    elif major == 6:
                        year = min(year, 2012) if year else 2012
                    elif major == 7:
                        year = min(year, 2016) if year else 2016
                except:
                    pass

    # Web server version mapping
    if "microsoft-iis/5" in full_text:
        year = min(year, 2000) if year else 2000
    elif "microsoft-iis/6" in full_text:
        year = min(year, 2003) if year else 2003
    elif "microsoft-iis/7" in full_text:
        year = min(year, 2008) if year else 2008

    # Apache version
    apache_match = re.search(r"apache/([0-9])\.([0-9])", full_text)
    if apache_match:
        major = int(apache_match.group(1))
        if major == 1:
            year = min(year, 1999) if year else 1999
        elif major == 2:
            year = min(year, 2002) if year else 2002

    # Windows OS mapping
    if "windows 2000" in full_text:
        year = min(year, 2000) if year else 2000
    elif "windows xp" in full_text:
        year = min(year, 2001) if year else 2001
    elif "windows 2003" in full_text or "windows server 2003" in full_text:
        year = min(year, 2003) if year else 2003
    elif "windows vista" in full_text:
        year = min(year, 2007) if year else 2007
    elif "windows 7" in full_text:
        year = min(year, 2009) if year else 2009

    return year


# ============================================================================
# Risk Scoring
# ============================================================================

def calculate_risk_score(fingerprint: HostFingerprint) -> None:
    """Calculate Y2K38 risk score and vulnerability level with comprehensive detection"""
    base_score = 50
    reasons = []
    evidence = []

    # Collect all text for analysis
    all_text = []
    for svc in fingerprint.tcp_services + fingerprint.udp_services:
        if svc.get("banner"):
            all_text.append(svc["banner"])

    if fingerprint.snmp_info:
        for _, value in fingerprint.snmp_info.items():
            all_text.append(str(value))

    if fingerprint.smb_info:
        for _, value in fingerprint.smb_info.items():
            all_text.append(str(value))

    if fingerprint.http_headers and fingerprint.http_headers.get("server"):
        all_text.append(fingerprint.http_headers["server"])

    combined_text = "\n".join(all_text)

    # Determine architecture and basic properties
    fingerprint.architecture = guess_architecture(combined_text)
    fingerprint.embedded_device = detect_embedded_device(combined_text)
    fingerprint.os_type = detect_os_type(combined_text)
    fingerprint.approx_age_year = estimate_service_age(fingerprint)

    # Extract CPU info from SNMP if available
    if fingerprint.snmp_info:
        for key in ["hrDeviceDescr1", "hrDeviceDescr2"]:
            if key in fingerprint.snmp_info:
                fingerprint.cpu_info = fingerprint.snmp_info[key]
                all_text.append(fingerprint.cpu_info)
                break

    # Check SNMP sysObjectID for known embedded hardware
    if fingerprint.snmp_info and "sysObjectID" in fingerprint.snmp_info:
        oid = fingerprint.snmp_info["sysObjectID"]
        for oid_prefix, (_device_type, is_32bit, description) in KNOWN_DEVICE_OIDS.items():
            if oid.startswith(oid_prefix):
                fingerprint.embedded_device = True
                if is_32bit:
                    fingerprint.architecture = "likely_32bit"
                reasons.append(f"Identified as {description} via SNMP OID")
                evidence.append(f"Known device: {description}")
                base_score += 20
                break

    # Check memory size from SNMP (hrMemorySize in KB)
    if fingerprint.snmp_info and "hrMemorySize" in fingerprint.snmp_info:
        try:
            mem_kb = int(fingerprint.snmp_info["hrMemorySize"])
            mem_gb = mem_kb / (1024 * 1024)

            if mem_gb <= 4:
                base_score += 25
                reasons.append(
                    f"System has ≤4GB RAM ({mem_gb:.1f}GB) - likely 32-bit")
                evidence.append(
                    f"Memory limit: {mem_gb:.1f}GB indicates 32-bit system")
                if fingerprint.architecture == "unknown":
                    fingerprint.architecture = "likely_32bit"
        except:
            pass

    # Parse Windows version from SMB
    if fingerprint.smb_info and fingerprint.smb_info.get("os"):
        os_str = fingerprint.smb_info["os"].lower()

        # Windows NT 5.x = 2000/XP/2003 (32-bit era)
        if any(x in os_str for x in ["windows 5.0", "windows 5.1", "windows 5.2", "windows nt 5"]):
            base_score += 30
            reasons.append("Windows 2000/XP/2003 detected via SMB")
            evidence.append("Legacy Windows NT 5.x - 32-bit OS")

            # Unless explicitly x64 Edition
            if "x64" not in os_str and "64-bit" not in os_str:
                fingerprint.architecture = "likely_32bit"

        # Samba < 4.0
        samba_match = re.search(r"samba[  ]?([0-3])\.", os_str)
        if samba_match:
            base_score += 20
            reasons.append("Old Samba version detected (< 4.0)")
            evidence.append("Samba 3.x or older - typically 32-bit era")

    # Check TLS/SSL configuration
    if fingerprint.tls_info:
        if fingerprint.tls_info.get("legacy_only"):
            base_score += 20
            reasons.append(
                "Only legacy SSL/TLS protocols supported (SSLv3/TLS1.0)")
            evidence.append("Legacy TLS - indicates old 32-bit SSL library")

    # Check NTP version and behavior
    if fingerprint.ntp_info:
        ntp_version = fingerprint.ntp_info.get("version", 4)
        refid = fingerprint.ntp_info.get("refid", "")

        if ntp_version <= 3:
            base_score += 15
            reasons.append("NTP version 3 or older detected")
            evidence.append("NTPv3 - typically pre-2008 firmware")

        if refid in ["LOCL", "INIT", "locl", "init"]:
            base_score += 10
            reasons.append(f"Legacy NTP REFID detected: {refid}")
            evidence.append("Legacy NTP configuration")

    # Check IPMI/BMC presence
    if fingerprint.ipmi_info:
        base_score += 15
        reasons.append("IPMI/BMC interface detected")
        evidence.append("Server BMC often runs 32-bit firmware")

    # MAC vendor analysis
    if fingerprint.mac_vendor:
        vendor_lower = fingerprint.mac_vendor.lower()

        if any(v in vendor_lower for v in LEGACY_VENDORS):
            base_score += 10
            reasons.append(f"Legacy hardware vendor: {fingerprint.mac_vendor}")
            evidence.append(
                f"Vendor {fingerprint.mac_vendor} associated with older equipment")

    # Hostname hints
    if fingerprint.hostname_hints:
        base_score += 5 * len(fingerprint.hostname_hints)
        for hint in fingerprint.hostname_hints:
            reasons.append(f"Hostname hint: {hint}")
            evidence.extend(fingerprint.hostname_hints)

    # Architecture-based scoring
    if fingerprint.architecture == "likely_64bit":
        base_score -= 30
        reasons.append(
            "System appears to use 64-bit architecture (x86_64/amd64/arm64)")
        evidence.append("64-bit architecture detected")
    elif fingerprint.architecture == "likely_32bit":
        base_score += 30
        reasons.append(
            "System appears to use 32-bit architecture (i686/armv7/mips)")
        evidence.append("32-bit architecture detected - HIGH RISK")
    else:
        reasons.append("Architecture could not be determined from banners")

    # Age-based scoring
    if fingerprint.approx_age_year:
        if fingerprint.approx_age_year <= 2005:
            base_score += 25
            reasons.append(
                f"Service versions suggest pre-2005 system (≈{fingerprint.approx_age_year})")
            evidence.append(
                f"Very old services detected (~{fingerprint.approx_age_year})")
        elif fingerprint.approx_age_year <= 2010:
            base_score += 15
            reasons.append(
                f"Service versions suggest 2005-2010 era (≈{fingerprint.approx_age_year})")
            evidence.append(
                f"Old services detected (~{fingerprint.approx_age_year})")
        elif fingerprint.approx_age_year <= 2015:
            base_score += 5
            reasons.append(
                f"Service versions suggest 2010-2015 era (≈{fingerprint.approx_age_year})")

    # Check for ancient SSH versions
    for svc in fingerprint.tcp_services:
        if svc.get("port") == 22 and svc.get("banner"):
            banner_lower = svc["banner"].lower()
            if any(x in banner_lower for x in ["openssh_1.", "openssh_2.", "openssh_3."]):
                base_score += 20
                reasons.append("Ancient OpenSSH version detected (pre-4.x)")
                evidence.append("Critically outdated SSH implementation")

    # Embedded device scoring
    if fingerprint.embedded_device:
        base_score += 15
        reasons.append("Device appears to be embedded/IoT/ICS equipment")
        evidence.append(
            "Embedded device - often 32-bit with limited update capability")

    # NTP service exposure
    has_ntp = any(svc.get("port") == 123 for svc in fingerprint.udp_services)
    if has_ntp:
        base_score += 10
        reasons.append("NTP service exposed (time-dependent service)")
        evidence.append(
            "NTP service detected - directly affected by time overflow")

    # Check for time-critical services
    for svc in fingerprint.tcp_services:
        port = svc.get("port")
        if port in TIME_CRITICAL_PORTS:
            base_score += 5
            db_name = TIME_CRITICAL_PORTS[port]
            reasons.append(
                f"{db_name} database detected (timestamp-dependent)")
            evidence.append(f"{db_name} service - uses timestamps internally")

    # Telnet = very old/insecure
    if any(svc.get("port") == 23 for svc in fingerprint.tcp_services):
        base_score += 15
        reasons.append(
            "Telnet service active (indicates legacy/unsecured system)")
        evidence.append("Telnet enabled - strong indicator of legacy system")

    # Clamp score
    fingerprint.risk_score = max(0, min(100, base_score))
    fingerprint.reasons = reasons
    fingerprint.evidence = evidence

    # Determine vulnerability level
    if fingerprint.risk_score >= RISK_THRESHOLDS["critical"]:
        fingerprint.vulnerability_level = VulnerabilityLevel.CRITICAL
    elif fingerprint.risk_score >= RISK_THRESHOLDS["vulnerable"]:
        fingerprint.vulnerability_level = VulnerabilityLevel.VULNERABLE
    elif fingerprint.risk_score >= RISK_THRESHOLDS["potentially_vulnerable"]:
        fingerprint.vulnerability_level = VulnerabilityLevel.POTENTIALLY_VULNERABLE
    elif fingerprint.risk_score >= RISK_THRESHOLDS["unknown"]:
        fingerprint.vulnerability_level = VulnerabilityLevel.UNKNOWN
    elif fingerprint.risk_score >= RISK_THRESHOLDS["likely_safe"]:
        fingerprint.vulnerability_level = VulnerabilityLevel.LIKELY_SAFE
    else:
        fingerprint.vulnerability_level = VulnerabilityLevel.SAFE

    # Calculate confidence based on available data with refined weights
    confidence = 0.0

    # Direct architecture evidence (highest weight)
    if fingerprint.architecture != "unknown":
        confidence += CONFIDENCE_WEIGHTS["architecture"]

    # SNMP HOST-RESOURCES-MIB data (very reliable)
    if fingerprint.snmp_info:
        if any(key in fingerprint.snmp_info for key in ["hrMemorySize", "hrDeviceDescr1", "hrDeviceDescr2"]):
            confidence += CONFIDENCE_WEIGHTS["snmp_hr_mib"]
        else:
            confidence += CONFIDENCE_WEIGHTS["snmp_basic"]

    # Service version data
    if fingerprint.approx_age_year:
        confidence += CONFIDENCE_WEIGHTS["service_version"]

    # MAC vendor identification
    if fingerprint.mac_vendor and fingerprint.mac_vendor != "Unknown":
        confidence += CONFIDENCE_WEIGHTS["mac_vendor"]

    # TLS/protocol behavior analysis
    if fingerprint.tls_info:
        confidence += CONFIDENCE_WEIGHTS["tls_analysis"]

    # SMB/OS fingerprinting
    if fingerprint.smb_info:
        confidence += CONFIDENCE_WEIGHTS["smb_fingerprint"]

    # Multiple service detection
    if len(fingerprint.tcp_services) >= 3:
        confidence += CONFIDENCE_WEIGHTS["multi_service"]

    fingerprint.confidence = min(1.0, confidence)
