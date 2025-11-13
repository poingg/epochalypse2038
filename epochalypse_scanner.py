#!/usr/bin/env python3
# pylint: disable=W0718, C0301, C0302, C0415, W0702
"""
Epochalypse Network Scanner - Enhanced Y2K38 Vulnerability Scanner
Combines TCP/UDP scanning, SNMP probing, and optional LLM-based risk assessment
"""

import argparse
import ipaddress
import json
import socket
import ssl
import re
import sys
# false positive pylint: disable=E0611
from concurrent.futures import ThreadPoolExecutor, as_completed # pylint: disable=E0611
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from typing import Any

# Required dependencies
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
)
from impacket.smbconnection import SMBConnection
import requests


# Default scanning configuration
DEFAULT_TCP_PORTS = [21, 22, 23, 25, 80, 110,
                     143, 443, 445, 3306, 3389, 5432, 8080, 8443]
# DNS, NTP, SNMP, IKE, Syslog, UPnP
DEFAULT_UDP_PORTS = [53, 123, 161, 500, 514, 1900]
CONNECT_TIMEOUT = 2
READ_TIMEOUT = 2
UDP_TIMEOUT = 2.0
MAX_BANNER_BYTES = 1024

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
    discovered_ports: set[int] = field(default_factory=set)
    tcp_services: list[dict[str, Any]] = field(default_factory=list)
    udp_services: list[dict[str, Any]] = field(default_factory=list)
    snmp_info: dict[str, Any] | None = None
    smb_info: dict[str, Any] | None = None
    ntp_info: dict[str, Any] | None = None
    architecture: str = "unknown"
    os_type: str | None = None
    os_version: str | None = None
    approx_age_year: int | None = None
    embedded_device: bool = False
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
        return data


# ============================================================================
# TCP Scanning Functions
# ============================================================================

def scan_tcp_port(ip: str, port: int, use_ssl: bool = False) -> dict[str, Any] | None:
    """Scan a single TCP port and retrieve banner if available."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(CONNECT_TIMEOUT)

    try:
        s.connect((ip, port))
    except (socket.timeout, ConnectionRefusedError, OSError):
        s.close()
        return None

    banner = ""
    error = None

    try:
        s.settimeout(READ_TIMEOUT)

        if port == 22:  # SSH
            data = s.recv(MAX_BANNER_BYTES)
            banner = data.decode(errors="ignore").strip()

        elif port in (80, 443, 8080, 8443):  # HTTP/HTTPS
            req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: epochalypse-scanner/1.0\r\n\r\n".encode()

            if use_ssl or port in (443, 8443):
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    s = context.wrap_socket(s, server_hostname=ip)
                except ssl.SSLError as e:
                    error = f"ssl_error:{e}"

            try:
                s.sendall(req)
                resp = s.recv(MAX_BANNER_BYTES)
                banner = resp.decode(errors="ignore")
            except Exception as e:
                error = f"http_error:{e}"

        elif port == 25:  # SMTP
            data = s.recv(MAX_BANNER_BYTES)
            banner = data.decode(errors="ignore").strip()

        elif port == 21:  # FTP
            data = s.recv(MAX_BANNER_BYTES)
            banner = data.decode(errors="ignore").strip()

        else:  # Generic port
            try:
                data = s.recv(MAX_BANNER_BYTES)
                banner = data.decode(errors="ignore").strip()
            except Exception:
                pass

    except Exception as e:
        error = f"read_error:{e}"
    finally:
        try:
            s.close()
        except:
            pass

    service = {
        "port": port,
        "protocol": "tcp",
        "state": "open",
        "banner": banner,
    }

    if error:
        service["error"] = error

    return service


def scan_host_tcp(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Scan all TCP ports for a host."""
    services = []

    for port in ports:
        use_ssl = port in (443, 8443)
        result = scan_tcp_port(ip, port, use_ssl=use_ssl)
        if result:
            services.append(result)

    return services


# ============================================================================
# UDP Scanning Functions
# ============================================================================

def scan_udp_port(ip: str, port: int) -> dict[str, Any] | None:
    """Scan a single UDP port with service-specific probes"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(UDP_TIMEOUT)

    try:
        if port == 123:  # NTP
            return probe_ntp_detailed(ip, s)
        elif port == 161:  # SNMP (basic check, detailed probe done separately)
            return probe_udp_generic(ip, port, s, b"\x30\x26\x02\x01\x00")
        elif port == 53:  # DNS
            # Simple DNS query for version.bind
            query = b"\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03"
            return probe_udp_generic(ip, port, s, query)
        else:
            return probe_udp_generic(ip, port, s)

    except Exception:
        return None
    finally:
        s.close()


def probe_udp_generic(ip: str, port: int, sock: socket.socket, probe: bytes = b"\x00") -> dict[str, Any] | None:
    """Generic UDP probe"""
    try:
        sock.sendto(probe, (ip, port))
        data, _ = sock.recvfrom(4096)

        if data:
            return {
                "port": port,
                "protocol": "udp",
                "state": "open",
                "response": data.hex()[:200],  # Limit response size
            }
    except socket.timeout:
        return None
    except Exception:
        return None

    return None


def probe_ntp_detailed(ip: str, sock: socket.socket) -> dict[str, Any] | None:
    """Detailed NTP probe"""
    # NTP client request: LI=0, VN=3, Mode=3
    packet = b"\x1b" + 47 * b"\x00"

    try:
        sock.sendto(packet, (ip, 123))
        data, _ = sock.recvfrom(48)

        if len(data) >= 48:
            first_byte = data[0]
            li = (first_byte >> 6) & 0x3
            vn = (first_byte >> 3) & 0x7
            mode = first_byte & 0x7
            stratum = data[1]
            refid = data[12:16]

            try:
                refid_text = refid.decode("ascii", errors="ignore").strip()
            except:
                refid_text = ""

            return {
                "port": 123,
                "protocol": "udp",
                "state": "open",
                "service": "ntp",
                "version": vn,
                "mode": mode,
                "stratum": stratum,
                "leap_indicator": li,
                "refid": refid_text,
            }
    except:
        pass

    return None


def scan_host_udp(ip: str, ports: list[int]) -> list[dict[str, Any]]:
    """Scan multiple UDP ports on a host"""
    services = []

    for port in ports:
        result = scan_udp_port(ip, port)
        if result:
            services.append(result)

    return services


# ============================================================================
# SNMP Probing Functions
# ============================================================================

def probe_snmp_full(ip: str, community: str = "public") -> dict[str, Any] | None:
    """"Comprehensive SNMP probe for system information"""
    import asyncio

    oids_to_query = {
        "sysDescr": "1.3.6.1.2.1.1.1.0",
        "sysObjectID": "1.3.6.1.2.1.1.2.0",
        "sysUpTime": "1.3.6.1.2.1.1.3.0",
        "sysName": "1.3.6.1.2.1.1.5.0",
        "sysLocation": "1.3.6.1.2.1.1.6.0",
    }

    async def snmp_get_all():
        """Query all SNMP OIDs asynchronously"""
        results = {}
        engine = SnmpEngine()

        try:
            for name, oid_str in oids_to_query.items():
                try:
                    target = await UdpTransportTarget.create((ip, 161), timeout=UDP_TIMEOUT, retries=0)
                    error_indication, error_status, _, var_binds = await get_cmd(
                        engine,
                        CommunityData(community, mpModel=1),  # SNMPv2c
                        target,
                        ContextData(),
                        ObjectType(ObjectIdentity(oid_str)),
                    )

                    if not error_indication and not error_status:
                        for var_bind in var_binds:
                            results[name] = str(var_bind[1])
                except Exception:
                    continue
        finally:
            # Properly close the SNMP engine
            if hasattr(engine, 'close_dispatcher'):
                engine.close_dispatcher()

        return results

    loop = None
    try:
        # Run async SNMP queries with proper cleanup
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        snmp_data = loop.run_until_complete(snmp_get_all())
        return snmp_data if snmp_data else None
    except Exception:
        return None
    finally:
        # Properly clean up the event loop
        if loop:
            try:
                # Cancel all pending tasks
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                # Run the loop briefly to allow cancellations to complete
                if pending:
                    loop.run_until_complete(asyncio.gather(
                        *pending, return_exceptions=True))
            except Exception:
                pass
            finally:
                loop.close()


# ============================================================================
# SMB Probing Functions
# ============================================================================

def probe_smb(ip: str) -> dict[str, Any] | None:
    """Probe SMB for OS information"""
    try:
        conn = SMBConnection(ip, ip, sess_port=445, timeout=CONNECT_TIMEOUT)
        conn.negotiateSession()

        os_info = conn.getServerOS() or ""
        domain = conn.getServerDomain() or ""
        name = conn.getServerName() or ""

        conn.close()

        return {
            "os": os_info,
            "domain": domain,
            "name": name,
        }
    except Exception:
        return None


# ============================================================================
# Analysis and Heuristics Functions
# ============================================================================

def guess_architecture(text: str) -> str:
    """Guess system architecture from text"""
    t = text.lower()

    # 64-bit indicators
    if any(x in t for x in ["x86_64", "amd64", "win64", "x64", "aarch64", "arm64", "ppc64", "s390x"]):
        return "likely_64bit"

    # 32-bit indicators
    if any(x in t for x in ["i386", "i486", "i586", "i686", "x86", "win32", "armv5", "armv6", "armv7", "mips", "mipsel", "powerpc"]):
        return "likely_32bit"

    return "unknown"


def detect_embedded_device(text: str) -> bool:
    """Detect if system appears to be an embedded device"""
    t = text.lower()

    keywords = [
        "router", "switch", "firewall", "access point", "wifi", "ap",
        "dsl", "adsl", "vdsl", "ont", "modem",
        "dvr", "nvr", "camera", "webcam", "ipcam",
        "printer", "print server",
        "nas", "storage",
        "synology", "qnap", "netgear", "buffalo",
        "mikrotik", "tp-link", "d-link", "linksys", "ubiquiti",
        "hikvision", "dahua", "axis",
        "scada", "plc", "hmi", "modbus", "bacnet", "ics",
        "embedded", "busybox", "openwrt", "dd-wrt",
    ]

    return any(k in t for k in keywords)


def detect_os_type(text: str) -> str | None:
    """Detect operating system from text"""
    t = text.lower()

    os_patterns = {
        'linux': ['linux', 'ubuntu', 'debian', 'centos', 'redhat', 'fedora', 'suse', 'alpine'],
        'windows': ['windows', 'microsoft', 'win32', 'win64', 'microsoft-iis'],
        'freebsd': ['freebsd'],
        'openbsd': ['openbsd'],
        'netbsd': ['netbsd'],
        'macos': ['darwin', 'mac os', 'macos'],
        'solaris': ['solaris', 'sunos'],
        'cisco': ['cisco', 'ios'],
        'juniper': ['junos', 'juniper'],
    }

    for os_name, patterns in os_patterns.items():
        if any(p in t for p in patterns):
            return os_name

    return None


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

    full_text = "\n".join(all_text).lower()

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


def calculate_risk_score(fingerprint: HostFingerprint) -> None:
    """Calculate Y2K38 risk score and vulnerability level"""
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

    combined_text = "\n".join(all_text)

    # Determine architecture
    fingerprint.architecture = guess_architecture(combined_text)
    fingerprint.embedded_device = detect_embedded_device(combined_text)
    fingerprint.os_type = detect_os_type(combined_text)
    fingerprint.approx_age_year = estimate_service_age(fingerprint)

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
    time_critical_ports = {
        3306: "MySQL",
        5432: "PostgreSQL",
        6379: "Redis",
        27017: "MongoDB",
    }

    for svc in fingerprint.tcp_services:
        port = svc.get("port")
        if port in time_critical_ports:
            base_score += 5
            db_name = time_critical_ports[port]
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
    if fingerprint.risk_score >= 85:
        fingerprint.vulnerability_level = VulnerabilityLevel.CRITICAL
    elif fingerprint.risk_score >= 70:
        fingerprint.vulnerability_level = VulnerabilityLevel.VULNERABLE
    elif fingerprint.risk_score >= 50:
        fingerprint.vulnerability_level = VulnerabilityLevel.POTENTIALLY_VULNERABLE
    elif fingerprint.risk_score >= 30:
        fingerprint.vulnerability_level = VulnerabilityLevel.UNKNOWN
    elif fingerprint.risk_score >= 15:
        fingerprint.vulnerability_level = VulnerabilityLevel.LIKELY_SAFE
    else:
        fingerprint.vulnerability_level = VulnerabilityLevel.SAFE

    # Calculate confidence based on available data
    confidence = 0.0
    if fingerprint.architecture != "unknown":
        confidence += 0.3
    if fingerprint.approx_age_year:
        confidence += 0.2
    if fingerprint.snmp_info:
        confidence += 0.2
    if fingerprint.smb_info:
        confidence += 0.15
    if len(fingerprint.tcp_services) >= 3:
        confidence += 0.15

    fingerprint.confidence = min(1.0, confidence)


# ============================================================================
# LLM Integration for Advanced Risk Assessment
# ============================================================================

def llm_assess_vulnerability(fingerprint: HostFingerprint, api_key: str, model: str = "gpt-4") -> dict[str, Any] | None:
    """Use LLM to assess Y2K38 vulnerability probability"""
    # Prepare context for LLM
    context = {
        "ip": fingerprint.ip,
        "architecture": fingerprint.architecture,
        "os_type": fingerprint.os_type,
        "approx_age": fingerprint.approx_age_year,
        "embedded": fingerprint.embedded_device,
        "services": [],
        "snmp_info": fingerprint.snmp_info,
        "smb_info": fingerprint.smb_info,
    }

    # Add service summaries
    for svc in fingerprint.tcp_services[:10]:  # Limit to avoid token overflow
        svc_summary = {
            "port": svc.get("port"),
            "protocol": svc.get("protocol"),
            "banner": svc.get("banner", "")[:200],  # Limit banner length
        }
        context["services"].append(svc_summary)

    for svc in fingerprint.udp_services[:5]:
        svc_summary = {
            "port": svc.get("port"),
            "protocol": svc.get("protocol"),
            "service": svc.get("service", "unknown"),
        }
        context["services"].append(svc_summary)

    prompt = f"""You are a cybersecurity expert analyzing systems for Year 2038 (Y2K38/Epochalypse) vulnerability.

The Year 2038 problem occurs when 32-bit systems reach the maximum value of a signed 32-bit integer (2,147,483,647) representing seconds since January 1, 1970. On January 19, 2038, at 03:14:07 UTC, this will overflow.

Analyze this system and provide:
1. Vulnerability probability (0-100%)
2. Confidence level (0-100%)
3. Key risk factors
4. Recommendations

System Information:
{json.dumps(context, indent=2)}

Respond in JSON format:
{{
  "probability": <0-100>,
  "confidence": <0-100>,
  "risk_factors": ["factor1", "factor2", ...],
  "recommendations": ["rec1", "rec2", ...],
  "reasoning": "brief explanation"
}}"""

    try:
        # Support both OpenAI and compatible APIs
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a cybersecurity expert specializing in legacy system vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.3,
            "max_tokens": 1000,
        }

        # Try OpenAI API
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=30
        )

        if response.status_code == 200:
            result = response.json()
            content = result["choices"][0]["message"]["content"]

            # Try to parse JSON from response
            try:
                # Extract JSON from markdown code blocks if present
                if "```json" in content:
                    content = content.split("```json")[1].split("```")[0]
                elif "```" in content:
                    content = content.split("```")[1].split("```")[0]

                llm_result = json.loads(content.strip())
                return llm_result
            except json.JSONDecodeError:
                return {
                    "probability": None,
                    "confidence": None,
                    "error": "Failed to parse LLM response",
                    "raw_response": content[:500]
                }
        else:
            return {
                "error": f"API request failed: {response.status_code}",
                "message": response.text[:200]
            }

    except Exception as e:
        return {
            "error": f"LLM assessment failed: {str(e)}"
        }


# ============================================================================
# Host Scanning Orchestration
# ============================================================================

def scan_host(
    ip: str,
    tcp_ports: list[int],
    udp_ports: list[int],
    snmp_community: str | None,
    enable_smb: bool,
    llm_api_key: str | None = None,
    llm_model: str = "gpt-4",
) -> HostFingerprint | None:
    """Scan a single host comprehensively"""

    fingerprint = HostFingerprint(ip=ip)

    # TCP scanning
    tcp_services = scan_host_tcp(ip, tcp_ports)
    if tcp_services:
        fingerprint.tcp_services = tcp_services

    # UDP scanning
    udp_services = scan_host_udp(ip, udp_ports)
    if udp_services:
        fingerprint.udp_services = udp_services

    # SNMP probing
    if snmp_community:
        snmp_info = probe_snmp_full(ip, snmp_community)
        if snmp_info:
            fingerprint.snmp_info = snmp_info

    # SMB probing
    if enable_smb:
        smb_info = probe_smb(ip)
        if smb_info:
            fingerprint.smb_info = smb_info

    # Extract NTP info from UDP services if available
    for svc in fingerprint.udp_services:
        if svc.get("service") == "ntp":
            fingerprint.ntp_info = {
                "version": svc.get("version"),
                "stratum": svc.get("stratum"),
                "refid": svc.get("refid"),
            }

    # Skip if no services discovered
    if not fingerprint.tcp_services and not fingerprint.udp_services and not fingerprint.snmp_info:
        return None

    # Try hostname resolution
    try:
        fingerprint.hostname = socket.gethostbyaddr(ip)[0]
    except:
        pass

    # Calculate risk score
    calculate_risk_score(fingerprint)

    # Optional LLM assessment
    if llm_api_key and fingerprint.vulnerability_level in [
        VulnerabilityLevel.POTENTIALLY_VULNERABLE,
        VulnerabilityLevel.VULNERABLE,
        VulnerabilityLevel.CRITICAL
    ]:
        llm_result = llm_assess_vulnerability(
            fingerprint, llm_api_key, llm_model)
        if llm_result:
            fingerprint.llm_assessment = llm_result

    return fingerprint


# ============================================================================
# Reporting Functions
# ============================================================================

def print_text_report(results: list[HostFingerprint]) -> None:
    """Print human-readable text report"""
    # Sort by risk score (highest first)
    results_sorted = sorted(results, key=lambda h: h.risk_score, reverse=True)

    print("\n" + "=" * 100)
    print(" " * 35 + "EPOCHALYPSE Y2K38 VULNERABILITY SCAN REPORT")
    print("=" * 100)
    print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total hosts scanned: {len(results)}")
    print()

    # Summary statistics
    level_counts = {}
    for r in results:
        level = r.vulnerability_level.value
        level_counts[level] = level_counts.get(level, 0) + 1

    print("VULNERABILITY SUMMARY:")
    print("-" * 100)
    for level in VulnerabilityLevel:
        count = level_counts.get(level.value, 0)
        print(f"  {level.value.upper():30s}: {count:3d}")
    print()

    # Detailed host reports
    print("DETAILED HOST ANALYSIS:")
    print("=" * 100)

    for host in results_sorted:
        print()
        print(f"Host: {host.ip}" +
              (f" ({host.hostname})" if host.hostname else ""))
        print(
            f"Risk Score: {host.risk_score}/100 | Level: {host.vulnerability_level.value.upper()} | Confidence: {host.confidence:.0%}")

        if host.architecture != "unknown":
            print(f"Architecture: {host.architecture}")

        if host.os_type:
            print(f"OS Type: {host.os_type}")

        if host.approx_age_year:
            print(f"Approximate Service Age: ~{host.approx_age_year}")

        if host.embedded_device:
            print("Device Type: Embedded/IoT/ICS")

        # SNMP info
        if host.snmp_info:
            print("\nSNMP Information:")
            if host.snmp_info.get("sysDescr"):
                descr = host.snmp_info["sysDescr"][:150]
                print(
                    f"  Description: {descr}{'...' if len(host.snmp_info['sysDescr']) > 150 else ''}")
            if host.snmp_info.get("sysName"):
                print(f"  System Name: {host.snmp_info['sysName']}")

        # SMB info
        if host.smb_info:
            print("\nSMB Information:")
            print(f"  OS: {host.smb_info.get('os', 'N/A')}")
            print(f"  Domain: {host.smb_info.get('domain', 'N/A')}")
            print(f"  Name: {host.smb_info.get('name', 'N/A')}")

        # NTP info
        if host.ntp_info:
            print("\nNTP Service:")
            print(f"  Version: {host.ntp_info.get('version', 'N/A')}")
            print(f"  Stratum: {host.ntp_info.get('stratum', 'N/A')}")

        # Risk reasons
        if host.reasons:
            print("\nRisk Assessment Factors:")
            for reason in host.reasons:
                print(f"  • {reason}")

        # LLM assessment
        if host.llm_assessment:
            print("\nLLM-Enhanced Assessment:")
            if host.llm_assessment.get("error"):
                print(f"  Error: {host.llm_assessment['error']}")
            else:
                print(
                    f"  Probability: {host.llm_assessment.get('probability', 'N/A')}%")
                print(
                    f"  LLM Confidence: {host.llm_assessment.get('confidence', 'N/A')}%")
                if host.llm_assessment.get("reasoning"):
                    print(
                        f"  Reasoning: {host.llm_assessment['reasoning'][:200]}")
                if host.llm_assessment.get("recommendations"):
                    print("  Recommendations:")
                    for rec in host.llm_assessment["recommendations"][:3]:
                        print(f"    - {rec}")

        # Services summary
        tcp_count = len(host.tcp_services)
        udp_count = len(host.udp_services)
        print(f"\nServices: {tcp_count} TCP, {udp_count} UDP")

        # Show key services
        for svc in host.tcp_services[:5]:
            banner = (svc.get("banner") or "").replace(
                "\r", " ").replace("\n", " ")[:100]
            print(f"  TCP/{svc['port']:5d}: {banner}")

        for svc in host.udp_services[:3]:
            svc_name = svc.get("service", "unknown")
            print(f"  UDP/{svc['port']:5d}: {svc_name}")

        print("-" * 100)

    if not results_sorted:
        print("No responsive hosts found.")


def generate_json_report(results: list[HostFingerprint]) -> str:
    """Generate JSON report"""
    report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_hosts": len(results),
            "scanner_version": "1.0",
        },
        "summary": {},
        "hosts": []
    }

    # Summary statistics
    for r in results:
        level = r.vulnerability_level.value
        report["summary"][level] = report["summary"].get(level, 0) + 1

    # Host details
    for host in results:
        report["hosts"].append(host.to_dict())

    return json.dumps(report, indent=2)


def generate_csv_report(results: list[HostFingerprint]) -> str:
    """Generate CSV report"""
    import io
    import csv

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "IP", "Hostname", "Risk Score", "Vulnerability Level",
        "Architecture", "OS Type", "Age (Year)", "Embedded",
        "TCP Services", "UDP Services", "SNMP", "Confidence"
    ])

    # Data rows
    for host in sorted(results, key=lambda h: h.risk_score, reverse=True):
        writer.writerow([
            host.ip,
            host.hostname or "",
            host.risk_score,
            host.vulnerability_level.value,
            host.architecture,
            host.os_type or "",
            host.approx_age_year or "",
            "Yes" if host.embedded_device else "No",
            len(host.tcp_services),
            len(host.udp_services),
            "Yes" if host.snmp_info else "No",
            f"{host.confidence:.0%}"
        ])

    return output.getvalue()


# ============================================================================
# Main Function
# ============================================================================

def main():
    """ Start here """
    parser = argparse.ArgumentParser(
        description="Epochalypse Y2K38 Network Vulnerability Scanner - Enhanced Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  %(prog)s 192.168.1.0/24
  
  # Full scan with SNMP and custom ports
  %(prog)s 10.0.0.0/16 --snmp-community public --tcp-ports 22,80,443,3306 --udp-ports 123,161
  
  # Scan with LLM-enhanced assessment
  %(prog)s 192.168.1.0/24 --llm-api-key sk-... --llm-model gpt-4
  
  # Generate JSON report
  %(prog)s 172.16.0.0/24 --format json --output report.json
  
About Y2K38:
  The Year 2038 problem (Epochalypse) affects systems using 32-bit time_t values.
  On January 19, 2038, at 03:14:07 UTC, these systems will experience integer overflow.
  This scanner identifies potentially vulnerable systems in your network.
        """
    )

    # Required arguments
    parser.add_argument(
        "cidr", help="CIDR network range (e.g., 192.168.1.0/24)")

    # Port configuration
    parser.add_argument(
        "--tcp-ports",
        help=f"Comma-separated TCP ports (default: {','.join(map(str, DEFAULT_TCP_PORTS))})"
    )
    parser.add_argument(
        "--udp-ports",
        help=f"Comma-separated UDP ports (default: {','.join(map(str, DEFAULT_UDP_PORTS))})"
    )

    # Scanning options
    parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Concurrent worker threads (default: 50)"
    )
    parser.add_argument(
        "--snmp-community",
        help="SNMP community string for querying (e.g., 'public')"
    )
    parser.add_argument(
        "--disable-smb",
        action="store_true",
        help="Disable SMB OS fingerprinting"
    )
    parser.add_argument(
        "--disable-udp",
        action="store_true",
        help="Disable UDP port scanning"
    )

    # LLM integration
    parser.add_argument(
        "--llm-api-key",
        help="API key for LLM-enhanced vulnerability assessment (OpenAI compatible)"
    )
    parser.add_argument(
        "--llm-model",
        default="gpt-4",
        help="LLM model to use (default: gpt-4)"
    )

    # Output options
    parser.add_argument(
        "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output format (default: text)"
    )
    parser.add_argument(
        "--output",
        help="Output file (default: stdout)"
    )

    args = parser.parse_args()

    # Validate CIDR
    try:
        network = ipaddress.ip_network(args.cidr, strict=False)
    except ValueError as e:
        print(f"[!] Invalid CIDR: {e}", file=sys.stderr)
        sys.exit(1)

    # Parse port lists
    if args.tcp_ports:
        tcp_ports = [int(p.strip()) for p in args.tcp_ports.split(",")]
    else:
        tcp_ports = DEFAULT_TCP_PORTS

    if args.udp_ports:
        udp_ports = [int(p.strip()) for p in args.udp_ports.split(",")]
    else:
        udp_ports = DEFAULT_UDP_PORTS if not args.disable_udp else []

    # Generate IP list
    ips = [str(ip) for ip in network.hosts()]
    if not ips:  # Handle /32 and /31
        ips = [str(network.network_address)]

    print("[*] Starting Epochalypse Y2K38 vulnerability scan", file=sys.stderr)
    print(f"[*] Network: {network}", file=sys.stderr)
    print(f"[*] Hosts to scan: {len(ips)}", file=sys.stderr)
    print(
        f"[*] TCP ports: {len(tcp_ports)}, UDP ports: {len(udp_ports)}", file=sys.stderr)
    if args.llm_api_key:
        print(
            f"[*] LLM enhancement enabled: {args.llm_model}", file=sys.stderr)
    print(f"[*] Workers: {args.workers}", file=sys.stderr)
    print(file=sys.stderr)

    # Scan all hosts
    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                scan_host,
                ip,
                tcp_ports,
                udp_ports,
                args.snmp_community,
                not args.disable_smb,
                args.llm_api_key,
                args.llm_model,
            ): ip
            for ip in ips
        }

        for future in as_completed(futures):
            completed += 1
            ip = futures[future]

            try:
                result = future.result()
                if result:
                    results.append(result)
                    print(
                        f"[*] Progress: {completed}/{len(ips)} - {ip} - Risk: {result.risk_score}", file=sys.stderr)
                else:
                    print(
                        f"[*] Progress: {completed}/{len(ips)} - {ip} - No response", file=sys.stderr)
            except Exception as e:
                print(f"[!] Error scanning {ip}: {e}", file=sys.stderr)

    print(
        f"\n[*] Scan complete. Found {len(results)} responsive hosts.", file=sys.stderr)

    # Generate report
    if args.format == "json":
        report = generate_json_report(results)
    elif args.format == "csv":
        report = generate_csv_report(results)
    else:
        # Text format prints directly
        if args.output:
            import io
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()
            print_text_report(results)
            report = sys.stdout.getvalue()
            sys.stdout = old_stdout
        else:
            print_text_report(results)
            report = None

    # Output report
    if report:
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"[*] Report saved to: {args.output}", file=sys.stderr)
        else:
            print(report)

    # Exit code based on findings
    critical_count = sum(
        1 for r in results
        if r.vulnerability_level in [VulnerabilityLevel.CRITICAL, VulnerabilityLevel.VULNERABLE]
    )

    if critical_count > 0:
        print(
            f"\n[!] WARNING: Found {critical_count} critical/vulnerable hosts!", file=sys.stderr)
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
