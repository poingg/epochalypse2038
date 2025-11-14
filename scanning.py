#!/usr/bin/env python3
# pylint: disable=W0718, C0301, W0702
"""
Network scanning functions for Epochalypse Scanner
TCP/UDP port scanning, banner grabbing, and protocol-specific probes
"""

import asyncio
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from typing import Any

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

from config import (
    CONNECT_TIMEOUT, READ_TIMEOUT, UDP_TIMEOUT, MAX_BANNER_BYTES,
    MAC_VENDOR_API_URL, MAC_VENDOR_CACHE_FILE, MAC_VENDOR_RATE_LIMIT,
    SNMP_OIDS
)


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
    """"Comprehensive SNMP probe for system and hardware information"""
    async def snmp_get_all():
        """Query all SNMP OIDs asynchronously"""
        results = {}
        engine = SnmpEngine()

        try:
            for name, oid_str in SNMP_OIDS.items():
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
# MAC Address and Vendor Lookup Functions
# ============================================================================

def get_mac_address(ip: str) -> str | None:
    """Retrieve MAC address for an IP using ARP table"""
    try:
        # Try using arp command (works on macOS and Linux)
        if sys.platform == "darwin" or sys.platform.startswith("linux"):
            result = subprocess.run(
                ["arp", "-n", ip],
                capture_output=True,
                text=True,
                timeout=2,
                check=False
            )

            if result.returncode == 0:
                # Parse ARP output
                for line in result.stdout.splitlines():
                    if ip in line:
                        # Match MAC address pattern
                        mac_match = re.search(
                            r"([0-9a-fA-F]{1,2}[:-]){5}([0-9a-fA-F]{1,2})", line)
                        if mac_match:
                            return mac_match.group(0).upper()

        elif sys.platform == "win32":
            result = subprocess.run(
                ["arp", "-a", ip],
                capture_output=True,
                text=True,
                timeout=2,
                check=False
            )

            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if ip in line:
                        mac_match = re.search(
                            r"([0-9a-fA-F]{1,2}[-]){5}([0-9a-fA-F]{1,2})", line)
                        if mac_match:
                            return mac_match.group(0).upper()

    except Exception:
        pass

    return None


def load_mac_vendor_cache() -> dict[str, str]:
    """Load MAC vendor cache from disk"""
    try:
        if os.path.exists(MAC_VENDOR_CACHE_FILE):
            with open(MAC_VENDOR_CACHE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_mac_vendor_cache(cache: dict[str, str]) -> None:
    """Save MAC vendor cache to disk"""
    try:
        with open(MAC_VENDOR_CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
    except Exception:
        pass


_mac_vendor_cache = load_mac_vendor_cache()
_last_api_call = 0.0 # pylint: disable=C0103


def lookup_mac_vendor(mac: str) -> str | None:
    """Lookup MAC address vendor using macvendors.com API with caching"""
    global _mac_vendor_cache, _last_api_call # pylint: disable=W0602

    if not mac:
        return None

    # Normalize MAC address
    mac_normalized = mac.upper().replace(":", "").replace("-", "")

    # Check cache first (use OUI prefix - first 6 chars)
    oui = mac_normalized[:6]
    if oui in _mac_vendor_cache:
        return _mac_vendor_cache[oui]

    # Rate limiting - respect 1 req/sec limit
    current_time = time.time()
    time_since_last = current_time - _last_api_call
    if time_since_last < MAC_VENDOR_RATE_LIMIT:
        time.sleep(MAC_VENDOR_RATE_LIMIT - time_since_last)

    try:
        response = requests.get(
            f"{MAC_VENDOR_API_URL}{mac}",
            timeout=5
        )
        _last_api_call = time.time()

        if response.status_code == 200:
            vendor = response.text.strip()
            _mac_vendor_cache[oui] = vendor
            save_mac_vendor_cache(_mac_vendor_cache)
            return vendor
        elif response.status_code == 404:
            _mac_vendor_cache[oui] = "Unknown"
            save_mac_vendor_cache(_mac_vendor_cache)
            return "Unknown"

    except Exception:
        pass

    return None


# ============================================================================
# TLS/SSL Analysis Functions
# ============================================================================

def probe_tls_info(ip: str, port: int = 443) -> dict[str, Any] | None:
    """Probe TLS/SSL configuration and extract version/cipher information"""
    try:
        # Try different SSL/TLS protocol versions
        protocols_to_try = [
            ("TLSv1.2", ssl.PROTOCOL_TLSv1_2),
            ("TLSv1.1", ssl.PROTOCOL_TLSv1_1),
            ("TLSv1", ssl.PROTOCOL_TLSv1),
        ]

        # Try SSLv3 if available (deprecated but useful for detection)
        if hasattr(ssl, 'PROTOCOL_SSLv3'):
            protocols_to_try.append(("SSLv3", ssl.PROTOCOL_SSLv3))

        working_protocols = []
        cipher_info = None
        cert_info = None

        for protocol_name, protocol_const in protocols_to_try:
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((ip, port), timeout=CONNECT_TIMEOUT) as sock:
                    with context.wrap_socket(sock, server_hostname=ip) as ssock:
                        working_protocols.append(protocol_name)

                        # Get cipher and certificate info from first successful connection
                        if not cipher_info:
                            cipher_info = ssock.cipher()

                        if not cert_info:
                            try:
                                cert = ssock.getpeercert(binary_form=False)
                                if cert:
                                    cert_info = {
                                        "subject": dict(x[0] for x in cert.get("subject", [])),  # type: ignore
                                        "issuer": dict(x[0] for x in cert.get("issuer", [])),  # type: ignore
                                        "version": cert.get("version"),
                                    }
                            except:
                                pass

                        break  # Only need one successful connection

            except:
                continue

        if working_protocols:
            tls_data = {
                "protocols": working_protocols,
                "legacy_only": all(p in ["TLSv1", "SSLv3"] for p in working_protocols),
            }

            if cipher_info:
                tls_data["cipher"] = {
                    "name": cipher_info[0] if cipher_info else None,
                    "protocol": cipher_info[1] if len(cipher_info) > 1 else None,
                    "bits": cipher_info[2] if len(cipher_info) > 2 else None,
                }

            if cert_info:
                tls_data["certificate"] = cert_info

            return tls_data

    except Exception:
        pass

    return None


# ============================================================================
# IPMI Detection Functions
# ============================================================================

def probe_ipmi(ip: str) -> dict[str, Any] | None:
    """Probe IPMI/BMC on port 623 UDP"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)

        # RMCP Presence Ping (IPMI Get Channel Authentication Capabilities)
        # This is a simplified probe - full IPMI would need proper ASN.1 encoding
        rmcp_ping = bytes([
            0x06, 0x00, 0xff, 0x06,  # RMCP Header
            0x00, 0x00, 0x11, 0xbe,  # IANA Enterprise Number
            0x80, 0x00, 0x00, 0x00   # Presence ping
        ])

        try:
            sock.sendto(rmcp_ping, (ip, 623))
            data, _ = sock.recvfrom(1024)

            if data and len(data) >= 16:
                # Basic IPMI response detected
                ipmi_data = {
                    "detected": True,
                    "port": 623,
                    "response_length": len(data),
                }

                # Try to extract IPMI version if present
                if len(data) > 20:
                    # This is simplified - real parsing would decode RMCP/IPMI properly
                    ipmi_data["raw_response"] = data[:32].hex()

                return ipmi_data

        except socket.timeout:
            pass
        finally:
            sock.close()

    except Exception:
        pass

    return None


# ============================================================================
# HTTP Header Analysis Functions
# ============================================================================

def extract_http_headers(ip: str, port: int = 80, use_ssl: bool = False) -> dict[str, Any] | None:
    """Extract HTTP headers for version detection"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((ip, port))

        if use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=ip)

        # Send HTTP request
        request = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())

        # Read response
        response = b""
        sock.settimeout(READ_TIMEOUT)
        while len(response) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response += chunk
            if b"\r\n\r\n" in response:
                break

        sock.close()

        # Parse headers
        response_text = response.decode('utf-8', errors='ignore')
        lines = response_text.split('\r\n')

        headers = {}
        for line in lines[1:]:  # Skip status line
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        if headers:
            return {
                "server": headers.get("server"),
                "x-powered-by": headers.get("x-powered-by"),
                "all_headers": headers,
            }

    except Exception:
        pass

    return None


# ============================================================================
# Hostname Analysis
# ============================================================================

def extract_hostname_hints(hostname: str) -> list[str]:
    """Extract OS/device hints from hostname"""
    if not hostname:
        return []

    hints = []
    h = hostname.lower()

    # Windows versions
    if any(x in h for x in ["win2000", "w2k", "win2k"]):
        hints.append("Windows 2000 in hostname")
    if any(x in h for x in ["winxp", "xp"]):
        hints.append("Windows XP in hostname")
    if any(x in h for x in ["win2003", "w2k3", "sbs2003"]):
        hints.append("Windows 2003 in hostname")

    # Architecture hints
    if any(x in h for x in ["arm", "mips", "ppc"]):
        hints.append("Architecture hint in hostname")

    # Device type hints
    if any(x in h for x in ["router", "switch", "ap", "printer", "camera", "nas"]):
        hints.append("Device type in hostname")

    # Extract potential year references (e.g., srv2005, router2008)
    year_match = re.search(r"(19|20)\d{2}", h)
    if year_match:
        hints.append(f"Year reference: {year_match.group(0)}")

    return hints
