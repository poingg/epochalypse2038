#!/usr/bin/env python3
# pylint: disable=W0718, C0301
"""
Reporting functions for Epochalypse Scanner
Text, JSON, and CSV report generation
"""

import csv
import io
import json
from datetime import datetime
# from typing import Any

from models import HostFingerprint, VulnerabilityLevel
from config import REPORT_TEXT_WIDTH, REPORT_MAX_BANNER_LENGTH


# ============================================================================
# Text Report Generation
# ============================================================================

def print_text_report(results: list[HostFingerprint]) -> None:
    """Print human-readable text report"""
    # Sort by risk score (highest first)
    results_sorted = sorted(results, key=lambda h: h.risk_score, reverse=True)

    print("\n" + "=" * REPORT_TEXT_WIDTH)
    print(" " * 35 + "EPOCHALYPSE Y2K38 VULNERABILITY SCAN REPORT")
    print("=" * REPORT_TEXT_WIDTH)
    print(f"Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total hosts scanned: {len(results)}")
    print()

    # Summary statistics
    level_counts = {}
    for r in results:
        level = r.vulnerability_level.value
        level_counts[level] = level_counts.get(level, 0) + 1

    print("VULNERABILITY SUMMARY:")
    print("-" * REPORT_TEXT_WIDTH)
    for level in VulnerabilityLevel:
        count = level_counts.get(level.value, 0)
        print(f"  {level.value.upper():30s}: {count:3d}")
    print()

    # Detailed host reports
    print("DETAILED HOST ANALYSIS:")
    print("=" * REPORT_TEXT_WIDTH)

    for host in results_sorted:
        print()
        print(f"Host: {host.ip}" +
              (f" ({host.hostname})" if host.hostname else ""))
        print(
            f"Risk Score: {host.risk_score}/100 | Level: {host.vulnerability_level.value.upper()} | Confidence: {host.confidence:.0%}")

        if host.mac_address:
            print(f"MAC Address: {host.mac_address}" +
                  (f" ({host.mac_vendor})" if host.mac_vendor else ""))

        if host.architecture != "unknown":
            print(f"Architecture: {host.architecture}")

        if host.cpu_info:
            print(f"CPU Info: {host.cpu_info}")

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
            if host.snmp_info.get("hrMemorySize"):
                mem_gb = int(host.snmp_info["hrMemorySize"]) / (1024 * 1024)
                print(f"  Memory: {mem_gb:.1f} GB")

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
            print(f"  REFID: {host.ntp_info.get('refid', 'N/A')}")

        # TLS info
        if host.tls_info:
            print("\nTLS/SSL Information:")
            print(
                f"  Protocols: {', '.join(host.tls_info.get('protocols', []))}")
            if host.tls_info.get("legacy_only"):
                print("  ⚠ WARNING: Only legacy protocols supported!")

        # HTTP headers
        if host.http_headers:
            print("\nHTTP Headers:")
            if host.http_headers.get("server"):
                print(f"  Server: {host.http_headers['server']}")
            if host.http_headers.get("x-powered-by"):
                print(f"  X-Powered-By: {host.http_headers['x-powered-by']}")

        # IPMI info
        if host.ipmi_info:
            print("\nIPMI/BMC Detected:")
            print("  Port 623 responded to IPMI probe")

        # Hostname hints
        if host.hostname_hints:
            print("\nHostname Hints:")
            for hint in host.hostname_hints:
                print(f"  • {hint}")

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
                "\r", " ").replace("\n", " ")[:REPORT_MAX_BANNER_LENGTH]
            print(f"  TCP/{svc['port']:5d}: {banner}")

        for svc in host.udp_services[:3]:
            svc_name = svc.get("service", "unknown")
            print(f"  UDP/{svc['port']:5d}: {svc_name}")

        print("-" * REPORT_TEXT_WIDTH)

    if not results_sorted:
        print("No responsive hosts found.")


# ============================================================================
# JSON Report Generation
# ============================================================================

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


# ============================================================================
# CSV Report Generation
# ============================================================================

def generate_csv_report(results: list[HostFingerprint]) -> str:
    """Generate CSV report with enhanced fields"""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "IP", "Hostname", "MAC Address", "MAC Vendor", "Risk Score", "Vulnerability Level",
        "Architecture", "OS Type", "Age (Year)", "Embedded", "CPU Info",
        "TCP Services", "UDP Services", "SNMP", "TLS Legacy", "IPMI", "Confidence"
    ])

    # Data rows
    for host in sorted(results, key=lambda h: h.risk_score, reverse=True):
        writer.writerow([
            host.ip,
            host.hostname or "",
            host.mac_address or "",
            host.mac_vendor or "",
            host.risk_score,
            host.vulnerability_level.value,
            host.architecture,
            host.os_type or "",
            host.approx_age_year or "",
            "Yes" if host.embedded_device else "No",
            host.cpu_info or "",
            len(host.tcp_services),
            len(host.udp_services),
            "Yes" if host.snmp_info else "No",
            "Yes" if (host.tls_info and host.tls_info.get(
                "legacy_only")) else "No",
            "Yes" if host.ipmi_info else "No",
            f"{host.confidence:.0%}"
        ])

    return output.getvalue()
