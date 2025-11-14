#!/usr/bin/env python3
# pylint: disable=W0718, C0301, W0702
"""
Epochalypse Network Scanner - Enhanced Y2K38 Vulnerability Scanner
Combines TCP/UDP scanning, SNMP probing, and optional LLM-based risk assessment

Main entry point - orchestrates scanning and reporting
"""

import argparse
import ipaddress
import socket
import sys
import io
from concurrent.futures import ThreadPoolExecutor, as_completed # pylint: disable=E0611

from models import HostFingerprint, VulnerabilityLevel
from config import DEFAULT_TCP_PORTS, DEFAULT_UDP_PORTS, DEFAULT_WORKERS, LLM_DEFAULT_MODEL
from scanning import (
    scan_host_tcp, scan_host_udp, probe_snmp_full, probe_smb,
    get_mac_address, lookup_mac_vendor, probe_tls_info, probe_ipmi,
    extract_http_headers, extract_hostname_hints
)
from risk_scoring import calculate_risk_score
from llm_integration import llm_assess_vulnerability
from reporting import print_text_report, generate_json_report, generate_csv_report


def scan_host(
    ip: str,
    tcp_ports: list[int],
    udp_ports: list[int],
    snmp_community: str | None,
    enable_smb: bool,
    llm_api_key: str | None = None,
    llm_model: str = "gpt-4",
) -> HostFingerprint | None:
    """Scan a single host comprehensively with all detection methods"""

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
        # Check for IPMI
        if svc.get("port") == 623:
            ipmi_data = probe_ipmi(ip)
            if ipmi_data:
                fingerprint.ipmi_info = ipmi_data

    # HTTP header extraction for web servers
    for svc in fingerprint.tcp_services:
        if svc.get("port") in [80, 8080]:
            headers = extract_http_headers(ip, svc["port"], use_ssl=False)
            if headers:
                fingerprint.http_headers = headers
                break
        elif svc.get("port") in [443, 8443]:
            headers = extract_http_headers(ip, svc["port"], use_ssl=True)
            if headers:
                fingerprint.http_headers = headers
            # Also get TLS info
            tls_data = probe_tls_info(ip, svc["port"])
            if tls_data:
                fingerprint.tls_info = tls_data
            break

    # MAC address lookup
    mac = get_mac_address(ip)
    if mac:
        fingerprint.mac_address = mac
        vendor = lookup_mac_vendor(mac)
        if vendor:
            fingerprint.mac_vendor = vendor

    # Skip if no services discovered
    if not fingerprint.tcp_services and not fingerprint.udp_services and not fingerprint.snmp_info:
        return None

    # Try hostname resolution
    try:
        fingerprint.hostname = socket.gethostbyaddr(ip)[0]
        # Extract hostname hints
        fingerprint.hostname_hints = extract_hostname_hints(
            fingerprint.hostname)
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


def main():
    """Main entry point"""
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
        default=DEFAULT_WORKERS,
        help=f"Concurrent worker threads (default: {DEFAULT_WORKERS})"
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
        default=LLM_DEFAULT_MODEL,
        help=f"LLM model to use (default: {LLM_DEFAULT_MODEL})"
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
            # import io
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
