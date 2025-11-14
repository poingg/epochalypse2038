# Major Detection Accuracy Improvements

## High Priority - Immediate Impact

- MAC Address Vendor Lookup - Integrate with macvendors.com API to identify hardware manufacturers. Legacy vendors (old Cisco, 3Com, Linksys) correlate strongly with 32-bit systems.

- Enhanced SNMP HOST-RESOURCES-MIB - Currently only querying basic sys* OIDs. Add CPU detection (hrDeviceDescr), RAM size (hrStorageSize), and system metrics to identify <4GB systems (almost certainly 32-bit).

- Extended Architecture Detection - Add patterns like "ELF 32-bit", "ARMv5tel", "MIPS32", "uClibc", "Windows NT 5.x", "WOW64" to catch more architecture indicators in banners.

- SNMP sysObjectID Mapping - Map OID prefixes to known embedded hardware (Cisco 2600, WRT54G, HP printers) for automatic embedded device classification.

## Medium Priority - Enhanced Analysis

- Service Version Dating - Extend age estimation to Postfix, Exchange, ProFTPD, Samba, nginx, IIS with version→year mappings for more accurate approx_age_year.

- TLS Protocol Analysis - Inspect SSL/TLS versions and cipher suites. Systems limited to SSLv3/TLS1.0 are typically legacy 32-bit builds.

- Enhanced SMB Parsing - Parse Windows version numbers (5.0=Win2000, 5.1=XP), check for "x64 Edition", analyze SMB dialects and buffer sizes.

- NTP Behavioral Analysis - Flag NTPv3 or older, check REFID patterns ("LOCL", "INIT") as legacy firmware indicators.

## Additional Heuristics

- Resource Limit Detection - Use SNMP hrStorageSize and SMB MaxBufferSize to identify <4GB systems (32-bit constraint).

- ARP Table Scanning - Parse system ARP tables to discover MAC addresses for vendor correlation.

- HTTP Header Analysis - Parse Server and X-Powered-By headers for version information.

- IPMI/BMC Detection - Scan port 623 for server management interfaces (old iLO, DRAC often 32-bit).

## Advanced Techniques

- DNS/Hostname Patterns - Extract hints from PTR records and hostnames (e.g., "win2000", "xp", "arm").

- TCP/IP Stack Fingerprinting - Passive OS detection via window size, TTL, TCP options.

- Embedded Device Signatures - Build signature database for IoT, ICS, cameras, routers.

- Confidence Scoring Refinement - Weight evidence sources appropriately for better risk assessment.

The MAC address vendor lookup via macvendors.com API is particularly valuable - it's free (1000 requests/day), requires no API key, and provides direct hardware manufacturer identification that correlates strongly with system age and architecture.
