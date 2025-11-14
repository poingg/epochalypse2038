#!/usr/bin/env python3
"""
Configuration file for Epochalypse Scanner
Centralized location for all configurable parameters
"""

# ============================================================================
# Network Scanning Configuration
# ============================================================================

# Default TCP ports to scan
DEFAULT_TCP_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
]

# Default UDP ports to scan
DEFAULT_UDP_PORTS = [
    53,    # DNS
    123,   # NTP
    161,   # SNMP
    500,   # IKE
    514,   # Syslog
    623,   # IPMI
    1900,  # UPnP
]

# Timeout settings (seconds)
CONNECT_TIMEOUT = 2
READ_TIMEOUT = 2
UDP_TIMEOUT = 2.0

# Maximum banner bytes to read
MAX_BANNER_BYTES = 1024

# Default number of worker threads
DEFAULT_WORKERS = 50

# ============================================================================
# MAC Vendor Lookup Configuration
# ============================================================================

MAC_VENDOR_API_URL = "https://api.macvendors.com/"
MAC_VENDOR_CACHE_FILE = ".mac_vendor_cache.json"
MAC_VENDOR_RATE_LIMIT = 1.0  # seconds between API calls

# ============================================================================
# SNMP Configuration
# ============================================================================

# Default SNMP community string
DEFAULT_SNMP_COMMUNITY = "public"

# SNMP sysObjectID to known embedded/legacy hardware mapping
# Format: OID prefix -> (device_type, likely_32bit, description)
KNOWN_DEVICE_OIDS = {
    # Cisco Routers
    "1.3.6.1.4.1.9.1.107": ("cisco_router", True, "Cisco 2600 series router"),
    "1.3.6.1.4.1.9.1.122": ("cisco_router", True, "Cisco 2800 series router"),
    "1.3.6.1.4.1.9.1.448": ("cisco_router", True, "Cisco 1841 router"),

    # Cisco Switches
    "1.3.6.1.4.1.9.1.324": ("cisco_switch", True, "Cisco 2950 switch"),
    "1.3.6.1.4.1.9.1.359": ("cisco_switch", True, "Cisco 3750 switch"),
    "1.3.6.1.4.1.9.1.525": ("cisco_switch", True, "Cisco 2960 switch"),

    # Network Devices
    "1.3.6.1.4.1.890.1.5": ("zyxel", True, "ZyXEL network device"),
    "1.3.6.1.4.1.3955": ("linksys", True, "Linksys device"),
    "1.3.6.1.4.1.4526": ("netgear", True, "Netgear device"),
    "1.3.6.1.4.1.171": ("dlink", True, "D-Link device"),
    "1.3.6.1.4.1.14988.1": ("mikrotik", True, "MikroTik RouterOS"),

    # Printers
    "1.3.6.1.4.1.11.2.3.7": ("hp_printer", True, "HP LaserJet printer"),
    "1.3.6.1.4.1.11.2.3.9": ("hp_printer", True, "HP DeskJet printer"),

    # Enterprise Equipment
    "1.3.6.1.4.1.2636.1.1": ("juniper", False, "Juniper Networks device"),
    "1.3.6.1.4.1.674.10892": ("dell_server", False, "Dell PowerEdge server"),
    "1.3.6.1.4.1.6876": ("vmware", False, "VMware ESX/ESXi"),
    "1.3.6.1.4.1.12356": ("fortinet", True, "Fortinet FortiGate firewall"),

    # NAS Devices
    "1.3.6.1.4.1.2021.250": ("synology", False, "Synology NAS"),
    "1.3.6.1.4.1.24681": ("qnap", False, "QNAP NAS"),
}

# SNMP OIDs to query
SNMP_OIDS = {
    # Basic system OIDs
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",

    # HOST-RESOURCES-MIB OIDs for hardware detection
    "hrMemorySize": "1.3.6.1.2.1.25.2.2.0",         # Total RAM in KB
    "hrSystemNumUsers": "1.3.6.1.2.1.25.1.5.0",     # Number of users
    "hrDeviceDescr1": "1.3.6.1.2.1.25.3.2.1.3.1",   # Processor info
    "hrDeviceDescr2": "1.3.6.1.2.1.25.3.2.1.3.2",
    "hrStorageSize1": "1.3.6.1.2.1.25.2.3.1.5.1",   # Storage size
    "hrStorageSize2": "1.3.6.1.2.1.25.2.3.1.5.2",
}

# ============================================================================
# Service Version to Release Year Mapping
# ============================================================================

SERVICE_VERSION_YEARS = {
    # Postfix versions
    "postfix 2.0": 2002,
    "postfix 2.1": 2004,
    "postfix 2.2": 2005,
    "postfix 2.3": 2006,
    "postfix 2.4": 2007,
    "postfix 2.5": 2008,
    "postfix 2.6": 2009,
    "postfix 2.7": 2010,
    "postfix 2.8": 2011,
    "postfix 2.9": 2012,
    "postfix 2.10": 2013,
    "postfix 2.11": 2014,
    "postfix 3.0": 2015,

    # ProFTPD versions
    "proftpd 1.2": 2003,
    "proftpd 1.3.0": 2006,
    "proftpd 1.3.1": 2008,
    "proftpd 1.3.2": 2009,
    "proftpd 1.3.3": 2010,
    "proftpd 1.3.4": 2011,
    "proftpd 1.3.5": 2013,

    # Samba versions
    "samba 2.": 1999,
    "samba 3.0": 2003,
    "samba 3.2": 2008,
    "samba 3.4": 2009,
    "samba 3.5": 2010,
    "samba 3.6": 2011,
    "samba 4.0": 2012,
    "samba 4.1": 2013,

    # nginx versions
    "nginx/0.": 2006,
    "nginx/1.0": 2011,
    "nginx/1.2": 2012,
    "nginx/1.4": 2013,
    "nginx/1.6": 2014,

    # Exchange versions
    "exchange 5.5": 1997,
    "exchange 6.0": 2000,
    "exchange 6.5": 2003,
    "exchange 2007": 2007,
    "exchange 2010": 2010,

    # OpenSSL versions
    "openssl 0.9.6": 2000,
    "openssl 0.9.7": 2002,
    "openssl 0.9.8": 2005,
    "openssl 1.0.0": 2010,
    "openssl 1.0.1": 2012,
    "openssl 1.0.2": 2015,
}

# ============================================================================
# Architecture Detection Patterns
# ============================================================================

# 64-bit architecture indicators
ARCH_64BIT_PATTERNS = [
    "x86_64", "amd64", "win64", "x64", "aarch64", "arm64", "ppc64", "s390x",
    "elf 64-bit", "wow64", "x64 edition", "64-bit", "armv8",
    "mips64", "ia64", "sparc64"
]

# 32-bit architecture indicators
ARCH_32BIT_PATTERNS = [
    "i386", "i486", "i586", "i686", "x86", "win32",
    "armv5", "armv6", "armv7", "armv5tel", "armv7l",
    "mips", "mipsel", "mips32", "powerpc", "powerpc 740", "powerpc 750",
    "elf 32-bit", "windows nt 5", "uclibc", "uclinux",
    "bsd/os 4", "sunos 5.8", "sunos 5.9", "intel 486"
]

# ============================================================================
# Embedded Device Detection Keywords
# ============================================================================

EMBEDDED_DEVICE_KEYWORDS = [
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

# ============================================================================
# Operating System Detection Patterns
# ============================================================================

OS_PATTERNS = {
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

# ============================================================================
# Risk Scoring Configuration
# ============================================================================

# Time-critical database ports
TIME_CRITICAL_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}

# Legacy hardware vendors (associated with older equipment)
LEGACY_VENDORS = [
    "3com", "linksys", "netgear", "d-link", "cisco", "hp"
]

# Risk score thresholds
RISK_THRESHOLDS = {
    "critical": 85,
    "vulnerable": 70,
    "potentially_vulnerable": 50,
    "unknown": 30,
    "likely_safe": 15,
}

# Confidence scoring weights
CONFIDENCE_WEIGHTS = {
    "architecture": 0.30,
    "snmp_hr_mib": 0.25,
    "snmp_basic": 0.15,
    "service_version": 0.15,
    "mac_vendor": 0.10,
    "tls_analysis": 0.10,
    "smb_fingerprint": 0.10,
    "multi_service": 0.05,
}

# ============================================================================
# LLM Configuration
# ============================================================================

LLM_DEFAULT_MODEL = "gpt-4.1-mini"
LLM_TEMPERATURE = 0.3
LLM_MAX_TOKENS = 1000
LLM_API_ENDPOINT = "https://api.openai.com/v1/chat/completions"

# ============================================================================
# Report Configuration
# ============================================================================

REPORT_TEXT_WIDTH = 100
REPORT_MAX_BANNER_LENGTH = 100
REPORT_MAX_DESCRIPTION_LENGTH = 150
REPORT_MAX_TCP_SERVICES = 5
REPORT_MAX_UDP_SERVICES = 3
