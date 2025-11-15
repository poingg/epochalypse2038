# Epochalypse Scanner - TODO List

## Additional Heuristics for Y2K38 Vulnerability Detection

### High Priority - Maximum Impact

#### 1. Industrial Control System (ICS) Protocols

- [ ] Add **Modbus TCP** detection (port 502)
- [ ] Add **BACnet** detection (port 47808)
- [ ] Add **DNP3** detection (port 20000)
- [ ] Add **EtherNet/IP** detection (port 44818)
- [ ] Parse protocol-specific device information
- [ ] Note: These systems are notoriously long-lived and 32-bit

#### 2. Database Version Parsing

- [ ] Parse MySQL banner versions (MySQL 3.x/4.x = ancient, likely 32-bit)
- [ ] Extract PostgreSQL version from banners (< 8.x = pre-2005)
- [ ] Add Oracle database port (1521) detection
- [ ] Add SQL Server version detection via SMB or direct connection
- [ ] Map database versions to release years

#### 3. TLS Certificate Analysis Enhancement

- [ ] Analyze certificate expiration dates (certs expiring after 2038 on 32-bit systems)
- [ ] Check certificate issuance dates (pre-2010 suggests old systems)
- [ ] Parse certificate CN/SAN patterns for device identification
- [ ] Add risk scoring based on cert age vs system capabilities

#### 4. UPnP/SSDP Device Information Parsing

- [ ] Parse UPnP device descriptors from port 1900 responses
- [ ] Extract manufacturer, model number, firmware version
- [ ] Many IoT devices expose detailed hardware info via UPnP
- [ ] Map UPnP device types to 32-bit risk profiles

#### 5. Extended Port List Coverage

- [ ] Add SIP port 5060 (UDP/TCP) for VoIP detection
- [ ] Add Modbus TCP port 502 for ICS
- [ ] Add IPP port 631 for CUPS/printer detection
- [ ] Add VNC port 5900 for remote desktop
- [ ] Add Oracle port 1521 for database detection

### Medium Priority - Enhanced Detection

#### 6. FTP/SMTP Version Detection Enhancement

- [ ] Parse vsftpd versions (1.x = 2001-2004 era)
- [ ] Detect Pure-FTPd versions
- [ ] Parse Sendmail versions (especially 8.x series)
- [ ] Detect Exim versions (Exim 3.x = early 2000s)
- [ ] Map to release years in SERVICE_VERSION_YEARS

#### 7. DNS Server Implementation Detection

- [ ] Parse BIND versions from DNS responses
  - [ ] BIND 8.x = 32-bit era (pre-2004)
  - [ ] BIND 9.0-9.3 = potentially 32-bit (2000-2005)
- [ ] Enhance version.bind CHAOS query parsing (port 53 already probed)
- [ ] Add dnsmasq/unbound version detection

#### 8. Kernel/OS Version Pattern Enhancement

- [ ] Detect Linux kernel versions from banners (2.4.x kernel = 32-bit era)
- [ ] Parse Windows NT version numbers more precisely:
  - [ ] NT 4.0 = definitely 32-bit
  - [ ] NT 5.0/5.1/5.2 = Windows 2000/XP/2003 (highly vulnerable)
  - [ ] NT 6.0/6.1 = Vista/7 (check for 32-bit edition)
- [ ] Add Solaris version detection (SunOS 5.8/5.9 = 32-bit)

#### 9. VoIP/SIP Detection

- [ ] Detect SIP on port 5060 (UDP/TCP)
- [ ] Parse SIP USER-AGENT headers for device/firmware info
- [ ] Identify PBX systems (Asterisk, FreePBX versions)
- [ ] Detect IP phone models (Cisco, Polycom, Yealink)
- [ ] Note: Many VoIP systems run 32-bit embedded OSes

#### 10. CUPS Printer Detection

- [ ] Add IPP port 631 to default scan list
- [ ] Detect CUPS version (many embedded print servers run old CUPS)
- [ ] Parse printer firmware information
- [ ] Note: Printer firmware often uses 32-bit time

### Lower Priority - Refinement

#### 11. Real-Time Clock/RTC Detection

- [ ] Detect IPMI firmware versions (many BMCs have 32-bit RTCs)
- [ ] Check for BIOS date constraints via SNMP
- [ ] Identify hardware RTC limitations from device info

#### 12. Syslog Server Detection Enhancement

- [ ] Parse syslog-ng vs rsyslog versions from port 514
- [ ] Check for timezone handling patterns
- [ ] Detect logging timestamp formats

#### 13. VNC/Remote Desktop Detection

- [ ] Add VNC port 5900 to scan list
- [ ] Detect RealVNC, TightVNC versions
- [ ] Note: Many embedded VNC servers are 32-bit

#### 14. Java/JVM Version Detection

- [ ] Parse Java version from HTTP headers (X-Powered-By: Servlet/X.X)
- [ ] Detect JRE/JDK version patterns in service banners
- [ ] Add scoring for Java 1.6 and earlier (32-bit time issues)
- [ ] Map Java versions to release years

#### 15. PHP Version Detection Enhancement

- [ ] Parse PHP versions from X-Powered-By headers (already captured)
- [ ] Add risk scoring for PHP 5.x series (pre-2014)
- [ ] Flag PHP 4.x (ancient) as definite risk
- [ ] Correlate PHP version with likely 32-bit systems

#### 16. Memory Address Space Patterns

- [ ] Look for 32-bit address space patterns in SNMP sysDescr
- [ ] Detect process listings showing max 4GB memory allocation
- [ ] Identify PAE (Physical Address Extension) references = 32-bit kernel workaround

#### 17. File System Type Detection

- [ ] Detect FAT32 from SNMP (4GB file size limit = likely older 32-bit)
- [ ] Identify ext2/ext3 without ext4 (pre-2008 Linux)
- [ ] Flag NTFS on Windows 2000/XP

#### 18. Hardware Vendor-Specific Pattern Expansion

- [ ] Add Buffalo Technology to MAC vendor scoring (NAS devices, often 32-bit)
- [ ] Add Western Digital (MyCloud series has Y2K38 issues)
- [ ] Add Seagate (older NAS products)
- [ ] Parse QNAP/Synology model numbers (early models are 32-bit ARM)

#### 19. Bootloader/Firmware Pattern Detection

- [ ] Detect U-Boot version in banners (bootloader for ARM devices)
- [ ] Identify RedBoot patterns (Cisco/network equipment)
- [ ] Check for GRUB version hints (GRUB 0.x = ancient)

#### 20. SSL/TLS Cipher Suite Analysis

- [ ] Detect systems only supporting RC4, DES, 3DES (ancient)
- [ ] Flag systems with no ECDHE support (pre-2010 OpenSSL)
- [ ] Analyze cipher strength limitations (old crypto stack indicator)

#### 21. Port Combination Pattern Analysis

- [ ] Create fingerprints based on port combinations:
  - [ ] 21+23+80 (no SSH) = very old embedded device
  - [ ] 139+445 without modern ports = Windows NT/2000
  - [ ] 80+8080+1900 = consumer router pattern
  - [ ] 623+161+443 = server with BMC (check BMC architecture)

## Code Quality Improvements

### Refactoring

- [ ] Split large functions in [risk_scoring.py](risk_scoring.py) for better maintainability
- [ ] Add more comprehensive unit tests
- [ ] Improve error handling and logging
- [ ] Add debug/verbose mode for troubleshooting

### Performance

- [ ] Optimize SNMP queries (batch multiple OIDs)
- [ ] Add connection pooling for HTTP requests
- [ ] Implement smarter timeout handling
- [ ] Add progress indicators for long scans

### Documentation

- [ ] Add inline documentation for complex heuristics
- [ ] Create architecture diagrams
- [ ] Document risk scoring algorithm in detail
- [ ] Add more usage examples

## Feature Enhancements

### Reporting

- [ ] Add HTML report format with charts
- [ ] Create executive summary section
- [ ] Add remediation recommendations per device type
- [ ] Generate compliance reports (for audit purposes)

### Integration

- [ ] Add Splunk/ELK output format
- [ ] Create Ansible/Puppet integration modules
- [ ] Add webhook support for alerting
- [ ] Support asset management system imports (CSV/API)

### Scanning

- [ ] Add IPv6 support
- [ ] Implement adaptive scanning (adjust based on discovered info)
- [ ] Add credential-based deep scanning (SSH/WMI)
- [ ] Support proxy/tunnel scanning for remote networks

## Notes

- Priority is based on detection impact and prevalence of vulnerable systems
- ICS/SCADA protocols are highest priority due to critical infrastructure impact
- Database and certificate analysis provide high value with minimal code changes
- Many lower-priority items can be implemented incrementally
