# Versions

## Version 1

- Basic scanning with LLM support

## Version 2

- ✨ **MAC address discovery** via ARP table parsing with vendor identification
- ✨ **Enhanced SNMP** querying HOST-RESOURCES-MIB for CPU, RAM, and storage metrics
- ✨ **TLS/SSL protocol detection** identifying legacy-only endpoints
- ✨ **IPMI/BMC detection** for server management interfaces
- ✨ **HTTP header analysis** for web server version extraction
- ✨ **Expanded architecture patterns** covering 60+ indicators (ELF, ARM variants, MIPS, Windows NT 5.x, etc.)
- ✨ **Service version database** with 50+ software version→year mappings
- ✨ **sysObjectID mapping** to 19 embedded device families
- ✨ **Memory limit heuristics** auto-flagging <4GB systems
- ✨ **Hostname analysis** extracting OS/device hints from DNS
- ✨ **Refined confidence scoring** with evidence-weighted calculations
- 🔧 **Enhanced SMB parsing** with Windows NT version detection
- 🔧 **NTP behavioral analysis** checking version and REFID patterns
- 📊 **Updated reports** showing MAC vendor, TLS status, IPMI, CPU info, memory size
