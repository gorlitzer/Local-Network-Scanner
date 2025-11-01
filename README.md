# Local Network Scanner

> **TL;DR**: A powerful network reconnaissance tool that discovers devices, identifies vendors, scans ports, and grabs service banners. Perfect for security audits and network administration.

![Local Network Scanner Banner](banner.png)

A comprehensive network reconnaissance tool designed for **security professionals** and **network administrators**. This utility performs automated discovery and enumeration of devices within local network segments, providing detailed intelligence on active hosts, services, and device characteristics.

## Overview

The Local Network Scanner conducts multi-phase network reconnaissance including host discovery, port scanning, service enumeration, and device fingerprinting. Results are presented in structured formats suitable for integration with other security tools and workflows.

## Key Capabilities

### Host Discovery & Enumeration
- **Network Discovery**: Utilizes *nmap* for efficient host discovery with fallback to *ICMP* ping sweeps
- **Device Identification**: Automatic vendor identification through *IEEE OUI* database lookup
- **Service Probing**: Comprehensive port scanning with service banner extraction

### Advanced Analysis
- **Port Scanning**: Systematic enumeration of common service ports (`22`, `23`, `53`, `80`, `443`, `139`, `445`, `3389`, `8080`) with optional extended scanning
- **Service Fingerprinting**: Banner grabbing and protocol analysis for service identification
- **Device Classification**: Intelligent categorization of discovered devices with visual indicators

### Output & Integration
- **Structured Data**: *JSON* and *CSV* export formats for downstream analysis
- **Visual Reporting**: Formatted terminal output with device metadata
- **Wake-on-LAN**: Network-powered device activation support

## Installation & Configuration

### Prerequisites
- **Operating System**: *macOS* or *Linux*
- **Shell Environment**: *bash* or *zsh*
- **Core Utilities**: *nmap*, *arp*, *netcat* (`nc`), *jq* (optional for enhanced JSON processing)
- **Network Access**: Appropriate permissions for target network segmentation

### Initial Setup
1. Execute permissions configuration:
   ```bash
   chmod +x scanner.sh
   ```

2. OUI Database initialization (optional but recommended):
   - Automatic: Script downloads *IEEE OUI* database on first execution
   - Manual: Create `oui.txt` with OUI-to-vendor mappings (format: `OUI<TAB>Vendor Name`)

## Usage Examples

### Standard Network Scan
```bash
./scanner.sh
```

### Targeted Network Segmentation
```bash
./scanner.sh 192.168.1.0/24
```

### Comprehensive Analysis
```bash
./scanner.sh --deep
```

### Custom Output Configuration
```bash
./scanner.sh --out security_audit_$(date +%Y%m%d)
```

### Remote Device Activation
```bash
./scanner.sh --wol AA:BB:CC:DD:EE:FF 192.168.1.100
```

## Output Specifications

### Generated Artifacts
- `lan_scan_results.json`: Machine-readable *JSON* data structure
- `lan_scan_results.csv`: Spreadsheet-compatible *CSV* format
- **Terminal Display**: Formatted table with device classification and vendor information

### Data Structure
Results include *IP addresses*, *MAC addresses*, vendor identification, open ports, service banners, and device classifications for comprehensive network mapping.

## Security Considerations

### Legal Compliance
⚠️ **Authorized Use Only**: This tool must only be deployed against networks and systems for which you possess explicit authorization. Unauthorized network scanning may violate applicable laws, regulations, and terms of service.

### Operational Security
- Network reconnaissance activities should be conducted during authorized testing windows
- Results should be handled as sensitive security information
- Compliance with organizational security policies and procedures is required

## Technical Specifications

### Performance Characteristics
- **Scan Duration**: Variable based on network size and selected scanning depth
- **Resource Usage**: Minimal system resource consumption during operation
- **Compatibility**: Cross-platform support for macOS and Linux environments

### Network Requirements
- Sufficient network access for ICMP and TCP port scanning
- Appropriate firewall permissions for service enumeration
- Network latency considerations for optimal discovery performance

## Troubleshooting

### Common Issues
- **Locale Errors**: *macOS* locale configuration resolved via `LC_ALL=C` environment setting
- **Permission Denied**: Ensure adequate network scanning permissions
- **Banner Parsing**: Enhanced parsing available with *jq* installation

### Performance Optimization
- *Deep scans* significantly increase scan duration
- Large networks may require extended execution time
- Consider network segmentation for comprehensive coverage

## License & Contribution

This project is licensed under the *MIT License*. Contributions are welcome through standard open-source collaboration processes.

## Version Information

Current Version: 1.0.0
Last Updated: November 2025
