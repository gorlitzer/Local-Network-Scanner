# Local Network Scanner

This project contains a shell script (`scanner.sh`) for scanning devices on your local network. The script discovers active hosts, identifies device vendors using IEEE OUI database, probes open ports and service banners, and displays results in a visually appealing ASCII table with device classification and icons.

## Features

- **Host Discovery**: Uses nmap for efficient host discovery, with ping sweep fallback
- **Vendor Identification**: Automatically identifies device manufacturers using IEEE OUI database
- **Port Scanning**: Scans common ports (22, 23, 53, 80, 443, 139, 445, 3389, 8080, etc.) with optional deep scanning
- **Service Banner Grabbing**: Attempts to identify running services on open ports
- **Device Classification**: Categorizes devices as PCs, routers, Raspberry Pis, phones, etc. with emoji icons
- **Multiple Output Formats**: Saves results as JSON and CSV files
- **Wake-on-LAN Support**: Can send WOL magic packets to wake sleeping devices

## Usage

### Basic Scan
```sh
./scanner.sh
```

### Scan Specific Network
```sh
./scanner.sh 192.168.1.0/24
```

### Deep Scan (More Ports, Longer Banner Grabs)
```sh
./scanner.sh --deep
```

### Custom Output Prefix
```sh
./scanner.sh --out my_scan
```

### Wake-on-LAN
```sh
./scanner.sh --wol AA:BB:CC:DD:EE:FF 192.168.1.100
```

## Requirements

- **Operating System**: macOS or Linux
- **Shell**: zsh or bash
- **Tools**: nmap (recommended), arp, nc/netcat, jq (optional for better JSON parsing)
- **Network**: Permission to scan the target network

## Setup

1. Make the script executable:
   ```sh
   chmod +x scanner.sh
   ```

2. For vendor lookup (optional but recommended):
   - The script will automatically download the IEEE OUI database on first run
   - Or manually create `oui.txt` with format: `OUI<TAB>Vendor Name`

## Output Files

- `lan_scan_results.json`: Structured JSON data
- `lan_scan_results.csv`: Comma-separated values for spreadsheet import
- ASCII table display in terminal with device icons and vendor information

## Legal Notice

⚠️ **Only scan networks you own or have explicit permission to test.** Unauthorized network scanning may violate laws and terms of service.

## Recent Fixes

- Fixed "tr: Illegal byte sequence" error on macOS by using `LC_ALL=C` locale
- Improved banner parsing with proper JSON handling using jq when available
- Enhanced table formatting with dynamic column widths and text truncation
- Expanded OUI database with comprehensive vendor list including NVIDIA, Apple, Microsoft, etc.
- Better error handling and cross-platform compatibility

## License

MIT
