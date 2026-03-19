# lanscan

![Local Network Scanner Banner](banner.png)

Scan your local network. Find devices, identify vendors, check open ports, grab banners. One command.

## Install

```bash
chmod +x scanner.sh
sudo ln -sf "$(pwd)/scanner.sh" /usr/local/bin/lanscan
```

Now run `lanscan` from anywhere.

## Usage

```bash
lanscan                          # auto-detect your /24 subnet
lanscan 192.168.1.0/24           # target a specific subnet
lanscan --deep                   # more ports, longer timeouts
lanscan --out mynetwork          # custom output prefix
lanscan --wol AA:BB:CC:DD:EE:FF 192.168.1.100  # wake a device
```

## What it does

- Discovers hosts via nmap (falls back to ping sweep)
- Resolves hostnames via reverse DNS + mDNS/Bonjour
- Looks up vendor from MAC address (auto-downloads IEEE OUI database)
- Scans common ports and grabs service banners
- Classifies devices: routers, PCs, Raspberry Pis, printers, IoT, MCUs, smart TVs, cameras, NAS, and more
- Detects same device on multiple interfaces
- Color-coded table output with device icons
- Exports to JSON and CSV

## Output

```
LAN Scan Results

┌─────────────────┬──────────────────────────┬──────────────────────────────┬─────────────────┐
│ IP Address      │   Hostname               │ Vendor                       │ Ports           │
├─────────────────┼──────────────────────────┼──────────────────────────────┼─────────────────┤
│ 192.168.1.108   │ 🍓 the-ugly-pi.local     │ Raspberry Pi Trading Ltd     │ 22              │
│ 192.168.1.114   │ 🖥️ pi.hole               │ Raspberry Pi Foundation      │ 22,53,80,443    │
│ 192.168.1.157   │ 💻 —                     │ AzureWave Technology Inc.    │ 22,53           │
│ 192.168.1.235   │ 🏠 —                     │ Google, Inc.                 │                 │
│ 192.168.1.254   │ 📡 —                     │ Technicolor                  │ 53,80,443,8080  │
└─────────────────┴──────────────────────────┴──────────────────────────────┴─────────────────┘
```

### Device icons

| Icon | Type |
|------|------|
| 📱 | Phone |
| 💻 | PC |
| 📡 | Router |
| 🍓 | Raspberry Pi |
| 🎮 | Console |
| 🖨️ | Printer |
| 📷 | Camera |
| 📺 | Smart TV |
| 💾 | NAS |
| 🏠 | IoT |
| 🔊 | Speaker |
| 🖥️ | Server |
| 🔌 | Switch/AP |
| 🔧 | MCU (ESP32, Arduino...) |
| ❓ | Unknown |

## Requirements

- macOS or Linux
- `nmap` (recommended), falls back to ping sweep
- `bash` 3.2+

## Legal

Only scan networks you own or have permission to test.
