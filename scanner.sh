#!/usr/bin/env bash
# lan_scan.sh - portable zsh/bash LAN scanner for macOS & Linux
# Usage:
#   ./lan_scan.sh [CIDR] [--deep] [--out PREFIX] 
#   ./lan_scan.sh --wol AA:BB:CC:DD:EE:FF 192.168.1.5   # send Wake-on-LAN magic packet
#
# Examples:
#   sudo ./lan_scan.sh 192.168.1.0/24
#   ./lan_scan.sh                # auto-detect /24 subnet
#
# Outputs:
#   <out_prefix>_scan_results.json
#   <out_prefix>_scan_results.csv
#
# Notes:
#  - Run with sudo when using nmap's advanced features or arp-scan.
#  - To enable vendor lookup create a file named "oui.txt" in the same directory:
#       format: "001122\tVendor Name" where 001122 are hex OUI (no separators), OR
#       get IEEE OUI listing and convert to that format (instructions below).
#  - Use --deep to scan more ports and attempt longer banner grabs.
#
# Legal: Only run on networks you own or have permission to test.
################################################################################

set -euo pipefail
IFS=$'\n\t'

# default settings
OUT_PREFIX="lan"
CIDR=""
DEEP=0
TIMEOUT_CMD="timeout"   # fallback if available; macOS uses gtimeout (from coreutils)
COMMON_PORTS=(22 23 53 80 443 139 445 515 631 3389 8080 9100 1900 5353 3306 5900)
DEEP_PORTS=(21 22 23 25 53 67 68 80 110 139 143 161 443 445 515 587 631 3306 3389 5900 8080 8443 8888 9100 5353 1900)
# Resolve SCRIPT_DIR through symlinks (macOS compatible)
_source="${BASH_SOURCE[0]}"
while [[ -L "$_source" ]]; do
  _dir="$(cd "$(dirname "$_source")" && pwd)"
  _source="$(readlink "$_source")"
  [[ "$_source" != /* ]] && _source="$_dir/$_source"
done
SCRIPT_DIR="$(cd "$(dirname "$_source")" && pwd)"
unset _source _dir

# ANSI color codes
C_RESET='\033[0m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_CYAN='\033[0;36m'
C_MAGENTA='\033[0;35m'
C_RED='\033[0;31m'
C_BLUE='\033[0;34m'
C_BOLD='\033[1m'
C_DIM='\033[2m'

# Disable colors if stdout is not a terminal
if [[ ! -t 1 ]]; then
  C_RESET="" C_GREEN="" C_YELLOW="" C_CYAN="" C_MAGENTA="" C_RED="" C_BLUE="" C_BOLD="" C_DIM=""
fi

# check for command presence
has_cmd() { command -v "$1" >/dev/null 2>&1; }

# pick timeout wrapper (macOS coreutils can provide gtimeout)
if has_cmd timeout; then
  TIMEOUT_WRAPPER="timeout"
elif has_cmd gtimeout; then
  TIMEOUT_WRAPPER="gtimeout"
else
  TIMEOUT_WRAPPER=""
fi

usage() {
  cat <<EOF
Usage: $0 [CIDR] [--deep] [--out PREFIX] | --wol MAC IP
Options:
  CIDR         network to scan (e.g. 192.168.1.0/24). Auto-detected if omitted.
  --deep       run a deeper scan (more ports, longer banner grabs)
  --out PREFIX output files prefix (default: lan)
  --wol MAC IP send Wake-on-LAN magic packet to MAC and target IP (requires root to send broadcast)
EOF
  exit 1
}

# Wake-on-LAN function
send_wol() {
  local MAC="$1"
  local TARGET_IP="${2:-255.255.255.255}"
  # normalize MAC
  local mac_clean
  mac_clean=$(echo "$MAC" | tr -d ':-' | tr '[:lower:]' '[:upper:]')
  if [[ ${#mac_clean} -ne 12 ]]; then
    echo "Invalid MAC format: $MAC"; exit 2
  fi
  local payload
  payload=$(printf 'FF%.0s' {1..6})
  for i in $(seq 0 15); do payload="$payload$mac_clean"; done

  # convert hex string to binary and send to broadcast port 9
  # Use xxd if available, otherwise use python -c (but we try to avoid python)
  if has_cmd xxd; then
    echo "$payload" | sed 's/../& /g' | xxd -r -p | nc -w1 -u -b "$TARGET_IP" 9 || {
      # try broadcast
      echo "$payload" | sed 's/../& /g' | xxd -r -p | nc -w1 -u -b 255.255.255.255 9
    }
  elif has_cmd openssl; then
    echo "$payload" | sed 's/../& /g' | awk '{for(i=1;i<=NF;i++) printf "%c", strtonum("0x"$i)}' | nc -w1 -u -b "$TARGET_IP" 9
  else
    echo "Cannot send WOL: missing 'xxd' or 'openssl'."
    exit 2
  fi
  echo "WOL packet sent to $MAC via $TARGET_IP"
  exit 0
}

# parse args
if [[ $# -gt 0 ]]; then
  case "$1" in
    --wol)
      if [[ $# -ne 3 ]]; then usage; fi
      send_wol "$2" "$3"
      ;;
  esac
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep) DEEP=1; shift ;;
    --out) OUT_PREFIX="$2"; shift 2 ;;
    -*|--*) echo "Unknown option: $1"; usage ;;
    *) 
       if [[ -z "$CIDR" ]]; then CIDR="$1"; shift; else echo "Multiple CIDRs? $1"; usage; fi
       ;;
  esac
done

# Auto-detect CIDR (only IPv4 /24 heuristic)
if [[ -z "$CIDR" ]]; then
  if has_cmd ip && [[ "$(uname)" != "Darwin" ]]; then
    # Linux: ip route to detect the interface network
    # gets a route like "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.12"
    CIDR=$(ip -4 route list match 0/0 | awk '{for(i=1;i<=NF;i++) if ($i ~ /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+/) print $i; exit}')
    if [[ -z "$CIDR" ]]; then
      CIDR=$(ip -4 addr show scope global | awk '/inet /{print $2; exit}')
    fi
  else
    # macOS or fallback: use route get or ifconfig
    if has_cmd route; then
      # route get default -> start address. We will turn it into /24 by taking first 3 octets
      local_ip=$(route get default 2>/dev/null | awk '/interface:/{print $2; exit}')
      if [[ -n "$local_ip" ]]; then
        cidr_try=$(ifconfig "$local_ip" 2>/dev/null | awk '/inet /{print $2; exit}')
      fi
      if [[ -z "$cidr_try" ]]; then
        cidr_try=$(ifconfig 2>/dev/null | awk '/inet / && $2 != "127.0.0.1"{print $2; exit}')
      fi
      if [[ -n "$cidr_try" ]]; then
        IFS='.' read -r o1 o2 o3 o4 <<< "$cidr_try"
        CIDR="${o1}.${o2}.${o3}.0/24"
      fi
    fi
  fi
fi

# Fallback if still empty
if [[ -z "$CIDR" ]]; then
  echo "Could not auto-detect network. Please specify CIDR like 192.168.1.0/24"
  exit 1
fi

printf "${C_BOLD}Starting LAN scan on ${C_GREEN}$CIDR${C_RESET}\n"
echo "Output prefix: $OUT_PREFIX"
echo
printf "${C_RED}${C_BOLD}⚠  WARNING: Only scan networks you own or are authorized to test.${C_RESET}\n"
echo

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

DISCOVERED_IPS="$TMPDIR/ips.txt"
ARP_RAW="$TMPDIR/arp_raw.txt"
RESULTS_JSON="${OUT_PREFIX}_scan_results.json"
RESULTS_CSV="${OUT_PREFIX}_scan_results.csv"
NDJSON="$TMPDIR/ndjson.tmp"

> "$DISCOVERED_IPS"
> "$NDJSON"

# 1) Discover hosts: prefer nmap -sn
discover_hosts() {
  if has_cmd nmap; then
    echo "Using nmap for host discovery..."
    if [[ $DEEP -eq 1 ]]; then
      # slower but thorough pings
      sudo nmap -sn "$CIDR" -n -oG - 2>/dev/null | awk '/Up$/{print $2}' | sort -u > "$DISCOVERED_IPS"
    else
      nmap -sn "$CIDR" -n -oG - 2>/dev/null | awk '/Up$/{print $2}' | sort -u > "$DISCOVERED_IPS"
    fi
  else
    echo "nmap not found — falling back to ping sweep (this is slower)..."
    # extract base first three octets for /24 only
    base=$(echo "$CIDR" | awk -F/ '{print $1}' | awk -F. '{print $1"."$2"."$3}')
    if [[ -z "$base" ]]; then
      echo "CIDR not in expected /24 format. Please run with nmap installed or provide a /24."
      exit 1
    fi
    # ping in background
    for i in $(seq 1 254); do
      ip="${base}.${i}"
      ( ping -c 1 -W 1 "$ip" >/dev/null 2>&1 && echo "$ip" >> "$DISCOVERED_IPS" ) &
      # throttle a bit
      if (( i % 50 == 0 )); then wait; fi
    done
    wait
    sort -u "$DISCOVERED_IPS" -o "$DISCOVERED_IPS"
  fi

  echo "Discovered $(wc -l < "$DISCOVERED_IPS") hosts."
}

# 2) Populate/collect ARP table (Linux / macOS)
collect_arp() {
  echo "Collecting ARP table..."
  # on Linux: /proc/net/arp
  if [[ -f /proc/net/arp ]]; then
    awk 'NR>1 {print $1" "$4}' /proc/net/arp > "$ARP_RAW" || true
  else
    # macOS or fallback: arp -a
    if has_cmd arp; then
      arp -an | awk '/\([0-9]/ { gsub(/[()]/,"",$2); ip=$2; mac=$4; if(mac=="<incomplete>") mac=""; print ip" "mac }' > "$ARP_RAW" || true
    fi
  fi
}

# 3) Auto-download OUI database if missing
ensure_oui() {
  local oui_path="$SCRIPT_DIR/oui.txt"
  if [[ -f "$oui_path" ]]; then return 0; fi
  printf "${C_YELLOW}OUI database not found. Downloading IEEE OUI list...${C_RESET}\n"
  local url="http://standards-oui.ieee.org/oui/oui.txt"
  local raw="$TMPDIR/oui_raw.txt"
  if has_cmd curl; then
    curl -sL "$url" -o "$raw"
  elif has_cmd wget; then
    wget -q "$url" -O "$raw"
  else
    printf "${C_RED}Warning: Cannot download OUI database (no curl/wget). Vendor lookup disabled.${C_RESET}\n"
    return 1
  fi
  awk -F'\t' '/\(hex\)/ { gsub(/-/,"",$1); split($1,a," "); print a[1]"\t"$3 }' "$raw" > "$oui_path"
  printf "${C_GREEN}OUI database saved (%d entries).${C_RESET}\n" "$(wc -l < "$oui_path")"
}

# helper: look up vendor from oui.txt (format: 001122<TAB>Vendor Name)
vendor_lookup() {
  local mac="$1"
  local vendor=""
  local oui_path="$SCRIPT_DIR/oui.txt"
  if [[ -f "$oui_path" ]]; then
    hex=$(printf '%s' "$mac" | tr -d ':' | tr -d '-' | tr -d ' ' | cut -c1-6 | tr '[:lower:]' '[:upper:]')
    if [[ ${#hex} -eq 6 ]]; then
      vendor=$(awk -v k="$hex" -F'\t' '$1==k{print $2; exit}' "$oui_path" || true)
    fi
  fi
  echo "$vendor"
}

# 4) reverse DNS
reverse_dns() {
  local ip="$1"
  local name=""

  # 1. Try standard Unicast DNS
  if has_cmd host; then
    name=$(host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//')
  elif has_cmd dig; then
    name=$(dig -x "$ip" +short | sed 's/\.$//' | head -n1)
  fi

  # 2. If no name, try Multicast DNS (mDNS)
  # Use short timeout to avoid hanging
  if [[ -z "$name" ]] && has_cmd dig; then
    name=$(dig -x "$ip" @224.0.0.251 -p 5353 +short +time=1 +tries=1 2>/dev/null | sed 's/\.$//' | head -n1)
  fi

  # 3. If still no name, try NetBIOS (nmblookup) if available
  if [[ -z "$name" ]] && has_cmd nmblookup; then
    name=$(nmblookup -A "$ip" 2>/dev/null | awk '/<00>/ && !/GROUP/ {print $1; exit}')
  fi

  echo "$name"
}

# 5) mDNS/Bonjour discovery for richer device names
discover_mdns() {
  local mdns_file="$TMPDIR/mdns_names.txt"
  > "$mdns_file"
  if [[ "$(uname)" == "Darwin" ]] && has_cmd dns-sd && [[ -n "$TIMEOUT_WRAPPER" ]]; then
    printf "${C_DIM}Discovering mDNS services...${C_RESET}\n"
    for svc in _http._tcp _ssh._tcp _smb._tcp _printer._tcp _ipp._tcp _airplay._tcp _raop._tcp _googlecast._tcp _hap._tcp; do
      $TIMEOUT_WRAPPER 3 dns-sd -B "$svc" local. 2>/dev/null | awk '/Add/{print $NF"\t'"$svc"'"}' >> "$mdns_file" &
    done
    wait
  elif has_cmd avahi-browse && [[ -n "$TIMEOUT_WRAPPER" ]]; then
    printf "${C_DIM}Discovering mDNS services...${C_RESET}\n"
    $TIMEOUT_WRAPPER 5 avahi-browse -aptk 2>/dev/null | awk -F';' '/^=/{print $4"\t"$5}' >> "$mdns_file" || true
  fi
}

mdns_lookup_name() {
  local ip="$1"
  if [[ "$(uname)" == "Darwin" ]] && has_cmd dns-sd && [[ -n "$TIMEOUT_WRAPPER" ]]; then
    local name
    name=$($TIMEOUT_WRAPPER 2 dns-sd -G v4 "$ip" 2>/dev/null | awk 'NR>1{print $6; exit}' || true)
    if [[ -n "$name" ]]; then echo "$name"; return; fi
  elif has_cmd avahi-resolve; then
    local name
    name=$(avahi-resolve -a "$ip" 2>/dev/null | awk '{print $2}' || true)
    if [[ -n "$name" ]]; then echo "$name"; return; fi
  fi
  echo ""
}

# 6) probe port (fast). Using nc if available, otherwise /dev/tcp.
probe_port_banner() {
  local ip="$1"; local port="$2"; local timeout_s="$3"
  local banner=""
  if has_cmd nc; then
    banner=$(nc -w "$timeout_s" "$ip" "$port" 2>/dev/null | head -c 512 | LC_ALL=C tr -d '\r' || true)
  else
    # try bash /dev/tcp (note: no banner read timeout guarantee)
    if (exec 3<>/dev/tcp/"$ip"/"$port") 2>/dev/null; then
      # try to read non-blocking with timeout hack using dd & sleep
      banner=$( { read -t "$timeout_s" -r -n 512 out && printf "%s" "$out"; } 2>/dev/null || true)
      exec 3>&-
    else
      banner=""
    fi
  fi
  # clean non-printables, limit length
  banner=$(echo "$banner" | LC_ALL=C tr -cd '\11\12\15\40-\176' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | head -c 400)
  echo "$banner"
}

# 6) device type classification
icon_for_type() {
  case "$1" in
    phone)     echo "📱";;
    pc)        echo "💻";;
    router)    echo "📡";;
    pi)        echo "🍓";;
    console)   echo "🎮";;
    printer)   echo "🖨️";;
    camera)    echo "📷";;
    smart_tv)  echo "📺";;
    nas)       echo "💾";;
    iot)       echo "🏠";;
    speaker)   echo "🔊";;
    server)    echo "🖥️";;
    switch_ap) echo "🔌";;
    mcu)       echo "🔧";;
    *)         echo "❓";;
  esac
}

classify_type() {
  local vendor="$1" hostname="$2" mac="$3" ports="$4"
  local v_lower h_lower
  v_lower=$(echo "$vendor" | tr '[:upper:]' '[:lower:]')
  h_lower=$(echo "$hostname" | tr '[:upper:]' '[:lower:]')

  # Hostname-based (highest priority)
  if [[ "$h_lower" =~ (raspberry|raspberrypi|rpi) ]]; then echo "pi"; return; fi
  if [[ "$h_lower" =~ (pihole|pi[-.]?hole) ]]; then echo "server"; return; fi
  if [[ "$h_lower" =~ (nas|synology|diskstation|qnap|freenas|truenas|unraid) ]]; then echo "nas"; return; fi
  if [[ "$h_lower" =~ (tv|bravia|roku|firestick|fire-tv|chromecast|appletv|apple-tv|smarttv|tizen|webos|vidaa) ]]; then echo "smart_tv"; return; fi
  if [[ "$h_lower" =~ (echo|alexa|dot|show|nest-hub|google-home|homepod|home-mini|nest-mini) ]]; then echo "speaker"; return; fi
  if [[ "$h_lower" =~ (sonos|beam|arc|sub|one|play:1|play:3|play:5|symfonisk) ]]; then echo "speaker"; return; fi
  if [[ "$h_lower" =~ (esp|esp32|esp8266|wemos|nodemcu|arduino|d1.mini|m5stack|m5stick|lolin|ttgo|xiao|pico.w|feather|particle|teensy) ]]; then echo "mcu"; return; fi
  if [[ "$h_lower" =~ (tasmota|esphome|wled) ]]; then echo "mcu"; return; fi
  if [[ "$h_lower" =~ (hue|tradfri|wiz|lifx|nanoleaf|smartthings|tuya|shelly|homebridge|homeassistant|home-assistant) ]]; then echo "iot"; return; fi
  if [[ "$h_lower" =~ (phone|android|iphone|ipad|galaxy|pixel|oneplus|huawei|oppo|xiaomi|redmi|poco|realme|a96) ]]; then echo "phone"; return; fi
  if [[ "$h_lower" =~ (xbox|playstation|ps[345]|nintendo|switch) ]]; then echo "console"; return; fi
  if [[ "$h_lower" =~ (openwrt|router|gateway|modem|fritz|fritzbox|edgerouter|unifi-gw|ubnt|mikrotik) ]]; then echo "router"; return; fi
  if [[ "$h_lower" =~ (switch|ap|access.point|unifi-ap|eap) ]]; then echo "switch_ap"; return; fi
  if [[ "$h_lower" =~ (printer|laserjet|officejet|deskjet|mfc-|hl-|ecosys|kyocera|epson|pixma) ]]; then echo "printer"; return; fi
  if [[ "$h_lower" =~ (cam|camera|ipcam|doorbell|ring|arlo|nest-cam|wyze) ]]; then echo "camera"; return; fi
  if [[ "$h_lower" =~ (server|srv|proxmox|esxi|vmware|docker|kube|k3s|k8s) ]]; then echo "server"; return; fi
  if [[ "$h_lower" =~ (macbook|imac|mac-pro|mac-mini|mac-studio) ]]; then echo "pc"; return; fi
  if [[ "$h_lower" =~ (desktop|laptop|thinkpad|latitude|xps|surface|zenbook|spectre) ]]; then echo "pc"; return; fi

  # Vendor-based
  if [[ "$v_lower" =~ (synology|qnap|netgear.readynas|western.digital|buffalo|drobo|asustor) ]]; then echo "nas"; return; fi
  if [[ "$v_lower" =~ (samsung.electronics|lg.electronics|sony|vizio|hisense|tcl|roku) ]]; then echo "smart_tv"; return; fi
  if [[ "$v_lower" =~ (sonos|bose|harman|jbl|bang.olufsen|denon|marantz) ]]; then echo "speaker"; return; fi
  if [[ "$v_lower" =~ (amazon|echo|ring) ]]; then echo "speaker"; return; fi
  if [[ "$v_lower" =~ (espressif|arduino|seeed|adafruit|wemos|m5stack|olimex|particle|nordic.semi|silicon.labs|texas.instruments|microchip|stmicro) ]]; then echo "mcu"; return; fi
  if [[ "$v_lower" =~ (signify|philips.lighting|philips.hue|ikea.of.sweden|lifx|nanoleaf|tuya|shelly) ]]; then echo "iot"; return; fi
  if [[ "$v_lower" =~ (nest|google.*home) ]]; then echo "iot"; return; fi
  if [[ "$v_lower" =~ (cisco|ubiquiti|tp-link|netgear|d-link|technicolor|arris|actiontec|mikrotik|zyxel|huawei.tech|draytek|fortinet|sonicwall|juniper|pfsense) ]]; then echo "router"; return; fi
  if [[ "$v_lower" =~ (hewlett|hp.inc|canon|epson|brother|kyocera|xerox|lexmark|ricoh|konica|sharp.corp|oki.data) ]]; then echo "printer"; return; fi
  if [[ "$v_lower" =~ (hikvision|dahua|axis|reolink|amcrest|lorex|vivotek|bosch.security|hanwha|flir) ]]; then echo "camera"; return; fi
  if [[ "$v_lower" =~ (raspberry.pi|pi.foundation) ]]; then echo "pi"; return; fi
  if [[ "$v_lower" =~ (microsoft|xbox) ]]; then echo "pc"; return; fi
  if [[ "$v_lower" =~ (apple|dell|lenovo|acer|asus|intel.corporate|gigabyte|msi|asrock|supermicro) ]]; then echo "pc"; return; fi
  if [[ "$v_lower" =~ (azurewave|realtek|qualcomm.atheros|mediatek|ralink|broadcom|intel.wireless) ]]; then echo "pc"; return; fi
  if [[ "$v_lower" =~ (samsung|huawei.device|oneplus|xiaomi|oppo|vivo|realme|motorola|zte|nokia.mobile) ]]; then echo "phone"; return; fi
  if [[ "$v_lower" =~ (google) ]]; then echo "iot"; return; fi

  # Port-based fallbacks
  if [[ "$ports" =~ (9100) ]]; then echo "printer"; return; fi
  if [[ "$ports" =~ (8096|32400|8989|7878) ]]; then echo "server"; return; fi
  if [[ "$ports" =~ (5357|137|138|139|445) && "$ports" =~ (22|3389) ]]; then echo "pc"; return; fi
  if [[ "$ports" =~ 5900 ]]; then echo "pc"; return; fi
  # Router heuristic: DNS + HTTP + many services
  if [[ "$ports" =~ 53 && "$ports" =~ (80|443) && "$ports" =~ (139|445|631|8080) ]]; then echo "router"; return; fi

  echo "other"
}

# 7) scan ports list for an IP, output JSON object per host
scan_host() {
  local ip="$1"
  local mac vendor rname
  mac=$(awk -v ip="$ip" '$1==ip{print $2; exit}' "$ARP_RAW" || true)
  if [[ -z "$mac" ]]; then mac=""; fi
  if [[ -n "$mac" ]]; then vendor=$(vendor_lookup "$mac"); else vendor=""; fi
  rname=$(reverse_dns "$ip" || true)
  if [[ -z "$rname" ]]; then
    rname=$(mdns_lookup_name "$ip" || true)
  fi

  # choose ports list
  local -a portset
  if [[ $DEEP -eq 1 ]]; then
    portset=("${DEEP_PORTS[@]}")
    timeout_sec=5
  else
    portset=("${COMMON_PORTS[@]}")
    timeout_sec=3
  fi

  # if nmap available, use it for port scan (less noisy than many connect attempts)
  local open_ports_json="[]"
  local ports_found=()
  declare -a port_banners
  if has_cmd nmap; then
    # Add timeout to prevent hanging (30s per host max)
    local nmap_timeout="30s"
    if [[ $DEEP -eq 1 ]]; then
      # more thorough
      nmout=$(nmap -Pn -sT -p "$(IFS=,; echo "${portset[*]}")" --open -n --host-timeout "$nmap_timeout" -oG - "$ip" 2>/dev/null || true)
    else
      nmout=$(nmap -Pn -sT -p "$(IFS=,; echo "${portset[*]}")" --open -n --host-timeout "$nmap_timeout" -oG - "$ip" 2>/dev/null || true)
    fi
    # parse open ports lines
    ports_found=($(echo "$nmout" | awk '/Ports:/ {gsub(/,/," "); for(i=1;i<=NF;i++) if($i ~ /[0-9]+\/open/) { split($i,a,"/"); print a[1] } }' || true))
    # For each open port, try banner grab
    for p in "${ports_found[@]:-}"; do
      b=$(probe_port_banner "$ip" "$p" "$timeout_sec")
      port_banners+=("$p|$b")
    done
  else
    # fallback connect-probe per port
    for p in "${portset[@]}"; do
      # attempt TCP connect with timeout
      if has_cmd nc; then
        if nc -z -w "$timeout_sec" "$ip" "$p" >/dev/null 2>&1; then
          ports_found+=("$p")
          b=$(probe_port_banner "$ip" "$p" "$timeout_sec")
          port_banners+=("$p|$b")
        fi
      else
        # try bash /dev/tcp hack; non-blocking may be unreliable
        if (exec 3<>/dev/tcp/"$ip"/"$p") 2>/dev/null; then
          ports_found+=("$p")
          b=$(probe_port_banner "$ip" "$p" "$timeout_sec")
          port_banners+=("$p|$b")
          exec 3>&-
        fi
      fi
    done
  fi

  # Build JSON object (NDJSON line)
  # escape strings safely
  esc() { printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' '\\n'; }
  local json="{"
  json="$json\"ip\":\"$(esc "$ip")\""
  json="$json,\"reverse_dns\":\"$(esc "$rname")\""
  json="$json,\"mac\":\"$(esc "$mac")\""
  json="$json,\"vendor\":\"$(esc "$vendor")\""
  json="$json,\"open_ports\":["
  local first=1
  for p in "${ports_found[@]:-}"; do
    if (( first )); then first=0; else json="$json,"; fi
    json="$json$(printf '%s' "$p")"
  done
  json="$json],\"banners\":["
  if [[ -n "${port_banners[*]}" ]]; then
    first=1
    for pb in "${port_banners[@]:-}"; do
      pnum=${pb%%|*}
      pbanner=${pb#*|}
      if [[ -n "$pnum" ]]; then
        if (( first )); then first=0; else json="$json,"; fi
        json="$json{\"port\":$pnum,\"banner\":\"$(esc "$pbanner")\"}"
      fi
    done
  fi
  json="$json]"
  # Classify device type
  local dtype
  dtype=$(classify_type "$vendor" "$rname" "$mac" "$(IFS=,; echo "${ports_found[*]:-}")")
  json="$json,\"device_type\":\"$dtype\"}"
  echo "$json" >> "$NDJSON"
}

# run discovery
ensure_oui
discover_hosts
collect_arp
discover_mdns

# iterate hosts and scan
total_hosts=$(wc -l < "$DISCOVERED_IPS" | tr -d ' ')
echo "Scanning discovered hosts for ports and banners... (0/$total_hosts)"
scanned=0
while read -r ip; do
  if [[ -z "$ip" ]]; then continue; fi
  scan_host "$ip" &
  scanned=$((scanned + 1))
  # throttle concurrency
  running=$(jobs -rp | wc -l)
  while [[ $running -ge 60 ]]; do
    sleep 0.2
    running=$(jobs -rp | wc -l)
  done
  # show progress every 10 hosts or when starting new batch
  if (( scanned % 10 == 0 )) || (( running < 5 )); then
    printf "\rScanning discovered hosts for ports and banners... (%d/$total_hosts)" "$scanned" >&2
  fi
done < "$DISCOVERED_IPS"
printf "\rScanning discovered hosts for ports and banners... (%d/$total_hosts)\n" "$scanned" >&2
echo "Waiting for all scans to complete..."
wait
echo "All scans completed."

# Sort NDJSON by IP address
# Extract IPs, sort them, then rebuild NDJSON in sorted order
awk -F'"ip":"' '{split($2,a,"\""); print a[1]}' "$NDJSON" | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n > "$TMPDIR/sorted_ips.txt"
> "$NDJSON.sorted"
while read -r sorted_ip; do
  grep "\"ip\":\"${sorted_ip}\"" "$NDJSON" >> "$NDJSON.sorted"
done < "$TMPDIR/sorted_ips.txt"
mv "$NDJSON.sorted" "$NDJSON"

# create final JSON array
echo "[" > "$RESULTS_JSON"
first=1
while read -r line; do
  if [[ $first -eq 1 ]]; then
    echo "$line" >> "$RESULTS_JSON"
    first=0
  else
    echo ",$line" >> "$RESULTS_JSON"
  fi
done < "$NDJSON"
echo "]" >> "$RESULTS_JSON"

# create CSV (simple flattened)
echo "ip,reverse_dns,mac,vendor,device_type,open_ports,banners" > "$RESULTS_CSV"
while read -r line; do
  ip=$(echo "$line" | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')
  rd=$(echo "$line" | sed -n 's/.*"reverse_dns":"\([^"]*\)".*/\1/p')
  mac=$(echo "$line" | sed -n 's/.*"mac":"\([^"]*\)".*/\1/p')
  vendor=$(echo "$line" | sed -n 's/.*"vendor":"\([^"]*\)".*/\1/p')
  dtype=$(echo "$line" | sed -n 's/.*"device_type":"\([^"]*\)".*/\1/p')
  ports=$(echo "$line" | sed -n 's/.*"open_ports":\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr -d '\n')
  banners=$(echo "$line" | sed -n 's/.*"banners":\[\(.*\)\].*/\1/p' | sed 's/},{/}|{/g' | tr -d '\n' )
  rd=$(echo "$rd" | sed 's/,/;/g'); vendor=$(echo "$vendor" | sed 's/,/;/g'); banners=$(echo "$banners" | sed 's/,/;/g')
  echo "\"$ip\",\"$rd\",\"$mac\",\"$vendor\",\"$dtype\",\"$ports\",\"$banners\"" >> "$RESULTS_CSV"
done < "$NDJSON"



# ── Helper: extract fields from a JSON line ──
json_field() { echo "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }
json_array() { echo "$1" | sed -n "s/.*\"$2\":\[\([^]]*\)\].*/\1/p" | tr -d '"' | tr ' ' ','; }

# ── Pre-compute: calculate column widths (first pass over NDJSON) ──
TYPE_COUNTS_FILE="$TMPDIR/type_counts.txt"
SEEN_HOSTNAMES="$TMPDIR/seen_hostnames.txt"
> "$TYPE_COUNTS_FILE"
> "$SEEN_HOSTNAMES"

w_ip=15; w_host=8; w_vendor=6; w_ports=5

while read -r line; do
  line=$(echo "$line" | tr -d '\r\n')
  [[ -z "$line" ]] && continue

  ip=$(json_field "$line" "ip")
  rd=$(json_field "$line" "reverse_dns")
  vendor=$(json_field "$line" "vendor" | tr -d '\r')
  ports=$(json_array "$line" "open_ports")
  dtype=$(json_field "$line" "device_type")

  [[ -z "$ip" ]] && continue

  # Re-classify with vendor if scan-time classification missed it
  if [[ -z "$dtype" || "$dtype" == "other" ]]; then
    dtype=$(classify_type "$vendor" "$rd" "" "$ports")
  fi

  ports_display="$ports"

  echo "$dtype" >> "$TYPE_COUNTS_FILE"
  [[ -n "$rd" ]] && echo "$rd" >> "$SEEN_HOSTNAMES"

  (( ${#ip} > w_ip )) && w_ip=${#ip}
  (( ${#rd} > w_host )) && w_host=${#rd}
  (( ${#vendor} > w_vendor )) && w_vendor=${#vendor}
  (( ${#ports_display} > w_ports )) && w_ports=${#ports_display}
done < "$NDJSON"

# Add room for interface notes on duplicate hostnames
dup_exists=$(sort "$SEEN_HOSTNAMES" | uniq -d | head -1)
if [[ -n "$dup_exists" ]]; then
  w_host=$((w_host + 16))
fi
(( w_host > 40 )) && w_host=40
(( w_vendor > 32 )) && w_vendor=32
(( w_ports > 50 )) && w_ports=50

# ── Draw table ──
host_count=$(wc -l < "$NDJSON" | tr -d ' ')

# Box-drawing helpers
hline() {
  local l="$1"; local m="$2"; local r="$3"
  printf "%s" "$l"
  printf "%s" "$(printf "─%.0s" $(seq 1 $((w_ip + 2))))"
  printf "%s" "$m"
  printf "%s" "$(printf "─%.0s" $(seq 1 $((w_host + 4))))"
  printf "%s" "$m"
  printf "%s" "$(printf "─%.0s" $(seq 1 $((w_vendor + 2))))"
  printf "%s" "$m"
  printf "%s" "$(printf "─%.0s" $(seq 1 $((w_ports + 2))))"
  printf "%s\n" "$r"
}

echo
printf "${C_BOLD}LAN Scan Results${C_RESET}\n"
echo

# Header
hline "┌" "┬" "┐"
printf "│ ${C_BOLD}%-${w_ip}s${C_RESET} │ ${C_BOLD}  %-${w_host}s${C_RESET} │ ${C_BOLD}%-${w_vendor}s${C_RESET} │ ${C_BOLD}%-${w_ports}s${C_RESET} │\n" \
  "IP Address" "Hostname" "Vendor" "Ports"
hline "├" "┼" "┤"

# Pre-scan for duplicate hostnames → build hostname:first_ip mapping
SEEN_HOSTS="$TMPDIR/seen_hosts.txt"
> "$SEEN_HOSTS"
while read -r line; do
  line=$(echo "$line" | tr -d '\r\n')
  [[ -z "$line" ]] && continue
  _ip=$(json_field "$line" "ip")
  _rd=$(json_field "$line" "reverse_dns")
  [[ -n "$_rd" ]] && echo "${_rd}::${_ip}" >> "$SEEN_HOSTS"
done < "$NDJSON"

# Data rows (second pass over NDJSON)
host_count=0
while read -r line; do
  line=$(echo "$line" | tr -d '\r\n')
  [[ -z "$line" ]] && continue
  host_count=$((host_count + 1))

  ip=$(json_field "$line" "ip")
  rd=$(json_field "$line" "reverse_dns")
  vendor=$(json_field "$line" "vendor" | tr -d '\r')
  ports=$(json_array "$line" "open_ports")
  dtype=$(json_field "$line" "device_type")

  [[ -z "$ip" ]] && continue

  # Re-classify with vendor if scan-time missed it
  if [[ -z "$dtype" || "$dtype" == "other" ]]; then
    dtype=$(classify_type "$vendor" "$rd" "" "$ports")
  fi

  icon=$(icon_for_type "$dtype")

  # Generate placeholder hostname if empty
  if [[ -z "$rd" ]]; then
    rd="—"
    rd_color="${C_DIM}"
  else
    rd_color="${C_CYAN}"
  fi

  # Detect multi-interface devices (same hostname, different IP)
  iface_note=""
  if [[ -n "$rd" && "$rd" != "—" && "$rd" != ~* ]]; then
    dup_count=$(grep -c "^${rd}::" "$SEEN_HOSTS" 2>/dev/null | tr -d '[:space:]' || echo "0")
    if [[ "$dup_count" -gt 1 ]]; then
      first_ip=$(grep "^${rd}::" "$SEEN_HOSTS" | head -1 | sed 's/.*:://')
      if [[ "$ip" == "$first_ip" ]]; then
        iface_note=" (iface 1)"
      else
        iface_note=" (iface 2 ↔ .${first_ip##*.})"
      fi
    fi
  fi

  # Truncate if needed
  rd_display="${rd}${iface_note}"
  rd_display=$(echo "$rd_display" | cut -c1-$w_host)
  vendor=$(echo "$vendor" | cut -c1-$w_vendor)

  printf "│ ${C_GREEN}%-${w_ip}s${C_RESET} │ %s ${rd_color}%-${w_host}s${C_RESET} │ ${C_DIM}%-${w_vendor}s${C_RESET} │ ${C_YELLOW}%-${w_ports}s${C_RESET} │\n" \
    "$ip" "$icon" "$rd_display" "$vendor" "$ports"
done < "$NDJSON"

# Footer
hline "└" "┴" "┘"

# Summary by device type
echo
printf "${C_BOLD}Summary:${C_RESET} %d hosts found\n" "$host_count"
echo "┌────┬──────────────┬───────┐"
printf "│ ${C_BOLD}    %-12s${C_RESET} │ ${C_BOLD}%-5s${C_RESET} │\n" "Type" "Count"
echo "├────┼──────────────┼───────┤"
if [[ -s "$TYPE_COUNTS_FILE" ]]; then
  sort "$TYPE_COUNTS_FILE" | uniq -c | sort -rn | while read -r line; do
    count=$(echo "$line" | awk '{print $1}')
    dtype=$(echo "$line" | awk '{print $2}')
    icon=$(icon_for_type "$dtype")
    printf "│ %s │ %-12s │ ${C_BOLD}%5s${C_RESET} │\n" "$icon" "$dtype" "$count"
  done
fi
echo "└────┴──────────────┴───────┘"

printf "Results saved to:\n"
printf "  📄 ${C_BOLD}%s${C_RESET}\n" "$RESULTS_JSON"
printf "  📊 ${C_BOLD}%s${C_RESET}\n" "$RESULTS_CSV"

exit 0


