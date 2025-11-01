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
COMMON_PORTS=(22 23 53 80 443 139 445 3389 8080 1900 5353 3306 5900)
DEEP_PORTS=(21 22 23 25 53 67 68 80 110 139 143 443 445 587 3306 3389 5900 8080 8443 8888 5353 1900)

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

echo "Starting LAN scan on $CIDR"
echo "Output prefix: $OUT_PREFIX"
echo
echo "Legal reminder: Only scan networks you own or are authorized to test."
echo

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

DISCOVERED_IPS="$TMPDIR/ips.txt"
ARP_RAW="$TMPDIR/arp_raw.txt"
RESULTS_JSON="$OUT_PREFIX"_scan_results.json
RESULTS_CSV="$OUT_PREFIX"_scan_results.csv
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

# 3) helper: look up vendor from oui.txt (format: 001122<TAB>Vendor Name)
vendor_lookup() {
  local mac="$1"
  local vendor=""
  if [[ -f "./oui.txt" ]]; then
    hex=$(echo "$mac" | tr -d ':-' | cut -c1-6 | tr '[:lower:]' '[:upper:]')
    vendor=$(awk -v k="$hex" -F'\t' '$1==k{print $2; exit}' ./oui.txt || true)
  fi
  echo "$vendor"
}

# 4) reverse DNS
reverse_dns() {
  local ip="$1"
  if has_cmd host; then
    host "$ip" 2>/dev/null | awk '/domain name pointer/ {print $5}' | sed 's/\.$//' || true
  elif has_cmd dig; then
    dig -x "$ip" +short | sed 's/\.$//' | head -n1 || true
  else
    echo ""
  fi
}

# 5) probe port (fast). Using nc if available, otherwise /dev/tcp.
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

# 6) scan ports list for an IP, output JSON object per host
scan_host() {
  local ip="$1"
  local mac vendor rname
  mac=$(awk -v ip="$ip" '$1==ip{print $2}' "$ARP_RAW" || true)
  if [[ -z "$mac" ]]; then mac=""; fi
  if [[ -n "$mac" ]]; then vendor=$(vendor_lookup "$mac"); else vendor=""; fi
  rname=$(reverse_dns "$ip" || true)

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
    if [[ $DEEP -eq 1 ]]; then
      # more thorough
      nmout=$(nmap -Pn -sT -p "$(IFS=,; echo "${portset[*]}")" --open -n -oG - "$ip" 2>/dev/null || true)
    else
      nmout=$(nmap -Pn -sT -p "$(IFS=,; echo "${portset[*]}")" --open -n -oG - "$ip" 2>/dev/null || true)
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
  json="$json]}"
  echo "$json" >> "$NDJSON"
}

# run discovery
discover_hosts
collect_arp

# iterate hosts and scan
echo "Scanning discovered hosts for ports and banners..."
while read -r ip; do
  if [[ -z "$ip" ]]; then continue; fi
  scan_host "$ip" &
  # throttle concurrency
  running=$(jobs -rp | wc -l)
  while [[ $running -ge 60 ]]; do
    sleep 0.2
    running=$(jobs -rp | wc -l)
  done
done < "$DISCOVERED_IPS"
wait

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
echo "ip,reverse_dns,mac,vendor,open_ports,banners" > "$RESULTS_CSV"
while read -r line; do
  ip=$(echo "$line" | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')
  rd=$(echo "$line" | sed -n 's/.*"reverse_dns":"\([^"]*\)".*/\1/p')
  mac=$(echo "$line" | sed -n 's/.*"mac":"\([^"]*\)".*/\1/p')
  vendor=$(echo "$line" | sed -n 's/.*"vendor":"\([^"]*\)".*/\1/p')
  ports=$(echo "$line" | sed -n 's/.*"open_ports":\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr -d '\n')
  # banners: join port:banner pairs
  banners=$(echo "$line" | sed -n 's/.*"banners":\[\(.*\)\].*/\1/p' | sed 's/},{/}|{/g' | tr -d '\n' )
  # clean commas
  rd=$(echo "$rd" | sed 's/,/;/g'); vendor=$(echo "$vendor" | sed 's/,/;/g'); banners=$(echo "$banners" | sed 's/,/;/g')
  echo "\"$ip\",\"$rd\",\"$mac\",\"$vendor\",\"$ports\",\"$banners\"" >> "$RESULTS_CSV"
done < "$NDJSON"

echo
echo "Scan complete."

# Simple display - replacing complex ASCII table
echo
echo "LAN Scan Results:"
echo "=================="

icon_for_type() {
  case "$1" in
    phone) echo "📱";;
    pc) echo "💻";;
    router) echo "📡";;
    pi) echo "🍓";;
    xbox) echo "🎮";;
    printer) echo "🖨️";;
    camera) echo "📷";;
    *) echo "❓";;
  esac
}

classify_type() {
  local vendor="$1"; local hostname="$2"; local mac="$3"
  if [[ "$hostname" =~ (raspberry|pi) ]]; then echo "pi"; return; fi
  if [[ "$hostname" =~ (OPPO|A96) ]]; then echo "phone"; return; fi
  if [[ "$hostname" =~ (phone|android|oppo|iphone|ios) ]]; then echo "phone"; return; fi
  if [[ "$hostname" =~ (xbox|XBOX) ]]; then echo "xbox"; return; fi
  if [[ "$hostname" =~ (openwrt|OpenWrt) ]]; then echo "router"; return; fi
  if [[ "$vendor" =~ (Cisco|OpenWrt|Ubiquiti|TP-Link|Netgear|D-Link|Technicolor) ]]; then echo "router"; return; fi
  if [[ "$vendor" =~ (HP|Canon|Epson|Brother) ]]; then echo "printer"; return; fi
  if [[ "$vendor" =~ (Microsoft|Apple|Dell|Lenovo|Acer|Asus|PC) ]]; then echo "pc"; return; fi
  if [[ "$vendor" =~ (Camera|Hikvision|Axis) ]]; then echo "camera"; return; fi
  echo "other"
}





host_count=0
while read -r line; do
  # Clean control characters
  line=$(echo "$line" | tr -d '\r\n\t')
  
  # Skip empty lines
  if [[ -z "$line" ]]; then continue; fi
  
  host_count=$((host_count + 1))
  
  # Extract basic info
  ip=$(echo "$line" | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')
  rd=$(echo "$line" | sed -n 's/.*"reverse_dns":"\([^"]*\)".*/\1/p')
  vendor=$(echo "$line" | sed -n 's/.*"vendor":"\([^"]*\)".*/\1/p')
  ports=$(echo "$line" | sed -n 's/.*"open_ports":\[\([^]]*\)\].*/\1/p')
  
  # Skip if no IP
  if [[ -z "$ip" ]]; then continue; fi
  
  # Clean vendor field
  vendor=$(echo "$vendor" | tr -d '\r')
  
  # Classify device
  dtype=$(classify_type "$vendor" "$rd" "")
  icon=$(icon_for_type "$dtype")
  
  # Build display line
  display_line="$icon $ip"
  
  # Add hostname if available
  if [[ -n "$rd" ]]; then
    display_line="$display_line  $rd"
  fi
  
  # Add vendor info in parentheses if available
  if [[ -n "$vendor" ]]; then
    display_line="$display_line ($vendor)"
  fi
  
  # Add port info if available
  if [[ -n "$ports" ]]; then
    port_list=$(echo "$ports" | tr -d '"' | tr ' ' ',')
    display_line="$display_line [Ports: $port_list]"
  fi
  
  echo "$display_line"
done < "$NDJSON"

echo
echo "Found $host_count hosts"
echo
echo "Full results saved to:"
echo "  📄 JSON: $RESULTS_JSON"
echo "  📊 CSV:  $RESULTS_CSV"




exit 0



debug_count=0
while read -r line; do
  debug_count=$((debug_count + 1))
  
  # Clean carriage returns and any other control characters from the line
  line=$(echo "$line" | tr -d '\r\n\t' | sed 's/[[:cntrl:]]//g')
  
  # Skip empty lines
  if [[ -z "$line" ]]; then
    continue
  fi
  
  # Debug output for problematic lines
  if [[ $debug_count -le 3 ]] || [[ $debug_count -ge 9 ]]; then
    echo "DEBUG: Processing line $debug_count: ${line:0:80}..." >&2
  fi
  
  # Extract fields in order with strict patterns to avoid cross-field confusion
  # 1. Extract IP first (most reliable field)
  ip=$(echo "$line" | sed -n 's/.*"ip":"\([^"]*\)".*/\1/p')
  
  # 2. Extract reverse_dns (look for exact pattern)
  rd=$(echo "$line" | sed -n 's/.*"reverse_dns":"\([^"]*\)".*/\1/p')
  
  # 3. Extract MAC
  mac=$(echo "$line" | sed -n 's/.*"mac":"\([^"]*\)".*/\1/p')
  
  # 4. Extract vendor
  vendor=$(echo "$line" | sed -n 's/.*"vendor":"\([^"]*\)".*/\1/p')
  
  # 5. Extract ports
  ports=$(echo "$line" | sed -n 's/.*"open_ports":\[\([^]]*\)\].*/\1/p')
  if [[ -n "$ports" ]]; then
    ports=$(echo "$ports" | tr -d '"' | tr -d ' ' | tr -d '\n')
  fi
  
  # 6. Extract banners (get the entire banners array)
  banners_raw=$(echo "$line" | sed -n 's/.*"banners":\[\(.*\)\].*/\1/p')
  banners=""
  if [[ -n "$banners_raw" && "$banners_raw" != "" ]]; then
    if command -v jq >/dev/null 2>&1; then
      # Use jq for reliable JSON parsing
      banners=$(echo "$line" | jq -r '.banners[] | "\(.port):\(.banner)"' 2>/dev/null | tr '\n' ';' | sed 's/;$//')
    else
      # Fallback parsing - extract port:banner pairs
      banners=$(echo "$banners_raw" | sed -E 's/\{"port":([0-9]+),"banner":"([^"]*")\}/\1:\2;/g' | sed 's/;*$//')
    fi
  fi
  
  # Skip hosts where we couldn't extract IP
  if [[ -z "$ip" ]]; then
    echo "DEBUG: Failed to extract IP from line $debug_count" >&2
    continue
  fi
  
  # Clean up vendor field
  vendor=$(echo "$vendor" | tr -d '\r\n\t' | sed 's/[[:cntrl:]]//g')
  
  # Classify device type
  dtype=$(classify_type "$vendor" "$rd" "$mac")
  icon=$(icon_for_type "$dtype")
  
  # Set defaults for empty fields
  if [[ -z "$rd" ]]; then rd=""; fi
  if [[ -z "$ports" ]]; then ports="-"; fi
  if [[ -z "$banners" ]]; then banners="-"; fi

  # Truncate long fields to fit columns
  rd_trunc=$(echo "$rd" | cut -c1-$HOSTNAME_WIDTH)
  vendor_trunc=$(echo "$vendor" | cut -c1-$VENDOR_WIDTH)
  ports_trunc=$(echo "$ports" | cut -c1-$PORTS_WIDTH)
  banners_trunc=$(echo "$banners" | cut -c1-$BANNERS_WIDTH | sed 's/; /\n/g' | head -1 | sed 's/$/.../')

  printf "$row_fmt" "$ip" "$rd_trunc" "$mac" "$vendor_trunc" "$icon" "$ports_trunc" "$banners_trunc"
done < "$NDJSON"

echo "DEBUG: Total lines processed in ASCII table: $debug_count" >&2
echo "$border_bottom"

echo
echo "CSV results:  $RESULTS_CSV"


