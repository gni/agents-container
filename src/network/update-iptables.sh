#!/bin/bash
set -e

CONFIG_FILE="/app/config/ottergate/config.json"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "[update-iptables] Error: Config file not found at $CONFIG_FILE"
    exit 1
fi

echo "[update-iptables] Rebuilding iptables sandbox ac rules..."

# 1. Create chains if they don't exist
iptables -N ISOLATION-FW 2>/dev/null || true
iptables -N ISOLATION-OUT 2>/dev/null || true
iptables -t nat -N ISOLATION-NAT 2>/dev/null || true

# 2. Flush chains
iptables -F ISOLATION-FW
iptables -F ISOLATION-OUT
iptables -t nat -F ISOLATION-NAT

# 3. Setup jumps
if ! iptables -C DOCKER-USER -j ISOLATION-FW 2>/dev/null; then
    iptables -I DOCKER-USER 1 -j ISOLATION-FW
fi

if ! iptables -C INPUT -j ISOLATION-FW 2>/dev/null; then
    iptables -I INPUT 1 -j ISOLATION-FW
fi

if ! iptables -C OUTPUT -j ISOLATION-OUT 2>/dev/null; then
    iptables -I OUTPUT 1 -j ISOLATION-OUT
fi

if ! iptables -t nat -C PREROUTING -j ISOLATION-NAT 2>/dev/null; then
    iptables -t nat -I PREROUTING 1 -j ISOLATION-NAT
fi

# Get all IPs of the Ottergate proxy container
OTTERGATE_IPS=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' ac-ottergate-1 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | tr '\n' ' ')
if [ -z "$OTTERGATE_IPS" ]; then
    OTTERGATE_IPS="172.20.0.53"
fi
echo "[update-iptables] Detected Ottergate IPs: $OTTERGATE_IPS"

# 4. Populate ISOLATION-FW (Forward / Input)
# Allow established/related
iptables -A ISOLATION-FW -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Allow all to/from mock backend on test_net (172.21.0.100)
iptables -A ISOLATION-FW -d 172.21.0.100 -j ACCEPT
iptables -A ISOLATION-FW -s 172.21.0.100 -j ACCEPT

# Read blocklisted IPs and ranges using python
python_out="$(python3 -c "
import json
import ipaddress

def clean_ips(lst):
    cleaned = []
    for item in lst:
        try:
            ipaddress.ip_address(item)
            cleaned.append(item)
        except ValueError:
            pass
    return cleaned

def clean_ranges(lst):
    cleaned = []
    for item in lst:
        try:
            ipaddress.ip_network(item, strict=False)
            cleaned.append(item)
        except ValueError:
            pass
    return cleaned

try:
    with open('$CONFIG_FILE') as f:
        cfg = json.load(f)
    fw = cfg.get('firewall', {})
    ips = clean_ips(fw.get('blocklist_ips', []))
    ranges = clean_ranges(fw.get('blocklist_ranges', []))
    
    # Extract allowed upstreams
    raw_allowed = []
    dnat_ips = []
    hosts = cfg.get('hosts', {})
    for h, host_cfg in hosts.items():
        hp = host_cfg.get('http_proxy', {})
        if hp and hp.get('enabled', True):
            up = hp.get('upstream', '')
            if '//' in up:
                raw_allowed.append(up.split('//')[1].split(':')[0])
        tp = host_cfg.get('tls_proxy', {})
        if tp:
            tip = tp.get('targetIp', '')
            if tip:
                raw_allowed.append(tip)
        
        # Extract custom IP A records for DNAT transparent redirection
        for r in host_cfg.get('records', []):
            if r.get('type') == 'A':
                addr = r.get('address', '')
                if addr and addr not in ('172.20.0.53', '0.0.0.0', '127.0.0.1'):
                    dnat_ips.append(addr)
                    
    allowed = clean_ips(raw_allowed)
    dnat_ips = clean_ips(dnat_ips)
                
    out_ips = [ip for ip in ips if not ip.startswith('127.')]
    out_ranges = [r for r in ranges if not (r.startswith('127.') or r.startswith('172.20.') or r.startswith('172.21.'))]
    print(' '.join(ips))
    print(' '.join(ranges))
    print(' '.join(out_ips))
    print(' '.join(out_ranges))
    print(' '.join(allowed))
    print(' '.join(dnat_ips))
except Exception as e:
    pass
")"
BL_IPS=$(echo "$python_out" | sed -n '1p')
BL_RANGES=$(echo "$python_out" | sed -n '2p')
OUT_IPS=$(echo "$python_out" | sed -n '3p')
OUT_RANGES=$(echo "$python_out" | sed -n '4p')
ALLOWED_IPS=$(echo "$python_out" | sed -n '5p')
DNAT_IPS=$(echo "$python_out" | sed -n '6p')

# Configure Ottergate-specific forwarding rules
for og_ip in $OTTERGATE_IPS; do
    # Allow Ottergate to reach allowed upstreams
    for ip in $ALLOWED_IPS; do
        iptables -A ISOLATION-FW -s "$og_ip" -d "$ip" -j ACCEPT
    done

    # Block Ottergate from reaching blocklisted IPs/ranges
    for ip in $BL_IPS; do
        iptables -A ISOLATION-FW -s "$og_ip" -d "$ip" -j DROP
    done
    for cidr in $BL_RANGES; do
        iptables -A ISOLATION-FW -s "$og_ip" -d "$cidr" -j DROP
    done

    # Allow all other traffic to/from Ottergate proxy
    iptables -A ISOLATION-FW -d "$og_ip" -j ACCEPT
    iptables -A ISOLATION-FW -s "$og_ip" -j ACCEPT
done

# Drop all other traffic originating from the sandbox network (172.20.0.0/16)
# This prevents direct container-to-container connections and access to host interfaces
iptables -A ISOLATION-FW -s 172.20.0.0/16 -j DROP


# 5. Populate ISOLATION-OUT (Output)
iptables -A ISOLATION-OUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Explicitly allow connections to allowed upstreams/proxy targets (to bypass blocklist)
for ip in $ALLOWED_IPS; do
    iptables -A ISOLATION-OUT -d "$ip" -j ACCEPT
done

# Block host/proxy from initiating connections to blocklisted IPs/ranges
for ip in $OUT_IPS; do
    iptables -A ISOLATION-OUT -d "$ip" -j DROP
done

for cidr in $OUT_RANGES; do
    iptables -A ISOLATION-OUT -d "$cidr" -j DROP
done


# 6. Populate ISOLATION-NAT (NAT PREROUTING DNAT rules for custom IPs)
for ip in $DNAT_IPS; do
    iptables -t nat -A ISOLATION-NAT -s 172.20.0.0/16 -d "$ip" -p tcp -m multiport --dports 80,443 -j DNAT --to-destination 172.20.0.53
done

echo "[update-iptables] Security policy applied successfully."
