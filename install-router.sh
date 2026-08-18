#!/bin/sh
URL="${1:-}"
TOKEN="${2:-}"
NAME="${3:-}"

usage() {
  cat <<'EOF'
wgman - OpenWrt router installer

Usage:
  sh install-router.sh <api_url> <token> [name]

The router auto-detects its LAN subnet, generates WireGuard keys,
registers itself with the wgman server and applies the config.
EOF
}

[ -n "$URL" ] && [ -n "$TOKEN" ] || { usage; exit 1; }
[ "$(id -u)" = "0" ] || { echo "ERROR: run as root on the router"; exit 1; }

HOSTPORT=${URL#*://}
HOSTPORT=${HOSTPORT%%/*}
case "$HOSTPORT" in
  *:*:*) case "$HOSTPORT" in
           *\[*) ;;
           *) echo "ERROR: IPv6 endpoint must use brackets, e.g. https://[ipv6]:51821/register"; exit 1 ;;
         esac ;;
esac

if [ -z "$NAME" ]; then
  NAME=$(uci -q get system.@system[0].hostname 2>/dev/null)
  [ -n "$NAME" ] || NAME="router-$(date +%s)"
fi
NAME=$(printf '%s' "$NAME" | tr -c 'A-Za-z0-9_.-' '_' | cut -c1-32)

echo "==> Router name: $NAME"
echo "==> install-router.sh version: 2.3 (universal)"

mask2bits() {
  local m=$1 bits=0 o oifs
  oifs=$IFS; IFS=.; set -- $m; IFS=$oifs
  for o in "$@"; do
    case "$o" in
      255) bits=$((bits+8)) ;;
      254) bits=$((bits+7)) ;;
      252) bits=$((bits+6)) ;;
      248) bits=$((bits+5)) ;;
      240) bits=$((bits+4)) ;;
      224) bits=$((bits+3)) ;;
      192) bits=$((bits+2)) ;;
      128) bits=$((bits+1)) ;;
      0) ;;
      *) echo 0; return ;;
    esac
  done
  echo "$bits"
}

detect_lan() {
  local dev cidr addr mask
  dev=$(uci -q get network.lan.device)
  [ -n "$dev" ] || dev="br-lan"

  cidr=$(ubus -S call network.interface.lan status 2>/dev/null | \
    sed -n 's/.*"ipv4-address":\[{"address":"\([0-9.]*\)","mask":\([0-9]*\).*/\1\/\2/p')
  [ -n "$cidr" ] && { echo "$cidr"; return; }

  addr=$(uci -q get network.lan.ipaddr)
  mask=$(uci -q get network.lan.netmask)
  [ -n "$mask" ] || mask="255.255.255.0"
  if [ -n "$addr" ]; then
    echo "$addr/$(mask2bits "$mask")"
    return
  fi

  cidr=$(ip -4 -o addr show dev "$dev" 2>/dev/null | awk '{print $4; exit}')
  [ -n "$cidr" ] && echo "$cidr"
}

if ! command -v wg >/dev/null 2>&1; then
  echo "==> WireGuard tools missing, installing packages..."
  opkg update >/dev/null 2>&1 || true
  opkg install wireguard-tools >/dev/null 2>&1 || true
  opkg install kmod-wireguard >/dev/null 2>&1 || true
  opkg install luci-proto-wireguard >/dev/null 2>&1 || true
  command -v wg >/dev/null 2>&1 || { echo "ERROR: wg not found. Install wireguard-tools/kmod-wireguard."; exit 1; }
fi

LAN_CIDR=$(detect_lan)
echo "==> LAN detected: ${LAN_CIDR:-unknown}"

WG_PRIV=$(wg genkey) || { echo "ERROR: wg genkey failed"; exit 1; }
WG_PUB=$(printf '%s' "$WG_PRIV" | wg pubkey)

JSON="{\"token\":\"$TOKEN\",\"name\":\"$NAME\",\"public_key\":\"$WG_PUB\",\"lan_cidr\":\"$LAN_CIDR\",\"endpoint\":\"\"}"

post_json() {
  local data=$1 out=""
  if command -v curl >/dev/null 2>&1; then
    out=$(curl -sk --max-time 40 -X POST "$URL" -H "Content-Type: application/json" -d "$data" 2>/dev/null || true)
  elif command -v wget >/dev/null 2>&1; then
    out=$(wget -q --no-check-certificate -T 40 -O - --post-data="$data" --header="Content-Type: application/json" "$URL" 2>/dev/null || true)
  else
    echo "ERROR: curl/wget not found; run: opkg install curl" >&2
    return 1
  fi
  echo "$out"
}

echo "==> Registering with server..."
RESP=$(post_json "$JSON")

if [ -z "$RESP" ]; then
  echo "==> Empty response (possibly no TLS in wget), installing curl..."
  opkg update >/dev/null 2>&1 || true
  opkg install curl >/dev/null 2>&1 || true
  if command -v curl >/dev/null 2>&1; then
    RESP=$(curl -sk --max-time 40 -X POST "$URL" -H "Content-Type: application/json" -d "$JSON" 2>/dev/null || true)
  fi
fi

parse_json() {
  sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

STATUS=$(printf '%s' "$RESP" | parse_json status)
if [ "$STATUS" != "ok" ]; then
  MSG=$(printf '%s' "$RESP" | parse_json message)
  echo "ERROR: server said: ${MSG:-registration failed}"
  exit 1
fi

WG_IP=$(printf '%s' "$RESP" | parse_json ip)
SRV_PUB=$(printf '%s' "$RESP" | parse_json server_public_key)
ENDPOINT=$(printf '%s' "$RESP" | parse_json server_endpoint)
ALLOWED=$(printf '%s' "$RESP" | parse_json allowed_ips)
DNS=$(printf '%s' "$RESP" | parse_json dns)

[ -n "$WG_IP" ] && [ -n "$SRV_PUB" ] || { echo "ERROR: bad server response: $RESP"; exit 1; }
[ -n "$ALLOWED" ] || ALLOWED="10.66.66.0/24"

EP_HOST="$ENDPOINT"; EP_PORT="51820"
case "$ENDPOINT" in
  *:*) EP_HOST=${ENDPOINT%:*}; EP_PORT=${ENDPOINT##*:} ;;
esac
EP_HOST=${EP_HOST#[}
EP_HOST=${EP_HOST%]}

echo "==> Assigned WG IP: $WG_IP"
echo "==> Applying OpenWrt configuration..."

uci_run() {
  echo "  ++ $*"
  uci "$@" || { echo "ERROR: failed command: uci $*"; exit 1; }
}

uci -q delete network.wg0 2>/dev/null
uci -q delete network.wg0peer 2>/dev/null

uci_run set network.wg0=interface
uci_run set network.wg0.proto=wireguard
uci_run set network.wg0.private_key="$WG_PRIV"
uci_run set network.wg0.listen_port=51820
uci_run set network.wg0.mtu=1420
uci_run set network.wg0.ipaddr="$WG_IP"
uci_run set network.wg0.netmask=255.255.255.0

uci_run set network.wg0peer=wireguard_peer
uci_run set network.wg0peer.ifname=wg0
uci_run set network.wg0peer.public_key="$SRV_PUB"
uci_run set network.wg0peer.endpoint_host="$EP_HOST"
uci_run set network.wg0peer.endpoint_port="$EP_PORT"
uci_run set network.wg0peer.allowed_ips="$ALLOWED"
uci_run set network.wg0peer.persistent_keepalive=25
uci_run set network.wg0peer.route_allowed_ips=1

LAN_ZONE=$(uci show firewall 2>/dev/null | grep "\.name='lan'" | sed "s/\.name.*//" | head -n1)
if [ -z "$LAN_ZONE" ]; then
  LAN_ZONE=$(uci show firewall 2>/dev/null | grep "\.network='lan'" | sed "s/\.network.*//" | head -n1)
fi
if [ -n "$LAN_ZONE" ]; then
  CUR=$(uci -q get "$LAN_ZONE.network" 2>/dev/null)
  case " $CUR " in
    *" wg0 "*) echo "==> wg0 already in lan zone" ;;
    *) uci_run add_list "$LAN_ZONE.network=wg0" ;;
  esac
else
  echo "WARNING: lan firewall zone not found, wg0 not added to it"
fi

uci_run commit network
uci_run commit firewall

/etc/init.d/network reload
sleep 2
ifup wg0 2>/dev/null || true

if command -v fw4 >/dev/null 2>&1; then
  fw4 reload 2>/dev/null || true
else
  fw3 reload 2>/dev/null || true
fi

sleep 2
STAT=$(ubus call network.interface.wg0 status 2>/dev/null)
case "$STAT" in
  *'"up":true'*) UP="up" ;;
  *) UP="not up (check dmesg / kmod-wireguard)" ;;
esac

echo ""
echo "=== Done ==="
echo "Router:      $NAME"
echo "WG address:  $WG_IP"
echo "Server:      $EP_HOST:$EP_PORT"
echo "Interface:   $UP"
echo "You can manage this router over VPN at https://$WG_IP (LuCI)"
