#!/bin/sh
URL=""
TOKEN=""
NAME=""
MODE="wg"

idx=0
for a in "$@"; do
  case "$a" in
    --awg) MODE="awg" ;;
    --wg) MODE="wg" ;;
    *) idx=$((idx+1)); [ "$idx" = "1" ] && URL=$a; [ "$idx" = "2" ] && TOKEN=$a; [ "$idx" = "3" ] && NAME=$a ;;
  esac
done

usage() {
  cat <<'EOF'
wgman - OpenWrt router installer

Usage:
  sh install-router.sh <api_url> <token> [name] [--wg|--awg]

The router auto-detects its LAN subnet, generates WireGuard/AmneziaWG keys,
registers itself with the wgman server and applies the config.
Use --awg to enable the AmneziaWG tunnel (obfuscated, bypasses DPI blocking).
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
echo "==> install-router.sh version: 2.5 (wg + awg), mode: $MODE"

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

install_pkg() {
  if command -v apk >/dev/null 2>&1; then
    apk update >/dev/null 2>&1 || true
    apk add "$@" >/dev/null 2>&1 || true
  else
    opkg update >/dev/null 2>&1 || true
    opkg install "$@" >/dev/null 2>&1 || true
  fi
}

install_awg() {
  echo "==> AmneziaWG tools missing, installing from awg-openwrt..."
  wget -q -O /tmp/awg-install.sh "https://raw.githubusercontent.com/Slava-Shchipunov/awg-openwrt/refs/heads/master/amneziawg-install.sh" 2>/dev/null || true
  if [ -s /tmp/awg-install.sh ]; then
    sh /tmp/awg-install.sh -e -n >/dev/null 2>&1 || true
  fi
  command -v awg >/dev/null 2>&1 || {
    echo "ERROR: awg not found. Install kmod-amneziawg + amneziawg-tools"
    echo "       (see /tmp/awg-install.sh output) or run install script manually."
    exit 1
  }
}

if [ "$MODE" = "awg" ] && ! command -v awg >/dev/null 2>&1; then
  install_awg
fi

if ! command -v wg >/dev/null 2>&1; then
  echo "==> WireGuard tools missing, installing packages..."
  install_pkg wireguard-tools kmod-wireguard luci-proto-wireguard
  command -v wg >/dev/null 2>&1 || { echo "ERROR: wg not found. Install wireguard-tools/kmod-wireguard."; exit 1; }
fi

LAN_CIDR=$(detect_lan)
echo "==> LAN detected: ${LAN_CIDR:-unknown}"

if [ "$MODE" = "awg" ] && command -v awg >/dev/null 2>&1; then
  WG_PRIV=$(awg genkey 2>/dev/null) || WG_PRIV=$(wg genkey)
  WG_PUB=$(printf '%s' "$WG_PRIV" | awg pubkey 2>/dev/null || printf '%s' "$WG_PRIV" | wg pubkey)
else
  WG_PRIV=$(wg genkey) || { echo "ERROR: wg genkey failed"; exit 1; }
  WG_PUB=$(printf '%s' "$WG_PRIV" | wg pubkey)
fi

JSON="{\"token\":\"$TOKEN\",\"name\":\"$NAME\",\"public_key\":\"$WG_PUB\",\"lan_cidr\":\"$LAN_CIDR\",\"endpoint\":\"\",\"proto\":\"$MODE\"}"

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

EP_HOST="$ENDPOINT"; EP_PORT="51820"
case "$ENDPOINT" in
  *:*) EP_HOST=${ENDPOINT%:*}; EP_PORT=${ENDPOINT##*:} ;;
esac
EP_HOST=${EP_HOST#[}
EP_HOST=${EP_HOST%]}

if [ "$MODE" = "awg" ]; then
  [ -n "$ALLOWED" ] || ALLOWED="10.66.77.0/24"
  P_AWG=$(printf '%s' "$RESP" | parse_json awg_port); [ -n "$P_AWG" ] && EP_PORT="$P_AWG"
  MTU=$(printf '%s' "$RESP" | parse_json mtu); [ -n "$MTU" ] || MTU="1420"
  AWG_JC=$(printf '%s' "$RESP" | parse_json awg_jc);   [ -n "$AWG_JC" ] || AWG_JC="50"
  AWG_JMIN=$(printf '%s' "$RESP" | parse_json awg_jmin); [ -n "$AWG_JMIN" ] || AWG_JMIN="5"
  AWG_JMAX=$(printf '%s' "$RESP" | parse_json awg_jmax); [ -n "$AWG_JMAX" ] || AWG_JMAX="5"
  AWG_S1=$(printf '%s' "$RESP" | parse_json awg_s1);  [ -n "$AWG_S1" ] || AWG_S1="0"
  AWG_S2=$(printf '%s' "$RESP" | parse_json awg_s2);  [ -n "$AWG_S2" ] || AWG_S2="0"
  AWG_H1=$(printf '%s' "$RESP" | parse_json awg_h1);  [ -n "$AWG_H1" ] || AWG_H1="2048"
  AWG_H2=$(printf '%s' "$RESP" | parse_json awg_h2);  [ -n "$AWG_H2" ] || AWG_H2="4096"
  AWG_H3=$(printf '%s' "$RESP" | parse_json awg_h3);  [ -n "$AWG_H3" ] || AWG_H3="8192"
  AWG_H4=$(printf '%s' "$RESP" | parse_json awg_h4);  [ -n "$AWG_H4" ] || AWG_H4="16384"
else
  [ -n "$ALLOWED" ] || ALLOWED="10.66.66.0/24"
fi

echo "==> Assigned IP: $WG_IP  mode: $MODE"
echo "==> Applying OpenWrt configuration..."

PREFIX=${ALLOWED##*/}

uci_run() {
  echo "  ++ $*"
  uci "$@" || { echo "ERROR: failed command: uci $*"; exit 1; }
}

configure_wg() {
  uci -q delete network.wg0 2>/dev/null
  uci -q delete network.wg0peer 2>/dev/null
  uci -q delete network.wireguard_wg0 2>/dev/null
  uci -q delete network.@wireguard_wg0 2>/dev/null

  uci_run set network.wg0=interface
  uci_run set network.wg0.proto=wireguard
  uci_run set network.wg0.private_key="$WG_PRIV"
  uci_run set network.wg0.listen_port=51820
  uci_run set network.wg0.mtu=1420
  uci_run add_list network.wg0.addresses="$WG_IP/$PREFIX"

  uci_run set network.wireguard_wg0=wireguard_wg0
  uci_run set network.wireguard_wg0.public_key="$SRV_PUB"
  uci_run set network.wireguard_wg0.endpoint_host="$EP_HOST"
  uci_run set network.wireguard_wg0.endpoint_port="$EP_PORT"
  uci_run add_list network.wireguard_wg0.allowed_ips="$ALLOWED"
  uci_run set network.wireguard_wg0.persistent_keepalive=25
  uci_run set network.wireguard_wg0.route_allowed_ips=1

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
}

configure_awg() {
  uci -q delete network.wg0 2>/dev/null
  uci -q delete network.wg0peer 2>/dev/null
  uci -q delete network.wireguard_wg0 2>/dev/null
  uci -q delete network.@wireguard_wg0 2>/dev/null
  uci -q delete network.awg1 2>/dev/null
  uci -q delete network.amneziawg_awg1 2>/dev/null
  uci -q delete network.@amneziawg_awg1 2>/dev/null

  uci_run set network.awg1=interface
  uci_run set network.awg1.proto=amneziawg
  uci_run set network.awg1.private_key="$WG_PRIV"
  uci_run set network.awg1.listen_port="$EP_PORT"
  uci_run set network.awg1.mtu="$MTU"
  uci_run add_list network.awg1.addresses="$WG_IP/$PREFIX"
  uci_run set network.awg1.awg_jc="$AWG_JC"
  uci_run set network.awg1.awg_jmin="$AWG_JMIN"
  uci_run set network.awg1.awg_jmax="$AWG_JMAX"
  uci_run set network.awg1.awg_s1="$AWG_S1"
  uci_run set network.awg1.awg_s2="$AWG_S2"
  uci_run set network.awg1.awg_h1="$AWG_H1"
  uci_run set network.awg1.awg_h2="$AWG_H2"
  uci_run set network.awg1.awg_h3="$AWG_H3"
  uci_run set network.awg1.awg_h4="$AWG_H4"

  uci_run set network.amneziawg_awg1=amneziawg_awg1
  uci_run set network.amneziawg_awg1.public_key="$SRV_PUB"
  uci_run set network.amneziawg_awg1.endpoint_host="$EP_HOST"
  uci_run set network.amneziawg_awg1.endpoint_port="$EP_PORT"
  uci_run add_list network.amneziawg_awg1.allowed_ips="$ALLOWED"
  uci_run set network.amneziawg_awg1.persistent_keepalive=25
  uci_run set network.amneziawg_awg1.route_allowed_ips=1

  LAN_ZONE=$(uci show firewall 2>/dev/null | grep "\.name='lan'" | sed "s/\.name.*//" | head -n1)
  if [ -z "$LAN_ZONE" ]; then
    LAN_ZONE=$(uci show firewall 2>/dev/null | grep "\.network='lan'" | sed "s/\.network.*//" | head -n1)
  fi
  if [ -n "$LAN_ZONE" ]; then
    uci -q del_list "$LAN_ZONE.network=wg0" 2>/dev/null || true
    CUR=$(uci -q get "$LAN_ZONE.network" 2>/dev/null)
    case " $CUR " in
      *" awg1 "*) echo "==> awg1 already in lan zone" ;;
      *) uci_run add_list "$LAN_ZONE.network=awg1" ;;
    esac
  else
    echo "WARNING: lan firewall zone not found, awg1 not added to it"
  fi
}

if [ "$MODE" = "awg" ]; then
  configure_awg
else
  configure_wg
fi

uci_run commit network
uci_run commit firewall

IFACE=wg0; [ "$MODE" = "awg" ] && IFACE=awg1

/etc/init.d/network reload
sleep 2
ifup "$IFACE" 2>/dev/null || true
fw4 reload 2>/dev/null || fw3 reload 2>/dev/null || true

sleep 3
STAT=$(ubus call "network.interface.$IFACE" status 2>/dev/null)
case "$STAT" in
  *'"up":true'*) UP="up" ;;
  *)
    echo "==> $IFACE not up after reload, restarting network..."
    /etc/init.d/network restart 2>/dev/null || true
    sleep 5
    STAT=$(ubus call "network.interface.$IFACE" status 2>/dev/null)
    case "$STAT" in
      *'"up":true'*) UP="up" ;;
      *) UP="not up (check dmesg / kmod / packages)" ;;
    esac
    ;;
esac

echo ""
echo "=== Done ==="
echo "Router:      $NAME"
echo "Mode:        $MODE"
echo "Address:     $WG_IP"
echo "Server:      $EP_HOST:$EP_PORT"
echo "Interface:   $IFACE $UP"
echo "You can manage this router over VPN at https://$WG_IP (LuCI)"
