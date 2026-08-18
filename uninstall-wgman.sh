#!/usr/bin/env bash
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "ERROR: run as root"; exit 1; }

echo "==> Stopping services..."
systemctl stop wgman-api.service wgman-firewall.service wg-quick@wg0 2>/dev/null || true
systemctl disable wgman-api.service wgman-firewall.service wg-quick@wg0 2>/dev/null || true

echo "==> Removing systemd units..."
rm -f /etc/systemd/system/wgman-api.service
rm -f /etc/systemd/system/wgman-firewall.service
systemctl daemon-reload

echo "==> Tearing down wg0..."
wg-quick down wg0 2>/dev/null || true

echo "==> Removing /etc/wireguard and /opt/wgman..."
rm -rf /etc/wireguard
rm -rf /opt/wgman

echo "==> Cleaning up leftovers in iptables..."
iptables -D INPUT -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -p tcp --dport 51821 -j ACCEPT 2>/dev/null || true
iptables -D INPUT -i wg0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -i wg0 -o wg0 -j ACCEPT 2>/dev/null || true
iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -j MASQUERADE 2>/dev/null || true
iptables -t nat -S POSTROUTING | grep -q "10.66.66.0/24.*MASQUERADE" && {
  for iface in $(ip -o link show | awk -F': ' '{print $2}'); do
    iptables -t nat -D POSTROUTING -s 10.66.66.0/24 -o "$iface" -j MASQUERADE 2>/dev/null || true
  done
}

echo "==> Optional: reset IP forwarding in sysctl.conf"
sed -i '/^net.ipv4.ip_forward=1/d' /etc/sysctl.conf 2>/dev/null || true

echo "Done. wgman fully removed."
echo "Reinstall: bash /root/wgremote/install-wgman.sh --host <IPv4>"