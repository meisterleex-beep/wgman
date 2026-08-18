#!/usr/bin/env bash
set -e

SRC_DIR=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" != "0" ]; then
  echo "ERROR: run as root"
  exit 1
fi

mkdir -p /opt/wgman
cp "$SRC_DIR/wgman" "$SRC_DIR/api.py" "$SRC_DIR/webui.py" /opt/wgman/
chmod +x /opt/wgman/wgman

echo "wgman installed to /opt/wgman"
exec /opt/wgman/wgman install "$@"
