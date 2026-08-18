#!/usr/bin/env python3
import json
import os
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

WG_DIR = "/opt/wgman"
STATE_DIR = os.path.join(WG_DIR, "state")
TOKEN_FILE = os.path.join(STATE_DIR, "token")
CONFIG_FILE = os.path.join(STATE_DIR, "config")
CERT_FILE = os.path.join(STATE_DIR, "server.crt")
KEY_FILE = os.path.join(STATE_DIR, "server.key")
API_PORT = 51821


def load_config():
    cfg = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip()
    return cfg


cfg = load_config()

TOKEN = ""
if os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE) as f:
        TOKEN = f.read().strip()


def respond(handler, code, obj):
    data = json.dumps(obj).encode()
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.rstrip("/") == "/status":
            respond(self, 200, {"status": "ok"})
        else:
            respond(self, 404, {"status": "error", "message": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/register":
            respond(self, 404, {"status": "error", "message": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            req = json.loads(body.decode() or "{}")
        except Exception:
            respond(self, 400, {"status": "error", "message": "bad request"})
            return
        if not TOKEN or req.get("token") != TOKEN:
            respond(self, 403, {"status": "error", "message": "invalid token"})
            return
        name = (req.get("name") or "").strip()
        pub = (req.get("public_key") or "").strip()
        lan = (req.get("lan_cidr") or "").strip()
        ep = (req.get("endpoint") or "").strip()
        if not name or not pub:
            respond(self, 400, {"status": "error", "message": "name and public_key are required"})
            return
        cmd = ["bash", os.path.join(WG_DIR, "wgman"), "_register", name, pub, lan, ep]
        res = subprocess.run(cmd, capture_output=True, text=True)
        out = (res.stdout or "").strip()
        lines = out.splitlines()
        if res.returncode != 0:
            err = (res.stderr or res.stdout or "").strip()
            respond(self, 400, {"status": "error", "message": err or "registration failed"})
            return
        if not lines or not lines[-1].startswith("OK "):
            respond(self, 500, {"status": "error", "message": "unexpected server response"})
            return
        ip = lines[-1][3:].strip()

        srv_pub = ""
        pubfile = "/etc/wireguard/server.pub"
        if os.path.exists(pubfile):
            with open(pubfile) as f:
                srv_pub = f.read().strip()

        host = cfg.get("SERVER_HOST", "")
        port = cfg.get("PORT", "51820")
        endpoint = (host + ":" + port) if host else ""
        net = cfg.get("NET", "10.66.66")
        prefix = cfg.get("PREFIX", "24")
        dns = cfg.get("DNS1", "1.1.1.1") + "," + cfg.get("DNS2", "8.8.8.8")

        respond(self, 200, {
            "status": "ok",
            "ip": ip,
            "server_public_key": srv_pub,
            "server_endpoint": endpoint,
            "dns": dns,
            "allowed_ips": net + ".0/" + prefix,
        })

    def log_message(self, fmt, *args):
        sys.stderr.write("[wgman-api] %s - %s\n" % (self.address_string(), fmt % args))


def main():
    port = int(os.environ.get("WGMAN_API_PORT", API_PORT))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    else:
        sys.stderr.write("WARNING: no TLS cert found, running over plain HTTP\n")
    sys.stderr.write("wgman-api listening on 0.0.0.0:%s\n" % port)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
