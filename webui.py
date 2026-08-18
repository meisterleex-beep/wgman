#!/usr/bin/env python3
import html
import hmac
import json
import os
import secrets
import ssl
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

WG_DIR = "/opt/wgman"
STATE_DIR = os.path.join(WG_DIR, "state")
PEERS_FILE = os.path.join(STATE_DIR, "peers")
TOKEN_FILE = os.path.join(STATE_DIR, "token")
CONFIG_FILE = os.path.join(STATE_DIR, "config")
SESSION_FILE = os.path.join(STATE_DIR, "session")
CERT_FILE = os.path.join(STATE_DIR, "server.crt")
KEY_FILE = os.path.join(STATE_DIR, "server.key")
SERVER_PUB_FILE = "/etc/wireguard/server.pub"
API_PORT = 51821

AWG_DEFAULTS = {"JC": "50", "JMIN": "5", "JMAX": "5", "S1": "0", "S2": "0",
                "H1": "2048", "H2": "4096", "H3": "8192", "H4": "16384"}


def read_file(p):
    try:
        with open(p) as f:
            return f.read().strip()
    except OSError:
        return ""


def load_config():
    cfg = {}
    for line in read_file(CONFIG_FILE).splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip()
    return cfg


def run_wgman(args):
    res = subprocess.run(
        ["bash", os.path.join(WG_DIR, "wgman")] + list(args),
        capture_output=True, text=True)
    return res.returncode, (res.stdout or "").strip(), (res.stderr or "").strip()


def fmt_endpoint(host, port):
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    return host + ":" + port


def send(code, body, ctype, handler, extra=None):
    handler.send_response(code)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    for k, v in (extra or {}).items():
        handler.send_header(k, v)
    handler.end_headers()
    if body:
        handler.wfile.write(body if isinstance(body, bytes) else body.encode())


def send_json(handler, code, obj):
    send(code, json.dumps(obj).encode(), "application/json", handler)


def send_html(handler, code, body):
    send(code, body, "text/html; charset=utf-8", handler)


def redirect(handler, location):
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def cookies(handler):
    out = {}
    for part in handler.headers.get("Cookie", "").split(";"):
        if "=" in part:
            k, v = part.strip().split("=", 1)
            out[k] = v
    return out


def auth_ok(req):
    sid = cookies(req).get("sid", "")
    cur = read_file(SESSION_FILE)
    return bool(sid and cur and hmac.compare_digest(sid, cur))


def handshakes():
    hs = {}
    for cmd in (["wg", "show", "wg0", "latest-handshakes"],
                ["awg", "show", "awg0", "latest-handshakes"]):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True)
            out = res.stdout or ""
        except OSError:
            continue
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                try:
                    hs[parts[0]] = int(parts[1])
                except ValueError:
                    pass
    return hs


def parse_peers():
    peers = []
    for line in read_file(PEERS_FILE).splitlines():
        parts = line.split("|")
        if len(parts) >= 7:
            proto = parts[7] if len(parts) > 7 and parts[7] else "wg"
            enabled = parts[8] if len(parts) > 8 and parts[8] else "1"
            peers.append({
                "name": parts[0], "pub": parts[1], "ip": parts[2],
                "lan": parts[3], "ep": parts[4], "type": parts[5], "date": parts[6],
                "proto": proto, "enabled": enabled,
            })
    return peers


PAGE_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; background: #0f1419; color: #e6e6e6; padding: 24px; }
.wrap { max-width: 1200px; margin: 0 auto; }
h1 { font-size: 22px; margin-bottom: 4px; }
.sub { color: #8b949e; font-size: 13px; margin-bottom: 20px; }
.card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 16px; margin-bottom: 16px; }
.card h2 { font-size: 15px; color: #79c0ff; margin-bottom: 12px; text-transform: uppercase; letter-spacing: .5px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 14px; }
.kv { font-size: 13px; }
.kv .k { color: #8b949e; display: block; font-size: 11px; }
.kv .v { font-family: ui-monospace, Consolas, monospace; word-break: break-all; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #21262d; }
th { color: #8b949e; font-size: 11px; text-transform: uppercase; }
td.mono { font-family: ui-monospace, Consolas, monospace; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; }
.b-on { background: #1f6f2f; color: #7ee787; }
.b-off { background: #442310; color: #ffa657; }
button { background: #21262d; border: 1px solid #30363d; color: #e6e6e6; padding: 7px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }
button:hover { background: #30363d; }
button.primary { background: #238636; border-color: #238636; color: #fff; }
button.danger { background: #4d1d1d; border-color: #5c1f1f; }
a.btn { display: inline-block; text-decoration: none; background: #21262d; border: 1px solid #30363d; padding: 6px 12px; border-radius: 6px; font-size: 13px; color: #e6e6e6; margin-right: 6px; }
a.btn:hover { background: #30363d; }
.login { max-width: 380px; margin: 12vh auto 0; }
.login .card { padding: 28px; }
input[type=password] { width: 100%; background: #0d1117; border: 1px solid #30363d; color: #e6e6e6; padding: 10px; border-radius: 6px; margin: 12px 0; font-size: 14px; }
.note { color: #8b949e; font-size: 12px; margin-top: 14px; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; }
"""


def page(title, body):
    return ("<!doctype html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>" + html.escape(title) + " - wgman</title>"
            "<style>" + PAGE_CSS + "</style></head><body><div class='wrap'>"
            + body + "</div></body></html>")


def login_page(msg=""):
    msg_html = ("<p style='color:#ff7b72'>" + html.escape(msg) + "</p>" if msg else "")
    return page("Login", """
<div class='login'><div class='card'>
<h2 style='color:#79c0ff'>wgman</h2>
""" + msg_html + """
<form id='login'>
<input type='password' id='pw' placeholder='Admin password' autofocus>
<button class='primary' type='submit' style='width:100%'>Sign in</button>
</form>
</div></div>
<script>
document.getElementById('login').addEventListener('submit', async function(e){
  e.preventDefault();
  const pw = document.getElementById('pw').value;
  const r = await fetch('/api/login', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({password:pw})});
  const j = await r.json().catch(()=>({ok:false}));
  if (j.ok) location.href = '/'; else alert(j.message || 'Login failed');
});
</script>""")


def dashboard(handler):
    cfg = load_config()
    hs = handshakes()
    peers = parse_peers()
    net = cfg.get("NET", "10.66.66")
    prefix = cfg.get("PREFIX", "24")
    port = cfg.get("PORT", "51820")
    host = cfg.get("SERVER_HOST", "")
    endpoint = (host + ":" + port) if host else ("<unknown, set host>")
    srv_pub = read_file(SERVER_PUB_FILE)

    ep_disp = fmt_endpoint(host, port) or "<unknown, set host>"
    awg_on = cfg.get("AWG") == "1"
    awg_state_disp = ("<span class='badge b-on'>enabled</span>" if awg_on
                      else "<span class='badge b-off'>disabled</span>")
    awg_kv = ""
    if awg_on:
        awg_port = cfg.get("AWG_PORT", "51823")
        awg_net = cfg.get("AWG_NET", "10.66.77")
        awg_prefix = cfg.get("AWG_PREFIX", "24")
        awg_kv = ("<div class='kv'><span class='k'>AWG endpoint</span><span class='v'>"
                  + html.escape(fmt_endpoint(host, awg_port)) + "</span></div>"
                  "<div class='kv'><span class='k'>AWG network</span><span class='v'>"
                  + html.escape(awg_net + ".0/" + awg_prefix) + "</span></div>")
    rows = []
    for p in peers:
        now = time.time()
        ts = hs.get(p["pub"], 0)
        online = bool(ts and (now - ts) < 180)
        status = ("<span class='badge b-on'>online</span>" if online
                  else "<span class='badge b-off'>offline</span>")
        tlabel = "router" if p["type"] == "router" else "client"
        proto = p.get("proto") or "wg"
        rows.append(
            "<tr><td class='mono'>" + html.escape(p["name"]) + "</td>"
            "<td class='mono'>" + html.escape(p["ip"]) + "</td>"
            "<td class='mono'>" + html.escape(p["lan"]) + "</td>"
            "<td>" + tlabel + "</td>"
            "<td class='mono'>" + proto.upper() + "</td>"
            "<td class='mono'>" + html.escape(p["ep"]) + "</td>"
            "<td>" + status + "</td>"
            "<td><input type='checkbox' " + ("checked" if p.get("enabled") != "0" else "")
            + " onchange='togglePeer(\"" + html.escape(p["name"], quote=True)
            + "\",this.checked)'></td>"
            "<td>" + html.escape(p["date"]) + "</td>"
            "<td><a class='btn' href='/api/config/" + html.escape(p["name"], quote=True)
            + "' target='_blank'>config</a>"
            "<a class='btn danger' href='#' onclick='removePeer(\"" + html.escape(p["name"], quote=True)
            + "\");return false;'>del</a></td></tr>")

    peer_rows = "\n".join(rows) if rows else ("<tr><td colspan='10' style='color:#8b949e'>"
                                              "No peers yet. Add a PC client or register a router.</td></tr>")

    body = ("<h1>wgman</h1><div class='sub'>WireGuard manager for OpenWrt routers</div>"
            "<div class='card'><h2>Server</h2><div class='grid'>"
            "<div class='kv'><span class='k'>Endpoint</span><span class='v'>" + html.escape(ep_disp) + "</span></div>"
            "<div class='kv'><span class='k'>WG network</span><span class='v'>" + html.escape(net + ".0/" + prefix) + "</span></div>"
            "<div class='kv'><span class='k'>Port</span><span class='v'>" + html.escape(port) + "/udp</span></div>"
            + awg_kv +
            "<div class='kv'><span class='k'>AWG tunnel</span><span class='v'>" + awg_state_disp + "</span></div>"
            "<div class='kv'><span class='k'>Public key</span><span class='v'>" + html.escape(srv_pub) + "</span></div>"
            "</div></div>"
            "<div class='actions'>"
            "<button onclick='addClient()'>+ PC client</button>"
            "<button onclick='addRouter()'>+ Router</button>"
            "<button onclick='toggleAwg()'>AWG: " + ("disable" if awg_on else "enable") + "</button>"
            "<button onclick='rotateToken()'>Rotate API token</button>"
            "<button onclick='setHost()'>Set host</button>"
            "<a class='btn' href='/logout'>Logout</a>"
            "</div>"
            "<div class='card'><h2>Peers</h2><table>"
            "<thead><tr><th>Name</th><th>WG IP</th><th>LAN</th><th>Type</th><th>Proto</th><th>Endpoint</th>"
            "<th>Status</th><th>On</th><th>Added</th><th>Actions</th></tr></thead>"
            "<tbody>" + peer_rows + "</tbody></table></div>"
            "<div class='note'>To add a router automatically, run on the router itself: "
            "sh install-router.sh https://" + html.escape(fmt_endpoint(host, str(cfg.get("API_PORT", "51821"))))
            + "/register &lt;token&gt; name&lt;br&gt;Add &lt;b&gt;--awg&lt;/b&gt; to use the AmneziaWG tunnel (obfuscated, DPI-resistant). "
            "The + PC client and + Router buttons ask which protocol to use. "
            "New PC/manager clients keep the token secret; only the admin password is needed here.</div>"
            "<script>"
            "const post=async(url,data)=>{const r=await fetch(url,{method:'POST',"
            "headers:{'Content-Type':'application/json'},body:JSON.stringify(data||{})});"
            "return r.json().catch(()=>({ok:false,message:'bad response'}));};"
            "async function addClient(){const n=prompt('Client name:');if(!n)return;"
            "const awg=confirm('AmneziaWG (obfuscated, DPI-resistant)?\\nOK = AWG / Cancel = WireGuard');"
            "const j=await post('/api/add_client',{name:n,proto:awg?'awg':'wg'});"
            "if(j.ok){alert('Client created: '+n+' ('+(awg?'AWG':'WG')+')');window.open('/api/config/'+n);"
            "location.reload();}else alert(j.message);}"
            "async function toggleAwg(){const now=" + ("true" if awg_on else "false") + ";"
            "const j=await post('/api/awg',{action:now?'off':'on'});"
            "if(j.ok)location.reload();else alert(j.message);}"
            "async function addRouter(){const n=prompt('Router name:');if(!n)return;"
            "const l=prompt('LAN subnet (CIDR), optional:','');"
            "const awg=confirm('AmneziaWG (obfuscated, DPI-resistant)?\\nOK = AWG / Cancel = WireGuard');"
            "const j=await post('/api/add_router',{name:n,lan:l||'',proto:awg?'awg':'wg'});"
            "if(j.ok){alert('Router created, IP: '+j.ip+' ('+(awg?'AWG':'WG')+')');"
            "window.open('/api/config/'+n);location.reload();}else alert(j.message);}"
            "async function removePeer(n){if(!confirm('Remove '+n+'?'))return;"
            "const j=await post('/api/remove',{sel:n});"
            "if(j.ok)location.reload();else alert(j.message);}"
            "async function togglePeer(n,c){const j=await post('/api/peer_toggle',{name:n,enabled:c});"
            "if(!j.ok)alert(j.message);location.reload();}"
            "async function rotateToken(){if(!confirm('Rotate API token? confirm in browser.'))return;"
            "const j=await post('/api/token',{action:'new'});"
            "if(j.ok)alert('New API token: '+j.token);else alert(j.message);}"
            "async function setHost(){const h=prompt('Public endpoint host of the server:');"
            "if(!h)return;const j=await post('/api/host',{host:h});"
            "if(j.ok){alert('OK');location.reload();}else alert(j.message);}"
            "</script>")
    return page("Dashboard", body)


class Handler(BaseHTTPRequestHandler):
    server_version = "wgman"

    def log_message(self, fmt, *args):
        sys.stderr.write("[wgman] %s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/status", "/health"):
            send_json(self, 200, {"status": "ok"})
            return
        if path == "/register":
            send_json(self, 200, {"status": "ok", "method": "POST"})
            return
        if path == "/login":
            if auth_ok(self):
                redirect(self, "/")
            else:
                send_html(self, 200, login_page())
            return
        if path == "/logout":
            if os.path.exists(SESSION_FILE):
                os.remove(SESSION_FILE)
            redirect(self, "/login")
            return
        if not auth_ok(self):
            redirect(self, "/login")
            return
        if path == "/" or path == "/dashboard":
            send_html(self, 200, dashboard(self))
            return
        if path.startswith("/api/config/"):
            name = path[len("/api/config/"):]
            rc, out, err = run_wgman(["config", name])
            if rc != 0:
                send_json(self, 404, {"ok": False, "message": err or out})
            else:
                send(200, out + "\n", "text/plain; charset=utf-8", self)
            return
        if path in ("/api/status", "/api/peers"):
            cfg = load_config()
            send_json(self, 200, {
                "ok": True,
                "server": {
                    "endpoint": fmt_endpoint(cfg.get("SERVER_HOST", ""), cfg.get("PORT", "51820")),
                    "net": cfg.get("NET", "10.66.66") + ".0/" + cfg.get("PREFIX", "24"),
                    "public_key": read_file(SERVER_PUB_FILE),
                },
                "awg": {
                    "enabled": cfg.get("AWG") == "1",
                    "endpoint": fmt_endpoint(cfg.get("SERVER_HOST", ""), cfg.get("AWG_PORT", "51823")),
                    "net": cfg.get("AWG_NET", "10.66.77") + ".0/" + cfg.get("AWG_PREFIX", "24"),
                },
                "peers": parse_peers(),
            })
            return
        send_json(self, 404, {"ok": False, "message": "not found"})

    def _read_json(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        try:
            return json.loads(body.decode() or "{}")
        except Exception:
            return {}

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/register":
            self._register()
            return
        if path == "/api/login":
            data = self._read_json()
            if hmac.compare_digest(str(data.get("password") or ""), read_file_prefix(CONFIG_FILE, "ADMIN_PASS")):
                sid = secrets.token_hex(32)
                os.makedirs(STATE_DIR, exist_ok=True)
                with open(SESSION_FILE, "w") as f:
                    f.write(sid)
                extra = {"Set-Cookie": "sid=" + sid + "; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"}
                send(200, json.dumps({"ok": True}).encode(), "application/json", self, extra)
            else:
                send_json(self, 401, {"ok": False, "message": "wrong password"})
            return
        if not auth_ok(self):
            send_json(self, 401, {"ok": False, "message": "unauthorized"})
            return
        data = self._read_json()
        if path == "/api/add_client":
            name = str(data.get("name") or "").strip()
            proto = str(data.get("proto") or "wg").strip()
            cmd = ["add", name] + (["--awg"] if proto == "awg" else [])
            rc, out, err = run_wgman(cmd)
            if rc != 0:
                send_json(self, 400, {"ok": False, "message": (err or out)})
            else:
                send_json(self, 200, {"ok": True, "name": name})
            return
        if path == "/api/awg":
            action = str(data.get("action") or "").strip()
            if action not in ("on", "off"):
                send_json(self, 400, {"ok": False, "message": "action must be on or off"})
                return
            rc, out, err = run_wgman(["awg", action])
            send_json(self, 200 if rc == 0 else 400,
                      {"ok": rc == 0, "message": (err or out)})
            return
        if path == "/api/add_router":
            name = str(data.get("name") or "").strip()
            lan = str(data.get("lan") or "").strip()
            proto = str(data.get("proto") or "wg").strip()
            cmd = ["router-new", name, lan] + (["awg"] if proto == "awg" else [])
            rc, out, err = run_wgman(cmd)
            if rc != 0:
                send_json(self, 400, {"ok": False, "message": (err or out)})
            else:
                ip = out.split("OK ")[-1].split()[0] if "OK " in out else ""
                send_json(self, 200, {"ok": True, "name": name, "ip": ip, "proto": proto})
            return
        if path == "/api/remove":
            rc, out, err = run_wgman(["remove", str(data.get("sel") or "").strip()])
            send_json(self, 200 if rc == 0 else 400,
                      {"ok": rc == 0, "message": (err or out)})
            return
        if path == "/api/peer_toggle":
            name = str(data.get("name") or "").strip()
            enabled = 1 if data.get("enabled") else 0
            rc, out, err = run_wgman(["enable" if enabled else "disable", name])
            send_json(self, 200 if rc == 0 else 400,
                      {"ok": rc == 0, "message": (err or out)})
            return
        if path == "/api/token":
            if str(data.get("action") or "") == "new":
                rc, out, err = run_wgman(["token", "new"])
                if rc != 0:
                    send_json(self, 400, {"ok": False, "message": err or out})
                    return
                newtok = run_wgman(["token"])[1]
                send_json(self, 200, {"ok": True, "token": newtok})
            else:
                send_json(self, 200, {"ok": True, "token": run_wgman(["token"])[1]})
            return
        if path == "/api/host":
            rc, out, err = run_wgman(["host", str(data.get("host") or "").strip()])
            send_json(self, 200 if rc == 0 else 400,
                      {"ok": rc == 0, "message": (err or out)})
            return
        send_json(self, 404, {"ok": False, "message": "not found"})

    def _register(self):
        cfg = load_config()
        token = read_file(TOKEN_FILE)
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b""
            req = json.loads(body.decode() or "{}")
        except Exception:
            send_json(self, 400, {"status": "error", "message": "bad request"})
            return
        if not token or req.get("token") != token:
            send_json(self, 403, {"status": "error", "message": "invalid token"})
            return
        name = (req.get("name") or "").strip()
        pub = (req.get("public_key") or "").strip()
        lan = (req.get("lan_cidr") or "").strip()
        ep = (req.get("endpoint") or "").strip()
        proto = (req.get("proto") or "wg").strip()
        if proto not in ("wg", "awg"):
            proto = "wg"
        if not name or not pub:
            send_json(self, 400, {"status": "error", "message": "name and public_key are required"})
            return
        rc, out, err = run_wgman(["_register", name, pub, lan, ep, proto])
        lines = out.strip().splitlines()
        if rc != 0:
            send_json(self, 400, {"status": "error", "message": (err or out or "registration failed")})
            return
        if not lines or not lines[-1].startswith("OK "):
            send_json(self, 500, {"status": "error", "message": "unexpected server response"})
            return
        ip = lines[-1][3:].strip()
        host = cfg.get("SERVER_HOST", "")
        port = cfg.get("PORT", "51820")
        dns = cfg.get("DNS1", "1.1.1.1") + "," + cfg.get("DNS2", "8.8.8.8")
        resp = {
            "status": "ok",
            "ip": ip,
            "server_public_key": read_file(SERVER_PUB_FILE),
            "dns": dns,
            "proto": proto,
        }
        if proto == "awg":
            ap = cfg.get("AWG_PORT", "51823")
            resp["server_endpoint"] = fmt_endpoint(host, ap)
            resp["allowed_ips"] = cfg.get("AWG_NET", "10.66.77") + ".0/" + cfg.get("AWG_PREFIX", "24")
            resp["awg_port"] = ap
            resp["mtu"] = cfg.get("AWG_MTU", "1420")
            for k in ("JC", "JMIN", "JMAX", "S1", "S2", "H1", "H2", "H3", "H4"):
                resp["awg_" + k.lower()] = cfg.get("AWG_" + k, AWG_DEFAULTS[k])
        else:
            resp["server_endpoint"] = fmt_endpoint(host, port)
            resp["allowed_ips"] = cfg.get("NET", "10.66.66") + ".0/" + cfg.get("PREFIX", "24")
        send_json(self, 200, resp)


def read_file_prefix(path, key):
    for line in read_file(path).splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return ""


def main():
    port = int(os.environ.get("WGMAN_API_PORT", API_PORT))
    httpd = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT_FILE, KEY_FILE)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    else:
        sys.stderr.write("WARNING: no TLS cert found, running over plain HTTP\n")
    sys.stderr.write("wgman web UI listening on 0.0.0.0:%s\n" % port)
    httpd.serve_forever()


if __name__ == "__main__":
    main()