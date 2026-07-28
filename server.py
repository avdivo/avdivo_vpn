import csv
import os
import secrets
import subprocess
import sys
from datetime import date
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

WG_DIR = "/etc/wireguard-config"
WG_CONF = "/etc/wireguard/wg0.conf"
TEMPLATE = "client.conf.template"
SERVER_PUBKEY = "QrsyvITrXZA1a4eGj42WHXNIA11pIYX6xLmE24hAjWs="
SERVER_ENDPOINT = "46.8.112.244:51820"

PASSWORD = os.environ.get("WG_PASSWORD", "")
if not PASSWORD:
    print("FATAL: WG_PASSWORD not set", file=sys.stderr)
    sys.exit(1)

os.makedirs(f"{WG_DIR}/configs", exist_ok=True)
CSV_PATH = f"{WG_DIR}/devices.csv"
if not os.path.exists(CSV_PATH):
    with open(CSV_PATH, "w") as f:
        f.write("number|ip|date|name|pubkey\n")


class Handler(BaseHTTPRequestHandler):
    def _html(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def _text(self, text, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(text.encode())

    def do_GET(self):
        if self.path != "/wg/" and self.path != "/wg":
            self.send_error(404)
            return
        self._html(
            "<html><body>"
            "<h2>WireGuard config generator</h2>"
            "<form method='POST'>"
            "<label>Password: <input type='password' name='pass' required></label><br>"
            "<label>Device name: <input name='name' required placeholder='lena-win'></label><br>"
            "<button type='submit'>Generate config</button>"
            "</form>"
            "</body></html>"
        )

    def do_POST(self):
        if self.path != "/wg/" and self.path != "/wg":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = parse_qs(body)
        pwd = params.get("pass", [""])[0]
        name = params.get("name", [""])[0]

        if pwd != PASSWORD:
            self._text("Wrong password", 403)
            return
        if not name or not name.strip():
            self._text("Device name is required", 400)
            return

        name = name.strip().replace(" ", "_")

        try:
            config = self.generate(name)
        except Exception as e:
            self._text(f"Error: {e}", 500)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f"attachment; filename={config}")
        self.end_headers()
        with open(config, "rb") as f:
            self.wfile.write(f.read())

    def generate(self, name):
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True)
        privkey = priv.stdout.strip()
        pub = subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True, text=True, check=True)
        pubkey = pub.stdout.strip()

        with open(CSV_PATH) as f:
            rows = list(csv.DictReader(f, delimiter="|"))
        last_num = max((int(r["number"]) for r in rows), default=1)
        new_num = last_num + 1
        ip = f"10.0.0.{new_num}"

        with open(TEMPLATE) as f:
            conf = (
                f.read()
                .replace("__PRIVATE_KEY__", privkey)
                .replace("__ADDRESS__", ip)
            )

        cfg_path = f"{WG_DIR}/configs/wg{new_num:02d}.conf"
        with open(cfg_path, "w") as f:
            f.write(conf)

        peer_block = (
            f"\n[Peer]\n"
            f"PublicKey = {pubkey}\n"
            f"AllowedIPs = {ip}/32\n"
        )
        with open(WG_CONF, "a") as f:
            f.write(peer_block)

        subprocess.run(["systemctl", "restart", "wg-quick@wg0"], check=True)

        with open(CSV_PATH, "a") as f:
            f.write(f"{new_num:02d}|{ip}|{date.today()}|{name}|{pubkey}\n")

        return cfg_path


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9800))
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Listening on 127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
