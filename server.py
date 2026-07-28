import csv
import os
import subprocess
import sys
from datetime import date
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

WG_DIR = "/etc/wireguard-config"
WG_CONF = "/etc/wireguard/wg0.conf"
TEMPLATE = "client.conf.template"
SYSCTL_RESTART = ["systemctl", "restart", "wg-quick@wg0"]

PASSWORD = os.environ.get("WG_PASSWORD", "")
if not PASSWORD:
    print("FATAL: WG_PASSWORD not set", file=sys.stderr)
    sys.exit(1)

os.makedirs(f"{WG_DIR}/configs", exist_ok=True)
CSV_PATH = f"{WG_DIR}/devices.csv"
if not os.path.exists(CSV_PATH):
    with open(CSV_PATH, "w") as f:
        f.write("number|ip|date|name|pubkey\n")


def read_devices():
    with open(CSV_PATH) as f:
        return list(csv.DictReader(f, delimiter="|"))


def write_devices(rows):
    with open(CSV_PATH, "w") as f:
        f.write("number|ip|date|name|pubkey\n")
        w = csv.DictWriter(f, fieldnames=["number", "ip", "date", "name", "pubkey"], delimiter="|")
        for r in rows:
            w.writerow(r)


PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WireGuard config generator</title>
<style>
  *,*::before,*::after{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0;padding:1rem}
  .card{background:#1e293b;border-radius:1rem;padding:2.5rem;width:100%;max-width:460px;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
  h2{margin:0 0 .5rem;font-size:1.5rem;font-weight:600}
  p{color:#94a3b8;margin:0 0 1.5rem;font-size:.9rem}
  label{display:block;font-size:.85rem;font-weight:500;margin-bottom:.35rem;color:#cbd5e1}
  input{width:100%;padding:.65rem .85rem;border:1px solid #334155;border-radius:.5rem;background:#0f172a;color:#e2e8f0;font-size:.95rem;outline:none;transition:border-color .15s;margin-bottom:1rem}
  input:focus{border-color:#6366f1}
  button{width:100%;padding:.7rem;border:none;border-radius:.5rem;background:#6366f1;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;transition:background .15s}
  button:hover{background:#4f46e5}
  .btn-danger{background:#dc2626}
  .btn-danger:hover{background:#b91c1c}
  .error{background:#7f1d1d;color:#fca5a5;padding:.65rem;border-radius:.5rem;margin-bottom:1rem;font-size:.85rem;text-align:center}
  .success{background:#14532d;color:#86efac;padding:.65rem;border-radius:.5rem;margin-bottom:1rem;font-size:.85rem;text-align:center}
  .divider{border:none;border-top:1px solid #334155;margin:1.5rem 0}
  .hint{text-align:center;margin-top:1rem;font-size:.8rem;color:#475569}
  .section-title{font-size:.9rem;font-weight:500;color:#94a3b8;margin-bottom:1rem}
</style>
</head>
<body>
<div class="card">
  <h2>WireGuard config</h2>
  <p>Сгенерировать или отозвать конфиг устройства</p>
  __MSG__
  <div class="section-title">Создать новый</div>
  <form method="POST">
    <input type="hidden" name="action" value="generate">
    <label for="pass">Password</label>
    <input type="password" id="pass" name="pass" required placeholder="••••••••">
    <label for="name">Device name</label>
    <input type="text" id="name" name="name" required placeholder="lena-win">
    <button type="submit">Generate config</button>
  </form>
  <hr class="divider">
  <div class="section-title">Отозвать устройство</div>
  <form method="POST">
    <input type="hidden" name="action" value="revoke">
    <label for="rpass">Password</label>
    <input type="password" id="rpass" name="pass" required placeholder="••••••••">
    <label for="rname">Device name</label>
    <input type="text" id="rname" name="name" required placeholder="lena-win">
    <button type="submit" class="btn-danger">Revoke config</button>
  </form>
  <div class="hint">После отзыва устройство потеряет доступ к VPN</div>
</div>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def _page(self, msg=""):
        html = PAGE.replace("__MSG__", msg)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def _file(self, path):
        with open(path, "rb") as f:
            data = f.read()
        fname = os.path.basename(path)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f"attachment; filename={fname}")
        self.end_headers()
        self.wfile.write(data)

    def _parse_post(self):
        length = int(self.headers.get("Content-Length", 0))
        return parse_qs(self.rfile.read(length).decode())

    def do_GET(self):
        if not self.path.startswith("/wg"):
            self.send_error(404)
            return
        self._page()

    def do_POST(self):
        if not self.path.startswith("/wg"):
            self.send_error(404)
            return
        params = self._parse_post()
        action = params.get("action", [""])[0]
        if action == "revoke":
            self._handle_revoke(params)
        else:
            self._handle_generate(params)

    def _handle_generate(self, params):
        pwd = params.get("pass", [""])[0]
        name = params.get("name", [""])[0]

        if pwd != PASSWORD:
            self._page('<div class="error">Wrong password</div>')
            return
        if not name or not name.strip():
            self._page('<div class="error">Device name is required</div>')
            return

        name = name.strip().replace(" ", "_")

        devices = read_devices()
        if any(d["name"] == name for d in devices):
            self._page(f'<div class="error">Device "{name}" already exists</div>')
            return

        try:
            cfg_path = self.generate(name, devices)
        except Exception as e:
            self._page(f'<div class="error">Error: {e}</div>')
            return

        self._file(cfg_path)

    def _handle_revoke(self, params):
        pwd = params.get("pass", [""])[0]
        name = params.get("name", [""])[0]

        if pwd != PASSWORD:
            self._page('<div class="error">Wrong password</div>')
            return
        if not name or not name.strip():
            self._page('<div class="error">Device name is required</div>')
            return

        name = name.strip()

        try:
            self.revoke(name)
        except ValueError as e:
            self._page(f'<div class="error">{e}</div>')
            return
        except Exception as e:
            self._page(f'<div class="error">Error: {e}</div>')
            return

        self._page(f'<div class="success">Device "{name}" revoked</div>')

    def generate(self, name, devices):
        priv = subprocess.run(["wg", "genkey"], capture_output=True, text=True, check=True)
        privkey = priv.stdout.strip()
        pub = subprocess.run(["wg", "pubkey"], input=privkey, capture_output=True, text=True, check=True)
        pubkey = pub.stdout.strip()

        last_num = max((int(d["number"]) for d in devices), default=1)
        new_num = last_num + 1
        ip = f"10.0.0.{new_num}"

        with open(TEMPLATE) as f:
            conf = f.read().replace("__PRIVATE_KEY__", privkey).replace("__ADDRESS__", ip)

        cfg_path = f"{WG_DIR}/configs/wg{new_num:02d}.conf"
        with open(cfg_path, "w") as f:
            f.write(conf)

        peer = f"\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {ip}/32\n"
        with open(WG_CONF, "a") as f:
            f.write(peer)

        subprocess.run(SYSCTL_RESTART, check=True)

        with open(CSV_PATH, "a") as f:
            f.write(f"{new_num:02d}|{ip}|{date.today()}|{name}|{pubkey}\n")

        return cfg_path

    def revoke(self, name):
        devices = read_devices()
        match = [d for d in devices if d["name"] == name]
        if not match:
            raise ValueError(f'Device "{name}" not found')
        dev = match[0]

        os.remove(f"{WG_DIR}/configs/wg{dev['number']}.conf")

        devices = [d for d in devices if d["name"] != name]
        write_devices(devices)

        with open(WG_CONF) as f:
            content = f.read()

        pk = dev["pubkey"]
        import re
        content = re.sub(
            rf"\n\[Peer\]\nPublicKey = {re.escape(pk)}\nAllowedIPs = .*",
            "",
            content,
        )
        content = content.strip() + "\n"

        with open(WG_CONF, "w") as f:
            f.write(content)

        with open(WG_CONF, "w") as f:
            f.writelines(new_lines)

        subprocess.run(SYSCTL_RESTART, check=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9800))
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Listening on 127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
