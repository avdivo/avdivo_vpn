import csv
import json
import os
import re
import subprocess
import sys
from datetime import date
from http.cookies import SimpleCookie
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode

WG_DIR = "/etc/wireguard-config"
WG_CONF = "/etc/wireguard/wg0.conf"
TEMPLATE = "client.conf.template"
WG_IFACE = "wg0"

PASSWORD = os.environ.get("WG_PASSWORD", "")
if not PASSWORD:
    print("FATAL: WG_PASSWORD not set", file=sys.stderr)
    sys.exit(1)

os.makedirs(f"{WG_DIR}/configs", exist_ok=True)
CSV_PATH = f"{WG_DIR}/devices.csv"
if not os.path.exists(CSV_PATH):
    with open(CSV_PATH, "w") as f:
        f.write("number|ip|date|name|pubkey|disabled\n")


def read_devices():
    with open(CSV_PATH, newline="") as f:
        return list(csv.DictReader(f, delimiter="|"))


def write_devices(rows):
    with open(CSV_PATH, "w", newline="") as f:
        f.write("number|ip|date|name|pubkey|disabled\n")
        w = csv.DictWriter(f, fieldnames=["number", "ip", "date", "name", "pubkey", "disabled"], delimiter="|")
        for r in rows:
            w.writerow(r)


def peer_add(pubkey, ip):
    subprocess.run(["wg", "set", WG_IFACE, "peer", pubkey, "allowed-ips", f"{ip}/32"], check=True)


def peer_remove(pubkey):
    subprocess.run(["wg", "set", WG_IFACE, "peer", pubkey, "remove"], check=True)


LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>avdivo VPN</title>
<style>
  *,*::before,*::after{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0;padding:1rem}
  .card{background:#1e293b;border-radius:1rem;padding:2.5rem;width:100%;max-width:400px;box-shadow:0 25px 50px -12px rgba(0,0,0,.5)}
  h2{text-align:center;margin:0 0 1.5rem;font-size:1.5rem;font-weight:600}
  label{display:block;font-size:.85rem;font-weight:500;margin-bottom:.35rem;color:#cbd5e1}
  input{width:100%;padding:.65rem .85rem;border:1px solid #334155;border-radius:.5rem;background:#0f172a;color:#e2e8f0;font-size:.95rem;outline:none;transition:border-color .15s;margin-bottom:1rem}
  input:focus{border-color:#6366f1}
  button{width:100%;padding:.7rem;border:none;border-radius:.5rem;background:#6366f1;color:#fff;font-size:1rem;font-weight:600;cursor:pointer;transition:background .15s}
  button:hover{background:#4f46e5}
  .error{background:#7f1d1d;color:#fca5a5;padding:.65rem;border-radius:.5rem;margin-bottom:1rem;font-size:.85rem;text-align:center}
</style>
</head>
<body>
<div class="card">
  <h2>avdivo VPN</h2>
  __MSG__
  <form method="POST">
    <input type="hidden" name="action" value="login">
    <label for="pass">Пароль</label>
    <input type="password" id="pass" name="pass" required placeholder="••••••••">
    <button type="submit">Войти</button>
  </form>
</div>
</body>
</html>"""

ADMIN_HTML = """\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>avdivo VPN — админка</title>
<style>
  *,*::before,*::after{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem 1rem}
  h2{margin:0 0 .25rem;font-size:1.5rem;font-weight:600}
  p{color:#94a3b8;margin:0 0 1.5rem;font-size:.9rem}
  label{display:block;font-size:.85rem;font-weight:500;margin-bottom:.35rem;color:#cbd5e1}
  input{width:100%;padding:.65rem .85rem;border:1px solid #334155;border-radius:.5rem;background:#0f172a;color:#e2e8f0;font-size:.95rem;outline:none;transition:border-color .15s;margin-bottom:1rem}
  input:focus{border-color:#6366f1}
  button{padding:.6rem 1.2rem;border:none;border-radius:.5rem;font-size:.9rem;font-weight:600;cursor:pointer;transition:background .15s}
  .btn-primary{background:#6366f1;color:#fff}
  .btn-primary:hover{background:#4f46e5}
  .btn-danger{background:#dc2626;color:#fff}
  .btn-danger:hover{background:#b91c1c}
  .btn-sm{padding:.4rem .8rem;font-size:.8rem}
  .msg{background:#14532d;color:#86efac;padding:.65rem;border-radius:.5rem;margin-bottom:1rem;font-size:.85rem;text-align:center}
  .err{background:#7f1d1d;color:#fca5a5;padding:.65rem;border-radius:.5rem;margin-bottom:1rem;font-size:.85rem;text-align:center}
  table{width:100%;border-collapse:collapse;margin-top:1rem}
  th,td{text-align:left;padding:.7rem .5rem;border-bottom:1px solid #334155;font-size:.9rem}
  th{color:#94a3b8;font-weight:500;font-size:.8rem;text-transform:uppercase}
  .badge{padding:.2rem .5rem;border-radius:999px;font-size:.75rem;font-weight:600}
  .badge-on{background:#14532d;color:#86efac}
  .badge-off{background:#7f1d1d;color:#fca5a5}
  .toggle{cursor:pointer;color:#6366f1;font-weight:600;font-size:.8rem}
  .toggle:hover{color:#4f46e5}
  .link{color:#6366f1;cursor:pointer;text-decoration:none;font-weight:500}
  .link:hover{color:#4f46e5}
  .header{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem}
  .add-section{background:#1e293b;border-radius:.75rem;padding:1.5rem;margin-bottom:1.5rem;display:flex;gap:1rem;align-items:end}
  .add-section input{flex:1;margin-bottom:0}
  .add-section button{white-space:nowrap}
  a{color:#6366f1;text-decoration:none}
  .logout{font-size:.85rem;color:#64748b}
  .center{max-width:900px;margin:0 auto}
  @media(max-width:640px){.add-section{flex-direction:column;align-items:stretch}}
</style>
</head>
<body>
<div class="center">
<div class="header">
  <div><h2>avdivo VPN</h2><p class="logout">Управление устройствами</p></div>
  <form method="POST" style="margin:0"><input type="hidden" name="action" value="logout"><button class="btn-sm btn-primary" type="submit">Выйти</button></form>
</div>
__MSG__
<div class="add-section">
  <form method="POST" style="display:contents" id="create-form">
    <input type="hidden" name="action" value="create">
    <input type="text" name="name" placeholder="Имя устройства" required>
    <button class="btn-primary" type="submit">Создать</button>
  </form>
</div>
<table>
<thead><tr><th>№</th><th>Имя</th><th>IP</th><th>Дата</th><th>Статус</th><th></th><th></th></tr></thead>
<tbody>
__ROWS__
</tbody>
</table>
</div>
</body>
</html>"""

ROWS_TPL = """\
<tr>
  <td>wg{num}</td>
  <td>{name}</td>
  <td>{ip}</td>
  <td>{date}</td>
  <td>{status_badge}</td>
  <td><form method="POST" style="margin:0"><input type="hidden" name="action" value="toggle"><input type="hidden" name="name" value="{name}">{toggle_btn}</form></td>
  <td><form method="POST" style="margin:0" onsubmit="return confirm('Удалить устройство {name}?')"><input type="hidden" name="action" value="delete"><input type="hidden" name="name" value="{name}"><button class="btn-sm btn-danger" type="submit">Удалить</button></form></td>
</tr>"""


class Handler(BaseHTTPRequestHandler):
    def _cookie(self, value="", max_age=0):
        c = SimpleCookie()
        c["avdivo_vpn"] = value
        c["avdivo_vpn"]["path"] = "/"
        c["avdivo_vpn"]["max-age"] = max_age
        return c["avdivo_vpn"].OutputString()

    def _authed(self):
        raw = self.headers.get("Cookie", "")
        c = SimpleCookie()
        c.load(raw)
        return c.get("avdivo_vpn", None) and c["avdivo_vpn"].value == PASSWORD

    def _send_html(self, html, cookie_header=None):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if cookie_header:
            self.send_header("Set-Cookie", cookie_header)
        self.end_headers()
        self.wfile.write(html.encode())

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode())

    def _redirect(self, msg, err=False):
        qs = urlencode({"msg": msg, "err": "1" if err else "0"})
        self.send_response(303)
        self.send_header("Location", f"/wg?{qs}")
        self.end_headers()

    def _file_response(self, path):
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

    def _get_msg(self):
        from urllib.parse import urlparse, parse_qs as pqs
        q = pqs(urlparse(self.path).query)
        msg = q.get("msg", [None])[0]
        err = q.get("err", ["0"])[0] == "1"
        if msg:
            cls = "err" if err else "msg"
            return f'<div class="{cls}">{msg}</div>'
        return ""

    def _render_admin(self, extra_msg=""):
        devices = read_devices()
        rows = []
        for d in devices:
            status_badge = '<span class="badge badge-on">вкл</span>' if d.get("disabled") != "1" else '<span class="badge badge-off">выкл</span>'
            toggle_label = "Выкл" if d.get("disabled") != "1" else "Вкл"
            toggle_btn = f'<button class="btn-sm toggle" type="submit">{toggle_label}</button>'
            rows.append(ROWS_TPL.format(
                num=d["number"], name=d["name"], ip=d["ip"],
                date=d["date"], status_badge=status_badge, toggle_btn=toggle_btn,
            ))
        html = ADMIN_HTML.replace("__MSG__", extra_msg + self._get_msg()).replace("__ROWS__", "".join(rows))
        self._send_html(html)

    def do_GET(self):
        if self.path.startswith("/wg/download"):
            from urllib.parse import urlparse, parse_qs as pqs
            name = pqs(urlparse(self.path).query).get("name", [None])[0]
            if not name or not self._authed():
                self._redirect("Требуется вход", err=True)
                return
            devices = read_devices()
            match = [d for d in devices if d["name"] == name]
            if not match:
                self._redirect("Устройство не найдено", err=True)
                return
            path = f"{WG_DIR}/configs/wg{match[0]['number']}.conf"
            if not os.path.exists(path):
                self._redirect("Файл не найден", err=True)
                return
            self._file_response(path)
            return

        if not self._authed():
            msg = self._get_msg()
            html = LOGIN_HTML.replace("__MSG__", msg)
            self._send_html(html)
            return

        self._render_admin()

    def do_POST(self):
        if not self.path.startswith("/wg"):
            self.send_error(404)
            return

        params = self._parse_post()
        action = params.get("action", [""])[0]

        if action == "login":
            pwd = params.get("pass", [""])[0]
            if pwd == PASSWORD:
                self.send_response(303)
                self.send_header("Set-Cookie", self._cookie(PASSWORD, 86400 * 30))
                self.send_header("Location", "/wg")
                self.end_headers()
            else:
                html = LOGIN_HTML.replace("__MSG__", '<div class="error">Неверный пароль</div>')
                self._send_html(html)
            return

        if action == "logout":
            self.send_response(303)
            self.send_header("Set-Cookie", self._cookie("", 0))
            self.send_header("Location", "/wg?msg=Выход+выполнен&err=0")
            self.end_headers()
            return

        if not self._authed():
            self._redirect("Требуется вход", err=True)
            return

        if action == "create":
            self._handle_create(params)
        elif action == "toggle":
            self._handle_toggle(params)
        elif action == "delete":
            self._handle_delete(params)
        else:
            self._redirect("Неизвестное действие", err=True)

    def _handle_create(self, params):
        name = params.get("name", [""])[0].strip().replace(" ", "_")
        if not name:
            self._redirect("Введите имя устройства", err=True)
            return

        devices = read_devices()
        if any(d["name"] == name for d in devices):
            self._redirect(f"Устройство '{name}' уже существует", err=True)
            return

        try:
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

            peer_block = f"\n[Peer]\nPublicKey = {pubkey}\nAllowedIPs = {ip}/32\n"
            with open(WG_CONF, "a") as f:
                f.write(peer_block)

            peer_add(pubkey, ip)

            with open(CSV_PATH, "a") as f:
                f.write(f"{new_num:02d}|{ip}|{date.today()}|{name}|{pubkey}|0\n")

            msg = f"Устройство '{name}' создано — <a href='/wg/download?name={name}' style='color:#86efac'>скачать конфиг</a>"
            self._redirect(msg)

        except Exception as e:
            self._redirect(f"Ошибка: {e}", err=True)

    def _redirect_to(self, url):
        self.send_response(303)
        self.send_header("Location", url)
        self.end_headers()

    def _handle_toggle(self, params):
        name = params.get("name", [""])[0].strip()
        devices = read_devices()
        match = [d for d in devices if d["name"] == name]
        if not match:
            self._redirect(f"Устройство '{name}' не найдено", err=True)
            return

        d = match[0]
        new_status = "0" if d.get("disabled") == "1" else "1"

        if new_status == "1":
            peer_remove(d["pubkey"])
        else:
            peer_add(d["pubkey"], d["ip"])

        for dev in devices:
            if dev["name"] == name:
                dev["disabled"] = new_status
                break
        write_devices(devices)

        label = "выключено" if new_status == "1" else "включено"
        self._redirect(f"Устройство '{name}' {label}")

    def _handle_delete(self, params):
        name = params.get("name", [""])[0].strip()
        devices = read_devices()
        match = [d for d in devices if d["name"] == name]
        if not match:
            self._redirect(f"Устройство '{name}' не найдено", err=True)
            return

        d = match[0]
        peer_remove(d["pubkey"])

        cfg_path = f"{WG_DIR}/configs/wg{d['number']}.conf"
        if os.path.exists(cfg_path):
            os.remove(cfg_path)

        with open(WG_CONF) as f:
            content = f.read()
        content = re.sub(
            rf"\n\[Peer\]\nPublicKey = {re.escape(d['pubkey'])}\nAllowedIPs = .*",
            "", content,
        )
        content = content.strip() + "\n"
        with open(WG_CONF, "w") as f:
            f.write(content)

        devices = [x for x in devices if x["name"] != name]
        write_devices(devices)

        self._redirect(f"Устройство '{name}' удалено")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9800))
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"Listening on 127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
