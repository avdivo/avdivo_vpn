import csv
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from http.cookies import SimpleCookie
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlencode, urlparse

WG_DIR = "/etc/wireguard-config"
WG_CONF = "/etc/wireguard/wg0.conf"
TEMPLATE = "client.conf.template"
WG_IFACE = "wg0"
STATS_DB = "/var/lib/wg-stats/wg-stats.db"

# Часовой пояс пользователя (Минск, UTC+3, без перехода на летнее/зимнее).
MINSK = timezone(timedelta(hours=3))


def _minsk(ts=None):
    """Текущее время или ts в часовом поясе Минска."""
    if ts is None:
        return datetime.now(timezone.utc).astimezone(MINSK)
    return datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(MINSK)

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


# ---- Статистика (wg-stats.py, SQLite) ----

def human_bytes(n):
    """Байты -> человекочитаемый размер."""
    n = max(0, n or 0)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "Б" else f"{n:.2f} {unit}"
        n /= 1024
    return f"{n:.2f} ТБ"


def stats_window(period):
    """Возвращает (start_ts, start_day) для периода в часовом поясе Минска."""
    now = _minsk()
    if period == "today":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return start.timestamp(), start.strftime("%Y-%m-%d")
    if period == "week":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=6)
        return start.timestamp(), start.strftime("%Y-%m-%d")
    if period == "month":
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=29)
        return start.timestamp(), start.strftime("%Y-%m-%d")
    return 0.0, "2000-01-01"  # all


def stats_db():
    """Открывает БД статистики; None, если её ещё нет."""
    if not os.path.exists(STATS_DB):
        return None
    return sqlite3.connect(STATS_DB)


def _day_range(day):
    """(start_ts, end_ts) для конкретного дня (часовой пояс Минска)."""
    start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=MINSK)
    end = start + timedelta(days=1)
    return start.timestamp(), end.timestamp()


def stats_peers(period, peer, day=None):
    """Агрегат по пирам за период. Список (peer, name, rx, tx, active, reconnects)."""
    db = stats_db()
    if db is None:
        return []
    if day:
        s, e = _day_range(day)
        q = ("SELECT peer, MAX(name), SUM(rx_delta), SUM(tx_delta), SUM(online), SUM(reconnects) "
             "FROM samples WHERE ts >= ? AND ts < ?")
        args = [s, e]
    else:
        start_ts, _ = stats_window(period)
        q = ("SELECT peer, MAX(name), SUM(rx_delta), SUM(tx_delta), SUM(online), SUM(reconnects) "
             "FROM samples WHERE ts >= ?")
        args = [start_ts]
    if peer and peer != "all":
        q += " AND peer = ?"
        args.append(peer)
    q += " GROUP BY peer ORDER BY MAX(name)"
    try:
        rows = db.execute(q, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    dev = {d["pubkey"]: d["name"] for d in read_devices()}
    return [(p, dev.get(p, n or "unknown"), rx, tx, act, rec) for p, n, rx, tx, act, rec in rows]


def stats_total_intervals(period, day=None):
    """Сколько всего 5-минутных точек снято за период (для расчёта % времени)."""
    db = stats_db()
    if db is None:
        return 0
    if day:
        s, e = _day_range(day)
        try:
            return db.execute("SELECT COUNT(DISTINCT ts) FROM samples WHERE ts >= ? AND ts < ?", (s, e)).fetchone()[0]
        except sqlite3.Error:
            return 0
        finally:
            db.close()
    start_ts, _ = stats_window(period)
    try:
        return db.execute("SELECT COUNT(DISTINCT ts) FROM samples WHERE ts >= ?", (start_ts,)).fetchone()[0]
    except sqlite3.Error:
        return 0
    finally:
        db.close()


def stats_live():
    """Текущее состояние пиров: pubkey -> последний handshake (unix ts)."""
    db = stats_db()
    if db is None:
        return {}
    try:
        rows = db.execute("SELECT peer, last_handshake FROM peers").fetchall()
    except sqlite3.Error:
        return {}
    finally:
        db.close()
    return {p: h for p, h in rows}


def stats_total(period, peer, day=None):
    """Итого за период по всем выбранным пирам."""
    db = stats_db()
    if db is None:
        return (0, 0, 0, 0)
    if day:
        s, e = _day_range(day)
        q = ("SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0), "
             "COALESCE(SUM(online),0), COALESCE(SUM(reconnects),0) FROM samples WHERE ts >= ? AND ts < ?")
        args = [s, e]
    else:
        start_ts, _ = stats_window(period)
        q = ("SELECT COALESCE(SUM(rx_delta),0), COALESCE(SUM(tx_delta),0), "
             "COALESCE(SUM(online),0), COALESCE(SUM(reconnects),0) FROM samples WHERE ts >= ?")
        args = [start_ts]
    if peer and peer != "all":
        q += " AND peer = ?"
        args.append(peer)
    try:
        row = db.execute(q, args).fetchone()
    except sqlite3.Error:
        return (0, 0, 0, 0)
    finally:
        db.close()
    return tuple(row or (0, 0, 0, 0))


def stats_days(period, peer, day=None):
    """Дневные агрегаты: (day, peer, name, rx, tx, active, reconnects)."""
    db = stats_db()
    if db is None:
        return []
    if day:
        q = ("SELECT day, peer, MAX(name), SUM(rx_sum), SUM(tx_sum), SUM(active), SUM(reconnects) "
             "FROM daily WHERE day = ?")
        args = [day]
    else:
        _, start_day = stats_window(period)
        q = ("SELECT day, peer, MAX(name), SUM(rx_sum), SUM(tx_sum), SUM(active), SUM(reconnects) "
             "FROM daily WHERE day >= ?")
        args = [start_day]
    if peer and peer != "all":
        q += " AND peer = ?"
        args.append(peer)
    q += " GROUP BY day, peer ORDER BY day DESC, MAX(name)"
    try:
        rows = db.execute(q, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    dev = {d["pubkey"]: d["name"] for d in read_devices()}
    return [(day, p, dev.get(p, n or "unknown"), rx, tx, act, rec) for day, p, n, rx, tx, act, rec in rows]


def stats_points(period, peer, limit=200, day=None):
    """Детальные точки (последние limit). (time, name, rx, tx, online)."""
    db = stats_db()
    if db is None:
        return []
    # Время показываем в часовом поясе Минска (UTC+3), без секунд.
    time_expr = "strftime('%d.%m %H:%M', ts+10800, 'unixepoch')"
    if day:
        s, e = _day_range(day)
        q = (f"SELECT {time_expr}, name, rx_delta, tx_delta, online "
             "FROM samples WHERE ts >= ? AND ts < ?")
        args = [s, e]
    else:
        start_ts, _ = stats_window(period)
        q = (f"SELECT {time_expr}, name, rx_delta, tx_delta, online "
             "FROM samples WHERE ts >= ?")
        args = [start_ts]
    if peer and peer != "all":
        q += " AND peer = ?"
        args.append(peer)
    q += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    try:
        rows = db.execute(q, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    return rows


def stats_peer_options():
    """Варианты пиров для фильтра: (peer, name)."""
    db = stats_db()
    if db is None:
        return []
    try:
        rows = db.execute("SELECT DISTINCT peer, MAX(name) FROM samples GROUP BY peer ORDER BY MAX(name)").fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    dev = {d["pubkey"]: d["name"] for d in read_devices()}
    return [(p, dev.get(p, n or "unknown")) for p, n in rows]


def stats_http(period, day=None):
    """HTTP-запросы к сайтам за период: (host, requests, wg_requests)."""
    db = stats_db()
    if db is None:
        return []
    if day:
        q = ("SELECT host, SUM(requests), SUM(wg_requests) FROM http_daily "
             "WHERE day = ? GROUP BY host ORDER BY SUM(requests) DESC")
        args = [day]
    else:
        _, start_day = stats_window(period)
        q = ("SELECT host, SUM(requests), SUM(wg_requests) FROM http_daily "
             "WHERE day >= ? GROUP BY host ORDER BY SUM(requests) DESC")
        args = [start_day]
    try:
        rows = db.execute(q, args).fetchall()
    except sqlite3.Error:
        return []
    finally:
        db.close()
    return rows


def stats_series(period, peer, day=None):
    """Динамика за период: ('min'|'hour'|'day', [(label, rx, tx, online, rec), ...]).
    - конкретный день: по часам;
    - сегодня: каждые 5 минут;
    - 7/30/всё дней: по дням.
    Время всегда в часовом поясе Минска (UTC+3)."""
    db = stats_db()
    if db is None:
        return "day", []
    if day:
        s, e = _day_range(day)
        q = ("SELECT strftime('%H:00', ts+10800, 'unixepoch'), SUM(rx_delta), SUM(tx_delta), "
             "SUM(online), SUM(reconnects) FROM samples WHERE ts >= ? AND ts < ?")
        args = [s, e]
        kind = "hour"
    elif period == "today":
        start_ts, _ = stats_window(period)
        q = ("SELECT ts, rx_delta, tx_delta, online, reconnects FROM samples WHERE ts >= ?")
        args = [start_ts]
        kind = "min"
    else:
        start_ts, _ = stats_window(period)
        q = ("SELECT strftime('%d.%m', ts+10800, 'unixepoch'), SUM(rx_delta), SUM(tx_delta), "
             "SUM(online), SUM(reconnects) FROM samples WHERE ts >= ?")
        args = [start_ts]
        kind = "day"
    if peer and peer != "all":
        q += " AND peer = ?"
        args.append(peer)
    q += " GROUP BY 1 ORDER BY 1"
    try:
        rows = db.execute(q, args).fetchall()
    except sqlite3.Error:
        return kind, []
    finally:
        db.close()
    if kind == "min":
        # Для точек по 5 минут label = HH:MM в Минске.
        rows = [(datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(MINSK).strftime("%H:%M"),
                 rx, tx, online, rec) for (ts, rx, tx, online, rec) in rows]
    return kind, rows


def svg_bars(title, labels, values, color):
    """Простая SVG-гистограмма без внешних библиотек."""
    if not values:
        return ""
    n = len(values)
    if n == 0:
        return ""
    max_val = max(values) or 1
    pad = 8
    bw = max(2, min(48, (680 - pad * 2) // n))
    inner = n * bw
    width = max(680, inner + pad * 2)
    h, top, gap = 80, 10, 12
    plot = h - top - gap
    bars = []
    for i, v in enumerate(values):
        x = pad + i * bw
        bh = round((v / max_val) * plot)
        if 0 < v and bh < 1:
            bh = 1
        y = top + plot - bh
        bars.append(f'<rect x="{x}" y="{y}" width="{max(1, bw - 1)}" height="{bh}" rx="1" fill="{color}"/>')
    step = max(1, n // 10)
    lab = "".join(
        f'<text x="{pad + i * bw + bw / 2}" y="{h - 2}" font-size="9" fill="#64748b" text-anchor="middle">{labels[i]}</text>'
        for i in range(0, n, step)
    )
    return (
        f'<div class="chart-box">'
        f'<div class="chart-title">{title}</div>'
        f'<svg viewBox="0 0 {width} {h}" width="100%">{bars}{lab}</svg></div>'
    )


def svg_lines(title, labels, series, colors):
    """SVG-линейный график. series=[(name, [values])]."""
    if not labels or not series:
        return ""
    n = len(labels)
    if n == 0:
        return ""
    pad = 8
    width = 680
    h, top, gap = 150, 14, 20
    plot_h = h - top - gap
    all_vals = [v for _, vals in series for v in vals]
    max_val = max(all_vals) if all_vals else 1
    max_val = max(1, max_val)

    def x(i):
        return pad + (i * (width - pad * 2) // (n - 1)) if n > 1 else width // 2

    def y(v):
        return top + round(plot_h - (v / max_val) * plot_h)

    paths = []
    for (_, vals), color in zip(series, colors):
        d = "M" + " ".join(f"{x(i)},{y(v)}" for i, v in enumerate(vals))
        paths.append(f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>')
        for i, v in enumerate(vals):
            if v > 0:
                paths.append(f'<circle cx="{x(i)}" cy="{y(v)}" r="1.5" fill="{color}"/>')

    step = max(1, n // 10)
    lab = "".join(
        f'<text x="{x(i)}" y="{h - 3}" font-size="9" fill="#64748b" text-anchor="middle">{labels[i]}</text>'
        for i in range(0, n, step)
    )
    legend = "".join(
        f'<span style="display:inline-flex;align-items:center;gap:.35rem;margin-right:1rem;font-size:.8rem;color:#94a3b8">'
        f'<span style="width:10px;height:3px;border-radius:2px;background:{color}"></span>{name}</span>'
        for (name, _), color in zip(series, colors)
    )
    return (
        f'<div class="chart-box">'
        f'<div class="chart-title">{title}</div>'
        f'<svg viewBox="0 0 {width} {h}" width="100%">{paths}{lab}</svg>'
        f'<div style="margin-top:.35rem">{legend}</div></div>'
    )


LOGIN_HTML = """\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>avdivo VPN</title>
<link rel="icon" type="image/png" href="/wg/favicon.png">
<link rel="apple-touch-icon" href="/wg/apple-touch-icon.png">
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
<link rel="icon" type="image/png" href="/wg/favicon.png">
<link rel="apple-touch-icon" href="/wg/apple-touch-icon.png">
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
  .nav{display:flex;gap:1.25rem;margin-top:.6rem}
  .nav a{color:#94a3b8;font-size:.9rem;font-weight:500;padding-bottom:.2rem}
  .nav a:hover{color:#e2e8f0}
  .nav a.active{color:#6366f1;border-bottom:2px solid #6366f1}
  .logout{font-size:.85rem;color:#64748b}
  .center{max-width:900px;margin:0 auto}
  @media(max-width:640px){.add-section{flex-direction:column;align-items:stretch}}
</style>
</head>
<body>
<div class="center">
<div class="header">
  <div><h2>avdivo VPN</h2><p class="logout">Управление устройствами</p>
    <nav class="nav">
      <a href="/wg" class="active">Устройства</a>
      <a href="/wg/stats">Статистика</a>
    </nav>
  </div>
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
<thead><tr><th>№</th><th>Имя</th><th>IP</th><th>Дата</th><th>Статус</th><th>Файл</th><th></th><th></th></tr></thead>
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
  <td><a class="link" href="/wg/download?name={name}">Скачать</a></td>
  <td><form method="POST" style="margin:0"><input type="hidden" name="action" value="toggle"><input type="hidden" name="name" value="{name}">{toggle_btn}</form></td>
  <td><form method="POST" style="margin:0" onsubmit="return confirm('Удалить устройство {name}?')"><input type="hidden" name="action" value="delete"><input type="hidden" name="name" value="{name}"><button class="btn-sm btn-danger" type="submit">Удалить</button></form></td>
</tr>"""

STATS_HTML = """\
<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>avdivo VPN — статистика</title>
<link rel="icon" type="image/png" href="/wg/favicon.png">
<link rel="apple-touch-icon" href="/wg/apple-touch-icon.png">
<style>
  *,*::before,*::after{box-sizing:border-box}
  body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:2rem 1rem}
  h2{margin:0 0 .25rem;font-size:1.5rem;font-weight:600}
  p{color:#94a3b8;margin:0 0 1.5rem;font-size:.9rem}
  .header{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:1.5rem}
  .nav{display:flex;gap:1.25rem;margin-top:.6rem}
  .nav a{color:#94a3b8;font-size:.9rem;font-weight:500;padding-bottom:.2rem;text-decoration:none}
  .nav a:hover{color:#e2e8f0}
  .nav a.active{color:#6366f1;border-bottom:2px solid #6366f1}
  .logout{font-size:.85rem;color:#64748b}
  .btn-primary{background:#6366f1;color:#fff;border:none;border-radius:.5rem;padding:.6rem 1.2rem;font-size:.9rem;font-weight:600;cursor:pointer}
  .btn-primary:hover{background:#4f46e5}
  .btn-sm{padding:.4rem .8rem;font-size:.8rem}
  select{width:100%;padding:.6rem .8rem;border:1px solid #334155;border-radius:.5rem;background:#0f172a;color:#e2e8f0;font-size:.9rem;outline:none;cursor:pointer;transition:border-color .15s}
  select:focus{border-color:#6366f1}
  .link{color:#818cf8;text-decoration:none;font-weight:500;transition:color .15s}
  .link:hover{color:#a5b4fc}
  .crumbs{color:#94a3b8;font-size:.95rem;margin-bottom:.75rem}
  .charts{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem}
  .filters{background:#1e293b;border-radius:.75rem;padding:1.25rem;margin-bottom:1.5rem;display:grid;grid-template-columns:1fr 1fr 1fr;gap:1rem;align-items:end}
  .filters label{display:block;font-size:.8rem;font-weight:500;margin-bottom:.35rem;color:#cbd5e1}
  .cards{display:grid;grid-template-columns:repeat(2,1fr);gap:.75rem;margin-bottom:1rem}
  @media(max-width:360px){.cards{grid-template-columns:1fr}}
  .card{background:#1e293b;border-radius:.75rem;padding:.75rem 1rem}
  .card .k{font-size:.7rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.03em}
  .card .v{font-size:1.1rem;font-weight:600;margin-top:.25rem;color:#86efac}
  .chart-box{background:#1e293b;border-radius:.75rem;padding:.75rem 1rem .5rem;margin-bottom:1rem}
  .chart-title{font-size:.85rem;color:#cbd5e1;margin-bottom:.35rem}
  table{width:100%;border-collapse:collapse;margin-top:1rem;background:#1e293b;border-radius:.75rem;overflow:hidden}
  th,td{text-align:left;padding:.7rem .9rem;border-bottom:1px solid #334155;font-size:.9rem}
  th{color:#94a3b8;font-weight:500;font-size:.8rem;text-transform:uppercase;background:#1e293b}
  tr:last-child td{border-bottom:none}
  .muted{color:#64748b;font-size:.85rem}
  .badge-on{background:#14532d;color:#86efac}
  .badge-off{background:#1e3a8a;color:#93c5fd}
  .badge-dead{background:#334155;color:#94a3b8}
  .badge{padding:.15rem .5rem;border-radius:999px;font-size:.75rem;font-weight:600}
  .empty{background:#1e293b;border-radius:.75rem;padding:2rem;text-align:center;color:#94a3b8}
  .center{max-width:900px;margin:0 auto}
  .note{color:#64748b;font-size:.8rem;margin-top:.75rem}
  @media(max-width:700px){.filters{grid-template-columns:1fr}.cards{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<div class="center">
<div class="header">
  <div><h2>avdivo VPN</h2><p class="logout">Статистика по устройствам</p>
    <nav class="nav">
      <a href="/wg">Устройства</a>
      <a href="/wg/stats" class="active">Статистика</a>
    </nav>
  </div>
  <form method="POST" action="/wg" style="margin:0"><input type="hidden" name="action" value="logout"><button class="btn-primary btn-sm" type="submit">Выйти</button></form>
</div>
__CARDS__
<form method="GET" action="/wg/stats">
<div class="filters">
  <div>
    <label>Период</label>
    <select name="period" onchange="this.form.submit()">__PERIOD_OPTS__</select>
  </div>
  <div>
    <label>Устройство</label>
    <select name="peer" onchange="this.form.submit()">__PEER_OPTS__</select>
  </div>
  <div>
    <label>Вид отчёта</label>
    <select name="view" onchange="this.form.submit()">__VIEW_OPTS__</select>
  </div>
</div>
</form>
<div id="charts">__CHARTS__</div>
__TABLE__
__HTTP__
__NOTE__
</div>
</body>
</html>"""

CARD_TPL = """\
<div class="card">
  <div class="k">{key}</div>
  <div class="v">{value}</div>
</div>"""


class Handler(BaseHTTPRequestHandler):
    def _cookie(self, value="", max_age=0):
        c = SimpleCookie()
        c["avdivo_vpn"] = value
        c["avdivo_vpn"]["path"] = "/"
        c["avdivo_vpn"]["max-age"] = max_age
        if max_age == 0:
            c["avdivo_vpn"]["expires"] = "Thu, 01 Jan 1970 00:00:00 GMT"
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

    def _render_stats(self):
        q = parse_qs(urlparse(self.path).query)
        period = q.get("period", ["today"])[0]
        peer = q.get("peer", ["all"])[0]
        view = q.get("view", ["peers"])[0]
        day = q.get("day", [None])[0]
        if period not in ("today", "week", "month", "all"):
            period = "today"
        if view not in ("peers", "days", "points"):
            view = "peers"

        period_names = {"today": "Сегодня", "week": "7 дней", "month": "30 дней", "all": "Всё время"}
        view_names = {"peers": "По устройствам", "days": "По дням", "points": "Детально (точки)"}

        def opts(current, items):
            return "".join(
                f'<option value="{k}"{" selected" if k == current else ""}>{v}</option>'
                for k, v in items
            )

        def stat_url(**overrides):
            params = {"period": period, "peer": peer, "view": view}
            params.update(overrides)
            return "/wg/stats?" + urlencode(params)

        peer_opts = [("all", "Все устройства")] + [(p, n) for p, n in stats_peer_options()]
        peer_names = dict(peer_opts)

        html = STATS_HTML
        html = html.replace("__PERIOD_OPTS__", opts(period, period_names.items()))
        html = html.replace("__VIEW_OPTS__", opts(view, view_names.items()))
        html = html.replace("__PEER_OPTS__", opts(peer, peer_opts))

        cards = ""
        table = ""
        note = ""
        http_section = ""
        charts = ""

        # Хлебные крошки: Все устройства › Имя › день
        bread = ['<a class="link" href="/wg/stats?period=' + period + '&view=peers">Все устройства</a>']
        if peer != "all":
            bread.append(f'<a class="link" href="{stat_url(peer="all", view="peers")}">{peer_names.get(peer, peer)}</a>')
        if day:
            bread.append(f'<span>{day[8:]}.{day[5:7]}.{day[:4]}</span>')
        bread_html = '<div class="crumbs">' + ' <span style="color:#334155">›</span> '.join(bread) + '</div>'

        rx, tx, active, rec = stats_total(period, peer, day)
        cards = (
            CARD_TPL.format(key="Скачано всего", value=human_bytes(tx)) +
            CARD_TPL.format(key="Отдано всего", value=human_bytes(rx)) +
            CARD_TPL.format(key="Активных интервалов", value=f"{active}") +
            CARD_TPL.format(key="Переподключений", value=f"{rec}")
        )

        now = datetime.now().timestamp()
        live = stats_live()

        def status_html(peer_key):
            h = live.get(peer_key)
            if not h:
                return '<span class="muted">—</span>'
            diff = now - h
            if diff <= 180:
                return '<span class="badge badge-on">онлайн</span>'
            if diff < 3600:
                return f'<span class="muted">оффлайн · {int(diff // 60)} мин назад</span>'
            if diff < 86400:
                return f'<span class="muted">оффлайн · {int(diff // 3600)} ч назад</span>'
            return f'<span class="muted">оффлайн · {int(diff // 86400)} дн назад</span>'

        if view == "peers":
            rows = stats_peers(period, peer, day)
            total_intervals = stats_total_intervals(period, day)
            if rows:
                head = ('<tr><th>Устройство</th><th>Скачал</th><th>Отдал</th>'
                        '<th>Активность</th><th>Переподключ.</th><th>Статус</th></tr>')
                body_parts = []
                for pkey, name, rx, tx, act, rec in rows:
                    dead = (rx + tx) == 0 and act == 0
                    dead_tag = ' <span class="badge badge-dead">нет трафика</span>' if dead else ""
                    pct = f" ({act * 100 // total_intervals}%)" if total_intervals else ""
                    cell_style = ' style="opacity:.55"' if dead else ""
                    body_parts.append(
                        f'<tr{cell_style}><td>'
                        f'<a class="link" href="{stat_url(peer=pkey, view="points")}">{name}</a>{dead_tag}</td>'
                        f'<td>{human_bytes(tx)}</td><td>{human_bytes(rx)}</td>'
                        f'<td title="Из {total_intervals} интервалов по 5 минут">{act}{pct}</td>'
                        f'<td>{rec}</td><td>{status_html(pkey)}</td></tr>'
                    )
                table = bread_html + f"<table>{head}{''.join(body_parts)}</table>"
                note = '<div class="note">Клик по устройству — подробные подключения за каждые 5 минут.</div>'
            else:
                table = '<div class="empty">Нет данных за выбранный период.</div>'
        elif view == "days":
            rows = stats_days(period, peer, day)
            if rows:
                head = ('<tr><th>День</th><th>Устройство</th><th>Скачал</th><th>Отдал</th>'
                        '<th>Активность</th><th>Переподключ.</th></tr>')
                body_parts = []
                for d, pkey, name, rx, tx, act, rec in rows:
                    d_show = f"{d[8:]}.{d[5:7]}.{d[:4]}"
                    day_link = f'<a class="link" href="{stat_url(peer=pkey, view="points", day=d)}">{d_show}</a>'
                    dev_cell = name
                    if peer == "all":
                        dev_cell = f'<a class="link" href="{stat_url(peer=pkey, view="points")}">{name}</a>'
                    body_parts.append(
                        f'<tr><td>{day_link}</td><td>{dev_cell}</td>'
                        f'<td>{human_bytes(tx)}</td><td>{human_bytes(rx)}</td>'
                        f'<td>{act}</td><td>{rec}</td></tr>'
                    )
                table = bread_html + f"<table>{head}{''.join(body_parts)}</table>"
                note = '<div class="note">Клик по дню — детальные точки за этот день.</div>'
            else:
                table = '<div class="empty">Нет данных за выбранный период.</div>'
        else:
            # «Детально»: сегодня или конкретный день — точки по 5 минут,
            # длинные периоды (7/30 дней, всё время) — сводка по дням.
            if day or period == "today":
                rows = stats_points(period, peer, day=day)
                if rows:
                    head = '<tr><th>Время</th><th>Устройство</th><th>Скачал</th><th>Отдал</th><th>Статус</th></tr>'
                    body = "".join(
                        f'<tr><td class="muted">{t}</td><td>{name}</td><td>{human_bytes(tx)}</td>'
                        f'<td>{human_bytes(rx)}</td><td><span class="badge {"badge-on" if on else "badge-off"}">'
                        f'{"активен" if on else "в сети"}</span></td></tr>'
                        for t, name, rx, tx, on in rows
                    )
                    table = bread_html + f"<table>{head}{body}</table>"
                    day_note = f" за {day[8:]}.{day[5:7]}.{day[:4]}" if day else ""
                    note = f'<div class="note">Точки (каждая — 5 минут){day_note}. Показаны последние 200.</div>'
                else:
                    table = '<div class="empty">Нет данных за выбранный период.</div>'
            else:
                rows = stats_days(period, peer)
                if rows:
                    head = ('<tr><th>День</th><th>Устройство</th><th>Скачал</th><th>Отдал</th>'
                            '<th>Активность</th><th>Переподключ.</th></tr>')
                    body_parts = []
                    for d, pkey, name, rx, tx, act, rec in rows:
                        d_show = f"{d[8:]}.{d[5:7]}.{d[:4]}"
                        day_link = f'<a class="link" href="{stat_url(peer=pkey, view="points", day=d)}">{d_show}</a>'
                        body_parts.append(
                            f'<tr><td>{day_link}</td><td>{name}</td>'
                            f'<td>{human_bytes(tx)}</td><td>{human_bytes(rx)}</td>'
                            f'<td>{act}</td><td>{rec}</td></tr>'
                        )
                    table = bread_html + f"<table>{head}{''.join(body_parts)}</table>"
                    note = '<div class="note">Длительный период — сводка по дням. Клик по дню — точки за этот день.</div>'
                else:
                    table = '<div class="empty">Нет данных за выбранный период.</div>'

        if view in ("peers", "points"):
            kind, series = stats_series(period, peer, day)
            if series:
                labels = [s[0] for s in series]
                tx_mb = [round(s[2] / 1048576, 1) for s in series]
                rx_mb = [round(s[1] / 1048576, 1) for s in series]
                charts = svg_lines(
                    'Трафик, МБ (скачал/отдал)', labels,
                    [('Скачал', tx_mb), ('Отдал', rx_mb)], ['#34d399', '#818cf8'],
                )

        html = html.replace("__CARDS__", cards).replace("__CHARTS__", charts)
        html = html.replace("__TABLE__", table).replace("__NOTE__", note)

        http_rows = stats_http(period, day)
        if http_rows:
            total = sum(r[1] for r in http_rows)
            wg_total = sum(r[2] for r in http_rows)
            http_cards = (
                CARD_TPL.format(key="HTTP-запросов всего", value=f"{total}") +
                CARD_TPL.format(key="К админке VPN (/wg)", value=f"{wg_total}")
            )
            rows_html = "".join(
                f'<tr><td>{host}</td><td>{r}</td><td>{w}</td></tr>'
                for host, r, w in http_rows
            )
            http_section = (
                '<h3 style="margin:2rem 0 .5rem;font-size:1.05rem;color:#e2e8f0">'
                'Запросы к сайтам на сервере (Caddy)</h3>' +
                f'<div class="cards">{http_cards}</div>' +
                '<table><tr><th>Домен</th><th>Запросов</th><th>К админке VPN (/wg)</th></tr>' +
                rows_html + '</table>' +
                '<div class="note">Это количество HTTP-запросов к нашим сайтам '
                '(vpn/espocrm/landing и т.д.), а не трафик VPN-пользователей — '
                'он идёт мимо Caddy.</div>'
            )

        html = html.replace("__HTTP__", http_section)
        self._send_html(html)

    def do_GET(self):
        if self.path.startswith("/wg/favicon") or self.path.startswith("/wg/apple-touch-icon"):
            fname = os.path.basename(self.path)
            path = os.path.join(WG_DIR, fname)
            if os.path.exists(path):
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.end_headers()
                with open(path, "rb") as f:
                    self.wfile.write(f.read())
                return
            self.send_error(404)
            return

        if self.path.startswith("/wg/stats"):
            if not self._authed():
                self._redirect("Требуется вход", err=True)
                return
            self._render_stats()
            return

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
            qs = urlencode({"msg": "Выход выполнен", "err": "0"})
            self.send_header("Location", f"/wg?{qs}")
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
