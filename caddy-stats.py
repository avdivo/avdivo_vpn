#!/usr/bin/env python3
# Сбор статистики HTTP-запросов из access-логов Caddy.
#
# По cron (раз в 5 минут) читает /var/log/caddy/access.log, берёт новые
# записи (после cursor из БД), агрегирует по дням и доменам и пишет в ту же
# SQLite-базу, что и wg-stats.py: /var/lib/wg-stats/wg-stats.db
#   http_daily(day, host, requests, wg_requests) — дневные суммы по доменам
#   meta(cursor) — последний обработанный ts (чтобы не перечитывать файл)
#
# Это запросы к сайтам на сервере (vpn/espocrm/landing и т.д.), а не трафик
# VPN-пиров. Нагрузка минимальная: файл ~до 50 МБ (ротация Caddy 5x10MiB).

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

LOG = '/var/log/caddy/access.log'
MINSK = timezone(timedelta(hours=3))
DB = '/var/lib/wg-stats/wg-stats.db'


def main():
    if not os.path.exists(LOG):
        return

    db = sqlite3.connect(DB)
    db.execute('CREATE TABLE IF NOT EXISTS http_daily('
               'day TEXT NOT NULL, host TEXT NOT NULL, '
               'requests INTEGER NOT NULL, wg_requests INTEGER NOT NULL DEFAULT 0, '
               'PRIMARY KEY(day, host))')
    db.execute('CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)')
    row = db.execute("SELECT value FROM meta WHERE key='caddy_cursor'").fetchone()
    cursor = float(row[0]) if row else 0.0

    seen_max = cursor
    counts = {}   # (day, host) -> [requests, wg_requests]

    with open(LOG, errors='ignore') as f:
        for line in f:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if 'http.log.access' not in d.get('logger', ''):
                continue
            ts = float(d.get('ts', 0))
            if ts <= cursor:
                continue
            seen_max = max(seen_max, ts)
            req = d.get('request', {})
            host = (req.get('host') or 'unknown').lower()
            uri = req.get('uri', '') or ''
            day = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone(MINSK).strftime('%Y-%m-%d')
            c = counts.setdefault((day, host), [0, 0])
            c[0] += 1
            if uri.startswith('/wg'):
                c[1] += 1

    for (day, host), (requests, wg) in counts.items():
        db.execute('INSERT INTO http_daily(day, host, requests, wg_requests) VALUES(?,?,?,?) '
                   'ON CONFLICT(day, host) DO UPDATE SET '
                   'requests = requests + ?, wg_requests = wg_requests + ?',
                   (day, host, requests, wg, requests, wg))

    db.execute("INSERT INTO meta(key, value) VALUES('caddy_cursor', ?) "
               'ON CONFLICT(key) DO UPDATE SET value = ?', (str(seen_max), str(seen_max)))
    db.commit()
    db.close()


if __name__ == '__main__':
    main()