#!/usr/bin/env python3
# Сбор статистики WireGuard по пирам (устройствам VPN).
#
# Работает по cron раз в 5 минут: снимает показания wg show (трафик и время
# последнего handshake), сопоставляет публичные ключи с именами из devices.csv,
# считает дельты за интервал и пишет точки в SQLite.
#
# База: /var/lib/wg-stats/wg-stats.db
#   samples — детальные точки (хранятся 30 дней, потом удаляются автоматически)
#   peers   — текущие счётчики пиров (для расчёта дельт между запусками)
#   daily   — дневные агрегаты (хранятся вечно, крошечные: ~5 строк в день)
#
# Нагрузка на сервер — нулевая: один лёгкий процесс раз в 5 минут.

import os
import sqlite3
import subprocess
from datetime import datetime

DB = '/var/lib/wg-stats/wg-stats.db'
DEVICES_CSV = '/etc/wireguard-config/devices.csv'
# Детальные точки (каждые 5 минут) храним несколько дней — за это время видно
# кто как работает сегодня и вчера; дальше их место занимают дневные агрегаты
# (таблица daily живёт вечно и хранит сутки целиком).
RETENTION_DAYS = 3


def run(*args):
    """Выполнить команду и вернуть stdout."""
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def load_devices():
    """Читает devices.csv: pubkey -> (number, name, ip, disabled)."""
    devices = {}
    try:
        with open(DEVICES_CSV, encoding='utf-8') as f:
            f.readline()  # шапка
            for line in f:
                parts = line.rstrip('\n').split('|')
                if len(parts) >= 6:
                    number, ip, date, name, pubkey, disabled = parts[:6]
                    devices[pubkey] = (number, name, ip, disabled)
    except OSError:
        pass
    return devices


def parse_transfer(text):
    """Разбирает 'wg show wg0 transfer': pubkey -> (rx, tx) байт."""
    out = {}
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) == 3:
            out[parts[0]] = (int(parts[1]), int(parts[2]))
    return out


def parse_handshakes(text):
    """Разбирает 'wg show wg0 latest-handshakes': pubkey -> unix ts."""
    out = {}
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) == 2:
            out[parts[0]] = int(parts[1])
    return out


def main():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    db = sqlite3.connect(DB)
    db.execute('CREATE TABLE IF NOT EXISTS samples('
               'ts INTEGER NOT NULL, peer TEXT NOT NULL, name TEXT, '
               'rx_delta INTEGER, tx_delta INTEGER, online INTEGER, '
               'handshake_ts INTEGER, reconnects INTEGER)')
    db.execute('CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts)')
    db.execute('CREATE TABLE IF NOT EXISTS peers('
               'peer TEXT PRIMARY KEY, rx INTEGER, tx INTEGER, last_handshake INTEGER)')
    db.execute('CREATE TABLE IF NOT EXISTS daily('
               'day TEXT NOT NULL, peer TEXT NOT NULL, name TEXT, '
               'rx_sum INTEGER, tx_sum INTEGER, active INTEGER, reconnects INTEGER, '
               'PRIMARY KEY(day, peer))')

    now = int(datetime.now().timestamp())
    day = datetime.now().strftime('%Y-%m-%d')

    devices = load_devices()
    transfer = parse_transfer(run('wg', 'show', 'wg0', 'transfer'))
    handshakes = parse_handshakes(run('wg', 'show', 'wg0', 'latest-handshakes'))
    prev = {row[0]: row for row in db.execute('SELECT peer, rx, tx, last_handshake FROM peers')}

    for pubkey, (rx, tx) in transfer.items():
        number, name, ip, disabled = devices.get(pubkey, ('', 'unknown', '', ''))
        hand = handshakes.get(pubkey, 0)

        if pubkey in prev:
            prx, ptx, phand = prev[pubkey][1], prev[pubkey][2], prev[pubkey][3]
            # max(0, ...) защищает от сброса счётчиков (перезапуск wg0)
            rx_d = max(0, rx - prx)
            tx_d = max(0, tx - ptx)
            online = 1 if (hand and hand != phand) or rx_d or tx_d else 0
            reconnects = 1 if phand and hand > phand else 0
        else:
            # Первый запуск (или после перезапуска wg0): прошлый handshake
            # неизвестен, поэтому активность за интервал не засчитываем,
            # а счётчики просто запоминаем как базу для следующих дельт.
            rx_d = tx_d = 0
            online = 0
            reconnects = 0

        db.execute('INSERT INTO samples(ts, peer, name, rx_delta, tx_delta, online, handshake_ts, reconnects) '
                   'VALUES(?,?,?,?,?,?,?,?)',
                   (now, pubkey, name, rx_d, tx_d, online, hand, reconnects))
        db.execute('INSERT INTO peers(peer, rx, tx, last_handshake) VALUES(?,?,?,?) '
                   'ON CONFLICT(peer) DO UPDATE SET rx=?, tx=?, last_handshake=?',
                   (pubkey, rx, tx, hand, rx, tx, hand))
        db.execute('INSERT INTO daily(day, peer, name, rx_sum, tx_sum, active, reconnects) '
                   'VALUES(?,?,?,?,?,?,?) ON CONFLICT(day, peer) DO UPDATE SET '
                   'rx_sum = rx_sum + ?, tx_sum = tx_sum + ?, '
                   'active = active + ?, reconnects = reconnects + ?',
                   (day, pubkey, name, rx_d, tx_d, online, reconnects,
                    rx_d, tx_d, online, reconnects))

    # Автоочистка: детальные точки старше RETENTION_DAYS больше не нужны
    cutoff = now - RETENTION_DAYS * 86400
    db.execute('DELETE FROM samples WHERE ts < ?', (cutoff,))

    db.commit()
    db.close()


if __name__ == '__main__':
    main()