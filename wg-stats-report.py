#!/usr/bin/env python3
# Отчёт по статистике WireGuard за период.
#
# Использование:
#   python3 wg-stats-report.py today|week|month|all
#   python3 wg-stats-report.py YYYY-MM-DD [YYYY-MM-DD]
#
# Выводит по каждому устройству:
#   - трафик за период (скачано/отдано);
#   - активные интервалы — сколько раз за период устройство было онлайн
#     (передавало данные или делало handshake);
#   - переподключения — сколько раз сменился handshake (новое подключение).
#
# WireGuard измеряет байты и время handshake, а не «запросы»: активные
# интервалы и переподключения — это и есть доступная метрика «обращений».

import sqlite3
import sys
from datetime import datetime, timedelta

DB = '/var/lib/wg-stats/wg-stats.db'


def human(n):
    """Байты -> человекочитаемый размер."""
    for unit in ('Б', 'КБ', 'МБ', 'ГБ'):
        if n < 1024:
            return f'{n:.0f} {unit}' if unit == 'Б' else f'{n:.2f} {unit}'
        n /= 1024
    return f'{n:.2f} ТБ'


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    arg = sys.argv[1]
    if arg == 'today':
        start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        label = 'сегодня'
    elif arg == 'week':
        start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=6)
        label = 'за 7 дней'
    elif arg == 'month':
        start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=29)
        label = 'за 30 дней'
    elif arg == 'all':
        start = datetime(2000, 1, 1)
        label = 'за всё время'
    elif len(arg) == 10 and arg[4] == '-' and arg[7] == '-':
        start = datetime.strptime(arg, '%Y-%m-%d')
        label = f'с {arg}'
        if len(sys.argv) > 2:
            end = datetime.strptime(sys.argv[2], '%Y-%m-%d') + timedelta(days=1)
        else:
            end = start + timedelta(days=1)
        return report(start.timestamp(), end.timestamp(), label)
    else:
        print(__doc__)
        sys.exit(1)

    return report(start.timestamp(), None, label)


def report(start_ts, end_ts, label):
    db = sqlite3.connect(DB)
    if end_ts is None:
        rows = db.execute(
            'SELECT name, peer, SUM(rx_delta), SUM(tx_delta), SUM(online), SUM(reconnects) '
            'FROM samples WHERE ts >= ? GROUP BY peer ORDER BY name', (start_ts,)).fetchall()
    else:
        rows = db.execute(
            'SELECT name, peer, SUM(rx_delta), SUM(tx_delta), SUM(online), SUM(reconnects) '
            'FROM samples WHERE ts >= ? AND ts < ? GROUP BY peer ORDER BY name',
            (start_ts, end_ts)).fetchall()
    db.close()

    if not rows:
        print(f'Данных нет ({label}). Сбор ещё не запускался или период вне диапазона.')
        return

    print(f'Статистика WireGuard — {label}\n')
    print(f'{"Устройство":<14}{"Скачано":>12}{"Отдано":>12}{"Активных":>10}{"Подключ.":>10}')
    print('-' * 58)
    for name, peer, rx, tx, active, reconnects in rows:
        print(f'{name or "unknown":<14}{human(rx or 0):>12}{human(tx or 0):>12}'
              f'{(active or 0):>10}{(reconnects or 0):>10}')


if __name__ == '__main__':
    main()