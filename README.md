# avdivo_vpn

Auto-provision WireGuard configs через веб-форму.

## Быстрый старт

```bash
# 1. Клонировать на сервер
git clone https://github.com/avdivo/avdivo_vpn.git /etc/wireguard-config
cd /etc/wireguard-config

# 2. Создать .env из примера
cp .env.example .env
# Заполнить WG_PASSWORD

# 3. Установить сервис
cp avdivo-vpn.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now avdivo-vpn

# 4. Добавить DNS-запись vpn.alexlenaai.com → 46.8.112.244

# 5. Добавить роут в Caddyfile
```

## Переменные (.env)

| Переменная | Описание |
|-----------|----------|
| `WG_PASSWORD` | Пароль для доступа к генератору |
| `PORT` | Порт сервера (по умолчанию 9800) |

## Роут для Caddyfile

```caddy
vpn.alexlenaai.com {
    handle /wg/* {
        reverse_proxy 127.0.0.1:9800
    }
    handle {
        respond "VPN config generator" 200
    }
}
```

## Структура проекта

```
├── server.py              # HTTP-сервер
├── wg-stats.py            # Сбор статистики по пирам (cron, раз в 5 минут)
├── wg-stats-report.py     # Отчёт по статистике за период
├── client.conf.template   # Шаблон конфига
├── avdivo-vpn.service     # systemd unit
├── .env.example           # Шаблон переменных
├── .gitignore
└── README.md
```

## Статистика по устройствам

WireGuard сам не хранит историю трафика (только текущие счётчики). Сбор
ведётся скриптом `wg-stats.py` по cron и складывается в SQLite
`/var/lib/wg-stats/wg-stats.db`:

- **samples** — точки каждые 5 минут (трафик за интервал, активность,
  переподключения); хранятся 30 дней, удаляются автоматически;
- **peers** — текущие счётчики пиров (для расчёта дельт);
- **daily** — дневные агрегаты (хранятся вечно, ~5 строк в день).

Нагрузка на сервер нулевая (лёгкий процесс раз в 5 минут, БД маленькая).

### Установка сбора

```bash
# в /etc/cron.d/wg-stats:
*/5 * * * * root /usr/bin/python3 /etc/wireguard-config/wg-stats.py >> /var/log/wg-stats.log 2>&1
systemctl restart cron
```

### Отчёт

В админке (https://vpn.alexlenaai.com/wg) появилась вкладка **Статистика** —
`/wg/stats`. Фильтры (период/устройство/вид) обновляются сразу при выборе,
без кнопки. Карточки «итого» видны всегда.

- **Графики** — по выбранному периоду: скачал/отдал (МБ), переподключения,
  активность. Для «сегодня» — по часам, для длинных периодов — по дням.
  Показываются и по всем устройствам, и по конкретному.
- **По устройствам** — суммарная информация по каждому устройству за период.
  Клик по устройству — подробные подключения за каждые 5 минут.
- **По дням** — дневные агрегаты (клик по дню — точки за этот день).
- **Детально (точки)** — последние 200 точек по 5 минут.

Детальные точки хранятся 3 дня (потом стираются), дневные агрегаты — вечно.

Ниже таблиц — секция **«Запросы к сайтам на сервере (Caddy)»**: HTTP-запросы
к нашим доменам (общее и по доменам, отдельно к `/wg`), собирает `caddy-stats.py`
из access-логов Caddy (ротация 5×10MiB). Это запросы к сайтам на сервере,
а не трафик VPN-пользователей (он идёт мимо Caddy).

Из консоли (то же самое):

```bash
python3 /etc/wireguard-config/wg-stats-report.py today   # за сегодня
python3 /etc/wireguard-config/wg-stats-report.py week    # за 7 дней
python3 /etc/wireguard-config/wg-stats-report.py month   # за 30 дней
python3 /etc/wireguard-config/wg-stats-report.py all     # за всё время
python3 /etc/wireguard-config/wg-stats-report.py 2026-08-01 2026-08-15  # произвольный период
```

Показывает по каждому устройству: скачано/отдано, активные интервалы (когда
устройство передавало данные или подключалось) и переподключения (смены
handshake). WireGuard измеряет байты и handshake, а не «запросы» — активность
и переподключения и есть метрика «обращений» по пиру.
