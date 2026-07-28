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
├── client.conf.template   # Шаблон конфига
├── avdivo-vpn.service     # systemd unit
├── .env.example           # Шаблон переменных
├── .gitignore
└── README.md
```
