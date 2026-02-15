# PSAS

PSAS (Personal Secure Auto Setup) — набор инструментов для быстрой настройки VPS под **Hiddify Manager** с безопасным базовым профилем.

Что входит:
- `install/psas-install.sh` — интерактивный авто-установщик и hardening.
- `hiddify-sub` (устанавливается скриптом) — простой CLI для пользователей/подписок.
- `hiddify-apply-safe` (устанавливается скриптом) — безопасное применение конфигов с финальной синхронизацией LE-сертификата.
- `socks5-sub` (устанавливается скриптом) — thin-wrapper для `psasctl socks`.
- `trusttunnel-sub` (устанавливается скриптом) — thin-wrapper для `psasctl trust`.
- `mtproxy-sub` (устанавливается скриптом) — thin-wrapper для `psasctl mtproxy`.
- `cmd/psasctl` — Go CLI для управления Hiddify, SOCKS5 (Dante), TrustTunnel и Telegram MTProxy.

## 1) Быстрый старт

```bash
curl -fsSL https://raw.githubusercontent.com/conexl/PSAS/main/install/psas-install.sh -o psas-install.sh
chmod +x psas-install.sh
sudo ./psas-install.sh
```

Скрипт запросит:
- основной домен (например `vpn.example.com`),
- SNI для Reality (по умолчанию `www.cloudflare.com`),
- логин/пароль админа,
- базовые порты Hysteria2/Reality,
- опциональную ротацию admin path/secret,
- очистку legacy-сервисов.

## 2) Что делает installer

- Ставит/проверяет Hiddify (`https://i.hiddify.com/release`).
- Настраивает профиль протоколов:
  - включает `VLESS + Reality`, `Hysteria2`,
  - отключает лишние протоколы для снижения поверхности атаки.
- Оставляет домены:
  - основной `direct` домен,
  - `special_reality_tcp` домен для Reality SNI.
- Включает hardening:
  - UFW (22/tcp, 80/tcp, 443/tcp, 443/udp, Hysteria2 UDP),
  - fail2ban (`sshd`, `recidive`),
  - сетевые `sysctl`.
- Устанавливает вспомогательные команды:
  - `/usr/local/bin/hiddify-sub`
  - `/usr/local/bin/hiddify-apply-safe`
  - `/usr/local/bin/socks5-sub`
  - `/usr/local/bin/trusttunnel-sub`
  - `/usr/local/sbin/sync-hiddify-cert.sh`
- Настраивает cron на синхронизацию LE-сертификата в Hiddify:
  - `/etc/cron.d/sync-hiddify-cert`
- Опционально устанавливает и настраивает Dante SOCKS5 (`danted`) с логином/паролем и хранением пользователей в `/etc/psas/socks-users.json`, включая `udp.portrange` (по умолчанию `20000-50000`) для звонков и соответствующее правило UFW.
- Опционально устанавливает и настраивает TrustTunnel (`/opt/trusttunnel`) на отдельном порту (по умолчанию `8443`) с отдельными пользователями.
- Опционально устанавливает и настраивает Telegram MTProxy (`/opt/MTProxy`) с systemd-сервисом `mtproxy` и конфигом `/etc/psas/mtproxy.json`.

## 3) Админ-панель

После установки скрипт выводит:
- URL панели,
- admin UUID,
- username/password.

В форме входа, где требуется UUID:
- **Секретный код (UUID)**: admin UUID,
- **Пароль**: ваш пароль.

## 4) Управление пользователями (через `hiddify-sub`)

```bash
hiddify-sub list
hiddify-sub add --name user01 --days 30 --gb 300 --mode no_reset
hiddify-sub add --name user01 --true-unlimited --mode no_reset
hiddify-sub edit user01 --subscription-name "User01 iPhone"
hiddify-sub show <USER_ID>
hiddify-sub del <USER_ID>
hiddify-sub protocols list
hiddify-sub protocols enable hysteria2
```

`add` сразу печатает ссылки:
- `/auto/` — рекомендуемый импорт в Hiddify,
- `/sub64/`, `/sub/`, `/singbox/`.

Примечания:
- `USER_ID` может быть UUID или имя (точное/частичное совпадение).
- Флаги `--subscription-name` и `--name` эквивалентны (название профиля подписки пользователя).
- `--true-unlimited*` включает настоящий безлимит (автоматический patch Hiddify + restart сервисов при первом запуске).

## 5) Go CLI (`psasctl`)

Сборка:

```bash
go build -o psasctl ./cmd/psasctl
sudo install -m 0755 psasctl /usr/local/bin/psasctl
```

Команды:

```bash
psasctl status
psasctl status --json
psasctl admin-url
psasctl ui

psasctl users list
psasctl users list --enabled
psasctl users find user01
psasctl users add --name test --days 30 --gb 100 --mode no_reset
psasctl users add --subscription-name "Office iPhone" --days 30 --gb 100 --mode no_reset
psasctl users add --name test --unlimited --mode no_reset
psasctl users add --name test --true-unlimited --mode no_reset
psasctl users add --name test --unlimited-gb --unlimited-days --mode no_reset
psasctl users add --name test --json
psasctl users edit user01 --days 60 --gb 500 --mode monthly
psasctl users edit user01 --subscription-name "User01 Main" --true-unlimited-gb

# USER_ID = UUID или имя пользователя
psasctl users links <USER_ID>
psasctl users show <USER_ID>
psasctl users del <USER_ID>
# пример по имени:
psasctl users links user01

psasctl config get reality_enable
psasctl config set vmess_enable false
psasctl protocols list
psasctl protocols enable hysteria2
psasctl protocols disable --apply tuic vmess

psasctl apply

# TrustTunnel
psasctl trust status
psasctl trust users list
psasctl trust users add --name tt-user01 --show-config
psasctl trust users show tt-user01 --show-config
psasctl trust users edit tt-user01 --password 'newStrongPass'
psasctl trust users del tt-user01
psasctl trust users config tt-user01 --out /root/tt-user01.toml
psasctl trust service restart
psasctl trust ui

# SOCKS5 (Dante)
psasctl socks status
psasctl socks users list
psasctl socks users add --name socks01 --show-config --server vpn.example.com
psasctl socks users show --show-config --server vpn.example.com socks01
psasctl socks users edit socks01 --password 'newStrongPass'
psasctl socks users del socks01
psasctl socks users config --server vpn.example.com socks01
psasctl socks service restart
psasctl socks ui

# Telegram MTProxy
psasctl mtproxy status
psasctl mtproxy config
psasctl mtproxy secret show
psasctl mtproxy secret set <HEX32>
psasctl mtproxy secret regen
psasctl mtproxy service restart
psasctl mtproxy ui
```

Примечания:
- Флаги `--subscription-name` и `--name` для пользователя эквивалентны (в Hiddify это один и тот же профильный title).
- Для настоящего безлимита используйте `--true-unlimited*`: первый запуск автоматически патчит Hiddify и перезапускает сервисы.

Можно использовать короткий алиас:

```bash
psasctl u list
```

Интерактивный режим:
- `psasctl ui` (или `psasctl menu`) открывает clean-screen меню в терминале.
- Навигация: `↑/↓` (или `j/k`), выбор `Enter`, выход `q`.
- Быстрый выбор: введите номер пункта и нажмите `Enter`, либо используйте hotkey у пункта меню.
- Пункт `Flag command wizard` пошагово собирает стандартные команды (`status/users/config/apply/trust/socks/mtproxy`) и запускает их через тот же CLI, сохраняя оригинальную обработку флагов.
- Для TrustTunnel добавлен отдельный пункт `TrustTunnel` (status/list/add/edit/show/delete/service).
- Для SOCKS5 добавлен отдельный пункт `SOCKS5 (Dante)` (status/list/add/edit/show/delete/service).
- Для Telegram MTProxy добавлен отдельный пункт `Telegram MTProxy` (status/config/secret/service).
- В `Show user`/`Delete user` есть picker пользователей: стрелки, фильтр набором текста, `Backspace`, ручной ввод по `i`.
- В `Add user` режим тарифа (`no_reset|daily|weekly|monthly`) выбирается стрелками, есть опции безлимита по трафику и/или времени.
- Все флаговые команды продолжают работать как раньше.

Переменные окружения:
- `PSAS_PANEL_CFG` (default `/opt/hiddify-manager/hiddify-panel/app.cfg`)
- `PSAS_PANEL_ADDR` (default `http://127.0.0.1:9000`)
- `PSAS_PANEL_PY` (default auto detect)
- `PSAS_SOCKS_SERVICE` (default `danted`)
- `PSAS_SOCKS_CONF` (default `/etc/danted.conf`)
- `PSAS_SOCKS_USERS` (default `/etc/psas/socks-users.json`)
- `PSAS_SOCKS_HOST` (override host in generated SOCKS config)
- `PSAS_MTPROXY_DIR` (default `/opt/MTProxy`)
- `PSAS_MTPROXY_SERVICE` (default `mtproxy`)
- `PSAS_MTPROXY_CONF` (default `/etc/psas/mtproxy.json`)
- `PSAS_MTPROXY_HOST` (override host in generated MTProxy config/links)

## 6) Безопасное применение конфигов

После ручных изменений в панели/CLI используйте:

```bash
sudo hiddify-apply-safe <your-domain>
```

Это применит конфиги и затем синхронизирует LE-сертификат в Hiddify SSL-хранилище.

## 7) Важно

- Скрипт **не меняет `sshd_config`**.
- До запуска убедитесь, что A-запись домена указывает на VPS.
- На новой VPS лучше запускать installer в чистой системе.
