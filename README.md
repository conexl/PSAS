# PSAS

PSAS (Personal Secure Auto Setup) — набор инструментов для быстрой настройки VPS под **Hiddify Manager** с безопасным базовым профилем.

Что входит:
- `install/psas-install.sh` — интерактивный авто-установщик и hardening.
- `hiddify-sub` (устанавливается скриптом) — простой CLI для пользователей/подписок.
- `hiddify-apply-safe` (устанавливается скриптом) — безопасное применение конфигов с финальной синхронизацией LE-сертификата.
- `cmd/psasctl` — Go CLI для управления Hiddify.

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
  - `/usr/local/sbin/sync-hiddify-cert.sh`
- Настраивает cron на синхронизацию LE-сертификата в Hiddify:
  - `/etc/cron.d/sync-hiddify-cert`

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
hiddify-sub show <USER_UUID>
hiddify-sub del <USER_UUID>
```

`add` сразу печатает ссылки:
- `/auto/` — рекомендуемый импорт в Hiddify,
- `/sub64/`, `/sub/`, `/singbox/`.

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
psasctl users add --name test --json

# USER_ID = UUID или имя пользователя
psasctl users links <USER_ID>
psasctl users show <USER_ID>
psasctl users del <USER_ID>
# пример по имени:
psasctl users links user01

psasctl config get reality_enable
psasctl config set vmess_enable false

psasctl apply
```

Можно использовать короткий алиас:

```bash
psasctl u list
```

Интерактивный режим:
- `psasctl ui` (или `psasctl menu`) открывает текстовое меню в терминале.
- Все флаговые команды продолжают работать как раньше.

Переменные окружения:
- `PSAS_PANEL_CFG` (default `/opt/hiddify-manager/hiddify-panel/app.cfg`)
- `PSAS_PANEL_ADDR` (default `http://127.0.0.1:9000`)
- `PSAS_PANEL_PY` (default auto detect)

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
