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
- Быстрый выбор: клавиши `1-9` и hotkeys у пунктов меню.
- Пункт `Flag command wizard` пошагово собирает стандартные команды (`status/users/config/apply`) и запускает их через тот же CLI, сохраняя оригинальную обработку флагов.
- В `Show user`/`Delete user` есть picker пользователей: стрелки, фильтр набором текста, `Backspace`, ручной ввод по `i`.
- В `Add user` режим тарифа (`no_reset|daily|weekly|monthly`) выбирается стрелками, есть опции безлимита по трафику и/или времени.
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
