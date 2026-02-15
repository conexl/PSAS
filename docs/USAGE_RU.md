# PSAS: краткая инструкция (RU)

## Установка

```bash
curl -fsSL https://raw.githubusercontent.com/conexl/PSAS/main/install/psas-install.sh -o psas-install.sh
chmod +x psas-install.sh
sudo ./psas-install.sh
```

## Минимальный рабочий цикл

1. Войти в админ-панель по URL из итогового вывода скрипта.
2. Создать пользователя:

```bash
hiddify-sub add --name user01 --days 30 --gb 300 --mode no_reset
hiddify-sub edit user01 --subscription-name "User01 iPhone"
```

3. Взять ссылку `/auto/` и импортировать в Hiddify.

## Частые команды

```bash
# Проверка статуса
psasctl status
psasctl status --json

# Админ-ссылка
psasctl admin-url
psasctl ui

# Пользователи
psasctl users list
psasctl users list --enabled
psasctl users find ivan
psasctl users add --name ivan --days 30 --gb 300 --mode no_reset
psasctl users add --subscription-name "Ivan iPhone" --days 30 --gb 300 --mode no_reset
psasctl users add --name ivan --unlimited --mode no_reset
psasctl users add --name ivan --true-unlimited --mode no_reset
psasctl users add --name ivan --unlimited-gb --unlimited-days --mode no_reset
psasctl users edit ivan --days 60 --gb 500 --mode monthly
psasctl users edit ivan --subscription-name "Ivan Main" --true-unlimited-gb
psasctl users show <USER_ID>
psasctl users links <USER_ID>
psasctl users del <USER_ID>

# Конфиг
psasctl config get hysteria_enable
psasctl config set hysteria_enable true
psasctl protocols list
psasctl protocols enable hysteria2
psasctl protocols disable --apply tuic vmess

# Применить безопасно
psasctl apply
# или
hiddify-apply-safe <your-domain>

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
```

Примечание:
- `--subscription-name` и `--name` для пользователя эквивалентны (в Hiddify это одно поле).
- Для настоящего безлимита используйте `--true-unlimited*`: первый запуск автоматически патчит Hiddify и перезапускает сервисы.
- При установке SOCKS5 через `psas-install.sh` автоматически настраивается UDP relay range (`20000-50000`) и правило UFW для звонков через SOCKS5.

## Примечание по UUID

`USER_ID` в командах `show/links/del` может быть:
- UUID формата:

`6098ea35-8cb2-4a08-ba15-2be25bc49cb6`

- или имя пользователя (точное/частичное совпадение).

## Интерактивный режим

`psasctl ui` (или `psasctl menu`) запускает меню в терминале:
- clean-screen интерфейс (экран очищается при смене шага),
- выбор пунктов стрелками `↑/↓` (или `j/k`) и `Enter`,
- быстрый выбор по номеру (`1-9`) и hotkeys пунктов,
- есть `Flag command wizard`: пошаговая сборка стандартных команд (`status/users/config/apply/trust/socks`) с запуском через тот же `psasctl`, чтобы сохранить исходную обработку флагов,
- есть отдельный раздел `TrustTunnel` для управления пользователями и сервисом,
- есть отдельный раздел `SOCKS5 (Dante)` для управления логинами SOCKS5 и сервисом danted,
- в операциях `Show/Delete` есть стрелочный выбор пользователя с фильтром по вводу и ручным вводом `USER_ID`,
- в `Add user` режим (`no_reset|daily|weekly|monthly`) выбирается стрелками, есть опции безлимита по трафику и/или времени,
- для операций с параметрами утилита запросит нужные поля по шагам,
- просмотр статуса и URL админки,
- список/поиск пользователей,
- создание и удаление пользователей,
- применение конфигов.

При этом все обычные команды с флагами остаются доступными.
