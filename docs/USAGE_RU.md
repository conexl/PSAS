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
```

3. Взять ссылку `/auto/` и импортировать в Hiddify.

## Частые команды

```bash
# Проверка статуса
psasctl status

# Админ-ссылка
psasctl admin-url

# Пользователи
psasctl users list
psasctl users show <UUID>
psasctl users links <UUID>
psasctl users del <UUID>

# Конфиг
psasctl config get hysteria_enable
psasctl config set hysteria_enable true

# Применить безопасно
psasctl apply
# или
hiddify-apply-safe <your-domain>
```

## Примечание по UUID

Команды `show/links/del` принимают именно UUID формата:

`6098ea35-8cb2-4a08-ba15-2be25bc49cb6`

а не имя пользователя.
