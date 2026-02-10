package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode"
)

const (
	defaultPanelCfg            = "/opt/hiddify-manager/hiddify-panel/app.cfg"
	defaultPanelAddr           = "http://127.0.0.1:9000"
	defaultTrustDir            = "/opt/trusttunnel"
	defaultTrustService        = "trusttunnel"
	defaultTrustEndpoint       = "trusttunnel_endpoint"
	defaultMTProxyDir          = "/opt/MTProxy"
	defaultMTProxyBin          = "mtproto-proxy"
	defaultMTProxyService      = "mtproxy"
	defaultMTProxyConfig       = "/etc/psas/mtproxy.json"
	defaultMTProxyPort         = 2443
	defaultMTProxyInternalPort = 8888
	defaultSocksService        = "danted"
	defaultSocksConfig         = "/etc/danted.conf"
	defaultSocksUsers          = "/etc/psas/socks-users.json"
	defaultSocksPort           = 1080
	defaultUILang              = "us"
	uiLangUS                   = "us"
	uiLangRU                   = "ru"
	unlimitedPackageDays       = 10000
	unlimitedUsageGB           = 1000000.0
)

type state struct {
	APIPath   string                    `json:"api_path"`
	APIKey    string                    `json:"api_key"`
	AdminPath string                    `json:"admin_path"`
	Domains   []domain                  `json:"domains"`
	Users     []apiUser                 `json:"users"`
	Chconfigs map[string]map[string]any `json:"chconfigs"`
}

type domain struct {
	Domain                string `json:"domain"`
	Mode                  string `json:"mode"`
	InternalPortHysteria2 int    `json:"internal_port_hysteria2"`
	InternalPortSpecial   int    `json:"internal_port_special"`
}

type apiUser struct {
	UUID         string  `json:"uuid"`
	Name         string  `json:"name"`
	Enable       bool    `json:"enable"`
	UsageLimitGB float64 `json:"usage_limit_GB"`
	PackageDays  int     `json:"package_days"`
	Mode         string  `json:"mode"`
}

type linkSet struct {
	UUID    string `json:"uuid"`
	Host    string `json:"host"`
	Panel   string `json:"panel"`
	Auto    string `json:"auto"`
	Sub64   string `json:"sub64"`
	Sub     string `json:"sub"`
	Singbox string `json:"singbox"`
}

type client struct {
	panelCfg  string
	panelAddr string
	panelPy   string
	state     state
}

type trustClient struct {
	dir               string
	service           string
	lastExportAddress string
}

type trustUser struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type trustStatus struct {
	Installed     bool   `json:"installed"`
	Service       string `json:"service"`
	ServiceActive bool   `json:"service_active"`
	Directory     string `json:"directory"`
	ListenAddress string `json:"listen_address,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	Users         int    `json:"users"`
}

type mtproxyClient struct {
	dir     string
	service string
	config  string
}

type mtproxyConfig struct {
	Server       string `json:"server"`
	Port         int    `json:"port"`
	Secret       string `json:"secret"`
	InternalPort int    `json:"internal_port,omitempty"`
}

type mtproxyStatus struct {
	Installed     bool   `json:"installed"`
	Service       string `json:"service"`
	ServiceActive bool   `json:"service_active"`
	Directory     string `json:"directory"`
	ConfigPath    string `json:"config_path"`
	Server        string `json:"server,omitempty"`
	ListenPort    int    `json:"listen_port,omitempty"`
	InternalPort  int    `json:"internal_port,omitempty"`
	SecretMasked  string `json:"secret_masked,omitempty"`
}

type mtproxyConnInfo struct {
	Server       string `json:"server"`
	Port         int    `json:"port"`
	Secret       string `json:"secret"`
	SecretMasked string `json:"secret_masked"`
	TGLink       string `json:"tg_link"`
	ShareURL     string `json:"share_url"`
}

type socksClient struct {
	service string
	config  string
	users   string
}

type socksUser struct {
	Name       string `json:"name"`
	Password   string `json:"password"`
	SystemUser string `json:"system_user,omitempty"`
}

type socksStatus struct {
	Installed     bool   `json:"installed"`
	Service       string `json:"service"`
	ServiceActive bool   `json:"service_active"`
	ConfigPath    string `json:"config_path"`
	ListenAddress string `json:"listen_address,omitempty"`
	Users         int    `json:"users"`
}

type socksConnInfo struct {
	Server   string `json:"server"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	URI      string `json:"uri"`
}

type uiSettings struct {
	Lang string `json:"lang"`
}

type protocolSetting struct {
	Name    string
	Key     string
	Aliases []string
}

var protocolSettings = []protocolSetting{
	{Name: "hysteria2", Key: "hysteria_enable", Aliases: []string{"hysteria", "histeria", "histeria2", "hy2"}},
	{Name: "hysteria2-obfs", Key: "hysteria_obfs_enable", Aliases: []string{"hysteria-obfs", "hy2-obfs"}},
	{Name: "reality", Key: "reality_enable", Aliases: []string{}},
	{Name: "vless", Key: "vless_enable", Aliases: []string{}},
	{Name: "trojan", Key: "trojan_enable", Aliases: []string{}},
	{Name: "vmess", Key: "vmess_enable", Aliases: []string{}},
	{Name: "tuic", Key: "tuic_enable", Aliases: []string{}},
	{Name: "wireguard", Key: "wireguard_enable", Aliases: []string{"wg"}},
	{Name: "shadowtls", Key: "shadowtls_enable", Aliases: []string{}},
	{Name: "shadowsocks2022", Key: "shadowsocks2022_enable", Aliases: []string{"ss2022"}},
	{Name: "ssh", Key: "ssh_server_enable", Aliases: []string{}},
	{Name: "http-proxy", Key: "http_proxy_enable", Aliases: []string{"httpproxy"}},
	{Name: "v2ray", Key: "v2ray_enable", Aliases: []string{}},
	{Name: "ws", Key: "ws_enable", Aliases: []string{"websocket"}},
	{Name: "grpc", Key: "grpc_enable", Aliases: []string{}},
	{Name: "httpupgrade", Key: "httpupgrade_enable", Aliases: []string{"http-upgrade"}},
	{Name: "xhttp", Key: "xhttp_enable", Aliases: []string{}},
	{Name: "tcp", Key: "tcp_enable", Aliases: []string{}},
	{Name: "quic", Key: "quic_enable", Aliases: []string{}},
}

var uuidRe = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var mtproxySecretRe = regexp.MustCompile(`^[A-Fa-f0-9]{32}$`)
var trustUserRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
var socksUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
var dantedInternalRe = regexp.MustCompile(`(?i)^internal:\s*([^\s]+)(?:\s+port\s*=\s*([0-9]{1,5}))?\s*$`)
var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var errUISelectionCanceled = errors.New("selection canceled")
var errUIExitRequested = errors.New("exit requested")
var errUIManualEntry = errors.New("manual entry requested")
var currentUILang = defaultUILang
var uiTextRU = map[string]string{
	"Language":                   "Язык",
	"Language set to: %s":        "Язык установлен: %s",
	"Current language: %s":       "Текущий язык: %s",
	"Supported: us, ru":          "Поддерживается: us, ru",
	"PSASCTL - Interactive Menu": "PSASCTL - Интерактивное меню",
	"Controls: Up/Down or j/k to navigate, Enter to select, q to quit": "Управление: Up/Down или j/k, Enter выбрать, q выйти",
	"Quick select: Type number and press Enter, or use shortcut key":   "Быстрый выбор: введите номер и нажмите Enter, или используйте горячую клавишу",
	"Controls: Up/Down or j/k, Enter to select, q to cancel":           "Управление: Up/Down или j/k, Enter выбрать, q отмена",
	"Selected number": "Выбранный номер",
	"Sections: Hiddify Manager / Proxy Services / Tools / Preferences": "Разделы: Hiddify Manager / Proxy сервисы / Инструменты / Настройки",
	"Hiddify Manager": "Hiddify Manager",
	"Proxy Services":  "Proxy сервисы",
	"Tools":           "Инструменты",
	"Preferences":     "Настройки",
	"Session":         "Сессия",
	"Press Enter to return to menu (q to exit)...": "Нажмите Enter для возврата в меню (q для выхода)...",
	"Select command to build":                      "Выберите команду для сборки",
	"Run this command?":                            "Запустить эту команду?",
	"Canceled.":                                    "Отменено.",
	"ERROR":                                        "ОШИБКА",
	"Exit":                                         "Выход",
	"Back":                                         "Назад",
	"Status":                                       "Статус",
	"List users":                                   "Список пользователей",
	"Find users":                                   "Поиск пользователей",
	"Show user + links":                            "Пользователь + ссылки",
	"Add user":                                     "Добавить пользователя",
	"Edit user":                                    "Изменить пользователя",
	"Delete user":                                  "Удалить пользователя",
	"Protocols":                                    "Протоколы",
	"Admin URL":                                    "Ссылка админки",
	"Apply config":                                 "Применить конфиг",
	"Flag command wizard":                          "Мастер флаговых команд",
	"SOCKS5 (Dante)":                               "SOCKS5 (Dante)",
	"TrustTunnel":                                  "TrustTunnel",
	"Telegram MTProxy":                             "Telegram MTProxy",
	"Main domain, admin URL, protocols, users count":                    "Основной домен, админ URL, протоколы, количество пользователей",
	"Print all users in a table":                                        "Показать всех пользователей в таблице",
	"Search users by name/part and optional enabled filter":             "Поиск пользователей по имени/части и фильтру enabled",
	"Pick a user with arrows and print links":                           "Выберите пользователя стрелками и покажите ссылки",
	"Step-by-step wizard for creating a user":                           "Пошаговый мастер создания пользователя",
	"Pick a user and edit name/limits/mode/enabled state":               "Выберите пользователя и измените имя/лимиты/режим/статус",
	"Pick a user and delete with confirmation":                          "Выберите пользователя и удалите с подтверждением",
	"Manage SOCKS users and danted service":                             "Управление SOCKS-пользователями и сервисом danted",
	"Manage TrustTunnel users and service":                              "Управление пользователями TrustTunnel и сервисом",
	"Manage Telegram MTProxy service and secret":                        "Управление сервисом и секретом Telegram MTProxy",
	"List and toggle protocol enable flags":                             "Список и переключение флагов протоколов",
	"Print panel admin URL":                                             "Показать URL админ-панели",
	"Run hiddify-apply-safe or panel apply":                             "Запустить hiddify-apply-safe или panel apply",
	"Build and run existing psasctl commands with their original flags": "Собрать и запустить существующие команды psasctl с исходными флагами",
	"Leave interactive mode":                                            "Выйти из интерактивного режима",
	"Language and UI preferences":                                       "Язык и параметры интерфейса",
	"\nEnter option number (1-%d)":                                      "\nВведите номер пункта (1-%d)",
	"\nEnter option number":                                             "\nВведите номер пункта",
	"Invalid. Enter 1-%d or q":                                          "Неверно. Введите 1-%d или q",
	"Invalid. Enter 0-%d or q":                                          "Неверно. Введите 0-%d или q",
	"Value is required.":                                                "Значение обязательно.",
	"No users match current filter":                                     "Нет пользователей по текущему фильтру",
	"Filter: %s":                                                        "Фильтр: %s",
	"Showing: %d / %d users":                                            "Показано: %d / %d пользователей",
	"(Showing %d-%d of %d)":                                             "(Показано %d-%d из %d)",
	"Controls: Up/Down to navigate, Enter to select, Type to filter":    "Управление: Up/Down для выбора, Enter подтвердить, печатайте для фильтра",
	"          Backspace to erase, i for manual input, q to cancel":     "          Backspace удалить, i для ручного ввода, q отмена",
	"  0. Manual USER_ID input":                                         "  0. Ручной ввод USER_ID",
	"  q. Cancel":                                                       "  q. Отмена",
	"  q. Exit":                                                         "  q. Выход",
	"Enter user number":                                                 "Введите номер пользователя",
	"Use --json output?":                                                "Использовать --json вывод?",
	"Command":                                                           "Команда",
	"Invalid value: %v":                                                 "Неверное значение: %v",
	"SOCKS5 status":                                                     "Статус SOCKS5",
	"SOCKS users":                                                       "SOCKS пользователи",
	"SOCKS service":                                                     "Сервис SOCKS",
	"TrustTunnel status":                                                "Статус TrustTunnel",
	"TrustTunnel users":                                                 "Пользователи TrustTunnel",
	"MTProxy status":                                                    "Статус MTProxy",
	"MTProxy config":                                                    "Конфиг MTProxy",
	"MTProxy service":                                                   "Сервис MTProxy",
	"System Status":                                                     "Системный статус",
	"SOCKS5 config":                                                     "Конфиг SOCKS5",
	"SOCKS User":                                                        "SOCKS пользователь",
	"TrustTunnel User":                                                  "Пользователь TrustTunnel",
	"status":                                                            "статус",
	"start":                                                             "запуск",
	"stop":                                                              "остановка",
	"restart":                                                           "перезапуск",
	"back":                                                              "назад",
	"TrustTunnel installed":                                             "TrustTunnel установлен",
	"SOCKS installed":                                                   "SOCKS установлен",
	"Service":                                                           "Сервис",
	"Directory":                                                         "Каталог",
	"Config":                                                            "Конфиг",
	"Listen":                                                            "Слушает",
	"Hostname":                                                          "Хостнейм",
	"Users":                                                             "Пользователи",
	"Main domain":                                                       "Основной домен",
	"Client path":                                                       "Путь клиента",
	"Reality enabled":                                                   "Reality включен",
	"Hysteria2 enabled":                                                 "Hysteria2 включен",
	"Hysteria base port":                                                "Базовый порт Hysteria",
	"Reality SNI":                                                       "Reality SNI",
	"TrustTunnel active":                                                "TrustTunnel активен",
	"TrustTunnel listen":                                                "TrustTunnel слушает",
	"MTProxy installed":                                                 "MTProxy установлен",
	"MTProxy active":                                                    "MTProxy активен",
	"MTProxy endpoint":                                                  "Точка MTProxy",
	"SOCKS active":                                                      "SOCKS активен",
	"SOCKS listen":                                                      "SOCKS слушает",
	"No users found.":                                                   "Пользователи не найдены.",
	"User created successfully!":                                        "Пользователь успешно создан!",
	"USERNAME":                                                          "ПОЛЬЗОВАТЕЛЬ",
	"PASSWORD":                                                          "ПАРОЛЬ",
	"LOGIN":                                                             "ЛОГИН",
	"Server":                                                            "Сервер",
	"Port":                                                              "Порт",
	"Internal port":                                                     "Внутренний порт",
	"Login":                                                             "Логин",
	"Password":                                                          "Пароль",
	"Secret":                                                            "Секрет",
	"Secret masked":                                                     "Секрет (маска)",
	"tg:// link":                                                        "tg:// ссылка",
	"Share URL":                                                         "Ссылка для шаринга",
	"Username":                                                          "Имя пользователя",
	"Service control":                                                   "Управление сервисом",
	"Status / users / links / settings":                                 "Статус / пользователи / ссылки / настройки",
	"Show SOCKS service/config summary":                                 "Показать статус SOCKS сервиса и конфига",
	"Show SOCKS logins and masked passwords":                            "Показать SOCKS логины и скрытые пароли",
	"Create SOCKS login and set Linux password":                         "Создать SOCKS логин и установить Linux пароль",
	"Rename login and/or change password":                               "Переименовать логин и/или сменить пароль",
	"Show login/password and optional connect params":   "Показать логин/пароль и опциональные параметры подключения",
	"Remove SOCKS login and Linux user":                 "Удалить SOCKS логин и Linux пользователя",
	"status/start/stop/restart danted":                  "status/start/stop/restart danted",
	"Return to SOCKS menu":                              "Вернуться в меню SOCKS",
	"SOCKS login":                                       "SOCKS логин",
	"SOCKS user added: %s":                              "SOCKS пользователь добавлен: %s",
	"Print connection config now?":                      "Показать конфиг подключения сейчас?",
	"Server host/ip (empty = auto detect)":              "Сервер host/ip (пусто = автоопределение)",
	"Port (empty = from danted config)":                 "Порт (пусто = из конфига danted)",
	"invalid port: %s":                                  "неверный порт: %s",
	"Select SOCKS user to edit":                         "Выберите SOCKS пользователя для изменения",
	"selected user not found: %s":                       "выбранный пользователь не найден: %s",
	"New login (empty = keep: %s)":                      "Новый логин (пусто = оставить: %s)",
	"socks user already exists: %s":                     "socks пользователь уже существует: %s",
	"linux user already exists: %s":                     "linux пользователь уже существует: %s",
	"New password (empty = keep current)":               "Новый пароль (пусто = оставить текущий)",
	"No changes requested.":                             "Изменений не запрошено.",
	"SOCKS user updated: %s -> %s":                      "SOCKS пользователь обновлен: %s -> %s",
	"Select SOCKS user":                                 "Выберите SOCKS пользователя",
	"Print connection config?":                          "Показать конфиг подключения?",
	"Select SOCKS user to delete":                       "Выберите SOCKS пользователя для удаления",
	"Delete SOCKS user %s?":                             "Удалить SOCKS пользователя %s?",
	"Deleted SOCKS user: %s":                            "SOCKS пользователь удален: %s",
	"Show systemctl status":                             "Показать статус systemctl",
	"Start service":                                     "Запустить сервис",
	"Stop service":                                      "Остановить сервис",
	"Restart service":                                   "Перезапустить сервис",
	"SOCKS service %s: %s":                              "SOCKS сервис %s: %s",
	"unknown socks action: %s":                          "неизвестное действие socks: %s",
	"Show TrustTunnel service/config summary":           "Показать статус сервиса и конфига TrustTunnel",
	"Show users from credentials.toml":                  "Показать пользователей из credentials.toml",
	"Create TrustTunnel user and restart service":       "Создать пользователя TrustTunnel и перезапустить сервис",
	"Rename user and/or change password":                "Переименовать пользователя и/или сменить пароль",
	"Show username/password and optional client config": "Показать логин/пароль и опциональный клиентский конфиг",
	"Remove user and restart service":                   "Удалить пользователя и перезапустить сервис",
	"status/start/stop/restart trusttunnel":             "status/start/stop/restart trusttunnel",
	"Trust username":                                    "Логин Trust",
	"trust user already exists: %s":                     "trust пользователь уже существует: %s",
	"TrustTunnel user added: %s":                        "Пользователь TrustTunnel добавлен: %s",
	"Generate client config now?":                       "Сгенерировать клиентский конфиг сейчас?",
	"Address ip[:port] (empty = auto detect)":           "Адрес ip[:port] (пусто = автоопределение)",
	"Auto address detection failed: %v":                 "Автоопределение адреса не удалось: %v",
	"Address ip[:port] (manual)":                        "Адрес ip[:port] (вручную)",
	"Address: %s":                                       "Адрес: %s",
	"Select TrustTunnel user to edit":                   "Выберите пользователя TrustTunnel для изменения",
	"New username (empty = keep: %s)":                   "Новый логин (пусто = оставить: %s)",
	"TrustTunnel user updated: %s":                      "Пользователь TrustTunnel обновлен: %s",
	"Select TrustTunnel user":                           "Выберите пользователя TrustTunnel",
	"Generate client config?":                           "Сгенерировать клиентский конфиг?",
	"Select TrustTunnel user to delete":                 "Выберите пользователя TrustTunnel для удаления",
	"Delete trust user %s?":                             "Удалить пользователя TrustTunnel %s?",
	"Confirm delete?":                                   "Подтвердить удаление?",
	"Deleted trust user: %s":                            "Trust пользователь удален: %s",
	"TrustTunnel service":                               "Сервис TrustTunnel",
	"Return to TrustTunnel menu":                        "Вернуться в меню TrustTunnel",
	"TrustTunnel service %s: %s":                        "Сервис TrustTunnel %s: %s",
	"unknown trust action: %s":                          "неизвестное действие trust: %s",
	"unknown action: %s":                                "неизвестное действие: %s",
	"Warning: %s":                                       "Внимание: %s",
	"Show MTProxy service/config summary":               "Показать статус MTProxy сервиса и конфига",
	"Show config":                                       "Показать конфиг",
	"Print server/port/secret and connect links":        "Показать сервер/порт/секрет и ссылки подключения",
	"Set secret":                                        "Установить секрет",
	"Set custom HEX32 secret and restart service":       "Установить HEX32 секрет и перезапустить сервис",
	"Regenerate secret":                                 "Перегенерировать секрет",
	"Generate random HEX32 secret and restart service":  "Сгенерировать случайный HEX32 секрет и перезапустить сервис",
	"status/start/stop/restart mtproxy":                 "status/start/stop/restart mtproxy",
	"Return to MTProxy menu":                            "Вернуться в меню MTProxy",
	"MTProxy secret (HEX32)":                            "Секрет MTProxy (HEX32)",
	"Server host/ip (empty = from config)":              "Сервер host/ip (пусто = из конфига)",
	"Port (empty = from config)":                        "Порт (пусто = из конфига)",
}

func main() {
	initUILanguage()

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "status":
		runStatus(args)
	case "admin-url":
		runAdminURL(args)
	case "ui", "menu", "interactive":
		runUI(args)
	case "users", "user", "u":
		runUsers(args)
	case "protocols", "protocol", "proto":
		runProtocols(args)
	case "list", "ls":
		runListAlias(args)
	case "config":
		runConfig(args)
	case "apply":
		runApply(args)
	case "trust", "trusttunnel", "tt":
		runTrust(args)
	case "mtproxy", "mtp", "tgproxy":
		runMTProxy(args)
	case "socks", "socks5":
		runSocks(args)
	case "lang", "language":
		runLang(args)
	case "help", "-h", "--help":
		usage()
	default:
		fatalf("unknown command: %s", cmd)
	}
}

func usage() {
	fmt.Print(`psasctl - Hiddify manager helper

Usage:
  psasctl status [--json]
  psasctl admin-url
  psasctl ui
  psasctl users list [--name QUERY] [--enabled] [--json]
  psasctl users find [--enabled] [--json] <QUERY>
  psasctl users add --name NAME [--subscription-name TITLE] [--days 30] [--gb 100] [--unlimited] [--unlimited-days] [--unlimited-gb] [--true-unlimited] [--true-unlimited-days] [--true-unlimited-gb] [--mode no_reset] [--host DOMAIN] [--uuid UUID] [--json]
  psasctl users edit [--name NAME] [--subscription-name TITLE] [--days N] [--gb N] [--unlimited] [--unlimited-days] [--unlimited-gb] [--true-unlimited] [--true-unlimited-days] [--true-unlimited-gb] [--mode MODE] [--enable|--disable] [--host DOMAIN] [--json] <USER_ID>
  psasctl users show [--host DOMAIN] [--json] <USER_ID>
  psasctl users links [--host DOMAIN] [--json] <USER_ID>
  psasctl users del <USER_ID>
  psasctl protocols list [--json]
  psasctl list protocols [--json]
  psasctl protocols set <PROTOCOL> <on|off|true|false|1|0>
  psasctl protocols enable [--apply] <PROTOCOL>...
  psasctl protocols disable [--apply] <PROTOCOL>...
  psasctl config get <key>
  psasctl config set <key> <value>
  psasctl apply
  psasctl trust status [--json]
  psasctl trust users list [--json]
  psasctl trust users add --name NAME [--password PASS] [--address IP:PORT] [--show-config] [--json]
  psasctl trust users edit [--name NAME] [--password PASS] [--json] <USER_ID>
  psasctl trust users show [--address IP:PORT] [--show-config] [--json] <USER_ID>
  psasctl trust users config [--address IP:PORT] [--out FILE] [--json] <USER_ID>
  psasctl trust users del <USER_ID>
  psasctl trust service <status|start|stop|restart>
  psasctl trust ui
  psasctl mtproxy status [--json]
  psasctl mtproxy config [--server HOST] [--port N] [--secret HEX32] [--json]
  psasctl mtproxy secret show [--json]
  psasctl mtproxy secret set <HEX32> [--json]
  psasctl mtproxy secret regen [--json]
  psasctl mtproxy service <status|start|stop|restart>
  psasctl mtproxy ui
  psasctl socks status [--json]
  psasctl socks users list [--json]
  psasctl socks users add --name LOGIN [--password PASS] [--server HOST] [--port N] [--show-config] [--json]
  psasctl socks users edit [--name LOGIN] [--password PASS] [--json] <USER_ID>
  psasctl socks users show [--server HOST] [--port N] [--show-config] [--json] <USER_ID>
  psasctl socks users config [--server HOST] [--port N] [--out FILE] [--json] <USER_ID>
  psasctl socks users del <USER_ID>
  psasctl socks service <status|start|stop|restart>
  psasctl socks ui
  psasctl lang [show]
  psasctl lang set <us|ru>

USER_ID can be UUID or user name (exact/substring match).

Environment overrides:
  PSAS_PANEL_CFG   (default /opt/hiddify-manager/hiddify-panel/app.cfg)
  PSAS_PANEL_ADDR  (default http://127.0.0.1:9000)
  PSAS_PANEL_PY    (default auto-detect .venv313/.venv/python3)
  PSAS_TT_DIR      (default /opt/trusttunnel)
  PSAS_TT_SERVICE  (default trusttunnel)
  PSAS_MTPROXY_DIR     (default /opt/MTProxy)
  PSAS_MTPROXY_SERVICE (default mtproxy)
  PSAS_MTPROXY_CONF    (default /etc/psas/mtproxy.json)
  PSAS_MTPROXY_HOST    (override default host for mtproxy config output)
  PSAS_SOCKS_SERVICE (default danted)
  PSAS_SOCKS_CONF    (default /etc/danted.conf)
  PSAS_SOCKS_USERS   (default /etc/psas/socks-users.json)
  PSAS_SOCKS_HOST    (override default server host in config output)
  PSAS_UI_LANG       (force UI language: us|ru)
  PSAS_UI_LANG_FILE  (path to language settings file)
`)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output JSON")
	must(fs.Parse(args))
	if len(fs.Args()) != 0 {
		fatalf("status takes no positional args")
	}
	c := mustClient(false)
	mainDomain := c.mainDomain()
	cfg := c.currentConfig()

	out := map[string]any{
		"main_domain":        mainDomain,
		"admin_url":          c.adminURL(mainDomain),
		"client_path":        cfg["proxy_path_client"],
		"reality_enabled":    cfg["reality_enable"],
		"hysteria2_enabled":  cfg["hysteria_enable"],
		"hysteria_base_port": cfg["hysteria_port"],
		"reality_sni":        cfg["reality_server_names"],
		"users":              len(c.state.Users),
	}
	if tt, err := newTrustClient().status(); err == nil {
		out["trusttunnel"] = tt
	}
	if mtp, err := newMTProxyClient().status(); err == nil {
		out["mtproxy"] = mtp
	}
	if sc, err := newSocksClient().status(); err == nil {
		out["socks5"] = sc
	}
	if *jsonOut {
		printJSON(out)
		return
	}

	fmt.Printf("Main domain: %s\n", mainDomain)
	fmt.Printf("Admin URL: %s\n", c.adminURL(mainDomain))
	fmt.Printf("Client path: %v\n", cfg["proxy_path_client"])
	fmt.Printf("Reality enabled: %v\n", cfg["reality_enable"])
	fmt.Printf("Hysteria2 enabled: %v\n", cfg["hysteria_enable"])
	fmt.Printf("Hysteria base port: %v\n", cfg["hysteria_port"])
	fmt.Printf("Reality SNI: %v\n", cfg["reality_server_names"])
	fmt.Printf("Users: %d\n", len(c.state.Users))
	if tt, err := newTrustClient().status(); err == nil {
		fmt.Printf("TrustTunnel installed: %t\n", tt.Installed)
		if tt.Installed {
			fmt.Printf("TrustTunnel service active: %t\n", tt.ServiceActive)
			fmt.Printf("TrustTunnel listen: %s\n", tt.ListenAddress)
			fmt.Printf("TrustTunnel users: %d\n", tt.Users)
		}
	}
	if mtp, err := newMTProxyClient().status(); err == nil {
		fmt.Printf("MTProxy installed: %t\n", mtp.Installed)
		if mtp.Installed {
			fmt.Printf("MTProxy service active: %t\n", mtp.ServiceActive)
			if mtp.Server != "" && mtp.ListenPort > 0 {
				fmt.Printf("MTProxy endpoint: %s:%d\n", mtp.Server, mtp.ListenPort)
			}
		}
	}
	if sc, err := newSocksClient().status(); err == nil {
		fmt.Printf("SOCKS5 installed: %t\n", sc.Installed)
		if sc.Installed {
			fmt.Printf("SOCKS5 service active: %t\n", sc.ServiceActive)
			fmt.Printf("SOCKS5 listen: %s\n", sc.ListenAddress)
			fmt.Printf("SOCKS5 users: %d\n", sc.Users)
		}
	}
}

func runAdminURL(args []string) {
	if len(args) != 0 {
		fatalf("admin-url takes no args")
	}
	c := mustClient(true)
	fmt.Println(c.adminURL(c.mainDomainRequired()))
}

func runListAlias(args []string) {
	if len(args) < 1 {
		fatalf("list requires target: users|protocols")
	}
	target := strings.ToLower(strings.TrimSpace(args[0]))
	rest := args[1:]
	switch target {
	case "users", "user", "u":
		runUsers(append([]string{"list"}, rest...))
	case "protocols", "protocol", "proto":
		runProtocols(append([]string{"list"}, rest...))
	default:
		fatalf("unknown list target: %s (expected users|protocols)", args[0])
	}
}

func runUsers(args []string) {
	if len(args) < 1 {
		fatalf("users requires subcommand: list|find|add|edit|show|links|del")
	}
	c := mustClient(true)

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list", "ls":
		fs := flag.NewFlagSet("list", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		enabledOnly := fs.Bool("enabled", false, "show only enabled users")
		nameFilter := fs.String("name", "", "name contains (case-insensitive)")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("users list takes no positional args")
		}
		users, err := c.usersList()
		must(err)
		users = filterUsers(users, *nameFilter, *enabledOnly)
		if *jsonOut {
			printJSON(users)
			return
		}
		printUsers(users)
	case "find":
		fs := flag.NewFlagSet("find", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		enabledOnly := fs.Bool("enabled", false, "show only enabled users")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("users find requires QUERY")
		}
		users, err := c.usersList()
		must(err)
		users = filterUsers(users, rest[0], *enabledOnly)
		if *jsonOut {
			printJSON(users)
			return
		}
		printUsers(users)
	case "show":
		fs := flag.NewFlagSet("show", flag.ExitOnError)
		host := fs.String("host", "", "domain for generated links")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("users show requires USER_ID")
		}
		u, err := c.resolveUser(rest[0])
		must(err)
		h := strings.TrimSpace(*host)
		if h == "" {
			h = c.mainDomainRequired()
		}
		links := buildLinks(c.clientPath(), u.UUID, h)
		if *jsonOut {
			printJSON(map[string]any{
				"user":  u,
				"links": links,
			})
			return
		}
		printUser(u)
		printLinksFromSet(links)
	case "links":
		fs := flag.NewFlagSet("links", flag.ExitOnError)
		host := fs.String("host", "", "domain for generated links")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("users links requires USER_ID")
		}
		u, err := c.resolveUser(rest[0])
		must(err)
		h := *host
		if h == "" {
			h = c.mainDomainRequired()
		}
		links := buildLinks(c.clientPath(), u.UUID, h)
		if *jsonOut {
			printJSON(map[string]any{
				"user":  u,
				"links": links,
			})
			return
		}
		printLinksFromSet(links)
	case "add":
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		name := fs.String("name", "", "user name")
		subscriptionName := fs.String("subscription-name", "", "subscription/profile title (alias of --name)")
		days := fs.Int("days", 30, "package days")
		gb := fs.Float64("gb", 100, "usage limit in GB")
		unlimited := fs.Bool("unlimited", false, "set practically unlimited traffic and time")
		unlimitedDays := fs.Bool("unlimited-days", false, fmt.Sprintf("set package days to %d", unlimitedPackageDays))
		unlimitedGB := fs.Bool("unlimited-gb", false, fmt.Sprintf("set usage limit to %.0f GB", unlimitedUsageGB))
		trueUnlimited := fs.Bool("true-unlimited", false, "set truly unlimited traffic and time (auto-patches Hiddify once)")
		trueUnlimitedDays := fs.Bool("true-unlimited-days", false, "set truly unlimited time (auto-patches Hiddify once)")
		trueUnlimitedGB := fs.Bool("true-unlimited-gb", false, "set truly unlimited traffic (auto-patches Hiddify once)")
		mode := fs.String("mode", "no_reset", "user mode: no_reset|daily|weekly|monthly")
		host := fs.String("host", "", "domain for generated links")
		uuid := fs.String("uuid", "", "custom UUID (optional)")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("users add takes only flags")
		}
		nameValue, err := resolveUserDisplayName(*name, *subscriptionName, true)
		must(err)
		if nameValue == "" {
			fatalf("--name is required")
		}
		if !isValidMode(*mode) {
			fatalf("invalid --mode: %s", *mode)
		}
		daysValue := *days
		gbValue := *gb
		useTrueUnlimited := *trueUnlimited || *trueUnlimitedDays || *trueUnlimitedGB
		if *unlimited || *unlimitedDays || *trueUnlimited || *trueUnlimitedDays {
			daysValue = unlimitedPackageDays
		}
		if *unlimited || *unlimitedGB || *trueUnlimited || *trueUnlimitedGB {
			gbValue = unlimitedUsageGB
		}
		if daysValue < 1 {
			fatalf("--days must be >= 1 (or use --unlimited/--unlimited-days/--true-unlimited-days)")
		}
		if gbValue <= 0 {
			fatalf("--gb must be > 0 (or use --unlimited/--unlimited-gb/--true-unlimited-gb)")
		}
		if useTrueUnlimited {
			must(c.ensureTrueUnlimitedSupport())
		}
		newID := strings.TrimSpace(*uuid)
		if newID == "" {
			newID = newUUID()
		} else {
			mustValidUUID(newID)
		}
		payload := map[string]any{
			"uuid":           strings.ToLower(newID),
			"name":           nameValue,
			"package_days":   daysValue,
			"usage_limit_GB": gbValue,
			"mode":           *mode,
			"enable":         true,
		}
		u, err := c.userAdd(payload)
		must(err)
		h := *host
		if h == "" {
			h = c.mainDomainRequired()
		}
		links := buildLinks(c.clientPath(), u.UUID, h)
		if *jsonOut {
			printJSON(map[string]any{
				"user":  u,
				"links": links,
			})
			return
		}
		printLinksFromSet(links)
	case "edit", "update", "set":
		fs := flag.NewFlagSet("edit", flag.ExitOnError)
		name := fs.String("name", "", "new user name")
		subscriptionName := fs.String("subscription-name", "", "subscription/profile title (alias of --name)")
		days := fs.Int("days", -1, "new package days (omit to keep current)")
		gb := fs.Float64("gb", -1, "new usage limit in GB (omit to keep current)")
		unlimited := fs.Bool("unlimited", false, "set practically unlimited traffic and time")
		unlimitedDays := fs.Bool("unlimited-days", false, fmt.Sprintf("set package days to %d", unlimitedPackageDays))
		unlimitedGB := fs.Bool("unlimited-gb", false, fmt.Sprintf("set usage limit to %.0f GB", unlimitedUsageGB))
		trueUnlimited := fs.Bool("true-unlimited", false, "set truly unlimited traffic and time (auto-patches Hiddify once)")
		trueUnlimitedDays := fs.Bool("true-unlimited-days", false, "set truly unlimited time (auto-patches Hiddify once)")
		trueUnlimitedGB := fs.Bool("true-unlimited-gb", false, "set truly unlimited traffic (auto-patches Hiddify once)")
		mode := fs.String("mode", "", "new user mode: no_reset|daily|weekly|monthly")
		enableUser := fs.Bool("enable", false, "enable user")
		disableUser := fs.Bool("disable", false, "disable user")
		host := fs.String("host", "", "domain for generated links")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("users edit requires USER_ID")
		}

		u, err := c.resolveUser(rest[0])
		must(err)

		payload := map[string]any{}
		changed := false

		nameValue, err := resolveUserDisplayName(*name, *subscriptionName, false)
		must(err)
		if nameValue != "" {
			payload["name"] = nameValue
			changed = true
		}

		modeValue := strings.TrimSpace(*mode)
		if modeValue != "" {
			if !isValidMode(modeValue) {
				fatalf("invalid --mode: %s", modeValue)
			}
			payload["mode"] = modeValue
			changed = true
		}

		if *enableUser && *disableUser {
			fatalf("--enable and --disable cannot be used together")
		}
		if *enableUser {
			payload["enable"] = true
			changed = true
		}
		if *disableUser {
			payload["enable"] = false
			changed = true
		}

		useTrueUnlimited := *trueUnlimited || *trueUnlimitedDays || *trueUnlimitedGB

		hasDays := *days >= 0
		daysValue := *days
		if *unlimited || *unlimitedDays || *trueUnlimited || *trueUnlimitedDays {
			hasDays = true
			daysValue = unlimitedPackageDays
		}
		if hasDays {
			if daysValue < 1 {
				fatalf("--days must be >= 1 (or use --unlimited/--unlimited-days/--true-unlimited-days)")
			}
			payload["package_days"] = daysValue
			changed = true
		}

		hasGB := *gb >= 0
		gbValue := *gb
		if *unlimited || *unlimitedGB || *trueUnlimited || *trueUnlimitedGB {
			hasGB = true
			gbValue = unlimitedUsageGB
		}
		if hasGB {
			if gbValue <= 0 {
				fatalf("--gb must be > 0 (or use --unlimited/--unlimited-gb/--true-unlimited-gb)")
			}
			payload["usage_limit_GB"] = gbValue
			changed = true
		}

		if !changed {
			fatalf("users edit: no changes requested; pass at least one edit flag")
		}
		if useTrueUnlimited {
			must(c.ensureTrueUnlimitedSupport())
		}

		updated, err := c.userPatch(u.UUID, payload)
		must(err)

		h := strings.TrimSpace(*host)
		if h == "" {
			h = c.mainDomainRequired()
		}
		links := buildLinks(c.clientPath(), updated.UUID, h)
		if *jsonOut {
			printJSON(map[string]any{
				"user":  updated,
				"links": links,
			})
			return
		}
		printUser(updated)
		printLinksFromSet(links)
	case "del", "delete", "rm":
		if len(subArgs) != 1 {
			fatalf("users del requires USER_ID")
		}
		u, err := c.resolveUser(subArgs[0])
		must(err)
		must(c.userDelete(u.UUID))
		fmt.Printf("Deleted: %s (%s)\n", u.UUID, u.Name)
	default:
		fatalf("unknown users subcommand: %s", sub)
	}
}

type protocolState struct {
	Name    string   `json:"name"`
	Key     string   `json:"key"`
	Enabled bool     `json:"enabled"`
	Aliases []string `json:"aliases,omitempty"`
}

func runProtocols(args []string) {
	if len(args) < 1 {
		fatalf("protocols requires subcommand: list|set|enable|disable")
	}
	c := mustClient(true)

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list", "ls":
		fs := flag.NewFlagSet("protocols list", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("protocols list takes no positional args")
		}
		items := protocolStates(c.currentConfig())
		if *jsonOut {
			printJSON(items)
			return
		}
		printProtocolStatesTable(items)
	case "set":
		if len(subArgs) != 2 {
			fatalf("protocols set requires <PROTOCOL> <on|off|true|false|1|0>")
		}
		p, err := resolveProtocolSetting(subArgs[0])
		must(err)
		value, err := parseBoolLike(subArgs[1])
		must(err)
		must(c.setConfig(p.Key, strconv.FormatBool(value)))
		fmt.Printf("Protocol %s (%s) set to %t\n", p.Name, p.Key, value)
	case "enable", "disable":
		fs := flag.NewFlagSet("protocols "+sub, flag.ExitOnError)
		applyNow := fs.Bool("apply", false, "apply config after changes")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) == 0 {
			fatalf("protocols %s requires at least one protocol", sub)
		}
		value := sub == "enable"
		seen := map[string]bool{}
		for _, raw := range rest {
			p, err := resolveProtocolSetting(raw)
			must(err)
			if seen[p.Key] {
				continue
			}
			seen[p.Key] = true
			must(c.setConfig(p.Key, strconv.FormatBool(value)))
			fmt.Printf("Protocol %s (%s) set to %t\n", p.Name, p.Key, value)
		}
		if *applyNow {
			must(applyWithClient(c))
		}
	default:
		fatalf("unknown protocols subcommand: %s", sub)
	}
}

func runTrust(args []string) {
	if len(args) < 1 {
		fatalf("trust requires subcommand: status|users|service|ui")
	}

	tt := newTrustClient()
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	subArgs := args[1:]

	switch sub {
	case "status":
		fs := flag.NewFlagSet("trust status", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("trust status takes no positional args")
		}
		st, err := tt.status()
		must(err)
		if *jsonOut {
			printJSON(st)
			return
		}
		printTrustStatus(st)
	case "users", "user", "u":
		runTrustUsers(tt, subArgs)
	case "service", "svc":
		runTrustService(tt, subArgs)
	case "ui", "menu", "interactive":
		runTrustUI(subArgs)
	default:
		fatalf("unknown trust subcommand: %s", sub)
	}
}

func runMTProxy(args []string) {
	if len(args) < 1 {
		fatalf("mtproxy requires subcommand: status|config|secret|service|ui")
	}

	mp := newMTProxyClient()
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	subArgs := args[1:]

	switch sub {
	case "status":
		fs := flag.NewFlagSet("mtproxy status", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("mtproxy status takes no positional args")
		}
		st, err := mp.status()
		must(err)
		if *jsonOut {
			printJSON(st)
			return
		}
		printMTProxyStatus(st)
	case "config", "show", "links":
		fs := flag.NewFlagSet("mtproxy config", flag.ExitOnError)
		server := fs.String("server", "", "server host/ip for generated links")
		port := fs.Int("port", 0, "server port for generated links")
		secret := fs.String("secret", "", "secret override (HEX32)")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("mtproxy config takes only flags")
		}
		cfg, err := mp.connectionInfo(strings.TrimSpace(*server), *port, strings.TrimSpace(*secret))
		must(err)
		if *jsonOut {
			printJSON(cfg)
			return
		}
		printMTProxyConnInfo(cfg)
	case "secret":
		runMTProxySecret(mp, subArgs)
	case "service", "svc":
		runMTProxyService(mp, subArgs)
	case "ui", "menu", "interactive":
		runMTProxyUI(subArgs)
	default:
		fatalf("unknown mtproxy subcommand: %s", sub)
	}
}

func runMTProxySecret(mp *mtproxyClient, args []string) {
	if len(args) < 1 {
		fatalf("mtproxy secret requires subcommand: show|set|regen")
	}
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	subArgs := args[1:]

	switch sub {
	case "show":
		fs := flag.NewFlagSet("mtproxy secret show", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("mtproxy secret show takes no positional args")
		}
		cfg, err := mp.loadConfig()
		must(err)
		secret, err := normalizeMTProxySecret(cfg.Secret)
		must(err)
		if *jsonOut {
			printJSON(map[string]any{
				"secret":        secret,
				"secret_masked": maskSecret(secret),
			})
			return
		}
		fmt.Printf("Secret: %s\n", secret)
	case "set":
		fs := flag.NewFlagSet("mtproxy secret set", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("mtproxy secret set requires <HEX32>")
		}
		must(requireRoot("mtproxy secret set"))

		secret, err := normalizeMTProxySecret(rest[0])
		must(err)
		cfg, err := mp.loadConfig()
		must(err)
		cfg.Secret = secret
		must(mp.writeConfig(cfg))
		restartWarn := mtproxyRestartWarning(mp.service, mp.restartService())

		resp := map[string]any{
			"secret":        cfg.Secret,
			"secret_masked": maskSecret(cfg.Secret),
		}
		if restartWarn != "" {
			resp["restart_warning"] = restartWarn
		}
		if *jsonOut {
			printJSON(resp)
			return
		}
		fmt.Printf("MTProxy secret updated.\n")
		fmt.Printf("Secret: %s\n", cfg.Secret)
		if restartWarn != "" {
			fmt.Printf("Warning: %s\n", restartWarn)
		}
	case "regen", "rotate":
		fs := flag.NewFlagSet("mtproxy secret regen", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("mtproxy secret regen takes no positional args")
		}
		must(requireRoot("mtproxy secret regen"))

		cfg, err := mp.loadConfig()
		must(err)
		cfg.Secret = newHexToken(16)
		must(mp.writeConfig(cfg))
		restartWarn := mtproxyRestartWarning(mp.service, mp.restartService())

		resp := map[string]any{
			"secret":        cfg.Secret,
			"secret_masked": maskSecret(cfg.Secret),
		}
		if restartWarn != "" {
			resp["restart_warning"] = restartWarn
		}
		if *jsonOut {
			printJSON(resp)
			return
		}
		fmt.Printf("MTProxy secret regenerated.\n")
		fmt.Printf("Secret: %s\n", cfg.Secret)
		if restartWarn != "" {
			fmt.Printf("Warning: %s\n", restartWarn)
		}
	default:
		fatalf("unknown mtproxy secret subcommand: %s", sub)
	}
}

func runMTProxyService(mp *mtproxyClient, args []string) {
	if len(args) != 1 {
		fatalf("mtproxy service requires action: status|start|stop|restart")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "status":
		must(runCommand("systemctl", "--no-pager", "--full", "status", mp.service))
	case "start", "stop", "restart":
		must(runCommand("systemctl", action, mp.service))
		fmt.Printf("MTProxy service %s: %s\n", action, mp.service)
	default:
		fatalf("unknown mtproxy service action: %s (expected status|start|stop|restart)", action)
	}
}

func runMTProxyUI(args []string) {
	if len(args) != 0 {
		fatalf("mtproxy ui takes no args")
	}
	if !isInteractiveTerminal() {
		fatalf("mtproxy ui requires an interactive terminal")
	}
	in := bufio.NewReader(os.Stdin)
	clearScreen()
	printBoxedHeader("Telegram MTProxy")
	if err := uiMTProxy(in); err != nil {
		if errors.Is(err, errUISelectionCanceled) || errors.Is(err, errUIExitRequested) || errors.Is(err, io.EOF) {
			clearScreen()
			return
		}
		fatalf("mtproxy ui error: %v", err)
	}
	clearScreen()
}

func runSocks(args []string) {
	if len(args) < 1 {
		fatalf("socks requires subcommand: status|users|service|ui")
	}

	sc := newSocksClient()
	sub := strings.ToLower(strings.TrimSpace(args[0]))
	subArgs := args[1:]

	switch sub {
	case "status":
		fs := flag.NewFlagSet("socks status", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("socks status takes no positional args")
		}
		st, err := sc.status()
		must(err)
		if *jsonOut {
			printJSON(st)
			return
		}
		printSocksStatus(st)
	case "users", "user", "u":
		runSocksUsers(sc, subArgs)
	case "service", "svc":
		runSocksService(sc, subArgs)
	case "ui", "menu", "interactive":
		runSocksUI(subArgs)
	default:
		fatalf("unknown socks subcommand: %s", sub)
	}
}

func runSocksUsers(sc *socksClient, args []string) {
	if len(args) < 1 {
		fatalf("socks users requires subcommand: list|add|edit|show|config|del")
	}

	sub := strings.ToLower(strings.TrimSpace(args[0]))
	subArgs := args[1:]

	switch sub {
	case "list", "ls":
		fs := flag.NewFlagSet("socks users list", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("socks users list takes no positional args")
		}
		users, err := sc.usersList()
		must(err)
		if *jsonOut {
			printJSON(users)
			return
		}
		printSocksUsers(users)
	case "add":
		fs := flag.NewFlagSet("socks users add", flag.ExitOnError)
		name := fs.String("name", "", "login")
		password := fs.String("password", "", "password (empty = auto-generated)")
		server := fs.String("server", "", "server host/ip for generated config")
		port := fs.Int("port", 0, "server port for generated config (default: danted port)")
		showConfig := fs.Bool("show-config", false, "also print generated socks config")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("socks users add takes only flags")
		}
		must(requireRoot("socks users add"))

		login := normalizeSocksLogin(*name)
		if err := validateSocksLogin(login); err != nil {
			fatalf("%v", err)
		}

		users, err := sc.usersList()
		must(err)
		if hasSocksUserExact(users, login) {
			fatalf("socks user already exists: %s", login)
		}
		if osSocksUserExists(login) {
			fatalf("linux user already exists: %s", login)
		}

		pass := strings.TrimSpace(*password)
		if pass == "" {
			pass = newSecureToken(24)
		}

		must(sc.ensureLinuxUser(login, pass))
		users = append(users, socksUser{Name: login, Password: pass, SystemUser: login})
		must(sc.writeUsers(users))

		resp := map[string]any{
			"user": map[string]any{
				"name":        login,
				"password":    pass,
				"system_user": login,
			},
		}
		if *showConfig {
			cfg, err := sc.connectionConfig(socksUser{Name: login, Password: pass, SystemUser: login}, strings.TrimSpace(*server), *port)
			if err != nil {
				fatalf("user was added, but failed to build socks config: %v", err)
			}
			resp["config"] = cfg
		}
		if *jsonOut {
			printJSON(resp)
			return
		}

		fmt.Printf("SOCKS user added: %s\n", login)
		fmt.Printf("Password: %s\n", pass)
		if *showConfig {
			cfgAny := resp["config"]
			if cfg, ok := cfgAny.(socksConnInfo); ok {
				printSocksConnInfo(cfg)
			}
		}
	case "edit":
		fs := flag.NewFlagSet("socks users edit", flag.ExitOnError)
		name := fs.String("name", "", "new login")
		password := fs.String("password", "", "new password")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("socks users edit requires USER_ID")
		}
		must(requireRoot("socks users edit"))

		users, err := sc.usersList()
		must(err)
		current, idx, err := resolveSocksUser(users, rest[0])
		must(err)

		target := current
		newName := normalizeSocksLogin(*name)
		newPass := strings.TrimSpace(*password)
		oldSystemUser := socksSystemUser(current)

		if newName == "" && newPass == "" {
			fatalf("socks users edit: no changes requested")
		}
		if newName != "" && newName != current.Name {
			if err := validateSocksLogin(newName); err != nil {
				fatalf("%v", err)
			}
			for i, u := range users {
				if i == idx {
					continue
				}
				if strings.EqualFold(strings.TrimSpace(u.Name), newName) {
					fatalf("socks user already exists: %s", newName)
				}
			}
			if osSocksUserExists(newName) {
				fatalf("linux user already exists: %s", newName)
			}
			must(runCommand("usermod", "-l", newName, oldSystemUser))
			target.Name = newName
			target.SystemUser = newName
		}
		if newPass != "" {
			must(sc.setLinuxUserPassword(socksSystemUser(target), newPass))
			target.Password = newPass
		}

		users[idx] = target
		must(sc.writeUsers(users))

		if *jsonOut {
			printJSON(map[string]any{
				"user_before": current,
				"user_after":  target,
			})
			return
		}
		fmt.Printf("SOCKS user updated: %s -> %s\n", current.Name, target.Name)
		if newPass != "" {
			fmt.Printf("New password: %s\n", newPass)
		}
	case "show":
		fs := flag.NewFlagSet("socks users show", flag.ExitOnError)
		server := fs.String("server", "", "server host/ip for generated config")
		port := fs.Int("port", 0, "server port for generated config")
		showConfig := fs.Bool("show-config", false, "also print generated socks config")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("socks users show requires USER_ID")
		}

		users, err := sc.usersList()
		must(err)
		u, _, err := resolveSocksUser(users, rest[0])
		must(err)

		out := map[string]any{"user": u}
		if *showConfig {
			cfg, err := sc.connectionConfig(u, strings.TrimSpace(*server), *port)
			if err != nil {
				fatalf("failed to build socks config: %v", err)
			}
			out["config"] = cfg
		}
		if *jsonOut {
			printJSON(out)
			return
		}
		printSocksUser(u)
		if *showConfig {
			fmt.Println()
			if cfg, ok := out["config"].(socksConnInfo); ok {
				printSocksConnInfo(cfg)
			}
		}
	case "config":
		fs := flag.NewFlagSet("socks users config", flag.ExitOnError)
		server := fs.String("server", "", "server host/ip for generated config")
		port := fs.Int("port", 0, "server port for generated config")
		outPath := fs.String("out", "", "write socks config to file")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("socks users config requires USER_ID")
		}

		users, err := sc.usersList()
		must(err)
		u, _, err := resolveSocksUser(users, rest[0])
		must(err)
		cfg, err := sc.connectionConfig(u, strings.TrimSpace(*server), *port)
		must(err)

		if p := strings.TrimSpace(*outPath); p != "" {
			must(os.WriteFile(p, []byte(renderSocksConnInfo(cfg)), 0o600))
		}

		if *jsonOut {
			printJSON(map[string]any{
				"user":   u,
				"config": cfg,
				"out":    strings.TrimSpace(*outPath),
			})
			return
		}
		printSocksConnInfo(cfg)
		if p := strings.TrimSpace(*outPath); p != "" {
			fmt.Printf("Saved to: %s\n", p)
		}
	case "del", "delete", "rm":
		if len(subArgs) != 1 {
			fatalf("socks users del requires USER_ID")
		}
		must(requireRoot("socks users del"))

		users, err := sc.usersList()
		must(err)
		u, idx, err := resolveSocksUser(users, subArgs[0])
		must(err)
		next := make([]socksUser, 0, len(users)-1)
		next = append(next, users[:idx]...)
		next = append(next, users[idx+1:]...)
		must(sc.writeUsers(next))

		warn := ""
		if err := sc.deleteLinuxUser(socksSystemUser(u)); err != nil {
			warn = err.Error()
		}
		fmt.Printf("SOCKS user deleted: %s\n", u.Name)
		if warn != "" {
			fmt.Printf("Warning: %s\n", warn)
		}
	default:
		fatalf("unknown socks users subcommand: %s", sub)
	}
}

func runSocksService(sc *socksClient, args []string) {
	if len(args) != 1 {
		fatalf("socks service requires action: status|start|stop|restart")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "status":
		must(runCommand("systemctl", "--no-pager", "--full", "status", sc.service))
	case "start", "stop", "restart":
		must(runCommand("systemctl", action, sc.service))
		fmt.Printf("SOCKS service %s: %s\n", action, sc.service)
	default:
		fatalf("unknown socks service action: %s (expected status|start|stop|restart)", action)
	}
}

func runSocksUI(args []string) {
	if len(args) != 0 {
		fatalf("socks ui takes no args")
	}
	if !isInteractiveTerminal() {
		fatalf("socks ui requires an interactive terminal")
	}
	in := bufio.NewReader(os.Stdin)
	clearScreen()
	printBoxedHeader("SOCKS5 (Dante)")
	if err := uiSocksProxy(in); err != nil {
		if errors.Is(err, errUISelectionCanceled) || errors.Is(err, errUIExitRequested) || errors.Is(err, io.EOF) {
			clearScreen()
			return
		}
		fatalf("socks ui error: %v", err)
	}
	clearScreen()
}

func runLang(args []string) {
	if len(args) == 0 || strings.EqualFold(strings.TrimSpace(args[0]), "show") {
		fmt.Println(currentUILang)
		return
	}
	if strings.EqualFold(strings.TrimSpace(args[0]), "set") {
		if len(args) != 2 {
			fatalf("lang set requires value: us|ru")
		}
		lang := normalizeUILang(args[1])
		if lang == "" {
			fatalf("unsupported language: %s (expected us|ru)", strings.TrimSpace(args[1]))
		}
		must(setUILang(lang, true))
		fmt.Printf(uiTextf("Language set to: %s", lang) + "\n")
		return
	}
	if strings.EqualFold(strings.TrimSpace(args[0]), "list") {
		fmt.Println("us")
		fmt.Println("ru")
		return
	}
	fatalf("lang supports: show | set <us|ru> | list")
}

func runTrustUsers(tt *trustClient, args []string) {
	if len(args) < 1 {
		fatalf("trust users requires subcommand: list|add|edit|show|config|del")
	}

	sub := strings.ToLower(strings.TrimSpace(args[0]))
	subArgs := args[1:]

	switch sub {
	case "list", "ls":
		fs := flag.NewFlagSet("trust users list", flag.ExitOnError)
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("trust users list takes no positional args")
		}
		users, err := tt.usersList()
		must(err)
		if *jsonOut {
			printJSON(users)
			return
		}
		printTrustUsers(users)
	case "add":
		fs := flag.NewFlagSet("trust users add", flag.ExitOnError)
		name := fs.String("name", "", "username")
		password := fs.String("password", "", "password (empty = auto-generated)")
		address := fs.String("address", "", "endpoint address ip[:port] for generated config")
		showConfig := fs.Bool("show-config", false, "also print generated client config")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("trust users add takes only flags")
		}

		username := strings.TrimSpace(*name)
		if err := validateTrustUsername(username); err != nil {
			fatalf("%v", err)
		}

		users, err := tt.usersList()
		must(err)
		if hasTrustUserExact(users, username) {
			fatalf("trust user already exists: %s", username)
		}

		pass := strings.TrimSpace(*password)
		if pass == "" {
			pass = newSecureToken(24)
		}

		users = append(users, trustUser{Username: username, Password: pass})
		must(tt.writeUsers(users))
		restartWarn := trustRestartWarning(tt.service, tt.restartService())

		resp := map[string]any{
			"user": map[string]any{
				"username": username,
				"password": pass,
			},
		}
		if restartWarn != "" {
			resp["restart_warning"] = restartWarn
		}

		if *showConfig {
			configText, err := tt.exportClientConfig(username, strings.TrimSpace(*address))
			if err != nil {
				fatalf("user was added, but failed to export client config: %v", err)
			}
			resp["client_config"] = configText
			resp["address"] = tt.lastExportAddress
		}

		if *jsonOut {
			printJSON(resp)
			return
		}

		fmt.Printf("TrustTunnel user added: %s\n", username)
		fmt.Printf("Password: %s\n", pass)
		if restartWarn != "" {
			fmt.Printf("Warning: %s\n", restartWarn)
		}
		if *showConfig {
			fmt.Println()
			fmt.Println("Client config")
			fmt.Println("=============")
			fmt.Println(resp["client_config"])
		}
	case "edit", "update", "set":
		fs := flag.NewFlagSet("trust users edit", flag.ExitOnError)
		name := fs.String("name", "", "new username")
		password := fs.String("password", "", "new password")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("trust users edit requires USER_ID")
		}

		users, err := tt.usersList()
		must(err)
		current, idx, err := resolveTrustUser(users, rest[0])
		must(err)

		newName := strings.TrimSpace(*name)
		newPassword := strings.TrimSpace(*password)
		if newName == "" && newPassword == "" {
			fatalf("trust users edit: no changes requested")
		}
		if newName != "" {
			if err := validateTrustUsername(newName); err != nil {
				fatalf("%v", err)
			}
			for i, u := range users {
				if i == idx {
					continue
				}
				if strings.EqualFold(strings.TrimSpace(u.Username), newName) {
					fatalf("trust user already exists: %s", newName)
				}
			}
			users[idx].Username = newName
		}
		if newPassword != "" {
			users[idx].Password = newPassword
		}

		must(tt.writeUsers(users))
		restartWarn := trustRestartWarning(tt.service, tt.restartService())

		out := map[string]any{
			"before": current,
			"after":  users[idx],
		}
		if restartWarn != "" {
			out["restart_warning"] = restartWarn
		}
		if *jsonOut {
			printJSON(out)
			return
		}
		fmt.Printf("TrustTunnel user updated: %s -> %s\n", current.Username, users[idx].Username)
		if restartWarn != "" {
			fmt.Printf("Warning: %s\n", restartWarn)
		}
	case "show":
		fs := flag.NewFlagSet("trust users show", flag.ExitOnError)
		address := fs.String("address", "", "endpoint address ip[:port] for generated config")
		showConfig := fs.Bool("show-config", false, "also print generated client config")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("trust users show requires USER_ID")
		}

		users, err := tt.usersList()
		must(err)
		u, _, err := resolveTrustUser(users, rest[0])
		must(err)

		out := map[string]any{
			"user": u,
		}
		if *showConfig {
			configText, err := tt.exportClientConfig(u.Username, strings.TrimSpace(*address))
			if err != nil {
				fatalf("failed to export client config: %v", err)
			}
			out["client_config"] = configText
			out["address"] = tt.lastExportAddress
		}
		if *jsonOut {
			printJSON(out)
			return
		}
		printTrustUser(u)
		if *showConfig {
			fmt.Println()
			fmt.Println("Client config")
			fmt.Println("=============")
			fmt.Println(out["client_config"])
		}
	case "config":
		fs := flag.NewFlagSet("trust users config", flag.ExitOnError)
		address := fs.String("address", "", "endpoint address ip[:port] for generated config")
		outPath := fs.String("out", "", "write client config to file")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("trust users config requires USER_ID")
		}

		users, err := tt.usersList()
		must(err)
		u, _, err := resolveTrustUser(users, rest[0])
		must(err)

		configText, err := tt.exportClientConfig(u.Username, strings.TrimSpace(*address))
		must(err)

		if p := strings.TrimSpace(*outPath); p != "" {
			must(os.WriteFile(p, []byte(configText), 0o600))
		}

		if *jsonOut {
			printJSON(map[string]any{
				"user":    u,
				"address": tt.lastExportAddress,
				"config":  configText,
				"out":     strings.TrimSpace(*outPath),
			})
			return
		}
		fmt.Printf("Generated TrustTunnel config for %s\n", u.Username)
		fmt.Printf("Address: %s\n", tt.lastExportAddress)
		if p := strings.TrimSpace(*outPath); p != "" {
			fmt.Printf("Saved to: %s\n", p)
			return
		}
		fmt.Println()
		fmt.Println(configText)
	case "del", "delete", "rm":
		if len(subArgs) != 1 {
			fatalf("trust users del requires USER_ID")
		}

		users, err := tt.usersList()
		must(err)
		u, idx, err := resolveTrustUser(users, subArgs[0])
		must(err)

		next := make([]trustUser, 0, len(users)-1)
		next = append(next, users[:idx]...)
		next = append(next, users[idx+1:]...)
		must(tt.writeUsers(next))
		restartWarn := trustRestartWarning(tt.service, tt.restartService())

		fmt.Printf("TrustTunnel user deleted: %s\n", u.Username)
		if restartWarn != "" {
			fmt.Printf("Warning: %s\n", restartWarn)
		}
	default:
		fatalf("unknown trust users subcommand: %s", sub)
	}
}

func runTrustService(tt *trustClient, args []string) {
	if len(args) != 1 {
		fatalf("trust service requires action: status|start|stop|restart")
	}
	action := strings.ToLower(strings.TrimSpace(args[0]))
	switch action {
	case "status":
		must(runCommand("systemctl", "--no-pager", "--full", "status", tt.service))
	case "start", "stop", "restart":
		must(runCommand("systemctl", action, tt.service))
		fmt.Printf("TrustTunnel service %s: %s\n", action, tt.service)
	default:
		fatalf("unknown trust service action: %s (expected status|start|stop|restart)", action)
	}
}

func runTrustUI(args []string) {
	if len(args) != 0 {
		fatalf("trust ui takes no args")
	}
	if !isInteractiveTerminal() {
		fatalf("trust ui requires an interactive terminal")
	}

	in := bufio.NewReader(os.Stdin)
	clearScreen()
	printBoxedHeader("TrustTunnel")
	if err := uiTrustTunnel(in); err != nil {
		if errors.Is(err, errUISelectionCanceled) || errors.Is(err, errUIExitRequested) {
			clearScreen()
			return
		}
		if errors.Is(err, io.EOF) {
			clearScreen()
			return
		}
		fatalf("trust ui error: %v", err)
	}
	clearScreen()
}

func printTrustStatus(st trustStatus) {
	fmt.Printf("%s: %t\n", uiText("TrustTunnel installed"), st.Installed)
	fmt.Printf("%s: %s (active=%t)\n", uiText("Service"), st.Service, st.ServiceActive)
	fmt.Printf("%s: %s\n", uiText("Directory"), st.Directory)
	if st.ListenAddress != "" {
		fmt.Printf("%s: %s\n", uiText("Listen"), st.ListenAddress)
	}
	if st.Hostname != "" {
		fmt.Printf("%s: %s\n", uiText("Hostname"), st.Hostname)
	}
	fmt.Printf("%s: %d\n", uiText("Users"), st.Users)
}

func printTrustUsers(users []trustUser) {
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, uiText("USERNAME")+"\t"+uiText("PASSWORD"))
	for _, u := range users {
		fmt.Fprintf(tw, "%s\t%s\n", u.Username, maskSecret(u.Password))
	}
	_ = tw.Flush()
}

func printTrustUser(u trustUser) {
	fmt.Println()
	fmt.Println(uiText("TrustTunnel User"))
	fmt.Println("================")
	fmt.Printf("%s: %s\n", uiText("Username"), u.Username)
	fmt.Printf("%s: %s\n", uiText("Password"), u.Password)
}

func printSocksStatus(st socksStatus) {
	fmt.Printf("%s: %t\n", uiText("SOCKS installed"), st.Installed)
	fmt.Printf("%s: %s (active=%t)\n", uiText("Service"), st.Service, st.ServiceActive)
	fmt.Printf("%s: %s\n", uiText("Config"), st.ConfigPath)
	if st.ListenAddress != "" {
		fmt.Printf("%s: %s\n", uiText("Listen"), st.ListenAddress)
	}
	fmt.Printf("%s: %d\n", uiText("Users"), st.Users)
}

func printSocksUsers(users []socksUser) {
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, uiText("LOGIN")+"\t"+uiText("PASSWORD"))
	for _, u := range users {
		fmt.Fprintf(tw, "%s\t%s\n", u.Name, maskSecret(u.Password))
	}
	_ = tw.Flush()
}

func printSocksUser(u socksUser) {
	fmt.Println()
	fmt.Println(uiText("SOCKS User"))
	fmt.Println("==========")
	fmt.Printf("%s: %s\n", uiText("Login"), u.Name)
	fmt.Printf("%s: %s\n", uiText("Password"), u.Password)
}

func renderSocksConnInfo(cfg socksConnInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", uiText("Server"), cfg.Server)
	fmt.Fprintf(&b, "%s: %d\n", uiText("Port"), cfg.Port)
	fmt.Fprintf(&b, "%s: %s\n", uiText("Login"), cfg.Username)
	fmt.Fprintf(&b, "%s: %s\n", uiText("Password"), cfg.Password)
	fmt.Fprintf(&b, "URI: %s\n", cfg.URI)
	return b.String()
}

func printSocksConnInfo(cfg socksConnInfo) {
	fmt.Println(uiText("SOCKS5 config"))
	fmt.Println("=============")
	fmt.Print(renderSocksConnInfo(cfg))
}

func printMTProxyStatus(st mtproxyStatus) {
	fmt.Printf("%s: %t\n", uiText("MTProxy installed"), st.Installed)
	fmt.Printf("%s: %s (active=%t)\n", uiText("Service"), st.Service, st.ServiceActive)
	fmt.Printf("%s: %s\n", uiText("Directory"), st.Directory)
	fmt.Printf("%s: %s\n", uiText("Config"), st.ConfigPath)
	if st.Server != "" {
		fmt.Printf("%s: %s\n", uiText("Server"), st.Server)
	}
	if st.ListenPort > 0 {
		fmt.Printf("%s: %d\n", uiText("Port"), st.ListenPort)
	}
	if st.InternalPort > 0 {
		fmt.Printf("%s: %d\n", uiText("Internal port"), st.InternalPort)
	}
	if st.SecretMasked != "" {
		fmt.Printf("%s: %s\n", uiText("Secret"), st.SecretMasked)
	}
}

func renderMTProxyConnInfo(cfg mtproxyConnInfo) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %s\n", uiText("Server"), cfg.Server)
	fmt.Fprintf(&b, "%s: %d\n", uiText("Port"), cfg.Port)
	fmt.Fprintf(&b, "%s: %s\n", uiText("Secret"), cfg.Secret)
	fmt.Fprintf(&b, "%s: %s\n", uiText("Secret masked"), cfg.SecretMasked)
	fmt.Fprintf(&b, "%s: %s\n", uiText("tg:// link"), cfg.TGLink)
	fmt.Fprintf(&b, "%s: %s\n", uiText("Share URL"), cfg.ShareURL)
	return b.String()
}

func printMTProxyConnInfo(cfg mtproxyConnInfo) {
	fmt.Println(uiText("MTProxy config"))
	fmt.Println("==============")
	fmt.Print(renderMTProxyConnInfo(cfg))
}

func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	return s[:2] + strings.Repeat("*", len(s)-4) + s[len(s)-2:]
}

func trustRestartWarning(service string, err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("credentials saved, but failed to restart %s: %v", service, err)
}

func mtproxyRestartWarning(service string, err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("config saved, but failed to restart %s: %v", service, err)
}

func protocolStates(cfg map[string]any) []protocolState {
	out := make([]protocolState, 0, len(protocolSettings))
	for _, p := range protocolSettings {
		out = append(out, protocolState{
			Name:    p.Name,
			Key:     p.Key,
			Enabled: anyToBool(cfg[p.Key]),
			Aliases: append([]string(nil), p.Aliases...),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func printProtocolStatesTable(items []protocolState) {
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "PROTOCOL\tENABLED\tKEY\tALIASES")
	for _, p := range items {
		fmt.Fprintf(tw, "%s\t%t\t%s\t%s\n", p.Name, p.Enabled, p.Key, strings.Join(p.Aliases, ","))
	}
	_ = tw.Flush()
}

func resolveProtocolSetting(raw string) (protocolSetting, error) {
	k := normalizeProtocolName(raw)
	for _, p := range protocolSettings {
		if normalizeProtocolName(p.Name) == k || normalizeProtocolName(p.Key) == k {
			return p, nil
		}
		for _, alias := range p.Aliases {
			if normalizeProtocolName(alias) == k {
				return p, nil
			}
		}
	}
	known := make([]string, 0, len(protocolSettings))
	for _, p := range protocolSettings {
		known = append(known, p.Name)
	}
	sort.Strings(known)
	return protocolSetting{}, fmt.Errorf("unknown protocol %q; known: %s", raw, strings.Join(known, ", "))
}

func normalizeProtocolName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "_", "-")
	return s
}

func runConfig(args []string) {
	if len(args) < 2 {
		fatalf("config requires subcommand: get|set")
	}
	c := mustClient(true)
	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "get":
		if len(subArgs) != 1 {
			fatalf("config get requires key")
		}
		k := subArgs[0]
		cfg := c.currentConfig()
		v, ok := cfg[k]
		if !ok {
			fatalf("key not found: %s", k)
		}
		fmt.Println(v)
	case "set":
		if len(subArgs) != 2 {
			fatalf("config set requires key and value")
		}
		k := subArgs[0]
		v := subArgs[1]
		must(c.setConfig(k, v))
		fmt.Printf("Set %s=%s\n", k, v)
	default:
		fatalf("unknown config subcommand: %s", sub)
	}
}

func runApply(args []string) {
	if len(args) != 0 {
		fatalf("apply takes no args")
	}
	c := mustClient(true)
	must(applyWithClient(c))
}

func applyWithClient(c *client) error {
	mainDomain, err := c.mainDomainOrErr()
	if err != nil {
		return err
	}
	if fileExists("/usr/local/bin/hiddify-apply-safe") {
		if err := runCommand("/usr/local/bin/hiddify-apply-safe", mainDomain); err != nil {
			return err
		}
		fmt.Println("Applied with hiddify-apply-safe")
		return nil
	}
	if err := runCommand("/opt/hiddify-manager/common/commander.py", "apply"); err != nil {
		return err
	}
	fmt.Println("Applied with /opt/hiddify-manager/common/commander.py apply")
	return nil
}

func runUI(args []string) {
	if len(args) != 0 {
		fatalf("ui takes no args")
	}
	if !isInteractiveTerminal() {
		fatalf("ui mode requires an interactive terminal")
	}

	c := mustClient(true)
	in := bufio.NewReader(os.Stdin)
	menuItems := []uiMenuItem{
		{Section: "Hiddify Manager", Key: "status", Shortcut: 's', Title: "Status", Hint: "Main domain, admin URL, protocols, users count"},
		{Section: "Hiddify Manager", Key: "list", Shortcut: 'l', Title: "List users", Hint: "Print all users in a table"},
		{Section: "Hiddify Manager", Key: "find", Shortcut: 'f', Title: "Find users", Hint: "Search users by name/part and optional enabled filter"},
		{Section: "Hiddify Manager", Key: "show", Shortcut: 'v', Title: "Show user + links", Hint: "Pick a user with arrows and print links"},
		{Section: "Hiddify Manager", Key: "add", Shortcut: 'a', Title: "Add user", Hint: "Step-by-step wizard for creating a user"},
		{Section: "Hiddify Manager", Key: "edit", Shortcut: 'e', Title: "Edit user", Hint: "Pick a user and edit name/limits/mode/enabled state"},
		{Section: "Hiddify Manager", Key: "delete", Shortcut: 'd', Title: "Delete user", Hint: "Pick a user and delete with confirmation"},
		{Section: "Hiddify Manager", Key: "protocols", Shortcut: 't', Title: "Protocols", Hint: "List and toggle protocol enable flags"},
		{Section: "Hiddify Manager", Key: "admin", Shortcut: 'u', Title: "Admin URL", Hint: "Print panel admin URL"},
		{Section: "Hiddify Manager", Key: "apply", Shortcut: 'p', Title: "Apply config", Hint: "Run hiddify-apply-safe or panel apply"},
		{Section: "Proxy Services", Key: "socks", Shortcut: 'k', Title: "SOCKS5 (Dante)", Hint: "Manage SOCKS users and danted service"},
		{Section: "Proxy Services", Key: "trust", Shortcut: 'r', Title: "TrustTunnel", Hint: "Manage TrustTunnel users and service"},
		{Section: "Proxy Services", Key: "mtproxy", Shortcut: 'm', Title: "Telegram MTProxy", Hint: "Manage Telegram MTProxy service and secret"},
		{Section: "Tools", Key: "wizard", Shortcut: 'w', Title: "Flag command wizard", Hint: "Build and run existing psasctl commands with their original flags"},
		{Section: "Preferences", Key: "lang", Shortcut: 'g', Title: "Language", Hint: "Language and UI preferences"},
		{Section: "Session", Key: "exit", Shortcut: 'q', Title: "Exit", Hint: "Leave interactive mode"},
	}

	for {
		choice, err := uiSelectMenuItem(menuItems, in)
		if err != nil {
			if errors.Is(err, io.EOF) {
				clearScreen()
				return
			}
			fatalf("ui input error: %v", err)
		}
		if choice.Key == "exit" {
			clearScreen()
			return
		}

		clearScreen()
		printBoxedHeader(choice.Title)

		var actionErr error
		handledPause := false
		switch choice.Key {
		case "status":
			actionErr = uiStatus(c)
		case "list":
			actionErr = uiListUsers(c)
		case "find":
			actionErr = uiFindUsers(c, in)
		case "show":
			actionErr = uiShowUser(c, in)
		case "add":
			actionErr = uiAddUser(c, in)
		case "edit":
			actionErr = uiEditUser(c, in)
		case "delete":
			actionErr = uiDeleteUser(c, in)
		case "socks":
			actionErr = uiSocksProxy(in)
			handledPause = true
		case "trust":
			actionErr = uiTrustTunnel(in)
			handledPause = true
		case "mtproxy":
			actionErr = uiMTProxy(in)
			handledPause = true
		case "protocols":
			actionErr = uiProtocols(c, in)
		case "admin":
			actionErr = uiAdminURL(c)
		case "apply":
			if err := ensureHiddifyStateLoaded(c); err != nil {
				actionErr = err
			} else {
				actionErr = applyWithClient(c)
			}
		case "wizard":
			actionErr = uiRunFlagWizard(c, in)
		case "lang":
			actionErr = uiLanguageSettings(in)
		default:
			actionErr = fmt.Errorf("unknown option: %s", choice.Key)
		}

		if actionErr != nil {
			if errors.Is(actionErr, errUIExitRequested) {
				clearScreen()
				return
			}
			if errors.Is(actionErr, errUISelectionCanceled) {
				fmt.Println("\n" + uiText("Canceled."))
			} else {
				fmt.Printf("\n%s: %v\n", uiText("ERROR"), actionErr)
			}
		}
		if handledPause {
			continue
		}
		if err := uiPause(in); err != nil {
			if errors.Is(err, errUIExitRequested) {
				clearScreen()
				return
			}
			if errors.Is(err, io.EOF) {
				clearScreen()
				return
			}
			fatalf("ui input error: %v", err)
		}
	}
}

type uiMenuItem struct {
	Section  string
	Key      string
	Shortcut rune
	Title    string
	Hint     string
}

type uiMenuKey int

const (
	uiMenuKeyUnknown uiMenuKey = iota
	uiMenuKeyUp
	uiMenuKeyDown
	uiMenuKeyLeft
	uiMenuKeyRight
	uiMenuKeyHome
	uiMenuKeyEnd
	uiMenuKeyEnter
	uiMenuKeyQuit
	uiMenuKeyBackspace
	uiMenuKeyChar
)

type uiMenuInput struct {
	Key uiMenuKey
	Ch  rune
}

type terminalState struct {
	sttyMode string
}

// Simplified UI drawing functions
func printBoxedHeader(title string) {
	title = uiText(title)
	fmt.Println()
	fmt.Println(strings.ToUpper(title))
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()
}

func printSectionHeader(title string) {
	fmt.Printf("\n%s:\n", uiText(title))
}

func printInfo(msg string) {
	fmt.Printf("  %s\n", uiText(msg))
}

func printSuccess(msg string) {
	fmt.Printf("  OK: %s\n", uiText(msg))
}

func printError(msg string) {
	fmt.Printf("  %s: %s\n", uiText("ERROR"), uiText(msg))
}

func printSeparator() {
	fmt.Println(strings.Repeat("-", 60))
}

func uiSelectMenuItem(items []uiMenuItem, in *bufio.Reader) (uiMenuItem, error) {
	if len(items) == 0 {
		return uiMenuItem{}, errors.New("empty menu")
	}

	state, err := enterRawMode()
	if err != nil {
		return uiSelectMenuItemFallback(items, in)
	}
	defer state.restore()

	selected := 0
	typedNumber := ""
	rawIn := bufio.NewReader(os.Stdin)
	for {
		drawUIMenu(items, selected, typedNumber)
		input, err := readUIMenuKey(rawIn)
		if err != nil {
			return uiMenuItem{}, err
		}
		switch input.Key {
		case uiMenuKeyUp:
			typedNumber = ""
			selected--
			if selected < 0 {
				selected = len(items) - 1
			}
		case uiMenuKeyDown:
			typedNumber = ""
			selected++
			if selected >= len(items) {
				selected = 0
			}
		case uiMenuKeyHome:
			typedNumber = ""
			selected = 0
		case uiMenuKeyEnd:
			typedNumber = ""
			selected = len(items) - 1
		case uiMenuKeyBackspace:
			if len(typedNumber) > 0 {
				typedNumber = typedNumber[:len(typedNumber)-1]
			}
		case uiMenuKeyEnter:
			if typedNumber != "" {
				n, err := strconv.Atoi(typedNumber)
				if err == nil && n >= 1 && n <= len(items) {
					return items[n-1], nil
				}
				typedNumber = ""
				continue
			}
			return items[selected], nil
		case uiMenuKeyQuit:
			return uiMenuItem{Key: "exit", Title: "Exit"}, nil
		case uiMenuKeyChar:
			ch := unicode.ToLower(input.Ch)
			if ch >= '0' && ch <= '9' {
				maxDigits := len(strconv.Itoa(len(items)))
				if len(typedNumber) >= maxDigits {
					typedNumber = ""
				}
				typedNumber += string(ch)
				n, err := strconv.Atoi(typedNumber)
				if err == nil && n >= 1 && n <= len(items) {
					selected = n - 1
				}
				continue
			}
			typedNumber = ""
			switch ch {
			case 'k':
				selected--
				if selected < 0 {
					selected = len(items) - 1
				}
				continue
			case 'j':
				selected++
				if selected >= len(items) {
					selected = 0
				}
				continue
			case 'q':
				return uiMenuItem{Key: "exit", Title: "Exit"}, nil
			}
			if idx, ok := findMenuItemByShortcut(items, ch); ok {
				return items[idx], nil
			}
		}
	}
}

func uiSelectMenuItemFallback(items []uiMenuItem, in *bufio.Reader) (uiMenuItem, error) {
	clearScreen()

	fmt.Println()
	fmt.Println(uiText("PSASCTL - Interactive Menu"))
	fmt.Println("===========================")
	fmt.Println()

	lastSection := ""
	for i, item := range items {
		section := strings.TrimSpace(item.Section)
		if section != "" && section != lastSection {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("  [%s]\n", uiText(section))
			lastSection = section
		}
		fmt.Printf("  %d. %s\n", i+1, uiText(item.Title))
	}
	fmt.Println(uiText("  q. Exit"))

	for {
		raw, err := promptRequiredLine(in, uiTextf("\nEnter option number (1-%d)", len(items)))
		if err != nil {
			return uiMenuItem{}, err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return uiMenuItem{Key: "exit", Title: "Exit"}, nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > len(items) {
			printError(uiTextf("Invalid. Enter 1-%d or q", len(items)))
			continue
		}
		return items[n-1], nil
	}
}

func drawUIMenu(items []uiMenuItem, selected int, typedNumber string) {
	clearScreen()

	fmt.Println()
	fmt.Println(uiText("PSASCTL - Interactive Menu"))
	fmt.Println("===========================")
	fmt.Println()
	fmt.Println(uiText("Controls: Up/Down or j/k to navigate, Enter to select, q to quit"))
	fmt.Println(uiText("Quick select: Type number and press Enter, or use shortcut key"))
	fmt.Printf("%s: %s\n", uiText("Language"), currentUILang)
	if strings.TrimSpace(typedNumber) != "" {
		fmt.Printf("%s: %s\n", uiText("Selected number"), typedNumber)
	}
	fmt.Println(uiText("Sections: Hiddify Manager / Proxy Services / Tools / Preferences"))
	fmt.Println()

	lastSection := ""
	for i, item := range items {
		section := strings.TrimSpace(item.Section)
		if section != "" && section != lastSection {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("  [%s]\n", uiText(section))
			lastSection = section
		}

		prefix := "   "
		if i == selected {
			prefix = ">> "
		}

		shortcut := ""
		if item.Shortcut != 0 {
			shortcut = fmt.Sprintf(" [%c]", item.Shortcut)
		}

		fmt.Printf("%s%d. %s%s\n", prefix, i+1, uiText(item.Title), shortcut)
	}

	if selected >= 0 && selected < len(items) && items[selected].Hint != "" {
		fmt.Println()
		fmt.Printf("  * %s\n", uiText(items[selected].Hint))
	}
	fmt.Println()
}

func readUIMenuKey(in *bufio.Reader) (uiMenuInput, error) {
	b, err := in.ReadByte()
	if err != nil {
		return uiMenuInput{Key: uiMenuKeyUnknown}, err
	}
	switch b {
	case '\r', '\n':
		return uiMenuInput{Key: uiMenuKeyEnter}, nil
	case 3, 4:
		return uiMenuInput{Key: uiMenuKeyQuit}, nil
	case 8, 127:
		return uiMenuInput{Key: uiMenuKeyBackspace}, nil
	case 27:
		next, err := in.ReadByte()
		if err != nil {
			return uiMenuInput{Key: uiMenuKeyUnknown}, nil
		}
		if next != '[' && next != 'O' {
			return uiMenuInput{Key: uiMenuKeyUnknown}, nil
		}
		tail, err := in.ReadByte()
		if err != nil {
			return uiMenuInput{Key: uiMenuKeyUnknown}, nil
		}
		switch tail {
		case 'A':
			return uiMenuInput{Key: uiMenuKeyUp}, nil
		case 'B':
			return uiMenuInput{Key: uiMenuKeyDown}, nil
		case 'C':
			return uiMenuInput{Key: uiMenuKeyRight}, nil
		case 'D':
			return uiMenuInput{Key: uiMenuKeyLeft}, nil
		case 'H':
			return uiMenuInput{Key: uiMenuKeyHome}, nil
		case 'F':
			return uiMenuInput{Key: uiMenuKeyEnd}, nil
		case '1', '7':
			end, err := in.ReadByte()
			if err == nil && end == '~' {
				return uiMenuInput{Key: uiMenuKeyHome}, nil
			}
		case '4', '8':
			end, err := in.ReadByte()
			if err == nil && end == '~' {
				return uiMenuInput{Key: uiMenuKeyEnd}, nil
			}
		}
	}
	if b >= 32 && b <= 126 {
		return uiMenuInput{Key: uiMenuKeyChar, Ch: rune(b)}, nil
	}
	return uiMenuInput{Key: uiMenuKeyUnknown}, nil
}

func findMenuItemByShortcut(items []uiMenuItem, key rune) (int, bool) {
	for i, item := range items {
		if item.Shortcut == 0 {
			continue
		}
		if unicode.ToLower(item.Shortcut) == key {
			return i, true
		}
	}
	return 0, false
}

func enterRawMode() (*terminalState, error) {
	get := exec.Command("stty", "-g")
	get.Stdin = os.Stdin
	out, err := get.Output()
	if err != nil {
		return nil, err
	}
	mode := strings.TrimSpace(string(out))
	if mode == "" {
		return nil, errors.New("failed to read tty mode")
	}

	// FIX: `stty raw` часто отключает обработку вывода (-opost/-onlcr),
	// и тогда '\n' НЕ возвращает курсор в колонку 0, из-за чего UI "едет".
	// Включаем opost/onlcr обратно.
	set := exec.Command("stty", "raw", "-echo", "opost", "onlcr")
	set.Stdin = os.Stdin
	if err := set.Run(); err != nil {
		return nil, err
	}
	return &terminalState{sttyMode: mode}, nil
}

func (s *terminalState) restore() {
	if s == nil || strings.TrimSpace(s.sttyMode) == "" {
		return
	}
	set := exec.Command("stty", s.sttyMode)
	set.Stdin = os.Stdin
	_ = set.Run()
}

func clearScreen() {
	// Стандартнее: сначала очистить экран, потом переместиться домой
	fmt.Print("\033[2J\033[H")
}

func uiPause(in *bufio.Reader) error {
	fmt.Println()
	fmt.Println(strings.Repeat("-", 60))
	fmt.Print(uiText("Press Enter to return to menu (q to exit)..."))
	raw, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(raw), "q") {
		return errUIExitRequested
	}
	return nil
}

func uiLanguageSettings(in *bufio.Reader) error {
	current := normalizeUILang(currentUILang)
	if current == "" {
		current = defaultUILang
	}
	defaultIdx := 0
	if current == uiLangRU {
		defaultIdx = 1
	}
	choice, err := uiSelectOptionValue("Language", []uiOption{
		{Value: uiLangUS, Title: "us (default)", Hint: "English"},
		{Value: uiLangRU, Title: "ru", Hint: "Русский"},
	}, defaultIdx, in)
	if err != nil {
		return err
	}
	if err := setUILang(choice, true); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(uiTextf("Language set to: %s", choice))
	fmt.Println(uiTextf("Current language: %s", currentUILang))
	return nil
}

func uiRunFlagWizard(c *client, in *bufio.Reader) error {
	options := []uiOption{
		{Value: "status", Title: "status", Hint: "Supports --json"},
		{Value: "admin-url", Title: "admin-url", Hint: "Print admin panel URL"},
		{Value: "users-list", Title: "users list", Hint: "Supports --name, --enabled, --json"},
		{Value: "users-find", Title: "users find", Hint: "Supports --enabled, --json + QUERY"},
		{Value: "users-show", Title: "users show", Hint: "Supports --host, --json + USER_ID"},
		{Value: "users-links", Title: "users links", Hint: "Supports --host, --json + USER_ID"},
		{Value: "users-add", Title: "users add", Hint: "Supports --name, --days, --gb, --unlimited*, --true-unlimited*, --mode, --host, --uuid, --json"},
		{Value: "users-del", Title: "users del", Hint: "Delete by USER_ID"},
		{Value: "config-get", Title: "config get", Hint: "Get config by key"},
		{Value: "config-set", Title: "config set", Hint: "Set config key/value"},
		{Value: "trust-status", Title: "trust status", Hint: "Supports --json"},
		{Value: "trust-users-list", Title: "trust users list", Hint: "Supports --json"},
		{Value: "trust-users-add", Title: "trust users add", Hint: "Supports --name, --password, --show-config, --address, --json"},
		{Value: "trust-users-edit", Title: "trust users edit", Hint: "Supports --name, --password, --json + USER_ID"},
		{Value: "trust-users-show", Title: "trust users show", Hint: "Supports --show-config, --address, --json + USER_ID"},
		{Value: "trust-users-config", Title: "trust users config", Hint: "Supports --address, --out, --json + USER_ID"},
		{Value: "trust-users-del", Title: "trust users del", Hint: "Delete by USER_ID"},
		{Value: "trust-service", Title: "trust service", Hint: "Run status/start/stop/restart"},
		{Value: "socks-status", Title: "socks status", Hint: "Supports --json"},
		{Value: "socks-users-list", Title: "socks users list", Hint: "Supports --json"},
		{Value: "socks-users-add", Title: "socks users add", Hint: "Supports --name, --password, --show-config, --server, --port, --json"},
		{Value: "socks-users-edit", Title: "socks users edit", Hint: "Supports --name, --password, --json + USER_ID"},
		{Value: "socks-users-show", Title: "socks users show", Hint: "Supports --show-config, --server, --port, --json + USER_ID"},
		{Value: "socks-users-config", Title: "socks users config", Hint: "Supports --server, --port, --out, --json + USER_ID"},
		{Value: "socks-users-del", Title: "socks users del", Hint: "Delete by USER_ID"},
		{Value: "socks-service", Title: "socks service", Hint: "Run status/start/stop/restart"},
		{Value: "mtproxy-status", Title: "mtproxy status", Hint: "Supports --json"},
		{Value: "mtproxy-config", Title: "mtproxy config", Hint: "Supports --server, --port, --secret, --json"},
		{Value: "mtproxy-secret-show", Title: "mtproxy secret show", Hint: "Print current secret"},
		{Value: "mtproxy-secret-regen", Title: "mtproxy secret regen", Hint: "Generate new secret and restart service"},
		{Value: "mtproxy-service", Title: "mtproxy service", Hint: "Run status/start/stop/restart"},
		{Value: "apply", Title: "apply", Hint: "Apply config safely"},
	}

	choice, err := uiSelectOptionValue(uiText("Select command to build"), options, 0, in)
	if err != nil {
		return err
	}

	args, err := uiBuildWizardArgs(c, choice, in)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errUISelectionCanceled
	}

	fmt.Printf("\n%s: psasctl %s\n", uiText("Command"), quoteCommandArgs(args))
	runNow, err := promptYesNo(in, uiText("Run this command?"), true)
	if err != nil {
		return err
	}
	if !runNow {
		return errUISelectionCanceled
	}
	return runSelfCommand(args)
}

func uiBuildWizardArgs(c *client, choice string, in *bufio.Reader) ([]string, error) {
	switch choice {
	case "status":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"status"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "admin-url":
		return []string{"admin-url"}, nil
	case "users-list":
		name, err := promptLine(in, "Name contains (--name, optional)", "")
		if err != nil {
			return nil, err
		}
		enabledOnly, err := promptYesNo(in, "Only enabled users? (--enabled)", false)
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"users", "list"}
		if strings.TrimSpace(name) != "" {
			args = append(args, "--name", strings.TrimSpace(name))
		}
		if enabledOnly {
			args = append(args, "--enabled")
		}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "users-find":
		query, err := promptRequiredLine(in, "QUERY for users find")
		if err != nil {
			return nil, err
		}
		enabledOnly, err := promptYesNo(in, "Only enabled users? (--enabled)", false)
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"users", "find"}
		if enabledOnly {
			args = append(args, "--enabled")
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, query)
		return args, nil
	case "users-show":
		if err := ensureHiddifyStateLoaded(c); err != nil {
			return nil, err
		}
		u, err := uiPromptUserSelection(c, in, "Select user for users show", "USER_ID for users show")
		if err != nil {
			return nil, err
		}
		host, err := promptLine(in, "Host for links (--host, optional)", "")
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"users", "show"}
		if strings.TrimSpace(host) != "" {
			args = append(args, "--host", strings.TrimSpace(host))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, u.UUID)
		return args, nil
	case "users-links":
		if err := ensureHiddifyStateLoaded(c); err != nil {
			return nil, err
		}
		u, err := uiPromptUserSelection(c, in, "Select user for users links", "USER_ID for users links")
		if err != nil {
			return nil, err
		}
		host, err := promptLine(in, "Host for links (--host, optional)", "")
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"users", "links"}
		if strings.TrimSpace(host) != "" {
			args = append(args, "--host", strings.TrimSpace(host))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, u.UUID)
		return args, nil
	case "users-add":
		name, err := promptRequiredLine(in, "User name (--name)")
		if err != nil {
			return nil, err
		}
		trueUnlimitedAll, err := promptYesNo(in, "True unlimited traffic + time? (--true-unlimited)", false)
		if err != nil {
			return nil, err
		}
		unlimitedAll := false
		if !trueUnlimitedAll {
			unlimitedAll, err = promptYesNo(in, "Unlimited traffic + time? (--unlimited)", false)
			if err != nil {
				return nil, err
			}
		}
		useUnlimitedDays := false
		useUnlimitedGB := false
		days := 30
		gb := 100.0
		if !unlimitedAll && !trueUnlimitedAll {
			useUnlimitedDays, err = promptYesNo(in, fmt.Sprintf("Unlimited package time? (--unlimited-days = %d days)", unlimitedPackageDays), false)
			if err != nil {
				return nil, err
			}
			if !useUnlimitedDays {
				days, err = promptPositiveIntValue(in, "Package days (--days)", 30)
				if err != nil {
					return nil, err
				}
			}

			useUnlimitedGB, err = promptYesNo(in, fmt.Sprintf("Unlimited traffic? (--unlimited-gb = %.0f GB)", unlimitedUsageGB), false)
			if err != nil {
				return nil, err
			}
			if !useUnlimitedGB {
				gb, err = promptPositiveFloatValue(in, "Usage limit GB (--gb)", 100)
				if err != nil {
					return nil, err
				}
			}
		}
		mode, err := uiSelectMode(in)
		if err != nil {
			return nil, err
		}
		host, err := promptLine(in, "Host for links (--host, optional)", "")
		if err != nil {
			return nil, err
		}
		uuid, err := promptUUIDOptionalValue(in, "Custom UUID (--uuid, optional)")
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{
			"users", "add",
			"--name", name,
			"--mode", mode,
		}
		if trueUnlimitedAll {
			args = append(args, "--true-unlimited")
		} else if unlimitedAll {
			args = append(args, "--unlimited")
		} else {
			if useUnlimitedDays {
				args = append(args, "--unlimited-days")
			} else {
				args = append(args, "--days", strconv.Itoa(days))
			}
			if useUnlimitedGB {
				args = append(args, "--unlimited-gb")
			} else {
				args = append(args, "--gb", strconv.FormatFloat(gb, 'f', -1, 64))
			}
		}
		if strings.TrimSpace(host) != "" {
			args = append(args, "--host", strings.TrimSpace(host))
		}
		if uuid != "" {
			args = append(args, "--uuid", uuid)
		}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "users-del":
		if err := ensureHiddifyStateLoaded(c); err != nil {
			return nil, err
		}
		u, err := uiPromptUserSelection(c, in, "Select user for users del", "USER_ID for users del")
		if err != nil {
			return nil, err
		}
		return []string{"users", "del", u.UUID}, nil
	case "config-get":
		key, err := promptRequiredLine(in, "Config key")
		if err != nil {
			return nil, err
		}
		return []string{"config", "get", key}, nil
	case "config-set":
		key, err := promptRequiredLine(in, "Config key")
		if err != nil {
			return nil, err
		}
		value, err := promptRequiredLine(in, "Config value")
		if err != nil {
			return nil, err
		}
		return []string{"config", "set", key, value}, nil
	case "trust-status":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"trust", "status"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "trust-users-list":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"trust", "users", "list"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "trust-users-add":
		name, err := promptRequiredLine(in, "Username (--name)")
		if err != nil {
			return nil, err
		}
		password, err := promptLine(in, "Password (--password, optional)", "")
		if err != nil {
			return nil, err
		}
		showConfig, err := promptYesNo(in, "Generate config now? (--show-config)", false)
		if err != nil {
			return nil, err
		}
		address := ""
		if showConfig {
			address, err = promptLine(in, "Address ip[:port] (--address, optional)", "")
			if err != nil {
				return nil, err
			}
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"trust", "users", "add", "--name", strings.TrimSpace(name)}
		if strings.TrimSpace(password) != "" {
			args = append(args, "--password", strings.TrimSpace(password))
		}
		if showConfig {
			args = append(args, "--show-config")
		}
		if strings.TrimSpace(address) != "" {
			args = append(args, "--address", strings.TrimSpace(address))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "trust-users-edit":
		tt := newTrustClient()
		u, err := uiPromptTrustUserSelection(tt, in, "Select trust user for trust users edit", "USER_ID for trust users edit")
		if err != nil {
			return nil, err
		}
		name, err := promptLine(in, "New username (--name, optional)", "")
		if err != nil {
			return nil, err
		}
		password, err := promptLine(in, "New password (--password, optional)", "")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(name) == "" && strings.TrimSpace(password) == "" {
			return nil, errors.New("no changes requested: set --name and/or --password")
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"trust", "users", "edit"}
		if strings.TrimSpace(name) != "" {
			args = append(args, "--name", strings.TrimSpace(name))
		}
		if strings.TrimSpace(password) != "" {
			args = append(args, "--password", strings.TrimSpace(password))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, strings.TrimSpace(u.Username))
		return args, nil
	case "trust-users-show":
		tt := newTrustClient()
		u, err := uiPromptTrustUserSelection(tt, in, "Select trust user for trust users show", "USER_ID for trust users show")
		if err != nil {
			return nil, err
		}
		showConfig, err := promptYesNo(in, "Generate config now? (--show-config)", false)
		if err != nil {
			return nil, err
		}
		address := ""
		if showConfig {
			address, err = promptLine(in, "Address ip[:port] (--address, optional)", "")
			if err != nil {
				return nil, err
			}
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"trust", "users", "show"}
		if showConfig {
			args = append(args, "--show-config")
		}
		if strings.TrimSpace(address) != "" {
			args = append(args, "--address", strings.TrimSpace(address))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, strings.TrimSpace(u.Username))
		return args, nil
	case "trust-users-config":
		tt := newTrustClient()
		u, err := uiPromptTrustUserSelection(tt, in, "Select trust user for trust users config", "USER_ID for trust users config")
		if err != nil {
			return nil, err
		}
		address, err := promptLine(in, "Address ip[:port] (--address, optional)", "")
		if err != nil {
			return nil, err
		}
		outPath, err := promptLine(in, "Output file (--out, optional)", "")
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"trust", "users", "config"}
		if strings.TrimSpace(address) != "" {
			args = append(args, "--address", strings.TrimSpace(address))
		}
		if strings.TrimSpace(outPath) != "" {
			args = append(args, "--out", strings.TrimSpace(outPath))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, strings.TrimSpace(u.Username))
		return args, nil
	case "trust-users-del":
		tt := newTrustClient()
		u, err := uiPromptTrustUserSelection(tt, in, "Select trust user for trust users del", "USER_ID for trust users del")
		if err != nil {
			return nil, err
		}
		return []string{"trust", "users", "del", strings.TrimSpace(u.Username)}, nil
	case "trust-service":
		action, err := uiSelectOptionValue("TrustTunnel service action", []uiOption{
			{Value: "status", Title: "status", Hint: "Show systemctl status trusttunnel"},
			{Value: "start", Title: "start", Hint: "Start trusttunnel service"},
			{Value: "stop", Title: "stop", Hint: "Stop trusttunnel service"},
			{Value: "restart", Title: "restart", Hint: "Restart trusttunnel service"},
		}, 0, in)
		if err != nil {
			return nil, err
		}
		return []string{"trust", "service", action}, nil
	case "socks-status":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"socks", "status"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "socks-users-list":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"socks", "users", "list"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "socks-users-add":
		name, err := promptRequiredLine(in, "Login (--name)")
		if err != nil {
			return nil, err
		}
		password, err := promptLine(in, "Password (--password, optional)", "")
		if err != nil {
			return nil, err
		}
		showConfig, err := promptYesNo(in, "Print config now? (--show-config)", false)
		if err != nil {
			return nil, err
		}
		server := ""
		port := ""
		if showConfig {
			server, err = promptLine(in, "Server (--server, optional)", "")
			if err != nil {
				return nil, err
			}
			port, err = promptLine(in, "Port (--port, optional)", "")
			if err != nil {
				return nil, err
			}
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"socks", "users", "add", "--name", strings.TrimSpace(name)}
		if strings.TrimSpace(password) != "" {
			args = append(args, "--password", strings.TrimSpace(password))
		}
		if showConfig {
			args = append(args, "--show-config")
		}
		if strings.TrimSpace(server) != "" {
			args = append(args, "--server", strings.TrimSpace(server))
		}
		if p := strings.TrimSpace(port); p != "" {
			args = append(args, "--port", p)
		}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "socks-users-edit":
		sc := newSocksClient()
		u, err := uiPromptSocksUserSelection(sc, in, "Select socks user for socks users edit", "USER_ID for socks users edit")
		if err != nil {
			return nil, err
		}
		name, err := promptLine(in, "New login (--name, optional)", "")
		if err != nil {
			return nil, err
		}
		password, err := promptLine(in, "New password (--password, optional)", "")
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(name) == "" && strings.TrimSpace(password) == "" {
			return nil, errors.New("no changes requested: set --name and/or --password")
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"socks", "users", "edit"}
		if strings.TrimSpace(name) != "" {
			args = append(args, "--name", strings.TrimSpace(name))
		}
		if strings.TrimSpace(password) != "" {
			args = append(args, "--password", strings.TrimSpace(password))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, strings.TrimSpace(u.Name))
		return args, nil
	case "socks-users-show":
		sc := newSocksClient()
		u, err := uiPromptSocksUserSelection(sc, in, "Select socks user for socks users show", "USER_ID for socks users show")
		if err != nil {
			return nil, err
		}
		showConfig, err := promptYesNo(in, "Print config now? (--show-config)", false)
		if err != nil {
			return nil, err
		}
		server := ""
		port := ""
		if showConfig {
			server, err = promptLine(in, "Server (--server, optional)", "")
			if err != nil {
				return nil, err
			}
			port, err = promptLine(in, "Port (--port, optional)", "")
			if err != nil {
				return nil, err
			}
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"socks", "users", "show"}
		if showConfig {
			args = append(args, "--show-config")
		}
		if strings.TrimSpace(server) != "" {
			args = append(args, "--server", strings.TrimSpace(server))
		}
		if p := strings.TrimSpace(port); p != "" {
			args = append(args, "--port", p)
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, strings.TrimSpace(u.Name))
		return args, nil
	case "socks-users-config":
		sc := newSocksClient()
		u, err := uiPromptSocksUserSelection(sc, in, "Select socks user for socks users config", "USER_ID for socks users config")
		if err != nil {
			return nil, err
		}
		server, err := promptLine(in, "Server (--server, optional)", "")
		if err != nil {
			return nil, err
		}
		port, err := promptLine(in, "Port (--port, optional)", "")
		if err != nil {
			return nil, err
		}
		outPath, err := promptLine(in, "Output file (--out, optional)", "")
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"socks", "users", "config"}
		if strings.TrimSpace(server) != "" {
			args = append(args, "--server", strings.TrimSpace(server))
		}
		if p := strings.TrimSpace(port); p != "" {
			args = append(args, "--port", p)
		}
		if strings.TrimSpace(outPath) != "" {
			args = append(args, "--out", strings.TrimSpace(outPath))
		}
		if jsonOut {
			args = append(args, "--json")
		}
		args = append(args, strings.TrimSpace(u.Name))
		return args, nil
	case "socks-users-del":
		sc := newSocksClient()
		u, err := uiPromptSocksUserSelection(sc, in, "Select socks user for socks users del", "USER_ID for socks users del")
		if err != nil {
			return nil, err
		}
		return []string{"socks", "users", "del", strings.TrimSpace(u.Name)}, nil
	case "socks-service":
		action, err := uiSelectOptionValue("SOCKS service action", []uiOption{
			{Value: "status", Title: "status", Hint: "Show systemctl status danted"},
			{Value: "start", Title: "start", Hint: "Start danted service"},
			{Value: "stop", Title: "stop", Hint: "Stop danted service"},
			{Value: "restart", Title: "restart", Hint: "Restart danted service"},
		}, 0, in)
		if err != nil {
			return nil, err
		}
		return []string{"socks", "service", action}, nil
	case "mtproxy-status":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"mtproxy", "status"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "mtproxy-config":
		server, err := promptLine(in, "Server (--server, optional)", "")
		if err != nil {
			return nil, err
		}
		port, err := promptLine(in, "Port (--port, optional)", "")
		if err != nil {
			return nil, err
		}
		secret, err := promptLine(in, "Secret HEX32 (--secret, optional)", "")
		if err != nil {
			return nil, err
		}
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"mtproxy", "config"}
		if strings.TrimSpace(server) != "" {
			args = append(args, "--server", strings.TrimSpace(server))
		}
		if p := strings.TrimSpace(port); p != "" {
			args = append(args, "--port", p)
		}
		if s := strings.TrimSpace(secret); s != "" {
			args = append(args, "--secret", s)
		}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "mtproxy-secret-show":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"mtproxy", "secret", "show"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "mtproxy-secret-regen":
		jsonOut, err := promptYesNo(in, "Use --json output?", false)
		if err != nil {
			return nil, err
		}
		args := []string{"mtproxy", "secret", "regen"}
		if jsonOut {
			args = append(args, "--json")
		}
		return args, nil
	case "mtproxy-service":
		action, err := uiSelectOptionValue("MTProxy service action", []uiOption{
			{Value: "status", Title: "status", Hint: "Show systemctl status mtproxy"},
			{Value: "start", Title: "start", Hint: "Start mtproxy service"},
			{Value: "stop", Title: "stop", Hint: "Stop mtproxy service"},
			{Value: "restart", Title: "restart", Hint: "Restart mtproxy service"},
		}, 0, in)
		if err != nil {
			return nil, err
		}
		return []string{"mtproxy", "service", action}, nil
	case "apply":
		return []string{"apply"}, nil
	default:
		return nil, fmt.Errorf("unsupported wizard command: %s", choice)
	}
}

func promptYesNo(in *bufio.Reader, label string, def bool) (bool, error) {
	defRaw := "no"
	if def {
		defRaw = "yes"
	}
	suffix := " (yes/no)"
	if currentUILang == uiLangRU {
		suffix = " (yes/no, да/нет)"
		defRaw = "нет"
		if def {
			defRaw = "да"
		}
	}
	raw, err := promptLine(in, label+suffix, defRaw)
	if err != nil {
		return false, err
	}
	return isYes(raw), nil
}

func promptUUIDOptionalValue(in *bufio.Reader, label string) (string, error) {
	for {
		raw, err := promptLine(in, label, "")
		if err != nil {
			return "", err
		}
		id := strings.TrimSpace(raw)
		if id == "" {
			return "", nil
		}
		if err := validateUUID(id); err != nil {
			printError(err.Error())
			continue
		}
		return strings.ToLower(id), nil
	}
}

func runSelfCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("empty command")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return fmt.Errorf("command exited with code %d", exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func quoteCommandArgs(args []string) string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		out = append(out, quoteCommandArg(a))
	}
	return strings.Join(out, " ")
}

func quoteCommandArg(s string) string {
	if s == "" {
		return "''"
	}
	if isShellSafeWord(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func isShellSafeWord(s string) bool {
	for _, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '_', ch == '-', ch == '.', ch == '/', ch == ':', ch == '@':
		default:
			return false
		}
	}
	return true
}

type uiOption struct {
	Value string
	Title string
	Hint  string
}

func uiSelectMode(in *bufio.Reader) (string, error) {
	options := []uiOption{
		{Value: "no_reset", Title: "no_reset", Hint: "No periodic reset (recommended default)."},
		{Value: "daily", Title: "daily", Hint: "Reset usage every day."},
		{Value: "weekly", Title: "weekly", Hint: "Reset usage every week."},
		{Value: "monthly", Title: "monthly", Hint: "Reset usage every month."},
	}
	return uiSelectOptionValue("Select user mode", options, 0, in)
}

func uiSelectOptionValue(title string, options []uiOption, defaultIdx int, in *bufio.Reader) (string, error) {
	if len(options) == 0 {
		return "", errors.New("no options available")
	}
	if defaultIdx < 0 || defaultIdx >= len(options) {
		defaultIdx = 0
	}

	state, err := enterRawMode()
	if err != nil {
		return uiSelectOptionValueFallback(title, options, defaultIdx, in)
	}
	defer state.restore()

	selected := defaultIdx
	rawIn := bufio.NewReader(os.Stdin)
	for {
		drawUIOptionsMenu(title, options, selected)
		input, err := readUIMenuKey(rawIn)
		if err != nil {
			return "", err
		}
		switch input.Key {
		case uiMenuKeyUp:
			selected--
			if selected < 0 {
				selected = len(options) - 1
			}
		case uiMenuKeyDown:
			selected++
			if selected >= len(options) {
				selected = 0
			}
		case uiMenuKeyHome:
			selected = 0
		case uiMenuKeyEnd:
			selected = len(options) - 1
		case uiMenuKeyEnter:
			return options[selected].Value, nil
		case uiMenuKeyQuit:
			return "", errUISelectionCanceled
		case uiMenuKeyChar:
			ch := unicode.ToLower(input.Ch)
			switch ch {
			case 'k':
				selected--
				if selected < 0 {
					selected = len(options) - 1
				}
			case 'j':
				selected++
				if selected >= len(options) {
					selected = 0
				}
			case 'q':
				return "", errUISelectionCanceled
			default:
				if ch >= '1' && ch <= '9' {
					idx := int(ch - '1')
					if idx >= 0 && idx < len(options) {
						return options[idx].Value, nil
					}
				}
			}
		}
	}
}

func uiSelectOptionValueFallback(title string, options []uiOption, defaultIdx int, in *bufio.Reader) (string, error) {
	clearScreen()
	title = uiText(title)

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()

	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, uiText(opt.Title))
	}
	fmt.Println(uiText("  q. Cancel"))

	def := strconv.Itoa(defaultIdx + 1)
	for {
		raw, err := promptLine(in, uiText("\nEnter option number"), def)
		if err != nil {
			return "", err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return "", errUISelectionCanceled
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > len(options) {
			printError(uiTextf("Invalid. Enter 1-%d or q", len(options)))
			continue
		}
		return options[n-1].Value, nil
	}
}

func drawUIOptionsMenu(title string, options []uiOption, selected int) {
	clearScreen()
	title = uiText(title)

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()
	fmt.Println(uiText("Controls: Up/Down or j/k, Enter to select, q to cancel"))
	fmt.Println()

	for i, opt := range options {
		prefix := "   "
		if i == selected {
			prefix = ">> "
		}
		fmt.Printf("%s%d. %s\n", prefix, i+1, uiText(opt.Title))
	}

	if selected >= 0 && selected < len(options) && options[selected].Hint != "" {
		fmt.Println()
		fmt.Printf("  * %s\n", uiText(options[selected].Hint))
	}
	fmt.Println()
}

func uiPromptUserSelection(c *client, in *bufio.Reader, title, manualLabel string) (apiUser, error) {
	users, err := c.usersList()
	if err != nil {
		return apiUser{}, err
	}
	if len(users) == 0 {
		return apiUser{}, errors.New("no users in panel")
	}

	u, err := uiSelectUser(users, title, in)
	if err == nil {
		return u, nil
	}
	if errors.Is(err, errUIManualEntry) {
		id, perr := promptRequiredLine(in, manualLabel)
		if perr != nil {
			return apiUser{}, perr
		}
		return c.resolveUser(id)
	}
	return apiUser{}, err
}

func uiSelectUser(users []apiUser, title string, in *bufio.Reader) (apiUser, error) {
	if len(users) == 0 {
		return apiUser{}, errors.New("no users in panel")
	}

	state, err := enterRawMode()
	if err != nil {
		return uiSelectUserFallback(users, title, in)
	}
	defer state.restore()

	query := ""
	selected := 0
	rawIn := bufio.NewReader(os.Stdin)
	for {
		filtered := filterUsersForPicker(users, query)
		if len(filtered) == 0 {
			selected = 0
		} else if selected >= len(filtered) {
			selected = len(filtered) - 1
		}

		drawUIUserPicker(title, users, filtered, selected, query)

		input, err := readUIMenuKey(rawIn)
		if err != nil {
			return apiUser{}, err
		}
		switch input.Key {
		case uiMenuKeyUp:
			if len(filtered) == 0 {
				continue
			}
			selected--
			if selected < 0 {
				selected = len(filtered) - 1
			}
		case uiMenuKeyDown:
			if len(filtered) == 0 {
				continue
			}
			selected++
			if selected >= len(filtered) {
				selected = 0
			}
		case uiMenuKeyHome:
			selected = 0
		case uiMenuKeyEnd:
			if len(filtered) > 0 {
				selected = len(filtered) - 1
			}
		case uiMenuKeyBackspace:
			query = trimLastRune(query)
		case uiMenuKeyEnter:
			if len(filtered) == 0 {
				continue
			}
			return filtered[selected], nil
		case uiMenuKeyQuit:
			return apiUser{}, errUISelectionCanceled
		case uiMenuKeyChar:
			ch := unicode.ToLower(input.Ch)
			switch ch {
			case 'k':
				if len(filtered) == 0 {
					continue
				}
				selected--
				if selected < 0 {
					selected = len(filtered) - 1
				}
			case 'j':
				if len(filtered) == 0 {
					continue
				}
				selected++
				if selected >= len(filtered) {
					selected = 0
				}
			case 'q':
				return apiUser{}, errUISelectionCanceled
			case 'i':
				return apiUser{}, errUIManualEntry
			default:
				query += string(input.Ch)
			}
		}
	}
}

func uiSelectUserFallback(users []apiUser, title string, in *bufio.Reader) (apiUser, error) {
	clearScreen()
	title = uiText(title)

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()

	for i, u := range users {
		status := "OFF"
		if u.Enable {
			status = "ON"
		}
		name := u.Name
		if len(name) > 20 {
			name = name[:17] + "..."
		}
		fmt.Printf("  %d. %-20s %s [%s]\n", i+1, name, u.UUID, status)
	}
	fmt.Println(uiText("  0. Manual USER_ID input"))
	fmt.Println(uiText("  q. Cancel"))

	for {
		raw, err := promptRequiredLine(in, uiText("Enter user number"))
		if err != nil {
			return apiUser{}, err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return apiUser{}, errUISelectionCanceled
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > len(users) {
			printError(uiTextf("Invalid. Enter 0-%d or q", len(users)))
			continue
		}
		if n == 0 {
			return apiUser{}, errUIManualEntry
		}
		return users[n-1], nil
	}
}

func drawUIUserPicker(title string, users, filtered []apiUser, selected int, query string) {
	clearScreen()
	title = uiText(title)

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()
	fmt.Println(uiText("Controls: Up/Down to navigate, Enter to select, Type to filter"))
	fmt.Println(uiText("          Backspace to erase, i for manual input, q to cancel"))
	fmt.Println()
	fmt.Printf("%s\n", uiTextf("Filter: %s", query))
	fmt.Printf("%s\n", uiTextf("Showing: %d / %d users", len(filtered), len(users)))
	fmt.Println(strings.Repeat("-", 60))

	if len(filtered) == 0 {
		fmt.Println("  " + uiText("No users match current filter"))
		return
	}

	const pageSize = 12
	start := 0
	if selected >= pageSize {
		start = selected - pageSize + 1
	}
	if start+pageSize > len(filtered) {
		start = len(filtered) - pageSize
		if start < 0 {
			start = 0
		}
	}
	end := min(len(filtered), start+pageSize)

	fmt.Println()
	for i := start; i < end; i++ {
		u := filtered[i]
		prefix := "   "
		if i == selected {
			prefix = ">> "
		}

		status := "OFF"
		if u.Enable {
			status = "ON "
		}

		name := u.Name
		if len(name) > 20 {
			name = name[:17] + "..."
		}

		fmt.Printf("%s%-20s  %s  [%s]\n", prefix, name, u.UUID, status)
	}

	if end < len(filtered) {
		fmt.Printf("\n  %s\n", uiTextf("(Showing %d-%d of %d)", start+1, end, len(filtered)))
	}
	fmt.Println()
}

func filterUsersForPicker(users []apiUser, query string) []apiUser {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return users
	}
	out := make([]apiUser, 0, len(users))
	for _, u := range users {
		name := strings.ToLower(strings.TrimSpace(u.Name))
		id := strings.ToLower(strings.TrimSpace(u.UUID))
		if strings.Contains(name, q) || strings.Contains(id, q) {
			out = append(out, u)
		}
	}
	return out
}

func trimLastRune(s string) string {
	r := []rune(s)
	if len(r) == 0 {
		return s
	}
	return string(r[:len(r)-1])
}

func uiPromptTrustUserSelection(tt *trustClient, in *bufio.Reader, title, manualLabel string) (trustUser, error) {
	users, err := tt.usersList()
	if err != nil {
		return trustUser{}, err
	}
	if len(users) == 0 {
		return trustUser{}, errors.New("no TrustTunnel users")
	}

	u, err := uiSelectTrustUser(users, title, in)
	if err == nil {
		return u, nil
	}
	if errors.Is(err, errUIManualEntry) {
		id, perr := promptRequiredLine(in, manualLabel)
		if perr != nil {
			return trustUser{}, perr
		}
		u, _, rerr := resolveTrustUser(users, id)
		return u, rerr
	}
	return trustUser{}, err
}

func uiPromptSocksUserSelection(sc *socksClient, in *bufio.Reader, title, manualLabel string) (socksUser, error) {
	users, err := sc.usersList()
	if err != nil {
		return socksUser{}, err
	}
	if len(users) == 0 {
		return socksUser{}, errors.New("no SOCKS users")
	}

	shadow := make([]trustUser, 0, len(users))
	index := map[string]socksUser{}
	for _, u := range users {
		shadow = append(shadow, trustUser{Username: u.Name, Password: u.Password})
		index[strings.ToLower(strings.TrimSpace(u.Name))] = u
	}

	picked, err := uiSelectTrustUser(shadow, title, in)
	if err == nil {
		if u, ok := index[strings.ToLower(strings.TrimSpace(picked.Username))]; ok {
			return u, nil
		}
	}
	if errors.Is(err, errUIManualEntry) {
		id, perr := promptRequiredLine(in, manualLabel)
		if perr != nil {
			return socksUser{}, perr
		}
		u, _, rerr := resolveSocksUser(users, id)
		return u, rerr
	}
	if err == nil {
		return socksUser{}, errors.New("selected SOCKS user not found")
	}
	return socksUser{}, err
}

func uiSelectTrustUser(users []trustUser, title string, in *bufio.Reader) (trustUser, error) {
	if len(users) == 0 {
		return trustUser{}, errors.New("no TrustTunnel users")
	}

	state, err := enterRawMode()
	if err != nil {
		return uiSelectTrustUserFallback(users, title, in)
	}
	defer state.restore()

	query := ""
	selected := 0
	rawIn := bufio.NewReader(os.Stdin)
	for {
		filtered := filterTrustUsersForPicker(users, query)
		if len(filtered) == 0 {
			selected = 0
		} else if selected >= len(filtered) {
			selected = len(filtered) - 1
		}

		drawUITrustUserPicker(title, users, filtered, selected, query)

		input, err := readUIMenuKey(rawIn)
		if err != nil {
			return trustUser{}, err
		}
		switch input.Key {
		case uiMenuKeyUp:
			if len(filtered) == 0 {
				continue
			}
			selected--
			if selected < 0 {
				selected = len(filtered) - 1
			}
		case uiMenuKeyDown:
			if len(filtered) == 0 {
				continue
			}
			selected++
			if selected >= len(filtered) {
				selected = 0
			}
		case uiMenuKeyHome:
			selected = 0
		case uiMenuKeyEnd:
			if len(filtered) > 0 {
				selected = len(filtered) - 1
			}
		case uiMenuKeyBackspace:
			query = trimLastRune(query)
		case uiMenuKeyEnter:
			if len(filtered) == 0 {
				continue
			}
			return filtered[selected], nil
		case uiMenuKeyQuit:
			return trustUser{}, errUISelectionCanceled
		case uiMenuKeyChar:
			ch := unicode.ToLower(input.Ch)
			switch ch {
			case 'k':
				if len(filtered) == 0 {
					continue
				}
				selected--
				if selected < 0 {
					selected = len(filtered) - 1
				}
			case 'j':
				if len(filtered) == 0 {
					continue
				}
				selected++
				if selected >= len(filtered) {
					selected = 0
				}
			case 'q':
				return trustUser{}, errUISelectionCanceled
			case 'i':
				return trustUser{}, errUIManualEntry
			default:
				query += string(input.Ch)
			}
		}
	}
}

func uiSelectTrustUserFallback(users []trustUser, title string, in *bufio.Reader) (trustUser, error) {
	clearScreen()
	title = uiText(title)

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()

	for i, u := range users {
		fmt.Printf("  %d. %-24s %s\n", i+1, u.Username, maskSecret(u.Password))
	}
	fmt.Println(uiText("  0. Manual USER_ID input"))
	fmt.Println(uiText("  q. Cancel"))

	for {
		raw, err := promptRequiredLine(in, uiText("Enter user number"))
		if err != nil {
			return trustUser{}, err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return trustUser{}, errUISelectionCanceled
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > len(users) {
			printError(uiTextf("Invalid. Enter 0-%d or q", len(users)))
			continue
		}
		if n == 0 {
			return trustUser{}, errUIManualEntry
		}
		return users[n-1], nil
	}
}

func drawUITrustUserPicker(title string, users, filtered []trustUser, selected int, query string) {
	clearScreen()
	title = uiText(title)

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()
	fmt.Println(uiText("Controls: Up/Down to navigate, Enter to select, Type to filter"))
	fmt.Println(uiText("          Backspace to erase, i for manual input, q to cancel"))
	fmt.Println()
	fmt.Printf("%s\n", uiTextf("Filter: %s", query))
	fmt.Printf("%s\n", uiTextf("Showing: %d / %d users", len(filtered), len(users)))
	fmt.Println(strings.Repeat("-", 60))

	if len(filtered) == 0 {
		fmt.Println("  " + uiText("No users match current filter"))
		return
	}

	const pageSize = 12
	start := 0
	if selected >= pageSize {
		start = selected - pageSize + 1
	}
	if start+pageSize > len(filtered) {
		start = len(filtered) - pageSize
		if start < 0 {
			start = 0
		}
	}
	end := min(len(filtered), start+pageSize)

	fmt.Println()
	for i := start; i < end; i++ {
		u := filtered[i]
		prefix := "   "
		if i == selected {
			prefix = ">> "
		}
		name := u.Username
		if len(name) > 24 {
			name = name[:21] + "..."
		}
		fmt.Printf("%s%-24s  %s\n", prefix, name, maskSecret(u.Password))
	}

	if end < len(filtered) {
		fmt.Printf("\n  %s\n", uiTextf("(Showing %d-%d of %d)", start+1, end, len(filtered)))
	}
	fmt.Println()
}

func filterTrustUsersForPicker(users []trustUser, query string) []trustUser {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return users
	}
	out := make([]trustUser, 0, len(users))
	for _, u := range users {
		name := strings.ToLower(strings.TrimSpace(u.Username))
		if strings.Contains(name, q) {
			out = append(out, u)
		}
	}
	return out
}

func findTrustUserIndex(users []trustUser, username string) int {
	for i, u := range users {
		if strings.EqualFold(strings.TrimSpace(u.Username), strings.TrimSpace(username)) {
			return i
		}
	}
	return -1
}

func uiStatus(c *client) error {
	if err := c.loadState(); err != nil {
		return err
	}
	cfg := c.currentConfig()
	mainDomain := c.mainDomain()

	fmt.Println()
	fmt.Println(uiText("System Status"))
	fmt.Println("=============")
	fmt.Printf("%-20s: %s\n", uiText("Main domain"), mainDomain)
	fmt.Printf("%-20s: %s\n", uiText("Admin URL"), c.adminURL(mainDomain))
	fmt.Printf("%-20s: %v\n", uiText("Client path"), cfg["proxy_path_client"])
	fmt.Printf("%-20s: %v\n", uiText("Reality enabled"), cfg["reality_enable"])
	fmt.Printf("%-20s: %v\n", uiText("Hysteria2 enabled"), cfg["hysteria_enable"])
	fmt.Printf("%-20s: %v\n", uiText("Hysteria base port"), cfg["hysteria_port"])
	fmt.Printf("%-20s: %v\n", uiText("Reality SNI"), cfg["reality_server_names"])
	fmt.Printf("%-20s: %d\n", uiText("Users"), len(c.state.Users))
	if tt, err := newTrustClient().status(); err == nil {
		fmt.Printf("%s: %t\n", uiText("TrustTunnel installed"), tt.Installed)
		if tt.Installed {
			fmt.Printf("%s: %t\n", uiText("TrustTunnel active"), tt.ServiceActive)
			fmt.Printf("%s: %s\n", uiText("TrustTunnel listen"), tt.ListenAddress)
			fmt.Printf("%s: %d\n", uiText("TrustTunnel users"), tt.Users)
		}
	}
	if mtp, err := newMTProxyClient().status(); err == nil {
		fmt.Printf("%s: %t\n", uiText("MTProxy installed"), mtp.Installed)
		if mtp.Installed {
			fmt.Printf("%s: %t\n", uiText("MTProxy active"), mtp.ServiceActive)
			if mtp.Server != "" && mtp.ListenPort > 0 {
				fmt.Printf("%s: %s:%d\n", uiText("MTProxy endpoint"), mtp.Server, mtp.ListenPort)
			}
		}
	}
	if sc, err := newSocksClient().status(); err == nil {
		fmt.Printf("%s: %t\n", uiText("SOCKS installed"), sc.Installed)
		if sc.Installed {
			fmt.Printf("%s: %t\n", uiText("SOCKS active"), sc.ServiceActive)
			fmt.Printf("%s: %s\n", uiText("SOCKS listen"), sc.ListenAddress)
			fmt.Printf("%s: %d\n", uiText("SOCKS users"), sc.Users)
		}
	}
	return nil
}

func uiListUsers(c *client) error {
	if err := c.loadState(); err != nil {
		return err
	}
	users, err := c.usersList()
	if err != nil {
		return err
	}
	printUsers(users)
	return nil
}

func uiFindUsers(c *client, in *bufio.Reader) error {
	if err := c.loadState(); err != nil {
		return err
	}
	query, err := promptRequiredLine(in, "Find by name/part")
	if err != nil {
		return err
	}
	enabledRaw, err := promptLine(in, "Only enabled? (y/N)", "n")
	if err != nil {
		return err
	}
	users, err := c.usersList()
	if err != nil {
		return err
	}
	users = filterUsers(users, query, isYes(enabledRaw))
	if len(users) == 0 {
		fmt.Println("\n" + uiText("No users found."))
		return nil
	}
	printUsers(users)
	return nil
}

func uiShowUser(c *client, in *bufio.Reader) error {
	if err := c.loadState(); err != nil {
		return err
	}
	u, err := uiPromptUserSelection(c, in, "Select user for details and links", "USER_ID (UUID or name)")
	if err != nil {
		return err
	}
	host, err := promptLine(in, "Host for links (empty = main domain)", "")
	if err != nil {
		return err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host, err = c.mainDomainOrErr()
		if err != nil {
			return err
		}
	}
	links := buildLinks(c.clientPath(), u.UUID, host)
	printUser(u)
	fmt.Println()
	printLinksFromSet(links)
	return nil
}

func uiAddUser(c *client, in *bufio.Reader) error {
	if err := c.loadState(); err != nil {
		return err
	}

	name, err := promptRequiredLine(in, "User name")
	if err != nil {
		return err
	}

	trueUnlimitedAll, err := promptYesNo(in, "True unlimited traffic + time? (patches Hiddify once)", false)
	if err != nil {
		return err
	}
	needsTrueUnlimitedPatch := false
	unlimitedAll := false
	days := 30
	gb := 100.0
	if trueUnlimitedAll {
		days = unlimitedPackageDays
		gb = unlimitedUsageGB
		needsTrueUnlimitedPatch = true
	} else {
		unlimitedAll, err = promptYesNo(in, "Unlimited traffic + time?", false)
		if err != nil {
			return err
		}
	}
	if trueUnlimitedAll {
		// already set above
	} else if unlimitedAll {
		days = unlimitedPackageDays
		gb = unlimitedUsageGB
	} else {
		useUnlimitedDays, derr := promptYesNo(in, fmt.Sprintf("Unlimited package time? (%d days)", unlimitedPackageDays), false)
		if derr != nil {
			return derr
		}
		if useUnlimitedDays {
			days = unlimitedPackageDays
		} else {
			days, derr = promptPositiveIntValue(in, "Package days", 30)
			if derr != nil {
				return derr
			}
		}

		useUnlimitedGB, gerr := promptYesNo(in, fmt.Sprintf("Unlimited traffic? (%.0f GB)", unlimitedUsageGB), false)
		if gerr != nil {
			return gerr
		}
		if useUnlimitedGB {
			gb = unlimitedUsageGB
		} else {
			gb, gerr = promptPositiveFloatValue(in, "Usage limit (GB)", 100)
			if gerr != nil {
				return gerr
			}
		}
	}

	mode, err := uiSelectMode(in)
	if err != nil {
		return err
	}

	id, err := promptUUIDOrAuto(in, "Custom UUID (empty = auto)")
	if err != nil {
		return err
	}

	host, err := promptLine(in, "Host for links (empty = main domain)", "")
	if err != nil {
		return err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host, err = c.mainDomainOrErr()
		if err != nil {
			return err
		}
	}

	payload := map[string]any{
		"uuid":           id,
		"name":           name,
		"package_days":   days,
		"usage_limit_GB": gb,
		"mode":           mode,
		"enable":         true,
	}
	if needsTrueUnlimitedPatch {
		if err := c.ensureTrueUnlimitedSupport(); err != nil {
			return err
		}
	}
	u, err := c.userAdd(payload)
	if err != nil {
		return err
	}
	links := buildLinks(c.clientPath(), u.UUID, host)
	fmt.Println("\n" + uiText("User created successfully!"))
	printLinksFromSet(links)
	return nil
}

func uiEditUser(c *client, in *bufio.Reader) error {
	if err := c.loadState(); err != nil {
		return err
	}

	u, err := uiPromptUserSelection(c, in, "Select user to edit", "USER_ID to edit (UUID or name)")
	if err != nil {
		return err
	}

	payload := map[string]any{}
	changed := false
	needsTrueUnlimitedPatch := false

	name, err := promptLine(in, fmt.Sprintf("Subscription/user name (empty = keep: %s)", u.Name), "")
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	if name != "" && name != u.Name {
		payload["name"] = name
		changed = true
	}

	changeLimits, err := promptYesNo(in, "Change traffic/time limits?", false)
	if err != nil {
		return err
	}
	if changeLimits {
		trueUnlimitedAll, terr := promptYesNo(in, "True unlimited traffic + time? (patches Hiddify once)", false)
		if terr != nil {
			return terr
		}
		if trueUnlimitedAll {
			payload["package_days"] = unlimitedPackageDays
			payload["usage_limit_GB"] = unlimitedUsageGB
			changed = true
			needsTrueUnlimitedPatch = true
		} else {
			unlimitedAll, uerr := promptYesNo(in, "Practical unlimited traffic + time?", false)
			if uerr != nil {
				return uerr
			}
			if unlimitedAll {
				payload["package_days"] = unlimitedPackageDays
				payload["usage_limit_GB"] = unlimitedUsageGB
				changed = true
			} else {
				daysAction, derr := uiSelectOptionValue("Package days", []uiOption{
					{Value: "keep", Title: fmt.Sprintf("Keep (%d days)", u.PackageDays), Hint: "Do not change package days"},
					{Value: "set", Title: "Set custom days", Hint: "Enter a specific positive number of days"},
					{Value: "unlimited", Title: fmt.Sprintf("Practical unlimited (%d days)", unlimitedPackageDays), Hint: "Set to large value"},
					{Value: "true-unlimited", Title: "True unlimited days", Hint: "Set unlimited logic in patched Hiddify"},
				}, 0, in)
				if derr != nil {
					return derr
				}
				switch daysAction {
				case "set":
					days, perr := promptPositiveIntValue(in, "Package days", max(1, u.PackageDays))
					if perr != nil {
						return perr
					}
					payload["package_days"] = days
					changed = true
				case "unlimited":
					payload["package_days"] = unlimitedPackageDays
					changed = true
				case "true-unlimited":
					payload["package_days"] = unlimitedPackageDays
					changed = true
					needsTrueUnlimitedPatch = true
				}

				gbAction, gerr := uiSelectOptionValue("Traffic limit", []uiOption{
					{Value: "keep", Title: fmt.Sprintf("Keep (%.2f GB)", u.UsageLimitGB), Hint: "Do not change usage limit"},
					{Value: "set", Title: "Set custom GB", Hint: "Enter a specific positive traffic limit"},
					{Value: "unlimited", Title: fmt.Sprintf("Practical unlimited (%.0f GB)", unlimitedUsageGB), Hint: "Set to large value"},
					{Value: "true-unlimited", Title: "True unlimited traffic", Hint: "Set unlimited logic in patched Hiddify"},
				}, 0, in)
				if gerr != nil {
					return gerr
				}
				switch gbAction {
				case "set":
					defGB := u.UsageLimitGB
					if defGB <= 0 {
						defGB = 1
					}
					gb, perr := promptPositiveFloatValue(in, "Usage limit (GB)", defGB)
					if perr != nil {
						return perr
					}
					payload["usage_limit_GB"] = gb
					changed = true
				case "unlimited":
					payload["usage_limit_GB"] = unlimitedUsageGB
					changed = true
				case "true-unlimited":
					payload["usage_limit_GB"] = unlimitedUsageGB
					changed = true
					needsTrueUnlimitedPatch = true
				}
			}
		}
	}

	modeChoice, merr := uiSelectOptionValue("User mode", []uiOption{
		{Value: "keep", Title: fmt.Sprintf("Keep (%s)", u.Mode), Hint: "Do not change user mode"},
		{Value: "no_reset", Title: "no_reset", Hint: "No periodic reset"},
		{Value: "daily", Title: "daily", Hint: "Reset usage every day"},
		{Value: "weekly", Title: "weekly", Hint: "Reset usage every week"},
		{Value: "monthly", Title: "monthly", Hint: "Reset usage every month"},
	}, 0, in)
	if merr != nil {
		return merr
	}
	if modeChoice != "keep" && modeChoice != u.Mode {
		payload["mode"] = modeChoice
		changed = true
	}

	stateText := "OFF"
	if u.Enable {
		stateText = "ON"
	}
	enableChoice, eerr := uiSelectOptionValue("Enabled state", []uiOption{
		{Value: "keep", Title: fmt.Sprintf("Keep (%s)", stateText), Hint: "Do not change enable state"},
		{Value: "enable", Title: "Enable", Hint: "Force user enabled"},
		{Value: "disable", Title: "Disable", Hint: "Force user disabled"},
	}, 0, in)
	if eerr != nil {
		return eerr
	}
	if enableChoice == "enable" && !u.Enable {
		payload["enable"] = true
		changed = true
	}
	if enableChoice == "disable" && u.Enable {
		payload["enable"] = false
		changed = true
	}

	if !changed {
		fmt.Println("\nNo changes requested.")
		return nil
	}

	if needsTrueUnlimitedPatch {
		if err := c.ensureTrueUnlimitedSupport(); err != nil {
			return err
		}
	}

	updated, err := c.userPatch(u.UUID, payload)
	if err != nil {
		return err
	}

	host, err := promptLine(in, "Host for links (empty = main domain)", "")
	if err != nil {
		return err
	}
	host = strings.TrimSpace(host)
	if host == "" {
		host, err = c.mainDomainOrErr()
		if err != nil {
			return err
		}
	}

	links := buildLinks(c.clientPath(), updated.UUID, host)
	fmt.Println("\nUser updated successfully!")
	printUser(updated)
	fmt.Println()
	printLinksFromSet(links)
	return nil
}

func uiProtocols(c *client, in *bufio.Reader) error {
	if err := c.loadState(); err != nil {
		return err
	}

	printSectionHeader("Protocols")
	printProtocolStatesTable(protocolStates(c.currentConfig()))

	for {
		action, err := uiSelectOptionValue("Protocol action", []uiOption{
			{Value: "list", Title: "List protocols", Hint: "Show current protocol enabled flags"},
			{Value: "enable", Title: "Enable protocol", Hint: "Set one protocol key to true"},
			{Value: "disable", Title: "Disable protocol", Hint: "Set one protocol key to false"},
			{Value: "set", Title: "Set protocol value", Hint: "Set protocol via on/off/true/false/1/0"},
			{Value: "back", Title: "Back", Hint: "Return to main menu"},
		}, 0, in)
		if err != nil {
			if errors.Is(err, errUISelectionCanceled) {
				return nil
			}
			return err
		}

		switch action {
		case "back":
			return nil
		case "list":
			if err := c.loadState(); err != nil {
				return err
			}
			fmt.Println()
			printProtocolStatesTable(protocolStates(c.currentConfig()))
			fmt.Println()
			fmt.Print("Press Enter to continue (q to back)...")
			raw, rerr := in.ReadString('\n')
			if rerr != nil && !errors.Is(rerr, io.EOF) {
				return rerr
			}
			if strings.EqualFold(strings.TrimSpace(raw), "q") {
				return nil
			}
		case "enable", "disable", "set":
			if err := c.loadState(); err != nil {
				return err
			}
			p, perr := uiSelectProtocol(c, in, "Select protocol")
			if perr != nil {
				if errors.Is(perr, errUISelectionCanceled) {
					continue
				}
				return perr
			}

			newValue := false
			switch action {
			case "enable":
				newValue = true
			case "disable":
				newValue = false
			case "set":
				raw, rerr := promptRequiredLine(in, "Value (on/off/true/false/1/0)")
				if rerr != nil {
					return rerr
				}
				parsed, perr := parseBoolLike(raw)
				if perr != nil {
					return perr
				}
				newValue = parsed
			}

			if err := c.setConfig(p.Key, strconv.FormatBool(newValue)); err != nil {
				return err
			}
			fmt.Printf("\nProtocol %s (%s) set to %t\n", p.Name, p.Key, newValue)

			applyNow, aerr := promptYesNo(in, "Apply config now?", false)
			if aerr != nil {
				return aerr
			}
			if applyNow {
				if err := applyWithClient(c); err != nil {
					return err
				}
			}

			if err := c.loadState(); err != nil {
				return err
			}
			fmt.Println()
			printProtocolStatesTable(protocolStates(c.currentConfig()))
		}
	}
}

func uiSelectProtocol(c *client, in *bufio.Reader, title string) (protocolSetting, error) {
	items := protocolStates(c.currentConfig())
	if len(items) == 0 {
		return protocolSetting{}, errors.New("no protocols available")
	}

	options := make([]uiOption, 0, len(items))
	for _, item := range items {
		status := "OFF"
		if item.Enabled {
			status = "ON"
		}
		options = append(options, uiOption{
			Value: item.Key,
			Title: fmt.Sprintf("%s [%s]", item.Name, status),
			Hint:  item.Key,
		})
	}

	choice, err := uiSelectOptionValue(title, options, 0, in)
	if err != nil {
		return protocolSetting{}, err
	}
	return resolveProtocolSetting(choice)
}

func uiDeleteUser(c *client, in *bufio.Reader) error {
	if err := c.loadState(); err != nil {
		return err
	}
	u, err := uiPromptUserSelection(c, in, "Select user to delete", "USER_ID to delete (UUID or name)")
	if err != nil {
		return err
	}

	fmt.Printf("\nAbout to delete: %s (%s)\n", u.UUID, u.Name)
	confirm, err := promptYesNo(in, "Confirm delete?", false)
	if err != nil {
		return err
	}
	if !confirm {
		fmt.Println(uiText("Canceled."))
		return nil
	}
	if err := c.userDelete(u.UUID); err != nil {
		return err
	}
	fmt.Printf("\nDeleted: %s (%s)\n", u.UUID, u.Name)
	return nil
}

func uiMTProxy(in *bufio.Reader) error {
	mp := newMTProxyClient()
	for {
		action, err := uiSelectOptionValue("Telegram MTProxy", []uiOption{
			{Value: "status", Title: "Status", Hint: "Show MTProxy service/config summary"},
			{Value: "config", Title: "Show config", Hint: "Print server/port/secret and connect links"},
			{Value: "set-secret", Title: "Set secret", Hint: "Set custom HEX32 secret and restart service"},
			{Value: "regen-secret", Title: "Regenerate secret", Hint: "Generate random HEX32 secret and restart service"},
			{Value: "service", Title: "Service control", Hint: "status/start/stop/restart mtproxy"},
			{Value: "back", Title: "Back", Hint: "Return to main menu"},
		}, 0, in)
		if err != nil {
			if errors.Is(err, errUISelectionCanceled) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		var actionErr error
		switch action {
		case "back":
			return nil
		case "status":
			actionErr = uiMTProxyStatus(mp)
		case "config":
			actionErr = uiMTProxyShowConfig(mp, in)
		case "set-secret":
			actionErr = uiMTProxySetSecret(mp, in)
		case "regen-secret":
			actionErr = uiMTProxyRegenSecret(mp)
		case "service":
			actionErr = uiMTProxyService(mp, in)
		default:
			actionErr = fmt.Errorf("unknown mtproxy action: %s", action)
		}

		if actionErr != nil {
			if errors.Is(actionErr, errUISelectionCanceled) {
				fmt.Println("\n" + uiText("Canceled."))
			} else if errors.Is(actionErr, errUIExitRequested) || errors.Is(actionErr, io.EOF) {
				return nil
			} else {
				fmt.Printf("\n%s: %v\n", uiText("ERROR"), actionErr)
			}
		}

		if err := uiPause(in); err != nil {
			if errors.Is(err, errUIExitRequested) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func uiMTProxyStatus(mp *mtproxyClient) error {
	st, err := mp.status()
	if err != nil {
		return err
	}
	printSectionHeader("MTProxy status")
	printMTProxyStatus(st)
	return nil
}

func uiMTProxyShowConfig(mp *mtproxyClient, in *bufio.Reader) error {
	server, err := promptLine(in, "Server host/ip (empty = from config)", "")
	if err != nil {
		return err
	}
	portRaw, err := promptLine(in, "Port (empty = from config)", "")
	if err != nil {
		return err
	}
	port := 0
	if strings.TrimSpace(portRaw) != "" {
		n, err := strconv.Atoi(strings.TrimSpace(portRaw))
		if err != nil {
			return fmt.Errorf("invalid port: %s", strings.TrimSpace(portRaw))
		}
		port = n
	}
	cfg, err := mp.connectionInfo(strings.TrimSpace(server), port, "")
	if err != nil {
		return err
	}
	fmt.Println()
	printMTProxyConnInfo(cfg)
	return nil
}

func uiMTProxySetSecret(mp *mtproxyClient, in *bufio.Reader) error {
	if err := requireRoot("mtproxy secret set"); err != nil {
		return err
	}
	secretRaw, err := promptRequiredLine(in, "MTProxy secret (HEX32)")
	if err != nil {
		return err
	}
	secret, err := normalizeMTProxySecret(secretRaw)
	if err != nil {
		return err
	}
	cfg, err := mp.loadConfig()
	if err != nil {
		return err
	}
	cfg.Secret = secret
	if err := mp.writeConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("MTProxy secret updated.\n")
	fmt.Printf("Secret: %s\n", cfg.Secret)
	if warn := mtproxyRestartWarning(mp.service, mp.restartService()); warn != "" {
		fmt.Printf("Warning: %s\n", warn)
	}
	return nil
}

func uiMTProxyRegenSecret(mp *mtproxyClient) error {
	if err := requireRoot("mtproxy secret regen"); err != nil {
		return err
	}
	cfg, err := mp.loadConfig()
	if err != nil {
		return err
	}
	cfg.Secret = newHexToken(16)
	if err := mp.writeConfig(cfg); err != nil {
		return err
	}
	fmt.Printf("MTProxy secret regenerated.\n")
	fmt.Printf("Secret: %s\n", cfg.Secret)
	if warn := mtproxyRestartWarning(mp.service, mp.restartService()); warn != "" {
		fmt.Printf("Warning: %s\n", warn)
	}
	return nil
}

func uiMTProxyService(mp *mtproxyClient, in *bufio.Reader) error {
	action, err := uiSelectOptionValue("MTProxy service", []uiOption{
		{Value: "status", Title: "status", Hint: "Show systemctl status"},
		{Value: "start", Title: "start", Hint: "Start service"},
		{Value: "stop", Title: "stop", Hint: "Stop service"},
		{Value: "restart", Title: "restart", Hint: "Restart service"},
		{Value: "back", Title: "back", Hint: "Return to MTProxy menu"},
	}, 0, in)
	if err != nil {
		return err
	}
	if action == "back" {
		return nil
	}
	switch action {
	case "status":
		return runCommand("systemctl", "--no-pager", "--full", "status", mp.service)
	case "start", "stop", "restart":
		if err := runCommand("systemctl", action, mp.service); err != nil {
			return err
		}
		fmt.Printf("MTProxy service %s: %s\n", action, mp.service)
		return nil
	default:
		return fmt.Errorf("unknown action: %s", action)
	}
}

func uiSocksProxy(in *bufio.Reader) error {
	sc := newSocksClient()
	for {
		action, err := uiSelectOptionValue("SOCKS5 (Dante)", []uiOption{
			{Value: "status", Title: "Status", Hint: "Show SOCKS service/config summary"},
			{Value: "list", Title: "List users", Hint: "Show SOCKS logins and masked passwords"},
			{Value: "add", Title: "Add user", Hint: "Create SOCKS login and set Linux password"},
			{Value: "edit", Title: "Edit user", Hint: "Rename login and/or change password"},
			{Value: "show", Title: "Show user", Hint: "Show login/password and optional connect params"},
			{Value: "delete", Title: "Delete user", Hint: "Remove SOCKS login and Linux user"},
			{Value: "service", Title: "Service control", Hint: "status/start/stop/restart danted"},
			{Value: "back", Title: "Back", Hint: "Return to main menu"},
		}, 0, in)
		if err != nil {
			if errors.Is(err, errUISelectionCanceled) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		var actionErr error
		switch action {
		case "back":
			return nil
		case "status":
			actionErr = uiSocksStatus(sc)
		case "list":
			actionErr = uiSocksListUsers(sc)
		case "add":
			actionErr = uiSocksAddUser(sc, in)
		case "edit":
			actionErr = uiSocksEditUser(sc, in)
		case "show":
			actionErr = uiSocksShowUser(sc, in)
		case "delete":
			actionErr = uiSocksDeleteUser(sc, in)
		case "service":
			actionErr = uiSocksService(sc, in)
		default:
			actionErr = fmt.Errorf(uiTextf("unknown socks action: %s", action))
		}

		if actionErr != nil {
			if errors.Is(actionErr, errUISelectionCanceled) {
				fmt.Println("\n" + uiText("Canceled."))
			} else if errors.Is(actionErr, errUIExitRequested) || errors.Is(actionErr, io.EOF) {
				return nil
			} else {
				fmt.Printf("\n%s: %v\n", uiText("ERROR"), actionErr)
			}
		}

		if err := uiPause(in); err != nil {
			if errors.Is(err, errUIExitRequested) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func uiSocksStatus(sc *socksClient) error {
	st, err := sc.status()
	if err != nil {
		return err
	}
	printSectionHeader("SOCKS5 status")
	printSocksStatus(st)
	return nil
}

func uiSocksListUsers(sc *socksClient) error {
	users, err := sc.usersList()
	if err != nil {
		return err
	}
	printSectionHeader("SOCKS users")
	printSocksUsers(users)
	return nil
}

func uiSocksAddUser(sc *socksClient, in *bufio.Reader) error {
	if err := requireRoot("socks users add"); err != nil {
		return err
	}
	login, err := promptRequiredLine(in, "SOCKS login")
	if err != nil {
		return err
	}
	login = normalizeSocksLogin(login)
	if err := validateSocksLogin(login); err != nil {
		return err
	}

	users, err := sc.usersList()
	if err != nil {
		return err
	}
	if hasSocksUserExact(users, login) {
		return fmt.Errorf(uiTextf("socks user already exists: %s", login))
	}
	if osSocksUserExists(login) {
		return fmt.Errorf(uiTextf("linux user already exists: %s", login))
	}

	password, err := promptLine(in, "Password (empty = auto-generate)", "")
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)
	if password == "" {
		password = newSecureToken(24)
	}

	if err := sc.ensureLinuxUser(login, password); err != nil {
		return err
	}
	u := socksUser{Name: login, Password: password, SystemUser: login}
	users = append(users, u)
	if err := sc.writeUsers(users); err != nil {
		return err
	}

	fmt.Printf("\n%s\n", uiTextf("SOCKS user added: %s", login))
	fmt.Printf("%s: %s\n", uiText("Password"), password)

	showConfig, err := promptYesNo(in, "Print connection config now?", true)
	if err != nil {
		return err
	}
	if !showConfig {
		return nil
	}
	return uiSocksPrintConn(sc, in, u)
}

func uiSocksPrintConn(sc *socksClient, in *bufio.Reader, u socksUser) error {
	server, err := promptLine(in, "Server host/ip (empty = auto detect)", "")
	if err != nil {
		return err
	}
	portRaw, err := promptLine(in, "Port (empty = from danted config)", "")
	if err != nil {
		return err
	}
	port := 0
	if strings.TrimSpace(portRaw) != "" {
		p, err := strconv.Atoi(strings.TrimSpace(portRaw))
		if err != nil {
			return fmt.Errorf(uiTextf("invalid port: %s", strings.TrimSpace(portRaw)))
		}
		port = p
	}
	cfg, err := sc.connectionConfig(u, strings.TrimSpace(server), port)
	if err != nil {
		return err
	}
	fmt.Println()
	printSocksConnInfo(cfg)
	return nil
}

func uiSocksEditUser(sc *socksClient, in *bufio.Reader) error {
	if err := requireRoot("socks users edit"); err != nil {
		return err
	}
	users, err := sc.usersList()
	if err != nil {
		return err
	}
	current, err := uiPromptSocksUserSelection(sc, in, "Select SOCKS user to edit", "USER_ID to edit")
	if err != nil {
		return err
	}
	idx := findSocksUserIndex(users, current.Name)
	if idx < 0 {
		return fmt.Errorf(uiTextf("selected user not found: %s", current.Name))
	}

	newName, err := promptLine(in, uiTextf("New login (empty = keep: %s)", current.Name), "")
	if err != nil {
		return err
	}
	newName = normalizeSocksLogin(newName)
	if newName != "" && newName != current.Name {
		if err := validateSocksLogin(newName); err != nil {
			return err
		}
		for i, u := range users {
			if i == idx {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(u.Name), newName) {
				return fmt.Errorf(uiTextf("socks user already exists: %s", newName))
			}
		}
		if osSocksUserExists(newName) {
			return fmt.Errorf(uiTextf("linux user already exists: %s", newName))
		}
		if err := runCommand("usermod", "-l", newName, socksSystemUser(current)); err != nil {
			return err
		}
		users[idx].Name = newName
		users[idx].SystemUser = newName
	}

	newPassword, err := promptLine(in, "New password (empty = keep current)", "")
	if err != nil {
		return err
	}
	newPassword = strings.TrimSpace(newPassword)
	if newPassword != "" {
		if err := sc.setLinuxUserPassword(socksSystemUser(users[idx]), newPassword); err != nil {
			return err
		}
		users[idx].Password = newPassword
	}

	if users[idx] == current {
		fmt.Println("\n" + uiText("No changes requested."))
		return nil
	}
	if err := sc.writeUsers(users); err != nil {
		return err
	}
	fmt.Printf("\n%s\n", uiTextf("SOCKS user updated: %s -> %s", current.Name, users[idx].Name))
	if newPassword != "" {
		fmt.Printf("%s\n", uiTextf("New password: %s", newPassword))
	}
	return nil
}

func uiSocksShowUser(sc *socksClient, in *bufio.Reader) error {
	u, err := uiPromptSocksUserSelection(sc, in, "Select SOCKS user", "USER_ID to show")
	if err != nil {
		return err
	}
	printSocksUser(u)
	showConfig, err := promptYesNo(in, "Print connection config?", true)
	if err != nil {
		return err
	}
	if !showConfig {
		return nil
	}
	return uiSocksPrintConn(sc, in, u)
}

func uiSocksDeleteUser(sc *socksClient, in *bufio.Reader) error {
	if err := requireRoot("socks users del"); err != nil {
		return err
	}
	users, err := sc.usersList()
	if err != nil {
		return err
	}
	u, err := uiPromptSocksUserSelection(sc, in, "Select SOCKS user to delete", "USER_ID to delete")
	if err != nil {
		return err
	}
	idx := findSocksUserIndex(users, u.Name)
	if idx < 0 {
		return fmt.Errorf(uiTextf("selected user not found: %s", u.Name))
	}
	confirm, err := promptYesNo(in, uiTextf("Delete SOCKS user %s?", u.Name), false)
	if err != nil {
		return err
	}
	if !confirm {
		fmt.Println(uiText("Canceled."))
		return nil
	}
	next := make([]socksUser, 0, len(users)-1)
	next = append(next, users[:idx]...)
	next = append(next, users[idx+1:]...)
	if err := sc.writeUsers(next); err != nil {
		return err
	}
	fmt.Printf("%s\n", uiTextf("Deleted SOCKS user: %s", u.Name))
	if err := sc.deleteLinuxUser(socksSystemUser(u)); err != nil {
		fmt.Printf("%s\n", uiTextf("Warning: %s", err.Error()))
	}
	return nil
}

func uiSocksService(sc *socksClient, in *bufio.Reader) error {
	action, err := uiSelectOptionValue("SOCKS service", []uiOption{
		{Value: "status", Title: "status", Hint: "Show systemctl status"},
		{Value: "start", Title: "start", Hint: "Start service"},
		{Value: "stop", Title: "stop", Hint: "Stop service"},
		{Value: "restart", Title: "restart", Hint: "Restart service"},
		{Value: "back", Title: "back", Hint: "Return to SOCKS menu"},
	}, 0, in)
	if err != nil {
		return err
	}
	if action == "back" {
		return nil
	}
	switch action {
	case "status":
		return runCommand("systemctl", "--no-pager", "--full", "status", sc.service)
	case "start", "stop", "restart":
		if err := runCommand("systemctl", action, sc.service); err != nil {
			return err
		}
		fmt.Printf("%s\n", uiTextf("SOCKS service %s: %s", action, sc.service))
		return nil
	default:
		return fmt.Errorf(uiTextf("unknown action: %s", action))
	}
}

func uiTrustTunnel(in *bufio.Reader) error {
	tt := newTrustClient()
	for {
		action, err := uiSelectOptionValue("TrustTunnel", []uiOption{
			{Value: "status", Title: "Status", Hint: "Show TrustTunnel service/config summary"},
			{Value: "list", Title: "List users", Hint: "Show users from credentials.toml"},
			{Value: "add", Title: "Add user", Hint: "Create TrustTunnel user and restart service"},
			{Value: "edit", Title: "Edit user", Hint: "Rename user and/or change password"},
			{Value: "show", Title: "Show user", Hint: "Show username/password and optional client config"},
			{Value: "delete", Title: "Delete user", Hint: "Remove user and restart service"},
			{Value: "service", Title: "Service control", Hint: "status/start/stop/restart trusttunnel"},
			{Value: "back", Title: "Back", Hint: "Return to main menu"},
		}, 0, in)
		if err != nil {
			if errors.Is(err, errUISelectionCanceled) {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		var actionErr error
		switch action {
		case "back":
			return nil
		case "status":
			actionErr = uiTrustStatus(tt)
		case "list":
			actionErr = uiTrustListUsers(tt)
		case "add":
			actionErr = uiTrustAddUser(tt, in)
		case "edit":
			actionErr = uiTrustEditUser(tt, in)
		case "show":
			actionErr = uiTrustShowUser(tt, in)
		case "delete":
			actionErr = uiTrustDeleteUser(tt, in)
		case "service":
			actionErr = uiTrustService(tt, in)
		default:
			actionErr = fmt.Errorf(uiTextf("unknown trust action: %s", action))
		}

		if actionErr != nil {
			if errors.Is(actionErr, errUISelectionCanceled) {
				fmt.Println("\n" + uiText("Canceled."))
			} else if errors.Is(actionErr, errUIExitRequested) || errors.Is(actionErr, io.EOF) {
				return nil
			} else {
				fmt.Printf("\n%s: %v\n", uiText("ERROR"), actionErr)
			}
		}

		if err := uiPause(in); err != nil {
			if errors.Is(err, errUIExitRequested) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func uiTrustStatus(tt *trustClient) error {
	st, err := tt.status()
	if err != nil {
		return err
	}
	printSectionHeader("TrustTunnel status")
	printTrustStatus(st)
	return nil
}

func uiTrustListUsers(tt *trustClient) error {
	users, err := tt.usersList()
	if err != nil {
		return err
	}
	printSectionHeader("TrustTunnel users")
	printTrustUsers(users)
	return nil
}

func uiTrustAddUser(tt *trustClient, in *bufio.Reader) error {
	username, err := promptRequiredLine(in, "Trust username")
	if err != nil {
		return err
	}
	username = strings.TrimSpace(username)
	if err := validateTrustUsername(username); err != nil {
		return err
	}

	users, err := tt.usersList()
	if err != nil {
		return err
	}
	if hasTrustUserExact(users, username) {
		return fmt.Errorf(uiTextf("trust user already exists: %s", username))
	}

	password, err := promptLine(in, "Password (empty = auto-generate)", "")
	if err != nil {
		return err
	}
	password = strings.TrimSpace(password)
	if password == "" {
		password = newSecureToken(24)
	}

	users = append(users, trustUser{Username: username, Password: password})
	if err := tt.writeUsers(users); err != nil {
		return err
	}

	fmt.Printf("\n%s\n", uiTextf("TrustTunnel user added: %s", username))
	fmt.Printf("%s: %s\n", uiText("Password"), password)
	if warn := trustRestartWarning(tt.service, tt.restartService()); warn != "" {
		fmt.Printf("%s\n", uiTextf("Warning: %s", warn))
	}

	showConfig, err := promptYesNo(in, "Generate client config now?", false)
	if err != nil {
		return err
	}
	if !showConfig {
		return nil
	}
	return uiTrustPrintClientConfig(tt, in, username)
}

func uiTrustPrintClientConfig(tt *trustClient, in *bufio.Reader, username string) error {
	address, err := promptLine(in, "Address ip[:port] (empty = auto detect)", "")
	if err != nil {
		return err
	}
	configText, err := tt.exportClientConfig(username, strings.TrimSpace(address))
	if err != nil && strings.TrimSpace(address) == "" {
		fmt.Printf("%s\n", uiTextf("Auto address detection failed: %v", err))
		manualAddress, perr := promptRequiredLine(in, "Address ip[:port] (manual)")
		if perr != nil {
			return perr
		}
		configText, err = tt.exportClientConfig(username, strings.TrimSpace(manualAddress))
	}
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Printf("%s\n", uiTextf("Address: %s", tt.lastExportAddress))
	fmt.Println(configText)
	return nil
}

func uiTrustEditUser(tt *trustClient, in *bufio.Reader) error {
	users, err := tt.usersList()
	if err != nil {
		return err
	}
	current, err := uiPromptTrustUserSelection(tt, in, "Select TrustTunnel user to edit", "USER_ID to edit")
	if err != nil {
		return err
	}
	idx := findTrustUserIndex(users, current.Username)
	if idx < 0 {
		return fmt.Errorf(uiTextf("selected user not found: %s", current.Username))
	}

	newName, err := promptLine(in, uiTextf("New username (empty = keep: %s)", current.Username), "")
	if err != nil {
		return err
	}
	newName = strings.TrimSpace(newName)
	if newName != "" {
		if err := validateTrustUsername(newName); err != nil {
			return err
		}
		for i, u := range users {
			if i == idx {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(u.Username), newName) {
				return fmt.Errorf(uiTextf("trust user already exists: %s", newName))
			}
		}
		users[idx].Username = newName
	}

	newPassword, err := promptLine(in, "New password (empty = keep current)", "")
	if err != nil {
		return err
	}
	newPassword = strings.TrimSpace(newPassword)
	if newPassword != "" {
		users[idx].Password = newPassword
	}

	if users[idx] == current {
		fmt.Println("\n" + uiText("No changes requested."))
		return nil
	}

	if err := tt.writeUsers(users); err != nil {
		return err
	}
	fmt.Printf("\n%s\n", uiTextf("TrustTunnel user updated: %s", current.Username))
	if warn := trustRestartWarning(tt.service, tt.restartService()); warn != "" {
		fmt.Printf("%s\n", uiTextf("Warning: %s", warn))
	}
	printTrustUser(users[idx])
	return nil
}

func uiTrustShowUser(tt *trustClient, in *bufio.Reader) error {
	u, err := uiPromptTrustUserSelection(tt, in, "Select TrustTunnel user", "USER_ID to show")
	if err != nil {
		return err
	}
	printTrustUser(u)

	showConfig, err := promptYesNo(in, "Generate client config?", false)
	if err != nil {
		return err
	}
	if !showConfig {
		return nil
	}
	return uiTrustPrintClientConfig(tt, in, u.Username)
}

func uiTrustDeleteUser(tt *trustClient, in *bufio.Reader) error {
	users, err := tt.usersList()
	if err != nil {
		return err
	}
	u, err := uiPromptTrustUserSelection(tt, in, "Select TrustTunnel user to delete", "USER_ID to delete")
	if err != nil {
		return err
	}
	idx := findTrustUserIndex(users, u.Username)
	if idx < 0 {
		return fmt.Errorf(uiTextf("selected user not found: %s", u.Username))
	}
	confirm, err := promptYesNo(in, uiTextf("Delete trust user %s?", u.Username), false)
	if err != nil {
		return err
	}
	if !confirm {
		fmt.Println(uiText("Canceled."))
		return nil
	}
	next := make([]trustUser, 0, len(users)-1)
	next = append(next, users[:idx]...)
	next = append(next, users[idx+1:]...)
	if err := tt.writeUsers(next); err != nil {
		return err
	}
	fmt.Printf("%s\n", uiTextf("Deleted trust user: %s", u.Username))
	if warn := trustRestartWarning(tt.service, tt.restartService()); warn != "" {
		fmt.Printf("%s\n", uiTextf("Warning: %s", warn))
	}
	return nil
}

func uiTrustService(tt *trustClient, in *bufio.Reader) error {
	action, err := uiSelectOptionValue("TrustTunnel service", []uiOption{
		{Value: "status", Title: "status", Hint: "Show systemctl status"},
		{Value: "start", Title: "start", Hint: "Start service"},
		{Value: "stop", Title: "stop", Hint: "Stop service"},
		{Value: "restart", Title: "restart", Hint: "Restart service"},
		{Value: "back", Title: "back", Hint: "Return to TrustTunnel menu"},
	}, 0, in)
	if err != nil {
		return err
	}
	if action == "back" {
		return nil
	}
	switch action {
	case "status":
		return runCommand("systemctl", "--no-pager", "--full", "status", tt.service)
	case "start", "stop", "restart":
		if err := runCommand("systemctl", action, tt.service); err != nil {
			return err
		}
		fmt.Printf("%s\n", uiTextf("TrustTunnel service %s: %s", action, tt.service))
		return nil
	default:
		return fmt.Errorf(uiTextf("unknown action: %s", action))
	}
}

func uiAdminURL(c *client) error {
	if err := c.loadState(); err != nil {
		return err
	}
	host, err := c.mainDomainOrErr()
	if err != nil {
		return err
	}
	fmt.Println(c.adminURL(host))
	return nil
}

func mustClient(loadState bool) *client {
	c := &client{
		panelCfg:  envOr("PSAS_PANEL_CFG", defaultPanelCfg),
		panelAddr: envOr("PSAS_PANEL_ADDR", defaultPanelAddr),
		panelPy:   envOr("PSAS_PANEL_PY", detectPanelPython()),
	}
	if loadState {
		must(c.loadState())
	}
	return c
}

func ensureHiddifyStateLoaded(c *client) error {
	if c == nil {
		return errors.New("nil client")
	}
	if strings.TrimSpace(c.state.APIPath) != "" && strings.TrimSpace(c.state.APIKey) != "" {
		return nil
	}
	return c.loadState()
}

func detectPanelPython() string {
	candidates := []string{
		"/opt/hiddify-manager/.venv313/bin/python3",
		"/opt/hiddify-manager/.venv/bin/python3",
	}
	for _, c := range candidates {
		if fileExists(c) {
			return c
		}
	}
	return "python3"
}

func newMTProxyClient() *mtproxyClient {
	return &mtproxyClient{
		dir:     envOr("PSAS_MTPROXY_DIR", defaultMTProxyDir),
		service: envOr("PSAS_MTPROXY_SERVICE", defaultMTProxyService),
		config:  envOr("PSAS_MTPROXY_CONF", defaultMTProxyConfig),
	}
}

func (m *mtproxyClient) status() (mtproxyStatus, error) {
	st := mtproxyStatus{
		Installed:  m.installed(),
		Service:    m.service,
		Directory:  m.dir,
		ConfigPath: m.config,
	}
	if active, err := m.serviceIsActive(); err == nil {
		st.ServiceActive = active
	}
	cfg, err := m.loadConfig()
	if err == nil {
		st.Server = cfg.Server
		st.ListenPort = cfg.Port
		st.InternalPort = cfg.InternalPort
		st.SecretMasked = maskSecret(cfg.Secret)
	}
	return st, nil
}

func (m *mtproxyClient) installed() bool {
	if fileExists(m.binaryPath()) {
		return true
	}
	_, err := exec.LookPath(defaultMTProxyBin)
	return err == nil
}

func (m *mtproxyClient) binaryPath() string {
	return filepath.Join(m.dir, "objs", "bin", defaultMTProxyBin)
}

func (m *mtproxyClient) serviceIsActive() (bool, error) {
	out, err := runCommandOutput("systemctl", "is-active", m.service)
	state := strings.ToLower(strings.TrimSpace(out))
	switch state {
	case "active":
		return true, nil
	case "inactive", "failed", "activating", "deactivating", "not-found", "unknown":
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("systemctl is-active %s: %w (%s)", m.service, err, strings.TrimSpace(out))
	}
	return false, nil
}

func (m *mtproxyClient) restartService() error {
	return runCommand("systemctl", "restart", m.service)
}

func (m *mtproxyClient) loadConfig() (mtproxyConfig, error) {
	cfg := mtproxyConfig{
		Server:       strings.TrimSpace(os.Getenv("PSAS_MTPROXY_HOST")),
		Port:         defaultMTProxyPort,
		InternalPort: defaultMTProxyInternalPort,
	}
	if fileExists(m.config) {
		raw, err := os.ReadFile(m.config)
		if err != nil {
			return cfg, err
		}
		if strings.TrimSpace(string(raw)) != "" {
			var parsed mtproxyConfig
			if err := json.Unmarshal(raw, &parsed); err != nil {
				return cfg, fmt.Errorf("parse %s: %w", m.config, err)
			}
			if strings.TrimSpace(parsed.Server) != "" {
				cfg.Server = strings.TrimSpace(parsed.Server)
			}
			if parsed.Port > 0 {
				cfg.Port = parsed.Port
			}
			if parsed.InternalPort > 0 {
				cfg.InternalPort = parsed.InternalPort
			}
			if strings.TrimSpace(parsed.Secret) != "" {
				secret, err := normalizeMTProxySecret(parsed.Secret)
				if err != nil {
					return cfg, err
				}
				cfg.Secret = secret
			}
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return cfg, fmt.Errorf("invalid mtproxy port: %d", cfg.Port)
	}
	if cfg.InternalPort < 1 || cfg.InternalPort > 65535 {
		return cfg, fmt.Errorf("invalid mtproxy internal port: %d", cfg.InternalPort)
	}
	return cfg, nil
}

func (m *mtproxyClient) writeConfig(cfg mtproxyConfig) error {
	cfg.Server = strings.TrimSpace(cfg.Server)
	if cfg.Server == "" {
		if envHost := strings.TrimSpace(os.Getenv("PSAS_MTPROXY_HOST")); envHost != "" {
			cfg.Server = envHost
		}
	}
	if cfg.Port <= 0 {
		cfg.Port = defaultMTProxyPort
	}
	if cfg.InternalPort <= 0 {
		cfg.InternalPort = defaultMTProxyInternalPort
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return fmt.Errorf("invalid mtproxy port: %d", cfg.Port)
	}
	if cfg.InternalPort < 1 || cfg.InternalPort > 65535 {
		return fmt.Errorf("invalid mtproxy internal port: %d", cfg.InternalPort)
	}
	secret, err := normalizeMTProxySecret(cfg.Secret)
	if err != nil {
		return err
	}
	cfg.Secret = secret

	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.config), 0o755); err != nil {
		return err
	}
	return os.WriteFile(m.config, append(payload, '\n'), 0o600)
}

func (m *mtproxyClient) connectionInfo(server string, port int, secret string) (mtproxyConnInfo, error) {
	cfg, err := m.loadConfig()
	if err != nil {
		return mtproxyConnInfo{}, err
	}
	if strings.TrimSpace(server) != "" {
		cfg.Server = strings.TrimSpace(server)
	}
	if port > 0 {
		cfg.Port = port
	}
	if strings.TrimSpace(secret) != "" {
		cfg.Secret = strings.TrimSpace(secret)
	}

	cfg.Server = strings.TrimSpace(cfg.Server)
	if cfg.Server == "" {
		ip, err := detectPublicIPv4()
		if err != nil {
			return mtproxyConnInfo{}, err
		}
		cfg.Server = ip
	}
	if strings.ContainsAny(cfg.Server, " \t\r\n") {
		return mtproxyConnInfo{}, fmt.Errorf("invalid server value: %q", cfg.Server)
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return mtproxyConnInfo{}, fmt.Errorf("invalid mtproxy port: %d", cfg.Port)
	}
	normalizedSecret, err := normalizeMTProxySecret(cfg.Secret)
	if err != nil {
		return mtproxyConnInfo{}, err
	}
	q := url.Values{}
	q.Set("server", cfg.Server)
	q.Set("port", strconv.Itoa(cfg.Port))
	q.Set("secret", normalizedSecret)
	return mtproxyConnInfo{
		Server:       cfg.Server,
		Port:         cfg.Port,
		Secret:       normalizedSecret,
		SecretMasked: maskSecret(normalizedSecret),
		TGLink:       "tg://proxy?" + q.Encode(),
		ShareURL:     "https://t.me/proxy?" + q.Encode(),
	}, nil
}

func normalizeMTProxySecret(raw string) (string, error) {
	secret := strings.ToLower(strings.TrimSpace(raw))
	if !mtproxySecretRe.MatchString(secret) {
		return "", fmt.Errorf("invalid MTProxy secret %q (expected 32 hex chars)", strings.TrimSpace(raw))
	}
	return secret, nil
}

func newHexToken(bytesLen int) string {
	if bytesLen <= 0 {
		bytesLen = 16
	}
	raw := make([]byte, bytesLen)
	mustReadRand(raw)
	return hex.EncodeToString(raw)
}

func newTrustClient() *trustClient {
	return &trustClient{
		dir:     envOr("PSAS_TT_DIR", defaultTrustDir),
		service: envOr("PSAS_TT_SERVICE", defaultTrustService),
	}
}

func (t *trustClient) status() (trustStatus, error) {
	st := trustStatus{
		Installed: t.installed(),
		Service:   t.service,
		Directory: t.dir,
	}

	active, err := t.serviceIsActive()
	if err == nil {
		st.ServiceActive = active
	}

	if !st.Installed {
		return st, nil
	}

	if listen, lerr := t.listenAddress(); lerr == nil {
		st.ListenAddress = listen
	}
	if host, herr := t.hostname(); herr == nil {
		st.Hostname = host
	}
	users, uerr := t.usersList()
	if uerr == nil {
		st.Users = len(users)
	}
	return st, nil
}

func (t *trustClient) installed() bool {
	return fileExists(t.endpointPath())
}

func (t *trustClient) endpointPath() string {
	return filepath.Join(t.dir, defaultTrustEndpoint)
}

func (t *trustClient) vpnPath() string {
	return filepath.Join(t.dir, "vpn.toml")
}

func (t *trustClient) hostsPath() string {
	return filepath.Join(t.dir, "hosts.toml")
}

func (t *trustClient) serviceIsActive() (bool, error) {
	out, err := runCommandOutput("systemctl", "is-active", t.service)
	state := strings.ToLower(strings.TrimSpace(out))
	switch state {
	case "active":
		return true, nil
	case "inactive", "failed", "activating", "deactivating", "not-found", "unknown":
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("systemctl is-active %s: %w (%s)", t.service, err, strings.TrimSpace(out))
	}
	return false, nil
}

func (t *trustClient) restartService() error {
	return runCommand("systemctl", "restart", t.service)
}

func (t *trustClient) listenAddress() (string, error) {
	raw, err := os.ReadFile(t.vpnPath())
	if err != nil {
		return "", err
	}
	v, ok, err := parseTOMLStringKey(string(raw), "listen_address")
	if err != nil {
		return "", err
	}
	if !ok || strings.TrimSpace(v) == "" {
		return "", errors.New("listen_address not found in vpn.toml")
	}
	return strings.TrimSpace(v), nil
}

func (t *trustClient) hostname() (string, error) {
	raw, err := os.ReadFile(t.hostsPath())
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n")
	inMainHosts := false
	for _, line := range lines {
		trimmed := stripTOMLComment(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "[[") && strings.HasSuffix(trimmed, "]]") {
			section := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			inMainHosts = section == "main_hosts"
			continue
		}
		if !inMainHosts {
			continue
		}
		if v, ok, err := parseTOMLStringAssignment(trimmed, "hostname"); err != nil {
			return "", err
		} else if ok {
			return strings.TrimSpace(v), nil
		}
	}

	if v, ok, err := parseTOMLStringKey(string(raw), "hostname"); err != nil {
		return "", err
	} else if ok {
		return strings.TrimSpace(v), nil
	}
	return "", errors.New("hostname not found in hosts.toml")
}

func (t *trustClient) credentialsPath() (string, error) {
	path := "credentials.toml"
	if raw, err := os.ReadFile(t.vpnPath()); err == nil {
		if v, _, perr := parseTOMLStringKey(string(raw), "credentials_file"); perr == nil && strings.TrimSpace(v) != "" {
			path = strings.TrimSpace(v)
		}
	}
	if filepath.IsAbs(path) {
		return path, nil
	}
	return filepath.Join(t.dir, path), nil
}

func (t *trustClient) usersList() ([]trustUser, error) {
	if !t.installed() {
		return nil, fmt.Errorf("TrustTunnel is not installed at %s", t.dir)
	}
	credPath, err := t.credentialsPath()
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(credPath)
	if err != nil {
		return nil, err
	}
	users, err := parseTrustCredentials(string(raw))
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", credPath, err)
	}
	return users, nil
}

func (t *trustClient) writeUsers(users []trustUser) error {
	credPath, err := t.credentialsPath()
	if err != nil {
		return err
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(credPath); err == nil {
		mode = info.Mode()
	}

	payload, err := renderTrustCredentials(users)
	if err != nil {
		return err
	}
	return os.WriteFile(credPath, []byte(payload), mode)
}

func (t *trustClient) exportClientConfig(username, address string) (string, error) {
	if !t.installed() {
		return "", fmt.Errorf("TrustTunnel is not installed at %s", t.dir)
	}
	address = strings.TrimSpace(address)
	var err error
	if address == "" {
		address, err = t.defaultExportAddress()
		if err != nil {
			return "", err
		}
	} else {
		address, err = t.normalizeExportAddress(address)
		if err != nil {
			return "", err
		}
	}
	cmd := exec.Command(t.endpointPath(), "vpn.toml", "hosts.toml", "-c", username, "-a", address)
	cmd.Dir = t.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("trusttunnel_endpoint export failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	t.lastExportAddress = address
	return strings.TrimSpace(string(out)), nil
}

func (t *trustClient) defaultExportAddress() (string, error) {
	listen, err := t.listenAddress()
	if err != nil {
		return "", err
	}
	_, port, err := parseListenAddress(listen)
	if err != nil {
		return "", err
	}
	ip, err := detectPublicIPv4()
	if err != nil {
		return "", err
	}
	return ip + ":" + port, nil
}

func (t *trustClient) normalizeExportAddress(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty address")
	}
	if isIPv4(raw) {
		listen, err := t.listenAddress()
		if err != nil {
			return "", err
		}
		_, port, err := parseListenAddress(listen)
		if err != nil {
			return "", err
		}
		return raw + ":" + port, nil
	}
	host, port, err := parseListenAddress(raw)
	if err != nil {
		return "", fmt.Errorf("invalid --address %q: expected ip or ip:port", raw)
	}
	if !isIPv4(host) {
		return "", fmt.Errorf("invalid --address host %q: TrustTunnel expects ip or ip:port", host)
	}
	return host + ":" + port, nil
}

func newSocksClient() *socksClient {
	return &socksClient{
		service: envOr("PSAS_SOCKS_SERVICE", defaultSocksService),
		config:  envOr("PSAS_SOCKS_CONF", defaultSocksConfig),
		users:   envOr("PSAS_SOCKS_USERS", defaultSocksUsers),
	}
}

func (s *socksClient) status() (socksStatus, error) {
	st := socksStatus{
		Installed:  s.installed(),
		Service:    s.service,
		ConfigPath: s.config,
	}
	active, err := s.serviceIsActive()
	if err == nil {
		st.ServiceActive = active
	}
	if !st.Installed {
		return st, nil
	}
	if listen, err := s.listenAddress(); err == nil {
		st.ListenAddress = listen
	}
	if users, err := s.usersList(); err == nil {
		st.Users = len(users)
	}
	return st, nil
}

func (s *socksClient) installed() bool {
	if _, err := exec.LookPath("danted"); err == nil {
		return true
	}
	return fileExists("/usr/sbin/danted") || fileExists("/usr/bin/danted")
}

func (s *socksClient) serviceIsActive() (bool, error) {
	out, err := runCommandOutput("systemctl", "is-active", s.service)
	state := strings.ToLower(strings.TrimSpace(out))
	switch state {
	case "active":
		return true, nil
	case "inactive", "failed", "activating", "deactivating", "not-found", "unknown":
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("systemctl is-active %s: %w (%s)", s.service, err, strings.TrimSpace(out))
	}
	return false, nil
}

func (s *socksClient) restartService() error {
	return runCommand("systemctl", "restart", s.service)
}

func (s *socksClient) listenAddress() (string, error) {
	raw, err := os.ReadFile(s.config)
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r", ""), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		m := dantedInternalRe.FindStringSubmatch(line)
		if len(m) == 0 {
			continue
		}
		host := strings.Trim(strings.TrimSpace(m[1]), "[]")
		if host == "" {
			host = "0.0.0.0"
		}
		port := strings.TrimSpace(m[2])
		if port == "" {
			port = strconv.Itoa(defaultSocksPort)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 1 || p > 65535 {
			return "", fmt.Errorf("invalid SOCKS port in %s: %s", s.config, port)
		}
		if strings.Contains(host, ":") {
			return net.JoinHostPort(host, port), nil
		}
		return host + ":" + port, nil
	}
	return "", fmt.Errorf("internal listen address not found in %s", s.config)
}

func (s *socksClient) usersList() ([]socksUser, error) {
	if !fileExists(s.users) {
		return []socksUser{}, nil
	}
	raw, err := os.ReadFile(s.users)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(raw)) == "" {
		return []socksUser{}, nil
	}
	var users []socksUser
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.users, err)
	}
	out := make([]socksUser, 0, len(users))
	for _, u := range users {
		name := normalizeSocksLogin(u.Name)
		if name == "" {
			continue
		}
		systemUser := strings.TrimSpace(u.SystemUser)
		if systemUser == "" {
			systemUser = name
		}
		out = append(out, socksUser{
			Name:       name,
			Password:   strings.TrimSpace(u.Password),
			SystemUser: strings.TrimSpace(systemUser),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (s *socksClient) writeUsers(users []socksUser) error {
	for i := range users {
		users[i].Name = normalizeSocksLogin(users[i].Name)
		if users[i].SystemUser == "" {
			users[i].SystemUser = users[i].Name
		}
	}
	payload, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.users), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.users, append(payload, '\n'), 0o600)
}

func (s *socksClient) ensureLinuxUser(login, password string) error {
	login = normalizeSocksLogin(login)
	if err := validateSocksLogin(login); err != nil {
		return err
	}
	if !osSocksUserExists(login) {
		shell := "/usr/sbin/nologin"
		if !fileExists(shell) {
			shell = "/sbin/nologin"
		}
		if !fileExists(shell) {
			shell = "/bin/false"
		}
		if err := runCommand("useradd", "-M", "-N", "-s", shell, login); err != nil {
			return fmt.Errorf("useradd %s: %w", login, err)
		}
	}
	if err := s.setLinuxUserPassword(login, password); err != nil {
		return err
	}
	return nil
}

func (s *socksClient) setLinuxUserPassword(login, password string) error {
	login = strings.TrimSpace(login)
	if login == "" {
		return errors.New("empty login")
	}
	if strings.TrimSpace(password) == "" {
		return errors.New("empty password")
	}
	line := login + ":" + password + "\n"
	if err := runCommandInput(line, "chpasswd"); err != nil {
		return fmt.Errorf("chpasswd for %s: %w", login, err)
	}
	return nil
}

func (s *socksClient) deleteLinuxUser(login string) error {
	login = strings.TrimSpace(login)
	if login == "" {
		return nil
	}
	if !osSocksUserExists(login) {
		return nil
	}
	if err := runCommand("userdel", login); err != nil {
		return fmt.Errorf("failed to delete linux user %s: %w", login, err)
	}
	return nil
}

func (s *socksClient) connectionConfig(u socksUser, server string, port int) (socksConnInfo, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		server = strings.TrimSpace(os.Getenv("PSAS_SOCKS_HOST"))
	}
	if server == "" {
		ip, err := detectPublicIPv4()
		if err != nil {
			return socksConnInfo{}, err
		}
		server = ip
	}
	server = strings.Trim(strings.TrimSpace(server), "[]")
	if server == "" || strings.ContainsAny(server, " \t\r\n") {
		return socksConnInfo{}, fmt.Errorf("invalid server value: %q", server)
	}

	if port <= 0 {
		if listen, err := s.listenAddress(); err == nil {
			if _, p, perr := parseListenAddress(listen); perr == nil {
				if n, aerr := strconv.Atoi(p); aerr == nil {
					port = n
				}
			}
		}
	}
	if port <= 0 {
		port = defaultSocksPort
	}
	if port < 1 || port > 65535 {
		return socksConnInfo{}, fmt.Errorf("invalid SOCKS port: %d", port)
	}

	uriHost := net.JoinHostPort(server, strconv.Itoa(port))
	uri := "socks5://" + url.QueryEscape(u.Name) + ":" + url.QueryEscape(u.Password) + "@" + uriHost
	return socksConnInfo{
		Server:   server,
		Port:     port,
		Username: u.Name,
		Password: u.Password,
		URI:      uri,
	}, nil
}

func parseTrustCredentials(raw string) ([]trustUser, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n")
	users := []trustUser{}

	inClient := false
	current := trustUser{}
	seen := map[string]bool{}

	flushCurrent := func() error {
		if !inClient {
			return nil
		}
		if strings.TrimSpace(current.Username) == "" {
			return errors.New("client entry missing username")
		}
		if strings.TrimSpace(current.Password) == "" {
			return fmt.Errorf("client %q missing password", current.Username)
		}
		lc := strings.ToLower(strings.TrimSpace(current.Username))
		if seen[lc] {
			return fmt.Errorf("duplicate username: %s", current.Username)
		}
		seen[lc] = true
		users = append(users, current)
		current = trustUser{}
		return nil
	}

	for _, line := range lines {
		trimmed := stripTOMLComment(line)
		if trimmed == "" {
			continue
		}
		if trimmed == "[[client]]" {
			if err := flushCurrent(); err != nil {
				return nil, err
			}
			inClient = true
			continue
		}
		if !inClient {
			continue
		}
		if v, ok, err := parseTOMLStringAssignment(trimmed, "username"); err != nil {
			return nil, err
		} else if ok {
			current.Username = strings.TrimSpace(v)
			continue
		}
		if v, ok, err := parseTOMLStringAssignment(trimmed, "password"); err != nil {
			return nil, err
		} else if ok {
			current.Password = strings.TrimSpace(v)
			continue
		}
	}
	if err := flushCurrent(); err != nil {
		return nil, err
	}
	sort.Slice(users, func(i, j int) bool {
		return strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
	})
	return users, nil
}

func renderTrustCredentials(users []trustUser) (string, error) {
	for _, u := range users {
		if err := validateTrustUsername(u.Username); err != nil {
			return "", err
		}
		if strings.TrimSpace(u.Password) == "" {
			return "", fmt.Errorf("password is empty for user %s", u.Username)
		}
	}
	sort.Slice(users, func(i, j int) bool {
		return strings.ToLower(users[i].Username) < strings.ToLower(users[j].Username)
	})

	var b strings.Builder
	for i, u := range users {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString("[[client]]\n")
		b.WriteString("username = ")
		b.WriteString(strconv.Quote(strings.TrimSpace(u.Username)))
		b.WriteString("\n")
		b.WriteString("password = ")
		b.WriteString(strconv.Quote(strings.TrimSpace(u.Password)))
		b.WriteString("\n")
	}
	return b.String(), nil
}

func resolveTrustUser(users []trustUser, id string) (trustUser, int, error) {
	key := strings.TrimSpace(id)
	if key == "" {
		return trustUser{}, -1, errors.New("empty USER_ID")
	}
	var exactIdx []int
	for i, u := range users {
		if strings.EqualFold(strings.TrimSpace(u.Username), key) {
			exactIdx = append(exactIdx, i)
		}
	}
	if len(exactIdx) == 1 {
		idx := exactIdx[0]
		return users[idx], idx, nil
	}
	if len(exactIdx) > 1 {
		return trustUser{}, -1, fmt.Errorf("multiple users have name %q", key)
	}

	lcKey := strings.ToLower(key)
	var partialIdx []int
	for i, u := range users {
		if strings.Contains(strings.ToLower(u.Username), lcKey) {
			partialIdx = append(partialIdx, i)
		}
	}
	if len(partialIdx) == 1 {
		idx := partialIdx[0]
		return users[idx], idx, nil
	}
	if len(partialIdx) == 0 {
		return trustUser{}, -1, fmt.Errorf("trust user not found: %s", key)
	}
	return trustUser{}, -1, fmt.Errorf("multiple trust users match %q", key)
}

func hasTrustUserExact(users []trustUser, username string) bool {
	for _, u := range users {
		if strings.EqualFold(strings.TrimSpace(u.Username), strings.TrimSpace(username)) {
			return true
		}
	}
	return false
}

func validateTrustUsername(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return errors.New("trust username is required")
	}
	if !trustUserRe.MatchString(username) {
		return fmt.Errorf("invalid trust username %q (allowed: A-Z a-z 0-9 . _ @ -)", username)
	}
	return nil
}

func normalizeSocksLogin(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}

func validateSocksLogin(login string) error {
	login = normalizeSocksLogin(login)
	if login == "" {
		return errors.New("socks login is required")
	}
	if !socksUserRe.MatchString(login) {
		return fmt.Errorf("invalid socks login %q (allowed: lowercase linux login, e.g. user01)", login)
	}
	return nil
}

func socksSystemUser(u socksUser) string {
	if strings.TrimSpace(u.SystemUser) != "" {
		return strings.TrimSpace(u.SystemUser)
	}
	return normalizeSocksLogin(u.Name)
}

func hasSocksUserExact(users []socksUser, login string) bool {
	login = normalizeSocksLogin(login)
	for _, u := range users {
		if normalizeSocksLogin(u.Name) == login {
			return true
		}
	}
	return false
}

func findSocksUserIndex(users []socksUser, login string) int {
	login = normalizeSocksLogin(login)
	for i, u := range users {
		if normalizeSocksLogin(u.Name) == login {
			return i
		}
	}
	return -1
}

func resolveSocksUser(users []socksUser, id string) (socksUser, int, error) {
	key := normalizeSocksLogin(id)
	if key == "" {
		return socksUser{}, -1, errors.New("empty USER_ID")
	}
	var exactIdx []int
	for i, u := range users {
		if normalizeSocksLogin(u.Name) == key {
			exactIdx = append(exactIdx, i)
		}
	}
	if len(exactIdx) == 1 {
		idx := exactIdx[0]
		return users[idx], idx, nil
	}
	if len(exactIdx) > 1 {
		return socksUser{}, -1, fmt.Errorf("multiple socks users have name %q", key)
	}

	var partialIdx []int
	for i, u := range users {
		if strings.Contains(normalizeSocksLogin(u.Name), key) {
			partialIdx = append(partialIdx, i)
		}
	}
	if len(partialIdx) == 1 {
		idx := partialIdx[0]
		return users[idx], idx, nil
	}
	if len(partialIdx) == 0 {
		return socksUser{}, -1, fmt.Errorf("socks user not found: %s", key)
	}
	return socksUser{}, -1, fmt.Errorf("multiple socks users match %q", key)
}

func osSocksUserExists(login string) bool {
	login = normalizeSocksLogin(login)
	if login == "" {
		return false
	}
	_, err := runCommandOutput("id", "-u", login)
	return err == nil
}

func requireRoot(action string) error {
	if os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("%s requires root (run with sudo)", action)
}

func parseTOMLStringKey(raw, key string) (string, bool, error) {
	lines := strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n")
	for _, line := range lines {
		trimmed := stripTOMLComment(line)
		if trimmed == "" {
			continue
		}
		v, ok, err := parseTOMLStringAssignment(trimmed, key)
		if err != nil {
			return "", false, err
		}
		if ok {
			return v, true, nil
		}
	}
	return "", false, nil
}

func parseTOMLStringAssignment(line, key string) (string, bool, error) {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", false, nil
	}
	k := strings.TrimSpace(parts[0])
	if k != key {
		return "", false, nil
	}
	rawValue := strings.TrimSpace(parts[1])
	v, err := strconv.Unquote(rawValue)
	if err != nil {
		return "", false, fmt.Errorf("invalid TOML string for %s: %s", key, rawValue)
	}
	return v, true, nil
}

func stripTOMLComment(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	inString := false
	escaped := false
	for i, ch := range line {
		switch {
		case ch == '\\' && inString && !escaped:
			escaped = true
			continue
		case ch == '"' && !escaped:
			inString = !inString
		case ch == '#' && !inString:
			return strings.TrimSpace(line[:i])
		}
		escaped = false
	}
	return strings.TrimSpace(line)
}

func parseListenAddress(addr string) (string, string, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", errors.New("empty address")
	}
	idx := strings.LastIndex(addr, ":")
	if idx <= 0 || idx >= len(addr)-1 {
		return "", "", fmt.Errorf("invalid address: %s", addr)
	}
	host := strings.TrimSpace(addr[:idx])
	port := strings.TrimSpace(addr[idx+1:])
	p, err := strconv.Atoi(port)
	if err != nil || p <= 0 || p > 65535 {
		return "", "", fmt.Errorf("invalid port in address: %s", addr)
	}
	host = strings.Trim(host, "[]")
	return host, port, nil
}

func detectPublicIPv4() (string, error) {
	if envIP := strings.TrimSpace(os.Getenv("PSAS_PUBLIC_IP")); envIP != "" {
		if isIPv4(envIP) {
			return envIP, nil
		}
		return "", fmt.Errorf("PSAS_PUBLIC_IP is not valid IPv4: %s", envIP)
	}

	if out, err := runCommandOutput("curl", "-4", "-fsSL", "--max-time", "4", "https://api.ipify.org"); err == nil {
		ip := strings.TrimSpace(out)
		if isIPv4(ip) {
			return ip, nil
		}
	}

	if out, err := runCommandOutput("ip", "-4", "route", "get", "1.1.1.1"); err == nil {
		fields := strings.Fields(out)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "src" && isIPv4(fields[i+1]) {
				return fields[i+1], nil
			}
		}
	}

	return "", errors.New("unable to detect public IPv4 automatically; pass --address <ip:port> or set PSAS_PUBLIC_IP")
}

func newSecureToken(length int) string {
	if length <= 0 {
		length = 24
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	raw := make([]byte, length)
	mustReadRand(raw)
	out := make([]byte, length)
	for i, b := range raw {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}

func (c *client) loadState() error {
	out, err := c.runPanel("all-configs")
	if err != nil {
		return err
	}
	jsonOut, err := extractJSONObject(out)
	if err != nil {
		return fmt.Errorf("parse all-configs: %w; output=%q", err, shortText(string(stripANSI(out)), 240))
	}
	var st state
	if err := json.Unmarshal(jsonOut, &st); err != nil {
		return fmt.Errorf("parse all-configs: %w", err)
	}
	if st.APIPath == "" || st.APIKey == "" {
		return errors.New("invalid all-configs output: empty api_path/api_key")
	}
	c.state = st
	return nil
}

func (c *client) runPanel(args ...string) ([]byte, error) {
	cmdArgs := append([]string{"-m", "hiddifypanel"}, args...)
	cmd := exec.Command(c.panelPy, cmdArgs...)
	cmd.Env = append(os.Environ(), "HIDDIFY_CFG_PATH="+c.panelCfg)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := bytes.TrimSpace(stdout.Bytes())
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = strings.TrimSpace(stdout.String())
		}
		return nil, fmt.Errorf("panel cli failed: %w\n%s", err, msg)
	}
	if len(out) == 0 {
		// Some panel builds may print to stderr on success.
		out = bytes.TrimSpace(stderr.Bytes())
	}
	return out, nil
}

func (c *client) api(method, path string, body any) ([]byte, error) {
	url := strings.TrimRight(c.panelAddr, "/") + "/" + strings.Trim(c.state.APIPath, "/") + "/api/v2/admin/" + strings.TrimLeft(path, "/")

	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Hiddify-API-Key", c.state.APIKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("api %s %s failed: %s\n%s", method, path, resp.Status, string(respBody))
	}
	return respBody, nil
}

func (c *client) usersList() ([]apiUser, error) {
	b, err := c.api(http.MethodGet, "user/", nil)
	if err != nil {
		return nil, err
	}
	var users []apiUser
	if err := json.Unmarshal(b, &users); err != nil {
		return nil, err
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	return users, nil
}

func (c *client) userShow(uuid string) (apiUser, error) {
	b, err := c.api(http.MethodGet, "user/"+uuid+"/", nil)
	if err != nil {
		return apiUser{}, err
	}
	var u apiUser
	if err := json.Unmarshal(b, &u); err != nil {
		return apiUser{}, err
	}
	return u, nil
}

func (c *client) userAdd(payload map[string]any) (apiUser, error) {
	b, err := c.api(http.MethodPost, "user/", payload)
	if err != nil {
		return apiUser{}, err
	}
	var u apiUser
	if err := json.Unmarshal(b, &u); err != nil {
		return apiUser{}, err
	}
	return u, nil
}

func (c *client) userPatch(uuid string, payload map[string]any) (apiUser, error) {
	b, err := c.api(http.MethodPatch, "user/"+uuid+"/", payload)
	if err != nil {
		return apiUser{}, err
	}
	var u apiUser
	if err := json.Unmarshal(b, &u); err != nil {
		return apiUser{}, err
	}
	return u, nil
}

func (c *client) userDelete(uuid string) error {
	_, err := c.api(http.MethodDelete, "user/"+uuid+"/", nil)
	return err
}

func (c *client) resolveUser(id string) (apiUser, error) {
	key := strings.TrimSpace(id)
	if key == "" {
		return apiUser{}, errors.New("empty USER_ID")
	}
	if uuidRe.MatchString(key) {
		u, err := c.userShow(strings.ToLower(key))
		if err != nil {
			return apiUser{}, fmt.Errorf("user not found by UUID: %s", key)
		}
		return u, nil
	}

	users, err := c.usersList()
	if err != nil {
		return apiUser{}, err
	}
	if len(users) == 0 {
		return apiUser{}, errors.New("no users in panel")
	}

	var exact []apiUser
	for _, u := range users {
		if strings.EqualFold(strings.TrimSpace(u.Name), key) {
			exact = append(exact, u)
		}
	}
	if len(exact) == 1 {
		return exact[0], nil
	}
	if len(exact) > 1 {
		return apiUser{}, fmt.Errorf("multiple users have name %q: %s", key, formatUserRefs(exact))
	}

	var partial []apiUser
	lkey := strings.ToLower(key)
	for _, u := range users {
		if strings.Contains(strings.ToLower(u.Name), lkey) {
			partial = append(partial, u)
		}
	}
	if len(partial) == 1 {
		return partial[0], nil
	}
	if len(partial) == 0 {
		return apiUser{}, fmt.Errorf("user not found by name/UUID: %s", key)
	}
	return apiUser{}, fmt.Errorf("multiple matches for %q: %s", key, formatUserRefs(partial))
}

func (c *client) setConfig(key, value string) error {
	_, err := c.runPanel("set-setting", "-k", key, "-v", value)
	return err
}

type textPatch struct {
	Old    string
	New    string
	Marker string
}

func (c *client) ensureTrueUnlimitedSupport() error {
	panelPkgDir, err := c.panelPackageDir()
	if err != nil {
		return err
	}

	userModelPath := filepath.Join(panelPkgDir, "models", "user.py")
	hiddifyPath := filepath.Join(panelPkgDir, "panel", "hiddify.py")

	userPatches := []textPatch{
		{
			Old: `        is_active = True
        if not self:
            is_active = False
        elif not self.enable:
            is_active = False
        elif self.usage_limit < self.current_usage:
            is_active = False
        elif self.remaining_days < 0:
            is_active = False
`,
			New: `        is_active = True
        unlimited_usage = self.usage_limit >= 1000000 * ONE_GIG
        unlimited_days = (self.package_days or 0) >= 10000
        if not self:
            is_active = False
        elif not self.enable:
            is_active = False
        elif (not unlimited_usage) and self.usage_limit < self.current_usage:
            is_active = False
        elif (not unlimited_days) and self.remaining_days < 0:
            is_active = False
`,
			Marker: "unlimited_usage = self.usage_limit >= 1000000 * ONE_GIG",
		},
		{
			Old: `        res = -1
        if self.package_days is None:
            res = -1
        elif self.start_date:
            # print(datetime.date.today(), u.start_date,u.package_days, u.package_days - (datetime.date.today() - u.start_date).days)
            res = self.package_days - (datetime.date.today() - self.start_date).days
        else:
            # print("else",u.package_days )
            res = self.package_days
        return min(res, 10000)
`,
			New: `        if (self.package_days or 0) >= 10000:
            return 10000

        res = -1
        if self.package_days is None:
            res = -1
        elif self.start_date:
            # print(datetime.date.today(), u.start_date,u.package_days, u.package_days - (datetime.date.today() - self.start_date).days)
            res = self.package_days - (datetime.date.today() - self.start_date).days
        else:
            # print("else",u.package_days )
            res = self.package_days
        return min(res, 10000)
`,
			Marker: "if (self.package_days or 0) >= 10000:",
		},
	}
	hiddifyPatches := []textPatch{
		{
			Old:    "    valid_users = [u.to_dict(dump_id=True) for u in User.query.filter((User.usage_limit > User.current_usage)).all() if u.is_active]\n",
			New:    "    valid_users = [u.to_dict(dump_id=True) for u in User.query.filter((User.usage_limit > User.current_usage) | (User.usage_limit >= 1000000 * 1024 * 1024 * 1024)).all() if u.is_active]\n",
			Marker: "User.usage_limit >= 1000000 * 1024 * 1024 * 1024",
		},
	}

	changedUsers, err := applyTextPatches(userModelPath, userPatches)
	if err != nil {
		return fmt.Errorf("true-unlimited patch failed for %s: %w", userModelPath, err)
	}
	changedHiddify, err := applyTextPatches(hiddifyPath, hiddifyPatches)
	if err != nil {
		return fmt.Errorf("true-unlimited patch failed for %s: %w", hiddifyPath, err)
	}

	if !changedUsers && !changedHiddify {
		return nil
	}

	fmt.Println("Enabled true unlimited support in Hiddify.")
	if err := restartHiddifyServices(); err != nil {
		return fmt.Errorf("true-unlimited patch applied, but failed to restart services: %w", err)
	}
	if err := c.waitPanelHTTP(45 * time.Second); err != nil {
		return fmt.Errorf("true-unlimited patch applied, but panel did not become reachable in time: %w", err)
	}
	return nil
}

func applyTextPatches(path string, patches []textPatch) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	orig := string(raw)
	updated := orig

	for _, p := range patches {
		if p.Marker != "" && strings.Contains(updated, p.Marker) {
			continue
		}
		if p.New != "" && strings.Contains(updated, p.New) {
			continue
		}
		if !strings.Contains(updated, p.Old) {
			return false, fmt.Errorf("patch pattern not found")
		}
		updated = strings.Replace(updated, p.Old, p.New, 1)
	}

	if updated == orig {
		return false, nil
	}

	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	backupPath := path + ".psas.bak"
	if !fileExists(backupPath) {
		if err := os.WriteFile(backupPath, raw, info.Mode()); err != nil {
			return false, err
		}
	}
	if err := os.WriteFile(path, []byte(updated), info.Mode()); err != nil {
		return false, err
	}
	return true, nil
}

func (c *client) panelPackageDir() (string, error) {
	cmd := exec.Command(c.panelPy, "-c", "import pathlib,hiddifypanel; print(pathlib.Path(hiddifypanel.__file__).resolve().parent)")
	cmd.Env = append(os.Environ(), "HIDDIFY_CFG_PATH="+c.panelCfg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("detect hiddifypanel package dir: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	lines := strings.Split(strings.ReplaceAll(string(out), "\r", ""), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		dir := strings.TrimSpace(lines[i])
		if dir == "" {
			continue
		}
		if !filepath.IsAbs(dir) {
			return "", fmt.Errorf("invalid hiddifypanel package dir: %q", dir)
		}
		return dir, nil
	}
	return "", errors.New("empty output while detecting hiddifypanel package dir")
}

func restartHiddifyServices() error {
	if fileExists("/opt/hiddify-manager/common/commander.py") {
		return runCommand("/opt/hiddify-manager/common/commander.py", "restart-services")
	}
	return errors.New("/opt/hiddify-manager/common/commander.py not found")
}

func (c *client) waitPanelHTTP(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := strings.TrimRight(c.panelAddr, "/") + "/"
	httpClient := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := httpClient.Get(url)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		lastErr = err
		time.Sleep(1 * time.Second)
	}
	if lastErr == nil {
		lastErr = errors.New("panel is not reachable")
	}
	return lastErr
}

func (c *client) currentConfig() map[string]any {
	if c.state.Chconfigs == nil {
		return map[string]any{}
	}
	cfg, ok := c.state.Chconfigs["0"]
	if !ok {
		return map[string]any{}
	}
	return cfg
}

func (c *client) mainDomain() string {
	for _, d := range c.state.Domains {
		if d.Mode == "direct" && !isIPv4(d.Domain) {
			return d.Domain
		}
	}
	for _, d := range c.state.Domains {
		if d.Mode == "direct" {
			return d.Domain
		}
	}
	return ""
}

func (c *client) mainDomainOrErr() (string, error) {
	h := strings.TrimSpace(c.mainDomain())
	if h == "" {
		return "", errors.New("main domain not found in Hiddify domains; pass --host explicitly")
	}
	return h, nil
}

func (c *client) mainDomainRequired() string {
	h, err := c.mainDomainOrErr()
	if err != nil {
		fatalf("%v", err)
	}
	return h
}

func (c *client) clientPath() string {
	v := c.currentConfig()["proxy_path_client"]
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func (c *client) adminURL(host string) string {
	return "https://" + strings.TrimSpace(host) + strings.TrimSpace(c.state.AdminPath)
}

func printUsers(users []apiUser) {
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "UUID\tNAME\tENABLED\tLIMIT_GB\tDAYS\tMODE")
	for _, u := range users {
		fmt.Fprintf(tw, "%s\t%s\t%t\t%.2f\t%d\t%s\n", u.UUID, u.Name, u.Enable, u.UsageLimitGB, u.PackageDays, u.Mode)
	}
	_ = tw.Flush()
}

func filterUsers(users []apiUser, nameFilter string, enabledOnly bool) []apiUser {
	if nameFilter == "" && !enabledOnly {
		return users
	}
	out := make([]apiUser, 0, len(users))
	q := strings.ToLower(strings.TrimSpace(nameFilter))
	for _, u := range users {
		if enabledOnly && !u.Enable {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(u.Name), q) {
			continue
		}
		out = append(out, u)
	}
	return out
}

func printUser(u apiUser) {
	fmt.Println()
	fmt.Println("User Details")
	fmt.Println("============")
	fmt.Printf("UUID      : %s\n", u.UUID)
	fmt.Printf("Name      : %s\n", u.Name)
	fmt.Printf("Enabled   : %t\n", u.Enable)
	fmt.Printf("Limit GB  : %.2f\n", u.UsageLimitGB)
	fmt.Printf("Days      : %d\n", u.PackageDays)
	fmt.Printf("Mode      : %s\n", u.Mode)
}

func buildLinks(clientPath, uuid, host string) linkSet {
	base := fmt.Sprintf("https://%s/%s/%s", strings.TrimSpace(host), strings.Trim(clientPath, "/"), strings.TrimSpace(uuid))
	return linkSet{
		UUID:    strings.TrimSpace(uuid),
		Host:    strings.TrimSpace(host),
		Panel:   base + "/",
		Auto:    base + "/auto/",
		Sub64:   base + "/sub64/",
		Sub:     base + "/sub/",
		Singbox: base + "/singbox/",
	}
}

func printLinksFromSet(l linkSet) {
	fmt.Println()
	fmt.Println("Access Links")
	fmt.Println("============")
	fmt.Printf("User UUID           : %s\n", l.UUID)
	fmt.Printf("Panel URL           : %s\n", l.Panel)
	fmt.Printf("Hiddify (auto)      : %s\n", l.Auto)
	fmt.Printf("Subscription b64    : %s\n", l.Sub64)
	fmt.Printf("Subscription plain  : %s\n", l.Sub)
	fmt.Printf("Sing-box            : %s\n", l.Singbox)
}

func formatUserRefs(users []apiUser) string {
	if len(users) == 0 {
		return ""
	}
	const maxItems = 5
	items := make([]string, 0, min(len(users), maxItems))
	for i, u := range users {
		if i >= maxItems {
			break
		}
		items = append(items, fmt.Sprintf("%s(%s)", u.Name, u.UUID))
	}
	if len(users) > maxItems {
		items = append(items, fmt.Sprintf("+%d more", len(users)-maxItems))
	}
	return strings.Join(items, ", ")
}

func printJSON(v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	fmt.Println(string(b))
}

func extractJSONObject(raw []byte) ([]byte, error) {
	cleaned := bytes.TrimSpace(stripANSI(raw))
	if len(cleaned) == 0 {
		return nil, errors.New("empty output")
	}
	if json.Valid(cleaned) {
		return cleaned, nil
	}
	start := bytes.IndexByte(cleaned, '{')
	end := bytes.LastIndexByte(cleaned, '}')
	if start == -1 || end == -1 || end < start {
		return nil, errors.New("json object not found in output")
	}
	payload := bytes.TrimSpace(cleaned[start : end+1])
	if !json.Valid(payload) {
		return nil, errors.New("json object is invalid")
	}
	return payload, nil
}

func stripANSI(b []byte) []byte {
	s := ansiRe.ReplaceAllString(string(b), "")
	s = strings.ReplaceAll(s, "\r", "")
	return []byte(s)
}

func shortText(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	if maxLen < 4 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func isInteractiveTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func promptLine(in *bufio.Reader, label, def string) (string, error) {
	label = uiText(label)
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	s, err := in.ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) {
			s = strings.TrimSpace(s)
			if s == "" {
				return "", io.EOF
			}
			return s, nil
		}
		return "", err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return s, nil
}

func promptRequiredLine(in *bufio.Reader, label string) (string, error) {
	for {
		s, err := promptLine(in, label, "")
		if err != nil {
			return "", err
		}
		if strings.TrimSpace(s) != "" {
			return s, nil
		}
		printError(uiText("Value is required."))
	}
}

func promptPositiveIntValue(in *bufio.Reader, label string, def int) (int, error) {
	defStr := strconv.Itoa(def)
	for {
		raw, err := promptLine(in, label, defStr)
		if err != nil {
			return 0, err
		}
		v, err := parsePositiveInt(raw)
		if err != nil {
			printError(uiTextf("Invalid value: %v", err))
			continue
		}
		return v, nil
	}
}

func promptPositiveFloatValue(in *bufio.Reader, label string, def float64) (float64, error) {
	defStr := strconv.FormatFloat(def, 'f', -1, 64)
	for {
		raw, err := promptLine(in, label, defStr)
		if err != nil {
			return 0, err
		}
		v, err := parsePositiveFloat(raw)
		if err != nil {
			printError(uiTextf("Invalid value: %v", err))
			continue
		}
		return v, nil
	}
}

func promptUUIDOrAuto(in *bufio.Reader, label string) (string, error) {
	for {
		raw, err := promptLine(in, label, "")
		if err != nil {
			return "", err
		}
		id := strings.TrimSpace(raw)
		if id == "" {
			return newUUID(), nil
		}
		if err := validateUUID(id); err != nil {
			printError(err.Error())
			continue
		}
		return strings.ToLower(id), nil
	}
}

func parsePositiveInt(s string) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if v <= 0 {
		return 0, errors.New("must be > 0")
	}
	return v, nil
}

func parsePositiveFloat(s string) (float64, error) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, err
	}
	if v <= 0 {
		return 0, errors.New("must be > 0")
	}
	return v, nil
}

func resolveUserDisplayName(name, subscriptionName string, required bool) (string, error) {
	n := strings.TrimSpace(name)
	s := strings.TrimSpace(subscriptionName)
	if s != "" {
		if n != "" && n != s {
			return "", errors.New("--name and --subscription-name must be the same when both are provided")
		}
		n = s
	}
	if required && n == "" {
		return "", errors.New("name is required")
	}
	return n, nil
}

func parseBoolLike(raw string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "t", "yes", "y", "on", "enable", "enabled", "да", "д":
		return true, nil
	case "0", "false", "f", "no", "n", "off", "disable", "disabled", "нет", "н":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", raw)
	}
}

func anyToBool(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		b, err := parseBoolLike(x)
		if err == nil {
			return b
		}
		return strings.TrimSpace(x) != ""
	case float64:
		return x != 0
	case float32:
		return x != 0
	case int:
		return x != 0
	case int8:
		return x != 0
	case int16:
		return x != 0
	case int32:
		return x != 0
	case int64:
		return x != 0
	case uint:
		return x != 0
	case uint8:
		return x != 0
	case uint16:
		return x != 0
	case uint32:
		return x != 0
	case uint64:
		return x != 0
	default:
		return false
	}
}

func isYes(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes", "1", "true", "да", "д":
		return true
	default:
		return false
	}
}

func isValidMode(m string) bool {
	switch m {
	case "no_reset", "daily", "weekly", "monthly":
		return true
	default:
		return false
	}
}

func validateUUID(s string) error {
	if !uuidRe.MatchString(s) {
		return fmt.Errorf("invalid UUID: %s", s)
	}
	return nil
}

func mustValidUUID(s string) {
	if err := validateUUID(s); err != nil {
		fatalf("%v", err)
	}
}

func newUUID() string {
	b := make([]byte, 16)
	mustReadRand(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func mustReadRand(b []byte) {
	if _, err := rand.Read(b); err != nil {
		fatalf("failed to generate UUID: %v", err)
	}
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, ch := range p {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}
	return true
}

func normalizeUILang(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case uiLangUS:
		return uiLangUS
	case uiLangRU:
		return uiLangRU
	default:
		return ""
	}
}

func uiLangConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("PSAS_UI_LANG_FILE")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err == nil && strings.TrimSpace(home) != "" {
		return filepath.Join(home, ".config", "psasctl", "ui.json")
	}
	return "/tmp/psasctl-ui.json"
}

func initUILanguage() {
	currentUILang = defaultUILang
	if env := normalizeUILang(os.Getenv("PSAS_UI_LANG")); env != "" {
		currentUILang = env
		return
	}
	path := uiLangConfigPath()
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var cfg uiSettings
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return
	}
	if lang := normalizeUILang(cfg.Lang); lang != "" {
		currentUILang = lang
	}
}

func setUILang(lang string, persist bool) error {
	lang = normalizeUILang(lang)
	if lang == "" {
		return errors.New("unsupported UI language (expected us|ru)")
	}
	currentUILang = lang
	if !persist {
		return nil
	}
	path := uiLangConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(uiSettings{Lang: lang}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(payload, '\n'), 0o600)
}

func uiText(s string) string {
	if currentUILang != uiLangRU {
		return s
	}
	if v, ok := uiTextRU[s]; ok {
		return v
	}
	return s
}

func uiTextf(format string, args ...any) string {
	return fmt.Sprintf(uiText(format), args...)
}

func runCommand(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func runCommandOutput(bin string, args ...string) (string, error) {
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func runCommandInput(input, bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func envOr(k, v string) string {
	if x := strings.TrimSpace(os.Getenv(k)); x != "" {
		return x
	}
	return v
}

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	if !filepath.IsAbs(p) {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "Error: "+format+"\n", args...)
	os.Exit(1)
}
