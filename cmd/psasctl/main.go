package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"unicode"
)

const (
	defaultPanelCfg  = "/opt/hiddify-manager/hiddify-panel/app.cfg"
	defaultPanelAddr = "http://127.0.0.1:9000"
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

var uuidRe = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var errUISelectionCanceled = errors.New("selection canceled")
var errUIManualEntry = errors.New("manual entry requested")

func main() {
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
	case "config":
		runConfig(args)
	case "apply":
		runApply(args)
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
  psasctl users add --name NAME [--days 30] [--gb 100] [--mode no_reset] [--host DOMAIN] [--uuid UUID] [--json]
  psasctl users show [--host DOMAIN] [--json] <USER_ID>
  psasctl users links [--host DOMAIN] [--json] <USER_ID>
  psasctl users del <USER_ID>
  psasctl config get <key>
  psasctl config set <key> <value>
  psasctl apply

USER_ID can be UUID or user name (exact/substring match).

Environment overrides:
  PSAS_PANEL_CFG   (default /opt/hiddify-manager/hiddify-panel/app.cfg)
  PSAS_PANEL_ADDR  (default http://127.0.0.1:9000)
  PSAS_PANEL_PY    (default auto-detect .venv313/.venv/python3)
`)
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output JSON")
	must(fs.Parse(args))
	if len(fs.Args()) != 0 {
		fatalf("status takes no positional args")
	}
	c := mustClient(true)
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
}

func runAdminURL(args []string) {
	if len(args) != 0 {
		fatalf("admin-url takes no args")
	}
	c := mustClient(true)
	fmt.Println(c.adminURL(c.mainDomainRequired()))
}

func runUsers(args []string) {
	if len(args) < 1 {
		fatalf("users requires subcommand: list|find|add|show|links|del")
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
		days := fs.Int("days", 30, "package days")
		gb := fs.Float64("gb", 100, "usage limit in GB")
		mode := fs.String("mode", "no_reset", "user mode: no_reset|daily|weekly|monthly")
		host := fs.String("host", "", "domain for generated links")
		uuid := fs.String("uuid", "", "custom UUID (optional)")
		jsonOut := fs.Bool("json", false, "output JSON")
		must(fs.Parse(subArgs))
		if len(fs.Args()) != 0 {
			fatalf("users add takes only flags")
		}
		if *name == "" {
			fatalf("--name is required")
		}
		if !isValidMode(*mode) {
			fatalf("invalid --mode: %s", *mode)
		}
		if *days < 1 {
			fatalf("--days must be >= 1")
		}
		if *gb <= 0 {
			fatalf("--gb must be > 0")
		}
		newID := strings.TrimSpace(*uuid)
		if newID == "" {
			newID = newUUID()
		} else {
			mustValidUUID(newID)
		}
		payload := map[string]any{
			"uuid":           strings.ToLower(newID),
			"name":           *name,
			"package_days":   *days,
			"usage_limit_GB": *gb,
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
		{Key: "status", Shortcut: 's', Title: "Status", Hint: "Main domain, admin URL, protocols, users count"},
		{Key: "list", Shortcut: 'l', Title: "List users", Hint: "Print all users in a table"},
		{Key: "find", Shortcut: 'f', Title: "Find users", Hint: "Search users by name/part and optional enabled filter"},
		{Key: "show", Shortcut: 'v', Title: "Show user + links", Hint: "Pick a user with arrows and print links"},
		{Key: "add", Shortcut: 'a', Title: "Add user", Hint: "Step-by-step wizard for creating a user"},
		{Key: "delete", Shortcut: 'd', Title: "Delete user", Hint: "Pick a user and delete with confirmation"},
		{Key: "admin", Shortcut: 'u', Title: "Admin URL", Hint: "Print panel admin URL"},
		{Key: "apply", Shortcut: 'p', Title: "Apply config", Hint: "Run hiddify-apply-safe or panel apply"},
		{Key: "wizard", Shortcut: 'w', Title: "Flag command wizard", Hint: "Build and run existing psasctl commands with their original flags"},
		{Key: "exit", Shortcut: 'q', Title: "Exit", Hint: "Leave interactive mode"},
	}

	for {
		choice, err := uiSelectMenuItem(menuItems, in)
		if err != nil {
			fatalf("ui input error: %v", err)
		}
		if choice.Key == "exit" {
			clearScreen()
			return
		}

		clearScreen()
		fmt.Printf("=== %s ===\n\n", choice.Title)

		var actionErr error
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
		case "delete":
			actionErr = uiDeleteUser(c, in)
		case "admin":
			actionErr = uiAdminURL(c)
		case "apply":
			actionErr = applyWithClient(c)
		case "wizard":
			actionErr = uiRunFlagWizard(c, in)
		default:
			actionErr = fmt.Errorf("unknown option: %s", choice.Key)
		}

		if actionErr != nil {
			if errors.Is(actionErr, errUISelectionCanceled) {
				fmt.Println("Canceled.")
			} else {
				fmt.Printf("Error: %v\n", actionErr)
			}
		}
		must(uiPause(in))
	}
}

type uiMenuItem struct {
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
	rawIn := bufio.NewReader(os.Stdin)
	for {
		drawUIMenu(items, selected)
		input, err := readUIMenuKey(rawIn)
		if err != nil {
			return uiMenuItem{}, err
		}
		switch input.Key {
		case uiMenuKeyUp:
			selected--
			if selected < 0 {
				selected = len(items) - 1
			}
		case uiMenuKeyDown:
			selected++
			if selected >= len(items) {
				selected = 0
			}
		case uiMenuKeyHome:
			selected = 0
		case uiMenuKeyEnd:
			selected = len(items) - 1
		case uiMenuKeyEnter:
			return items[selected], nil
		case uiMenuKeyQuit:
			return uiMenuItem{Key: "exit", Title: "Exit"}, nil
		case uiMenuKeyChar:
			ch := unicode.ToLower(input.Ch)
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
			case 'g':
				selected = 0
				continue
			case 'q':
				return uiMenuItem{Key: "exit", Title: "Exit"}, nil
			}
			if ch >= '1' && ch <= '9' {
				idx := int(ch - '1')
				if idx >= 0 && idx < len(items) {
					return items[idx], nil
				}
			}
			if idx, ok := findMenuItemByShortcut(items, ch); ok {
				return items[idx], nil
			}
		}
	}
}

func uiSelectMenuItemFallback(items []uiMenuItem, in *bufio.Reader) (uiMenuItem, error) {
	clearScreen()
	fmt.Println("psasctl interactive menu")
	fmt.Println("Arrow-mode is unavailable in this terminal; fallback to number input.")
	fmt.Println()
	for i, item := range items {
		fmt.Printf("  %d) %s\n", i+1, item.Title)
	}
	for {
		raw, err := promptRequiredLine(in, "Choose option number")
		if err != nil {
			return uiMenuItem{}, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || n < 1 || n > len(items) {
			fmt.Printf("Invalid option. Enter number 1-%d.\n", len(items))
			continue
		}
		return items[n-1], nil
	}
}

func drawUIMenu(items []uiMenuItem, selected int) {
	clearScreen()
	fmt.Println("psasctl interactive console")
	fmt.Println("Navigate with Arrow Up/Down (or j/k), Enter to select, q to exit.")
	fmt.Println("Quick select: number 1-9 or shortcut key in brackets.")
	fmt.Println()
	for i, item := range items {
		cursor := "  "
		if i == selected {
			cursor = "> "
		}
		hotkey := ""
		if item.Shortcut != 0 {
			hotkey = fmt.Sprintf(" [%c]", unicode.ToLower(item.Shortcut))
		}
		fmt.Printf("%s%d) %s%s\n", cursor, i+1, item.Title, hotkey)
	}
	if selected >= 0 && selected < len(items) && items[selected].Hint != "" {
		fmt.Println()
		fmt.Printf("Hint: %s\n", items[selected].Hint)
	}
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

	set := exec.Command("stty", "raw", "-echo")
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
	fmt.Print("\033[H\033[2J")
}

func uiPause(in *bufio.Reader) error {
	fmt.Print("\nPress Enter to return to menu...")
	_, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
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
		{Value: "users-add", Title: "users add", Hint: "Supports --name, --days, --gb, --mode, --host, --uuid, --json"},
		{Value: "users-del", Title: "users del", Hint: "Delete by USER_ID"},
		{Value: "config-get", Title: "config get", Hint: "Get config by key"},
		{Value: "config-set", Title: "config set", Hint: "Set config key/value"},
		{Value: "apply", Title: "apply", Hint: "Apply config safely"},
	}

	choice, err := uiSelectOptionValue("Select command to build", options, 0, in)
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

	fmt.Printf("Command: psasctl %s\n", quoteCommandArgs(args))
	runNow, err := promptYesNo(in, "Run this command?", true)
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
		days, err := promptPositiveIntValue(in, "Package days (--days)", 30)
		if err != nil {
			return nil, err
		}
		gb, err := promptPositiveFloatValue(in, "Usage limit GB (--gb)", 100)
		if err != nil {
			return nil, err
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
			"--days", strconv.Itoa(days),
			"--gb", strconv.FormatFloat(gb, 'f', -1, 64),
			"--mode", mode,
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
	case "apply":
		return []string{"apply"}, nil
	default:
		return nil, fmt.Errorf("unsupported wizard command: %s", choice)
	}
}

func promptYesNo(in *bufio.Reader, label string, def bool) (bool, error) {
	defRaw := "n"
	if def {
		defRaw = "y"
	}
	raw, err := promptLine(in, label+" (y/n)", defRaw)
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
			fmt.Println(err)
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
	fmt.Println(title)
	fmt.Println("Arrow-mode is unavailable; choose by number.")
	fmt.Println()
	for i, opt := range options {
		fmt.Printf("  %d) %s\n", i+1, opt.Title)
	}
	fmt.Println("  q) Cancel")
	def := strconv.Itoa(defaultIdx + 1)
	for {
		raw, err := promptLine(in, "Choose option number", def)
		if err != nil {
			return "", err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return "", errUISelectionCanceled
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > len(options) {
			fmt.Printf("Invalid option. Enter number 1-%d or q.\n", len(options))
			continue
		}
		return options[n-1].Value, nil
	}
}

func drawUIOptionsMenu(title string, options []uiOption, selected int) {
	clearScreen()
	fmt.Println(title)
	fmt.Println("Use Arrow Up/Down (or j/k), Enter to select, q to cancel.")
	fmt.Println()
	for i, opt := range options {
		cursor := "  "
		if i == selected {
			cursor = "> "
		}
		fmt.Printf("%s%d) %s\n", cursor, i+1, opt.Title)
	}
	if selected >= 0 && selected < len(options) && options[selected].Hint != "" {
		fmt.Println()
		fmt.Printf("Hint: %s\n", options[selected].Hint)
	}
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
	fmt.Println(title)
	fmt.Println("Arrow-mode is unavailable; choose by number.")
	fmt.Println()
	for i, u := range users {
		state := "off"
		if u.Enable {
			state = "on"
		}
		fmt.Printf("  %d) %s (%s) [%s]\n", i+1, u.Name, u.UUID, state)
	}
	fmt.Println("  0) Manual USER_ID input")
	fmt.Println("  q) Cancel")
	for {
		raw, err := promptRequiredLine(in, "Choose user number")
		if err != nil {
			return apiUser{}, err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return apiUser{}, errUISelectionCanceled
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > len(users) {
			fmt.Printf("Invalid option. Enter number 0-%d or q.\n", len(users))
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
	fmt.Println(title)
	fmt.Println("Use Arrow Up/Down to pick, Enter to select, type to filter, Backspace to erase.")
	fmt.Println("Press i for manual USER_ID input, q to cancel.")
	fmt.Println()
	fmt.Printf("Filter: %s\n", query)
	fmt.Printf("Matches: %d/%d\n", len(filtered), len(users))
	fmt.Println()

	if len(filtered) == 0 {
		fmt.Println("No users match current filter.")
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

	for i := start; i < end; i++ {
		u := filtered[i]
		cursor := "  "
		if i == selected {
			cursor = "> "
		}
		state := "off"
		if u.Enable {
			state = "on "
		}
		fmt.Printf("%s%-18s %-36s [%s]\n", cursor, shortText(u.Name, 18), u.UUID, state)
	}

	if end < len(filtered) {
		fmt.Println()
		fmt.Printf("Showing %d-%d of %d matches\n", start+1, end, len(filtered))
	}
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

func uiStatus(c *client) error {
	if err := c.loadState(); err != nil {
		return err
	}
	cfg := c.currentConfig()
	mainDomain := c.mainDomain()

	fmt.Printf("Main domain: %s\n", mainDomain)
	fmt.Printf("Admin URL: %s\n", c.adminURL(mainDomain))
	fmt.Printf("Client path: %v\n", cfg["proxy_path_client"])
	fmt.Printf("Reality enabled: %v\n", cfg["reality_enable"])
	fmt.Printf("Hysteria2 enabled: %v\n", cfg["hysteria_enable"])
	fmt.Printf("Hysteria base port: %v\n", cfg["hysteria_port"])
	fmt.Printf("Reality SNI: %v\n", cfg["reality_server_names"])
	fmt.Printf("Users: %d\n", len(c.state.Users))
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
		fmt.Println("No users found.")
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

	days, err := promptPositiveIntValue(in, "Package days", 30)
	if err != nil {
		return err
	}

	gb, err := promptPositiveFloatValue(in, "Usage limit (GB)", 100)
	if err != nil {
		return err
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
	u, err := c.userAdd(payload)
	if err != nil {
		return err
	}
	links := buildLinks(c.clientPath(), u.UUID, host)
	fmt.Println("User created.")
	printLinksFromSet(links)
	return nil
}

func uiDeleteUser(c *client, in *bufio.Reader) error {
	if err := c.loadState(); err != nil {
		return err
	}
	u, err := uiPromptUserSelection(c, in, "Select user to delete", "USER_ID to delete (UUID or name)")
	if err != nil {
		return err
	}

	fmt.Printf("About to delete: %s (%s)\n", u.UUID, u.Name)
	confirm, err := promptLine(in, "Confirm delete? (yes/no)", "no")
	if err != nil {
		return err
	}
	if !isYes(confirm) {
		fmt.Println("Canceled.")
		return nil
	}
	if err := c.userDelete(u.UUID); err != nil {
		return err
	}
	fmt.Printf("Deleted: %s (%s)\n", u.UUID, u.Name)
	return nil
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
	fmt.Printf("UUID: %s\n", u.UUID)
	fmt.Printf("Name: %s\n", u.Name)
	fmt.Printf("Enabled: %t\n", u.Enable)
	fmt.Printf("Limit GB: %.2f\n", u.UsageLimitGB)
	fmt.Printf("Days: %d\n", u.PackageDays)
	fmt.Printf("Mode: %s\n", u.Mode)
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
	fmt.Printf("User UUID: %s\n", l.UUID)
	fmt.Printf("Panel URL: %s\n", l.Panel)
	fmt.Printf("Hiddify (auto): %s\n", l.Auto)
	fmt.Printf("Subscription b64: %s\n", l.Sub64)
	fmt.Printf("Subscription plain: %s\n", l.Sub)
	fmt.Printf("Sing-box: %s\n", l.Singbox)
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

func shortText(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	if max < 4 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

func min(a, b int) int {
	if a < b {
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
	if def != "" {
		fmt.Printf("%s [%s]: ", label, def)
	} else {
		fmt.Printf("%s: ", label)
	}
	s, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
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
		fmt.Println("Value is required.")
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
			fmt.Printf("Invalid value: %v\n", err)
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
			fmt.Printf("Invalid value: %v\n", err)
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
			fmt.Println(err)
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

func isYes(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "y", "yes", "1", "true":
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

func runCommand(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
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
