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
	"time"
	"unicode"
)

const (
	defaultPanelCfg      = "/opt/hiddify-manager/hiddify-panel/app.cfg"
	defaultPanelAddr     = "http://127.0.0.1:9000"
	unlimitedPackageDays = 10000
	unlimitedUsageGB     = 1000000.0
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
var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var errUISelectionCanceled = errors.New("selection canceled")
var errUIExitRequested = errors.New("exit requested")
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
	case "protocols", "protocol", "proto":
		runProtocols(args)
	case "list", "ls":
		runListAlias(args)
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
		{Key: "status", Shortcut: 's', Title: "Status", Hint: "Main domain, admin URL, protocols, users count"},
		{Key: "list", Shortcut: 'l', Title: "List users", Hint: "Print all users in a table"},
		{Key: "find", Shortcut: 'f', Title: "Find users", Hint: "Search users by name/part and optional enabled filter"},
		{Key: "show", Shortcut: 'v', Title: "Show user + links", Hint: "Pick a user with arrows and print links"},
		{Key: "add", Shortcut: 'a', Title: "Add user", Hint: "Step-by-step wizard for creating a user"},
		{Key: "edit", Shortcut: 'e', Title: "Edit user", Hint: "Pick a user and edit name/limits/mode/enabled state"},
		{Key: "delete", Shortcut: 'd', Title: "Delete user", Hint: "Pick a user and delete with confirmation"},
		{Key: "protocols", Shortcut: 't', Title: "Protocols", Hint: "List and toggle protocol enable flags"},
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
		printBoxedHeader(choice.Title)

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
		case "edit":
			actionErr = uiEditUser(c, in)
		case "delete":
			actionErr = uiDeleteUser(c, in)
		case "protocols":
			actionErr = uiProtocols(c, in)
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
			if errors.Is(actionErr, errUIExitRequested) {
				clearScreen()
				return
			}
			if errors.Is(actionErr, errUISelectionCanceled) {
				fmt.Println("\nCanceled.")
			} else {
				fmt.Printf("\nERROR: %v\n", actionErr)
			}
		}
		if err := uiPause(in); err != nil {
			if errors.Is(err, errUIExitRequested) {
				clearScreen()
				return
			}
			fatalf("ui input error: %v", err)
		}
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

// Simplified UI drawing functions
func printBoxedHeader(title string) {
	fmt.Println()
	fmt.Println(strings.ToUpper(title))
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()
}

func printSectionHeader(title string) {
	fmt.Printf("\n%s:\n", title)
}

func printInfo(msg string) {
	fmt.Printf("  %s\n", msg)
}

func printSuccess(msg string) {
	fmt.Printf("  OK: %s\n", msg)
}

func printError(msg string) {
	fmt.Printf("  ERROR: %s\n", msg)
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

	fmt.Println()
	fmt.Println("PSASCTL - Interactive Menu")
	fmt.Println("===========================")
	fmt.Println()

	for i, item := range items {
		fmt.Printf("  %d. %s\n", i+1, item.Title)
	}
	fmt.Println("  q. Exit")

	for {
		raw, err := promptRequiredLine(in, "\nEnter option number (1-"+strconv.Itoa(len(items))+")")
		if err != nil {
			return uiMenuItem{}, err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return uiMenuItem{Key: "exit", Title: "Exit"}, nil
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > len(items) {
			printError(fmt.Sprintf("Invalid. Enter 1-%d or q", len(items)))
			continue
		}
		return items[n-1], nil
	}
}

func drawUIMenu(items []uiMenuItem, selected int) {
	clearScreen()

	fmt.Println()
	fmt.Println("PSASCTL - Interactive Menu")
	fmt.Println("===========================")
	fmt.Println()
	fmt.Println("Controls: Up/Down or j/k to navigate, Enter to select, q to quit")
	fmt.Println("Quick select: Press number 1-9 or shortcut key")
	fmt.Println()

	for i, item := range items {
		prefix := "   "
		if i == selected {
			prefix = ">> "
		}

		shortcut := ""
		if item.Shortcut != 0 {
			shortcut = fmt.Sprintf(" [%c]", item.Shortcut)
		}

		fmt.Printf("%s%d. %s%s\n", prefix, i+1, item.Title, shortcut)
	}

	if selected >= 0 && selected < len(items) && items[selected].Hint != "" {
		fmt.Println()
		fmt.Printf("  * %s\n", items[selected].Hint)
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
	fmt.Print("Press Enter to return to menu (q to exit)...")
	raw, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(raw), "q") {
		return errUIExitRequested
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
		{Value: "users-add", Title: "users add", Hint: "Supports --name, --days, --gb, --unlimited*, --true-unlimited*, --mode, --host, --uuid, --json"},
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

	fmt.Printf("\nCommand: psasctl %s\n", quoteCommandArgs(args))
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

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()

	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, opt.Title)
	}
	fmt.Println("  q. Cancel")

	def := strconv.Itoa(defaultIdx + 1)
	for {
		raw, err := promptLine(in, "\nEnter option number", def)
		if err != nil {
			return "", err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return "", errUISelectionCanceled
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > len(options) {
			printError(fmt.Sprintf("Invalid. Enter 1-%d or q", len(options)))
			continue
		}
		return options[n-1].Value, nil
	}
}

func drawUIOptionsMenu(title string, options []uiOption, selected int) {
	clearScreen()

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()
	fmt.Println("Controls: Up/Down or j/k, Enter to select, q to cancel")
	fmt.Println()

	for i, opt := range options {
		prefix := "   "
		if i == selected {
			prefix = ">> "
		}
		fmt.Printf("%s%d. %s\n", prefix, i+1, opt.Title)
	}

	if selected >= 0 && selected < len(options) && options[selected].Hint != "" {
		fmt.Println()
		fmt.Printf("  * %s\n", options[selected].Hint)
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
	fmt.Println("  0. Manual USER_ID input")
	fmt.Println("  q. Cancel")

	for {
		raw, err := promptRequiredLine(in, "\nEnter user number")
		if err != nil {
			return apiUser{}, err
		}
		raw = strings.TrimSpace(raw)
		if strings.EqualFold(raw, "q") {
			return apiUser{}, errUISelectionCanceled
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 || n > len(users) {
			printError(fmt.Sprintf("Invalid. Enter 0-%d or q", len(users)))
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

	fmt.Println()
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", len(title)))
	fmt.Println()
	fmt.Println("Controls: Up/Down to navigate, Enter to select, Type to filter")
	fmt.Println("          Backspace to erase, i for manual input, q to cancel")
	fmt.Println()
	fmt.Printf("Filter: %s\n", query)
	fmt.Printf("Showing: %d / %d users\n", len(filtered), len(users))
	fmt.Println(strings.Repeat("-", 60))

	if len(filtered) == 0 {
		fmt.Println("  No users match current filter")
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
		fmt.Printf("\n  (Showing %d-%d of %d)\n", start+1, end, len(filtered))
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

func uiStatus(c *client) error {
	if err := c.loadState(); err != nil {
		return err
	}
	cfg := c.currentConfig()
	mainDomain := c.mainDomain()

	fmt.Println()
	fmt.Println("System Status")
	fmt.Println("=============")
	fmt.Printf("Main domain         : %s\n", mainDomain)
	fmt.Printf("Admin URL           : %s\n", c.adminURL(mainDomain))
	fmt.Printf("Client path         : %v\n", cfg["proxy_path_client"])
	fmt.Printf("Reality enabled     : %v\n", cfg["reality_enable"])
	fmt.Printf("Hysteria2 enabled   : %v\n", cfg["hysteria_enable"])
	fmt.Printf("Hysteria base port  : %v\n", cfg["hysteria_port"])
	fmt.Printf("Reality SNI         : %v\n", cfg["reality_server_names"])
	fmt.Printf("Users               : %d\n", len(c.state.Users))
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
		fmt.Println("\nNo users found.")
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
	fmt.Println("\nUser created successfully!")
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
	fmt.Printf("\nDeleted: %s (%s)\n", u.UUID, u.Name)
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
		printError("Value is required.")
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
			printError(fmt.Sprintf("Invalid value: %v", err))
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
			printError(fmt.Sprintf("Invalid value: %v", err))
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
	case "1", "true", "t", "yes", "y", "on", "enable", "enabled":
		return true, nil
	case "0", "false", "f", "no", "n", "off", "disable", "disabled":
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
