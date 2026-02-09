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
)

const (
	defaultPanelCfg  = "/opt/hiddify-manager/hiddify-panel/app.cfg"
	defaultPanelAddr = "http://127.0.0.1:9000"
)

type state struct {
	APIPath   string                       `json:"api_path"`
	APIKey    string                       `json:"api_key"`
	AdminPath string                       `json:"admin_path"`
	Domains   []domain                     `json:"domains"`
	Users     []apiUser                    `json:"users"`
	Chconfigs map[string]map[string]any    `json:"chconfigs"`
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
	UUID     string `json:"uuid"`
	Host     string `json:"host"`
	Panel    string `json:"panel"`
	Auto     string `json:"auto"`
	Sub64    string `json:"sub64"`
	Sub      string `json:"sub"`
	Singbox  string `json:"singbox"`
}

type client struct {
	panelCfg  string
	panelAddr string
	panelPy   string
	state     state
}

var uuidRe = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var ansiRe = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

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
	fmt.Println(`psasctl - Hiddify manager helper

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

	for {
		fmt.Println("psasctl interactive menu")
		fmt.Println("  1) Status")
		fmt.Println("  2) List users")
		fmt.Println("  3) Find users")
		fmt.Println("  4) Show user + links")
		fmt.Println("  5) Add user")
		fmt.Println("  6) Delete user")
		fmt.Println("  7) Admin URL")
		fmt.Println("  8) Apply config")
		fmt.Println("  0) Exit")

		choice, err := promptLine(in, "Choose option", "")
		if err != nil {
			fatalf("ui input error: %v", err)
		}

		switch strings.ToLower(strings.TrimSpace(choice)) {
		case "1", "status":
			if err := uiStatus(c); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "2", "list":
			if err := uiListUsers(c); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "3", "find":
			if err := uiFindUsers(c, in); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "4", "show":
			if err := uiShowUser(c, in); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "5", "add":
			if err := uiAddUser(c, in); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "6", "delete", "del", "rm":
			if err := uiDeleteUser(c, in); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "7", "admin", "admin-url":
			if err := uiAdminURL(c); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "8", "apply":
			if err := applyWithClient(c); err != nil {
				fmt.Printf("Error: %v\n", err)
			}
		case "0", "q", "quit", "exit":
			return
		default:
			fmt.Printf("Unknown option: %q\n", choice)
		}
		fmt.Println()
	}
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
	id, err := promptRequiredLine(in, "USER_ID (UUID or name)")
	if err != nil {
		return err
	}
	u, err := c.resolveUser(id)
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

	daysStr, err := promptLine(in, "Package days", "30")
	if err != nil {
		return err
	}
	days, err := parsePositiveInt(daysStr)
	if err != nil {
		return fmt.Errorf("invalid days: %w", err)
	}

	gbStr, err := promptLine(in, "Usage limit (GB)", "100")
	if err != nil {
		return err
	}
	gb, err := parsePositiveFloat(gbStr)
	if err != nil {
		return fmt.Errorf("invalid GB: %w", err)
	}

	mode, err := promptLine(in, "Mode (no_reset|daily|weekly|monthly)", "no_reset")
	if err != nil {
		return err
	}
	mode = strings.TrimSpace(mode)
	if !isValidMode(mode) {
		return fmt.Errorf("invalid mode: %s", mode)
	}

	id, err := promptLine(in, "Custom UUID (empty = auto)", "")
	if err != nil {
		return err
	}
	id = strings.TrimSpace(id)
	if id == "" {
		id = newUUID()
	} else {
		if err := validateUUID(id); err != nil {
			return err
		}
		id = strings.ToLower(id)
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
	id, err := promptRequiredLine(in, "USER_ID to delete (UUID or name)")
	if err != nil {
		return err
	}
	u, err := c.resolveUser(id)
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
