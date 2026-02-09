package main

import (
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

type client struct {
	panelCfg  string
	panelAddr string
	panelPy   string
	state     state
}

var uuidRe = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

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
	case "users":
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
  psasctl status
  psasctl admin-url
  psasctl users list
  psasctl users add --name NAME [--days 30] [--gb 100] [--mode no_reset] [--host DOMAIN]
  psasctl users show <UUID>
  psasctl users links <UUID> [--host DOMAIN]
  psasctl users del <UUID>
  psasctl config get <key>
  psasctl config set <key> <value>
  psasctl apply

Environment overrides:
  PSAS_PANEL_CFG   (default /opt/hiddify-manager/hiddify-panel/app.cfg)
  PSAS_PANEL_ADDR  (default http://127.0.0.1:9000)
  PSAS_PANEL_PY    (default auto-detect .venv313/.venv/python3)
`)
}

func runStatus(args []string) {
	if len(args) != 0 {
		fatalf("status takes no args")
	}
	c := mustClient(true)
	mainDomain := c.mainDomain()
	cfg := c.currentConfig()

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
	fmt.Println(c.adminURL(c.mainDomain()))
}

func runUsers(args []string) {
	if len(args) < 1 {
		fatalf("users requires subcommand: list|add|show|links|del")
	}
	c := mustClient(true)

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		if len(subArgs) != 0 {
			fatalf("users list takes no args")
		}
		users, err := c.usersList()
		must(err)
		printUsers(users)
	case "show":
		if len(subArgs) != 1 {
			fatalf("users show requires UUID")
		}
		uuid := subArgs[0]
		mustValidUUID(uuid)
		u, err := c.userShow(uuid)
		must(err)
		b, _ := json.MarshalIndent(u, "", "  ")
		fmt.Println(string(b))
	case "links":
		fs := flag.NewFlagSet("links", flag.ExitOnError)
		host := fs.String("host", "", "domain for generated links")
		must(fs.Parse(subArgs))
		rest := fs.Args()
		if len(rest) != 1 {
			fatalf("users links requires UUID")
		}
		uuid := rest[0]
		mustValidUUID(uuid)
		h := *host
		if h == "" {
			h = c.mainDomain()
		}
		printLinks(c.clientPath(), uuid, h)
	case "add":
		fs := flag.NewFlagSet("add", flag.ExitOnError)
		name := fs.String("name", "", "user name")
		days := fs.Int("days", 30, "package days")
		gb := fs.Float64("gb", 100, "usage limit in GB")
		mode := fs.String("mode", "no_reset", "user mode: no_reset|daily|weekly|monthly")
		host := fs.String("host", "", "domain for generated links")
		must(fs.Parse(subArgs))
		if *name == "" {
			fatalf("--name is required")
		}
		if !isValidMode(*mode) {
			fatalf("invalid --mode: %s", *mode)
		}
		uuid := newUUID()
		payload := map[string]any{
			"uuid":           uuid,
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
			h = c.mainDomain()
		}
		printLinks(c.clientPath(), u.UUID, h)
	case "del", "delete", "rm":
		if len(subArgs) != 1 {
			fatalf("users del requires UUID")
		}
		uuid := subArgs[0]
		mustValidUUID(uuid)
		must(c.userDelete(uuid))
		fmt.Printf("Deleted: %s\n", uuid)
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
	mainDomain := c.mainDomain()

	if fileExists("/usr/local/bin/hiddify-apply-safe") {
		must(runCommand("/usr/local/bin/hiddify-apply-safe", mainDomain))
		fmt.Println("Applied with hiddify-apply-safe")
		return
	}
	must(runCommand("/opt/hiddify-manager/common/commander.py", "apply"))
	fmt.Println("Applied with /opt/hiddify-manager/common/commander.py apply")
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
	var st state
	if err := json.Unmarshal(out, &st); err != nil {
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
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("panel cli failed: %w\n%s", err, string(out))
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

func printLinks(clientPath, uuid, host string) {
	base := fmt.Sprintf("https://%s/%s/%s", strings.TrimSpace(host), strings.Trim(clientPath, "/"), uuid)
	fmt.Printf("User UUID: %s\n", uuid)
	fmt.Printf("Panel URL: %s/\n", base)
	fmt.Printf("Hiddify (auto): %s/auto/\n", base)
	fmt.Printf("Subscription b64: %s/sub64/\n", base)
	fmt.Printf("Subscription plain: %s/sub/\n", base)
	fmt.Printf("Sing-box: %s/singbox/\n", base)
}

func isValidMode(m string) bool {
	switch m {
	case "no_reset", "daily", "weekly", "monthly":
		return true
	default:
		return false
	}
}

func mustValidUUID(s string) {
	if !uuidRe.MatchString(s) {
		fatalf("invalid UUID: %s", s)
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
