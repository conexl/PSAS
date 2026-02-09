#!/usr/bin/env bash
set -euo pipefail

SCRIPT_VERSION="0.1.0"

info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*"; }
err() { echo "[ERROR] $*" >&2; }

require_root() {
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    err "Run as root: sudo bash install/psas-install.sh"
    exit 1
  fi
}

random_alnum() {
  local n="${1:-28}"
  # Hex is enough for non-guessable admin path and avoids SIGPIPE issues with pipefail.
  openssl rand -hex "$n" | cut -c1-"$n"
}

is_domain() {
  [[ "$1" =~ ^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$ ]]
}

is_port() {
  local p="${1:-}"
  [[ "$p" =~ ^[0-9]{1,5}$ ]] || return 1
  ((p >= 1 && p <= 65535))
}

install_prereqs() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl jq openssl ufw fail2ban ca-certificates uuid-runtime
}

install_hiddify_if_needed() {
  if [[ -d /opt/hiddify-manager ]]; then
    info "Hiddify detected in /opt/hiddify-manager"
    return
  fi

  info "Hiddify not found. Installing via official stable installer..."
  bash <(curl -fsSL https://i.hiddify.com/release)
}

wait_hiddify() {
  local i
  for i in {1..120}; do
    if [[ -f /opt/hiddify-manager/hiddify-panel/app.cfg ]]; then
      return 0
    fi
    sleep 2
  done
  err "Hiddify panel config not found: /opt/hiddify-manager/hiddify-panel/app.cfg"
  exit 1
}

detect_panel_python() {
  if [[ -x /opt/hiddify-manager/.venv313/bin/python3 ]]; then
    PANEL_PY="/opt/hiddify-manager/.venv313/bin/python3"
  elif [[ -x /opt/hiddify-manager/.venv/bin/python3 ]]; then
    PANEL_PY="/opt/hiddify-manager/.venv/bin/python3"
  else
    PANEL_PY="python3"
  fi

  PANEL_CFG="/opt/hiddify-manager/hiddify-panel/app.cfg"
}

hp_cli() {
  HIDDIFY_CFG_PATH="$PANEL_CFG" "$PANEL_PY" -m hiddifypanel "$@"
}

hp_set() {
  local key="$1"
  local val="$2"
  hp_cli set-setting -k "$key" -v "$val" >/dev/null
}

hp_python() {
  HIDDIFY_CFG_PATH="$PANEL_CFG" "$PANEL_PY" - "$@"
}

backup_hiddify() {
  local dst="/root/backup-hiddify-before-psas-$(date +%F-%H%M%S)"
  cp -a /opt/hiddify-manager "$dst"
  info "Backup created: $dst"
}

cleanup_legacy() {
  info "Removing legacy cron/service leftovers (x-ui, v2raya, shadowsocks-libev)"

  local tmp
  tmp="$(mktemp)"
  crontab -l >"$tmp" 2>/dev/null || true
  if [[ -s "$tmp" ]]; then
    grep -Ev 'x-ui restart|certbot renew --nginx' "$tmp" | crontab - || true
  fi
  rm -f "$tmp"

  rm -rf /var/log/x-ui || true
  systemctl disable --now x-ui.service 2>/dev/null || true
  systemctl disable --now x-ui 2>/dev/null || true
  rm -f /etc/systemd/system/x-ui.service /usr/lib/systemd/system/x-ui.service || true
  rm -rf /etc/x-ui /usr/local/x-ui /opt/x-ui || true
  systemctl daemon-reload || true
  systemctl disable --now v2raya.service 2>/dev/null || true
  systemctl disable --now shadowsocks-libev.service 2>/dev/null || true
}

write_sync_cert_script() {
  cat >/usr/local/sbin/sync-hiddify-cert.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

DOMAIN="${1:-vpn.example.com}"
SRC_CRT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
SRC_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
DST_DIR="/opt/hiddify-manager/ssl"
DST_CRT="${DST_DIR}/${DOMAIN}.crt"
DST_KEY="${DST_DIR}/${DOMAIN}.crt.key"

if [[ ! -s "$SRC_CRT" || ! -s "$SRC_KEY" ]]; then
  echo "LetsEncrypt cert/key not found for ${DOMAIN}. Skip sync." >&2
  exit 0
fi

mkdir -p "$DST_DIR"
changed=0
if [[ ! -f "$DST_CRT" ]] || ! cmp -s "$SRC_CRT" "$DST_CRT"; then
  cp "$SRC_CRT" "$DST_CRT"
  changed=1
fi
if [[ ! -f "$DST_KEY" ]] || ! cmp -s "$SRC_KEY" "$DST_KEY"; then
  cp "$SRC_KEY" "$DST_KEY"
  changed=1
fi
chmod 600 "$DST_CRT" "$DST_KEY"

if [[ "$changed" -eq 1 ]]; then
  systemctl reload hiddify-haproxy.service 2>/dev/null || true
  systemctl reload hiddify-nginx.service 2>/dev/null || true
fi
EOF
  chmod 0755 /usr/local/sbin/sync-hiddify-cert.sh
}

write_apply_safe_script() {
  cat >/usr/local/bin/hiddify-apply-safe <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

cd /opt/hiddify-manager
if [[ -x ./common/commander.py ]]; then
  ./common/commander.py apply
else
  bash ./apply_configs.sh
fi

# Keep LE cert as final source when available
if [[ -x /usr/local/sbin/sync-hiddify-cert.sh ]]; then
  /usr/local/sbin/sync-hiddify-cert.sh "${1:-vpn.example.com}" || true
fi
EOF
  chmod 0755 /usr/local/bin/hiddify-apply-safe
}

write_hiddify_sub_script() {
  cat >/usr/local/bin/hiddify-sub <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

PANEL_CFG_PATH="/opt/hiddify-manager/hiddify-panel/app.cfg"
if [[ -x /opt/hiddify-manager/.venv313/bin/python3 ]]; then
  PANEL_PY="/opt/hiddify-manager/.venv313/bin/python3"
elif [[ -x /opt/hiddify-manager/.venv/bin/python3 ]]; then
  PANEL_PY="/opt/hiddify-manager/.venv/bin/python3"
else
  PANEL_PY="python3"
fi
PANEL_ADDR="http://127.0.0.1:9000"

require_bin() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }
}
require_bin jq
require_bin curl
require_bin uuidgen

load_state() {
  local json
  json="$(HIDDIFY_CFG_PATH="$PANEL_CFG_PATH" "$PANEL_PY" -m hiddifypanel all-configs 2>/dev/null)"
  API_PATH="$(jq -r '.api_path' <<<"$json")"
  API_KEY="$(jq -r '.api_key' <<<"$json")"
  CLIENT_PATH="$(jq -r '.chconfigs["0"].proxy_path_client' <<<"$json")"
  MAIN_DOMAIN="$(jq -r '[.domains[] | select(.mode=="direct" and (.domain|test("^[0-9.]+$")|not)) | .domain][0] // [.domains[] | select(.mode=="direct") | .domain][0] // empty' <<<"$json")"
  if [[ -z "$API_PATH" || -z "$API_KEY" || -z "$CLIENT_PATH" || -z "$MAIN_DOMAIN" ]]; then
    echo "Unable to read Hiddify state" >&2
    exit 1
  fi
}

api() {
  local method="$1"; shift
  local path="$1"; shift
  local data="${1:-}"
  if [[ -n "$data" ]]; then
    curl -fsS -X "$method" -H "Hiddify-API-Key: $API_KEY" -H "Content-Type: application/json" "$PANEL_ADDR/$API_PATH/api/v2/admin/$path" -d "$data"
  else
    curl -fsS -X "$method" -H "Hiddify-API-Key: $API_KEY" "$PANEL_ADDR/$API_PATH/api/v2/admin/$path"
  fi
}

print_links() {
  local uuid="$1"
  local host="${2:-$MAIN_DOMAIN}"
  local base="https://$host/$CLIENT_PATH/$uuid"
  cat <<TXT
User UUID: $uuid
Panel URL: $base/
Hiddify (auto): $base/auto/
Subscription b64: $base/sub64/
Subscription plain: $base/sub/
Sing-box: $base/singbox/
TXT
}

usage() {
  cat <<'TXT'
Usage:
  hiddify-sub list
  hiddify-sub add --name NAME [--days 30] [--gb 100] [--mode no_reset|daily|weekly|monthly] [--host DOMAIN]
  hiddify-sub show <USER_UUID> [--host DOMAIN]
  hiddify-sub del <USER_UUID>
TXT
}

cmd_list() {
  api GET "user/" | jq -r '(["UUID","NAME","ENABLED","LIMIT_GB","DAYS","MODE"]|@tsv),(.[]|[.uuid,.name,(.enable|tostring),(.usage_limit_GB|tostring),(.package_days|tostring),(.mode|tostring)]|@tsv)'
}

cmd_add() {
  local name="" days="30" gb="100" mode="no_reset" host=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="${2:-}"; shift 2 ;;
      --days) days="${2:-}"; shift 2 ;;
      --gb) gb="${2:-}"; shift 2 ;;
      --mode) mode="${2:-}"; shift 2 ;;
      --host) host="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done
  [[ -n "$name" ]] || { echo "--name is required" >&2; exit 1; }
  case "$mode" in
    no_reset|daily|weekly|monthly) ;;
    *) echo "Invalid --mode: $mode" >&2; exit 1 ;;
  esac
  local u payload created
  u="$(uuidgen | tr 'A-Z' 'a-z')"
  payload="$(jq -nc --arg uuid "$u" --arg name "$name" --argjson package_days "$days" --argjson usage_limit_GB "$gb" --arg mode "$mode" '{uuid:$uuid,name:$name,package_days:$package_days,usage_limit_GB:$usage_limit_GB,mode:$mode,enable:true}')"
  created="$(api POST "user/" "$payload" | jq -r '.uuid')"
  [[ -n "$created" && "$created" != "null" ]] || { echo "Create failed" >&2; exit 1; }
  print_links "$created" "${host:-$MAIN_DOMAIN}"
}

cmd_show() {
  local uuid="${1:-}"; shift || true
  local host=""
  [[ -n "$uuid" ]] || { echo "USER_UUID is required" >&2; exit 1; }
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) host="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done
  api GET "user/$uuid/" >/dev/null
  print_links "$uuid" "${host:-$MAIN_DOMAIN}"
}

cmd_del() {
  local uuid="${1:-}"
  [[ -n "$uuid" ]] || { echo "USER_UUID is required" >&2; exit 1; }
  api DELETE "user/$uuid/" >/dev/null
  echo "Deleted: $uuid"
}

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    list|add|show|del|delete|rm) ;;
    -h|--help|help|"") usage; exit 0 ;;
    *) echo "Unknown command: $cmd" >&2; usage; exit 1 ;;
  esac

  load_state

  case "$cmd" in
    list) cmd_list "$@" ;;
    add) cmd_add "$@" ;;
    show) cmd_show "$@" ;;
    del|delete|rm) cmd_del "$@" ;;
  esac
}

main "$@"
EOF
  chmod 0755 /usr/local/bin/hiddify-sub
}

configure_domains() {
  PSAS_MAIN_DOMAIN="$MAIN_DOMAIN" PSAS_REALITY_SNI="$REALITY_SNI" hp_python <<'PY'
import os,sys
sys.argv=['script','web']
from hiddifypanel import create_app_wsgi
from hiddifypanel.database import db
from hiddifypanel.models import Domain, DomainType

main = os.environ['PSAS_MAIN_DOMAIN'].strip().lower()
reality = os.environ['PSAS_REALITY_SNI'].strip().lower()

app = create_app_wsgi()
with app.app_context():
    for d in Domain.query.all():
        db.session.delete(d)
    db.session.commit()

    Domain.add_or_update(domain=main, mode=DomainType.direct, child_id=0, commit=False)
    Domain.add_or_update(domain=reality, mode=DomainType.special_reality_tcp, child_id=0, servernames=reality, commit=False)
    db.session.commit()
PY
}

configure_panel_settings() {
  info "Applying protocol and hardening settings in Hiddify"

  hp_set vless_enable true
  hp_set reality_enable true
  hp_set hysteria_enable true
  hp_set hysteria_obfs_enable true
  hp_set tcp_enable true
  hp_set quic_enable true

  hp_set vmess_enable false
  hp_set tuic_enable false
  hp_set wireguard_enable false
  hp_set ssh_server_enable false
  hp_set http_proxy_enable false
  hp_set allow_invalid_sni false
  hp_set use_ip_in_config false
  hp_set v2ray_enable false
  hp_set ssfaketls_enable false
  hp_set shadowtls_enable false
  hp_set shadowsocks2022_enable false
  hp_set ssr_enable false
  hp_set ws_enable false
  hp_set grpc_enable false
  hp_set httpupgrade_enable false
  hp_set xhttp_enable false

  hp_set firewall true
  hp_set auto_update true
  hp_set tls_ports 443
  hp_set http_ports 80

  hp_set reality_server_names "$REALITY_SNI"
  hp_set reality_fallback_domain "$REALITY_SNI"
  hp_set hysteria_port "$HYSTERIA_BASE_PORT"
  hp_set special_port "$SPECIAL_BASE_PORT"

  if [[ "$ROTATE_ADMIN" == "yes" ]]; then
    NEW_ADMIN_SECRET="$(uuidgen | tr 'A-Z' 'a-z')"
    NEW_ADMIN_PATH="$(random_alnum 28)"
    hp_set admin_secret "$NEW_ADMIN_SECRET"
    hp_set proxy_path_admin "$NEW_ADMIN_PATH"
  fi
}

set_admin_credentials() {
  PSAS_ADMIN_USER="$ADMIN_USER" PSAS_ADMIN_PASS="$ADMIN_PASS" hp_python <<'PY'
import os,sys
sys.argv=['script','web']
from hiddifypanel import create_app_wsgi
from hiddifypanel.database import db
from hiddifypanel.models import AdminUser

admin_user = os.environ['PSAS_ADMIN_USER']
admin_pass = os.environ['PSAS_ADMIN_PASS']

app = create_app_wsgi()
with app.app_context():
    owner = AdminUser.get_super_admin()
    owner.username = admin_user
    owner.password = admin_pass
    db.session.commit()
PY
}

ensure_hiddify_units() {
  if [[ -f /opt/hiddify-manager/nginx/hiddify-nginx.service ]]; then
    ln -sf /opt/hiddify-manager/nginx/hiddify-nginx.service /etc/systemd/system/hiddify-nginx.service
  fi
  systemctl daemon-reload
  systemctl enable --now hiddify-nginx.service 2>/dev/null || true
  systemctl disable --now nginx.service 2>/dev/null || true
  systemctl restart hiddify-haproxy.service 2>/dev/null || true
}

configure_fail2ban() {
  cat >/etc/fail2ban/jail.d/hiddify-hardening.local <<'EOF'
[DEFAULT]
banaction = ufw
banaction_allports = ufw
backend = systemd
findtime = 10m
maxretry = 5
bantime = 12h

[sshd]
enabled = true
port = ssh
maxretry = 5
findtime = 10m
bantime = 12h

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
findtime = 1d
bantime = 7d
maxretry = 5
EOF
  systemctl enable --now fail2ban
  systemctl restart fail2ban
}

configure_sysctl() {
  cat >/etc/sysctl.d/99-vpn-hardening.conf <<'EOF'
# Basic network hardening for VPN host
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
  sysctl --system >/dev/null
}

configure_ufw() {
  local hy2_port="$1"
  ufw allow 22/tcp || true
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow 443/udp || true
  if [[ -n "$hy2_port" ]]; then
    ufw allow "${hy2_port}/udp" || true
  fi

  yes | ufw delete allow 1945 2>/dev/null || true
  yes | ufw delete allow 1945/tcp 2>/dev/null || true
  yes | ufw delete allow 8443/tcp 2>/dev/null || true

  if ! ufw status | grep -q '^Status: active'; then
    warn "UFW inactive. Enabling with defaults deny incoming / allow outgoing"
    ufw default deny incoming
    ufw default allow outgoing
    yes | ufw enable
  fi
}

setup_cert_sync_cron() {
  cat >/etc/cron.d/sync-hiddify-cert <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
17 3 * * * root /usr/local/sbin/sync-hiddify-cert.sh ${MAIN_DOMAIN} >/dev/null 2>&1
EOF
  chmod 0644 /etc/cron.d/sync-hiddify-cert
}

collect_state() {
  ALL_JSON="$(hp_cli all-configs 2>/dev/null)"
  ADMIN_PATH="$(jq -r '.admin_path' <<<"$ALL_JSON")"
  CLIENT_PATH="$(jq -r '.chconfigs["0"].proxy_path_client' <<<"$ALL_JSON")"
  OWNER_UUID="$(jq -r '.api_key' <<<"$ALL_JSON")"
  ADMIN_SECRET="$(jq -r '.admin_secret // .chconfigs["0"].admin_secret // empty' <<<"$ALL_JSON")"
  if [[ -z "$ADMIN_SECRET" || "$ADMIN_SECRET" == "null" ]]; then
    ADMIN_SECRET="$OWNER_UUID"
  fi
  HY2_PORT="$(jq -r --arg d "$MAIN_DOMAIN" '[.domains[] | select(.domain==$d) | .internal_port_hysteria2][0] // empty' <<<"$ALL_JSON")"
}

print_summary() {
  echo
  echo "================ PSAS setup complete ================"
  echo "Panel URL: https://${MAIN_DOMAIN}${ADMIN_PATH}"
  echo "Secret code (UUID): ${ADMIN_SECRET}"
  echo "Hiddify API key: ${OWNER_UUID}"
  echo "Admin username: ${ADMIN_USER}"
  echo "Admin password: ${ADMIN_PASS}"
  echo "Client path: ${CLIENT_PATH}"
  echo "Hysteria2 UDP port: ${HY2_PORT}"
  echo
  echo "User management commands:"
  echo "  hiddify-sub list"
  echo "  hiddify-sub add --name user01 --days 30 --gb 300 --mode no_reset"
  echo "  hiddify-sub show <USER_UUID>"
  echo
  echo "Apply config safely after manual edits:"
  echo "  hiddify-apply-safe ${MAIN_DOMAIN}"
  echo "====================================================="
}

prompt_inputs() {
  echo "PSAS installer v${SCRIPT_VERSION}"
  read -r -p "Main domain (A record to this VPS), e.g. vpn.example.com: " MAIN_DOMAIN
  if ! is_domain "$MAIN_DOMAIN"; then
    err "Invalid domain: $MAIN_DOMAIN"
    exit 1
  fi

  read -r -p "Reality SNI/fallback domain [www.cloudflare.com]: " REALITY_SNI
  REALITY_SNI="${REALITY_SNI:-www.cloudflare.com}"

  read -r -p "Admin username [psas-admin]: " ADMIN_USER
  ADMIN_USER="${ADMIN_USER:-psas-admin}"
  if ! [[ "$ADMIN_USER" =~ ^[A-Za-z0-9._-]{3,64}$ ]]; then
    err "Admin username must match [A-Za-z0-9._-]{3,64}"
    exit 1
  fi

  while true; do
    read -r -s -p "Admin password (required): " ADMIN_PASS
    echo
    if [[ -z "$ADMIN_PASS" ]]; then
      err "Password can not be empty"
      continue
    fi
    read -r -s -p "Repeat admin password: " ADMIN_PASS2
    echo
    if [[ "$ADMIN_PASS" != "$ADMIN_PASS2" ]]; then
      err "Passwords do not match"
      continue
    fi
    break
  done

  read -r -p "Hysteria2 base port [40718]: " HYSTERIA_BASE_PORT
  HYSTERIA_BASE_PORT="${HYSTERIA_BASE_PORT:-40718}"
  if ! is_port "$HYSTERIA_BASE_PORT"; then
    err "Invalid hysteria base port"
    exit 1
  fi

  read -r -p "Reality special base port [12504]: " SPECIAL_BASE_PORT
  SPECIAL_BASE_PORT="${SPECIAL_BASE_PORT:-12504}"
  if ! is_port "$SPECIAL_BASE_PORT"; then
    err "Invalid special base port"
    exit 1
  fi

  read -r -p "Rotate admin secret/path now? [yes/no, default yes]: " ROTATE_ADMIN
  ROTATE_ADMIN="${ROTATE_ADMIN:-yes}"
  if [[ "$ROTATE_ADMIN" != "yes" && "$ROTATE_ADMIN" != "no" ]]; then
    err "ROTATE_ADMIN must be yes or no"
    exit 1
  fi

  read -r -p "Cleanup legacy leftovers (x-ui, v2raya, shadowsocks-libev)? [yes/no, default yes]: " DO_CLEANUP
  DO_CLEANUP="${DO_CLEANUP:-yes}"
  if [[ "$DO_CLEANUP" != "yes" && "$DO_CLEANUP" != "no" ]]; then
    err "DO_CLEANUP must be yes or no"
    exit 1
  fi
}

main() {
  require_root
  prompt_inputs

  install_prereqs
  install_hiddify_if_needed
  wait_hiddify
  detect_panel_python
  backup_hiddify

  if [[ "$DO_CLEANUP" == "yes" ]]; then
    cleanup_legacy
  fi

  write_sync_cert_script
  write_apply_safe_script
  write_hiddify_sub_script
  setup_cert_sync_cron

  configure_panel_settings
  configure_domains
  set_admin_credentials

  /usr/local/bin/hiddify-apply-safe "$MAIN_DOMAIN"
  ensure_hiddify_units
  /usr/local/sbin/sync-hiddify-cert.sh "$MAIN_DOMAIN" || true

  collect_state

  configure_ufw "$HY2_PORT"
  configure_fail2ban
  configure_sysctl

  systemctl restart hiddify-panel.service hiddify-panel-background-tasks.service hiddify-singbox.service hiddify-xray.service hiddify-haproxy.service hiddify-nginx.service || true

  collect_state
  print_summary
}

main "$@"
