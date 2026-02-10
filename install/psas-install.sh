#!/usr/bin/env bash
set -euo pipefail

SCRIPT_VERSION="0.4.0"

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

is_socks_login() {
  [[ "${1:-}" =~ ^[a-z_][a-z0-9_-]{0,30}$ ]]
}

is_hex_secret_32() {
  [[ "${1:-}" =~ ^[A-Fa-f0-9]{32}$ ]]
}

install_prereqs() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl jq openssl ufw fail2ban ca-certificates uuid-runtime python3
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

install_trusttunnel_if_needed() {
  if [[ "${INSTALL_TRUSTTUNNEL:-no}" != "yes" ]]; then
    return
  fi
  if [[ -x /opt/trusttunnel/trusttunnel_endpoint ]]; then
    info "TrustTunnel detected in /opt/trusttunnel"
    return
  fi

  info "TrustTunnel not found. Installing latest TrustTunnel endpoint..."
  curl -fsSL https://raw.githubusercontent.com/TrustTunnel/TrustTunnel/refs/heads/master/scripts/install.sh | sh -s - -a y
}

setup_trusttunnel_reload_cron() {
  cat >/etc/cron.d/reload-trusttunnel-cert <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
41 3 * * * root systemctl restart trusttunnel.service >/dev/null 2>&1 || true
EOF
  chmod 0644 /etc/cron.d/reload-trusttunnel-cert
}

install_mtproxy_if_needed() {
  if [[ "${INSTALL_MTPROXY:-no}" != "yes" ]]; then
    return
  fi

  if [[ -x /opt/MTProxy/objs/bin/mtproto-proxy ]]; then
    info "Telegram MTProxy detected in /opt/MTProxy"
  else
    info "Installing Telegram MTProxy..."
    apt-get install -y git build-essential libssl-dev zlib1g-dev
    if [[ -d /opt/MTProxy/.git ]]; then
      git -C /opt/MTProxy pull --ff-only || true
    else
      rm -rf /opt/MTProxy
      git clone --depth 1 https://github.com/TelegramMessenger/MTProxy.git /opt/MTProxy
    fi

    # Upstream MTProxy asserts when PID > 65535 (common on modern systems).
    # Patch to store low 16 bits instead of aborting.
    if [[ -f /opt/MTProxy/common/pid.c ]]; then
      if grep -q 'assert (!(p & 0xffff0000));' /opt/MTProxy/common/pid.c; then
        cp -a /opt/MTProxy/common/pid.c /opt/MTProxy/common/pid.c.psas.bak
        perl -0777 -i -pe 's/int p = getpid \\(\\);\\s*assert \\(!\\(p & 0xffff0000\\)\\);\\s*PID\\.pid = p;/int p = getpid ();\\n    if (p < 0) { p = 0; }\\n    PID.pid = (unsigned short) p;/s' /opt/MTProxy/common/pid.c
      fi
    fi

    (
      cd /opt/MTProxy
      make -j"$(nproc 2>/dev/null || echo 2)"
    )
  fi

  if [[ ! -s /opt/MTProxy/proxy-secret ]]; then
    curl -fsSL https://core.telegram.org/getProxySecret -o /opt/MTProxy/proxy-secret
  fi
  if [[ ! -s /opt/MTProxy/proxy-multi.conf ]]; then
    curl -fsSL https://core.telegram.org/getProxyConfig -o /opt/MTProxy/proxy-multi.conf
  fi
  chmod 0644 /opt/MTProxy/proxy-secret /opt/MTProxy/proxy-multi.conf
}

install_dante_if_needed() {
  if [[ "${INSTALL_SOCKS5:-no}" != "yes" ]]; then
    return
  fi
  if command -v danted >/dev/null 2>&1 || [[ -x /usr/sbin/danted ]]; then
    info "Dante detected"
    return
  fi
  info "Installing Dante SOCKS5 server..."
  apt-get install -y dante-server
}

detect_default_iface() {
  local iface
  iface="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
  if [[ -z "$iface" ]]; then
    iface="eth0"
  fi
  printf '%s' "$iface"
}

write_socks_sub_script() {
  cat >/usr/local/bin/socks5-sub <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v psasctl >/dev/null 2>&1; then
  exec psasctl socks "$@"
fi

cat >&2 <<'TXT'
socks5-sub requires psasctl in PATH.
Build and install psasctl from the PSAS repository, then retry:
  cd /tmp/PSAS
  go build -o psasctl ./cmd/psasctl
  sudo install -m 0755 psasctl /usr/local/bin/psasctl
TXT
exit 1
EOF
  chmod 0755 /usr/local/bin/socks5-sub
}

configure_dante_socks() {
  if [[ "${INSTALL_SOCKS5:-no}" != "yes" ]]; then
    return
  fi

  if [[ -z "${SOCKS_PASS:-}" ]]; then
    SOCKS_PASS="$(random_alnum 20)"
  fi

  local shell_bin
  shell_bin="/usr/sbin/nologin"
  if [[ ! -x "$shell_bin" ]]; then
    shell_bin="/sbin/nologin"
  fi
  if [[ ! -x "$shell_bin" ]]; then
    shell_bin="/bin/false"
  fi

  info "Configuring Dante SOCKS5 on port ${SOCKS_PORT}"
  if id -u "${SOCKS_USER}" >/dev/null 2>&1; then
    echo "${SOCKS_USER}:${SOCKS_PASS}" | chpasswd
  else
    useradd -M -N -s "$shell_bin" "${SOCKS_USER}"
    echo "${SOCKS_USER}:${SOCKS_PASS}" | chpasswd
  fi

  SOCKS_IFACE="$(detect_default_iface)"
  cat >/etc/danted.conf <<EOF
logoutput: syslog

internal: 0.0.0.0 port = ${SOCKS_PORT}
external: ${SOCKS_IFACE}

clientmethod: none
socksmethod: username

user.privileged: root
user.notprivileged: nobody

client pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  log: error connect disconnect
}

socks pass {
  from: 0.0.0.0/0 to: 0.0.0.0/0
  command: connect udpassociate bind
  log: error connect disconnect
}
EOF
  chmod 0640 /etc/danted.conf

  mkdir -p /etc/psas
  jq -nc \
    --arg name "${SOCKS_USER}" \
    --arg password "${SOCKS_PASS}" \
    '[{name:$name,password:$password,system_user:$name}]' >/etc/psas/socks-users.json
  chmod 0600 /etc/psas/socks-users.json

  systemctl daemon-reload
  systemctl enable --now danted
  systemctl restart danted

  SOCKS_PUBLIC_IP="$(curl -4 -fsSL https://api.ipify.org 2>/dev/null || true)"
  if [[ -z "$SOCKS_PUBLIC_IP" ]]; then
    SOCKS_PUBLIC_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi

  cat >/root/socks5-credentials.txt <<EOF
Dante SOCKS5 credentials
server=${SOCKS_SERVER_HOST}
server_ip=${SOCKS_PUBLIC_IP}
port=${SOCKS_PORT}
username=${SOCKS_USER}
password=${SOCKS_PASS}
service=danted
users_file=/etc/psas/socks-users.json
EOF
  chmod 0600 /root/socks5-credentials.txt
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

disable_hiddify_login_menu_autorun() {
  local bashrc="/root/.bashrc"
  [[ -f "$bashrc" ]] || return 0

  # Remove legacy unconditional autostart lines if present.
  sed -i \
    -e '/^[[:space:]]*\/opt\/hiddify-manager\/menu\.sh[[:space:]]*$/d' \
    -e '/^[[:space:]]*cd[[:space:]]\+\/opt\/hiddify-manager\/[[:space:]]*$/d' \
    "$bashrc"

  # Add opt-in block once.
  if ! grep -q 'HIDDIFY_MENU_ON_LOGIN' "$bashrc"; then
    cat >>"$bashrc" <<'EOF'

# Hiddify interactive menu on login is disabled by PSAS installer.
# To re-enable for current session:
#   export HIDDIFY_MENU_ON_LOGIN=1
if [[ "${HIDDIFY_MENU_ON_LOGIN:-0}" == "1" ]]; then
  /opt/hiddify-manager/menu.sh
  cd /opt/hiddify-manager/ || true
fi
EOF
  fi
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
UNLIMITED_PACKAGE_DAYS=10000
UNLIMITED_USAGE_GB=1000000

require_bin() {
  command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1" >&2; exit 1; }
}
require_bin jq
require_bin curl
require_bin uuidgen
require_bin awk

load_state() {
  STATE_JSON="$(HIDDIFY_CFG_PATH="$PANEL_CFG_PATH" "$PANEL_PY" -m hiddifypanel all-configs 2>/dev/null)"
  API_PATH="$(jq -r '.api_path // empty' <<<"$STATE_JSON")"
  API_KEY="$(jq -r '.api_key // empty' <<<"$STATE_JSON")"
  CLIENT_PATH="$(jq -r '.chconfigs["0"].proxy_path_client // empty' <<<"$STATE_JSON")"
  MAIN_DOMAIN="$(jq -r '[.domains[] | select(.mode=="direct" and (.domain|test("^[0-9.]+$")|not)) | .domain][0] // [.domains[] | select(.mode=="direct") | .domain][0] // empty' <<<"$STATE_JSON")"
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

run_panel() {
  HIDDIFY_CFG_PATH="$PANEL_CFG_PATH" "$PANEL_PY" -m hiddifypanel "$@"
}

set_setting() {
  run_panel set-setting -k "$1" -v "$2" >/dev/null
}

apply_config() {
  if [[ -x /usr/local/bin/hiddify-apply-safe ]]; then
    /usr/local/bin/hiddify-apply-safe "$MAIN_DOMAIN"
    return
  fi
  if [[ -x /opt/hiddify-manager/common/commander.py ]]; then
    /opt/hiddify-manager/common/commander.py apply
    return
  fi
  echo "Unable to apply config automatically" >&2
  exit 1
}

trim() {
  local s="${1:-}"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

is_uuid() {
  [[ "${1:-}" =~ ^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$ ]]
}

is_positive_int() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && (( "$1" > 0 ))
}

is_positive_number() {
  awk -v n="${1:-}" 'BEGIN{if ((n+0) > 0) exit 0; exit 1}' >/dev/null 2>&1
}

normalize_token() {
  local x
  x="$(tr '[:upper:]' '[:lower:]' <<<"${1:-}")"
  x="${x// /}"
  x="${x//_/-}"
  printf '%s' "$x"
}

resolve_name_value() {
  local name subscription_name required
  name="$(trim "${1:-}")"
  subscription_name="$(trim "${2:-}")"
  required="${3:-no}"

  if [[ -n "$subscription_name" ]]; then
    if [[ -n "$name" && "$name" != "$subscription_name" ]]; then
      echo "--name and --subscription-name must be the same when both are provided" >&2
      return 1
    fi
    name="$subscription_name"
  fi

  if [[ "$required" == "yes" && -z "$name" ]]; then
    echo "--name is required" >&2
    return 1
  fi
  printf '%s' "$name"
}

resolve_user_uuid() {
  local key users_json key_lc exact_count partial_count refs
  key="$(trim "${1:-}")"
  [[ -n "$key" ]] || { echo "USER_ID is required" >&2; exit 1; }

  if is_uuid "$key"; then
    key="$(tr 'A-Z' 'a-z' <<<"$key")"
    api GET "user/$key/" >/dev/null
    printf '%s' "$key"
    return 0
  fi

  users_json="$(api GET "user/")"
  key_lc="$(tr '[:upper:]' '[:lower:]' <<<"$key")"

  exact_count="$(jq -r --arg q "$key_lc" '[.[] | select((.name // "" | ascii_downcase) == $q)] | length' <<<"$users_json")"
  if [[ "$exact_count" == "1" ]]; then
    jq -r --arg q "$key_lc" '.[] | select((.name // "" | ascii_downcase) == $q) | .uuid' <<<"$users_json"
    return 0
  fi
  if [[ "$exact_count" != "0" ]]; then
    refs="$(jq -r --arg q "$key_lc" '.[] | select((.name // "" | ascii_downcase) == $q) | "\(.name)(\(.uuid))"' <<<"$users_json" | paste -sd ', ' -)"
    echo "Multiple users have name \"$key\": ${refs}" >&2
    exit 1
  fi

  partial_count="$(jq -r --arg q "$key_lc" '[.[] | select((.name // "" | ascii_downcase | contains($q)))] | length' <<<"$users_json")"
  if [[ "$partial_count" == "1" ]]; then
    jq -r --arg q "$key_lc" '.[] | select((.name // "" | ascii_downcase | contains($q))) | .uuid' <<<"$users_json"
    return 0
  fi
  if [[ "$partial_count" == "0" ]]; then
    echo "User not found by name/UUID: $key" >&2
    exit 1
  fi
  refs="$(jq -r --arg q "$key_lc" '.[] | select((.name // "" | ascii_downcase | contains($q))) | "\(.name)(\(.uuid))"' <<<"$users_json" | paste -sd ', ' -)"
  echo "Multiple matches for \"$key\": ${refs}" >&2
  exit 1
}

PROTOCOL_SETTINGS=(
  "hysteria2:hysteria_enable:hysteria,hy2,histeria,histeria2"
  "hysteria2-obfs:hysteria_obfs_enable:hysteria-obfs,hy2-obfs"
  "reality:reality_enable:"
  "vless:vless_enable:"
  "trojan:trojan_enable:"
  "vmess:vmess_enable:"
  "tuic:tuic_enable:"
  "wireguard:wireguard_enable:wg"
  "shadowtls:shadowtls_enable:"
  "shadowsocks2022:shadowsocks2022_enable:ss2022"
  "ssh:ssh_server_enable:"
  "http-proxy:http_proxy_enable:httpproxy"
  "v2ray:v2ray_enable:"
  "ws:ws_enable:websocket"
  "grpc:grpc_enable:"
  "httpupgrade:httpupgrade_enable:http-upgrade"
  "xhttp:xhttp_enable:"
  "tcp:tcp_enable:"
  "quic:quic_enable:"
)

resolve_protocol_key() {
  local input row pname pkey palias alias arr
  input="$(normalize_token "${1:-}")"
  for row in "${PROTOCOL_SETTINGS[@]}"; do
    IFS=':' read -r pname pkey palias <<<"$row"
    if [[ "$(normalize_token "$pname")" == "$input" || "$(normalize_token "$pkey")" == "$input" ]]; then
      printf '%s' "$pkey"
      return 0
    fi
    IFS=',' read -r -a arr <<<"$palias"
    for alias in "${arr[@]}"; do
      [[ -n "$alias" ]] || continue
      if [[ "$(normalize_token "$alias")" == "$input" ]]; then
        printf '%s' "$pkey"
        return 0
      fi
    done
  done
  return 1
}

resolve_protocol_name_by_key() {
  local key row pname pkey palias
  key="$(trim "${1:-}")"
  for row in "${PROTOCOL_SETTINGS[@]}"; do
    IFS=':' read -r pname pkey palias <<<"$row"
    if [[ "$pkey" == "$key" ]]; then
      printf '%s' "$pname"
      return 0
    fi
  done
  printf '%s' "$key"
}

parse_bool_like() {
  case "$(normalize_token "${1:-}")" in
    1|true|t|yes|y|on|enable|enabled) printf 'true' ;;
    0|false|f|no|n|off|disable|disabled) printf 'false' ;;
    *) return 1 ;;
  esac
}

wait_panel_http() {
  local timeout i
  timeout="${1:-45}"
  i=0
  while (( i < timeout )); do
    if curl -fsS --max-time 2 "$PANEL_ADDR/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
    ((i+=1))
  done
  return 1
}

restart_hiddify_services() {
  if [[ -x /opt/hiddify-manager/common/commander.py ]]; then
    /opt/hiddify-manager/common/commander.py restart-services
    return
  fi
  echo "Cannot restart services: /opt/hiddify-manager/common/commander.py not found" >&2
  exit 1
}

ensure_true_unlimited_support() {
  local panel_pkg_dir user_model_path hiddify_path changed
  panel_pkg_dir="$(HIDDIFY_CFG_PATH="$PANEL_CFG_PATH" "$PANEL_PY" -c 'import pathlib,hiddifypanel; print(pathlib.Path(hiddifypanel.__file__).resolve().parent)')"
  panel_pkg_dir="$(trim "$panel_pkg_dir")"
  if [[ -z "$panel_pkg_dir" || "${panel_pkg_dir:0:1}" != "/" ]]; then
    echo "Unable to detect hiddifypanel package directory" >&2
    exit 1
  fi
  user_model_path="$panel_pkg_dir/models/user.py"
  hiddify_path="$panel_pkg_dir/panel/hiddify.py"

  changed="$(
    PSAS_USER_MODEL="$user_model_path" PSAS_HIDDIFY_PY="$hiddify_path" "$PANEL_PY" - <<'PY'
import os
from pathlib import Path

user_model = Path(os.environ["PSAS_USER_MODEL"])
hiddify_py = Path(os.environ["PSAS_HIDDIFY_PY"])

user_patches = [
    (
        """        is_active = True
        if not self:
            is_active = False
        elif not self.enable:
            is_active = False
        elif self.usage_limit < self.current_usage:
            is_active = False
        elif self.remaining_days < 0:
            is_active = False
""",
        """        is_active = True
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
""",
        "unlimited_usage = self.usage_limit >= 1000000 * ONE_GIG",
    ),
    (
        """        res = -1
        if self.package_days is None:
            res = -1
        elif self.start_date:
            # print(datetime.date.today(), u.start_date,u.package_days, u.package_days - (datetime.date.today() - u.start_date).days)
            res = self.package_days - (datetime.date.today() - self.start_date).days
        else:
            # print("else",u.package_days )
            res = self.package_days
        return min(res, 10000)
""",
        """        if (self.package_days or 0) >= 10000:
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
""",
        "if (self.package_days or 0) >= 10000:",
    ),
]

hiddify_patches = [
    (
        "    valid_users = [u.to_dict(dump_id=True) for u in User.query.filter((User.usage_limit > User.current_usage)).all() if u.is_active]\n",
        "    valid_users = [u.to_dict(dump_id=True) for u in User.query.filter((User.usage_limit > User.current_usage) | (User.usage_limit >= 1000000 * 1024 * 1024 * 1024)).all() if u.is_active]\n",
        "User.usage_limit >= 1000000 * 1024 * 1024 * 1024",
    ),
]

def apply_patches(path: Path, patches):
    text = path.read_text(encoding="utf-8")
    changed = False
    original = text
    for old, new, marker in patches:
        if marker and marker in text:
            continue
        if new in text:
            continue
        if old not in text:
            raise RuntimeError(f"patch pattern not found in {path}")
        text = text.replace(old, new, 1)
        changed = True

    if changed:
        backup = Path(str(path) + ".psas.bak")
        if not backup.exists():
            backup.write_text(original, encoding="utf-8")
        path.write_text(text, encoding="utf-8")
    return changed

changed = False
changed = apply_patches(user_model, user_patches) or changed
changed = apply_patches(hiddify_py, hiddify_patches) or changed
print("1" if changed else "0")
PY
  )"

  changed="$(trim "$changed")"
  if [[ "$changed" != "1" ]]; then
    return 0
  fi

  echo "Enabled true unlimited support in Hiddify."
  restart_hiddify_services
  if ! wait_panel_http 45; then
    echo "Patch applied, but panel did not become reachable in time" >&2
    exit 1
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
  hiddify-sub add --name NAME [--subscription-name TITLE] [--days 30] [--gb 100] [--unlimited] [--unlimited-days] [--unlimited-gb] [--true-unlimited] [--true-unlimited-days] [--true-unlimited-gb] [--mode no_reset|daily|weekly|monthly] [--host DOMAIN] [--uuid UUID]
  hiddify-sub edit <USER_ID> [--name NAME] [--subscription-name TITLE] [--days N] [--gb N] [--unlimited] [--unlimited-days] [--unlimited-gb] [--true-unlimited] [--true-unlimited-days] [--true-unlimited-gb] [--mode no_reset|daily|weekly|monthly] [--enable|--disable] [--host DOMAIN]
  hiddify-sub show <USER_ID> [--host DOMAIN]
  hiddify-sub del <USER_ID>
  hiddify-sub protocols list
  hiddify-sub protocols set <PROTOCOL> <on|off|true|false|1|0>
  hiddify-sub protocols enable [--apply] <PROTOCOL>...
  hiddify-sub protocols disable [--apply] <PROTOCOL>...

USER_ID can be UUID or user name (exact/substring match).
TXT
}

cmd_list() {
  api GET "user/" | jq -r '(["UUID","NAME","ENABLED","LIMIT_GB","DAYS","MODE"]|@tsv),(.[]|[.uuid,.name,(.enable|tostring),(.usage_limit_GB|tostring),(.package_days|tostring),(.mode|tostring)]|@tsv)'
}

cmd_add() {
  local name="" subscription_name="" days="30" gb="100" mode="no_reset" host="" custom_uuid=""
  local unlimited=0 unlimited_days=0 unlimited_gb=0 true_unlimited=0 true_unlimited_days=0 true_unlimited_gb=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="${2:-}"; shift 2 ;;
      --subscription-name) subscription_name="${2:-}"; shift 2 ;;
      --days) days="${2:-}"; shift 2 ;;
      --gb) gb="${2:-}"; shift 2 ;;
      --unlimited) unlimited=1; shift ;;
      --unlimited-days) unlimited_days=1; shift ;;
      --unlimited-gb) unlimited_gb=1; shift ;;
      --true-unlimited) true_unlimited=1; shift ;;
      --true-unlimited-days) true_unlimited_days=1; shift ;;
      --true-unlimited-gb) true_unlimited_gb=1; shift ;;
      --mode) mode="${2:-}"; shift 2 ;;
      --host) host="${2:-}"; shift 2 ;;
      --uuid) custom_uuid="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done
  name="$(resolve_name_value "$name" "$subscription_name" yes)" || exit 1
  case "$mode" in
    no_reset|daily|weekly|monthly) ;;
    *) echo "Invalid --mode: $mode" >&2; exit 1 ;;
  esac

  if (( unlimited || unlimited_days || true_unlimited || true_unlimited_days )); then
    days="$UNLIMITED_PACKAGE_DAYS"
  fi
  if (( unlimited || unlimited_gb || true_unlimited || true_unlimited_gb )); then
    gb="$UNLIMITED_USAGE_GB"
  fi

  is_positive_int "$days" || { echo "--days must be >= 1 (or use --unlimited*/--true-unlimited*)" >&2; exit 1; }
  is_positive_number "$gb" || { echo "--gb must be > 0 (or use --unlimited*/--true-unlimited*)" >&2; exit 1; }

  if (( true_unlimited || true_unlimited_days || true_unlimited_gb )); then
    ensure_true_unlimited_support
  fi

  local u payload created created_json
  if [[ -n "$custom_uuid" ]]; then
    is_uuid "$custom_uuid" || { echo "Invalid --uuid: $custom_uuid" >&2; exit 1; }
    u="$(tr 'A-Z' 'a-z' <<<"$custom_uuid")"
  else
    u="$(uuidgen | tr 'A-Z' 'a-z')"
  fi
  payload="$(jq -nc --arg uuid "$u" --arg name "$name" --argjson package_days "$days" --argjson usage_limit_GB "$gb" --arg mode "$mode" '{uuid:$uuid,name:$name,package_days:$package_days,usage_limit_GB:$usage_limit_GB,mode:$mode,enable:true}')"
  created_json="$(api POST "user/" "$payload")"
  created="$(jq -r '.uuid // empty' <<<"$created_json")"
  [[ -n "$created" && "$created" != "null" ]] || { echo "Create failed" >&2; exit 1; }
  print_links "$created" "${host:-$MAIN_DOMAIN}"
}

cmd_edit() {
  local user_id="" name="" subscription_name="" days="" gb="" mode="" host=""
  local unlimited=0 unlimited_days=0 unlimited_gb=0 true_unlimited=0 true_unlimited_days=0 true_unlimited_gb=0
  local set_enable=0 set_disable=0

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --name) name="${2:-}"; shift 2 ;;
      --subscription-name) subscription_name="${2:-}"; shift 2 ;;
      --days) days="${2:-}"; shift 2 ;;
      --gb) gb="${2:-}"; shift 2 ;;
      --unlimited) unlimited=1; shift ;;
      --unlimited-days) unlimited_days=1; shift ;;
      --unlimited-gb) unlimited_gb=1; shift ;;
      --true-unlimited) true_unlimited=1; shift ;;
      --true-unlimited-days) true_unlimited_days=1; shift ;;
      --true-unlimited-gb) true_unlimited_gb=1; shift ;;
      --mode) mode="${2:-}"; shift 2 ;;
      --enable) set_enable=1; shift ;;
      --disable) set_disable=1; shift ;;
      --host) host="${2:-}"; shift 2 ;;
      -*) echo "Unknown option: $1" >&2; usage; exit 1 ;;
      *)
        if [[ -z "$user_id" ]]; then
          user_id="$1"
          shift
        else
          echo "Unexpected positional argument: $1" >&2
          usage
          exit 1
        fi
        ;;
    esac
  done

  [[ -n "$user_id" ]] || { echo "USER_ID is required" >&2; usage; exit 1; }
  local user_uuid
  user_uuid="$(resolve_user_uuid "$user_id")"

  local name_value
  name_value="$(resolve_name_value "$name" "$subscription_name" no)" || exit 1
  if [[ -n "$mode" ]]; then
    case "$mode" in
      no_reset|daily|weekly|monthly) ;;
      *) echo "Invalid --mode: $mode" >&2; exit 1 ;;
    esac
  fi
  if (( set_enable && set_disable )); then
    echo "--enable and --disable cannot be used together" >&2
    exit 1
  fi

  local has_days=0 has_gb=0
  if [[ -n "$days" ]]; then has_days=1; fi
  if [[ -n "$gb" ]]; then has_gb=1; fi
  if (( unlimited || unlimited_days || true_unlimited || true_unlimited_days )); then
    has_days=1
    days="$UNLIMITED_PACKAGE_DAYS"
  fi
  if (( unlimited || unlimited_gb || true_unlimited || true_unlimited_gb )); then
    has_gb=1
    gb="$UNLIMITED_USAGE_GB"
  fi

  if (( has_days )); then
    is_positive_int "$days" || { echo "--days must be >= 1 (or use --unlimited*/--true-unlimited*)" >&2; exit 1; }
  fi
  if (( has_gb )); then
    is_positive_number "$gb" || { echo "--gb must be > 0 (or use --unlimited*/--true-unlimited*)" >&2; exit 1; }
  fi

  if (( true_unlimited || true_unlimited_days || true_unlimited_gb )); then
    ensure_true_unlimited_support
  fi

  local payload="{}" changed=0
  if [[ -n "$name_value" ]]; then
    payload="$(jq -c --arg v "$name_value" '. + {name:$v}' <<<"$payload")"
    changed=1
  fi
  if (( has_days )); then
    payload="$(jq -c --argjson v "$days" '. + {package_days:$v}' <<<"$payload")"
    changed=1
  fi
  if (( has_gb )); then
    payload="$(jq -c --argjson v "$gb" '. + {usage_limit_GB:$v}' <<<"$payload")"
    changed=1
  fi
  if [[ -n "$mode" ]]; then
    payload="$(jq -c --arg v "$mode" '. + {mode:$v}' <<<"$payload")"
    changed=1
  fi
  if (( set_enable )); then
    payload="$(jq -c '. + {enable:true}' <<<"$payload")"
    changed=1
  fi
  if (( set_disable )); then
    payload="$(jq -c '. + {enable:false}' <<<"$payload")"
    changed=1
  fi

  if (( ! changed )); then
    echo "No changes requested for edit. Pass at least one edit flag." >&2
    exit 1
  fi

  local updated_json updated_uuid
  updated_json="$(api PATCH "user/$user_uuid/" "$payload")"
  updated_uuid="$(jq -r '.uuid // empty' <<<"$updated_json")"
  if [[ -z "$updated_uuid" ]]; then
    updated_uuid="$user_uuid"
  fi
  print_links "$updated_uuid" "${host:-$MAIN_DOMAIN}"
}

cmd_show() {
  local user_id="${1:-}"; shift || true
  local host=""
  [[ -n "$user_id" ]] || { echo "USER_ID is required" >&2; exit 1; }
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) host="${2:-}"; shift 2 ;;
      *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
  done
  local uuid
  uuid="$(resolve_user_uuid "$user_id")"
  api GET "user/$uuid/" >/dev/null
  print_links "$uuid" "${host:-$MAIN_DOMAIN}"
}

cmd_del() {
  local user_id="${1:-}"
  [[ -n "$user_id" ]] || { echo "USER_ID is required" >&2; exit 1; }
  local uuid
  uuid="$(resolve_user_uuid "$user_id")"
  api DELETE "user/$uuid/" >/dev/null
  echo "Deleted: $uuid (${user_id})"
}

cmd_protocols_list() {
  local row pname pkey palias enabled
  printf "PROTOCOL\tENABLED\tKEY\tALIASES\n"
  for row in "${PROTOCOL_SETTINGS[@]}"; do
    IFS=':' read -r pname pkey palias <<<"$row"
    enabled="$(jq -r --arg k "$pkey" '.chconfigs["0"][$k] // false' <<<"$STATE_JSON")"
    printf "%s\t%s\t%s\t%s\n" "$pname" "$enabled" "$pkey" "$palias"
  done
}

cmd_protocols_set() {
  local raw_proto="${1:-}" raw_value="${2:-}" pkey pvalue pname
  [[ -n "$raw_proto" && -n "$raw_value" ]] || { echo "protocols set requires <PROTOCOL> <on|off|true|false|1|0>" >&2; exit 1; }
  pkey="$(resolve_protocol_key "$raw_proto")" || { echo "Unknown protocol: $raw_proto" >&2; exit 1; }
  pvalue="$(parse_bool_like "$raw_value")" || { echo "Invalid protocol value: $raw_value" >&2; exit 1; }
  set_setting "$pkey" "$pvalue"
  pname="$(resolve_protocol_name_by_key "$pkey")"
  echo "Protocol $pname ($pkey) set to $pvalue"
}

cmd_protocols_switch() {
  local desired="$1"; shift
  local apply_now=0 raw_proto pkey pname
  declare -A seen=()

  if [[ "${1:-}" == "--apply" ]]; then
    apply_now=1
    shift
  fi
  [[ $# -ge 1 ]] || { echo "protocols $( [[ "$desired" == "true" ]] && echo enable || echo disable ) requires at least one protocol" >&2; exit 1; }

  for raw_proto in "$@"; do
    pkey="$(resolve_protocol_key "$raw_proto")" || { echo "Unknown protocol: $raw_proto" >&2; exit 1; }
    if [[ -n "${seen[$pkey]:-}" ]]; then
      continue
    fi
    seen[$pkey]=1
    set_setting "$pkey" "$desired"
    pname="$(resolve_protocol_name_by_key "$pkey")"
    echo "Protocol $pname ($pkey) set to $desired"
  done

  if (( apply_now )); then
    apply_config
  fi
}

cmd_protocols() {
  local sub="${1:-}"; shift || true
  case "$sub" in
    list|ls) cmd_protocols_list "$@" ;;
    set) cmd_protocols_set "$@" ;;
    enable) cmd_protocols_switch true "$@" ;;
    disable) cmd_protocols_switch false "$@" ;;
    *) echo "Unknown protocols subcommand: $sub" >&2; usage; exit 1 ;;
  esac
}

main() {
  local cmd="${1:-}"; shift || true
  case "$cmd" in
    list|add|edit|update|set|show|del|delete|rm|protocols|protocol|proto) ;;
    -h|--help|help|"") usage; exit 0 ;;
    *) echo "Unknown command: $cmd" >&2; usage; exit 1 ;;
  esac

  load_state

  case "$cmd" in
    list) cmd_list "$@" ;;
    add) cmd_add "$@" ;;
    edit|update|set) cmd_edit "$@" ;;
    show) cmd_show "$@" ;;
    del|delete|rm) cmd_del "$@" ;;
    protocols|protocol|proto) cmd_protocols "$@" ;;
  esac
}

main "$@"
EOF
  chmod 0755 /usr/local/bin/hiddify-sub
}

write_trusttunnel_sub_script() {
  cat >/usr/local/bin/trusttunnel-sub <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v psasctl >/dev/null 2>&1; then
  exec psasctl trust "$@"
fi

cat >&2 <<'TXT'
trusttunnel-sub requires psasctl in PATH.
Build and install psasctl from the PSAS repository, then retry:
  cd /tmp/PSAS
  go build -o psasctl ./cmd/psasctl
  sudo install -m 0755 psasctl /usr/local/bin/psasctl
TXT
exit 1
EOF
  chmod 0755 /usr/local/bin/trusttunnel-sub
}

write_mtproxy_sub_script() {
  cat >/usr/local/bin/mtproxy-sub <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if command -v psasctl >/dev/null 2>&1; then
  exec psasctl mtproxy "$@"
fi

cat >&2 <<'TXT'
mtproxy-sub requires psasctl in PATH.
Build and install psasctl from the PSAS repository, then retry:
  cd /tmp/PSAS
  go build -o psasctl ./cmd/psasctl
  sudo install -m 0755 psasctl /usr/local/bin/psasctl
TXT
exit 1
EOF
  chmod 0755 /usr/local/bin/mtproxy-sub
}

write_mtproxy_runner_script() {
  cat >/usr/local/bin/psas-mtproxy-run <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

CONF_PATH="${PSAS_MTPROXY_CONF:-/etc/psas/mtproxy.json}"
MTPROXY_DIR="${PSAS_MTPROXY_DIR:-/opt/MTProxy}"
BIN_PATH="${PSAS_MTPROXY_BIN:-${MTPROXY_DIR}/objs/bin/mtproto-proxy}"

[[ -x "$BIN_PATH" ]] || { echo "mtproto-proxy binary not found: $BIN_PATH" >&2; exit 1; }
[[ -s "$CONF_PATH" ]] || { echo "MTProxy config not found: $CONF_PATH" >&2; exit 1; }
[[ -s "${MTPROXY_DIR}/proxy-secret" ]] || { echo "proxy-secret not found in ${MTPROXY_DIR}" >&2; exit 1; }
[[ -s "${MTPROXY_DIR}/proxy-multi.conf" ]] || { echo "proxy-multi.conf not found in ${MTPROXY_DIR}" >&2; exit 1; }

PORT="$(jq -r '.port // 2443' "$CONF_PATH")"
INTERNAL_PORT="$(jq -r '.internal_port // 8888' "$CONF_PATH")"
SECRET="$(jq -r '.secret // empty' "$CONF_PATH")"

[[ "$PORT" =~ ^[0-9]{1,5}$ ]] || { echo "invalid port in $CONF_PATH: $PORT" >&2; exit 1; }
[[ "$INTERNAL_PORT" =~ ^[0-9]{1,5}$ ]] || { echo "invalid internal_port in $CONF_PATH: $INTERNAL_PORT" >&2; exit 1; }
[[ "$SECRET" =~ ^[A-Fa-f0-9]{32}$ ]] || { echo "invalid secret in $CONF_PATH: expected 32 hex chars" >&2; exit 1; }

cd "$MTPROXY_DIR"
exec "$BIN_PATH" -u nobody -p "$INTERNAL_PORT" -H "$PORT" -S "$SECRET" --aes-pwd proxy-secret proxy-multi.conf -M 1
EOF
  chmod 0755 /usr/local/bin/psas-mtproxy-run
}

configure_mtproxy() {
  if [[ "${INSTALL_MTPROXY:-no}" != "yes" ]]; then
    return
  fi

  [[ -x /opt/MTProxy/objs/bin/mtproto-proxy ]] || { err "mtproto-proxy binary not found in /opt/MTProxy/objs/bin"; exit 1; }
  [[ -s /opt/MTProxy/proxy-secret ]] || { err "proxy-secret not found in /opt/MTProxy"; exit 1; }
  [[ -s /opt/MTProxy/proxy-multi.conf ]] || { err "proxy-multi.conf not found in /opt/MTProxy"; exit 1; }

  if [[ -z "${MTPROXY_SECRET:-}" ]]; then
    MTPROXY_SECRET="$(openssl rand -hex 16)"
  fi
  if ! is_hex_secret_32 "$MTPROXY_SECRET"; then
    err "MTProxy secret must be exactly 32 hex characters"
    exit 1
  fi
  MTPROXY_SECRET="$(tr 'A-F' 'a-f' <<<"$MTPROXY_SECRET")"

  mkdir -p /etc/psas
  jq -nc \
    --arg server "${MTPROXY_SERVER_HOST}" \
    --arg secret "${MTPROXY_SECRET}" \
    --argjson port "${MTPROXY_PORT}" \
    --argjson internal_port "${MTPROXY_INTERNAL_PORT}" \
    '{server:$server,port:$port,secret:$secret,internal_port:$internal_port}' >/etc/psas/mtproxy.json
  chmod 0600 /etc/psas/mtproxy.json

  cat >/etc/systemd/system/mtproxy.service <<'EOF'
[Unit]
Description=Telegram MTProxy (PSAS managed)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/psas-mtproxy-run
Restart=always
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now mtproxy.service
  systemctl restart mtproxy.service

  cat >/root/mtproxy-credentials.txt <<EOF
Telegram MTProxy credentials
server=${MTPROXY_SERVER_HOST}
port=${MTPROXY_PORT}
secret=${MTPROXY_SECRET}
service=mtproxy
config=/etc/psas/mtproxy.json
tg_link=tg://proxy?server=${MTPROXY_SERVER_HOST}&port=${MTPROXY_PORT}&secret=${MTPROXY_SECRET}
share_url=https://t.me/proxy?server=${MTPROXY_SERVER_HOST}&port=${MTPROXY_PORT}&secret=${MTPROXY_SECRET}
EOF
  chmod 0600 /root/mtproxy-credentials.txt
}

configure_trusttunnel_endpoint() {
  if [[ "${INSTALL_TRUSTTUNNEL:-no}" != "yes" ]]; then
    return
  fi

  [[ -x /opt/trusttunnel/setup_wizard ]] || { err "TrustTunnel setup_wizard not found in /opt/trusttunnel"; exit 1; }
  [[ -x /opt/trusttunnel/trusttunnel_endpoint ]] || { err "TrustTunnel endpoint binary not found in /opt/trusttunnel"; exit 1; }

  if [[ -z "${TRUSTTUNNEL_PASS:-}" ]]; then
    TRUSTTUNNEL_PASS="$(random_alnum 24)"
  fi

  info "Configuring TrustTunnel endpoint on port ${TRUSTTUNNEL_PORT}"

  (
    cd /opt/trusttunnel
    ./setup_wizard -m non-interactive \
      -a "0.0.0.0:${TRUSTTUNNEL_PORT}" \
      -c "${TRUSTTUNNEL_USER}:${TRUSTTUNNEL_PASS}" \
      -n "${TRUSTTUNNEL_DOMAIN}" \
      --lib-settings vpn.toml \
      --hosts-settings hosts.toml \
      --cert-type self-signed
  )

  TRUSTTUNNEL_CERT_MODE="self-signed"
  if [[ -s "/etc/letsencrypt/live/${TRUSTTUNNEL_DOMAIN}/fullchain.pem" && -s "/etc/letsencrypt/live/${TRUSTTUNNEL_DOMAIN}/privkey.pem" ]]; then
    cat >/opt/trusttunnel/hosts.toml <<EOF
ping_hosts = []
speedtest_hosts = []
reverse_proxy_hosts = []

[[main_hosts]]
hostname = "${TRUSTTUNNEL_DOMAIN}"
cert_chain_path = "/etc/letsencrypt/live/${TRUSTTUNNEL_DOMAIN}/fullchain.pem"
private_key_path = "/etc/letsencrypt/live/${TRUSTTUNNEL_DOMAIN}/privkey.pem"
allowed_sni = []
EOF
    TRUSTTUNNEL_CERT_MODE="letsencrypt"
    setup_trusttunnel_reload_cron
  else
    rm -f /etc/cron.d/reload-trusttunnel-cert
  fi

  cp /opt/trusttunnel/trusttunnel.service.template /etc/systemd/system/trusttunnel.service
  systemctl daemon-reload
  systemctl enable --now trusttunnel.service

  cat >/root/trusttunnel-credentials.txt <<EOF
TrustTunnel endpoint credentials
username=${TRUSTTUNNEL_USER}
password=${TRUSTTUNNEL_PASS}
domain=${TRUSTTUNNEL_DOMAIN}
listen_port=${TRUSTTUNNEL_PORT}
certificate_mode=${TRUSTTUNNEL_CERT_MODE}
EOF
  chmod 0600 /root/trusttunnel-credentials.txt

  TRUSTTUNNEL_PUBLIC_IP="$(curl -4 -fsSL https://api.ipify.org 2>/dev/null || true)"
  if [[ "${TRUSTTUNNEL_PUBLIC_IP}" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    (
      cd /opt/trusttunnel
      ./trusttunnel_endpoint vpn.toml hosts.toml -c "${TRUSTTUNNEL_USER}" -a "${TRUSTTUNNEL_PUBLIC_IP}:${TRUSTTUNNEL_PORT}" > /root/trusttunnel-endpoint-config.txt
    ) || true
    if [[ -s /root/trusttunnel-endpoint-config.txt ]]; then
      chmod 0600 /root/trusttunnel-endpoint-config.txt
    fi
  fi
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
  local trust_port="${2:-}"
  local socks_port="${3:-}"
  local mtproxy_port="${4:-}"
  ufw allow 22/tcp || true
  ufw allow 80/tcp || true
  ufw allow 443/tcp || true
  ufw allow 443/udp || true
  if [[ -n "$hy2_port" ]]; then
    ufw allow "${hy2_port}/udp" || true
  fi
  if [[ -n "$trust_port" ]]; then
    ufw allow "${trust_port}/tcp" || true
    ufw allow "${trust_port}/udp" || true
  fi
  if [[ -n "$socks_port" ]]; then
    ufw allow "${socks_port}/tcp" || true
  fi
  if [[ -n "$mtproxy_port" ]]; then
    ufw allow "${mtproxy_port}/tcp" || true
  fi

  yes | ufw delete allow 1945 2>/dev/null || true
  yes | ufw delete allow 1945/tcp 2>/dev/null || true
  if [[ -z "$trust_port" || "$trust_port" != "8443" ]]; then
    yes | ufw delete allow 8443/tcp 2>/dev/null || true
    yes | ufw delete allow 8443/udp 2>/dev/null || true
  fi

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
  echo "Hiddify SSH login menu autostart: disabled (set HIDDIFY_MENU_ON_LOGIN=1 to enable per session)"
  if [[ "${INSTALL_SOCKS5:-no}" == "yes" ]]; then
    echo "SOCKS5 server: ${SOCKS_SERVER_HOST}"
    echo "SOCKS5 port: ${SOCKS_PORT}"
    echo "SOCKS5 username: ${SOCKS_USER}"
    echo "SOCKS5 password: ${SOCKS_PASS}"
    echo "SOCKS5 creds file: /root/socks5-credentials.txt"
  fi
  if [[ "${INSTALL_TRUSTTUNNEL:-no}" == "yes" ]]; then
    echo "TrustTunnel domain: ${TRUSTTUNNEL_DOMAIN}"
    echo "TrustTunnel port: ${TRUSTTUNNEL_PORT}"
    echo "TrustTunnel cert mode: ${TRUSTTUNNEL_CERT_MODE:-self-signed}"
    echo "TrustTunnel username: ${TRUSTTUNNEL_USER}"
    echo "TrustTunnel password: ${TRUSTTUNNEL_PASS}"
    if [[ -s /root/trusttunnel-endpoint-config.txt ]]; then
      echo "TrustTunnel config file: /root/trusttunnel-endpoint-config.txt"
    fi
  fi
  if [[ "${INSTALL_MTPROXY:-no}" == "yes" ]]; then
    echo "MTProxy server: ${MTPROXY_SERVER_HOST}"
    echo "MTProxy port: ${MTPROXY_PORT}"
    echo "MTProxy internal port: ${MTPROXY_INTERNAL_PORT}"
    echo "MTProxy secret: ${MTPROXY_SECRET}"
    echo "MTProxy creds file: /root/mtproxy-credentials.txt"
  fi
  echo
  echo "User management commands:"
  echo "  hiddify-sub list"
  echo "  hiddify-sub add --name user01 --days 30 --gb 300 --mode no_reset"
  echo "  hiddify-sub edit user01 --subscription-name \"User01 iPhone\""
  echo "  hiddify-sub add --name user01 --true-unlimited --mode no_reset"
  echo "  hiddify-sub protocols enable hysteria2"
  echo "  hiddify-sub show <USER_ID>"
  if [[ "${INSTALL_SOCKS5:-no}" == "yes" ]]; then
    echo
    echo "SOCKS5 management commands:"
    echo "  psasctl socks status"
    echo "  psasctl socks users list"
    echo "  psasctl socks users add --name user01 --show-config --server ${SOCKS_SERVER_HOST}"
    echo "  psasctl socks users show --show-config --server ${SOCKS_SERVER_HOST} user01"
    echo "  psasctl socks users del user01"
    echo "  psasctl socks service restart"
  fi
  if [[ "${INSTALL_TRUSTTUNNEL:-no}" == "yes" ]]; then
    echo
    echo "TrustTunnel management commands:"
    echo "  psasctl trust status"
    echo "  psasctl trust users list"
    echo "  psasctl trust users add --name user01 --show-config"
    echo "  psasctl trust users show user01 --show-config"
    echo "  psasctl trust users del user01"
    echo "  psasctl trust service restart"
  fi
  if [[ "${INSTALL_MTPROXY:-no}" == "yes" ]]; then
    echo
    echo "Telegram MTProxy management commands:"
    echo "  psasctl mtproxy status"
    echo "  psasctl mtproxy config"
    echo "  psasctl mtproxy secret show"
    echo "  psasctl mtproxy secret regen"
    echo "  psasctl mtproxy service restart"
  fi
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

  read -r -p "Install Dante SOCKS5 proxy too? [yes/no, default yes]: " INSTALL_SOCKS5
  INSTALL_SOCKS5="${INSTALL_SOCKS5:-yes}"
  if [[ "$INSTALL_SOCKS5" != "yes" && "$INSTALL_SOCKS5" != "no" ]]; then
    err "INSTALL_SOCKS5 must be yes or no"
    exit 1
  fi

  if [[ "$INSTALL_SOCKS5" == "yes" ]]; then
    read -r -p "SOCKS server host/domain for clients [${MAIN_DOMAIN}]: " SOCKS_SERVER_HOST
    SOCKS_SERVER_HOST="${SOCKS_SERVER_HOST:-$MAIN_DOMAIN}"
    if [[ -z "$SOCKS_SERVER_HOST" || "$SOCKS_SERVER_HOST" =~ [[:space:]] ]]; then
      err "Invalid SOCKS server host"
      exit 1
    fi

    read -r -p "SOCKS listen port [1080]: " SOCKS_PORT
    SOCKS_PORT="${SOCKS_PORT:-1080}"
    if ! is_port "$SOCKS_PORT"; then
      err "Invalid SOCKS port"
      exit 1
    fi
    if [[ "$SOCKS_PORT" == "80" || "$SOCKS_PORT" == "443" ]]; then
      err "SOCKS port ${SOCKS_PORT} conflicts with Hiddify web ports 80/443"
      exit 1
    fi
    if [[ "$SOCKS_PORT" == "$HYSTERIA_BASE_PORT" || "$SOCKS_PORT" == "$SPECIAL_BASE_PORT" ]]; then
      err "SOCKS port ${SOCKS_PORT} conflicts with Hiddify configured ports"
      exit 1
    fi

    read -r -p "Initial SOCKS username [socks01]: " SOCKS_USER
    SOCKS_USER="${SOCKS_USER:-socks01}"
    if ! is_socks_login "$SOCKS_USER"; then
      err "SOCKS username must match [a-z_][a-z0-9_-]{0,30}"
      exit 1
    fi

    read -r -s -p "Initial SOCKS password [auto-generated if empty]: " SOCKS_PASS
    echo
    if [[ -n "$SOCKS_PASS" ]]; then
      if [[ "$SOCKS_PASS" == *:* || "$SOCKS_PASS" == *$'\n'* || "$SOCKS_PASS" == *$'\r'* ]]; then
        err "SOCKS password must not contain ':' or line breaks"
        exit 1
      fi
    fi
  fi

  read -r -p "Install TrustTunnel endpoint too? [yes/no, default yes]: " INSTALL_TRUSTTUNNEL
  INSTALL_TRUSTTUNNEL="${INSTALL_TRUSTTUNNEL:-yes}"
  if [[ "$INSTALL_TRUSTTUNNEL" != "yes" && "$INSTALL_TRUSTTUNNEL" != "no" ]]; then
    err "INSTALL_TRUSTTUNNEL must be yes or no"
    exit 1
  fi

  if [[ "$INSTALL_TRUSTTUNNEL" == "yes" ]]; then
    read -r -p "TrustTunnel domain [${MAIN_DOMAIN}]: " TRUSTTUNNEL_DOMAIN
    TRUSTTUNNEL_DOMAIN="${TRUSTTUNNEL_DOMAIN:-$MAIN_DOMAIN}"
    if ! is_domain "$TRUSTTUNNEL_DOMAIN"; then
      err "Invalid TrustTunnel domain: $TRUSTTUNNEL_DOMAIN"
      exit 1
    fi

    read -r -p "TrustTunnel listen port [8443]: " TRUSTTUNNEL_PORT
    TRUSTTUNNEL_PORT="${TRUSTTUNNEL_PORT:-8443}"
    if ! is_port "$TRUSTTUNNEL_PORT"; then
      err "Invalid TrustTunnel port"
      exit 1
    fi
    if [[ "$TRUSTTUNNEL_PORT" == "80" || "$TRUSTTUNNEL_PORT" == "443" ]]; then
      err "TrustTunnel port ${TRUSTTUNNEL_PORT} conflicts with Hiddify web ports 80/443"
      exit 1
    fi
    if [[ "$TRUSTTUNNEL_PORT" == "$HYSTERIA_BASE_PORT" || "$TRUSTTUNNEL_PORT" == "$SPECIAL_BASE_PORT" ]]; then
      err "TrustTunnel port ${TRUSTTUNNEL_PORT} conflicts with Hiddify configured ports"
      exit 1
    fi
    if [[ "${INSTALL_SOCKS5:-no}" == "yes" && "$TRUSTTUNNEL_PORT" == "$SOCKS_PORT" ]]; then
      err "TrustTunnel port ${TRUSTTUNNEL_PORT} conflicts with SOCKS port ${SOCKS_PORT}"
      exit 1
    fi

    read -r -p "TrustTunnel initial username [ttadmin]: " TRUSTTUNNEL_USER
    TRUSTTUNNEL_USER="${TRUSTTUNNEL_USER:-ttadmin}"
    if ! [[ "$TRUSTTUNNEL_USER" =~ ^[A-Za-z0-9._@-]{1,64}$ ]]; then
      err "TrustTunnel username must match [A-Za-z0-9._@-]{1,64}"
      exit 1
    fi

    read -r -s -p "TrustTunnel initial password [auto-generated if empty]: " TRUSTTUNNEL_PASS
    echo
  fi

  read -r -p "Install Telegram MTProxy too? [yes/no, default yes]: " INSTALL_MTPROXY
  INSTALL_MTPROXY="${INSTALL_MTPROXY:-yes}"
  if [[ "$INSTALL_MTPROXY" != "yes" && "$INSTALL_MTPROXY" != "no" ]]; then
    err "INSTALL_MTPROXY must be yes or no"
    exit 1
  fi

  if [[ "$INSTALL_MTPROXY" == "yes" ]]; then
    read -r -p "MTProxy server host/domain for clients [${MAIN_DOMAIN}]: " MTPROXY_SERVER_HOST
    MTPROXY_SERVER_HOST="${MTPROXY_SERVER_HOST:-$MAIN_DOMAIN}"
    if [[ -z "$MTPROXY_SERVER_HOST" || "$MTPROXY_SERVER_HOST" =~ [[:space:]] ]]; then
      err "Invalid MTProxy server host"
      exit 1
    fi

    read -r -p "MTProxy listen port [2443]: " MTPROXY_PORT
    MTPROXY_PORT="${MTPROXY_PORT:-2443}"
    if ! is_port "$MTPROXY_PORT"; then
      err "Invalid MTProxy port"
      exit 1
    fi
    if [[ "$MTPROXY_PORT" == "80" || "$MTPROXY_PORT" == "443" ]]; then
      err "MTProxy port ${MTPROXY_PORT} conflicts with Hiddify web ports 80/443"
      exit 1
    fi
    if [[ "$MTPROXY_PORT" == "$HYSTERIA_BASE_PORT" || "$MTPROXY_PORT" == "$SPECIAL_BASE_PORT" ]]; then
      err "MTProxy port ${MTPROXY_PORT} conflicts with Hiddify configured ports"
      exit 1
    fi
    if [[ "${INSTALL_SOCKS5:-no}" == "yes" && "$MTPROXY_PORT" == "$SOCKS_PORT" ]]; then
      err "MTProxy port ${MTPROXY_PORT} conflicts with SOCKS port ${SOCKS_PORT}"
      exit 1
    fi
    if [[ "${INSTALL_TRUSTTUNNEL:-no}" == "yes" && "$MTPROXY_PORT" == "$TRUSTTUNNEL_PORT" ]]; then
      err "MTProxy port ${MTPROXY_PORT} conflicts with TrustTunnel port ${TRUSTTUNNEL_PORT}"
      exit 1
    fi

    read -r -p "MTProxy internal port (-p) [8888]: " MTPROXY_INTERNAL_PORT
    MTPROXY_INTERNAL_PORT="${MTPROXY_INTERNAL_PORT:-8888}"
    if ! is_port "$MTPROXY_INTERNAL_PORT"; then
      err "Invalid MTProxy internal port"
      exit 1
    fi
    if [[ "$MTPROXY_INTERNAL_PORT" == "$MTPROXY_PORT" ]]; then
      err "MTProxy internal port must differ from listen port"
      exit 1
    fi

    read -r -p "MTProxy secret HEX32 [auto-generated if empty]: " MTPROXY_SECRET
    MTPROXY_SECRET="${MTPROXY_SECRET:-}"
    if [[ -n "$MTPROXY_SECRET" ]] && ! is_hex_secret_32 "$MTPROXY_SECRET"; then
      err "MTProxy secret must be exactly 32 hex chars"
      exit 1
    fi
  fi
}

main() {
  require_root
  prompt_inputs

  install_prereqs
  install_hiddify_if_needed
  wait_hiddify
  disable_hiddify_login_menu_autorun
  detect_panel_python
  backup_hiddify
  install_dante_if_needed
  install_trusttunnel_if_needed
  install_mtproxy_if_needed

  if [[ "$DO_CLEANUP" == "yes" ]]; then
    cleanup_legacy
  fi

  write_sync_cert_script
  write_apply_safe_script
  write_hiddify_sub_script
  if [[ "${INSTALL_SOCKS5:-no}" == "yes" ]]; then
    write_socks_sub_script
  fi
  if [[ "${INSTALL_TRUSTTUNNEL:-no}" == "yes" ]]; then
    write_trusttunnel_sub_script
  fi
  if [[ "${INSTALL_MTPROXY:-no}" == "yes" ]]; then
    write_mtproxy_sub_script
    write_mtproxy_runner_script
  fi
  setup_cert_sync_cron

  configure_panel_settings
  configure_domains
  set_admin_credentials

  /usr/local/bin/hiddify-apply-safe "$MAIN_DOMAIN"
  ensure_hiddify_units
  /usr/local/sbin/sync-hiddify-cert.sh "$MAIN_DOMAIN" || true

  collect_state
  configure_dante_socks
  configure_trusttunnel_endpoint
  configure_mtproxy

  configure_ufw "$HY2_PORT" "${TRUSTTUNNEL_PORT:-}" "${SOCKS_PORT:-}" "${MTPROXY_PORT:-}"
  configure_fail2ban
  configure_sysctl

  systemctl restart hiddify-panel.service hiddify-panel-background-tasks.service hiddify-singbox.service hiddify-xray.service hiddify-haproxy.service hiddify-nginx.service || true

  collect_state
  print_summary
}

main "$@"
