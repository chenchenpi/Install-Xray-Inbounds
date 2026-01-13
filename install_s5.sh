#!/usr/bin/env bash
# install_socks5_xray.sh
# 安装/追加 Xray 的 SOCKS5 入站 (支持用户名+密码认证，支持 UDP)
# 适配 Debian/Ubuntu/Alpine（OpenRC/Systemd 后台运行）
set -euo pipefail

die() { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }
info(){ echo -e "\e[32m[INFO]\e[0m $*"; }
warn(){ echo -e "\e[33m[WARN]\e[0m $*"; }

require_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    die "请以 root 身份运行（使用 sudo）"
  fi
}

detect_os() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID,,}"
  else
    die "无法检测系统类型（缺少 /etc/os-release）"
  fi
  case "$OS_ID" in
    debian|ubuntu) OS_FAMILY="debian" ;;
    alpine)        OS_FAMILY="alpine" ;;
    *)             die "当前系统不受支持：$OS_ID（仅支持 Debian/Ubuntu/Alpine）" ;;
  esac
  info "检测到系统：$PRETTY_NAME"
}

ensure_packages() {
  case "$OS_FAMILY" in
    debian)
      apt-get update -y
      DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates curl unzip xz-utils openssl python3 jq net-tools iproute2
      ;;
    alpine)
      apk add --no-cache ca-certificates curl unzip xz openssl python3 jq iproute2 net-tools
      ;;
  esac
}

create_xray_user() {
  if id -u xray >/dev/null 2>&1; then return; fi
  case "$OS_FAMILY" in
    debian) adduser --system --no-create-home --shell /usr/sbin/nologin --group xray ;;
    alpine) addgroup -S xray || true; adduser -S -H -s /sbin/nologin -G xray xray ;;
  esac
}

prompt_domain() {
  local input
  read -rp "请输入要使用的 IP 或者域名（留空则使用公网 IP）： " input || true
  input="$(echo -n "$input" | awk '{$1=$1;print}')"
  if [[ -z "$input" ]]; then
    SERVER_DOMAIN=""
    info "未输入 IP 或域名，将在稍后使用公网 IP。"
  else
    input="${input,,}"
    SERVER_DOMAIN="$input"
    info "将使用 IP 或域名：$SERVER_DOMAIN"
  fi
}

# ===== 端口输入与冲突检测 =====
read_port_once() {
  local input
  read -rp "请输入 SOCKS5 端口（1-65535，默认 10808）： " input || true
  input="${input:-10808}"
  [[ "$input" =~ ^[0-9]+$ ]] && (( input>=1 && input<=65535 )) || die "端口无效：$input"
  echo "$input"
}

port_in_config_inuse() {
  local cfg="/usr/local/etc/xray/config.json" p="$1"
  [[ -s "$cfg" ]] || return 1
  jq -e --argjson p "$p" '
    try (
      if .inbounds == null then
        false
      elif (.inbounds|type)!="array" then
        (.inbounds.port? // empty) == $p
      else
        any(.inbounds[]?; (.port? // empty) == $p)
      end
    ) catch false
  ' "$cfg" >/dev/null 2>&1
}

port_in_system_inuse() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    ss -H -lun 2>/dev/null | awk '{print $5}' | grep -Eq "[:.]${p}([[:space:]]|$)" && return 0
    return 1
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln 2>/dev/null | awk '{print $4}' | grep -Eq "[:.]${p}([[:space:]]|$)"
    return $?
  else
    return 1
  fi
}

prompt_port_until_free() {
  while :; do
    local p; p="$(read_port_once)"
    if port_in_config_inuse "$p"; then
      warn "端口 $p 已在 Xray 现有配置中使用，请换一个。"
      continue
    fi
    if port_in_system_inuse "$p"; then
      warn "端口 $p 已被系统占用，请换一个。"
      continue
    fi
    SOCKS_PORT="$p"
    info "将使用端口：$SOCKS_PORT"
    break
  done
}

install_xray() {
  local arch machine
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) arch="64" ;;
    aarch64|arm64) arch="arm64-v8a" ;;
    *) die "不支持的 CPU 架构: $machine" ;;
  esac

  local api="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
  info "获取 Xray 最新版本信息..."
  local tag
  tag="$(curl -fsSL "$api" | grep -oE '"tag_name":\s*"[^"]+"' | head -n1 | cut -d'"' -f4)" || true
  
  local tmpdir=""; trap 'test -n "${tmpdir:-}" && rm -rf "$tmpdir"' EXIT; tmpdir="$(mktemp -d)"
  local zipname="Xray-linux-${arch}.zip"
  local url_main="https://github.com/XTLS/Xray-core/releases/latest/download/${zipname}"
  local url_tag="https://github.com/XTLS/Xray-core/releases/download/${tag}/${zipname}"

  info "下载 Xray ($zipname)..."
  if [[ -n "${tag:-}" ]] && curl -fL "$url_tag" -o "$tmpdir/xray.zip"; then :; \
  elif curl -fL "$url_main" -o "$tmpdir/xray.zip"; then :; else die "下载 Xray 失败"; fi

  unzip -q -o "$tmpdir/xray.zip" -d "$tmpdir"
  install -m 0755 "$tmpdir/xray" /usr/local/bin/xray

  create_xray_user
  mkdir -p /usr/local/etc/xray
  chown -R xray:xray /usr/local/etc/xray
}

generate_credentials() {
  echo
  echo "================ SOCKS5 认证设置 ================"
  
  # 用户名
  read -rp "请输入用户名（留空自动生成）： " input_user || true
  input_user="$(echo -n "$input_user" | awk '{$1=$1;print}')"
  if [[ -n "$input_user" ]]; then
    SOCKS_USER="$input_user"
  else
    SOCKS_USER="user$(openssl rand -hex 3)"
    info "已生成随机用户名：$SOCKS_USER"
  fi

  # 密码
  read -rp "请输入密码（留空自动生成）： " input_pass || true
  input_pass="$(echo -n "$input_pass" | awk '{$1=$1;print}')"
  if [[ -n "$input_pass" ]]; then
    SOCKS_PASS="$input_pass"
  else
    SOCKS_PASS="$(openssl rand -base64 16 | tr -d '\n')"
    info "已生成随机密码"
  fi
}

backup_config_if_exists() {
  local cfg="/usr/local/etc/xray/config.json"
  if [[ -s "$cfg" ]]; then
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    cp -a "$cfg" "/root/xray-config-backup-${ts}.json"
  fi
}

generate_unique_tag() {
  local cfg="/usr/local/etc/xray/config.json"
  local base="socks-in-${SOCKS_PORT}"
  SOCKS_TAG="$base"

  if [[ -s "$cfg" ]] && jq empty "$cfg" >/dev/null 2>&1; then
    if jq -e --arg t "$SOCKS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) != null' "$cfg" >/dev/null; then
      local n=2
      while :; do
        SOCKS_TAG="${base}-${n}"
        jq -e --arg t "$SOCKS_TAG" '((.inbounds // []) | map(.tag // "") | index($t)) == null' "$cfg" >/dev/null && break
        n=$((n+1))
      done
    fi
  fi
  info "将使用 inbound tag：$SOCKS_TAG"
}

append_or_create_config() {
  local cfg="/usr/local/etc/xray/config.json"

  # SOCKS5 inbound 配置结构
  local new_inbound
  new_inbound="$(cat <<EOF
{
  "port": $SOCKS_PORT,
  "protocol": "socks",
  "settings": {
    "auth": "password",
    "accounts": [
      {
        "user": "$SOCKS_USER",
        "pass": "$SOCKS_PASS"
      }
    ],
    "udp": true
  },
  "tag": "$SOCKS_TAG"
}
EOF
)"

  if [[ -s "$cfg" ]]; then
    info "检测到已有 Xray 配置，追加 SOCKS5 inbound ..."
    if ! jq empty "$cfg" >/dev/null 2>&1; then
      die "现有配置不是有效 JSON，请手动检查：$cfg"
    fi
    local tmp; tmp="$(mktemp)"
    jq --argjson inbound "$new_inbound" '
      if .inbounds == null then
        .inbounds = [$inbound]
      elif (.inbounds|type) != "array" then
        .inbounds = [ .inbounds, $inbound ]
      else
        .inbounds += [ $inbound ]
      end
    ' "$cfg" > "$tmp"
    mv "$tmp" "$cfg"
  else
    info "生成新的配置文件 ..."
    cat > "$cfg" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [ $new_inbound ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "blocked" }
  ]
}
EOF
  fi

  chown xray:xray "$cfg"
  chmod 0644 "$cfg"
}

setup_service() {
  if command -v systemctl >/dev/null 2>&1; then
    # Systemd
    cat >/etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray Service
After=network-online.target nss-lookup.target
Wants=network-online.target

[Service]
User=xray
Group=xray
ExecStart=/usr/local/bin/xray -config /usr/local/etc/xray/config.json
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now xray
  elif command -v rc-update >/dev/null 2>&1; then
    # OpenRC
    cat >/etc/init.d/xray <<'EOF'
#!/sbin/openrc-run
name="xray"
description="Xray Service"
command="/usr/local/bin/xray"
command_args="-config /usr/local/etc/xray/config.json"
command_user="xray:xray"
command_background=true
pidfile="/run/xray.pid"
start_stop_daemon_args="--make-pidfile --background"

depend() {
  need net
  use dns
}
start_pre() {
  checkpath --directory --owner ${command_user} /run
}
EOF
    chmod +x /etc/init.d/xray
    rc-update add xray default
    rc-service xray restart || rc-service xray start
  fi
}

detect_address() {
  if [[ -n "${SERVER_DOMAIN:-}" ]]; then
    SERVER_ADDR="$SERVER_DOMAIN"; return
  fi
  local ipv4=""
  ipv4="$(curl -fsSL http://api.ipify.org || true)"
  [[ -n "$ipv4" ]] || ipv4="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  SERVER_ADDR="${ipv4:-<SERVER_IP>}"
}

print_socks_uri() {
  # Python 生成 URL 编码
  local uri_info
  uri_info="$(python3 -c "
import urllib.parse
user = urllib.parse.quote('''$SOCKS_USER''', safe='')
pwd  = urllib.parse.quote('''$SOCKS_PASS''', safe='')
tag  = urllib.parse.quote('''$SOCKS_TAG''', safe='')
print(f'socks5://{user}:{pwd}@$SERVER_ADDR:$SOCKS_PORT#{tag}')
")"

  echo
  echo "================ SOCKS5 配置信息 ================"
  echo "Address : $SERVER_ADDR"
  echo "Port    : $SOCKS_PORT"
  echo "User    : $SOCKS_USER"
  echo "Pass    : $SOCKS_PASS"
  echo "Tag     : $SOCKS_TAG"
  echo
  echo "SOCKS5 分享链接："
  echo "$uri_info"
  echo "================================================="

  local link_file="/root/xray_socks5_link.txt"
  {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]"
    echo "$uri_info"
    echo
  } >> "$link_file"
  info "链接已保存到：$link_file"
}

restart_service() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart xray || true
    systemctl status xray --no-pager -l || true
  else
    rc-service xray restart || true
    rc-service xray status || true
  fi
}

main() {
  require_root
  detect_os
  ensure_packages
  prompt_domain
  prompt_port_until_free
  install_xray
  generate_credentials
  backup_config_if_exists
  generate_unique_tag
  append_or_create_config
  setup_service
  detect_address
  print_socks_uri
  restart_service
}

main "$@"
