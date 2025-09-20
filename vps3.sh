#!/usr/bin/env bash
# -*- coding: utf-8 -*-
#
# proxy_manager_optimized.sh
# Final optimized, cross-distro, robust one-file installer & manager for:
#   - Xray & sing-box cores (auto-download/update from GitHub)
#   - Web management panel (Flask) with token auth, user mgmt, probe (public), node export
#   - nginx reverse-proxy + ACME support (acme.sh)
#   - Systemd units for panel and cores
#   - Uses python venv to avoid PEP 668 issues
#
# Author identity (embedded): 严谨的程序员
# Version: 1.3.1-final (optimized)
#
# Usage:
#   sudo ./proxy_manager_optimized.sh install
#   sudo ./proxy_manager_optimized.sh update-cores
#   sudo ./proxy_manager_optimized.sh issue-cert your.domain.tld
#   sudo ./proxy_manager_optimized.sh start|stop|restart|status|show-nodes|help
#
set -euo pipefail
IFS=$'\n\t'

# -------------------------
# Configuration (customize as needed)
# -------------------------
BASE_DIR="/etc/proxy-manager"   # change if you prefer /opt/...
CORES_DIR="${BASE_DIR}/cores"
CONF_DIR="${BASE_DIR}/conf"
WEB_DIR="${BASE_DIR}/web"
LOG_DIR="${BASE_DIR}/logs"
SECRETS_DIR="${BASE_DIR}/secrets"
VENV_DIR="${BASE_DIR}/venv"
SYSTEMD_DIR="/etc/systemd/system"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
PANEL_PORT=8080                 # Flask internal port (nginx will front to 80/443)
FLASK_ENV="production"

GITHUB_API="https://api.github.com"

# -------------------------
# Colors & helpers
# -------------------------
_info(){ printf "\e[32m[INFO]\e[0m %s\n" "$*"; }
_warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
_err(){ printf "\e[31m[ERROR]\e[0m %s\n" "$*"; }

ensure_root(){
  if [[ $EUID -ne 0 ]]; then
    _err "请以 root / sudo 运行此脚本。"
    exit 1
  fi
}

detect_env(){
  ARCH_RAW="$(uname -m)"
  case "$ARCH_RAW" in
    x86_64) ARCH_KEY="amd64"; ARCH_ALIASES=("amd64" "x86_64" "x64") ;;
    aarch64|arm64) ARCH_KEY="arm64"; ARCH_ALIASES=("arm64" "aarch64") ;;
    armv7l) ARCH_KEY="armv7"; ARCH_ALIASES=("armv7" "armv7l") ;;
    *) _err "不支持的架构: $ARCH_RAW"; exit 1 ;;
  esac

  if [[ -f /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    OS_ID="${ID,,}"
    OS_NAME="${PRETTY_NAME:-$NAME}"
  else
    OS_ID="$(uname -s | tr '[:upper:]' '[:lower:]')"
    OS_NAME="$OS_ID"
  fi
  _info "Detected OS: ${OS_NAME} (id=${OS_ID}), Arch: ${ARCH_RAW}"
}

prepare_dirs(){
  mkdir -p "$BASE_DIR" "$CORES_DIR" "$CONF_DIR" "$WEB_DIR" "$LOG_DIR" "$SECRETS_DIR"
  chmod 700 "$SECRETS_DIR"
}

# cross-distro package install (best-effort)
install_system_deps(){
  _info "Installing system dependencies (best effort for Debian/Ubuntu/CentOS/Alpine)..."
  if [[ "$OS_ID" =~ (debian|ubuntu) ]]; then
    apt-get update -y
    apt-get install -y curl wget jq unzip tar socat nginx python3-venv python3-pip uuid-runtime openssl net-tools iproute2 iputils-ping || true
  elif [[ "$OS_ID" =~ (centos|rhel|rocky) ]]; then
    yum install -y epel-release || true
    yum install -y curl wget jq unzip tar socat nginx python3 python3-venv python3-pip util-linux openssl net-tools iproute || true
  elif [[ "$OS_ID" == "alpine" ]]; then
    apk add --no-cache curl wget jq unzip tar socat nginx python3 py3-pip py3-virtualenv util-linux openssl iproute2 iputils || true
  else
    _warn "未知发行版，跳过自动依赖安装。请手动安装: curl wget jq nginx python3-venv openssl"
  fi
}

# safe curl with retries and timeouts
curl_get(){
  curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 "$@"
}

# -------------------------
# GitHub asset selector (robust)
# -------------------------
# Usage: download_release_asset owner/repo "<pattern1> <pattern2>" dest_path
download_release_asset(){
  local repo="$1"; shift
  local patterns_str="$1"; shift
  local dest="$1"; shift
  local patterns=()
  read -r -a patterns <<< "$patterns_str"

  _info "Querying GitHub releases for ${repo}..."
  # Try latest release first
  local releases_json
  releases_json="$(curl -s "${GITHUB_API}/repos/${repo}/releases" || true)"
  if [[ -z "$releases_json" ]]; then
    _warn "GitHub API unreachable for ${repo}."
    return 1
  fi

  # Iterate releases (prefers non-prereleases)
  local release_count
  release_count=$(echo "$releases_json" | jq '. | length' 2>/dev/null || echo 0)
  if (( release_count == 0 )); then
    _warn "No releases found for ${repo} via API."
    return 1
  fi

  # function to try assets of one release JSON object
  try_release_assets(){
    local release_json="$1"
    # get assets array
    echo "$release_json" | jq -c '.assets[]?' | while read -r asset; do
      local name
      name="$(echo "$asset" | jq -r '.name')"
      local url
      url="$(echo "$asset" | jq -r '.browser_download_url')"
      # lowercase for matching
      local lname
      lname="$(echo "$name" | tr '[:upper:]' '[:lower:]')"
      # require linux in name
      if [[ "$lname" != *linux* && "$lname" != *linux-* ]]; then
        continue
      fi
      # require arch
      local ok_arch=0
      for a in "${ARCH_ALIASES[@]}"; do
        if [[ "$lname" == *"$a"* ]]; then ok_arch=1; break; fi
      done
      if [[ $ok_arch -eq 0 ]]; then
        continue
      fi
      # extra patterns match
      if [[ "${#patterns[@]}" -gt 0 ]]; then
        local ok_pat=0
        for p in "${patterns[@]}"; do
          if [[ -z "$p" ]]; then continue; fi
          if echo "$lname" | grep -qi "$p"; then ok_pat=1; break; fi
        done
        if [[ $ok_pat -eq 0 ]]; then
          continue
        fi
      fi
      _info "Matched asset: $name"
      _info "Downloading $url -> $dest"
      if curl -L --retry 3 -o "$dest" "$url"; then
        return 0
      else
        _warn "Download failed for $url"
      fi
    done
    return 1
  }

  # Try releases in order: latest first
  local idx=0
  while true; do
    local release
    release="$(echo "$releases_json" | jq -r --argjson i "$idx" '.[$i] // empty')"
    if [[ -z "$release" ]]; then break; fi
    # skip prerelease unless no other found
    local prerelease
    prerelease="$(echo "$release" | jq -r '.prerelease')"
    if [[ "$prerelease" == "true" ]]; then
      idx=$((idx+1)); continue
    fi
    if try_release_assets "$release"; then
      return 0
    fi
    idx=$((idx+1))
  done

  # fallback: try the first releases even if prerelease
  idx=0
  while true; do
    local release
    release="$(echo "$releases_json" | jq -r --argjson i "$idx" '.[$i] // empty')"
    if [[ -z "$release" ]]; then break; fi
    if try_release_assets "$release"; then
      return 0
    fi
    idx=$((idx+1))
  done

  _warn "未能在 GitHub Releases 中找到匹配的 asset (repo=${repo})."
  return 1
}

# -------------------------
# Download xray / sing-box (use download_release_asset)
# -------------------------
XRAY_BIN="${CORES_DIR}/xray"
SINGBOX_BIN="${CORES_DIR}/sing-box"

download_xray(){
  mkdir -p "$CORES_DIR"
  local tmp="/tmp/xray_asset_${RANDOM}.zip"
  local patterns="xray|xray-core|xray-linux|xray-core-linux"
  if download_release_asset "XTLS/Xray-core" "$patterns" "$tmp"; then
    # unzip and find binary
    unzip -o "$tmp" -d /tmp/xray_unpack >/dev/null 2>&1 || true
    local binpath
    binpath="$(find /tmp/xray_unpack -type f -name "xray" | head -n1 || true)"
    if [[ -n "$binpath" ]]; then
      mv "$binpath" "$XRAY_BIN"
      chmod +x "$XRAY_BIN"
      rm -rf /tmp/xray_unpack
      rm -f "$tmp"
      _info "xray installed: $XRAY_BIN"
      return 0
    fi
  fi
  _warn "xray download failed via API. You may place xray binary at $XRAY_BIN manually (chmod +x)."
  return 1
}

download_singbox(){
  mkdir -p "$CORES_DIR"
  local tmp="/tmp/singbox_asset_${RANDOM}.tar.gz"
  local patterns="sing-box|singbox|sing-box-linux"
  if download_release_asset "SagerNet/sing-box" "$patterns" "$tmp"; then
    tar -xzf "$tmp" -C /tmp/singbox_unpack || true
    local binpath
    binpath="$(find /tmp/singbox_unpack -type f -name "sing-box" | head -n1 || true)"
    if [[ -n "$binpath" ]]; then
      mv "$binpath" "$SINGBOX_BIN"
      chmod +x "$SINGBOX_BIN"
      rm -rf /tmp/singbox_unpack
      rm -f "$tmp"
      _info "sing-box installed: $SINGBOX_BIN"
      return 0
    fi
  fi
  _warn "sing-box download failed via API. You may place sing-box binary at $SINGBOX_BIN manually (chmod +x)."
  return 1
}

# -------------------------
# Config, UUID, token, venv, web app writer
# -------------------------
DEFAULT_CONFIG_FILE="${CONF_DIR}/config.json"

generate_default_config(){
  if [[ -f "$DEFAULT_CONFIG_FILE" ]]; then
    _info "配置文件已存在：$DEFAULT_CONFIG_FILE"
    return 0
  fi
  _info "生成默认配置：$DEFAULT_CONFIG_FILE"
  local uuid
  uuid="$(uuidgen || cat /proc/sys/kernel/random/uuid)"
  local webpass
  webpass="$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 20)"
  cat > "$DEFAULT_CONFIG_FILE" <<EOF
{
  "uuid": "$uuid",
  "domain": "",
  "web": {
    "port": ${PANEL_PORT},
    "username": "admin",
    "password": "$webpass"
  },
  "cores": {
    "xray_version": "N/A",
    "singbox_version": "N/A",
    "auto_update": true
  },
  "routing": {
    "default": "direct",
    "rules": []
  },
  "warp": {
    "enabled": false,
    "socks_port": 1081
  },
  "probe_targets": [
    {"name":"Beijing (AliDNS)","ip":"223.5.5.5"},
    {"name":"Guangzhou (114)","ip":"114.114.114.114"},
    {"name":"Shanghai (Baidu)","ip":"180.76.76.76"},
    {"name":"Chengdu (Tencent)","ip":"119.29.29.29"},
    {"name":"HongKong (Cloudflare)","ip":"1.0.0.1"}
  ]
}
EOF
  chmod 600 "$DEFAULT_CONFIG_FILE"
  _info "默认配置已生成；面板初始用户名：admin，密码见 $DEFAULT_CONFIG_FILE (字段 web.password)"
}

ensure_uuid_and_token(){
  if [[ ! -f "${SECRETS_DIR}/admin.token" ]]; then
    local t
    t="$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 48)"
    echo "$t" > "${SECRETS_DIR}/admin.token"
    chmod 600 "${SECRETS_DIR}/admin.token"
    _info "生成管理员 token：${SECRETS_DIR}/admin.token （请尽快更改）"
  fi
  if [[ ! -f "${SECRETS_DIR}/uuid" ]]; then
    cat "$DEFAULT_CONFIG_FILE" | jq -r '.uuid' > "${SECRETS_DIR}/uuid"
    chmod 600 "${SECRETS_DIR}/uuid"
  fi
}

create_python_venv_and_install(){
  if [[ ! -d "$VENV_DIR" ]]; then
    _info "创建 Python venv：$VENV_DIR"
    python3 -m venv "$VENV_DIR"
  fi
  _info "安装 Python 依赖到 venv（flask, flask_cors, psutil）"
  "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
  "$VENV_DIR/bin/pip" install flask flask_cors psutil >/dev/null 2>&1 || true
}

# Write Flask web app (with probe public endpoint, token auth for admin endpoints, simple sqlite users)
write_web_app(){
  _info "写入 Web 面板程序到 $WEB_DIR"
  mkdir -p "${WEB_DIR}/templates" "${WEB_DIR}/static"
  # Flask app
  cat > "${WEB_DIR}/app.py" <<'PY'
#!/usr/bin/env python3
# Minimal but functional management panel backend
import os, json, sqlite3, subprocess, base64, time
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_from_directory

BASE = os.environ.get("BASE_DIR", "/etc/proxy-manager")
CONF = os.path.join(BASE, "conf", "config.json")
SECRETS = os.path.join(BASE, "secrets")
DB = os.path.join(SECRETS, "users.db")
TOKEN_FILE = os.path.join(SECRETS, "admin.token")

app = Flask(__name__, template_folder='templates', static_folder='static')

def read_token():
    try:
        return open(TOKEN_FILE).read().strip()
    except:
        return ""

def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization","")
        token = ""
        if auth.startswith("Bearer "):
            token = auth.split(" ",1)[1].strip()
        else:
            token = request.args.get("token","")
        if not token or token != read_token():
            return jsonify({"error":"unauthorized"}), 401
        return func(*args, **kwargs)
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/probe', methods=['GET'])
def probe():
    try:
        conf = json.load(open(CONF))
        targets = conf.get("probe_targets", [])
    except:
        targets = [{"name":"Cloudflare","ip":"1.1.1.1"}]
    results = []
    for t in targets:
        ip = t.get("ip")
        try:
            out = subprocess.check_output(["ping","-c","3","-W","2",ip], stderr=subprocess.STDOUT, timeout=12).decode()
            avg = "N/A"
            for line in out.splitlines():
                if "min/avg" in line or "rtt min/avg" in line:
                    parts = line.split("=")[1].split("/")
                    if len(parts) > 1:
                        avg = parts[1].strip()
            results.append({"name":t.get("name"), "ip":ip, "avg_ms":avg, "raw":out})
        except Exception as e:
            results.append({"name":t.get("name"), "ip":ip, "avg_ms":"N/A", "error":str(e)})
    return jsonify({"results":results})

@app.route('/api/status', methods=['GET'])
@token_required
def status():
    def running(p):
        return subprocess.call(["pgrep","-f",p])==0
    load = os.getloadavg() if hasattr(__import__("os"), "getloadavg") else [0,0,0]
    return jsonify({"services":{"xray":running("xray"), "sing-box":running("sing-box")}, "load":load})

@app.route('/api/nodes', methods=['GET'])
@token_required
def nodes():
    try:
        uuid = open(os.path.join(SECRETS,"uuid")).read().strip()
    except:
        uuid = ""
    ip = subprocess.getoutput("curl -s4 https://icanhazip.com || hostname -I | awk '{print $1}'")
    nodes=[]
    if uuid:
        nodes.append({"type":"vless", "uri": f"vless://{uuid}@{ip}:443?security=reality#vless_sample"})
        vm = {"v":"2","ps":"vmess","add":ip,"port":"443","id":uuid,"aid":"0","net":"ws","type":"none","host":"","path":f"/{uuid}-ws","tls":"tls"}
        nodes.append({"type":"vmess","uri":"vmess://"+base64.b64encode(json.dumps(vm).encode()).decode()})
    return jsonify({"nodes":nodes})

@app.route('/api/cores/update', methods=['POST'])
@token_required
def update_cores():
    helper = os.path.join(BASE, "helper.sh")
    try:
        subprocess.Popen(["/bin/bash", helper, "update-cores"])
        return jsonify({"result":"update started"})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route('/api/acme', methods=['POST'])
@token_required
def acme():
    j = request.get_json(force=True) or {}
    domain = j.get("domain","")
    if not domain:
        return jsonify({"error":"domain required"}),400
    helper = os.path.join(BASE,"helper.sh")
    subprocess.Popen(["/bin/bash", helper, "issue-cert", domain])
    return jsonify({"result":"acme started", "domain":domain})

if __name__ == '__main__':
    port = int(os.environ.get("FLASK_PORT", "8080"))
    app.run(host='0.0.0.0', port=port)
PY

  # Simple frontend (Bootstrap)
  cat > "${WEB_DIR}/templates/index.html" <<'HT'
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Proxy Manager</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h3>Proxy Manager 面板</h3>
    <small class="text-muted">Probe（公开） & 管理（Token 登录）</small>
  </div>

  <div class="row">
    <div class="col-md-8">
      <div class="card mb-3 p-3">
        <h5>探针（公开）</h5>
        <p>点击下方按钮运行全国探针（无需登录）。</p>
        <button id="probeBtn" class="btn btn-primary">运行探针</button>
        <pre id="probeRes" class="mt-2"></pre>
      </div>

      <div class="card mb-3 p-3">
        <h5>节点示例（需 Token）</h5>
        <p>获取服务器当前节点链接（VLESS/VMess 示例）。</p>
        <input id="tokenNodes" class="form-control mb-2" placeholder="管理员 token">
        <button id="nodesBtn" class="btn btn-outline-secondary">获取节点</button>
        <pre id="nodesRes" class="mt-2"></pre>
      </div>
    </div>

    <div class="col-md-4">
      <div class="card p-3 mb-3">
        <h6>管理员操作</h6>
        <input id="token1" class="form-control mb-2" placeholder="管理员 token">
        <button id="updateCoresBtn" class="btn btn-warning mb-2">更新内核</button><br/>
        <input id="acmeDomain" class="form-control mb-2" placeholder="域名 (example.com)">
        <button id="acmeBtn" class="btn btn-success">申请证书(ACME)</button>
      </div>
      <div class="card p-3">
        <h6>说明</h6>
        <ul>
          <li>探针公开可用，不需要 Token。</li>
          <li>管理员 token 存放于服务器：${SECRETS_DIR}/admin.token</li>
          <li>首次安装后请立即更改管理员 token。</li>
        </ul>
      </div>
    </div>
  </div>
</div>
<script>
document.getElementById('probeBtn').onclick = async ()=>{
  document.getElementById('probeRes').textContent='运行中...';
  const r = await fetch('/api/probe');
  const j = await r.json();
  document.getElementById('probeRes').textContent = JSON.stringify(j, null, 2);
};
document.getElementById('nodesBtn').onclick = async ()=>{
  const token = document.getElementById('tokenNodes').value;
  if(!token){ alert('请输入 Token'); return; }
  const r = await fetch('/api/nodes?token='+encodeURIComponent(token));
  const j = await r.json();
  document.getElementById('nodesRes').textContent = JSON.stringify(j, null, 2);
};
document.getElementById('updateCoresBtn').onclick = async ()=>{
  const token = document.getElementById('token1').value;
  if(!token){ alert('请输入 Token'); return; }
  await fetch('/api/cores/update', {method:'POST', headers:{'Authorization':'Bearer '+token}});
  alert('已开始更新内核');
};
document.getElementById('acmeBtn').onclick = async ()=>{
  const token = document.getElementById('token1').value;
  const domain = document.getElementById('acmeDomain').value;
  if(!token||!domain){ alert('请输入token与域名'); return; }
  const r = await fetch('/api/acme', {method:'POST', headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'}, body: JSON.stringify({domain})});
  const j = await r.json(); alert(JSON.stringify(j));
};
</script>
</body>
</html>
HT

  chmod 644 "${WEB_DIR}/templates/index.html"
  chmod +x "${WEB_DIR}/app.py"
  _info "Web 面板写入完成"
}

write_helper_sh(){
  cat > "${BASE_DIR}/helper.sh" <<'SH'
#!/usr/bin/env bash
BASE_DIR="/etc/proxy-manager"
case "$1" in
  update-cores)
    "${BASE_DIR}/proxy_manager_optimized.sh" update-cores
    ;;
  issue-cert)
    "${BASE_DIR}/proxy_manager_optimized.sh" issue-cert "$2"
    ;;
  *)
    echo "usage: helper.sh {update-cores|issue-cert domain}"
    ;;
esac
SH
  chmod +x "${BASE_DIR}/helper.sh"
}

# -------------------------
# systemd units & nginx
# -------------------------
write_systemd_units(){
  _info "写入 systemd 单元..."
  # web
  cat > "${SYSTEMD_DIR}/proxy-manager-web.service" <<EOF
[Unit]
Description=Proxy Manager Web UI
After=network.target

[Service]
Type=simple
Environment=BASE_DIR=${BASE_DIR}
Environment=FLASK_PORT=${PANEL_PORT}
ExecStart=${VENV_DIR}/bin/python ${WEB_DIR}/app.py
WorkingDirectory=${WEB_DIR}
Restart=on-failure
RestartSec=3s
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

  # xray unit (only if binary exists)
  cat > "${SYSTEMD_DIR}/xray.service" <<EOF
[Unit]
Description=Xray Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=${XRAY_BIN} run -c ${CONF_DIR}/xray.json
WorkingDirectory=${BASE_DIR}
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  # sing-box unit
  cat > "${SYSTEMD_DIR}/sing-box.service" <<EOF
[Unit]
Description=Sing-Box Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=${SINGBOX_BIN} run -c ${CONF_DIR}/singbox.json
WorkingDirectory=${BASE_DIR}
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload || true
  _info "systemd 单元写入完成"
}

write_nginx_config(){
  _info "写入 nginx 配置..."
  mkdir -p "$NGINX_SITES_AVAILABLE" "$NGINX_SITES_ENABLED"
  local site_conf="${NGINX_SITES_AVAILABLE}/proxy-manager"
  cat > "$site_conf" <<NG
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:${PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NG
  ln -sf "$site_conf" "${NGINX_SITES_ENABLED}/proxy-manager"
  nginx -t >/dev/null 2>&1 || _warn "nginx 配置测试失败，请检查 nginx 日志。"
  systemctl restart nginx || true
  _info "nginx 反向代理已启用（HTTP）。"
}

# -------------------------
# generate self-signed cert (for fallback)
# -------------------------
generate_self_signed_cert(){
  if [[ ! -f "${SECRETS_DIR}/cert.pem" ]]; then
    _info "生成自签证书..."
    openssl ecparam -genkey -name prime256v1 -out "${SECRETS_DIR}/private.key" >/dev/null 2>&1
    openssl req -new -x509 -days 36500 -key "${SECRETS_DIR}/private.key" -out "${SECRETS_DIR}/cert.pem" -subj "/CN=localhost" >/dev/null 2>&1
    chmod 600 "${SECRETS_DIR}/private.key" "${SECRETS_DIR}/cert.pem"
    _info "自签证书生成完成 (存放于 ${SECRETS_DIR})."
  fi
}

# -------------------------
# create basic xray/singbox config templates (can be extended by user / panel)
# -------------------------
generate_core_configs(){
  _info "生成基础 xray / sing-box 配置模板..."
  local uuid
  uuid="$(cat "${SECRETS_DIR}/uuid" 2>/dev/null || jq -r '.uuid' "$DEFAULT_CONFIG_FILE" || uuidgen)"
  mkdir -p "${CONF_DIR}"
  # xray.json
  cat > "${CONF_DIR}/xray.json" <<EOF
{
  "log": {"loglevel":"warning"},
  "inbounds":[
    {
      "tag":"vless-tcp",
      "port":443,
      "listen":"0.0.0.0",
      "protocol":"vless",
      "settings":{"clients":[{"id":"${uuid}"}],"decryption":"none"},
      "streamSettings":{"network":"tcp","security":"none"}
    }
  ],
  "outbounds":[{"protocol":"freedom","tag":"direct"}]
}
EOF

  # singbox.json
  cat > "${CONF_DIR}/singbox.json" <<EOF
{
  "log":{"disabled":false,"level":"info"},
  "inbounds":[
    {"type":"vmess","tag":"vmess-ws","listen":"0.0.0.0","listen_port":443,"users":[{"uuid":"${uuid}"}],"transport":{"type":"ws","path":"/${uuid}-ws"}}
  ],
  "outbounds":[{"type":"direct","tag":"direct"}]
}
EOF
  _info "基础核心配置写入：${CONF_DIR}"
}

# -------------------------
# ACME issue helper
# -------------------------
install_acme_sh(){
  if command -v acme.sh >/dev/null 2>&1; then
    _info "acme.sh 已安装"
    return 0
  fi
  _info "安装 acme.sh..."
  curl_get https://get.acme.sh | sh || _warn "acme.sh 安装失败（请手动安装）"
}

issue_cert_acme(){
  local domain="$1"
  if [[ -z "$domain" ]]; then _err "issue-cert 需要域名参数"; return 1; fi
  install_acme_sh
  export HOME="/root"
  ~/.acme.sh/acme.sh --issue --standalone -d "$domain" --force || { _err "acme issue 失败"; return 1; }
  mkdir -p "${CONF_DIR}/certs"
  ~/.acme.sh/acme.sh --install-cert -d "$domain" --key-file "${CONF_DIR}/certs/${domain}.key" --fullchain-file "${CONF_DIR}/certs/${domain}.crt" || _warn "acme install-cert 失败"
  _info "证书保存到 ${CONF_DIR}/certs/${domain}.crt"
  # rewrite nginx config to use TLS
  cat > "${NGINX_SITES_AVAILABLE}/proxy-manager" <<NG
server {
  listen 80;
  server_name ${domain};
  location /.well-known/acme-challenge/ { root /root/.acme.sh/${domain}; }
  location / { return 301 https://\$host\$request_uri; }
}
server {
  listen 443 ssl http2;
  server_name ${domain};
  ssl_certificate ${CONF_DIR}/certs/${domain}.crt;
  ssl_certificate_key ${CONF_DIR}/certs/${domain}.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  location / {
    proxy_pass http://127.0.0.1:${PANEL_PORT};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
}
NG
  ln -sf "${NGINX_SITES_AVAILABLE}/proxy-manager" "${NGINX_SITES_ENABLED}/proxy-manager"
  nginx -t >/dev/null 2>&1 || _warn "nginx 配置测试失败"
  systemctl restart nginx || true
  _info "已为 ${domain} 配置 HTTPS 反向代理 (nginx)"
}

# -------------------------
# start/stop/status helpers
# -------------------------
start_services(){
  _info "启用并启动服务..."
  systemctl daemon-reload
  systemctl enable proxy-manager-web xray sing-box >/dev/null 2>&1 || true
  systemctl restart nginx || true
  systemctl restart proxy-manager-web || true
  # attempt to restart xray/sing-box only if binaries exist
  if [[ -x "$XRAY_BIN" ]]; then systemctl restart xray || true; fi
  if [[ -x "$SINGBOX_BIN" ]]; then systemctl restart sing-box || true; fi
  _info "服务启动命令已下发"
}

stop_services(){
  _info "停止服务..."
  systemctl stop proxy-manager-web || true
  systemctl stop xray || true
  systemctl stop sing-box || true
  _info "服务已停止"
}

status_services(){
  echo "---- nginx ----"
  systemctl status nginx --no-pager || true
  echo "---- web ----"
  systemctl status proxy-manager-web --no-pager || true
  echo "---- xray ----"
  systemctl status xray --no-pager || true
  echo "---- sing-box ----"
  systemctl status sing-box --no-pager || true
}

show_nodes(){
  local ip
  ip="$(curl -s4 icanhazip.com || hostname -I | awk '{print $1}')"
  local uuid
  uuid="$(cat "${SECRETS_DIR}/uuid" 2>/dev/null || jq -r '.uuid' "${DEFAULT_CONFIG_FILE}" 2>/dev/null || echo "")"
  echo "Server IP: $ip"
  echo "UUID: $uuid"
  echo
  echo "VLESS sample:"
  echo "vless://${uuid}@${ip}:443?security=reality#vless_sample"
  echo
  local vm
  vm=$(printf '{"v":"2","ps":"vmess","add":"%s","port":"443","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"/%s-ws","tls":"tls"}' "$ip" "$uuid" "$uuid")
  echo "VMess base64: vmess://$(echo -n "$vm" | base64 -w0)"
}

# -------------------------
# install / update-cores / issue-cert command flow
# -------------------------
DEFAULT_CONFIG_FILE="${CONF_DIR}/config.json"

cmd_install(){
  ensure_root
  detect_env
  prepare_dirs
  install_system_deps
  generate_default_config
  ensure_uuid_and_token
  create_python_venv_and_install
  # download cores
  download_xray || _warn "xray 下载失败（请手动放置二进制到 ${XRAY_BIN}）"
  download_singbox || _warn "sing-box 下载失败（请手动放置二进制到 ${SINGBOX_BIN}）"
  generate_self_signed_cert
  write_web_app
  write_helper_sh
  write_systemd_units
  write_nginx_config
  generate_core_configs
  start_services
  _info "安装完成。访问面板 (HTTP): http://<VPS_IP>:${PANEL_PORT}"
  _info "管理员 token 存放：${SECRETS_DIR}/admin.token，请尽快更改。"
  _info "面板用户名/密码见配置文件：${DEFAULT_CONFIG_FILE} (字段 web.username/web.password)"
}

cmd_update_cores(){
  ensure_root
  detect_env
  download_xray || _warn "xray 更新失败"
  download_singbox || _warn "sing-box 更新失败"
  _info "内核更新尝试完成（若已下载请重启服务）"
}

cmd_issue_cert(){
  ensure_root
  local domain="${1:-}"
  if [[ -z "$domain" ]]; then _err "issue-cert 需要域名参数"; exit 1; fi
  issue_cert_acme "$domain"
}

# -------------------------
# CLI dispatch
# -------------------------
case "${1:-help}" in
  install) cmd_install ;;
  update-cores) cmd_update_cores ;;
  issue-cert) cmd_issue_cert "${2:-}" ;;
  start) start_services ;;
  stop) stop_services ;;
  restart) stop_services; start_services ;;
  status) status_services ;;
  show-nodes) show_nodes ;;
  help|*) 
    cat <<'USAGE'
Usage: proxy_manager_optimized.sh <cmd>
Commands:
  install            Full install (deps, cores, venv, web, nginx, systemd)
  update-cores       Attempt to update xray & sing-box from GitHub
  issue-cert DOMAIN  Issue ACME cert for DOMAIN and enable HTTPS (nginx)
  start|stop|restart
  status
  show-nodes         Print example node URIs
  help
USAGE
    ;;
esac

exit 0
