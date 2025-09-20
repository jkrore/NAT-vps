#!/usr/bin/env bash
# proxy_manager_final.sh
# Final robust deployer: xray + sing-box + Flask panel + nginx + acme + systemd
# - Uses GitHub Releases API to reliably find suitable binary assets (fixes 404 issues)
# - Uses Python venv to avoid PEP 668 system pip errors
# - Compatible with Debian/Ubuntu, CentOS/RHEL, Alpine
# - Creates systemd unit to run Flask app via venv python
# Usage:
#   sudo ./proxy_manager_final.sh install
#   sudo ./proxy_manager_final.sh update-cores
#   sudo ./proxy_manager_final.sh issue-cert your.domain.tld
#   sudo ./proxy_manager_final.sh start|stop|status|show-nodes
set -euo pipefail
IFS=$'\n\t'

# --------------------------
# Configuration - adjust if needed
# --------------------------
BASE="${HOME}/proxy-manager"
CORES="${BASE}/cores"
CONF="${BASE}/conf"
WEB="${BASE}/web"
LOG="${BASE}/logs"
SECRETS="${BASE}/secrets"
SYSTEMD_DIR="/etc/systemd/system"
PANEL_PORT=8080        # Flask internal port (nginx reverse proxy optional)
NGINX_CONF="/etc/nginx/conf.d/proxy_manager.conf"
ADMIN_DB="${SECRETS}/users.db"
ADMIN_TOKEN_FILE="${SECRETS}/admin.token"
UUID_FILE="${SECRETS}/uuid"
XRAY_BIN="${CORES}/xray"
SINGBOX_BIN="${CORES}/sing-box"
GITHUB_API="https://api.github.com"
# Which architectures map to known asset substrings
declare -A ARCH_MAP
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64) ARCH_KEY="amd64"; ARCH_MAP[alt]="amd64 x64 x86_64" ;;
  aarch64|arm64) ARCH_KEY="arm64"; ARCH_MAP[alt]="arm64 aarch64" ;;
  armv7l) ARCH_KEY="armv7"; ARCH_MAP[alt]="armv7 armv7l" ;;
  *) echo "Unsupported arch: $ARCH_RAW"; exit 1 ;;
esac

# Colors
_info(){ printf "\e[32m[INFO]\e[0m %s\n" "$*"; }
_warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
_err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; }

# --------------------------
# Helpers
# --------------------------
ensure_root(){
  if [[ $EUID -ne 0 ]]; then
    _err "请使用 root/sudo 运行此脚本"
    exit 1
  fi
}

detect_os(){
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS_ID="${ID,,}"
  else
    OS_ID="$(uname -s)"
  fi
  _info "Detected OS: $OS_ID, Arch: $ARCH_RAW"
}

prepare_dirs(){
  mkdir -p "$CORES" "$CONF" "$WEB" "$LOG" "$SECRETS"
  chmod 700 "$SECRETS"
}

install_system_packages(){
  _info "Installing system packages (best-effort) ..."
  if [[ "$OS_ID" =~ (debian|ubuntu) ]]; then
    apt-get update -y
    apt-get install -y curl wget jq unzip tar socat python3-venv python3-full nginx sqlite3 iproute2 iputils-ping
  elif [[ "$OS_ID" =~ (centos|rhel|rocky) ]]; then
    yum install -y epel-release
    yum install -y curl wget jq unzip tar socat python3 python3-venv nginx sqlite
  elif [[ "$OS_ID" == "alpine" ]]; then
    apk add --no-cache curl wget jq unzip tar socat python3 py3-pip python3-dev nginx sqlite
  else
    _warn "Unknown OS: please ensure curl jq nginx python3-venv are installed"
  fi
}

# safe curl with retries
curl_retry(){
  local url="$1"; shift
  curl -fsSL --retry 3 --retry-delay 2 "$url" "$@"
}

# Download a release asset by matching name patterns using GitHub Releases API
# Usage: download_release_asset "owner/repo" "pattern1 pattern2 ..." dest_path
download_release_asset(){
  local repo="$1"; shift
  local patterns=($1); shift || true
  local dest="$1"; shift || true
  _info "Searching release assets for repo: $repo"
  # query latest release
  local api="${GITHUB_API}/repos/${repo}/releases/latest"
  local release_json
  release_json="$(curl -sSf "${api}" || true)"
  if [[ -z "$release_json" ]]; then
    _warn "Failed to fetch release info for ${repo} (GitHub API). Trying releases list..."
    release_json="$(curl -sSf "${GITHUB_API}/repos/${repo}/releases" || true)"
    if [[ -z "$release_json" ]]; then
      _warn "Cannot reach GitHub API for ${repo}."
      return 1
    fi
  fi

  # Try to find matching asset
  local assets
  assets="$(echo "$release_json" | jq -r '[.assets[]? | {name: .name, url: .browser_download_url}] | .[] | @base64' 2>/dev/null || true)"
  if [[ -z "$assets" ]]; then
    # maybe release_json is an array (releases list). get first release assets
    assets="$(echo "$release_json" | jq -r '.[0].assets[]? | @base64' 2>/dev/null || true)"
  fi

  if [[ -z "$assets" ]]; then
    _warn "No assets discovered via API for ${repo}."
    return 1
  fi

  # build candidate match regexes: include linux and arch tokens
  local arch_tokens="${ARCH_MAP[alt]}"
  # convert to array
  read -r -a arch_array <<< "$arch_tokens"
  # iterate assets
  while IFS= read -r a_enc; do
    # decode
    name="$(echo "$a_enc" | base64 --decode | jq -r '.name')"
    url="$(echo "$a_enc" | base64 --decode | jq -r '.url')"
    # lower-case name for comparison
    lname="$(echo "$name" | tr '[:upper:]' '[:lower:]')"
    # must contain "linux" and one of arch tokens
    ok=0
    if [[ "$lname" == *linux* ]]; then
      for t in "${arch_array[@]}"; do
        if [[ "$lname" == *"$t"* ]]; then ok=1; break; fi
      done
    fi
    # also allow matching by user-specified patterns
    if [[ $ok -eq 0 && ${#patterns[@]} -gt 0 ]]; then
      for pat in "${patterns[@]}"; do
        if [[ "$lname" == *"${pat,,}"* ]]; then ok=1; break; fi
      done
    fi
    if [[ $ok -eq 1 ]]; then
      _info "Selected asset: $name"
      _info "Downloading $url ..."
      if curl -L --retry 3 -o "$dest" "$url"; then
        _info "Downloaded to $dest"
        return 0
      else
        _warn "Failed to download $url"
      fi
    fi
  done < <(echo "$assets")
  _warn "No matching asset downloaded for $repo"
  return 1
}

# Multi-strategy download wrapper for xray/sing-box
download_xray(){
  mkdir -p "$CORES"
  tmp="/tmp/xray_asset_$$"
  patterns=("xray" "xray-core" "xray-linux" "xray-core-linux")
  if download_release_asset "XTLS/Xray-core" "${patterns[*]}" "$tmp"; then
    unzip -o "$tmp" -d /tmp/ || true
    if [[ -f /tmp/xray ]]; then mv /tmp/xray "$XRAY_BIN"; chmod +x "$XRAY_BIN"; rm -f "$tmp"; _info "xray installed at $XRAY_BIN"; return 0; fi
    # sometimes binary inside folder e.g. xray/xray
    binpath=$(find /tmp -maxdepth 2 -type f -name "xray" | head -n1 || true)
    if [[ -n "$binpath" ]]; then mv "$binpath" "$XRAY_BIN"; chmod +x "$XRAY_BIN"; rm -f "$tmp"; _info "xray installed at $XRAY_BIN"; return 0; fi
  fi
  # fallback manual urls (older naming)
  candidates=(
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-${ARCH_KEY}.zip"
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$ARCH_RAW.zip"
  )
  for url in "${candidates[@]}"; do
    _info "Trying fallback URL: $url"
    if curl -L --retry 3 -f -o "$tmp" "$url"; then
      unzip -o "$tmp" -d /tmp/ || true
      if [[ -f /tmp/xray ]]; then mv /tmp/xray "$XRAY_BIN"; chmod +x "$XRAY_BIN"; rm -f "$tmp"; _info "xray installed at $XRAY_BIN"; return 0; fi
    fi
  done
  _warn "xray download failed. You can place xray binary at $XRAY_BIN manually and make it executable."
  return 1
}

download_singbox(){
  mkdir -p "$CORES"
  tmp="/tmp/singbox_asset_$$"
  patterns=("sing-box" "singbox" "sing-box-linux" "sing-box-${ARCH_KEY}")
  if download_release_asset "SagerNet/sing-box" "${patterns[*]}" "$tmp"; then
    # try untar
    tar -xzf "$tmp" -C /tmp/ || true
    binpath=$(find /tmp -maxdepth 3 -type f -name "sing-box" | head -n1 || true)
    if [[ -n "$binpath" ]]; then mv "$binpath" "$SINGBOX_BIN"; chmod +x "$SINGBOX_BIN"; rm -f "$tmp"; _info "sing-box installed at $SINGBOX_BIN"; return 0; fi
  fi
  # fallback patterns
  candidates=(
    "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-${ARCH_KEY}.tar.gz"
    "https://github.com/SagerNet/sing-box/releases/latest/download/sing-box-linux-${ARCH_KEY}.tar.gz"
  )
  for url in "${candidates[@]}"; do
    _info "Trying fallback URL: $url"
    if curl -L --retry 3 -f -o "$tmp" "$url"; then
      tar -xzf "$tmp" -C /tmp/ || true
      binpath=$(find /tmp -maxdepth 3 -type f -name "sing-box" | head -n1 || true)
      if [[ -n "$binpath" ]]; then mv "$binpath" "$SINGBOX_BIN"; chmod +x "$SINGBOX_BIN"; rm -f "$tmp"; _info "sing-box installed at $SINGBOX_BIN"; return 0; fi
    fi
  done
  _warn "sing-box download failed. You can place sing-box binary at $SINGBOX_BIN manually and make it executable."
  return 1
}

# --------------------------
# generate configs, uuid, admin token, venv, web app
# --------------------------
ensure_uuid_and_token(){
  if [[ ! -f "$UUID_FILE" ]]; then
    if command -v uuidgen >/dev/null 2>&1; then uuidgen > "$UUID_FILE"; else cat /proc/sys/kernel/random/uuid > "$UUID_FILE"; fi
    chmod 600 "$UUID_FILE"
  fi
  if [[ ! -f "$ADMIN_TOKEN_FILE" ]]; then
    token=$(head -c 48 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 48)
    echo "$token" > "$ADMIN_TOKEN_FILE"
    chmod 600 "$ADMIN_TOKEN_FILE"
    _info "Generated admin token at $ADMIN_TOKEN_FILE"
  fi
}

create_python_venv_and_install(){
  VENV_DIR="${BASE}/venv"
  if [[ ! -d "$VENV_DIR" ]]; then
    python3 -m venv "$VENV_DIR"
    _info "Created python venv at $VENV_DIR"
  fi
  # use venv pip; don't modify system pip
  "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
  "$VENV_DIR/bin/pip" install flask flask_cors psutil >/dev/null 2>&1 || true
  _info "Installed Python dependencies inside venv"
}

generate_basic_configs(){
  local uuid; uuid="$(cat "$UUID_FILE")"
  mkdir -p "${CONF}/xray" "${CONF}/singbox" "${CONF}/certs"
  cat > "${CONF}/xray/xray.json" <<EOF
{
  "log": {"loglevel":"warning"},
  "inbounds": [
    {
      "tag":"vless-reality",
      "listen":"0.0.0.0",
      "port":443,
      "protocol":"vless",
      "settings":{"clients":[{"id":"${uuid}"}],"decryption":"none"},
      "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"fingerprint":"chrome","dest":"example.com:443","serverNames":["example.com"],"privateKey":"","shortIds":[""]}}
    }
  ],
  "outbounds":[{"protocol":"freedom","tag":"direct"}]
}
EOF

  cat > "${CONF}/singbox/singbox.json" <<EOF
{
  "log":{"disabled":false,"level":"info"},
  "inbounds":[
    {"type":"vmess","tag":"vmess-ws","listen":"0.0.0.0","listen_port":443,"users":[{"uuid":"${uuid}"}],"transport":{"type":"ws","path":"/${uuid}-ws"}}
  ],
  "outbounds":[{"type":"direct","tag":"direct"}]
}
EOF

  # routing template
  cat > "${CONF}/routing.json" <<'EOF'
{
  "default_outbound":"direct",
  "cdn_pref": [],
  "rules": []
}
EOF

  # probe defaults (editable)
  cat > "${CONF}/probe_targets.json" <<'EOF'
[
  {"name":"Beijing (AliDNS)","ip":"223.5.5.5"},
  {"name":"Guangzhou (114)","ip":"114.114.114.114"},
  {"name":"Shanghai (Baidu)","ip":"180.76.76.76"},
  {"name":"Chengdu (Tencent)","ip":"119.29.29.29"},
  {"name":"HongKong (Cloudflare)","ip":"1.1.1.1"}
]
EOF

  _info "Generated baseline configs under $CONF"
}

# --------------------------
# Write web UI (Flask) - simple but functional and uses venv python
# --------------------------
write_web_app(){
  mkdir -p "$WEB/templates" "$WEB/static"
  cat > "${WEB}/app.py" <<'PY'
#!/usr/bin/env python3
import os, json, subprocess, sqlite3, base64
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_from_directory

BASE = os.environ.get("BASE_DIR", "/root/proxy-manager")
CONF_DIR = os.path.join(BASE, "conf")
SECRETS = os.path.join(BASE, "secrets")
DB = os.path.join(SECRETS, "users.db")
TOKEN_FILE = os.path.join(SECRETS, "admin.token")
app = Flask(__name__, template_folder='templates')

def read_token():
    try:
        return open(TOKEN_FILE).read().strip()
    except:
        return ""

def token_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization","")
        token=""
        if auth.startswith("Bearer "):
            token = auth.split(" ",1)[1].strip()
        else:
            token = request.args.get("token","")
        if token != read_token():
            return jsonify({"error":"Unauthorized"}),401
        return f(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/probe")
def probe():
    targets_file = os.path.join(CONF_DIR, "probe_targets.json")
    if os.path.exists(targets_file):
        targets = json.load(open(targets_file))
    else:
        targets = [{"name":"Cloudflare","ip":"1.1.1.1"}]
    res = []
    for t in targets:
        ip = t.get("ip")
        try:
            out = subprocess.check_output(["ping","-c","3","-W","2",ip], stderr=subprocess.STDOUT, timeout=10).decode()
            avg="N/A"
            for line in out.splitlines():
                if "rtt min/avg/max" in line or "min/avg" in line:
                    parts = line.split("=")[1].split("/")
                    avg = parts[1].strip()
            res.append({"name":t.get("name"),"ip":ip,"avg_ms":avg,"raw":out})
        except Exception as e:
            res.append({"name":t.get("name"),"ip":ip,"avg_ms":"N/A","error":str(e)})
    return jsonify({"results":res})

@app.route("/api/status")
@token_required
def status():
    def running(p):
        return subprocess.call(["pgrep","-f",p])==0
    load = os.getloadavg() if hasattr(os,'getloadavg') else [0,0,0]
    return jsonify({"services":{"xray":running("xray"),"sing-box":running("sing-box")}, "load":load})

@app.route("/api/nodes")
@token_required
def nodes():
    try:
        uuid = open(os.path.join(SECRETS,"uuid")).read().strip()
    except:
        uuid=""
    ip = subprocess.getoutput("curl -s4 https://icanhazip.com || hostname -I | awk '{print $1}'")
    nodes=[]
    if uuid:
        nodes.append({"type":"vless","uri":f"vless://{uuid}@{ip}:443?security=reality#vless"})
        vm = {"v":"2","ps":"vmess","add":ip,"port":"443","id":uuid,"aid":"0","net":"ws","type":"none","host":"","path":f"/{uuid}-ws","tls":"tls"}
        nodes.append({"type":"vmess","uri":"vmess://"+base64.b64encode(json.dumps(vm).encode()).decode()})
    return jsonify({"nodes":nodes})

@app.route("/api/cores/update", methods=["POST"])
@token_required
def update_cores():
    helper = os.path.join(BASE,"helper.sh")
    subprocess.Popen(["/bin/bash",helper,"update-cores"])
    return jsonify({"result":"update started"})

@app.route("/api/acme", methods=["POST"])
@token_required
def acme():
    j = request.get_json(force=True)
    domain = j.get("domain","")
    if not domain:
        return jsonify({"error":"domain required"}),400
    helper = os.path.join(BASE,"helper.sh")
    subprocess.Popen(["/bin/bash",helper,"issue-cert",domain])
    return jsonify({"result":"issue started","domain":domain})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("FLASK_PORT", "8080")))
PY

  # Very small frontend (Bootstrap) - probe public, admin features via token
  cat > "${WEB}/templates/index.html" <<'HT'
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<title>Proxy Manager</title></head><body>
<div class="container py-4">
<h3>Proxy Manager - Probe (public)</h3>
<p>Click to run probe (no login required)</p>
<button id="probe" class="btn btn-primary">Run Probe</button>
<pre id="res"></pre>
<hr>
<p>Admin actions (click triggers require token)</p>
<button id="cores" class="btn btn-warning">Update Cores</button>
<input id="token" class="form-control" placeholder="Admin token" style="width:60%;display:inline-block">
<script>
document.getElementById('probe').onclick = async ()=>{
  const r=await fetch('/api/probe'); const j=await r.json(); document.getElementById('res').textContent=JSON.stringify(j,null,2);
}
document.getElementById('cores').onclick = async ()=>{
  const t=document.getElementById('token').value; if(!t){alert('token needed');return;}
  await fetch('/api/cores/update',{method:'POST',headers:{'Authorization':'Bearer '+t}});
  alert('update started');
}
</script>
</div></body></html>
' >> "${WEB}/templates/index.html"
  chmod +x "${WEB}/app.py"
  _info "Web app written to $WEB"
}

write_helper_sh(){
  cat > "${BASE}/helper.sh" <<'SH'
#!/usr/bin/env bash
BASE="${HOME}/proxy-manager"
case "$1" in
  update-cores) "${BASE}/proxy_manager_final.sh" update-cores ;;
  issue-cert) "${BASE}/proxy_manager_final.sh" issue-cert "$2" ;;
  *) echo "usage: helper.sh <update-cores|issue-cert domain>" ;;
esac
SH
  chmod +x "${BASE}/helper.sh"
}

write_nginx_conf(){
  # basic HTTP reverse proxy (will be updated for TLS upon issue-cert)
  cat > "${NGINX_CONF}" <<NG
server {
    listen 80;
    server_name _;
    location / {
        proxy_pass http://127.0.0.1:${PANEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
NG
  nginx -t >/dev/null 2>&1 || _warn "nginx config test failed"
  systemctl restart nginx || true
  _info "Wrote nginx conf at ${NGINX_CONF}"
}

write_systemd_units(){
  # web service using venv python
  VENV="${BASE}/venv"
  APP="${WEB}/app.py"
  cat > "${SYSTEMD_DIR}/proxy-manager-web.service" <<EOF
[Unit]
Description=Proxy Manager Web UI
After=network.target

[Service]
Type=simple
Environment=BASE_DIR=${BASE}
Environment=FLASK_PORT=${PANEL_PORT}
ExecStart=${VENV}/bin/python ${APP}
WorkingDirectory=${WEB}
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF
  # xray
  if [[ -x "$XRAY_BIN" ]]; then
    cat > "${SYSTEMD_DIR}/xray-proxy.service" <<EOF
[Unit]
Description=Xray Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=${XRAY_BIN} run -c ${CONF}/xray/xray.json
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  fi
  # sing-box
  if [[ -x "$SINGBOX_BIN" ]]; then
    cat > "${SYSTEMD_DIR}/singbox-proxy.service" <<EOF
[Unit]
Description=sing-box Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=${SINGBOX_BIN} run -c ${CONF}/singbox/singbox.json
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
  fi
  systemctl daemon-reload || true
  systemctl enable proxy-manager-web.service || true
  systemctl restart proxy-manager-web.service || true
  _info "Systemd units written and web service started"
}

show_nodes(){
  ip=$(curl -s4 https://icanhazip.com || hostname -I | awk '{print $1}')
  uuid=$(cat "$UUID_FILE")
  echo "Server IP: $ip"
  echo "UUID: $uuid"
  echo
  echo "VLESS sample:"
  echo "vless://${uuid}@${ip}:443?security=reality#sample"
  echo
  vm=$(printf '{"v":"2","ps":"vmess","add":"%s","port":"443","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"/%s-ws","tls":"tls"}' "$ip" "$uuid" "$uuid")
  echo "VMess base64: vmess://$(echo -n "$vm" | base64 -w0)"
}

# --------------------------
# Commands: install, update-cores, issue-cert, start, stop, status, show-nodes
# --------------------------
case "${1:-help}" in
  install)
    ensure_root
    detect_os
    prepare_dirs
    install_system_packages
    download_xray || _warn "xray may not be installed — you can place binary at $XRAY_BIN"
    download_singbox || _warn "sing-box may not be installed — you can place binary at $SINGBOX_BIN"
    ensure_uuid_and_token
    create_python_venv_and_install
    generate_basic_configs
    write_web_app
    write_helper_sh
    write_nginx_conf
    write_systemd_units
    _info "Install finished. Panel: http://<VPS_IP>:${PANEL_PORT}  (Admin token at ${ADMIN_TOKEN_FILE})"
    ;;
  update-cores)
    ensure_root
    detect_os
    download_xray
    download_singbox
    ;;
  issue-cert)
    ensure_root
    domain="${2:-}"
    if [[ -z "$domain" ]]; then _err "usage: $0 issue-cert example.com"; exit 1; fi
    # install acme.sh if needed
    if ! command -v acme.sh >/dev/null 2>&1; then
      _info "Installing acme.sh"
      curl -sSfL https://get.acme.sh | sh || _warn "acme.sh install failed"
    fi
    export HOME="/root"
    ~/.acme.sh/acme.sh --issue --standalone -d "$domain" --force || { _err "acme issue failed"; exit 1; }
    mkdir -p "${CONF}/certs"
    ~/.acme.sh/acme.sh --install-cert -d "$domain" --key-file "${CONF}/certs/${domain}.key" --fullchain-file "${CONF}/certs/${domain}.crt"
    _info "Saved cert to ${CONF}/certs/${domain}.crt"
    # rewrite nginx conf for TLS
    cat > "${NGINX_CONF}" <<NG
server {
  listen 80;
  server_name ${domain};
  location /.well-known/acme-challenge/ { root /root/.acme.sh/${domain}; }
  location / { return 301 https://\$host\$request_uri; }
}
server {
  listen 443 ssl http2;
  server_name ${domain};
  ssl_certificate ${CONF}/certs/${domain}.crt;
  ssl_certificate_key ${CONF}/certs/${domain}.key;
  ssl_protocols TLSv1.2 TLSv1.3;
  location / {
    proxy_pass http://127.0.0.1:${PANEL_PORT};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
  }
}
NG
    systemctl restart nginx || true
    _info "Issued cert and reloaded nginx. Panel at https://${domain}"
    ;;
  start)
    systemctl start proxy-manager-web.service || true
    systemctl start xray-proxy.service || true
    systemctl start singbox-proxy.service || true
    ;;
  stop)
    systemctl stop proxy-manager-web.service || true
    systemctl stop xray-proxy.service || true
    systemctl stop singbox-proxy.service || true
    ;;
  status)
    systemctl status proxy-manager-web.service --no-pager || true
    systemctl status xray-proxy.service --no-pager || true
    systemctl status singbox-proxy.service --no-pager || true
    ;;
  show-nodes) show_nodes ;;
  help|*)
    cat <<USAGE
Usage: $0 <cmd>
Commands:
  install            Full install and start (deps, cores, venv, web, systemd, nginx)
  update-cores       Download latest xray and sing-box releases
  issue-cert DOMAIN  Request ACME cert and enable HTTPS fronting (nginx)
  start|stop|status
  show-nodes
USAGE
    ;;
esac
