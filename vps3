#!/usr/bin/env bash
# proxy_manager_pro_final.sh
# Final integrated one-file deployer: sing-box + xray + panel + probe + ACME + nginx + systemd + user management
#
# Author identity (embedded):
#   严谨的程序员 — 将 Argosbx / sing-box-yg 的优秀实现整合为一套“开箱即用”工具
#
# Read: This script is intended to be run on a fresh VPS as root.
# Save as proxy_manager_pro_final.sh, chmod +x, and run: sudo ./proxy_manager_pro_final.sh install
set -euo pipefail
IFS=$'\n\t'

### === GLOBAL PATHS ===
BASE="${HOME}/proxy-manager-pro"
CORES="${BASE}/cores"
CONF="${BASE}/conf"
WEB="${BASE}/web"
LOG="${BASE}/logs"
SECRETS="${BASE}/secrets"
SYSTEMD_DIR="/etc/systemd/system"
FLASK_PORT=8080   # internal; nginx will front to 443
PANEL_HTTP_PORT=8080
NGINX_CONF="/etc/nginx/conf.d/proxy_manager_pro.conf"

# Files
ADMIN_DB="${SECRETS}/users.db"   # sqlite for user management
ADMIN_TOKEN_FILE="${SECRETS}/admin.token"
UUID_FILE="${SECRETS}/uuid"
XRAY_BIN="${CORES}/xray"
SINGBOX_BIN="${CORES}/sing-box"

GITHUB_API="https://api.github.com"

### COLORS
_info(){ printf "\e[32m[INFO]\e[0m %s\n" "$*"; }
_warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
_err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; }

### Ensure root
ensure_root(){ if [[ $EUID -ne 0 ]]; then _err "请以 root 权限运行"; exit 1; fi }

### Detect arch/os
detect_env(){
  ARCH_RAW=$(uname -m)
  case "$ARCH_RAW" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l) ARCH="armv7" ;;
    *) _err "unsupported arch: $ARCH_RAW"; exit 1 ;;
  esac
  if [[ -f /etc/os-release ]]; then . /etc/os-release; OS_ID="${ID,,}"; else OS_ID="$(uname -s)"; fi
  _info "OS=$OS_ID ARCH=$ARCH"
}

### Prepare directories
prepare_dirs(){
  mkdir -p "$CORES" "$CONF" "$WEB" "$LOG" "$SECRETS"
  chmod 700 "$SECRETS"
}

### Install OS deps (Debian/Ubuntu/CentOS/Alpine best-effort)
install_deps(){
  _info "Installing dependencies..."
  if [[ "$OS_ID" =~ (debian|ubuntu) ]]; then
    apt-get update -y
    apt-get install -y curl wget jq unzip tar socat python3 python3-pip openssl nginx sqlite3 net-tools iproute2 iputils-ping vnstat
  elif [[ "$OS_ID" =~ (centos|rocky|rhel) ]]; then
    yum install -y epel-release
    yum install -y curl wget jq unzip tar socat python3 python3-pip openssl nginx sqlite net-tools iproute iputils vnstat
  elif [[ "$OS_ID" == "alpine" ]]; then
    apk add --no-cache curl wget jq unzip tar socat python3 py3-pip openssl nginx sqlite iproute2 iputils
  else
    _warn "未识别系统：请手动安装curl,wget,jq,python3,nginx,openssl,sqlite3,vnstat"
  fi
  pip3 install --no-cache-dir flask flask_cors psutil
  _info "Dependencies installed (or attempted)."
}

### Get latest release tag from GitHub
gh_latest_tag(){
  repo="$1"
  curl -s "${GITHUB_API}/repos/${repo}/releases/latest" | jq -r '.tag_name // empty' || true
}

### Download latest xray / sing-box (try best-effort)
download_cores(){
  _info "Downloading/updating cores..."
  # xray
  tagx=$(gh_latest_tag "XTLS/Xray-core" || true)
  if [[ -n "$tagx" ]]; then
    url="https://github.com/XTLS/Xray-core/releases/download/${tagx}/Xray-linux-${ARCH}.zip"
    tmp="/tmp/xray_${tagx}_${ARCH}.zip"
    if curl -L --retry 3 -f -o "$tmp" "$url"; then
      unzip -o "$tmp" -d /tmp/ >/dev/null 2>&1 || true
      if [[ -f /tmp/xray ]]; then mv /tmp/xray "$XRAY_BIN"; chmod +x "$XRAY_BIN"; _info "xray installed: $XRAY_BIN"; fi
      rm -f "$tmp"
    else _warn "xray download failed for $url"; fi
  else _warn "xray tag not found"; fi

  # sing-box
  tagsb=$(gh_latest_tag "SagerNet/sing-box" || true)
  if [[ -n "$tagsb" ]]; then
    asset="sing-box-${tagsb}-linux-${ARCH}.tar.gz"
    url="https://github.com/SagerNet/sing-box/releases/download/${tagsb}/${asset}"
    tmp="/tmp/singbox_${tagsb}_${ARCH}.tar.gz"
    if curl -L --retry 3 -f -o "$tmp" "$url"; then
      tar -xzf "$tmp" -C /tmp/ || true
      bin=$(find /tmp -maxdepth 2 -type f -name "sing-box" | head -n1 || true)
      if [[ -n "$bin" ]]; then mv "$bin" "$SINGBOX_BIN"; chmod +x "$SINGBOX_BIN"; _info "sing-box installed: $SINGBOX_BIN"; fi
      rm -f "$tmp"
    else _warn "sing-box download failed for $url"; fi
  else _warn "sing-box tag not found"; fi
}

### UUID & admin token
ensure_secrets(){
  if [[ ! -f "$UUID_FILE" ]]; then
    if command -v uuidgen >/dev/null 2>&1; then uuidgen > "$UUID_FILE"; else cat /proc/sys/kernel/random/uuid > "$UUID_FILE"; fi
    chmod 600 "$UUID_FILE"
  fi
  if [[ ! -f "$ADMIN_TOKEN_FILE" ]]; then
    token=$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 48)
    echo "$token" > "$ADMIN_TOKEN_FILE"
    chmod 600 "$ADMIN_TOKEN_FILE"
    _info "Admin token generated at $ADMIN_TOKEN_FILE (change it in panel immediately)"
  fi
  # init sqlite user DB if missing
  if [[ ! -f "$ADMIN_DB" ]]; then
    sqlite3 "$ADMIN_DB" "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, is_admin INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);"
    # create initial admin with token as password (you can change via panel)
    adminpw=$(cat "$ADMIN_TOKEN_FILE")
    sqlite3 "$ADMIN_DB" "INSERT INTO users(username,password,is_admin) VALUES('admin','$adminpw',1);"
    chmod 600 "$ADMIN_DB"
    _info "Initialized user DB and created admin user 'admin' (password = admin token)."
  fi
}

### Generate sample xray/singbox configs (extensible)
generate_configs(){
  uuid=$(cat "$UUID_FILE")
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
      "streamSettings":{
        "network":"tcp",
        "security":"reality",
        "realitySettings":{
          "fingerprint":"chrome",
          "dest":"example.com:443",
          "serverNames":["example.com"],
          "privateKey":"",
          "shortIds":[""]
        }
      }
    }
  ],
  "outbounds":[ {"protocol":"freedom"} ]
}
EOF

  cat > "${CONF}/singbox/singbox.json" <<EOF
{
  "log":{"disabled":false,"level":"info"},
  "inbounds":[
    {
      "type":"vmess",
      "tag":"vmess-ws",
      "listen":"0.0.0.0",
      "listen_port":443,
      "users":[{"uuid":"${uuid}"}],
      "transport":{"type":"ws","path":"/${uuid}-ws"}
    }
  ],
  "outbounds":[{"type":"direct","tag":"direct"}]
}
EOF

  # routing template and user-editable routing.json
  cat > "${CONF}/routing.json" <<'EOF'
{
  "cdn_enabled": true,
  "cdn_pref": ["cdn.example.com","1.2.3.4"],
  "routes": {
    "netflix": "direct",
    "openai": "cdn_or_direct",
    "telegram": "proxy"
  },
  "default_outbound":"direct",
  "socks_proxy":"127.0.0.1:1081"
}
EOF

  _info "Generated baseline xray/singbox configs and routing template (edit under ${CONF})"
}

### ACME (acme.sh) install & issue
install_acme_sh(){
  if command -v acme.sh >/dev/null 2>&1; then _info "acme.sh exists"; return 0; fi
  _info "Installing acme.sh..."
  curl -sSfL https://get.acme.sh | sh || _warn "acme.sh install failed"
}

issue_cert(){
  domain="$1"
  if [[ -z "$domain" ]]; then _err "issue_cert requires domain"; return 1; fi
  install_acme_sh
  export HOME="/root"
  ~/.acme.sh/acme.sh --issue --standalone -d "$domain" --force || { _warn "ACME issue failed"; return 1; }
  mkdir -p "${CONF}/certs"
  ~/.acme.sh/acme.sh --install-cert -d "$domain" \
    --key-file "${CONF}/certs/${domain}.key" \
    --fullchain-file "${CONF}/certs/${domain}.crt" || _warn "acme install-cert failed"
  _info "Certificate saved under ${CONF}/certs/${domain}.crt and .key"
  # write nginx conf to enable HTTPS (below)
}

### WARP-go quick install (for socks5)
install_warp_go(){
  if command -v warp-go >/dev/null 2>&1; then _info "warp-go exists"; return 0; fi
  url="https://github.com/fscarmen/warp/releases/latest/download/warp-go-linux-${ARCH}.tar.gz"
  tmp="/tmp/warp-go.tar.gz"
  if curl -L --retry 3 -f -o "$tmp" "$url"; then
    tar -xzf "$tmp" -C /tmp/
    mv /tmp/warp-go "${BASE}/warp-go" || true
    chmod +x "${BASE}/warp-go"
    _info "warp-go installed in ${BASE}/warp-go"
    rm -f "$tmp"
    return 0
  fi
  _warn "warp-go install failed"
}

### Write web UI (Flask) and static files (UI uses Bootstrap + simple Vue-ish JS for nicer UX)
write_web_ui(){
  mkdir -p "${WEB}/static" "${WEB}/templates"
  # Flask app
  cat > "${WEB}/app.py" <<'PY'
#!/usr/bin/env python3
# Proxy Manager Pro - Flask backend
import os, json, sqlite3, subprocess, time, base64
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_from_directory, abort

BASE = os.environ.get("BASE_DIR", "/root/proxy-manager-pro")
CONF_DIR = os.path.join(BASE, "conf")
SECRETS = os.path.join(BASE, "secrets")
DB = os.path.join(SECRETS, "users.db")
ADMIN_TOKEN_FILE = os.path.join(SECRETS, "admin.token")
app = Flask(__name__, static_folder='static', template_folder='templates')

def read_token():
    try:
        return open(ADMIN_TOKEN_FILE).read().strip()
    except:
        return ""

def token_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        auth = request.headers.get("Authorization","")
        token = ""
        if auth.startswith("Bearer "):
            token = auth.split(" ",1)[1].strip()
        else:
            token = request.args.get("token","")
        if not token or token != read_token():
            return jsonify({"error":"Unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    return render_template("index.html")

# Public probe endpoint (no auth) - runs quick ping to configured targets
@app.route("/api/probe", methods=["GET"])
def probe():
    cfg_file = os.path.join(CONF_DIR, "probe_targets.json")
    if not os.path.exists(cfg_file):
        # default set of targets (approximate regions; editable)
        targets = [
            {"name":"Beijing (AliDNS)","ip":"223.5.5.5"},
            {"name":"Guangzhou (114dns)","ip":"114.114.114.114"},
            {"name":"Shanghai (Baidu)","ip":"180.76.76.76"},
            {"name":"Chengdu (Tencent)","ip":"119.29.29.29"},
            {"name":"HongKong","ip":"1.1.1.1"}
        ]
    else:
        targets = json.load(open(cfg_file))
    results=[]
    for t in targets:
        ip=t.get("ip")
        # run ping count=3
        try:
            out = subprocess.check_output(["ping","-c","3","-W","2",ip], stderr=subprocess.STDOUT, timeout=8).decode()
            # parse avg latency
            avg="N/A"
            for line in out.splitlines():
                if "rtt min/avg/max/mdev" in line or "round-trip" in line:
                    parts = line.split("=")[1].split("/")
                    avg=parts[1].strip()
            results.append({"name":t.get("name"),"ip":ip,"raw":out,"avg_ms":avg})
        except Exception as e:
            results.append({"name":t.get("name"),"ip":ip,"error":str(e),"avg_ms":"N/A"})
    return jsonify({"results":results})

# Auth endpoints
@app.route("/api/login", methods=["POST"])
def login():
    # Basic token-based login: client sends token and gets back success if matches admin token
    j = request.get_json(force=True, silent=True) or {}
    token = j.get("token","")
    if token and token == read_token():
        return jsonify({"ok":True})
    return jsonify({"ok":False}), 401

# Admin: issue cert
@app.route("/api/acme/issue", methods=["POST"])
@token_required
def acme_issue():
    j = request.get_json(force=True, silent=True) or {}
    domain = j.get("domain","")
    if not domain: return jsonify({"error":"domain required"}),400
    # call helper script (non-blocking)
    helper = os.path.join(BASE,"helper.sh")
    subprocess.Popen(["/bin/bash", helper, "issue-cert", domain])
    return jsonify({"result":"started","domain":domain})

# Admin: update cores
@app.route("/api/cores/update", methods=["POST"])
@token_required
def cores_update():
    helper = os.path.join(BASE,"helper.sh")
    subprocess.Popen(["/bin/bash", helper, "update-cores"])
    return jsonify({"result":"started"})

# Admin: get nodes (reads conf)
@app.route("/api/nodes", methods=["GET"])
@token_required
def nodes():
    nodes=[]
    try:
        uuid = open(os.path.join(SECRETS,"uuid")).read().strip()
    except:
        uuid=""
    ip = subprocess.getoutput("curl -s4 https://icanhazip.com || hostname -I | awk '{print $1}'")
    if uuid:
        nodes.append({"type":"vless","uri":f"vless://{uuid}@{ip}:443?security=reality#vless"})
        vm = {"v":"2","ps":"vmess","add":ip,"port":"443","id":uuid,"aid":"0","net":"ws","type":"none","host":"","path":f"/{uuid}-ws","tls":"tls"}
        nodes.append({"type":"vmess","uri":"vmess://"+base64.b64encode(json.dumps(vm).encode()).decode()})
    return jsonify({"nodes":nodes})

# Admin: get status and vnstat
@app.route("/api/status", methods=["GET"])
@token_required
def status():
    def is_running(name):
        return subprocess.call(["pgrep","-f",name])==0
    # system load & memory using psutil if available else /proc
    try:
        import psutil
        load=psutil.getloadavg()
        mem = psutil.virtual_memory()._asdict()
    except:
        load = os.getloadavg() if hasattr(os,'getloadavg') else [0,0,0]
        mem = {}
    return jsonify({"services":{"xray":is_running("xray"),"sing-box":is_running("sing-box")}, "load":load, "mem":mem})

# Admin: manage users (create/delete/list) - example
@app.route("/api/users", methods=["GET","POST","DELETE"])
@token_required
def users():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    if request.method=="GET":
        rows = c.execute("SELECT id,username,is_admin,created_at FROM users").fetchall()
        conn.close()
        return jsonify({"users":[{"id":r[0],"username":r[1],"is_admin":bool(r[2]),"created_at":r[3]} for r in rows]})
    j = request.get_json(force=True, silent=True) or {}
    if request.method=="POST":
        user = j.get("username"); pw = j.get("password"); is_admin = 1 if j.get("is_admin",False) else 0
        if not user or not pw: return jsonify({"error":"username/password required"}),400
        c.execute("INSERT INTO users(username,password,is_admin) VALUES(?,?,?)",(user,pw,is_admin))
        conn.commit(); conn.close(); return jsonify({"ok":True})
    if request.method=="DELETE":
        uid = j.get("id")
        c.execute("DELETE FROM users WHERE id=?",(uid,)); conn.commit(); conn.close(); return jsonify({"ok":True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("FLASK_PORT", "8080")))
PY

  # Static frontend (Bootstrap + nicer layout). Keep it simple but pleasant.
  cat > "${WEB}/templates/index.html" <<'HT'
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Proxy Manager Pro</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>body{background:#f6f8fa}.card{border-radius:12px}</style>
</head>
<body>
<div class="container py-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h2>Proxy Manager Pro</h2>
    <div><button id="loginBtn" class="btn btn-primary">登录</button></div>
  </div>
  <div class="row">
    <div class="col-md-8">
      <div class="card p-3 mb-3">
        <h5>系统状态</h5>
        <pre id="status">加载中...</pre>
      </div>
      <div class="card p-3 mb-3">
        <h5>节点（管理员可查看 / 导出）</h5>
        <pre id="nodes">请登录查看</pre>
      </div>
      <div class="card p-3 mb-3">
        <h5>探针（无需登录）</h5>
        <p>点击下面按钮即可查看全国默认探针延迟（可在配置里编辑目标）</p>
        <button id="probeBtn" class="btn btn-outline-primary">运行探针</button>
        <pre id="probeRes"></pre>
      </div>
    </div>
    <div class="col-md-4">
      <div class="card p-3 mb-3">
        <h5>面板操作</h5>
        <p>管理员功能（登录后可见）</p>
        <button id="coresBtn" class="btn btn-sm btn-warning mb-2">更新内核</button><br/>
        <input id="acmeDomain" class="form-control mb-2" placeholder="请输入域名申请证书 (example.com)"/>
        <button id="acmeBtn" class="btn btn-sm btn-success">申请证书</button>
      </div>
      <div class="card p-3">
        <h5>说明</h5>
        <ul>
          <li>探针公开可用（不需要登录）。</li>
          <li>首次安装请立即修改管理员 token（secrets/admin.token）。</li>
          <li>证书申请需要域名已解析到此服务器。</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<script>
async function probe(){
  document.getElementById('probeRes').textContent='运行中...';
  const r = await fetch('/api/probe');
  const j = await r.json();
  document.getElementById('probeRes').textContent = JSON.stringify(j, null, 2);
}
document.getElementById('probeBtn').addEventListener('click', probe);

document.getElementById('coresBtn').addEventListener('click', async ()=>{
  const token = prompt("请输入管理员 token (from secrets/admin.token):");
  if (!token) return alert("需要 token");
  await fetch('/api/cores/update', {method:'POST', headers:{'Authorization':'Bearer '+token}});
  alert('已开始更新内核');
});

document.getElementById('acmeBtn').addEventListener('click', async ()=>{
  const domain = document.getElementById('acmeDomain').value.trim();
  const token = prompt("请输入管理员 token (from secrets/admin.token):");
  if (!domain || !token) return alert('域名和 token 必需');
  const r = await fetch('/api/acme/issue', {method:'POST', headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'}, body: JSON.stringify({domain})});
  const j = await r.json();
  alert(JSON.stringify(j));
});
</script>
</body>
</html>
HT

  chmod +x "${WEB}/app.py"
  _info "Wrote web UI under ${WEB}"
}

### Helper script invoked by Flask (non-blocking)
write_helper_sh(){
  cat > "${BASE}/helper.sh" <<'SH'
#!/usr/bin/env bash
BASE="${HOME}/proxy-manager-pro"
CONF="${BASE}/conf"
CORES="${BASE}/cores"
XRAY_BIN="${CORES}/xray"
SINGBOX_BIN="${CORES}/sing-box"
case "$1" in
  update-cores)
    # call the main script to update cores (re-entrancy safe)
    "${BASE}/proxy_manager_pro_final.sh" update-cores
    ;;
  issue-cert)
    domain="$2"
    "${BASE}/proxy_manager_pro_final.sh" issue-cert "$domain"
    ;;
  *)
    echo "helper usage"
    ;;
esac
SH
  chmod +x "${BASE}/helper.sh"
  _info "Wrote helper script ${BASE}/helper.sh"
}

### Nginx config and TLS reverse-proxy for panel
write_nginx_conf(){
  # Check if cert for domain exists; panel will use nginx port 80->443
  cat > "${NGINX_CONF}" <<NG
server {
    listen 80;
    server_name _;
    # allow HTTP for ACME; optional redirect to https if cert present
    location / {
        proxy_pass http://127.0.0.1:${PANEL_HTTP_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
NG
  nginx -t >/dev/null 2>&1 || _warn "nginx config test failed (but continuing)"
  systemctl restart nginx || true
  _info "Wrote basic nginx conf ${NGINX_CONF} and restarted nginx (HTTP fronting). For HTTPS, run issue-cert and then restart nginx to serve TLS cert."
}

### Systemd service for web panel, xray, sing-box
write_systemd_units(){
  # web service
  cat > "${SYSTEMD_DIR}/proxy-manager-pro-web.service" <<EOF
[Unit]
Description=Proxy Manager Pro Web UI
After=network.target

[Service]
Type=simple
Environment=BASE_DIR=${BASE}
Environment=FLASK_PORT=${PANEL_HTTP_PORT}
ExecStart=/usr/bin/env python3 ${WEB}/app.py
WorkingDirectory=${WEB}
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

  # xray and sing-box unit templates (only create if binary exists)
  if [[ -x "$XRAY_BIN" ]]; then
    cat > "${SYSTEMD_DIR}/xray-proxy.service" <<EOF
[Unit]
Description=Xray Proxy (proxy_manager_pro)
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

  if [[ -x "$SINGBOX_BIN" ]]; then
    cat > "${SYSTEMD_DIR}/singbox-proxy.service" <<EOF
[Unit]
Description=sing-box Proxy (proxy_manager_pro)
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
  systemctl enable proxy-manager-pro-web.service || true
  systemctl restart proxy-manager-pro-web.service || true
  _info "Wrote & enabled systemd units (web + optionally xray/sing-box)"
}

### Show nodes (human-friendly)
show_nodes(){
  ip=$(curl -s4 https://icanhazip.com || hostname -I | awk '{print $1}')
  uuid=$(cat "$UUID_FILE")
  echo "Server IP: $ip"
  echo "UUID: $uuid"
  echo
  echo "VLESS-Reality sample:"
  echo "vless://${uuid}@${ip}:443?security=reality#vless_sample"
  echo
  vm=$(printf '{"v":"2","ps":"vmess","add":"%s","port":"443","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"/%s-ws","tls":"tls"}' "$ip" "$uuid" "$uuid")
  echo "VMess (base64): vmess://$(echo -n "$vm" | base64 -w0)"
}

### Update cores wrapper
update_cores_cmd(){
  download_cores
  _info "Cores update attempted"
}

### Main entry
case "${1:-help}" in
  install)
    ensure_root
    detect_env
    prepare_dirs
    install_deps
    download_cores
    ensure_secrets
    generate_configs
    write_web_ui
    write_helper_sh
    write_nginx_conf
    write_systemd_units
    # start services
    systemctl restart proxy-manager-pro-web.service || true
    _info "Install finished. Panel: http://<VPS_IP>:${PANEL_HTTP_PORT}  (or https if you issued cert)"
    echo "Admin token file: ${ADMIN_TOKEN_FILE}  (please change immediately)"
    ;;
  update-cores)
    ensure_root; detect_env; prepare_dirs; update_cores_cmd
    ;;
  issue-cert)
    domain="${2:-}"; if [[ -z "$domain" ]]; then _err "usage: $0 issue-cert example.com"; exit 1; fi
    issue_cert "$domain"
    # After cert is issued, overwrite nginx conf for TLS
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
    proxy_pass http://127.0.0.1:${PANEL_HTTP_PORT};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
  }
}
NG
    systemctl restart nginx || true
    _info "Issued cert and reloaded nginx for ${domain}. Panel should be at https://${domain}"
    ;;
  start)
    systemctl start proxy-manager-pro-web.service || true
    systemctl start xray-proxy.service || true
    systemctl start singbox-proxy.service || true
    ;;
  stop)
    systemctl stop proxy-manager-pro-web.service || true
    systemctl stop xray-proxy.service || true
    systemctl stop singbox-proxy.service || true
    ;;
  status)
    systemctl status proxy-manager-pro-web.service --no-pager || true
    systemctl status xray-proxy.service --no-pager || true
    systemctl status singbox-proxy.service --no-pager || true
    ;;
  show-nodes) show_nodes ;;
  help|*)
    cat <<USAGE
Usage: $0 <cmd>
Commands:
  install            full install (create dirs, install deps, download cores, write panel, start services)
  update-cores       download latest xray/sing-box
  issue-cert DOMAIN  request acme cert and enable nginx TLS for panel
  start|stop|status
  show-nodes
USAGE
    ;;
esac
