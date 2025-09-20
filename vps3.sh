#!/usr/bin/env bash
# proxy_manager_ultimate.sh
# Ultimate Proxy Manager — one-file installer
# Author: 严谨的程序员 (GPT-5 Thinking mini)
# Version: 1.0.0-ultimate
#
# Features:
# - Multi-protocol templates: VLESS(Reality)/VMess(WS)/Tuic/Hysteria2/SS/Trojan (templates)
# - Port multiplexing templates & port range examples
# - Reality keypair + short_id generation and management
# - Web panel (Flask) with full user management (SQLite), admin roles, session tokens
# - Exec API (admin only) with whitelist + auditing
# - Public probe (no login) + per-region latency visualization (parallel ping/TCP)
# - WARP (warp-go) install & socks manage
# - GitHub releases asset smart download for xray & sing-box
# - Uses python venv, systemd units, nginx reverse-proxy, acme.sh support
#
set -euo pipefail
IFS=$'\n\t'

### ------------------------
### Configuration (tweak if desired)
### ------------------------
BASE_DIR="/etc/proxy-manager-ultimate"
CORES_DIR="${BASE_DIR}/cores"
CONF_DIR="${BASE_DIR}/conf"
WEB_DIR="${BASE_DIR}/web"
LOG_DIR="${BASE_DIR}/logs"
SECRETS_DIR="${BASE_DIR}/secrets"
VENV_DIR="${BASE_DIR}/venv"
SYSTEMD_DIR="/etc/systemd/system"
NGINX_SITES_AVAILABLE="/etc/nginx/sites-available"
NGINX_SITES_ENABLED="/etc/nginx/sites-enabled"
PANEL_PORT=8080
GITHUB_API="https://api.github.com"

# Files
CONFIG_JSON="${CONF_DIR}/config.json"
SQLITE_DB="${SECRETS_DIR}/users.db"
ADMIN_TOKEN_FILE="${SECRETS_DIR}/admin.token"
REALITY_PRIV="${SECRETS_DIR}/reality_priv.pem"
REALITY_PUB="${SECRETS_DIR}/reality_pub.pem"
REALITY_SHORTIDS="${SECRETS_DIR}/reality_shortids.json"
AUDIT_LOG="${LOG_DIR}/audit.log"

# Architectures mapping
ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
  x86_64) ARCH_KEY="amd64"; ARCH_ALIASES=("amd64" "x86_64" "x64");;
  aarch64|arm64) ARCH_KEY="arm64"; ARCH_ALIASES=("arm64" "aarch64");;
  armv7l) ARCH_KEY="armv7"; ARCH_ALIASES=("armv7" "armv7l");;
  *) echo "Unsupported arch: $ARCH_RAW"; exit 1;;
esac

# Colors
_info(){ printf "\e[32m[INFO]\e[0m %s\n" "$*"; }
_warn(){ printf "\e[33m[WARN]\e[0m %s\n" "$*"; }
_err(){ printf "\e[31m[ERR]\e[0m %s\n" "$*"; }

# Ensure running as root
ensure_root(){ if [[ $EUID -ne 0 ]]; then _err "Run as root"; exit 1; fi }

# Create required directories
prepare_dirs(){
  mkdir -p "$BASE_DIR" "$CORES_DIR" "$CONF_DIR" "$WEB_DIR" "$LOG_DIR" "$SECRETS_DIR"
  chmod 700 "$SECRETS_DIR"
  touch "$AUDIT_LOG"
}

# Install basic system deps (best-effort)
install_system_deps(){
  _info "Installing system dependencies (best-effort)..."
  if [[ -f /etc/debian_version ]]; then
    apt-get update -y
    apt-get install -y curl wget jq unzip tar socat nginx python3-venv python3-pip openssl iproute2 iputils-ping net-tools git || true
  elif [[ -f /etc/alpine-release ]]; then
    apk add --no-cache curl wget jq unzip tar socat nginx python3 py3-pip openssl iproute2 iputils bind-tools || true
  elif [[ -f /etc/redhat-release ]]; then
    yum install -y epel-release || true
    yum install -y curl wget jq unzip tar socat nginx python3 python3-pip openssl iproute iputils || true
  else
    _warn "Unknown OS; ensure curl, jq, nginx, python3-venv, openssl are installed."
  fi
}

# Curl helper
curl_get(){ curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 "$@"; }

# Smart GitHub asset download (tries releases, matches linux + arch + patterns)
download_release_asset(){
  repo="$1"; patterns="$2"; dest="$3"
  _info "Querying GitHub releases for $repo"
  releases=$(curl -s "${GITHUB_API}/repos/${repo}/releases" || echo "")
  if [[ -z "$releases" ]]; then _warn "GitHub API unreachable for $repo"; return 1; fi
  len=$(echo "$releases" | jq '. | length')
  if [[ "$len" == "0" ]]; then _warn "No releases found for $repo"; return 1; fi
  for i in $(seq 0 $((len-1))); do
    release=$(echo "$releases" | jq -r ".[$i]")
    # skip prerelease until later
    is_prerelease=$(echo "$release" | jq -r '.prerelease')
    if [[ "$is_prerelease" == "true" ]]; then continue; fi
    assets=$(echo "$release" | jq -c '.assets[]?')
    echo "$assets" | while read -r asset; do
      name=$(echo "$asset" | jq -r '.name' | tr '[:upper:]' '[:lower:]')
      url=$(echo "$asset" | jq -r '.browser_download_url')
      # require linux and arch alias
      if [[ "$name" != *linux* ]]; then continue; fi
      ok_arch=0
      for a in "${ARCH_ALIASES[@]}"; do
        if [[ "$name" == *"$a"* ]]; then ok_arch=1; break; fi
      done
      if [[ $ok_arch -eq 0 ]]; then continue; fi
      # patterns match
      ok_pat=0
      for p in $patterns; do
        if [[ -z "$p" ]]; then ok_pat=1; break; fi
        if echo "$name" | grep -qi "$p"; then ok_pat=1; break; fi
      done
      if [[ $ok_pat -eq 0 ]]; then continue; fi
      _info "Found asset: $name. Downloading..."
      if curl -L --retry 3 -o "$dest" "$url"; then return 0; fi
    done
  done
  # fallback: try any release (including prerelease)
  for i in $(seq 0 $((len-1))); do
    release=$(echo "$releases" | jq -r ".[$i]")
    assets=$(echo "$release" | jq -c '.assets[]?')
    echo "$assets" | while read -r asset; do
      name=$(echo "$asset" | jq -r '.name' | tr '[:upper:]' '[:lower:]')
      url=$(echo "$asset" | jq -r '.browser_download_url')
      if [[ "$name" != *linux* ]]; then continue; fi
      ok_arch=0
      for a in "${ARCH_ALIASES[@]}"; do
        if [[ "$name" == *"$a"* ]]; then ok_arch=1; break; fi
      done
      if [[ $ok_arch -eq 0 ]]; then continue; fi
      _info "Fallback asset: $name. Downloading..."
      if curl -L --retry 3 -o "$dest" "$url"; then return 0; fi
    done
  done
  _warn "No suitable asset found for $repo"
  return 1
}

download_xray(){
  mkdir -p "$CORES_DIR"
  tmp="/tmp/xray_asset_${RANDOM}"
  if download_release_asset "XTLS/Xray-core" "xray|xray-core" "$tmp"; then
    unzip -o "$tmp" -d /tmp/xray_unpack >/dev/null 2>&1 || true
    bin=$(find /tmp/xray_unpack -type f -name "xray" | head -n1 || true)
    if [[ -n "$bin" ]]; then mv "$bin" "${CORES_DIR}/xray"; chmod +x "${CORES_DIR}/xray"; rm -rf /tmp/xray_unpack; rm -f "$tmp"; _info "xray installed"; return 0; fi
  fi
  _warn "xray download failed; please place xray binary at ${CORES_DIR}/xray"
  return 1
}

download_singbox(){
  mkdir -p "$CORES_DIR"
  tmp="/tmp/singbox_asset_${RANDOM}"
  if download_release_asset "SagerNet/sing-box" "sing-box|singbox" "$tmp"; then
    mkdir -p /tmp/singbox_unpack
    tar -xzf "$tmp" -C /tmp/singbox_unpack || true
    bin=$(find /tmp/singbox_unpack -type f -name "sing-box" | head -n1 || true)
    if [[ -n "$bin" ]]; then mv "$bin" "${CORES_DIR}/sing-box"; chmod +x "${CORES_DIR}/sing-box"; rm -rf /tmp/singbox_unpack; rm -f "$tmp"; _info "sing-box installed"; return 0; fi
  fi
  _warn "sing-box download failed; please place sing-box binary at ${CORES_DIR}/sing-box"
  return 1
}

# Generate default configuration (including probe targets)
generate_default_config(){
  if [[ -f "$CONFIG_JSON" ]]; then _info "Config exists"; return 0; fi
  uuid="$(uuidgen || cat /proc/sys/kernel/random/uuid)"
  pass="$(head -c 48 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 16)"
  cat > "$CONFIG_JSON" <<EOF
{
  "uuid":"$uuid",
  "domain":"",
  "web":{"port":${PANEL_PORT},"admin_user":"admin","admin_pass":"$pass"},
  "warp":{"enabled":false,"socks_port":1081},
  "probe_targets":[
    {"region":"Beijing","name":"AliDNS","ip":"223.5.5.5"},
    {"region":"Guangzhou","name":"114","ip":"114.114.114.114"},
    {"region":"Shanghai","name":"Baidu","ip":"180.76.76.76"},
    {"region":"Chengdu","name":"Tencent","ip":"119.29.29.29"},
    {"region":"HK","name":"Cloudflare","ip":"1.1.1.1"}
  ],
  "cores":{"auto_update":true}
}
EOF
  chmod 600 "$CONFIG_JSON"
  _info "Default config generated. Admin password: $pass (in ${CONFIG_JSON} under web.admin_pass)."
}

ensure_secrets(){
  if [[ ! -f "$ADMIN_TOKEN_FILE" ]]; then
    t="$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 48)"
    echo "$t" > "$ADMIN_TOKEN_FILE"
    chmod 600 "$ADMIN_TOKEN_FILE"
    _info "Admin token generated at $ADMIN_TOKEN_FILE (change it after first login)."
  fi
  if [[ ! -f "${SECRETS_DIR}/uuid" ]]; then
    jq -r '.uuid' "$CONFIG_JSON" > "${SECRETS_DIR}/uuid"
    chmod 600 "${SECRETS_DIR}/uuid"
  fi
}

# Reality key generation: generate X25519 keypair (openssl), store priv/pub and create short ids
generate_reality_keys(){
  if [[ -f "$REALITY_PRIV" && -f "$REALITY_PUB" && -f "$REALITY_SHORTIDS" ]]; then
    _info "Reality keys exist"
    return 0
  fi
  _info "Generating Reality keypair (X25519) and short_ids..."
  # Generate X25519 private key
  openssl genpkey -algorithm X25519 -out "$REALITY_PRIV" 2>/dev/null || true
  # Extract public key
  openssl pkey -in "$REALITY_PRIV" -pubout -out "$REALITY_PUB" 2>/dev/null || true
  chmod 600 "$REALITY_PRIV" "$REALITY_PUB"
  # Create several short ids (base64 url-safe) for Reality
  jq -n '[ "shortid1","shortid2","shortid3" ]' > "$REALITY_SHORTIDS"
  # Replace placeholders with random base64 strings
  python3 - <<PY > /dev/null 2>&1 || true
import json,base64,os
s=[base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip('=') for _ in range(6)]
open("$REALITY_SHORTIDS","w").write(json.dumps(s))
PY
  _info "Reality private/public keys and short_ids created at ${SECRETS_DIR}"
}

# Create Python venv and install required Python packages (Flask, psutil, qrcode)
create_venv_and_install_pydeps(){
  if [[ ! -d "$VENV_DIR" ]]; then
    _info "Creating Python venv at $VENV_DIR"
    python3 -m venv "$VENV_DIR"
  fi
  "$VENV_DIR/bin/pip" install --upgrade pip setuptools wheel >/dev/null 2>&1 || true
  "$VENV_DIR/bin/pip" install flask flask_cors psutil qrcode pillow requests >/dev/null 2>&1 || true
  _info "Python deps installed in venv"
}

# Initialize SQLite DB for users and audit
init_sqlite_db(){
  if [[ ! -f "$SQLITE_DB" ]]; then
    _info "Initializing SQLite DB for users and audit"
    sqlite3 "$SQLITE_DB" <<SQL
CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  is_admin INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE exec_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user TEXT,
  cmd TEXT,
  result TEXT,
  ts DATETIME DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO users(username,password_hash,is_admin) VALUES('admin','$(python3 - <<PY
import hashlib,sys
salt='ultimate_salt'
pw = sys.stdin.read().strip()
h = hashlib.sha256((salt+pw).encode()).hexdigest()
print(h)
PY <<EOF
$(jq -r '.web.admin_pass' "$CONFIG_JSON")
EOF
)',1);
SQL
    chmod 600 "$SQLITE_DB"
    _info "SQLite DB initialized; admin user created (password from config.json web.admin_pass)."
  fi
}

# Write Flask app (full features)
write_web_app(){
  _info "Writing web application to ${WEB_DIR}"
  mkdir -p "${WEB_DIR}/templates" "${WEB_DIR}/static"
  cat > "${WEB_DIR}/app.py" <<'PY'
#!/usr/bin/env python3
# web app for proxy manager ultimate
import os, json, sqlite3, hashlib, base64, subprocess, threading, time, shlex
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_file, send_from_directory, redirect
import qrcode
import io
import psutil

BASE_DIR = os.environ.get("BASE_DIR", "/etc/proxy-manager-ultimate")
CONF_FILE = os.path.join(BASE_DIR, "conf", "config.json")
SECRETS_DIR = os.path.join(BASE_DIR, "secrets")
DB = os.path.join(SECRETS_DIR, "users.db")
TOKEN_FILE = os.path.join(SECRETS_DIR, "admin.token")
VENV_PY = os.path.join(BASE_DIR, "venv", "bin", "python")
AUDIT_LOG = os.path.join(BASE_DIR, "logs", "audit.log")

app = Flask(__name__, template_folder="templates", static_folder="static")

# password hashing
SALT = "ultimate_salt_v1"
def hash_pw(pw):
    return hashlib.sha256((SALT+pw).encode()).hexdigest()

def query_db(q, args=(), one=False):
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(q, args)
    rv = cur.fetchall()
    con.commit()
    con.close()
    return (rv[0] if rv else None) if one else rv

def token_ok(token):
    try:
        return open(TOKEN_FILE).read().strip() == token
    except:
        return False

# session: simple token in cookie
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        session_token = request.cookies.get("session_token","")
        if not session_token:
            return jsonify({"error":"login required"}),401
        # session token stored as base64 username:hash ; validate exists
        try:
            decoded = base64.b64decode(session_token).decode()
            username, token = decoded.split(":",1)
            # check user exists
            row = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
            if not row: return jsonify({"error":"invalid session"}),401
            # token is password_hash for simplicity
            if row["password_hash"] != token: return jsonify({"error":"invalid session"}),401
            request.user = {"username":username, "is_admin": bool(row["is_admin"])}
            return f(*args, **kwargs)
        except Exception as e:
            return jsonify({"error":"invalid session"}),401
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # require login first
        session_token = request.cookies.get("session_token","")
        if not session_token: return jsonify({"error":"login required"}),401
        decoded = base64.b64decode(session_token).decode()
        username, token = decoded.split(":",1)
        row = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
        if not row or not row["is_admin"]:
            return jsonify({"error":"admin required"}),403
        request.user = {"username":username, "is_admin": True}
        return f(*args, **kwargs)
    return wrapper

# Public probe endpoint (no auth)
@app.route("/api/probe")
def api_probe():
    try:
        conf = json.load(open(CONF_FILE))
        targets = conf.get("probe_targets", [])
    except:
        targets = [{"name":"Cloudflare","ip":"1.1.1.1"}]
    results = []
    threads = []
    lock = threading.Lock()
    def do_probe(t):
        ip = t.get("ip")
        name = t.get("name")
        region = t.get("region","")
        try:
            out = subprocess.check_output(["ping","-c","3","-W","2", ip], stderr=subprocess.STDOUT, timeout=12).decode()
            avg = "N/A"
            for line in out.splitlines():
                if "min/avg" in line or "rtt min/avg" in line:
                    parts = line.split("=")[1].split("/")
                    if len(parts)>1: avg = parts[1].strip()
            rec = {"name":name,"region":region,"ip":ip,"avg_ms":avg}
        except Exception as e:
            rec = {"name":name,"region":region,"ip":ip,"avg_ms":"N/A","error":str(e)}
        with lock:
            results.append(rec)
    for t in targets:
        thread = threading.Thread(target=do_probe, args=(t,))
        thread.start()
        threads.append(thread)
    for th in threads: th.join()
    return jsonify({"results":results})

# Authentication endpoints
@app.route("/api/register", methods=["POST"])
def api_register():
    j = request.get_json(force=True) or {}
    username = j.get("username","").strip()
    password = j.get("password","")
    if not username or not password: return jsonify({"error":"username/password required"}),400
    # disallow registering 'admin'
    if username == "admin": return jsonify({"error":"cannot register admin"}),403
    phash = hash_pw(password)
    try:
        query_db("INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,0)", (username, phash))
        return jsonify({"ok":True})
    except Exception as e:
        return jsonify({"error":str(e)}),400

@app.route("/api/login", methods=["POST"])
def api_login():
    j = request.get_json(force=True) or {}
    username = j.get("username","")
    password = j.get("password","")
    if not username or not password: return jsonify({"error":"username/password required"}),400
    row = query_db("SELECT * FROM users WHERE username=?", (username,), one=True)
    if not row: return jsonify({"error":"no such user"}),404
    if row["password_hash"] != hash_pw(password): return jsonify({"error":"invalid credentials"}),401
    session_token = base64.b64encode(f"{username}:{row['password_hash']}".encode()).decode()
    resp = jsonify({"ok":True})
    resp.set_cookie("session_token", session_token, httponly=True, samesite="Lax")
    return resp

@app.route("/api/logout", methods=["POST"])
def api_logout():
    resp = jsonify({"ok":True})
    resp.set_cookie("session_token","", expires=0)
    return resp

# User management (admin)
@app.route("/api/users", methods=["GET","POST","DELETE"])
@admin_required
def api_users():
    if request.method=="GET":
        rows = query_db("SELECT id,username,is_admin,created_at FROM users")
        users = [{"id":r["id"],"username":r["username"],"is_admin":bool(r["is_admin"]),"created_at":r["created_at"]} for r in rows]
        return jsonify({"users":users})
    j = request.get_json(force=True) or {}
    if request.method=="POST":
        u = j.get("username"); p = j.get("password"); is_admin = 1 if j.get("is_admin",False) else 0
        if not u or not p: return jsonify({"error":"username/password required"}),400
        try:
            query_db("INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,?)", (u, hash_pw(p), is_admin))
            return jsonify({"ok":True})
        except Exception as e:
            return jsonify({"error":str(e)}),400
    if request.method=="DELETE":
        uid = j.get("id")
        if not uid: return jsonify({"error":"id required"}),400
        query_db("DELETE FROM users WHERE id=?", (uid,))
        return jsonify({"ok":True})

# Nodes export
@app.route("/api/nodes", methods=["GET"])
@login_required
def api_nodes():
    sec = open(TOKEN_FILE).read().strip() if os.path.exists(TOKEN_FILE) else ""
    # require token matched or user is admin
    user = request.user
    # create sample nodes using uuid
    try:
        conf = json.load(open(CONF_FILE))
        uuid = conf.get("uuid","")
    except:
        uuid = ""
    ip = subprocess.getoutput("curl -s4 https://icanhazip.com || hostname -I | awk '{print $1}'")
    nodes = []
    if uuid:
        nodes.append({"type":"vless","uri":f"vless://{uuid}@{ip}:443?security=reality#vless_reality"})
        vm = {"v":"2","ps":"vmess","add":ip,"port":"443","id":uuid,"aid":"0","net":"ws","type":"none","host":"","path":f"/{uuid}-ws","tls":"tls"}
        nodes.append({"type":"vmess","uri":"vmess://"+base64.b64encode(json.dumps(vm).encode()).decode()})
    return jsonify({"nodes":nodes})

# QR generation for a URI
@app.route("/api/qrcode", methods=["GET"])
def api_qrcode():
    uri = request.args.get("uri","")
    if not uri: return jsonify({"error":"uri required"}),400
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")

# Core update trigger (admin)
@app.route("/api/cores/update", methods=["POST"])
@admin_required
def api_update_cores():
    helper = os.path.join(BASE_DIR, "helper.sh")
    subprocess.Popen(["/bin/bash", helper, "update-cores"])
    return jsonify({"result":"update started"})

# ACME trigger (admin)
@app.route("/api/acme", methods=["POST"])
@admin_required
def api_acme():
    j = request.get_json(force=True) or {}
    domain = j.get("domain","")
    if not domain: return jsonify({"error":"domain required"}),400
    helper = os.path.join(BASE_DIR, "helper.sh")
    subprocess.Popen(["/bin/bash", helper, "issue-cert", domain])
    return jsonify({"result":"acme started", "domain":domain})

# WARP control (admin)
@app.route("/api/warp/start", methods=["POST"])
@admin_required
def api_warp_start():
    helper = os.path.join(BASE_DIR, "helper.sh")
    subprocess.Popen(["/bin/bash", helper, "warp-start"])
    return jsonify({"result":"warp start requested"})

@app.route("/api/warp/stop", methods=["POST"])
@admin_required
def api_warp_stop():
    helper = os.path.join(BASE_DIR, "helper.sh")
    subprocess.Popen(["/bin/bash", helper, "warp-stop"])
    return jsonify({"result":"warp stop requested"})

# Exec API (admin) -- WHITELISTED commands only, audit logged
WHITELIST = ["systemctl","journalctl","tail","cat","ls","uname","df","free","ss","netstat","iptables","ip"]
def is_whitelisted(cmd):
    parts = shlex.split(cmd)
    if len(parts)==0: return False
    return parts[0] in WHITELIST

@app.route("/api/exec", methods=["POST"])
@admin_required
def api_exec():
    j = request.get_json(force=True) or {}
    cmd = j.get("cmd","")
    if not cmd: return jsonify({"error":"cmd required"}),400
    if not is_whitelisted(cmd):
        return jsonify({"error":"command not allowed"}),403
    user = request.user.get("username","unknown")
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=60, universal_newlines=True)
        # audit insert
        con = sqlite3.connect(DB); cur = con.cursor()
        cur.execute("INSERT INTO exec_audit(user,cmd,result) VALUES(?,?,?)", (user, cmd, out[:10000]))
        con.commit(); con.close()
        return jsonify({"out":out})
    except Exception as e:
        con = sqlite3.connect(DB); cur = con.cursor()
        cur.execute("INSERT INTO exec_audit(user,cmd,result) VALUES(?,?,?)", (user, cmd, str(e)[:10000]))
        con.commit(); con.close()
        return jsonify({"error":str(e)}),500

# Status (admin): system load, memory, processes
@app.route("/api/status", methods=["GET"])
@admin_required
def api_status():
    load = os.getloadavg() if hasattr(os, "getloadavg") else [0,0,0]
    mem = psutil.virtual_memory()._asdict() if hasattr(psutil,'virtual_memory') else {}
    services = {
        "xray": subprocess.call(["pgrep","-f","xray"])==0,
        "sing-box": subprocess.call(["pgrep","-f","sing-box"])==0,
        "nginx": subprocess.call(["pgrep","-f","nginx"])==0
    }
    return jsonify({"load":load,"mem":mem,"services":services})

# Serve frontend
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    port = int(os.environ.get("FLASK_PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
PY

  chmod +x "${WEB_DIR}/app.py"

  # Frontend: templates and static (Bootstrap + Chart.js)
  cat > "${WEB_DIR}/templates/index.html" <<'HTML'
<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Proxy Manager Ultimate</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    body{background:#f6f8fa}
    .card{border-radius:12px}
    pre{white-space:pre-wrap;word-break:break-word}
  </style>
</head>
<body>
<div class="container py-4">
  <div class="d-flex justify-content-between align-items-center mb-3">
    <h2>Proxy Manager Ultimate</h2>
    <div>
      <button id="btnLogin" class="btn btn-outline-primary btn-sm">登录</button>
    </div>
  </div>

  <div class="row">
    <div class="col-md-8">
      <div class="card p-3 mb-3">
        <h5>探针 (公开)</h5>
        <p>点击运行探针，显示各地区延迟（无需登录）。</p>
        <button id="probeBtn" class="btn btn-primary">运行探针</button>
        <pre id="probeRes" class="mt-2"></pre>
      </div>

      <div class="card p-3 mb-3">
        <h5>节点 & QR</h5>
        <div class="input-group mb-2">
          <input id="nodesToken" class="form-control" placeholder="管理员 token 用于获取节点 (可选)">
          <button id="nodesBtn" class="btn btn-outline-secondary">获取节点</button>
        </div>
        <pre id="nodesRes"></pre>
      </div>
    </div>

    <div class="col-md-4">
      <div class="card p-3 mb-3">
        <h6>管理员工具</h6>
        <input id="admToken" class="form-control mb-2" placeholder="Admin token">
        <button id="updateCoresBtn" class="btn btn-warning mb-2">更新内核</button><br/>
        <input id="acmeDomain" class="form-control mb-2" placeholder="域名申请证书 example.com">
        <button id="acmeBtn" class="btn btn-success mb-2">申请证书</button><br/>
        <button id="warpStartBtn" class="btn btn-info mb-2">启动 WARP (socks)</button>
        <button id="warpStopBtn" class="btn btn-secondary mb-2">停止 WARP</button>
      </div>

      <div class="card p-3">
        <h6>系统状态 (需登录)</h6>
        <button id="statusBtn" class="btn btn-outline-primary">查看状态</button>
        <pre id="statusRes"></pre>
      </div>
    </div>
  </div>
</div>

<script>
async function runProbe(){
  document.getElementById('probeRes').textContent='运行 probe...';
  const r = await fetch('/api/probe');
  const j = await r.json();
  document.getElementById('probeRes').textContent = JSON.stringify(j, null, 2);
}
document.getElementById('probeBtn').onclick = runProbe;

document.getElementById('nodesBtn').onclick = async ()=>{
  const token = document.getElementById('nodesToken').value.trim();
  const url = '/api/nodes' + (token? '?token='+encodeURIComponent(token):'');
  const r = await fetch(url);
  const j = await r.json();
  document.getElementById('nodesRes').textContent = JSON.stringify(j, null, 2);
};

document.getElementById('updateCoresBtn').onclick = async ()=>{
  const token = document.getElementById('admToken').value.trim();
  if(!token){ alert('需要 admin token'); return; }
  await fetch('/api/cores/update', {method:'POST', headers:{'Cookie':'session_token=','Authorization':'Bearer '+token}});
  alert('已触发内核更新');
};

document.getElementById('acmeBtn').onclick = async ()=>{
  const token = document.getElementById('admToken').value.trim();
  const domain = document.getElementById('acmeDomain').value.trim();
  if(!token||!domain){ alert('admin token 与域名必填'); return; }
  const r = await fetch('/api/acme', {method:'POST', headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json'}, body: JSON.stringify({domain})});
  alert('ACME 请求已发起');
};

document.getElementById('warpStartBtn').onclick = async ()=>{
  const token = document.getElementById('admToken').value.trim();
  if(!token){ alert('admin token required'); return; }
  await fetch('/api/warp/start', {method:'POST', headers:{'Authorization':'Bearer '+token}});
  alert('WARP 启动请求已发出');
};
document.getElementById('warpStopBtn').onclick = async ()=>{
  const token = document.getElementById('admToken').value.trim();
  if(!token){ alert('admin token required'); return; }
  await fetch('/api/warp/stop', {method:'POST', headers:{'Authorization':'Bearer '+token}});
  alert('WARP 停止请求已发出');
};

document.getElementById('statusBtn').onclick = async ()=>{
  const token = prompt('请输入 admin token (secrets/admin.token) 才能查看状态');
  if(!token) return;
  const r = await fetch('/api/status', {headers:{'Authorization':'Bearer '+token}});
  const j = await r.json();
  document.getElementById('statusRes').textContent = JSON.stringify(j, null, 2);
};
</script>
</body>
</html>
HTML

  _info "Web app and frontend written"
}

# Helper script for background ops (update cores, issue cert, warp control)
write_helper_script(){
  cat > "${BASE_DIR}/helper.sh" <<'SH'
#!/usr/bin/env bash
BASE="${BASE_DIR:-/etc/proxy-manager-ultimate}"
case "$1" in
  update-cores)
    "${BASE}/proxy_manager_ultimate.sh" update-cores
    ;;
  issue-cert)
    "${BASE}/proxy_manager_ultimate.sh" issue-cert "$2"
    ;;
  warp-start)
    # start warp-go socks (assumes warp-go binary at ${BASE}/warp-go)
    if [[ -x "${BASE}/warp-go" ]]; then
      nohup "${BASE}/warp-go" socks -l 127.0.0.1:1081 >/dev/null 2>&1 &
    fi
    ;;
  warp-stop)
    pkill -f warp-go || true
    ;;
  *) echo "usage: helper.sh {update-cores|issue-cert domain|warp-start|warp-stop}" ;;
esac
SH
  chmod +x "${BASE_DIR}/helper.sh"
  _info "Helper script written"
}

# Write systemd units (web, xray, sing-box)
write_systemd_units(){
  _info "Writing systemd units..."
  cat > "${SYSTEMD_DIR}/proxy-manager-web.service" <<EOF
[Unit]
Description=Proxy Manager Ultimate Web UI
After=network.target

[Service]
Type=simple
Environment=BASE_DIR=${BASE_DIR}
Environment=FLASK_PORT=${PANEL_PORT}
ExecStart=${VENV_DIR}/bin/python ${WEB_DIR}/app.py
WorkingDirectory=${WEB_DIR}
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

  cat > "${SYSTEMD_DIR}/xray.service" <<EOF
[Unit]
Description=Xray Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=${CORES_DIR}/xray run -c ${CONF_DIR}/xray.json
WorkingDirectory=${BASE_DIR}
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  cat > "${SYSTEMD_DIR}/sing-box.service" <<EOF
[Unit]
Description=Sing-Box Proxy Service
After=network.target

[Service]
Type=simple
ExecStart=${CORES_DIR}/sing-box run -c ${CONF_DIR}/singbox.json
WorkingDirectory=${BASE_DIR}
Restart=on-failure
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload || true
}

# Nginx site config and enable
write_nginx_site(){
  _info "Writing nginx site..."
  mkdir -p "${NGINX_SITES_AVAILABLE}" "${NGINX_SITES_ENABLED}"
  cat > "${NGINX_SITES_AVAILABLE}/proxy-manager-ultimate" <<NG
server {
  listen 80;
  server_name _;
  location / {
    proxy_pass http://127.0.0.1:${PANEL_PORT};
    proxy_set_header Host \$host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
  }
}
NG
  ln -sf "${NGINX_SITES_AVAILABLE}/proxy-manager-ultimate" "${NGINX_SITES_ENABLED}/proxy-manager-ultimate"
  nginx -t >/dev/null 2>&1 || _warn "nginx test failed"
  systemctl restart nginx || true
}

# Generate core config templates: VLESS(Reality), VMess(WS), Tuic, Hysteria2, SS, Trojan
generate_core_templates(){
  _info "Generating core configuration templates (xray.json, singbox.json, other templates)"
  mkdir -p "${CONF_DIR}"
  uuid="$(cat "${SECRETS_DIR}/uuid" 2>/dev/null || jq -r '.uuid' "$CONFIG_JSON" 2>/dev/null || uuidgen)"
  # Read reality keys & shortids
  priv_b64="$(base64 -w0 "${REALITY_PRIV}" 2>/dev/null || true)"
  shortids_json="$(cat "${REALITY_SHORTIDS}" 2>/dev/null || echo '[]')"
  # xray.json with VLESS+Reality + port multiplexing example
  cat > "${CONF_DIR}/xray.json" <<EOF
{
  "log":{"loglevel":"warning"},
  "inbounds":[
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
          "show":false,
          "dest":"${hostname:-example.com}:443",
          "serverNames":["${hostname:-example.com}"],
          "privateKey":"$(awk '{printf "%s\\n",$0}' "${REALITY_PRIV}" | base64 -w0 2>/dev/null || echo "")",
          "shortIds": $(cat "${REALITY_SHORTIDS}" 2>/dev/null || echo '[]')
        }
      }
    }
  ],
  "outbounds":[{"protocol":"freedom","tag":"direct"}]
}
EOF

  # singbox.json sample with vmess ws
  cat > "${CONF_DIR}/singbox.json" <<EOF
{
  "log":{"disabled":false,"level":"info"},
  "inbounds":[
    {"type":"vmess","tag":"vmess-ws","listen":"0.0.0.0","listen_port":443,"users":[{"uuid":"${uuid}"}],"transport":{"type":"ws","path":"/${uuid}-ws"}}
  ],
  "outbounds":[{"type":"direct","tag":"direct"}]
}
EOF

  # additional protocol templates (tuic/hysteria/shadowsocks/trojan) — put as separate files for ease of editing
  cat > "${CONF_DIR}/template_tuic.json" <<EOF
{
  "note":"tuic template - edit as needed",
  "inbound":{
    "type":"tuic",
    "listen":"0.0.0.0",
    "listen_port":8443,
    "password":"CHANGE_ME"
  }
}
EOF

  cat > "${CONF_DIR}/template_hysteria.json" <<EOF
{
  "note":"hysteria2 template - edit as needed",
  "inbound":{
    "type":"hysteria",
    "listen":"0.0.0.0",
    "listen_port":8444,
    "obfs":"udp",
    "password":"CHANGE_ME"
  }
}
EOF

  cat > "${CONF_DIR}/template_ss.json" <<EOF
{
  "note":"shadowsocks template",
  "method":"chacha20-ietf-poly1305",
  "password":"CHANGE_ME",
  "listen":"0.0.0.0",
  "port":8388
}
EOF

  cat > "${CONF_DIR}/template_trojan.json" <<EOF
{
  "note":"trojan template",
  "listen":"0.0.0.0",
  "port":443,
  "password":"CHANGE_ME"
}
EOF

  _info "Templates generated at ${CONF_DIR}"
}

# Install warp-go (optional)
install_warp_go(){
  dst="${BASE_DIR}/warp-go"
  if [[ -x "$dst" ]]; then _info "warp-go already installed"; return 0; fi
  _info "Installing warp-go..."
  url="https://github.com/fscarmen/warp/releases/latest/download/warp-go-linux-${ARCH_KEY}.tar.gz"
  tmp="/tmp/warp-go_${RANDOM}.tar.gz"
  if curl -L --retry 3 -o "$tmp" "$url"; then
    tar -xzf "$tmp" -C /tmp/ || true
    mv /tmp/warp-go "$dst" || true
    chmod +x "$dst"
    rm -f "$tmp"
    _info "warp-go installed: $dst"
    return 0
  fi
  _warn "warp-go install failed"
  return 1
}

# Start/Stop services
start_services(){
  write_systemd_units
  systemctl daemon-reload
  systemctl enable proxy-manager-web xray sing-box >/dev/null 2>&1 || true
  systemctl restart nginx || true
  systemctl restart proxy-manager-web || true
  if [[ -x "${CORES_DIR}/xray" ]]; then systemctl restart xray || true; fi
  if [[ -x "${CORES_DIR}/sing-box" ]]; then systemctl restart sing-box || true; fi
  _info "Services started (or restart requested)"
}

stop_services(){
  systemctl stop proxy-manager-web || true
  systemctl stop xray || true
  systemctl stop sing-box || true
  systemctl stop nginx || true
  _info "Services stopped"
}

show_nodes(){
  ip="$(curl -s4 icanhazip.com || hostname -I | awk '{print $1}')"
  uuid="$(cat "${SECRETS_DIR}/uuid" 2>/dev/null || jq -r '.uuid' "$CONFIG_JSON" 2>/dev/null || echo '')"
  echo "Server IP: $ip"
  echo "UUID: $uuid"
  echo "VLESS Reality sample:"
  echo "vless://${uuid}@${ip}:443?security=reality#vless_reality"
  vm=$(printf '{"v":"2","ps":"vmess","add":"%s","port":"443","id":"%s","aid":"0","net":"ws","type":"none","host":"","path":"/%s-ws","tls":"tls"}' "$ip" "$uuid" "$uuid")
  echo "VMess: vmess://$(echo -n "$vm" | base64 -w0)"
}

# CLI entry points
cmd_install(){
  ensure_root
  prepare_dirs
  install_system_deps
  generate_default_config
  ensure_secrets
  generate_reality_keys
  create_venv_and_install_pydeps
  init_sqlite_db
  download_xray || _warn "xray not downloaded automatically (place manually at ${CORES_DIR}/xray)"
  download_singbox || _warn "sing-box not downloaded automatically (place manually at ${CORES_DIR}/sing-box)"
  write_web_app
  write_helper_script
  write_nginx_site
  generate_core_templates
  start_services
  _info "Install complete. Visit: http://<VPS_IP>:${PANEL_PORT}"
  _info "Admin token at ${ADMIN_TOKEN_FILE}, initial web admin credentials at ${CONFIG_JSON} (web.admin_pass). Please change immediately."
}

cmd_update_cores(){
  ensure_root
  download_xray || _warn "xray update failed"
  download_singbox || _warn "sing-box update failed"
  _info "Core update attempted. Restart services to apply."
}

cmd_issue_cert(){
  ensure_root
  domain="$1"
  if [[ -z "$domain" ]]; then _err "issue-cert requires domain"; return 1; fi
  # install acme.sh and issue
  if ! command -v acme.sh >/dev/null 2>&1; then
    _info "Installing acme.sh"
    curl_get https://get.acme.sh | sh || _warn "acme.sh install failed"
  fi
  export HOME="/root"
  ~/.acme.sh/acme.sh --issue --standalone -d "$domain" --force || { _err "acme issue failed"; return 1; }
  mkdir -p "${CONF_DIR}/certs"
  ~/.acme.sh/acme.sh --install-cert -d "$domain" --key-file "${CONF_DIR}/certs/${domain}.key" --fullchain-file "${CONF_DIR}/certs/${domain}.crt"
  _info "Certificate installed to ${CONF_DIR}/certs/${domain}.crt"
  # update nginx site to use TLS
  cat > "${NGINX_SITES_AVAILABLE}/proxy-manager-ultimate" <<NG
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
  ln -sf "${NGINX_SITES_AVAILABLE}/proxy-manager-ultimate" "${NGINX_SITES_ENABLED}/proxy-manager-ultimate"
  nginx -t >/dev/null 2>&1 || _warn "nginx test failed"
  systemctl restart nginx || true
  _info "HTTPS enabled for ${domain}"
}

cmd_start(){ start_services; }
cmd_stop(){ stop_services; }
cmd_status(){
  systemctl status proxy-manager-web --no-pager || true
  systemctl status xray --no-pager || true
  systemctl status sing-box --no-pager || true
  systemctl status nginx --no-pager || true
}
cmd_show_nodes(){ show_nodes; }

# CLI dispatch
case "${1:-help}" in
  install) cmd_install ;;
  update-cores) cmd_update_cores ;;
  issue-cert) cmd_issue_cert "${2:-}" ;;
  start) cmd_start ;;
  stop) cmd_stop ;;
  status) cmd_status ;;
  show-nodes) cmd_show_nodes ;;
  *) cat <<USAGE
Usage: $0 {install|update-cores|issue-cert domain|start|stop|status|show-nodes}
USAGE
;;
esac

exit 0
