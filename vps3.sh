#!/usr/bin/env bash
# vps3_final.sh - 最终整合版（单文件）
# 功能：安装/更新 xray / sing-box / nginx / Flask 面板，包含交互式菜单、分流模板、证书（自签/ACME）、systemd、导出/卸载等。
# 使用：作为 root 运行；示例：bash /root/vps3_final.sh install
set -euo pipefail
IFS=$'\n\t'
export LANG=en_US.UTF-8

# ---------- 配置区（可用环境变量覆盖） ----------
BASE="/etc/proxy-manager-ultimate"
CONF="${BASE}/conf"
WEB="${BASE}/web"
BIN_DIR="${BASE}/bin"
PANEL_PORT="${PANEL_PORT:-8080}"
XRAY_BIN="${BIN_DIR}/xray"
SINGBOX_BIN="${BIN_DIR}/sing-box"
NGINX_SITE="/etc/nginx/sites-available/proxy-manager-ultimate"
SYSTEMD_DIR="/etc/systemd/system"
ACME_HOME="${HOME}/.acme.sh"
ADMIN_PASSWORD_FILE="${CONF}/admin_pass.txt"
ADMIN_TOKEN_FILE="${CONF}/admin.token"
DOMAIN="${DOMAIN:-}"                    # 若需 ACME，请 export DOMAIN=your.domain
KEEP_EXISTING_CORES="${KEEP_EXISTING_CORES:-false}"

# ---------- 颜色输出 ----------
_red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
_green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
_yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }
_blue(){ echo -e "\033[36m\033[01m$1\033[0m"; }
log(){ _green "[INFO] $1"; }
warn(){ _yellow "[WARN] $1"; }
err(){ _red "[ERROR] $1"; }

require_root(){ if [[ $EUID -ne 0 ]]; then err "请以 root 用户运行脚本"; exit 1; fi }

safe_mkdir(){ for d in "$@"; do mkdir -p "$d"; done }

# ---------- 架构识别 ----------
arch_map(){
  local a
  a=$(uname -m)
  case "$a" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    armv7l) echo armv7 ;;
    i386|i686) echo 386 ;;
    *) echo "$a" ;;
  esac
}

# ---------- 安装系统依赖 ----------
install_deps(){
  log "安装系统依赖（curl wget jq unzip tar socat nginx python3-venv python3-pip openssl git）"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y curl wget jq unzip tar socat nginx python3-venv python3-pip openssl iproute2 net-tools git
  elif command -v yum >/dev/null 2>&1; then
    yum install -y epel-release
    yum install -y curl wget jq unzip tar socat nginx python3 python3-venv python3-pip openssl iproute git
  else
    warn "未识别包管理器，请手动安装依赖"
  fi
}

# ---------- 下载 xray / sing-box ----------
download_xray(){
  local cpu tmp url
  cpu=$(arch_map)
  safe_mkdir "${BIN_DIR}"
  if [[ -x "${XRAY_BIN}" && "${KEEP_EXISTING_CORES}" == "true" ]]; then
    log "保留现有 xray（KEEP_EXISTING_CORES=true）"
    return 0
  fi
  log "下载 xray（arch=${cpu}）..."
  tmp="/tmp/xray-${cpu}.zip"
  url="https://github.com/XTLS/Xray-core/releases/latest/download/xray-linux-${cpu}.zip"
  if curl -fsSL -o "$tmp" "$url"; then
    mkdir -p /tmp/xray_unpack
    unzip -o "$tmp" -d /tmp/xray_unpack >/dev/null 2>&1 || true
    if [[ -f /tmp/xray_unpack/xray ]]; then
      mv /tmp/xray_unpack/xray "${XRAY_BIN}"
      chmod +x "${XRAY_BIN}"
      log "xray 已安装到 ${XRAY_BIN}"
    else
      warn "xray 可执行文件未找到，可能 release 结构变化"
    fi
    rm -rf /tmp/xray_unpack "$tmp"
  else
    warn "下载 xray 失败（网络或 GitHub 限制）"
  fi
}

download_singbox(){
  local cpu api rel ver name url tmp candidate
  cpu=$(arch_map)
  if [[ -x "${SINGBOX_BIN}" && "${KEEP_EXISTING_CORES}" == "true" ]]; then
    log "保留现有 sing-box（KEEP_EXISTING_CORES=true）"
    return 0
  fi
  log "下载 sing-box（arch=${cpu}）..."
  api="https://api.github.com/repos/SagerNet/sing-box/releases/latest"
  rel=$(curl -fsSL "$api" 2>/dev/null || true)
  ver=$(echo "$rel" | jq -r .tag_name 2>/dev/null || true)
  if [[ -z "$ver" || "$ver" == "null" ]]; then warn "无法获取 sing-box 版本"; return 0; fi
  ver=${ver#v}
  name="sing-box-v${ver}-linux-${cpu}.tar.gz"
  url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/${name}"
  tmp="/tmp/${name}"
  if curl -fsSL -o "$tmp" "$url"; then
    mkdir -p /tmp/singbox_unpack
    tar -xzf "$tmp" -C /tmp/singbox_unpack || true
    candidate=$(find /tmp/singbox_unpack -type f -name sing-box -print -quit 2>/dev/null || true)
    if [[ -n "$candidate" ]]; then
      mv "$candidate" "${SINGBOX_BIN}"
      chmod +x "${SINGBOX_BIN}"
      log "sing-box 已安装到 ${SINGBOX_BIN}"
    else
      warn "sing-box 可执行文件未找到"
    fi
    rm -rf /tmp/singbox_unpack "$tmp"
  else
    warn "下载 sing-box 失败"
  fi
}

# ---------- 随机密码生成 ----------
rand_pass(){ head -c32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c16 || true }

# ---------- 写 nginx site（template） ----------
write_nginx_template(){
  safe_mkdir "$(dirname "${NGINX_SITE}")"
  cat > "${NGINX_SITE}" <<'NGINX_EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name __DOMAIN__;
    location /.well-known/acme-challenge/ { root __ACME_ROOT__; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name __DOMAIN__;
    ssl_certificate __CRT__;
    ssl_certificate_key __KEY__;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:__PANEL_PORT__;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX_EOF
  sed -i "s|__PANEL_PORT__|${PANEL_PORT}|g" "${NGINX_SITE}"
}

# ---------- systemd 单元 ----------
write_systemd_units(){
  log "写入 systemd 单元"
  safe_mkdir "${SYSTEMD_DIR}"
  cat > "${SYSTEMD_DIR}/proxy-manager-web.service" <<EOF
[Unit]
Description=Proxy Manager Minimal Web UI
After=network.target

[Service]
Type=simple
Environment=BASE_DIR=${BASE}
Environment=FLASK_PORT=${PANEL_PORT}
ExecStart=${BASE}/venv/bin/python ${WEB}/app.py
WorkingDirectory=${WEB}
Restart=on-failure
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF

  if [[ -x "${XRAY_BIN}" ]]; then
    cat > "${SYSTEMD_DIR}/xray-proxy.service" <<EOF
[Unit]
Description=Xray Service
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

  if [[ -x "${SINGBOX_BIN}" ]]; then
    cat > "${SYSTEMD_DIR}/singbox-proxy.service" <<EOF
[Unit]
Description=sing-box Service
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
  [[ -f "${SYSTEMD_DIR}/xray-proxy.service" ]] && systemctl enable xray-proxy.service || true
  [[ -f "${SYSTEMD_DIR}/singbox-proxy.service" ]] && systemctl enable singbox-proxy.service || true
}

# ---------- 写默认配置模板（xray / singbox / nginx） ----------
write_default_templates(){
  log "写入默认配置模板到 ${CONF}"
  safe_mkdir "${CONF}/xray" "${CONF}/singbox" "${CONF}/certs" "/var/log/xray" "/var/log/singbox"

  # xray 示例配置（含占位 UUID）
  cat > "${CONF}/xray/xray.json" <<'XRAY_JSON'
{
  "log": {"access":"/var/log/xray/access.log","error":"/var/log/xray/error.log","loglevel":"warning"},
  "inbounds":[
    {
      "port":4430,
      "protocol":"vless",
      "settings":{"clients":[{"id":"__UUID__","flow":"xtls-rprx-vision"}]},
      "streamSettings":{"network":"tcp","security":"tls"}
    }
  ],
  "outbounds":[{"protocol":"freedom","settings":{}}]
}
XRAY_JSON

  # sing-box 示例配置
  cat > "${CONF}/singbox/singbox.json" <<'SBOX_JSON'
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "type": "trojan",
      "tag": "trojan-in",
      "listen": "0.0.0.0",
      "port": 8443,
      "sniff": false,
      "users": [
        {"name": "user1", "password": "pass1"}
      ]
    }
  ],
  "outbounds": [
    {"type":"direct"}
  ]
}
SBOX_JSON

  write_nginx_template
}

# ---------- 生成自签证书 ----------
generate_self_signed(){
  local certdir="${CONF}/certs"
  safe_mkdir "${certdir}"
  if [[ ! -f "${certdir}/self.crt" || ! -f "${certdir}/self.key" ]]; then
    log "生成自签证书"
    openssl ecparam -genkey -name prime256v1 -out "${certdir}/self.key"
    openssl req -new -x509 -days 36500 -key "${certdir}/self.key" -out "${certdir}/self.crt" -subj "/CN=proxy-manager-ultimate"
  fi
}

# ---------- acme.sh 安装与申请 ----------
install_acme_sh(){
  if [[ ! -d "${ACME_HOME}" ]]; then
    curl -sS https://get.acme.sh | bash || warn "acme.sh 安装失败"
  fi
}

issue_acme_cert(){
  if [[ -z "${DOMAIN}" ]]; then warn "DOMAIN 未设置，跳过 ACME"; return 0; fi
  install_acme_sh
  log "为 ${DOMAIN} 申请 ACME 证书（standalone）——确保 80 端口可访问"
  ~/.acme.sh/acme.sh --issue --standalone -d "${DOMAIN}" || { warn "ACME issue 失败"; return 1; }
  mkdir -p "${CONF}/certs"
  ~/.acme.sh/acme.sh --install-cert -d "${DOMAIN}" --key-file "${CONF}/certs/${DOMAIN}.key" --fullchain-file "${CONF}/certs/${DOMAIN}.crt" || warn "证书安装失败"
  # 替换 nginx 模板占位
  sed -i "s|__DOMAIN__|${DOMAIN}|g" "${NGINX_SITE}"
  sed -i "s|__ACME_ROOT__|${ACME_HOME}/${DOMAIN}|g" "${NGINX_SITE}"
  sed -i "s|__CRT__|${CONF}/certs/${DOMAIN}.crt|g" "${NGINX_SITE}"
  sed -i "s|__KEY__|${CONF}/certs/${DOMAIN}.key|g" "${NGINX_SITE}"
  nginx -t >/dev/null 2>&1 || warn "nginx 配置测试失败"
  systemctl restart nginx || warn "nginx 重启失败"
}

# ---------- 写 Web 面板（Flask + 静态） ----------
write_web_panel(){
  log "写入 Web 面板到 ${WEB}"
  safe_mkdir "${WEB}/static" "${WEB}/templates"
  cat > "${WEB}/app.py" <<'FLASK_APP'
from flask import Flask, jsonify, send_from_directory, request
import os, subprocess, json
app = Flask(__name__, static_folder='static', template_folder='templates')
BASE = os.environ.get('BASE_DIR','/etc/proxy-manager-ultimate')

@app.route('/')
def index():
    return send_from_directory('static','index.html')

@app.route('/api/status')
def status():
    def run(cmd):
        try:
            return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode()
        except:
            return ''
    s = {
        'xray': run('pgrep -af xray || true'),
        'singbox': run('pgrep -af sing-box || true'),
        'nginx': run('systemctl is-active nginx || true')
    }
    return jsonify(s)

@app.route('/api/reload', methods=['POST'])
def reload_services():
    os.system('systemctl restart nginx || true')
    os.system('systemctl restart proxy-manager-web || true')
    return jsonify({'ok': True})

if __name__ == '__main__':
    port = int(os.environ.get('FLASK_PORT', 8080))
    app.run(host='0.0.0.0', port=port)
FLASK_APP

  cat > "${WEB}/static/index.html" <<'HTML_PAGE'
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Proxy Manager Ultimate</title>
  <link rel="stylesheet" href="/static/style.css">
</head>
<body>
  <div id="app">
    <h1>Proxy Manager Ultimate</h1>
    <div id="controls">
      <button id="btn">刷新状态</button>
      <button id="reload">重启服务</button>
    </div>
    <pre id="out"></pre>
  </div>
  <script src="/static/app.js"></script>
</body>
</html>
HTML_PAGE

  cat > "${WEB}/static/app.js" <<'JS_PAGE'
async function fetchStatus(){
  const out = document.getElementById('out');
  out.textContent = '加载中...';
  try{
    const r = await fetch('/api/status');
    const j = await r.json();
    out.textContent = JSON.stringify(j, null, 2);
  }catch(e){ out.textContent = '请求失败: '+e }
}
window.addEventListener('load', ()=>{
  document.getElementById('btn').addEventListener('click', fetchStatus);
  document.getElementById('reload').addEventListener('click', async ()=>{
    const r = await fetch('/api/reload', {method:'POST'});
    const j = await r.json();
    alert('重启指令已发送: ' + (j.ok ? 'ok' : JSON.stringify(j)));
  });
  fetchStatus();
});
JS_PAGE

  cat > "${WEB}/static/style.css" <<'CSS_PAGE'
body{ font-family: Arial, Helvetica, sans-serif; background:#f7f7f9; color:#1a1a1a; padding:20px }
#app{ max-width:900px; margin:20px auto; background:white; padding:20px; border-radius:8px; box-shadow:0 6px 18px rgba(0,0,0,0.06) }
pre{ background:#0b1220; color:#0f0; padding:12px; border-radius:6px; overflow:auto; max-height:400px }
button{ margin-right:8px; padding:8px 12px; border-radius:6px; border:1px solid #ddd; background:#fff }
CSS_PAGE

  # venv & dependencies
  python3 -m venv "${BASE}/venv" || true
  "${BASE}/venv/bin/pip" install --upgrade pip flask >/dev/null 2>&1 || true
  chmod +x "${WEB}/app.py"
  log "Web 面板写入完成"
}

# ---------- 导入你上传的代码（如果 /mnt/data/代码.txt 存在） ----------
import_uploaded_code(){
  if [[ -f "/mnt/data/代码.txt" ]]; then
    safe_mkdir "${CONF}/original_upload"
    cp -f /mnt/data/代码.txt "${CONF}/original_upload/代码.txt"
    log "检测到 /mnt/data/代码.txt，已复制到 ${CONF}/original_upload/代码.txt"
  else
    log "未检测到 /mnt/data/代码.txt，跳过导入"
  fi
}

# ---------- 交互式节点/分流生成（示例实现） ----------
generate_node_interactive(){
  echo "生成节点（示例） — 支持 vless/vmess/trojan"
  read -p "节点类型 (vless/vmess/trojan) : " ntype
  read -p "监听端口 (默认 4430) : " nport
  nport=${nport:-4430}
  if [[ "$ntype" == "vless" ]]; then
    uuid=$(cat /proc/sys/kernel/random/uuid)
    out="${CONF}/xray/generated_vless_$(date +%s).json"
    sed "s/__UUID__/${uuid}/g" "${CONF}/xray/xray.json" > "$out"
    log "已生成 VLESS 配置：UUID=${uuid} -> ${out}"
  elif [[ "$ntype" == "vmess" ]]; then
    id=$(cat /proc/sys/kernel/random/uuid)
    out="${CONF}/xray/generated_vmess_$(date +%s).json"
    cat > "$out" <<VMESS_JSON
{
  "inbounds":[{"port":${nport},"protocol":"vmess","settings":{"clients":[{"id":"${id}","alterId":0}]}}],
  "outbounds":[{"protocol":"freedom"}]
}
VMESS_JSON
    log "已生成 VMESS 配置 id=${id} -> ${out}"
  elif [[ "$ntype" == "trojan" ]]; then
    secret=$(rand_pass)
    out="${CONF}/singbox/generated_trojan_$(date +%s).json"
    cat > "$out" <<TROJAN_JSON
{
  "inbounds":[{"type":"trojan","tag":"trojan-auto","listen":"0.0.0.0","port":${nport},"users":[{"name":"auto","password":"${secret}"}]}],
  "outbounds":[{"type":"direct"}]
}
TROJAN_JSON
    log "已生成 Trojan 配置 password=${secret} -> ${out}"
  else
    warn "未知类型：$ntype"
  fi
}

# ---------- 导出配置 / 打包 ----------
export_templates(){
  outdir="/root/pmu_export_$(date +%Y%m%d%H%M%S)"
  mkdir -p "$outdir"
  cp -r "${CONF}" "$outdir/" || true
  cp -r "${WEB}" "$outdir/" || true
  tar -czf "${outdir}.tar.gz" -C "$(dirname "$outdir")" "$(basename "$outdir")"
  log "导出完成：${outdir}.tar.gz"
}

# ---------- 卸载（慎用） ----------
uninstall_confirm(){
  read -p "确定删除 ${BASE} 并移除 systemd 单元？(yes/NO): " ans
  if [[ "$ans" == "yes" ]]; then
    systemctl stop proxy-manager-web || true
    systemctl disable proxy-manager-web || true
    rm -rf "${BASE}"
    rm -f "${SYSTEMD_DIR}/proxy-manager-web.service" "${SYSTEMD_DIR}/xray-proxy.service" "${SYSTEMD_DIR}/singbox-proxy.service"
    systemctl daemon-reload || true
    log "卸载完成"
  else
    warn "取消卸载"
  fi
}

# ---------- 状态检查 ----------
cmd_status(){
  echo "---- service status ----"
  systemctl status proxy-manager-web --no-pager || true
  [[ -f "${SYSTEMD_DIR}/xray-proxy.service" ]] && systemctl status xray-proxy --no-pager || true
  [[ -f "${SYSTEMD_DIR}/singbox-proxy.service" ]] && systemctl status singbox-proxy --no-pager || true
  systemctl status nginx --no-pager || true
}

# ---------- 交互菜单 ----------
menu(){
  cat <<MEN
Proxy Manager Ultimate - 菜单
1) 安装（依赖 + 内核 + web + nginx）
2) 更新内核（xray / sing-box）
3) 申请/更新 ACME 证书（需设置 DOMAIN 环境变量或在提示中输入）
4) 启动服务
5) 停止服务
6) 查看状态
7) 导出配置
8) 生成节点 / 分流（交互）
9) 卸载（危险）
0) 退出
请选择:
MEN
}

interactive_flow(){
  while true; do
    menu
    read -r opt
    case "$opt" in
      1) cmd_install ;;
      2) download_xray; download_singbox ;;
      3) read -p "输入 DOMAIN (空则取消): " DOMAIN; if [[ -n "$DOMAIN" ]]; then issue_acme_cert; fi ;;
      4) systemctl start proxy-manager-web || true; [[ -f "${SYSTEMD_DIR}/xray-proxy.service" ]] && systemctl start xray-proxy || true; [[ -f "${SYSTEMD_DIR}/singbox-proxy.service" ]] && systemctl start singbox-proxy || true; systemctl restart nginx || true ;;
      5) systemctl stop proxy-manager-web || true; systemctl stop xray-proxy || true; systemctl stop singbox-proxy || true; systemctl stop nginx || true ;;
      6) cmd_status ;;
      7) export_templates ;;
      8) generate_node_interactive ;;
      9) uninstall_confirm ;;
      0) break ;;
      *) warn "无效选项" ;;
    esac
  done
}

# ---------- 安装入口 ----------
cmd_install(){
  require_root
  safe_mkdir "${BASE}" "${CONF}" "${WEB}" "${BIN_DIR}"
  install_deps
  download_xray
  download_singbox
  write_default_templates
  generate_self_signed
  write_web_panel
  write_systemd_units
  import_uploaded_code
  # admin password
  if [[ ! -f "${ADMIN_PASSWORD_FILE}" ]]; then
    echo "$(rand_pass)" > "${ADMIN_PASSWORD_FILE}"
    chmod 600 "${ADMIN_PASSWORD_FILE}"
    log "Admin password 写入 ${ADMIN_PASSWORD_FILE}"
  else
    log "Admin password 已存在于 ${ADMIN_PASSWORD_FILE}"
  fi
  # nginx 启动与替换证书占位（若 DOMAIN 已有证书）
  if [[ -n "${DOMAIN}" && -f "${CONF}/certs/${DOMAIN}.crt" ]]; then
    sed -i "s|__DOMAIN__|${DOMAIN}|g" "${NGINX_SITE}"
    sed -i "s|__ACME_ROOT__|${ACME_HOME}/${DOMAIN}|g" "${NGINX_SITE}"
    sed -i "s|__CRT__|${CONF}/certs/${DOMAIN}.crt|g" "${NGINX_SITE}"
    sed -i "s|__KEY__|${CONF}/certs/${DOMAIN}.key|g" "${NGINX_SITE}"
  else
    sed -i "s|__DOMAIN__|_default_|g" "${NGINX_SITE}"
    sed -i "s|__ACME_ROOT__||g" "${NGINX_SITE}"
    sed -i "s|__CRT__|${CONF}/certs/self.crt|g" "${NGINX_SITE}"
    sed -i "s|__KEY__|${CONF}/certs/self.key|g" "${NGINX_SITE}"
  fi
  nginx -t >/dev/null 2>&1 || warn "nginx 配置测试失败"
  systemctl restart nginx || warn "nginx 重启失败"
  systemctl restart proxy-manager-web || true
  log "安装完成。面板访问（若使用直接 Flask）：http://<vps_ip>:${PANEL_PORT}；若使用 nginx：访问 80/443（视证书而定）"
  log "Admin password 文件：${ADMIN_PASSWORD_FILE}"
}

# ---------- CLI 支持 ----------
case "${1:-}" in
  install) cmd_install ;;
  menu) interactive_flow ;;
  update-cores) download_xray; download_singbox ;;
  issue-cert) DOMAIN="${2:-$DOMAIN}"; issue_acme_cert ;;
  start) systemctl start proxy-manager-web || true; [[ -f "${SYSTEMD_DIR}/xray-proxy.service" ]] && systemctl start xray-proxy || true; [[ -f "${SYSTEMD_DIR}/singbox-proxy.service" ]] && systemctl start singbox-proxy || true; systemctl restart nginx || true ;;
  stop) systemctl stop proxy-manager-web || true; systemctl stop xray-proxy || true; systemctl stop singbox-proxy || true; systemctl stop nginx || true ;;
  status) cmd_status ;;
  export) export_templates ;;
  uninstall) uninstall_confirm ;;
  *) cat <<USAGE
Usage: $0 {install|menu|update-cores|issue-cert [domain]|start|stop|status|export|uninstall}
Examples:
  $0 install
  DOMAIN=example.com $0 install
  $0 menu
USAGE
;;
esac

exit 0
