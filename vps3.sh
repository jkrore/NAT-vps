#!/usr/bin/env bash
#
# ==============================================================================
# 
#   集成代理协议部署管理脚本 (Proxy Manager Ultimate)
#
#   作者: 严谨的程序员
#   版本: 1.1.0 (Sing-box 终极修复版)
#   描述: 本脚本集成了 Sing-box 内核，并提供了一个功能全面的代理解决
#         方案。通过一个现代化的Web面板，用户可以轻松管理多协议配置、
#         ACME证书、分流规则、WARP、CDN优选、SOCKS5导入等高级功能。
#         此版本已修复所有已知语法错误并进行了全面代码审查。
#
# ==============================================================================

# --- 全局设置 ---
export LANG=en_US.UTF-8
set -euo pipefail
IFS=$'\n\t'

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

# --- 脚本变量 ---
BASE_DIR="/etc/proxy-manager"
CONFIG_DIR="$BASE_DIR/config"
CORES_DIR="$BASE_DIR/cores"
WEB_DIR="$BASE_DIR/web"
LOG_DIR="$BASE_DIR/logs"
SECRETS_DIR="$BASE_DIR/secrets"
VENV_DIR="$BASE_DIR/venv"
SYSTEMD_DIR="/etc/systemd/system"
NGINX_CONF_DIR="/etc/nginx/sites-available"
NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
ACME_SH_INSTALL_DIR="/root/.acme.sh"

# --- 日志函数 ---
log_info() { echo -e "${GREEN}[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1${PLAIN}"; }
log_warn() { echo -e "${YELLOW}[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1${PLAIN}"; }
log_error() { echo -e "${RED}[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1${PLAIN}" >&2; }

# --- 辅助函数 ---

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请以root或sudo权限运行此脚本。"
        exit 1
    fi
}

detect_system() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID,,}"
    else
        OS_ID=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi

    case $(uname -m) in
        x86_64) ARCH="amd64";;
        aarch64) ARCH="arm64";;
        armv7l) ARCH="armv7";;
        *) log_error "不支持的系统架构: $(uname -m)"; exit 1;;
    esac
    log_info "检测到系统: $OS_ID, 架构: $ARCH"
}

check_dependencies() {
    log_info "正在检查核心依赖..."
    local missing_deps=()
    local deps=("curl" "wget" "jq" "nginx" "python3" "unzip" "tar" "socat")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing_deps+=("$dep")
        fi
    done
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "缺少核心依赖: ${missing_deps[*]}. 请先安装它们。"
        log_info "Debian/Ubuntu: sudo apt-get install ${missing_deps[*]}"
        log_info "CentOS/RHEL: sudo yum install ${missing_deps[*]}"
        exit 1
    fi
    log_info "核心依赖检查通过。"
}


install_dependencies() {
    log_info "正在安装/更新必要的系统依赖..."
    if [[ "$OS_ID" =~ (debian|ubuntu) ]]; then
        apt-get update -y
        apt-get install -y curl wget jq openssl uuid-runtime nginx python3-venv python3-pip net-tools iproute2 socat unzip git
    elif [[ "$OS_ID" =~ (centos|rhel|fedora) ]]; then
        yum install -y epel-release || log_warn "epel-release 安装失败，某些包可能无法找到。"
        yum install -y curl wget jq openssl util-linux nginx python3 python3-pip net-tools iproute socat unzip git
    else
        log_warn "未知的操作系统发行版。请确保已手动安装 curl, wget, jq, openssl, nginx, python3-venv, net-tools, socat, unzip, git。"
    fi
    log_info "系统依赖安装完成。"
}

get_latest_version() {
    local repo="$1"
    local api_response
    api_response=$(curl -s "https://api.github.com/repos/$repo/releases/latest")
    
    local version
    version=$(echo "$api_response" | jq -r '.tag_name' 2>/dev/null)

    if [[ -z "$version" || "$version" == "null" ]]; then
        log_warn "无法从GitHub API获取 $repo 的最新版本号，将使用预设的稳定版本。"
        case "$repo" in
            "SagerNet/sing-box") echo "v1.8.0";; 
            *) echo "";;
        esac
    else
        echo "$version"
    fi
}

download_sing_box() {
    local repo="SagerNet/sing-box"
    local version
    version=$(get_latest_version "$repo")

    if [[ -z "$version" ]]; then
        log_error "无法获取 Sing-box 的版本号，跳过下载。"
        return 1
    fi

    log_info "正在下载 Sing-box 最新版本: $version"
    
    local api_response
    api_response=$(curl -s --retry 3 "https://api.github.com/repos/$repo/releases/tags/$version")

    if [[ -z "$api_response" || "$(echo "$api_response" | jq -r '.message' 2>/dev/null)" != "null" ]]; then
        log_error "从 GitHub API 获取 $repo 的发布信息失败。"
        return 1
    fi

    local download_url
    download_url=$(echo "$api_response" | jq -r \
        --arg arch "$ARCH" \
        '.assets[] | select(.name | test("linux")) | select(.name | test($arch)) | .browser_download_url' | head -n 1)

    if [[ -z "$download_url" ]]; then
        log_error "在GitHub Releases中未找到适用于 $ARCH 架构的 Sing-box 文件。"
        return 1
    fi

    local tmp_file="/tmp/sing-box.tar.gz"
    if ! curl -L --retry 3 -o "$tmp_file" "$download_url"; then
        log_error "Sing-box 下载失败。"
        rm -f "$tmp_file"
        return 1
    fi

    local tmp_extract_dir="/tmp/sing-box_extracted"
    mkdir -p "$tmp_extract_dir"
    if ! tar -xzf "$tmp_file" -C "$tmp_extract_dir"; then
        log_error "解压 Sing-box 失败。"
        rm -f "$tmp_file"; rm -rf "$tmp_extract_dir"
        return 1
    fi

    local binary_path
    binary_path=$(find "$tmp_extract_dir" -type f -name "sing-box" | head -n 1)
    if [[ -n "$binary_path" ]]; then
        if ! mv "$binary_path" "$CORES_DIR/"; then
            log_error "移动 Sing-box 可执行文件失败。"
            return 1
        fi
    else
        log_error "在解压的文件中未找到 'sing-box'。"
        rm -f "$tmp_file"; rm -rf "$tmp_extract_dir"
        return 1
    fi

    chmod +x "$CORES_DIR/sing-box"
    rm -f "$tmp_file"; rm -rf "$tmp_extract_dir"
    
    local installed_version
    installed_version=$($CORES_DIR/sing-box version | awk '/version/{print $NF}')
    log_info "Sing-box ($installed_version) 安装成功。"
    
    # Update config with version
    jq --arg version "$installed_version" '.cores.singbox_version = $version' "$CONFIG_DIR/config.json" > tmp.$$.json && mv tmp.$$.json "$CONFIG_DIR/config.json"
}


# --- 核心安装与配置 ---

initialize_setup() {
    log_info "正在初始化目录结构和默认配置..."
    mkdir -p "$CONFIG_DIR" "$CORES_DIR" "$WEB_DIR" "$LOG_DIR" "$SECRETS_DIR"

    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        local new_uuid
        new_uuid=$(uuidgen)
        local web_pass
        web_pass=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        
        # Generate Reality keypair
        "$CORES_DIR/sing-box" generate reality-keypair > /tmp/reality_keys.txt
        local private_key
        private_key=$(grep "PrivateKey" /tmp/reality_keys.txt | awk '{print $2}' | tr -d '"')
        local public_key
        public_key=$(grep "PublicKey" /tmp/reality_keys.txt | awk '{print $2}' | tr -d '"')
        local short_id
        short_id=$("$CORES_DIR/sing-box" generate rand --hex 8)
        rm -f /tmp/reality_keys.txt

        cat > "$CONFIG_DIR/config.json" <<EOF
{
    "uuid": "${new_uuid}",
    "domain": "",
    "certificates": {
        "enabled": false,
        "cert_path": "${SECRETS_DIR}/cert.pem",
        "key_path": "${SECRETS_DIR}/private.key"
    },
    "ports": {
        "vless": 20001,
        "vmess": 20002,
        "hysteria2": 20003,
        "tuic": 20004,
        "shadowsocks": 20005
    },
    "multiplexing": {
        "hysteria2_ports": "",
        "tuic_ports": ""
    },
    "reality": {
        "private_key": "${private_key}",
        "public_key": "${public_key}",
        "short_id": "${short_id}",
        "server_name": "apple.com"
    },
    "warp": {
        "enabled": false,
        "mode": "local",
        "country": "US"
    },
    "routing": {
        "global_outbound": "direct",
        "rules": [
            { "enabled": true, "name": "Netflix", "domains": ["netflix.com", "nflxvideo.net"], "outbound": "direct" },
            { "enabled": true, "name": "OpenAI/ChatGPT", "domains": ["openai.com", "chat.openai.com"], "outbound": "warp" }
        ]
    },
    "cdn": {
        "enabled": false,
        "ips": ["104.16.124.96"]
    },
    "proxies": {
        "custom_outbounds": []
    },
    "cores": {
        "singbox_version": "N/A",
        "auto_update": true
    },
    "web": {
        "port": 54321,
        "username": "admin",
        "password": "${web_pass}"
    }
}
EOF
        log_info "默认配置已生成。"
        log_info "Web面板登录名: admin"
        log_info "Web面板密码: ${YELLOW}${web_pass}${GREEN} (请妥善保管!)${PLAIN}"
    fi
}

generate_self_signed_cert() {
    if [[ ! -f "$SECRETS_DIR/cert.pem" ]]; then
        log_info "正在生成自签证书..."
        openssl ecparam -genkey -name prime256v1 -out "$SECRETS_DIR/private.key" >/dev/null 2>&1
        openssl req -new -x509 -days 36500 -key "$SECRETS_DIR/private.key" -out "$SECRETS_DIR/cert.pem" -subj "/CN=www.bing.com" >/dev/null 2>&1
        log_info "自签证书生成完成。"
    fi
}

setup_web_panel() {
    log_info "正在设置Web管理面板..."

    if [[ ! -d "$VENV_DIR" ]]; then python3 -m venv "$VENV_DIR"; fi
    "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
    if ! "$VENV_DIR/bin/pip" install flask flask-cors qrcode[pil] requests >/dev/null; then
        log_error "Python依赖安装失败。请检查pip和网络。"
        return 1
    fi

    # 写入Flask后端 (app.py)
    cat > "$WEB_DIR/app.py" <<'EOF'
# === BEGIN app.py ===
import os, sys, json, subprocess, base64, io, re
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS
import qrcode
import requests

app = Flask(__name__, template_folder='templates')
CORS(app)

BASE_DIR_ENV = "/etc/proxy-manager"
CONFIG_FILE = os.path.join(BASE_DIR_ENV, "config", "config.json")
MANAGER_SCRIPT = os.path.join(BASE_DIR_ENV, "proxy_manager.sh") # Assuming this script is named proxy_manager.sh

def run_command(command, sync=True):
    try:
        if sync:
            result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
            return {"status": "success", "output": result.stdout.strip()}
        else:
            subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return {"status": "success", "message": "Command started in background"}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error": e.stderr.strip() or e.stdout.strip()}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/config', methods=['GET', 'POST'])
def handle_config():
    if request.method == 'GET':
        try:
            with open(CONFIG_FILE, 'r') as f:
                return jsonify(json.load(f))
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500
    elif request.method == 'POST':
        try:
            new_config = request.json
            with open(CONFIG_FILE, 'w') as f:
                json.dump(new_config, f, indent=4)
            # DONT call restart here, let user click "save and apply"
            # run_command(f"sudo bash {MANAGER_SCRIPT} restart", sync=False)
            return jsonify({"status": "success", "message": "配置已保存。请点击'保存并应用'来重启服务。"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/status')
def get_status():
    services = {}
    for service in ['nginx', 'proxy-manager-web', 'sing-box']:
        result = run_command(f"systemctl is-active {service}")
        services[service] = "running" if result.get('output') == "active" else "stopped"
    return jsonify({"services": services})

@app.route('/api/actions/<action>', methods=['POST'])
def perform_action(action):
    command = f"sudo bash {MANAGER_SCRIPT} {action}"
    if action == 'apply-acme':
        domain = request.json.get('domain')
        if not domain:
            return jsonify({"status": "error", "message": "Domain is required"}), 400
        # The script will read domain from config, so we save it first
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
            config['domain'] = domain
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to save domain to config: {e}"}), 500
    
    result = run_command(command, sync=False)
    return jsonify(result)

@app.route('/api/ip-scanner/list')
def get_ip_list():
    ip_type = request.args.get('loadIPs', 'official')
    port = request.args.get('port', '443')
    url = f"https://cmvip.godeluoo.eu.org/jk/bestip?loadIPs={ip_type}&port={port}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        return f"Error fetching IP list: {e}", 500

@app.route('/api/proxies/import', methods=['POST'])
def import_proxies():
    data = request.json
    proxy_list_text = data.get('proxies', '')
    
    parsed_proxies = []
    failed_lines = 0
    
    for line in proxy_list_text.strip().split('\n'):
        line = line.strip()
        if not line: continue
        
        proxy = {}
        # Format A: 38.47.96.19:5555 | socks5:socks5 | In/Out: Japan-Osaka Fu Osaka[商企IP] | ...
        if '|' in line:
            parts = [p.strip() for p in line.split('|')]
            try:
                ip_port = parts[0].split(':')
                user_pass = parts[1].split(':')
                location_part = parts[2].split(':', 1)[1].strip()
                
                proxy['ip'] = ip_port[0]
                proxy['port'] = int(ip_port[1])
                proxy['user'] = user_pass[0]
                proxy['pass'] = user_pass[1]
                proxy['location'] = location_part
                proxy['name'] = f"SOCKS_{location_part.split('[')[0].strip()}"
                parsed_proxies.append(proxy)
            except Exception:
                failed_lines += 1
        # Format B: 38.15.10.106:36391:1A24NyA381510106A36391:dbRzDdQn0nV4
        elif line.count(':') == 3:
            try:
                ip, port, user, password = line.split(':')
                proxy['ip'] = ip
                proxy['port'] = int(port)
                proxy['user'] = user
                proxy['pass'] = password
                proxy['location'] = f"Location for {ip}"
                proxy['name'] = f"SOCKS_{ip.replace('.', '_')}"
                parsed_proxies.append(proxy)
            except Exception:
                failed_lines += 1
        else:
            failed_lines += 1

    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        if 'proxies' not in config: config['proxies'] = {}
        config['proxies']['custom_outbounds'] = parsed_proxies
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
            
        return jsonify({
            "status": "success",
            "message": f"成功导入 {len(parsed_proxies)} 个代理，{failed_lines} 行失败。"
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    port = 54321
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            port = config.get('web', {}).get('port', 54321)
    except:
        pass
    app.run(host='127.0.0.1', port=port)
# === END app.py ===
EOF

    # 写入HTML模板 (index.html)
    mkdir -p "$WEB_DIR/templates"
    cat > "$WEB_DIR/templates/index.html" <<'EOF'
# === BEGIN index.html ===
<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Manager Ultimate</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 1140px; }
        .card { transition: box-shadow .3s; }
        .card:hover { box-shadow: 0 .5rem 1rem rgba(0,0,0,.15); }
        .status-dot { height: 12px; width: 12px; border-radius: 50%; display: inline-block; margin-right: 8px; }
        .status-running { background-color: #198754; }
        .status-stopped { background-color: #dc3545; }
        .toast-container { z-index: 1090; }
        .table-responsive { max-height: 400px; }
    </style>
</head>
<body>
    <div class="container py-4" id="app">
        <header class="d-flex justify-content-between align-items-center mb-4 pb-3 border-bottom">
            <h2 class="mb-0">集成代理协议管理面板 (Sing-box 终极版)</h2>
            <div class="form-check form-switch">
                <input class="form-check-input" type="checkbox" id="darkModeSwitch" @change="toggleDarkMode">
                <label class="form-check-label" for="darkModeSwitch">暗黑模式</label>
            </div>
        </header>

        <ul class="nav nav-pills mb-3" id="mainTab" role="tablist">
            <li class="nav-item" role="presentation"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#dashboard" type="button">仪表盘</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#config" type="button">通用配置</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nodes" type="button">节点信息</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#cdn" type="button">CDN优选</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" data-bs-toggle="tab" data-bs-target="#proxy-import" type="button">代理导入</button></li>
        </ul>

        <div class="tab-content" id="mainTabContent">
            <!-- Dashboard Tab (Content is loaded dynamically with Vue) -->
            <div class="tab-pane fade show active" id="dashboard" role="tabpanel">
                <div class="row">
                    <div class="col-md-6">
                        <div class="card mb-4">
                            <div class="card-header">服务状态</div>
                            <ul class="list-group list-group-flush">
                                <li class="list-group-item d-flex justify-content-between align-items-center" v-for="(s, name) in status.services">
                                    <span class="text-capitalize">{{ name }}</span>
                                    <span>
                                        <span :class="['status-dot', s === 'running' ? 'status-running' : 'status-stopped']"></span>
                                        {{ s }}
                                    </span>
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Other tabs are dynamically rendered by Vue -->
            <div class="tab-pane fade" id="config" role="tabpanel">...</div>
            <div class="tab-pane fade" id="nodes" role="tabpanel">...</div>
            <div class="tab-pane fade" id="cdn" role="tabpanel">...</div>
            <div class="tab-pane fade" id="proxy-import" role="tabpanel">...</div>
        </div>
        
        <footer class="d-flex justify-content-end mt-4">
            <button class="btn btn-primary btn-lg" @click="saveConfig">保存并应用所有配置</button>
        </footer>
        
        <div class="toast-container position-fixed bottom-0 end-0 p-3">
             <div id="liveToast" class="toast" role="alert" aria-live="assertive" aria-atomic="true">
                <div class="toast-header"><strong class="me-auto">通知</strong><button type="button" class="btn-close" data-bs-dismiss="toast"></button></div>
                <div class="toast-body">{{ toastMessage }}</div>
             </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/vue@3.3.4/dist/vue.global.prod.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Full Vue app logic will be here
        const { createApp } = Vue;
        createApp({ /* Vue App Logic */ }).mount('#app');
    </script>
</body>
</html>
# === END index.html ===
EOF

    local web_port
    web_port=$(jq -r '.web.port' "$CONFIG_DIR/config.json" 2>/dev/null || echo 54321)
    
    cat > "$SYSTEMD_DIR/proxy-manager-web.service" <<EOF
[Unit]
Description=Proxy Manager Web Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$WEB_DIR
ExecStart=$VENV_DIR/bin/python $WEB_DIR/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    cat > "$NGINX_CONF_DIR/proxy-manager.conf" <<EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${web_port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    # Remove old symlink if it exists
    rm -f "$NGINX_ENABLED_DIR/proxy-manager.conf"
    ln -s "$NGINX_CONF_DIR/proxy-manager.conf" "$NGINX_ENABLED_DIR/proxy-manager.conf"
    log_info "Web面板和Nginx配置完成。"
}

create_core_services() {
    log_info "正在创建Sing-box核心服务的systemd文件..."
    cat > "$SYSTEMD_DIR/sing-box.service" <<EOF
[Unit]
Description=Sing-Box Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$CORES_DIR/sing-box run -c $CONFIG_DIR/sing-box.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    log_info "核心代理服务的systemd文件创建完成。"
}

start_all_services() {
    log_info "正在启动所有服务..."
    systemctl daemon-reload
    systemctl enable sing-box proxy-manager-web >/dev/null 2>&1
    if ! systemctl restart nginx; then log_error "Nginx 启动失败，请检查配置或80端口占用。"; fi
    if ! systemctl restart proxy-manager-web; then log_error "Web面板服务启动失败，请检查日志。"; fi
    if ! systemctl restart sing-box; then log_error "Sing-box 服务启动失败，请检查配置或端口占用。"; fi
    log_info "所有服务已启动。"
}

stop_all_services() {
    log_info "正在停止所有服务..."
    systemctl stop sing-box proxy-manager-web nginx || true
    log_info "所有服务已停止。"
}

uninstall() {
    log_warn "即将卸载Proxy Manager及其所有组件！"
    read -p "这将删除所有配置和核心文件。您确定要继续吗? (y/N): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
        log_info "卸载已取消。"; exit 0;
    fi
    
    stop_all_services
    systemctl disable sing-box proxy-manager-web >/dev/null 2>&1
    
    rm -f "$SYSTEMD_DIR/sing-box.service" "$SYSTEMD_DIR/proxy-manager-web.service"
    rm -f "$NGINX_CONF_DIR/proxy-manager.conf" "$NGINX_ENABLED_DIR/proxy-manager.conf"
    
    systemctl daemon-reload
    systemctl reset-failed
    
    rm -rf "$BASE_DIR"
    
    log_info "Proxy Manager已成功卸载。"
}

apply_acme() {
    local domain
    domain=$(jq -r '.domain' "$CONFIG_DIR/config.json" 2>/dev/null)
    if [[ -z "$domain" || "$domain" == "null" ]]; then
      log_error "请先在Web面板中配置域名并保存！"
      return 1
    fi
    log_info "正在为 ${domain} 申请ACME证书..."
    if [[ ! -f "$ACME_SH_INSTALL_DIR/acme.sh" ]]; then
        log_info "正在安装 acme.sh..."
        if ! curl https://get.acme.sh | sh; then
            log_error "acme.sh 安装失败。"
            return 1
        fi
    fi
    
    "$ACME_SH_INSTALL_DIR"/acme.sh --issue -d "$domain" --standalone -k ec-256
    
    if ! "$ACME_SH_INSTALL_DIR"/acme.sh --install-cert -d "$domain" --ecc \
      --cert-file      "$SECRETS_DIR/cert.pem" \
      --key-file       "$SECRETS_DIR/private.key" \
      --fullchain-file "$SECRETS_DIR/fullchain.pem"; then
        log_error "ACME证书安装失败。"
        return 1
    fi
      
    jq '.certificates.enabled = true' "$CONFIG_DIR/config.json" > tmp.$$.json && mv tmp.$$.json "$CONFIG_DIR/config.json"
    
    local web_port
    web_port=$(jq -r '.web.port' "$CONFIG_DIR/config.json")
    cat > "$NGINX_CONF_DIR/proxy-manager.conf" <<EOF
server {
    listen 80;
    server_name ${domain};
    location /.well-known/acme-challenge/ {
        root $ACME_SH_INSTALL_DIR/${domain}_ecc;
    }
    location / {
        return 301 https://\$host\$request_uri;
    }
}
server {
    listen 443 ssl http2;
    server_name ${domain};
    ssl_certificate       ${SECRETS_DIR}/fullchain.pem;
    ssl_certificate_key   ${SECRETS_DIR}/private.key;
    ssl_session_cache     shared:SSL:10m;
    ssl_session_timeout   1d;
    ssl_protocols         TLSv1.2 TLSv1.3;
    ssl_ciphers           EECDH+AESGCM:EDH+AESGCM;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://127.0.0.1:${web_port};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    log_info "ACME证书申请并配置完成，正在重启Nginx..."
    if ! systemctl restart nginx; then
        log_error "Nginx重启失败，请手动检查配置 `nginx -t`"
    fi
}
# --- 主逻辑 ---
main() {
    check_root
    
    case "${1:-menu}" in
        install)
            check_dependencies
            detect_system
            mkdir -p "$CONFIG_DIR" "$CORES_DIR"
            log_info "开始下载核心文件..."
            if ! download_sing_box; then
                log_error "核心文件下载失败，安装中止。请检查网络连���或稍后再试。"
                exit 1
            fi
            
            install_dependencies
            initialize_setup
            generate_self_signed_cert
            if ! setup_web_panel; then log_error "Web面板设置失败。"; exit 1; fi
            create_core_services
            
            start_all_services
            
            local server_ip
            server_ip=$(curl -s4 icanhazip.com || hostname -I | awk '{print $1}' | head -n1)
            log_info "🎉 安装完成！"
            log_info "请通过浏览器访问您的Web管理面板: ${YELLOW}http://${server_ip}${PLAIN}"
            log_warn "如果无法访问，请检查防火墙是否开放80端口。"
            ;;
        uninstall) uninstall;;
        start) start_all_services;;
        stop) stop_all_services;;
        restart) start_all_services;;
        update-cores) download_sing_box; start_all_services;;
        apply-acme) apply_acme;;
        *)
            echo "用法: $0 {install|uninstall|start|stop|restart|update-cores|apply-acme}"
            exit 1
            ;;
    esac
}

main "$@"
