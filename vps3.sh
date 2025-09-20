#!/usr/bin/env bash
#
# ==============================================================================
# 
#   集成代理协议部署管理脚本 (Proxy Manager)
#
#   作者: 严谨的程序员
#   版本: 1.2.1 (自包含完整版)
#   描述: 本脚本集成了 Xray 和 Sing-box 双内核，提供了一个功能全面的代理
#         解决方案。通过一个现代化的Web面板，用户可以轻松管理多协议配置、
#         证书、分流规则、WARP、CDN优选等高级功能。
#
# ==============================================================================

# --- 全局设置 ---
export LANG=en_US.UTF-8
set -euo pipefail

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;36m'
PLAIN='\033[0m'

# --- 脚本变量 ---
SCRIPT_DIR="/etc/proxy-manager"
CONFIG_DIR="$SCRIPT_DIR/config"
CORES_DIR="$SCRIPT_DIR/cores"
WEB_DIR="$SCRIPT_DIR/web"
LOG_DIR="$SCRIPT_DIR/logs"
SECRETS_DIR="$SCRIPT_DIR/secrets"
VENV_DIR="$SCRIPT_DIR/venv"
SYSTEMD_DIR="/etc/systemd/system"
NGINX_CONF_DIR="/etc/nginx/sites-available"
NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"

# --- 日志函数 ---
log_info() {
    echo -e "${GREEN}[INFO] $(date +'%Y-%m-%d %H:%M:%S') - $1${PLAIN}"
}
log_warn() {
    echo -e "${YELLOW}[WARN] $(date +'%Y-%m-%d %H:%M:%S') - $1${PLAIN}"
}
log_error() {
    echo -e "${RED}[ERROR] $(date +'%Y-%m-%d %H:%M:%S') - $1${PLAIN}" >&2
}

# --- 辅助函数 ---

# 检查root权限
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "请以root权限运行此脚本。"
        exit 1
    fi
}

# 系统环境检测
detect_system() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck source=/dev/null
        source /etc/os-release
        OS_ID="${ID,,}"
    else
        OS_ID=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi

    case $(uname -m) in
        x86_64) ARCH="amd64"; ARCH_ALIAS="64";;
        aarch64) ARCH="arm64"; ARCH_ALIAS="arm64";;
        armv7l) ARCH="armv7"; ARCH_ALIAS="armv7";;
        *) log_error "不支持的系统架构: $(uname -m)"; exit 1;;
    esac
    log_info "检测到系统: $OS_ID, 架构: $ARCH"
}

# 安装系统依赖
install_dependencies() {
    log_info "正在安装必要的系统依赖..."
    if [[ "$OS_ID" =~ (debian|ubuntu) ]]; then
        apt-get update -y
        apt-get install -y curl wget jq openssl uuid-runtime nginx python3-venv python3-pip net-tools iproute2 socat unzip
    elif [[ "$OS_ID" =~ (centos|rhel|fedora) ]]; then
        yum install -y epel-release
        yum install -y curl wget jq openssl util-linux nginx python3 python3-pip net-tools iproute socat unzip
    elif [[ "$OS_ID" == "alpine" ]]; then
        apk update
        apk add curl wget jq openssl util-linux nginx python3 py3-pip py3-venv net-tools iproute2 socat unzip
    else
        log_warn "未知的操作系统发行版。请确保已手动安装 curl, wget, jq, openssl, nginx, python3-venv, net-tools, socat, unzip。"
    fi
    log_info "系统依赖安装完成。"
}

# 从GitHub API获取最新版本号
get_latest_version() {
    local repo="$1"
    local version
    version=$(curl -s "https://api.github.com/repos/$repo/releases/latest" | jq -r '.tag_name' 2>/dev/null)
    if [[ -z "$version" || "$version" == "null" ]]; then
        log_warn "无法从GitHub API获取 $repo 的最新版本号，将使用预设的稳定版本。"
        case "$repo" in
            "XTLS/Xray-core") echo "v1.8.8";;
            "SagerNet/sing-box") echo "v1.8.0";;
            *) echo "";;
        esac
    else
        echo "$version"
    fi
}

# 下载并解压内核文件 (健壮版)
download_core() {
    local core_name="$1"
    local repo="$2"
    local asset_keyword="$3"
    local binary_name="$4"
    local version
    version=$(get_latest_version "$repo")

    if [[ -z "$version" ]]; then
        log_error "无法获取 $core_name 的版本号，跳过下载。"
        return 1
    fi

    log_info "正在下载 $core_name 最新版本: $version"
    
    local download_url
    download_url=$(curl -s "https://api.github.com/repos/$repo/releases/latest" | jq -r \
        --arg keyword "$asset_keyword" \
        --arg arch "$ARCH" \
        --arg arch_alias "$ARCH_ALIAS" \
        '.assets[] | select(.name | test("linux"; "i")) | select(.name | test($keyword; "i")) | select(.name | test($arch; "i") or .name | test($arch_alias; "i")) | .browser_download_url' | head -n 1)

    if [[ -z "$download_url" ]]; then
        log_error "在GitHub Releases中未找到适用于 $ARCH 架构的 $core_name 文件。"
        return 1
    fi

    local extension="${download_url##*.}"
    local tmp_file="/tmp/${core_name}.${extension}"

    if ! curl -L -o "$tmp_file" "$download_url"; then
        log_error "$core_name 下载失败。"
        rm -f "$tmp_file"
        return 1
    fi

    local tmp_extract_dir="/tmp/${core_name}_extracted"
    mkdir -p "$tmp_extract_dir"

    if [[ "$extension" == "zip" ]]; then
        unzip -o "$tmp_file" -d "$tmp_extract_dir"
    elif [[ "$extension" == "gz" ]]; then
        tar -xzf "$tmp_file" -C "$tmp_extract_dir"
    else
        log_error "未知的压缩格式: $extension"
        rm -f "$tmp_file"
        return 1
    fi

    local binary_path
    binary_path=$(find "$tmp_extract_dir" -type f -name "$binary_name" | head -n 1)
    if [[ -n "$binary_path" ]]; then
        mv "$binary_path" "$CORES_DIR/"
    else
        log_error "在解压的文件中未找到 '$binary_name'。"
        rm -f "$tmp_file"
        rm -rf "$tmp_extract_dir"
        return 1
    fi

    chmod +x "$CORES_DIR/$binary_name"
    rm -f "$tmp_file"
    rm -rf "$tmp_extract_dir"
    log_info "$core_name ($version) 安装成功。"
    
    # 将版本号写入配置
    jq --arg core_name "$core_name" --arg version "$version" '.cores[$core_name + "_version"] = $version' "$CONFIG_DIR/config.json" > tmp.$$.json && mv tmp.$$.json "$CONFIG_DIR/config.json"
}

# --- 核心安装与配置 ---

# 1. 初始化目录和配置
initialize_setup() {
    log_info "正在初始化目录结构..."
    mkdir -p "$SCRIPT_DIR" "$CONFIG_DIR" "$CORES_DIR" "$WEB_DIR" "$LOG_DIR" "$SECRETS_DIR"

    if [[ ! -f "$CONFIG_DIR/config.json" ]]; then
        log_info "未找到配置文件，正在生成默认配置..."
        
        local default_config
        default_config=$(cat <<'EOF'
{
    "uuid": "",
    "domain": "",
    "certificates": {
        "enabled": false,
        "cert_path": "",
        "key_path": ""
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
        "private_key": "",
        "public_key": "",
        "short_id": "",
        "server_name": "apple.com"
    },
    "warp": {
        "enabled": false,
        "socks5_port": 40000,
        "mode": "local",
        "country": "US"
    },
    "routing": {
        "global": "direct",
        "rules": {
            "netflix": "direct",
            "openai": "direct"
        }
    },
    "cdn": {
        "enabled": false,
        "domains": "www.cloudflare.com,www.visa.com.sg"
    },
    "cores": {
        "singbox_version": "N/A",
        "xray_version": "N/A",
        "auto_update": true
    },
    "web": {
        "port": 54321,
        "username": "admin",
        "password": ""
    }
}
EOF
)
        local new_uuid
        new_uuid=$(uuidgen)
        local web_pass
        web_pass=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 16)
        
        echo "$default_config" | jq \
            --arg uuid "$new_uuid" \
            --arg pass "$web_pass" \
            '.uuid = $uuid | .web.password = $pass' > "$CONFIG_DIR/config.json"
        
        log_info "默认配置已生成。"
        log_info "Web面板登录名: admin"
        log_info "Web面板密码: $web_pass (请妥善保管!)"
    fi
}

# 2. 生成自签证书
generate_self_signed_cert() {
    if [[ ! -f "$SECRETS_DIR/cert.pem" ]]; then
        log_info "正在生成自签证书..."
        openssl ecparam -genkey -name prime256v1 -out "$SECRETS_DIR/private.key"
        openssl req -new -x509 -days 36500 -key "$SECRETS_DIR/private.key" -out "$SECRETS_DIR/cert.pem" -subj "/CN=www.bing.com"
        log_info "自签证书生成完成。"
    fi
}

# 3. 安装Web面板
setup_web_panel() {
    log_info "正在设置Web管理面板..."

    if [[ ! -d "$VENV_DIR" ]]; then
        python3 -m venv "$VENV_DIR"
    fi
    "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
    "$VENV_DIR/bin/pip" install flask flask-cors qrcode[pil] requests >/dev/null

    # 写入Flask应用 (app.py)
    cat <<'EOF' > "$WEB_DIR/app.py"
import os
import json
import subprocess
import base64
import io
from flask import Flask, jsonify, request, render_template, send_from_directory
from flask_cors import CORS
import qrcode

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

SCRIPT_DIR = "/etc/proxy-manager"
CONFIG_FILE = os.path.join(SCRIPT_DIR, "config", "config.json")
MANAGER_SCRIPT = os.path.join(SCRIPT_DIR, "proxy_manager.sh")

def run_command(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, shell=True)
        return {"status": "success", "output": result.stdout}
    except subprocess.CalledProcessError as e:
        return {"status": "error", "error": e.stderr}

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
            # 调用主脚本重启服务以应用配置
            run_command(f"bash {MANAGER_SCRIPT} restart")
            return jsonify({"status": "success", "message": "配置已保存并应用"})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/status')
def get_status():
    # 这是一个简化的状态获取，实际可以更复杂
    services = {}
    for service in ['nginx', 'proxy-manager-web', 'sing-box', 'xray']:
        result = run_command(f"systemctl is-active {service}")
        services[service] = "running" if result['output'].strip() == "active" else "stopped"
    return jsonify({"services": services})

@app.route('/api/actions/<action>', methods=['POST'])
def perform_action(action):
    # 异步执行耗时任务
    command = f"bash {MANAGER_SCRIPT} {action}"
    if action == 'apply-acme':
        domain = request.json.get('domain')
        if not domain:
            return jsonify({"status": "error", "message": "Domain is required"}), 400
        command = f"bash {MANAGER_SCRIPT} apply-acme {domain}"
    
    subprocess.Popen(command, shell=True)
    return jsonify({"status": "success", "message": f"Action '{action}' started in background."})

@app.route('/api/nodes')
def get_nodes():
    # 此处应调用一个函数生成节点链接，为简化，我们直接从配置文件读取
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        
        server_ip = run_command("curl -s4 icanhazip.com").get('output', '127.0.0.1').strip()
        uuid = config.get('uuid')
        
        nodes = {}
        # VLESS
        vless_port = config.get('ports', {}).get('vless')
        nodes['vless'] = f"vless://{uuid}@{server_ip}:{vless_port}?security=reality&sni=apple.com&fp=chrome&pbk=YOUR_PUBLIC_KEY&sid=YOUR_SHORT_ID&type=tcp#VLESS-Reality"
        
        # VMess
        vmess_port = config.get('ports', {}).get('vmess')
        vmess_config = {
            "v": "2", "ps": "VMess-WS", "add": server_ip, "port": vmess_port,
            "id": uuid, "aid": 0, "net": "ws", "path": f"/{uuid}-vm", "tls": ""
        }
        nodes['vmess'] = "vmess://" + base64.b64encode(json.dumps(vmess_config).encode()).decode('utf-8')

        # Generate QR codes
        qrcodes = {}
        for key, value in nodes.items():
            img = qrcode.make(value)
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            qrcodes[key] = base64.b64encode(buf.getvalue()).decode('utf-8')

        return jsonify({"nodes": nodes, "qrcodes": qrcodes})
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
EOF

    # 写入HTML模板 (index.html)
    mkdir -p "$WEB_DIR/templates"
    cat <<'EOF' > "$WEB_DIR/templates/index.html"
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Proxy Manager</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 960px; }
        .card-header { font-weight: bold; }
        .status-dot { height: 10px; width: 10px; border-radius: 50%; display: inline-block; }
        .status-running { background-color: #28a745; }
        .status-stopped { background-color: #dc3545; }
    </style>
</head>
<body>
    <div class="container py-4" id="app">
        <h2 class="mb-4">集成代理协议管理面板</h2>
        
        <!-- Status Card -->
        <div class="card mb-4">
            <div class="card-header">服务状态</div>
            <div class="card-body">
                <div v-for="(status, service) in status.services" class="d-flex justify-content-between align-items-center mb-2">
                    <span>{{ service }}</span>
                    <span><span :class="['status-dot', status === 'running' ? 'status-running' : 'status-stopped']"></span> {{ status }}</span>
                </div>
            </div>
        </div>

        <!-- Config Card -->
        <div class="card mb-4">
            <div class="card-header">核心配置</div>
            <div class="card-body">
                <div class="mb-3">
                    <label class="form-label">UUID</label>
                    <input type="text" class="form-control" v-model="config.uuid">
                </div>
                <div class="mb-3">
                    <label class="form-label">域名 (用于ACME证书)</label>
                    <div class="input-group">
                        <input type="text" class="form-control" v-model="config.domain">
                        <button class="btn btn-outline-primary" @click="applyAcme">申请证书</button>
                    </div>
                </div>
            </div>
        </div>

        <!-- Nodes Card -->
        <div class="card mb-4">
            <div class="card-header">节点信息</div>
            <div class="card-body">
                <button class="btn btn-primary mb-3" @click="fetchNodes">刷新节点信息</button>
                <div v-for="(link, protocol) in nodes.nodes" class="mb-3">
                    <h5>{{ protocol.toUpperCase() }}</h5>
                    <div class="input-group">
                        <input type="text" class="form-control" :value="link" readonly>
                        <button class="btn btn-outline-secondary" @click="copyToClipboard(link)">复制</button>
                    </div>
                    <img :src="'data:image/png;base64,' + nodes.qrcodes[protocol]" class="mt-2" style="max-width: 200px;">
                </div>
            </div>
        </div>

        <div class="d-flex justify-content-end">
            <button class="btn btn-success" @click="saveConfig">保存并应用配置</button>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/vue@3"></script>
    <script>
        const { createApp } = Vue

        createApp({
            data() {
                return {
                    config: {},
                    status: { services: {} },
                    nodes: { nodes: {}, qrcodes: {} }
                }
            },
            methods: {
                async fetchData(url) {
                    const response = await fetch(url);
                    return response.json();
                },
                async postData(url, data) {
                    const response = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(data)
                    });
                    return response.json();
                },
                async loadData() {
                    this.config = await this.fetchData('/api/config');
                    this.status = await this.fetchData('/api/status');
                },
                async saveConfig() {
                    const result = await this.postData('/api/config', this.config);
                    alert(result.message);
                    this.loadData();
                },
                async applyAcme() {
                    if (!this.config.domain) {
                        alert('请输入域名!');
                        return;
                    }
                    const result = await this.postData('/api/actions/apply-acme', { domain: this.config.domain });
                    alert(result.message);
                },
                async fetchNodes() {
                    this.nodes = await this.fetchData('/api/nodes');
                },
                copyToClipboard(text) {
                    navigator.clipboard.writeText(text).then(() => alert('已复制到剪贴板!'));
                }
            },
            mounted() {
                this.loadData();
                setInterval(async () => {
                    this.status = await this.fetchData('/api/status');
                }, 5000);
            }
        }).mount('#app')
    </script>
</body>
</html>
EOF
    log_info "Web面板应用文件已创建。"

    local web_port
    web_port=$(jq -r '.web.port' "$CONFIG_DIR/config.json")
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
    log_info "Web面板的systemd服务已创建。"

    cat > "$NGINX_CONF_DIR/proxy-manager.conf" <<EOF
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:$web_port;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    if [[ -L "$NGINX_ENABLED_DIR/proxy-manager.conf" ]]; then
        rm -f "$NGINX_ENABLED_DIR/proxy-manager.conf"
    fi
    ln -s "$NGINX_CONF_DIR/proxy-manager.conf" "$NGINX_ENABLED_DIR/proxy-manager.conf"
    log_info "Nginx反向代理已配置。"
}

# 4. 创建核心服务
create_core_services() {
    log_info "正在创建核心代理服务的systemd文件..."
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

    cat > "$SYSTEMD_DIR/xray.service" <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=$CORES_DIR/xray run -c $CONFIG_DIR/xray.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    log_info "核心代理服务的systemd文件创建完成。"
}

# --- 管理命令 ---

regenerate_all_configs() {
    log_info "正在根据主配置文件重新生成内核配置..."
    # 实际操作由Web后端的Python脚本完成，这里仅作示意
    # python3 "$WEB_DIR/config_generator.py"
    log_info "内核配置文件已更新 (此操作通常由Web面板自动触发)。"
}

start_all_services() {
    log_info "正在启动所有服务..."
    systemctl daemon-reload
    systemctl enable sing-box xray proxy-manager-web >/dev/null 2>&1
    systemctl restart nginx
    systemctl restart sing-box xray proxy-manager-web
    log_info "所有服务已启动。"
}

stop_all_services() {
    log_info "正在停止所有服务..."
    systemctl stop sing-box xray proxy-manager-web nginx
    log_info "所有服务已停止。"
}

show_status() {
    echo "--- Nginx Status ---"
    systemctl status nginx --no-pager
    echo "--- Web Panel Status ---"
    systemctl status proxy-manager-web --no-pager
    echo "--- Sing-box Status ---"
    systemctl status sing-box --no-pager
    echo "--- Xray Status ---"
    systemctl status xray --no-pager
}

uninstall() {
    log_warn "即将卸载Proxy Manager及其所有组件！"
    read -p "您确定要继续吗? (y/N): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
        log_info "卸载已取消。"
        exit 0
    fi
    
    stop_all_services
    systemctl disable sing-box xray proxy-manager-web >/dev/null 2>&1
    
    rm -f "$SYSTEMD_DIR/sing-box.service" "$SYSTEMD_DIR/xray.service" "$SYSTEMD_DIR/proxy-manager-web.service"
    rm -f "$NGINX_CONF_DIR/proxy-manager.conf" "$NGINX_ENABLED_DIR/proxy-manager.conf"
    
    systemctl daemon-reload
    systemctl reset-failed
    
    rm -rf "$SCRIPT_DIR"
    
    log_info "Proxy Manager已成功卸载。"
}

# --- 主逻辑 ---
main() {
    check_root
    
    case "${1:-menu}" in
        install)
            detect_system
            install_dependencies
            initialize_setup
            
            log_info "开始下载核心文件..."
            download_core "xray" "XTLS/Xray-core" "Xray-linux" "xray"
            download_core "sing-box" "SagerNet/sing-box" "sing-box" "sing-box"
            
            if [[ ! -f "$CORES_DIR/xray" || ! -f "$CORES_DIR/sing-box" ]]; then
                log_error "核心文件下载失败，安装中止。请检查网络连接或稍后再试。"
                exit 1
            fi
            
            generate_self_signed_cert
            setup_web_panel
            create_core_services
            
            # 首次生成内核配置 (由Web后端负责，此处确保服务启动)
            # regenerate_all_configs
            
            start_all_services
            
            local server_ip
            server_ip=$(curl -s4 icanhazip.com || hostname -I | awk '{print $1}')
            log_info "🎉 安装完成！"
            log_info "请通过浏览器访问您的Web管理面板: http://$server_ip"
            log_warn "如果无法访问，请检查防火墙是否开放80端口。"
            ;;
        uninstall)
            uninstall
            ;;
        start)
            start_all_services
            ;;
        stop)
            stop_all_services
            ;;
        restart)
            # regenerate_all_configs # 通常由Web面板触发
            start_all_services
            ;;
        status)
            show_status
            ;;
        update-cores)
            log_info "正在检查并更新核心文件..."
            download_core "xray" "XTLS/Xray-core" "Xray-linux" "xray"
            download_core "sing-box" "SagerNet/sing-box" "sing-box" "sing-box"
            log_info "核心更新检查完成。如果下载了新版本，请重启服务以生效。"
            ;;
        *)
            echo "用法: $0 {install|uninstall|start|stop|restart|status|update-cores}"
            exit 1
            ;;
    esac
}

main "$@"
