#!/bin/bash

# ==============================================================================
#
#       集成代理协议管理面板 (Sing-box 终极版) - 一键部署脚本
#
#   功能:
#   1. 安装并配置 Nginx, Python (Flask) 环境。
#   2. 部署一个现代化的、深色主题的前端管理界面。
#   3. 部署一个提供 API 的 Python Flask 后端服务。
#   4. 配置 systemd 服务，确保后端持久化运行。
#   5. 自动配置 Nginx 反向代理，并清理潜在的冲突配置。
#   6. 提供色彩丰富的、可视化的安装流程。
#
# ==============================================================================

# 脚本出错时立即退出
set -e

# --- 定义颜色变量 ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- 定义消息打印函数 ---
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}


# --- 1. 创建后端 Python Flask 应用 ---
create_backend_app() {
    info "开始创建后端服务..."
    
    # 创建应用目录和虚拟环境
    mkdir -p /opt/proxy-manager
    python3 -m venv /opt/proxy-manager/venv
    
    # 在虚拟环境中安装 Flask
    source /opt/proxy-manager/venv/bin/activate
    pip install Flask > /dev/null 2>&1
    deactivate
    
    # 写入 Flask 应用代码
    cat <<'EOF' > /opt/proxy-manager/app.py
import subprocess
from flask import Flask, jsonify, send_from_directory

app = Flask(__name__, static_folder='.', static_url_path='')

# 主页路由，提供 index.html
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# API 路由，用于获取服务状态
@app.route('/api/status')
def get_status():
    services = ['nginx', 'sing-box', 'proxy-manager-backend']
    statuses = {}
    for service in services:
        try:
            # 使用 systemctl is-active 检查服务状态
            result = subprocess.run(
                ['systemctl', 'is-active', service],
                capture_output=True, text=True, check=False
            )
            status = result.stdout.strip()
            statuses[service] = 'active' if status == 'active' else 'inactive'
        except Exception as e:
            statuses[service] = 'error'

    return jsonify(statuses)

if __name__ == '__main__':
    # 监听 0.0.0.0:54321，允许外部访问（由 Nginx 代理）
    app.run(host='0.0.0.0', port=54321)
EOF
    success "后端 Python 应用创建完成。"
}


# --- 2. 创建前端 HTML 界面 ---
create_frontend_html() {
    info "开始创建前端管理界面..."
    cat <<'EOF' > /opt/proxy-manager/index.html
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>集成代理协议管理面板 (Sing-box 终极版)</title>
    <style>
        :root {
            --bg-color: #1a1a1a;
            --text-color: #e0e0e0;
            --primary-color: #007bff;
            --card-bg-color: #2c2c2c;
            --border-color: #444;
            --success-color: #28a745;
            --error-color: #dc3545;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            padding: 2rem;
            display: flex;
            justify-content: center;
            align-items: flex-start;
            min-height: 100vh;
        }
        .container {
            width: 100%;
            max-width: 800px;
        }
        header {
            text-align: center;
            margin-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 1rem;
        }
        h1 {
            font-size: 1.8rem;
            color: var(--primary-color);
            margin: 0;
        }
        .card {
            background-color: var(--card-bg-color);
            border-radius: 8px;
            padding: 1.5rem;
            border: 1px solid var(--border-color);
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
        }
        .card-title {
            font-size: 1.2rem;
            font-weight: 500;
            margin: 0;
        }
        .btn {
            background-color: var(--primary-color);
            color: white;
            border: none;
            padding: 0.6rem 1.2rem;
            border-radius: 5px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: background-color 0.3s ease;
        }
        .btn:hover {
            background-color: #0056b3;
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }
        .status-item {
            background-color: #3a3a3a;
            padding: 1rem;
            border-radius: 6px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .status-item span:first-child {
            font-weight: 500;
        }
        .status-light {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
        }
        .status-light.active {
            background-color: var(--success-color);
            box-shadow: 0 0 8px var(--success-color);
        }
        .status-light.inactive {
            background-color: var(--error-color);
            box-shadow: 0 0 8px var(--error-color);
        }
        .status-light.unknown {
            background-color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>集成代理协议管理面板 (Sing-box 终极版)</h1>
        </header>
        <main>
            <div class="card">
                <div class="card-header">
                    <h2 class="card-title">核心服务状态</h2>
                    <button id="refreshBtn" class="btn">刷新状态</button>
                </div>
                <div id="statusGrid" class="status-grid">
                    <!-- 状态项将由 JavaScript 动态生成 -->
                </div>
            </div>
        </main>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const refreshBtn = document.getElementById('refreshBtn');
            const statusGrid = document.getElementById('statusGrid');

            const fetchStatus = async () => {
                // 显示加载状态
                statusGrid.innerHTML = '<p>正在获取状态...</p>';
                refreshBtn.disabled = true;
                refreshBtn.textContent = '刷新中...';

                try {
                    const response = await fetch('/api/status');
                    if (!response.ok) {
                        throw new Error('网络响应错误');
                    }
                    const data = await response.json();
                    
                    updateStatusGrid(data);

                } catch (error) {
                    console.error('获取状态失败:', error);
                    statusGrid.innerHTML = '<p style="color: var(--error-color);">无法加载服务状态，请检查后端服务是否正常运行。</p>';
                } finally {
                    refreshBtn.disabled = false;
                    refreshBtn.textContent = '刷新状态';
                }
            };

            const updateStatusGrid = (data) => {
                statusGrid.innerHTML = ''; // 清空
                for (const [service, status] of Object.entries(data)) {
                    const item = document.createElement('div');
                    item.className = 'status-item';
                    
                    const nameSpan = document.createElement('span');
                    nameSpan.textContent = service;
                    
                    const lightSpan = document.createElement('span');
                    lightSpan.className = `status-light ${status}`;
                    
                    item.appendChild(nameSpan);
                    item.appendChild(lightSpan);
                    statusGrid.appendChild(item);
                }
            };

            refreshBtn.addEventListener('click', fetchStatus);

            // 页面加载时自动获取一次状态
            fetchStatus();
        });
    </script>
</body>
</html>
EOF
    success "前端管理界面创建完成。"
}

# --- 3. 创建 Systemd 服务文件 ---
create_systemd_service() {
    info "正在配置后端服务的 systemd 单元..."
    cat <<'EOF' > /etc/systemd/system/proxy-manager-backend.service
[Unit]
Description=Proxy Manager Backend Service
After=network.target

[Service]
User=root
WorkingDirectory=/opt/proxy-manager
ExecStart=/opt/proxy-manager/venv/bin/python app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    success "Systemd 服务配置完成。"
}


# --- 4. 配置 Nginx 反向代理 ---
setup_nginx() {
    info "开始配置 Nginx 反向代理..."

    # 清理可能存在的旧配置文件，避免冲突
    if [ -f "/etc/nginx/conf.d/proxy_manager_pro.conf" ]; then
        rm /etc/nginx/conf.d/proxy_manager_pro.conf
        warn "已删除旧的配置文件: /etc/nginx/conf.d/proxy_manager_pro.conf"
    fi
    if [ -f "/etc/nginx/sites-enabled/default" ]; then
        rm /etc/nginx/sites-enabled/default
        warn "已删除默认的 Nginx 站点配置。"
    fi
    
    # 写入新的 Nginx 配置文件
    cat <<'EOF' > /etc/nginx/sites-available/proxy-manager
server {
    listen 80;
    server_name _;

    location / {
        # 代理所有请求到后端的 Flask 服务
        proxy_pass http://127.0.0.1:54321;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

    # 启用新的站点配置
    if [ ! -L "/etc/nginx/sites-enabled/proxy-manager" ]; then
        ln -s /etc/nginx/sites-available/proxy-manager /etc/nginx/sites-enabled/
    fi

    # 测试 Nginx 配置语法
    nginx -t
    
    success "Nginx 配置完成。"
}


# --- 主函数 ---
main() {
    # 欢迎信息
    echo -e "${GREEN}=====================================================${NC}"
    echo -e "${GREEN}  欢迎使用集成代理协议管理面板 (Sing-box 终极版)  ${NC}"
    echo -e "${GREEN}=====================================================${NC}"
    echo

    # 检查是否为 root 用户
    if [ "$(id -u)" -ne 0 ]; then
        error "此脚本必须以 root 用户身份运行。"
    fi

    # 步骤 1: 安装依赖
    info "步骤 1/5: 更新系统并安装核心依赖 (Nginx, Python)..."
    apt-get update > /dev/null
    apt-get install -y nginx python3-pip python3-venv > /dev/null 2>&1
    success "依赖安装完成。"

    # 步骤 2: 创建后端和前端文件
    info "步骤 2/5: 部署后端和前端应用文件..."
    create_backend_app
    create_frontend_html
    
    # 步骤 3: 配置 Systemd 服务
    info "步骤 3/5: 配置系统服务..."
    create_systemd_service
    
    # 步骤 4: 配置 Nginx
    info "步骤 4/5: 配置 Nginx..."
    setup_nginx
    
    # 步骤 5: 启动并启用所有服务
    info "步骤 5/5: 启动所有服务..."
    systemctl enable proxy-manager-backend >/dev/null 2>&1
    systemctl restart proxy-manager-backend
    
    systemctl enable nginx >/dev/null 2>&1
    systemctl restart nginx
    
    # 获取服务器的公网 IP 地址
    IP_ADDR=$(curl -s http://ipv4.icanhazip.com)

    # 显示最终结果
    echo
    echo -e "${GREEN}🎉 恭喜！部署已全部完成！ 🎉${NC}"
    echo -e "-----------------------------------------------------"
    echo -e "您现在可以通过浏览器访问您的管理面板了。"
    echo -e "  "
    echo -e "   访问地址: ${YELLOW}http://${IP_ADDR}${NC}"
    echo -e "  "
    echo -e "-----------------------------------------------------"
    echo
}

# --- 执行主函数 ---
main
