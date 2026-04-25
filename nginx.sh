bash <(cat <<'EOF'
set -e

echo "======================================"
echo " Nginx Proxy Manager 一键安装脚本"
echo " 适用：Debian / Ubuntu / root 用户"
echo "======================================"

echo ""
echo "====== 1. 检查 root 权限 ======"
if [ "$EUID" -ne 0 ]; then
  echo "请使用 root 用户执行此脚本。"
  exit 1
fi

echo ""
echo "====== 2. 更新系统并安装基础依赖 ======"
apt update -y
apt install -y curl wget ca-certificates gnupg lsb-release ufw

echo ""
echo "====== 3. 放行防火墙端口 ======"
ufw allow 22/tcp || true
ufw allow 80/tcp || true
ufw allow 81/tcp || true
ufw allow 443/tcp || true

echo ""
echo "已添加 UFW 规则："
echo "22  - SSH"
echo "80  - HTTP"
echo "81  - NPM 管理后台"
echo "443 - HTTPS"
echo ""
echo "注意：脚本不会自动启用 ufw，避免误断 SSH。"
echo "如果你确认没问题，可之后手动执行：ufw enable"

echo ""
echo "====== 4. 安装 Docker ======"
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | bash
else
  echo "Docker 已安装，跳过。"
fi

systemctl enable docker
systemctl start docker

echo ""
echo "====== 5. 安装 Docker Compose ======"
if docker compose version >/dev/null 2>&1; then
  echo "Docker Compose 插件已存在，跳过。"
elif command -v docker-compose >/dev/null 2>&1; then
  echo "docker-compose 已存在，跳过。"
else
  curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" \
    -o /usr/local/bin/docker-compose
  chmod +x /usr/local/bin/docker-compose
fi

echo ""
echo "====== 6. 创建 NPM 安装目录 ======"
mkdir -p /etc/docker/npm
cd /etc/docker/npm

echo ""
echo "====== 7. 写入 docker-compose.yml ======"
cat > docker-compose.yml <<'COMPOSE'
services:
  app:
    image: 'docker.io/jc21/nginx-proxy-manager:latest'
    container_name: nginx-proxy-manager
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
COMPOSE

echo ""
echo "====== 8. 启动 Nginx Proxy Manager ======"
if docker compose version >/dev/null 2>&1; then
  docker compose up -d
else
  docker-compose up -d
fi

echo ""
echo "====== 9. 检查容器状态 ======"
docker ps | grep nginx-proxy-manager || true

SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org || echo "你的服务器IP")

echo ""
echo "======================================"
echo " 安装完成"
echo "======================================"
echo ""
echo "访问面板："
echo "http://${SERVER_IP}:81"
echo ""
echo "默认账号："
echo "Email:    admin@example.com"
echo "Password: changeme"
echo ""
echo "登录后请立即修改账号和密码。"
echo ""
echo "安装目录："
echo "/etc/docker/npm"
echo ""
echo "数据目录："
echo "/etc/docker/npm/data"
echo ""
echo "证书目录："
echo "/etc/docker/npm/letsencrypt"
echo ""
echo "常用命令："
echo "cd /etc/docker/npm && docker compose ps"
echo "cd /etc/docker/npm && docker compose logs -f"
echo "cd /etc/docker/npm && docker compose restart"
echo ""
EOF
)
