cat > /root/singbox-dual-28.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

echo "============================================================"
echo " Debian 13 + sing-box 双节点 28 优化"
echo " 场景：直连 VLESS + Cloudflare 固定 Tunnel"
echo " 用途：TikTok Live / YouTube / GPT / AI"
echo " 原则：少改、有效、稳"
echo "============================================================"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 用户执行：sudo -i"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo
echo ">>> 1. 安装必要工具..."
apt update -y
apt install -y \
  curl wget ca-certificates gnupg lsb-release \
  iproute2 iptables iptables-persistent netfilter-persistent \
  dnsutils iputils-ping ethtool chrony procps jq unzip

echo
echo ">>> 2. 启用时间同步..."
systemctl enable --now chrony >/dev/null 2>&1 || true

echo
echo ">>> 3. 启用 BBR + fq..."
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > /etc/modules-load.d/bbr.conf

echo
echo ">>> 4. 写入统一 sysctl 参数..."
rm -f /etc/sysctl.d/99-vless-direct-28.conf
rm -f /etc/sysctl.d/99-cf-singbox-argo-28.conf
rm -f /etc/sysctl.d/99-singbox-dual-28.conf

cat > /etc/sysctl.d/99-singbox-dual-28.conf <<'SYSCTL'
# ============================================================
# Debian 13 + sing-box 双节点 28 优化
# 直连 VLESS + Cloudflare/cloudflared 固定 Tunnel
# 少改、有效、稳
# ============================================================

# 核心：BBR + fq
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 长连接稳定性
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# 适度 buffer，适合直播 / 4K / AI，不盲目堆大
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 16384 8388608

# 减少应用层未发送队列堆积
net.ipv4.tcp_notsent_lowat = 16384

# 文件句柄总量
fs.file-max = 1048576
SYSCTL

sysctl --system >/dev/null

echo
echo ">>> 5. 设置 nofile..."
cat > /etc/security/limits.d/99-nofile.conf <<'LIMITS'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS

mkdir -p /etc/systemd/system.conf.d
cat > /etc/systemd/system.conf.d/99-limits.conf <<'SYSTEMD'
[Manager]
DefaultLimitNOFILE=1048576
SYSTEMD

echo
echo ">>> 6. 设置 sing-box / cloudflared 服务限制与自动重启..."
mkdir -p /etc/systemd/system/sing-box.service.d
cat > /etc/systemd/system/sing-box.service.d/override.conf <<'SINGBOX'
[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=3
SINGBOX

mkdir -p /etc/systemd/system/cloudflared.service.d
cat > /etc/systemd/system/cloudflared.service.d/override.conf <<'CFD'
[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=3
CFD

systemctl daemon-reexec
systemctl daemon-reload

echo
echo ">>> 7. 放行 cloudflared Tunnel 出站 UDP/TCP 7844..."
iptables -C OUTPUT -p udp --dport 7844 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p udp --dport 7844 -j ACCEPT
iptables -C OUTPUT -p tcp --dport 7844 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p tcp --dport 7844 -j ACCEPT

netfilter-persistent save >/dev/null 2>&1 || true

echo
echo ">>> 8. 创建 cloudflared 固定 Tunnel QUIC 配置示例..."
mkdir -p /etc/cloudflared

cat > /etc/cloudflared/config.yml.example <<'CLOUDFLARED'
# 固定 Tunnel 建议模板
# 注意：这是示例，不会覆盖你的真实 /etc/cloudflared/config.yml
#
# tunnel: <你的固定 Tunnel UUID 或名称>
# credentials-file: /etc/cloudflared/<你的固定 Tunnel UUID>.json
# protocol: quic
#
# ingress:
#   - hostname: your-domain.example.com
#     service: http://127.0.0.1:你的本地 sing-box/ws 端口
#   - service: http_status:404
CLOUDFLARED

echo
echo ">>> 9. 生成统一检查脚本 /root/singbox-dual-check.sh ..."
cat > /root/singbox-dual-check.sh <<'CHECK'
#!/usr/bin/env bash

echo "============================================================"
echo " sing-box 直连 + CF 固定 Tunnel 状态检查"
echo "============================================================"

echo
echo ">>> 系统版本:"
cat /etc/os-release | grep -E 'PRETTY_NAME|VERSION=' || true

echo
echo ">>> 当前内核:"
uname -r

echo
echo ">>> BBR / fq:"
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.default_qdisc

echo
echo ">>> BBR 模块:"
lsmod | grep bbr || echo "未看到 tcp_bbr 模块；如果上面显示 bbr，通常也可用"

echo
echo ">>> 关键 TCP 参数:"
sysctl net.ipv4.tcp_slow_start_after_idle
sysctl net.ipv4.tcp_mtu_probing
sysctl net.ipv4.tcp_notsent_lowat
sysctl net.core.rmem_max
sysctl net.core.wmem_max

echo
echo ">>> 当前 shell nofile:"
ulimit -n

echo
echo ">>> systemd nofile:"
systemctl show --property=DefaultLimitNOFILE | cat

echo
echo ">>> sing-box 服务状态:"
systemctl is-active sing-box 2>/dev/null || echo "sing-box 暂未运行或未安装"

echo
echo ">>> cloudflared 服务状态:"
systemctl is-active cloudflared 2>/dev/null || echo "cloudflared 暂未运行或未安装"

echo
echo ">>> 7844 出站规则:"
iptables -S OUTPUT | grep 7844 || echo "未看到 7844 出站规则"

echo
echo ">>> Cloudflare Tunnel SRV DNS:"
dig +short _v2-origintunneld._tcp.argotunnel.com SRV || true

echo
echo ">>> UDP 7844 简单测试:"
timeout 3 bash -c 'cat < /dev/null > /dev/udp/quic.cftunnel.com/7844' 2>/dev/null \
  && echo "UDP 7844 基础测试：可能可用" \
  || echo "UDP 7844 无法确认；如果 cloudflared QUIC 失败，请检查 VPS 防火墙/机房出站 UDP"

echo
echo ">>> sing-box 最近日志:"
journalctl -u sing-box -n 20 --no-pager 2>/dev/null || true

echo
echo ">>> cloudflared 最近日志:"
journalctl -u cloudflared -n 20 --no-pager 2>/dev/null || true

echo
echo "============================================================"
echo " 检查完成"
echo "============================================================"
CHECK

chmod +x /root/singbox-dual-check.sh

echo
echo "============================================================"
echo " 双节点 28 优化完成"
echo "============================================================"
echo
echo "建议现在重启一次，让 nofile / systemd / sysctl 完整生效："
echo "  reboot"
echo
echo "重启后检查："
echo "  bash /root/singbox-dual-check.sh"
echo
echo "使用建议："
echo "  1. 直连 VLESS：走你的 VPS IP/域名，适合低延迟和速度测试"
echo "  2. CF Tunnel：走你的优选域名 + 固定 Tunnel，适合隐藏源站和稳定入口"
echo "  3. cloudflared 建议 protocol: quic"
echo "  4. 直连 VLESS 入站端口要在 VPS 安全组/防火墙放行"
echo "  5. 不建议再跑直连脚本和 CF 脚本，避免重复配置"
echo
EOF

chmod +x /root/singbox-dual-28.sh
bash /root/singbox-dual-28.sh
