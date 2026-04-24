#!/bin/bash

echo "====== Step 1: 安装 XanMod 内核 ======"

export DEBIAN_FRONTEND=noninteractive

apt update -y && apt install -y wget gnupg2 lsb-release

echo ">>> 添加 XanMod 源..."
wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main" > /etc/apt/sources.list.d/xanmod-release.list

apt update -y

echo ">>> 安装 XanMod 内核..."
if apt install -y linux-xanmod-x64v3; then
    echo "✔ 已安装 x64v3 内核"
else
    echo "⚠ CPU 不支持 v3，安装标准版..."
    apt install -y linux-xanmod-x64
fi

echo ">>> 安装完成，准备重启..."
reboot




#!/bin/bash

echo "====== Step 2: BBR + 网络优化 ======"

# 1. 安装工具
apt update -y
apt install -y ethtool iptables-persistent dnsutils iputils-ping curl

# 2. 写入 sysctl
echo ">>> 写入优化参数..."
rm -f /etc/sysctl.d/99-*.conf

cat > /etc/sysctl.d/99-xanmod-bbr.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 稳定性优化
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# 8MB buffer（适合 4K）
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 16384 8388608

# 微优化（可选但推荐）
net.ipv4.tcp_notsent_lowat = 16384

fs.file-max = 1048576
EOF

sysctl --system

# 3. 验证
echo "====== 验证 ======"
echo "内核: $(uname -r)"
echo "BBR: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "QDISC: $(sysctl -n net.core.default_qdisc)"
echo "rmem_max: $(sysctl -n net.core.rmem_max)"
echo "wmem_max: $(sysctl -n net.core.wmem_max)"
echo "=================="

echo "✅ 优化完成！可以稳定跑代理 + 4K"













cat > /root/cf-singbox-argo-28.sh <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

echo "============================================================"
echo " Debian 13 + fscarmen/sing-box Argo Tunnel 28 优化"
echo " 场景：Cloudflare + cloudflared + 优选域名 + 固定 Tunnel"
echo " 用途：TikTok Live / YouTube Live / GPT / AI 产品"
echo "============================================================"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 root 用户执行：sudo -i"
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive

echo
echo ">>> 1. 更新系统并安装必要工具..."
apt update -y
apt install -y \
  curl wget ca-certificates gnupg lsb-release \
  iproute2 iptables iptables-persistent netfilter-persistent \
  dnsutils iputils-ping ethtool chrony procps jq unzip

echo
echo ">>> 2. 启用时间同步，避免 TLS / Cloudflare / AI 服务认证异常..."
systemctl enable --now chrony >/dev/null 2>&1 || true

echo
echo ">>> 3. 启用 BBR + fq..."
modprobe tcp_bbr 2>/dev/null || true
echo tcp_bbr > /etc/modules-load.d/bbr.conf

cat > /etc/sysctl.d/99-cf-singbox-argo-28.conf <<'SYSCTL'
# ============================================================
# Cloudflare + cloudflared + sing-box Argo Tunnel 28 优化
# 少改、有效、稳
# ============================================================

# 核心：BBR + fq
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 长连接稳定性
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# 适度 buffer，适合直播/视频/AI，不盲目堆大
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
echo ">>> 4. 设置 nofile，避免长期连接过多时受限..."
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

systemctl daemon-reexec

echo
echo ">>> 5. 放行 cloudflared QUIC / HTTP2 出站端口 7844..."
iptables -C OUTPUT -p udp --dport 7844 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p udp --dport 7844 -j ACCEPT
iptables -C OUTPUT -p tcp --dport 7844 -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p tcp --dport 7844 -j ACCEPT

netfilter-persistent save >/dev/null 2>&1 || true

echo
echo ">>> 6. 创建 cloudflared 固定 Tunnel QUIC 配置示例..."
mkdir -p /etc/cloudflared

cat > /etc/cloudflared/config.yml.example <<'CLOUDFLARED'
# 固定 Tunnel 建议模板
# 注意：这是示例，不会覆盖你现有 /etc/cloudflared/config.yml
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
echo ">>> 7. 写入服务级 override，提升 cloudflared / sing-box 进程限制..."

mkdir -p /etc/systemd/system/cloudflared.service.d
cat > /etc/systemd/system/cloudflared.service.d/override.conf <<'CFD'
[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=3
CFD

mkdir -p /etc/systemd/system/sing-box.service.d
cat > /etc/systemd/system/sing-box.service.d/override.conf <<'SINGBOX'
[Service]
LimitNOFILE=1048576
Restart=always
RestartSec=3
SINGBOX

systemctl daemon-reload

echo
echo ">>> 8. 生成检查脚本 /root/cf-singbox-argo-check.sh ..."
cat > /root/cf-singbox-argo-check.sh <<'CHECK'
#!/usr/bin/env bash

echo "============================================================"
echo " Cloudflare + sing-box Argo Tunnel 状态检查"
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
echo ">>> iptables 7844 出站规则:"
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
echo ">>> cloudflared 服务状态:"
systemctl is-active cloudflared 2>/dev/null || echo "cloudflared 暂未运行或未安装"

echo
echo ">>> sing-box 服务状态:"
systemctl is-active sing-box 2>/dev/null || echo "sing-box 暂未运行或未安装"

echo
echo ">>> cloudflared 最近日志，若存在:"
journalctl -u cloudflared -n 30 --no-pager 2>/dev/null || true

echo
echo "============================================================"
echo " 检查完成"
echo "============================================================"
CHECK

chmod +x /root/cf-singbox-argo-check.sh

echo
echo "============================================================"
echo " 28 优化完成"
echo "============================================================"
echo
echo "建议现在重启一次，让 nofile / systemd / sysctl 完整生效："
echo "  reboot"
echo
echo "重启后执行检查："
echo "  bash /root/cf-singbox-argo-check.sh"
echo
echo "后续 fscarmen/sing-box Argo 建议："
echo "  1. 用固定 Tunnel，不用随机 trycloudflare"
echo "  2. cloudflared 优先 protocol: quic"
echo "  3. 确认 VPS 厂商安全组也允许出站 UDP 7844"
echo "  4. 用你的优选域名作为客户端入口"
echo "  5. 不额外套 Worker / Pages / 多层反代"
echo
EOF

chmod +x /root/cf-singbox-argo-28.sh
bash /root/cf-singbox-argo-28.sh
