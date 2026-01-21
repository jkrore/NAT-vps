# 1. 更新源并安装必要工具
apt update && apt install wget gnupg2 -y

# 2. 添加 XanMod 官方源
wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

# 3. 安装 v3 版本内核 (适配现代 CPU 指令集)
apt update && apt install linux-xanmod-x64v3 -y

# 4. 必须重启以加载新内核！
echo "内核安装完成，系统即将重启..."
reboot


cat > opt.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[+] $*${NC}"; }

log "开始系统核心调优..."

# 安装必要工具
apt update && apt install -y ethtool linux-cpupower

# 1. 写入系统参数 (BBRv3 + 8MB 稳健缓冲区)
cat > /etc/sysctl.d/99-sa-ultimate.conf <<CONF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 16384 8388608
net.netfilter.nf_conntrack_max = 262144
fs.file-max = 2097152
net.ipv4.tcp_fastopen = 3
vm.swappiness = 10
CONF
sysctl -p /etc/sysctl.d/99-sa-ultimate.conf

# 2. 关闭网卡硬件卸载 (修复虚拟化丢包的核心)
IFACE=$(ip -o route get 1.1.1.1 | awk '{print $5; exit}')
ethtool -K "$IFACE" tso off gso off gro off lro off ufo off 2>/dev/null || true

# 3. CPU 性能模式锁定
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    echo performance > "$cpu" 2>/dev/null || true
done

log "调优完成！网卡卸载已关闭，BBRv3 已激活。"
EOF

bash opt.sh


运行脚本
bash <(wget -qO- https://raw.githubusercontent.com/fscarmen/sing-box/main/sing-box.sh) -c
saas.sin.fan


bash <(cat <<EOF
#!/bin/bash
echo ">>> 部署直播专项优化策略..."

# 1. DNS 锁定 (防止华为云等重置)
chattr -i /etc/resolv.conf 2>/dev/null || true
apt install -y nscd iptables-persistent >/dev/null 2>&1
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
chattr +i /etc/resolv.conf

# 2. 流量规则清理与重塑
iptables -t mangle -F
iptables -F

# MSS 钳制 1360 (抗 Argo 隧道分片)
iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360

# 阻断 UDP 443 (强制 TikTok 走 TCP)
iptables -A OUTPUT -p udp --dport 443 -j DROP

# 持久化规则
netfilter-persistent save
echo "🎉 所有优化已完成！"
EOF
)







bash <(cat <<EOF
#!/bin/bash
# ==============================================================================
#   💎 TikTok 直播节点：修正版交付脚本 (去除风险项，保留核心优化)
#   保留：DNS锁 (抗云厂商重置) + MSS钳制 (抗隧道分片) + QUIC阻断 (强吃BBRv3红利)
#   移除：Warm-up (无效流量) + Renice (系统风险)
# ==============================================================================

# --- UI 颜色 ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "\${YELLOW}>>> 开始部署修正版优化策略...\${NC}"

# 1. 基础工具安装 (保留)
apt update -y >/dev/null 2>&1
DEBIAN_FRONTEND=noninteractive apt install -y nscd iptables-persistent dnsutils e2fsprogs >/dev/null 2>&1

# 2. DNS 锁定 (针对华为云必须保留)
# 先解锁以防万一
chattr -i /etc/resolv.conf >/dev/null 2>&1
# 配置 NSCD 缓存加速
sed -i 's/enable-cache\s\+hosts\s\+no/enable-cache hosts yes/' /etc/nscd.conf
systemctl enable nscd >/dev/null 2>&1
systemctl restart nscd >/dev/null 2>&1
# 写入国际通用 DNS 并锁定
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
chattr +i /etc/resolv.conf
echo -e "\${GREEN}[OK] DNS 已锁定并开启缓存 (防止华为云重置)\${NC}"

# 3. 交通管制 (针对 Argo 隧道必须保留)
# 清理旧规则
iptables -t mangle -F
iptables -F

# MSS 钳制 1360 (防止 Argo 隧道分片导致直播卡顿)
iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360

# 阻断 UDP 443 (强迫 TikTok 降级走 TCP，从而享受 BBRv3 加速)
iptables -A OUTPUT -p udp --dport 443 -j DROP
iptables -A FORWARD -p udp --dport 443 -j DROP

# 持久化规则
netfilter-persistent save >/dev/null 2>&1
echo -e "\${GREEN}[OK] MSS 已钳制(1360)，QUIC 已阻断(强制TCP)\${NC}"

# 4. 清理之前的“智商税”定时任务 (如果装过)
crontab -l 2>/dev/null | grep -v "warmup_pro.sh" | grep -v "boost_proxy.sh" | crontab -
rm -f /usr/local/bin/warmup_pro.sh
rm -f /usr/local/bin/boost_proxy.sh
echo -e "\${GREEN}[OK] 已清理无用的预热和提权脚本\${NC}"

echo -e "\n\${GREEN}🎉 优化完成！这是最稳健、副作用最小的方案。\${NC}"
EOF
)

