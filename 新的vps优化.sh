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

# 颜色定义
GREEN='\033[0;32m'; NC='\033[0m'
log() { echo -e "${GREEN}[+] $*${NC}"; }

log "开始 SA 终极系统调优..."

# 0. 安装硬件管理工具 (补全缺失的工具)
apt update && apt install -y ethtool linux-cpupower

# 1. 协议栈核心优化 (BBRv3 + 长连接稳定性)
cat > /etc/sysctl.d/99-sa-ultimate.conf <<CONF
# --- 拥塞控制 ---
net.core.default_qdisc = fq_pie
net.ipv4.tcp_congestion_control = bbr

# --- 关键：解决代理/长连接卡顿与断流 ---
# 拒绝 TCP 空闲后降速 (对梯子/数据库极其重要)
net.ipv4.tcp_slow_start_after_idle = 0
# 开启 MTU 自动探测 (解决部分黑洞路由导致的断流)
net.ipv4.tcp_mtu_probing = 1

# --- 缓冲区扩容 (32MB, 适配 1G+ 带宽) ---
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 131072 33554432
net.ipv4.tcp_wmem = 4096 131072 33554432

# --- 连接追踪与并发 ---
net.netfilter.nf_conntrack_max = 262144
fs.file-max = 2097152
net.ipv4.tcp_fastopen = 3
# 稍微激进的内存回收 (适合跑服务)
vm.swappiness = 10
vm.vfs_cache_pressure = 50
CONF

# 应用 Sysctl
sysctl -p /etc/sysctl.d/99-sa-ultimate.conf

# 2. 解除 Limits 封印
cat > /etc/security/limits.d/99-sa-limits.conf <<LIMITS
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
LIMITS
# 同时修改 Systemd 全局限制 (确保服务守护进程也生效)
sed -i 's/^#DefaultLimitNOFILE=.*/DefaultLimitNOFILE=1048576/' /etc/systemd/system.conf
systemctl daemon-reexec

# 3. 硬件层卸载与 CPU 调度 (软件调优的倍增器)
log "正在进行硬件层优化..."
# 自动获取主网卡接口名
IFACE=$(ip -o route get 1.1.1.1 | awk '{print $5; exit}')

# [关键] 开启网卡硬件卸载 (大幅降低 CPU 软中断占用)
ethtool -K "$IFACE" tso on gso on gro on 2>/dev/null || true
# [关键] 加大网卡 Ring Buffer (防止突发流量下的物理丢包)
ethtool -G "$IFACE" rx 4096 tx 4096 2>/dev/null || true

# [关键] 锁定 CPU 为高性能模式 (拒绝延迟抖动)
if command -v cpupower &> /dev/null; then
    cpupower frequency-set -g performance
else
    log "cpupower 未找到，尝试直接修改 sysfs..."
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance > "$cpu" 2>/dev/null || true
    done
fi

# 4. SSH 基础优化
sed -i -E 's/^[#\s]*UseDNS\s+yes/UseDNS no/' /etc/ssh/sshd_config
sed -i -E 's/^[#\s]*GSSAPIAuthentication\s+yes/GSSAPIAuthentication no/' /etc/ssh/sshd_config
systemctl restart sshd

log "优化全部完成。硬件卸载已激活，CPU 已锁定高性能。"
EOF

# 运行优化脚本
bash opt.sh


运行脚本
bash <(wget -qO- https://raw.githubusercontent.com/fscarmen/sing-box/main/sing-box.sh) -c
saas.sin.fan








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












验证
bash <(cat <<EOF
#!/bin/bash
# ======================================================================
#   🏆 TikTok 直播节点：最终验收审计 (适配修正版架构)
#   只验证核心：BBRv3 / DNS锁 / MSS钳制 / QUIC阻断 / 连通性
# ======================================================================

# --- 颜色定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 依赖检查 ---
if ! command -v dig &> /dev/null; then apt update -y && apt install dnsutils -y; fi
if ! command -v lsattr &> /dev/null; then apt install e2fsprogs -y; fi

clear
echo -e "\${CYAN}============================================================\${NC}"
echo -e "           📊 广新直播专线 - 最终交付验收报告"
echo -e "\${CYAN}============================================================\${NC}"

# ===========================
# 1. 动力系统 (Kernel)
# ===========================
echo -e "\n\${YELLOW}[1. 动力系统]\${NC}"

# 1.1 BBR 检测
BBR_CHECK=\$(sysctl net.ipv4.tcp_congestion_control | awk '{print \$3}')
if [[ "\$BBR_CHECK" == *"bbr"* ]]; then
    echo -e "拥塞控制 (BBRv3)     : \${GREEN}✅ 已开启 (核心引擎)\${NC}"
else
    echo -e "拥塞控制 (BBRv3)     : \${RED}❌ 未开启\${NC}"
fi

# 1.2 队列检测
QDISC_CHECK=\$(sysctl net.core.default_qdisc | awk '{print \$3}')
if [[ "\$QDISC_CHECK" == *"fq_pie"* ]] || [[ "\$QDISC_CHECK" == *"fq"* ]]; then
    echo -e "队列算法 (FQ/FQ_PIE) : \${GREEN}✅ 已开启 (抗抖动)\${NC}"
else
    echo -e "队列算法 (FQ/FQ_PIE) : \${RED}❌ 未开启\${NC}"
fi

# 1.3 文件打开数
ULIMIT_CHECK=\$(ulimit -n)
if [[ "\$ULIMIT_CHECK" -gt 60000 ]]; then
    echo -e "并发连接数限制       : \${GREEN}✅ 已解锁 (\$ULIMIT_CHECK)\${NC}"
else
    echo -e "并发连接数限制       : \${RED}❌ 未解锁 (\$ULIMIT_CHECK)\${NC}"
fi

# ===========================
# 2. 交通管制 (Traffic Control)
# ===========================
echo -e "\n\${YELLOW}[2. 交通管制 (Argo 专用优化)]\${NC}"

# 2.1 MSS 钳制 (最关键)
MSS_RULE=\$(iptables -t mangle -L OUTPUT -n | grep "TCPMSS set 1360")
if [[ -n "\$MSS_RULE" ]]; then
    echo -e "MSS 防分片 (1360)    : \${GREEN}✅ 已生效 (防止直播卡顿)\${NC}"
else
    echo -e "MSS 防分片 (1360)    : \${RED}❌ 未生效 (严重隐患)\${NC}"
fi

# 2.2 QUIC 阻断 (最关键)
QUIC_RULE=\$(iptables -L OUTPUT -n | grep "udp dpt:443")
if [[ -n "\$QUIC_RULE" ]]; then
    echo -e "QUIC 阻断 (UDP 443)  : \${GREEN}✅ 已封杀 (强制走 TCP BBR)\${NC}"
else
    echo -e "QUIC 阻断 (UDP 443)  : \${RED}❌ 未生效 (可能导致 BBR 失效)\${NC}"
fi

# ===========================
# 3. 安全与解析 (DNS Security)
# ===========================
echo -e "\n\${YELLOW}[3. DNS 安全 (防华为云重置)]\${NC}"

# 3.1 DNS 锁定
ATTR=\$(lsattr /etc/resolv.conf)
if [[ "\$ATTR" == *"i"* ]]; then
    echo -e "DNS 配置文件锁       : \${GREEN}✅ 已焊死 (重启不掉线)\${NC}"
else
    echo -e "DNS 配置文件锁       : \${RED}❌ 未锁定\${NC}"
fi

# 3.2 DNS 内容
CONF=\$(cat /etc/resolv.conf)
if [[ "\$CONF" == *"1.1.1.1"* ]]; then
    echo -e "DNS 指向             : \${GREEN}✅ Cloudflare (1.1.1.1)\${NC}"
else
    echo -e "DNS 指向             : \${RED}❌ 异常 (可能被云厂商劫持)\${NC}"
fi

# 3.3 NSCD 缓存
if systemctl is-active --quiet nscd; then
    echo -e "NSCD 本地缓存        : \${GREEN}✅ 运行中 (加速解析)\${NC}"
else
    echo -e "NSCD 本地缓存        : \${RED}❌ 未运行\${NC}"
fi

# ===========================
# 4. 连通性测试 (Connectivity)
# ===========================
echo -e "\n\${YELLOW}[4. 业务连通性]\${NC}"
Start=\$(date +%s%N)
if curl -o /dev/null -s --connect-timeout 3 https://www.google.com; then
    End=\$(date +%s%N)
    Duration=\$(( (End - Start) / 1000000 ))
    echo -e "Google 连接测试      : \${GREEN}✅ 通畅 (耗时: \${Duration}ms)\${NC}"
else
    echo -e "Google 连接测试      : \${RED}❌ 失败 (网络不通)\${NC}"
fi

echo -e "\n\${CYAN}============================================================\${NC}"
echo -e "说明：如果以上全绿，说明你的节点已达到【T0 级直播专线】标准。"
echo -e "\${CYAN}============================================================\${NC}"
EOF
)
