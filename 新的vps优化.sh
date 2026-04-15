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
