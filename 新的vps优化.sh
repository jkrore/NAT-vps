#!/bin/bash

echo "====== XanMod + BBR 稳定优化一键安装 ======"

# 1. 基础环境
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt install -y wget gnupg2 lsb-release curl

# 2. 添加 XanMod 源
echo ">>> 添加 XanMod 源..."
wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main" > /etc/apt/sources.list.d/xanmod-release.list

# 3. 安装内核（优先 v3）
echo ">>> 安装 XanMod 内核..."
apt update -y
if apt install -y linux-xanmod-x64v3; then
    echo "✔ 已安装 x64v3 内核"
else
    echo "⚠ CPU 不支持 v3，安装标准版..."
    apt install -y linux-xanmod-x64
fi

echo ">>> 请重启系统后再运行本脚本第二次以继续优化"
read -p "是否现在重启？(y/n): " reboot_now
if [[ "$reboot_now" == "y" ]]; then
    reboot
    exit 0
fi

# 4. 安装工具
echo ">>> 安装工具..."
apt install -y ethtool iptables-persistent dnsutils iputils-ping

# 5. 写入核心优化参数（稳定版）
echo ">>> 写入 sysctl 参数..."
rm -f /etc/sysctl.d/99-*.conf

cat > /etc/sysctl.d/99-xanmod-bbr.conf <<EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# 提升稳定性
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1

# 8MB buffer（4K够用）
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 16384 8388608

# 可选微优化
net.ipv4.tcp_notsent_lowat = 16384

fs.file-max = 1048576
EOF

sysctl --system

# 6. 验证状态
echo "====== 验证结果 ======"
echo "内核: $(uname -r)"
echo "BBR: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "QDISC: $(sysctl -n net.core.default_qdisc)"
echo "rmem_max: $(sysctl -n net.core.rmem_max)"
echo "wmem_max: $(sysctl -n net.core.wmem_max)"
echo "======================"

echo "✅ 完成！系统已优化到适合代理 + 4K 的稳定状态"
