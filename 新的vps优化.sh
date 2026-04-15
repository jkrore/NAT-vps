# 1. 基础环境准备
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt install -y wget gnupg2 lsb-release

# 2. 添加 XanMod 官方源
echo "正在添加 XanMod 源..."
wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

# 3. 安装 v3 版本内核
echo "正在安装内核..."
apt update -y
# 智能安装：优先装 v3，不支持则装标准版
if ! apt install -y linux-xanmod-x64v3; then
    echo "CPU 不支持 v3，降级安装标准版..."
    apt install -y linux-xanmod-x64
fi

echo "✅ 内核安装完成！正在重启系统..."
reboot


# 1. 安装必要工具
apt install -y ethtool iptables-persistent nscd dnsutils iputils-ping curl

# 2. 写入内核参数 (BBRv3 + 8MB 缓冲区)
rm -f /etc/sysctl.d/99-*.conf
cat > /etc/sysctl.d/99-sa-ultimate.conf <<CONF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
# 8MB 缓冲区：适合 4K 视频，防止延迟抖动
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 16384 8388608
fs.file-max = 1048576
net.ipv4.tcp_mtu_probing = 1
CONF
sysctl -p /etc/sysctl.d/99-sa-ultimate.conf






echo "BBR: $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "QDISC: $(sysctl -n net.core.default_qdisc)"
echo "rmem_max: $(sysctl -n net.core.rmem_max)"
echo "wmem_max: $(sysctl -n net.core.wmem_max)"
