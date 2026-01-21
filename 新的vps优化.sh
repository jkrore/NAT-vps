# 1. 基础环境
export DEBIAN_FRONTEND=noninteractive
apt update -y && apt install -y wget gnupg2 lsb-release

# 2. 添加 XanMod 官方源
echo "正在添加 XanMod 源..."
wget -qO - https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list

# 3. 安装 v3 版本内核
echo "正在安装内核..."
apt update -y
# 智能回退机制：优先装v3，不行装标准版
if ! apt install -y linux-xanmod-x64v3; then
    echo "CPU不支持v3，降级安装标准版..."
    apt install -y linux-xanmod-x64
fi

echo "✅ 内核安装完成！请执行 'reboot' 重启系统。"


# 1. 安装工具
apt install -y ethtool iptables-persistent nscd dnsutils iputils-ping curl

# 2. 注入核心参数 (BBRv3 + 8MB 缓冲区)
# 作用：修复上传速度慢、网络抖动大
rm -f /etc/sysctl.d/99-*.conf
cat > /etc/sysctl.d/99-sa-ultimate.conf <<CONF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_slow_start_after_idle = 0
net.core.rmem_max = 8388608
net.core.wmem_max = 8388608
net.ipv4.tcp_rmem = 4096 87380 8388608
net.ipv4.tcp_wmem = 4096 16384 8388608
fs.file-max = 1048576
net.ipv4.tcp_mtu_probing = 1
CONF
sysctl -p /etc/sysctl.d/99-sa-ultimate.conf

# 3. 修复虚拟化丢包 (写入开机自启)
# 作用：修复 16% 的物理丢包
IFACE=$(ip -o route get 1.1.1.1 | awk '{print $5; exit}')
# 立即执行一次
ethtool -K "$IFACE" tso off gso off gro off lro off ufo off 2>/dev/null || true

# 写入服务文件
cat > /etc/systemd/system/nic-fix.service <<SERVICE
[Unit]
Description=Fix VirtIO Packet Loss
After=network.target
[Service]
Type=oneshot
ExecStart=/sbin/ethtool -K $IFACE tso off gso off gro off lro off ufo off
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
SERVICE

# 激活服务
systemctl daemon-reload
systemctl enable nic-fix.service
systemctl start nic-fix.service

echo "✅ 系统参数与网卡修复已完成！"

# 1. 清理旧规则
iptables -F
iptables -t mangle -F

# 2. MSS 钳制 1360 (Argo 防卡顿核心)
iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1360

# 3. 阻断 UDP 443 (强制 TikTok 走 TCP BBR)
iptables -A OUTPUT -p udp --dport 443 -j DROP
iptables -A FORWARD -p udp --dport 443 -j DROP

# 4. 持久化规则
netfilter-persistent save

# 5. 锁定 DNS (防止华为云重置)
chattr -i /etc/resolv.conf 2>/dev/null || true
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 8.8.8.8" >> /etc/resolv.conf
chattr +i /etc/resolv.conf

echo "✅ 业务防火墙规则已部署！"


# 自动带入优选域名参数 -c saas.sin.fan
bash <(wget -qO- https://raw.githubusercontent.com/fscarmen/sing-box/main/sing-box.sh) -c saas.sin.fan




clear
echo "------ 广新专线最终验收 ------"
echo "1. 内核: $(uname -r) (必须包含 xanmod)"
echo "2. 网卡: $(ethtool -k $(ip -o route get 1 | awk '{print $5}') | grep tcp-segmentation | awk '{print $2}') (必须是 off)"
echo "3. BBR : $(sysctl -n net.ipv4.tcp_congestion_control)"
echo "4. 规则: $(iptables -t mangle -L OUTPUT -n | grep 1360 | wc -l) 条 MSS 规则"
echo "------------------------------"
