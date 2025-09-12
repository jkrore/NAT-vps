#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 8.0 (Final Synthesis Edition)
#   Author: AI News Aggregator & Summarizer Expert
#   Description: 最终合成版。融合了v7.0的极限性能框架，并吸收了SKY-BOX和taurusxin脚本
#                在DNS/NTP、内核参数全面性、配置持久化等方面的全部优点。
#                这是我们追求极致性能之旅的最终章。
#
#   !!! 极度危险警告 !!!
#   此脚本会进行非常规且激进的系统修改，可能导致系统不稳定、数据丢失或无法启动。
#   仅用于测试环境或您完全了解其后果的场景。
#   在生产环境中使用前，必须、必须、必须进行完整备份！
#===============================================================================================

# --- 全局设置与工具函数 ---
set -eo pipefail
BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "\n${CYAN}>>> $1${NC}"; }
log_success() { echo -e "${GREEN}✔ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
log_error() { echo -e "${RED}✖ $1${NC}"; exit 1; }
add_config() { local file=$1; local config=$2; if ! grep -qF -- "$config" "$file"; then echo "$config" >> "$file"; fi; }

# --- 核心函数 ---

# 0. 初始化与环境检查
initialize_environment() {
    log_info "Step 0: 初始化环境与安全检查"
    if [ "$(id -u)" -ne 0 ]; then log_error "此脚本必须以root用户权限运行。"; fi
    mkdir -p "$BACKUP_DIR"; log_success "所有原始配置文件将备份至: $BACKUP_DIR"
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else log_error "无法检测到操作系统类型。"; fi
    log_success "检测到操作系统: $OS"
    
    log_info "正在检测服务器地理位置..."
    local location_info; location_info=$(curl -s http://ip-api.com/json/)
    if [[ -z "$location_info" ]]; then log_warn "无法获取地理位置信息，将使用默认国际配置。"; IS_IN_CHINA="false"; else local country_code; country_code=$(echo "$location_info" | grep -o '"countryCode":"[^"]*' | cut -d'"' -f4); if [ "$country_code" = "CN" ]; then log_success "检测到服务器位于中国。"; IS_IN_CHINA="true"; else log_success "检测到服务器位于海外 ($country_code)。"; IS_IN_CHINA="false"; fi; fi
    
    read -p "您已阅读顶部的极度危险警告，并愿意承担所有风险吗? (输入 'yes' 继续): " confirmation
    if [[ "$confirmation" != "yes" ]]; then log_error "用户取消操作。脚本已中止。"; fi
}

# 1. 更新软件包并安装核心工具
install_core_tools() {
    log_info "Step 1: 更新软件包并安装核心工具 (chrony, fail2ban, haveged...)"
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get upgrade -y && apt-get install -y curl chrony fail2ban haveged cpufrequtils ;;
        centos) yum update -y && yum install -y epel-release && yum install -y curl chrony fail2ban haveged kernel-tools ;;
    esac
    log_success "核心工具安装与系统更新完成。"
}

# 2. [融合] 智能创建Swap + 配置最低延迟DNS/NTP
configure_basics() {
    log_info "Step 2: 智能创建Swap并配置最低延迟DNS/NTP"
    # 创建Swap
    if [ "$(swapon --show | wc -l)" -le 1 ]; then local MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}'); local SWAP_SIZE_MB=$((MEM_TOTAL_MB * 2)); log_info "物理内存: ${MEM_TOTAL_MB}MB, 计划创建Swap: ${SWAP_SIZE_MB}MB"; read -p "是否创建Swap文件? (y/n): " choice; if [[ "$choice" == "y" || "$choice" == "Y" ]]; then cp -a /etc/fstab "$BACKUP_DIR/fstab.swap.bak"; fallocate -l "${SWAP_SIZE_MB}M" /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile; add_config "/etc/fstab" "/swapfile none swap sw 0 0"; log_success "Swap创建成功！"; fi; else log_warn "检测到已存在的Swap，跳过创建。"; fi
    
    # 配置DNS
    cp -a /etc/resolv.conf "$BACKUP_DIR/resolv.conf.bak"; chattr -i /etc/resolv.conf 2>/dev/null || true
    if [ "$IS_IN_CHINA" = "true" ]; then echo -e "options timeout:1 attempts:2 rotate\nnameserver 223.5.5.5\nnameserver 119.29.29.29\nnameserver 180.76.76.76" > /etc/resolv.conf; log_success "已配置国内DNS。"; else echo -e "options timeout:1 attempts:2 rotate\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9" > /etc/resolv.conf; log_success "已配置国际DNS。"; fi
    chattr +i /etc/resolv.conf 2>/dev/null || true
    
    # 配置NTP (chrony)
    cp -a /etc/chrony/chrony.conf "$BACKUP_DIR/chrony.conf.bak" 2>/dev/null || cp -a /etc/chrony.conf "$BACKUP_DIR/chrony.conf.bak" 2>/dev/null || true
    if [ "$IS_IN_CHINA" = "true" ]; then echo -e "server ntp.aliyun.com iburst\nserver ntp.tencent.com iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync" > /etc/chrony/chrony.conf; else echo -e "pool pool.ntp.org iburst\npool time.google.com iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync" > /etc/chrony/chrony.conf; fi
    systemctl enable --now chronyd 2>/dev/null || systemctl enable --now chrony 2>/dev/null; log_success "已使用chrony配置NTP时间同步。"
}

# 3. [融合] 极限内核与系统限制优化
optimize_kernel_and_limits() {
    log_info "Step 3: 应用极限内核与系统限制优化 (融合版)"
    # 开启BBR
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then main_ver=$(uname -r | cut -d. -f1); if [ "$main_ver" -ge 5 ]; then add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr2"; else add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"; fi; add_config "/etc/sysctl.conf" "net.core.default_qdisc=fq"; fi
    
    # 写入极限内核参数
    cp -a /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.bak"
    cat << EOF > /etc/sysctl.d/97-vps-final-synthesis.conf
#--- Kernel Optimization by VPS-Optimizer v8.0 (Final Synthesis) ---
# 文件句柄与inotify
fs.file-max=5120000; fs.nr_open=5120000; fs.inotify.max_user_instances=8192; fs.inotify.max_user_watches=524288
# 极限网络核心参数
net.core.somaxconn=131072; net.core.rmem_max=67108864; net.core.wmem_max=67108864; net.core.netdev_max_backlog=131072
# 激进TCP参数
net.ipv4.tcp_max_syn_backlog=131072; net.ipv4.tcp_rmem=4096 87380 67108864; net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_syncookies=1; net.ipv4.tcp_fastopen=3; net.ipv4.tcp_tw_reuse=1; net.ipv4.tcp_fin_timeout=10; net.ipv4.tcp_mtu_probing=1
# 极限内存与缓存策略
vm.swappiness=1; vm.vfs_cache_pressure=50; vm.overcommit_memory=1; vm.min_free_kbytes=65536
# IPv4优先
precedence ::ffff:0:0/96  100
EOF
    # 补充gai.conf
    add_config "/etc/gai.conf" "precedence ::ffff:0:0/96  100"
    sysctl --system; log_success "极限内核参数已应用。"
    
    # 写入极限系统限制
    cp -a /etc/security/limits.conf "$BACKUP_DIR/limits.conf.bak"
    echo -e "* soft nofile 5120000\n* hard nofile 5120000\nroot soft nofile 5120000\nroot hard nofile 5120000" > /etc/security/limits.conf
    log_success "文件句柄数限制已提升至极限值。"
}

# 4. [融合] 极限硬件性能优化 (CPU/IO/IRQ)
optimize_hardware_performance() {
    log_info "Step 4: 应用极限硬件性能优化 (CPU/IO/IRQ)"
    # CPU Governor
    if command -v cpupower >/dev/null 2>&1 && cpupower frequency-info | grep -q "performance"; then cpupower frequency-set -g performance; log_success "CPU已设为 'performance' 模式。"; else log_warn "未找到CPU调速工具或不支持。"; fi
    # IO Scheduler
    cat << EOF > /etc/udev/rules.d/60-io-scheduler.rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"
EOF
    udevadm control --reload-rules && udevadm trigger; log_success "I/O调度器已永久设为 'none'。"
    # fstab noatime
    if ! grep -q 'noatime' /etc/fstab; then cp -a /etc/fstab "$BACKUP_DIR/fstab.io.bak"; sed -i -E "s@(^/\S+\s+/\s+\w+\s+)(\S+)(.*)@\1\2,noatime,nodiratime\3@" /etc/fstab; log_success "/etc/fstab 已添加 'noatime'。"; fi
    # IRQ Affinity
    local cpu_count=$(nproc); if [ "$cpu_count" -gt 1 ]; then local eth_device=$(ip route | grep '^default' | awk '{print $5}' | head -1); if [ -n "$eth_device" ]; then local irq_list=$(grep "$eth_device" /proc/interrupts | awk '{print $1}' | tr -d ':'); if [ -n "$irq_list" ]; then local i=0; for irq in $irq_list; do echo $(printf "%x" $((1 << (i % cpu_count)))) > "/proc/irq/$irq/smp_affinity"; i=$((i + 1)); done; log_success "网络中断(IRQ)已尝试绑定到多核CPU。"; fi; fi; fi
}

# 5. [融合] 系统服务配置与清理
configure_services_and_cleanup() {
    log_info "Step 5: 配置系统服务、持久化并清理系统"
    # 配置rc.local
    cat << EOF > /etc/rc.local
#!/bin/bash
sysctl -p >/dev/null 2>&1
exit 0
EOF
    chmod +x /etc/rc.local
    if [ ! -f /etc/systemd/system/rc-local.service ]; then cat << EOF > /etc/systemd/system/rc-local.service
[Unit]
Description=/etc/rc.local Compatibility
[Service]
ExecStart=/etc/rc.local start
[Install]
WantedBy=multi-user.target
EOF
    fi
    systemctl enable rc-local.service; log_success "rc.local持久化已配置。"
    
    # 启用核心服务
    systemctl enable --now fail2ban; log_success "Fail2ban已启动。"
    systemctl enable --now haveged; log_success "Haveged已启动。"
    if [ "$OS" == "centos" ]; then tuned-adm profile virtual-guest; systemctl enable --now tuned; log_success "Tuned已设为 'virtual-guest' 模式。"; fi
    
    # 清理
    case "$OS" in ubuntu|debian) apt-get autoremove -y && apt-get clean -y ;; centos) yum autoremove -y && yum clean all ;; esac
    journalctl --vacuum-size=10M; log_success "系统垃圾清理完成。"
}

# --- 主执行流程 ---
main() {
    initialize_environment
    install_core_tools
    configure_basics
    optimize_kernel_and_limits
    optimize_hardware_performance
    configure_services_and_cleanup
    
    echo -e "\n${GREEN}=============================================================${NC}"
    echo -e "${GREEN}      🚀 Final Synthesis 优化已全部执行完毕! 🚀${NC}"
    echo -e "${YELLOW}=============================================================${NC}"
    log_warn "系统已进入极限性能模式。强烈建议您立即重启 (reboot)!"
    log_warn "重启后，请务必全面测试您的应用程序以确保其稳定性。"
}

main "$@"
