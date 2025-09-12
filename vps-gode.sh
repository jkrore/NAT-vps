#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 6.0 (Apex Predator Edition)
#   Author: AI News Aggregator & Summarizer Expert
#   Description: 纯粹为极限性能而生。此脚本将线性执行所有已知的、激进的系统优化，
#                以求在有限的硬件资源上，压榨出每一滴性能。
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

# --- 核心函数 ---

# 0. 初始化与环境检查
initialize_environment() {
    log_info "Step 0: 初始化环境与安全检查"
    if [ "$(id -u)" -ne 0 ]; then log_error "此脚本必须以root用户权限运行。"; fi
    
    mkdir -p "$BACKUP_DIR"
    log_success "所有原始配置文件将备份至: $BACKUP_DIR"
    
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else log_error "无法检测到操作系统类型。"; fi
    log_success "检测到操作系统: $OS"
    
    read -p "您已阅读顶部的极度危险警告，并愿意承担所有风险吗? (输入 'yes' 继续): " confirmation
    if [[ "$confirmation" != "yes" ]]; then
        log_error "用户取消操作。脚本已中止。"
    fi
}

# 1. 更新软件包
update_packages() {
    log_info "Step 1: 更新系统软件包至最新版本"
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get upgrade -y ;;
        centos) yum update -y ;;
    esac
    log_success "软件包更新完成。"
}

# 2. 开启BBRv2/BBR+FQ网络加速
enable_bbr() {
    log_info "Step 2: 尝试开启BBR+FQ网络加速 (智能检查内核)"
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        log_success "BBR+FQ已处于开启状态。"; return
    fi
    main_ver=$(uname -r | cut -d. -f1); minor_ver=$(uname -r | cut -d. -f2)
    if [ "$main_ver" -ge 5 ]; then
        log_info "内核版本 ($(uname -r)) 较高，尝试启用 BBRv2 (如果可用)"
        add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr2"
    elif [ "$main_ver" -eq 4 ] && [ "$minor_ver" -ge 9 ]; then
        log_info "内核版本 ($(uname -r)) 符合要求，配置 BBR。"
        add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"
    else
        log_warn "内核版本 ($(uname -r)) 过低，无法开启BBR。请手动升级内核。"; return
    fi
    cp -a /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.bak"
    add_config "/etc/sysctl.conf" "net.core.default_qdisc=fq"
    sysctl -p
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then log_success "BBR/BBR2+FQ已成功开启！"; else log_warn "BBR开启失败。"; fi
}

# 3. 极限内核与内存优化
optimize_kernel_beast_mode() {
    log_info "Step 3: 应用极限内核、内存与文件句柄数优化"
    cp -a /etc/sysctl.conf "$BACKUP_DIR/sysctl.conf.bak"
    cat << EOF > /etc/sysctl.d/98-vps-beast-mode.conf
#--- Kernel Optimization by VPS-Optimizer v6.0 (Apex Predator) ---
# 极限文件句柄
fs.file-max=4194304
fs.nr_open=4194304

# 激进的网络核心参数
net.core.somaxconn=131072
net.core.rmem_max=67108864
net.core.wmem_max=67108864
net.core.netdev_max_backlog=131072

# 激进的TCP参数
net.ipv4.tcp_max_syn_backlog=131072
net.ipv4.tcp_rmem=4096 87380 67108864
net.ipv4.tcp_wmem=4096 65536 67108864
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_mtu_probing=1

# 极限内存与缓存策略
vm.swappiness=1
vm.vfs_cache_pressure=50
vm.overcommit_memory=1
vm.dirty_background_ratio=5
vm.dirty_ratio=10
EOF
    sysctl --system; log_success "极限内核参数已应用。"
    
    cp -a /etc/security/limits.conf "$BACKUP_DIR/limits.conf.bak"
    sed -i '/nofile/d' /etc/security/limits.conf
    echo -e "* soft nofile 4194304\n* hard nofile 4194304\nroot soft nofile 4194304\nroot hard nofile 4194304" >> /etc/security/limits.conf
    log_success "文件句柄数限制已提升至极限值。"
}

# 4. 极限CPU性能模式
optimize_cpu_governor() {
    log_info "Step 4: 开启极限CPU性能模式"
    case "$OS" in ubuntu|debian) apt-get install -y cpufrequtils ;; centos) yum install -y kernel-tools ;; esac
    if command -v cpupower >/dev/null 2>&1 && cpupower frequency-info | grep -q "performance"; then
        cpupower frequency-set -g performance
        log_success "所有CPU核心已强制设为 'performance' 模式。"
    else
        log_warn "未找到CPU调速工具或不支持 'performance' 模式。"
    fi
}

# 5. 极限磁盘I/O优化
optimize_io_extreme() {
    log_info "Step 5: 应用极限磁盘I/O优化"
    # 1. 永久化I/O调度器为none (noop)
    cat << EOF > /etc/udev/rules.d/60-io-scheduler.rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"
EOF
    udevadm control --reload-rules && udevadm trigger
    log_success "I/O调度器已通过udev规则永久设置为 'none' (noop)。"
    
    # 2. 优化文件系统挂载选项
    cp -a /etc/fstab "$BACKUP_DIR/fstab.bak"
    if ! grep -q 'noatime' /etc/fstab; then
        sed -i -E "s@(^/\S+\s+/\s+\w+\s+)(\S+)(.*)@\1\2,noatime,nodiratime\3@" /etc/fstab
        log_success "/etc/fstab 已更新，添加 'noatime,nodiratime'，重启后生效。"
    else
        log_warn "'noatime' 已存在，跳过。"
    fi
}

# 6. [专家级] 优化网络中断亲和性 (IRQ Affinity)
optimize_irq_affinity() {
    log_info "Step 6: [专家级] 尝试优化网络中断(IRQ)亲和性"
    local cpu_count
    cpu_count=$(nproc)
    if [ "$cpu_count" -le 1 ]; then
        log_warn "单核CPU，无需进行IRQ优化。"; return
    fi
    
    local eth_device
    eth_device=$(ip route | grep '^default' | awk '{print $5}' | head -1)
    if [ -z "$eth_device" ]; then
        log_warn "无法找到主网络设备。"; return
    fi
    
    local irq_list
    irq_list=$(grep "$eth_device" /proc/interrupts | awk '{print $1}' | tr -d ':')
    if [ -z "$irq_list" ]; then
        log_warn "无法找到网络设备 $eth_device 的中断号。"; return
    fi
    
    log_success "找到网络设备 $eth_device, CPU核心数: $cpu_count"
    local i=0
    for irq in $irq_list; do
        local cpu_mask
        cpu_mask=$(printf "%x" $((1 << (i % cpu_count))))
        echo "$cpu_mask" > "/proc/irq/$irq/smp_affinity"
        log_success "中断 #$irq 已绑定到 CPU$((i % cpu_count)) (掩码: $cpu_mask)"
        i=$((i + 1))
    done
    log_warn "IRQ亲和性设置重启后会失效，建议使用 irqbalance 服务或启动脚本持久化。"
}

# 7. 安装基础工具并清理系统
install_and_cleanup() {
    log_info "Step 7: 安装基础性能/安全工具并清理系统"
    # 安装工具
    case "$OS" in
        ubuntu|debian) apt-get install -y fail2ban haveged ;;
        centos) yum install -y epel-release && yum install -y fail2ban haveged tuned ;;
    esac
    systemctl enable --now fail2ban; log_success "Fail2ban已安装并启动。"
    systemctl enable --now haveged; log_success "Haveged已安装并启动。"
    if [ "$OS" == "centos" ]; then tuned-adm profile virtual-guest; systemctl enable --now tuned; log_success "Tuned已安装并设置为 'virtual-guest' 模式。"; fi
    
    # 清理系统
    case "$OS" in
        ubuntu|debian) apt-get autoremove -y && apt-get clean -y ;;
        centos) yum autoremove -y && yum clean all ;;
    esac
    journalctl --vacuum-size=10M; log_success "系统垃圾清理完成。"
}

# --- 主执行流程 ---
main() {
    initialize_environment
    update_packages
    enable_bbr
    optimize_kernel_beast_mode
    optimize_cpu_governor
    optimize_io_extreme
    optimize_irq_affinity
    install_and_cleanup
    
    echo -e "\n${GREEN}=============================================================${NC}"
    echo -e "${GREEN}      🚀 Apex Predator 优化已全部执行完毕! 🚀${NC}"
    echo -e "${YELLOW}=============================================================${NC}"
    log_warn "系统已进入极限性能模式。强烈建议您立即重启 (reboot)!"
    log_warn "重启后，请务必全面测试您的应用程序以确保其稳定性。"
}

main "$@"
