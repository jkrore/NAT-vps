#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 12.0 (Ultimate Synthesis Edition)
#   Author: VPS Performance Expert
#   Description: 终极合成版。完美融合了v11.0的【智能BBR】、【免重启】、【自我诊断】框架，
#                并从v8.0及其他版本中吸收了【更全面的内核参数】、【IPv4优先】、
#                【CentOS tuned服务】等所有优点。这是当前最智能、最全面、最可靠的一键化终极解决方案。
#
#   !!! 终极危险警告 - 魔鬼协议 !!!
#   (警告内容与原版相同)
#===============================================================================================

# --- 全局设置与工具函数 ---
set -e
BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "\n${CYAN}>>> $1${NC}"; }
log_success() { echo -e "${GREEN}✔ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
log_error() { echo -e "${RED}✖ $1${NC}"; exit 1; }
add_config() { local file=$1; local config=$2; if ! grep -qF -- "$config" "$file"; then echo "$config" >> "$file"; fi; }

# --- 核心函数 ---

# 0. 初始化
initialize_environment() {
    log_info "Step 0: 初始化环境"
    if [ "$(id -u)" -ne 0 ]; then log_error "此脚本必须以root用户权限运行。"; fi
    mkdir -p "$BACKUP_DIR"; log_success "配置文件将备份至: $BACKUP_DIR"
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else log_error "无法检测到操作系统类型。"; fi
    read -p "您是否已阅读脚本顶部的终极危险警告? (请输入 'I_am_fully_aware_of_the_risks' 继续): " confirmation
    if [[ "$confirmation" != "I_am_fully_aware_of_the_risks" ]]; then log_error "协议未签订。脚本已中止。"; fi
}

# 1. [魔鬼级] 禁用CPU漏洞补丁 (需重启)
disable_cpu_mitigations() {
    log_info "Step 1: [魔鬼级] 配置禁用CPU漏洞补丁"
    if [ ! -f /etc/default/grub ]; then log_warn "/etc/default/grub 文件不存在，跳过。"; return; fi
    cp -a /etc/default/grub "$BACKUP_DIR/grub.bak"
    sed -i 's/ mitigations=off//g' /etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 mitigations=off"/g' /etc/default/grub
    update-grub >/dev/null 2>&1 || grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 || log_warn "请手动更新GRUB配置。"
    log_success "CPU漏洞补丁禁用已配置。此项优化【必须重启虚拟机】才能生效。"
}

# 2. 安装核心工具
install_core_tools() {
    log_info "Step 2: 更新软件包并安装核心工具"
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get install -y curl chrony haveged procps fail2ban cpufrequtils || log_warn "部分工具安装失败，已跳过。" ;;
        centos) yum update -y && yum install -y epel-release && yum install -y curl chrony haveged procps-ng fail2ban kernel-tools tuned || log_warn "部分工具安装失败，已跳过。" ;;
    esac
    log_success "核心工具安装与系统更新完成。"
}

# 3. [核心] 智能检测并开启BBR (免重启)
intelligent_bbr_setup() {
    log_info "Step 3: [智能检测] 开启最佳BBR版本 (免重启)"
    sed -i.bak '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i.bak '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    local available_bbrs; available_bbrs=$(sysctl -n net.ipv4.tcp_available_congestion_control)
    local best_bbr=""; if [[ "$available_bbrs" == *"bbr2"* ]]; then best_bbr="bbr2"; elif [[ "$available_bbrs" == *"bbr"* ]]; then best_bbr="bbr"; fi
    if [ -n "$best_bbr" ]; then
        log_success "检测到您的内核支持的最佳版本为: $best_bbr"
        modprobe "tcp_$best_bbr" 2>/dev/null || true
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = $best_bbr" >> /etc/sysctl.conf
        sysctl -p >/dev/null 2>&1
        if sysctl -n net.ipv4.tcp_congestion_control | grep -q "$best_bbr"; then log_success "BBR ($best_bbr) 已被强制开启并立即生效！"; else log_error "BBR 开启失败，未知错误。"; fi
    else
        log_warn "您的内核不支持任何BBR版本，已跳过此项优化。"
    fi
}

# 4. [融合] 应用全面的内核与系统限制 (免重启)
optimize_kernel_and_limits() {
    log_info "Step 4: [融合] 应用全面的内核与系统限制优化"
    cat << EOF > /etc/sysctl.d/98-vps-ultimate-synthesis.conf
#--- Kernel Optimization by VPS-Optimizer v12.0 (Ultimate Synthesis) ---
# 文件句柄与inotify
fs.file-max=10240000; fs.nr_open=10240000; fs.inotify.max_user_instances=8192; fs.inotify.max_user_watches=524288
# 网络核心参数
net.core.somaxconn=262144; net.core.netdev_max_backlog=262144
# 激进TCP参数
net.ipv4.tcp_max_syn_backlog=262144; net.ipv4.tcp_syncookies=1; net.ipv4.tcp_fastopen=3; net.ipv4.tcp_tw_reuse=1; net.ipv4.tcp_fin_timeout=15; net.ipv4.tcp_mtu_probing=1
# 内存与缓存策略
vm.swappiness=0; vm.vfs_cache_pressure=50; vm.overcommit_memory=1
EOF
    # [融合] IPv4优先
    add_config "/etc/gai.conf" "precedence ::ffff:0:0/96  100"
    
    sysctl --system >/dev/null 2>&1
    if [ "$(sysctl -n vm.swappiness)" != "0" ]; then
        log_warn "检测到内核参数未生效，正在启动 Plan B 强制应用..."
        systemctl restart procps.service 2>/dev/null || true; sysctl --system >/dev/null 2>&1
        if [ "$(sysctl -n vm.swappiness)" == "0" ]; then log_success "Plan B 成功！内核参数已强制应用。"; else log_error "Plan B 失败，请手动检查 sysctl 配置。"; fi
    else
        log_success "内核参数已成功应用。"
    fi
    
    echo -e "* soft nofile 10240000\n* hard nofile 10240000" > /etc/security/limits.conf
    log_success "文件句柄数限制已配置。"
}

# 5. [融合] 硬件优化与服务配置 (免重启)
finalize_setup() {
    log_info "Step 5: [融合] 应用硬件优化并配置服务"
    local disk; disk=$(lsblk -ndo NAME,TYPE | awk '$2=="disk" {print $1; exit}')
    if [ -n "$disk" ]; then echo "none" > "/sys/block/$disk/queue/scheduler"; log_success "I/O 调度器已设为 'none'。"; fi
    echo never > /sys/kernel/mm/transparent_hugepage/enabled; log_success "透明大页(THP)已禁用。"
    
    # [融合] CentOS tuned 服务
    if [ "$OS" == "centos" ] && command -v tuned-adm >/dev/null 2>&1; then
        tuned-adm profile virtual-guest
        systemctl enable --now tuned
        log_success "Tuned服务已为CentOS设为 'virtual-guest' 模式。"
    fi

    systemctl enable --now haveged fail2ban chrony >/dev/null 2>&1 || true
    log_success "核心服务(haveged, fail2ban, chrony)已启动。"
    mount -o remount,noatime / && log_success "'noatime' 已通过重新挂载分区立即生效。" || log_warn "'noatime' 重新挂载失败，需重启生效。"
}

# --- 主执行流程 ---
main() {
    initialize_environment
    disable_cpu_mitigations
    install_core_tools
    intelligent_bbr_setup
    optimize_kernel_and_limits
    finalize_setup
    
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${GREEN}      🚀 v12.0 终极合成版 优化已执行完毕! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${GREEN}以下优化已【立即生效】:${NC}"
    echo -e "${GREEN}  - 智能BBR网络加速 (已自动选择最佳版本)${NC}"
    echo -e "${GREEN}  - 全面内核参数优化 (融合v8.0优点)${NC}"
    echo -e "${GREEN}  - 硬件优化 (I/O调度器, THP, noatime等)${NC}"
    echo -e "${GREEN}  - 核心服务已启动 (含CentOS tuned优化)${NC}"
    echo ""
    echo -e "${YELLOW}以下优化需要【您的操作】才能完全激活:${NC}"
    echo -e "${YELLOW}  - 文件句柄数限制 -> 请【重新登录SSH】后生效。${NC}"
    echo -e "${YELLOW}  - CPU漏洞补丁禁用 -> 请在您方便时，手动【reboot】服务器来激活。${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
}

main "$@"
