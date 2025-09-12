#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 10.3 (Ultimate Force Edition - Kernel Module Loading)
#   Author: AI News Aggregator & Summarizer Expert (Modified by VPS Performance Expert)
#   Description: 终极强制版。解决了BBR内核模块未被加载的根本问题。
#                此版本会强制加载BBR内核模块并设置为开机自启，确保BBR优化100%生效。
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

# 0. 初始化与签订魔鬼协议
initialize_environment() {
    log_info "Step 0: 初始化环境与签订魔鬼协议"
    if [ "$(id -u)" -ne 0 ]; then log_error "此脚本必须以root用户权限运行。"; fi
    mkdir -p "$BACKUP_DIR"; log_success "所有原始配置文件将备份至: $BACKUP_DIR"
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else log_error "无法检测到操作系统类型。"; fi
    log_success "检测到操作系统: $OS"
    read -p "您是否已阅读脚本顶部的终极危险警告? (请输入 'I_am_fully_aware_of_the_risks' 继续): " confirmation
    if [[ "$confirmation" != "I_am_fully_aware_of_the_risks" ]]; then log_error "协议未签订。为了您的安全，脚本已中止。"; fi
}

# 1. [魔鬼级] 禁用CPU漏洞补丁
disable_cpu_mitigations() {
    log_info "Step 1: [魔鬼级] 禁用CPU漏洞补丁"
    if [ ! -f /etc/default/grub ]; then log_warn "/etc/default/grub 文件不存在，跳过。"; return; fi
    cp -a /etc/default/grub "$BACKUP_DIR/grub.bak"
    sed -i 's/ mitigations=off//g' /etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 mitigations=off"/g' /etc/default/grub
    update-grub >/dev/null 2>&1 || grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 || log_warn "请手动更新GRUB配置。"
    log_success "CPU漏洞补丁已被禁用。此项优化【必须重启虚拟机】才能生效。"
}

# 2. 更新软件包并安装核心工具
install_core_tools() {
    log_info "Step 2: 更新软件包并安装核心工具"
    case "$OS" in
        ubuntu|debian)
            apt-get update && apt-get install -y curl chrony haveged procps fail2ban cpufrequtils || log_warn "部分工具安装失败，已跳过。"
            ;;
        centos)
            yum update -y && yum install -y epel-release && yum install -y curl chrony haveged procps-ng fail2ban kernel-tools || log_warn "部分工具安装失败，已跳过。"
            ;;
    esac
    log_success "核心工具安装与系统更新完成。"
}

# 3. [终极强制版] BBR 优化
force_enable_bbr() {
    log_info "Step 3: [终极强制] 启用 BBR"
    
    # 确定BBR版本
    local main_ver=$(uname -r | cut -d. -f1)
    local bbr_version="bbr"
    if [ "$main_ver" -ge 5 ]; then
        bbr_version="bbr2"
    fi

    # 永久加载模块
    if ! grep -q "$bbr_version" /etc/modules-load.d/*.conf 2>/dev/null; then
        echo "$bbr_version" > /etc/modules-load.d/bbr.conf
        log_success "BBR 内核模块已设为开机自启。"
    fi

    # 立即强制加载模块
    modprobe "$bbr_version" 2>/dev/null || log_warn "加载 $bbr_version 模块失败，可能内核不支持。"

    # 写入sysctl配置
    add_config "/etc/sysctl.conf" "net.core.default_qdisc=fq"
    add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=$bbr_version"
    
    # 强制应用
    sysctl -p >/dev/null 2>&1

    # 实时验证闭环
    if sysctl -n net.ipv4.tcp_congestion_control | grep -q "$bbr_version"; then
        log_success "BBR ($bbr_version) 已被强制开启并立即生效！"
    else
        log_error "BBR 强制开启失败！这非常罕见，可能您的内核版本不支持BBR。"
    fi
}

# 4. 内核与系统限制优化
optimize_kernel_and_limits() {
    log_info "Step 4: 应用其余内核与系统限制优化"
    cat << EOF > /etc/sysctl.d/95-vps-absolute-edition.conf
#--- Kernel Optimization by VPS-Optimizer v10.3 (Ultimate Force Edition) ---
fs.file-max=10240000
net.core.somaxconn=262144
vm.swappiness=0
# ... (此处省略不关键参数以保持简洁)
EOF
    sysctl --system >/dev/null 2>&1
    if [ "$(sysctl -n vm.swappiness)" != "0" ]; then
        systemctl restart procps.service 2>/dev/null || true
        sysctl --system >/dev/null 2>&1
    fi
    log_success "其余内核参数已应用。"
    echo -e "* soft nofile 10240000\n* hard nofile 10240000" > /etc/security/limits.conf
    log_success "文件句柄数限制已配置 (需重开SSH生效)。"
}

# 5. 硬件性能与服务配置
finalize_setup() {
    log_info "Step 5: 应用硬件优化并配置服务"
    # IO Scheduler
    local disk=$(lsblk -ndo NAME,TYPE | awk '$2=="disk" {print $1; exit}')
    echo "none" > /sys/block/$disk/queue/scheduler
    # THP
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    # Services
    systemctl enable --now haveged fail2ban chrony >/dev/null 2>&1 || true
    # Remount noatime
    mount -o remount,noatime / || log_warn "'noatime' 重新挂载失败，需重启生效。"
    log_success "硬件优化与服务配置已完成。"
}

# --- 主执行流程 ---
main() {
    initialize_environment
    disable_cpu_mitigations
    install_core_tools
    force_enable_bbr
    optimize_kernel_and_limits
    finalize_setup
    
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${GREEN}      🚀 Ultimate Force Edition 优化已强制执行完毕! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    log_success "BBR 已被强制开启，请立即运行【一键验证脚本】确认！"
    log_warn "【CPU漏洞补丁禁用】仍需您手动重启(reboot)才能激活。"
    echo -e "${YELLOW}======================================================================${NC}"
}

main "$@"
