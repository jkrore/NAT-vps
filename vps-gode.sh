#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 5.1 (Ultimate Fusion)
#   Author: AI News Aggregator & Summarizer Expert
#   Description: 终极融合版。集成了v3.1的智能安全框架、v2.1的性能调优、以及v5.0的极限
#                压榨理念。提供“均衡稳定”与“野兽性能”两种一键优化模式。
#===============================================================================================

# --- 全局设置 ---
set -eo pipefail
BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- 工具函数 ---
log_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
log_success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }

init_backup() {
    if [ ! -d "$BACKUP_DIR" ]; then
        mkdir -p "$BACKUP_DIR"
        log_info "所有原始配置文件将备份至: $BACKUP_DIR"
    fi
}

backup_file() {
    if [ -f "$1" ]; then
        if [ ! -f "$BACKUP_DIR/$(basename "$1").bak" ]; then
            cp -a "$1" "$BACKUP_DIR/$(basename "$1").bak"
        fi
    fi
}

add_config() {
    local file=$1
    local config=$2
    if ! grep -qF -- "$config" "$file"; then
        echo "$config" >> "$file"
    fi
}

# --- 系统检测模块 ---
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "此脚本必须以root用户权限运行。"
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        log_error "无法检测到操作系统类型。"
    fi
    log_info "检测到操作系统: $OS"
}

check_location() {
    log_info "正在检测服务器地理位置..."
    local location_info
    location_info=$(curl -s http://ip-api.com/json/)
    if [[ -z "$location_info" ]]; then
        log_warn "无法获取地理位置信息，将使用默认国际配置。"
        IS_IN_CHINA="false"
        return
    fi
    local country_code
    country_code=$(echo "$location_info" | grep -o '"countryCode":"[^"]*' | cut -d'"' -f4)
    if [ "$country_code" = "CN" ]; then
        log_info "检测到服务器位于中国。"
        IS_IN_CHINA="true"
    else
        log_info "检测到服务器位于海外 ($country_code)。"
        IS_IN_CHINA="false"
    fi
}

# --- 优化功能模块 ---

# 1. 更新软件包
update_packages() {
    log_info "---> 更新系统软件包..."
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get upgrade -y ;;
        centos) yum update -y ;;
    esac
    log_success "软件包更新完成。"
}

# 2. 强制开启root用户SSH密码登录
enable_root_ssh() {
    log_info "---> 开启root用户SSH密码登录..."
    log_warn "安全警告: 直接允许root用户通过密码登录会显著增加服务器被暴力破解的风险。"
    read -p "您确定要继续开启root密码登录吗? (y/n): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
        log_info "用户取消操作。"; return
    fi
    log_info "请为root用户设置一个新密码。务必使用高强度的复杂密码！"
    if ! passwd root; then
        log_error "root密码设置失败，操作已中止。"
    fi
    backup_file "/etc/ssh/sshd_config"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    if systemctl is-active --quiet sshd; then systemctl restart sshd; elif systemctl is-active --quiet ssh; then systemctl restart ssh; else log_warn "请手动重启SSH服务。"; fi
    log_success "Root用户SSH密码登录已强制开启。"
}

# 3. 开启BBR+FQ网络加速 (集成内核版本检查)
enable_bbr() {
    log_info "---> 尝试开启BBR+FQ网络加速 (智能检查内核)..."
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        log_success "BBR+FQ已处于开启状态。"; return
    fi
    main_ver=$(uname -r | cut -d. -f1); minor_ver=$(uname -r | cut -d. -f2)
    if [ "$main_ver" -gt 4 ] || { [ "$main_ver" -eq 4 ] && [ "$minor_ver" -ge 9 ]; }; then
        log_info "内核版本 ($(uname -r)) 符合要求，开始配置BBR。"
        backup_file "/etc/sysctl.conf"
        add_config "/etc/sysctl.conf" "net.core.default_qdisc=fq"
        add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"
        sysctl -p
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then log_success "BBR+FQ已成功开启！"; else log_warn "BBR开启失败。"; fi
    else
        log_warn "您的内核版本 ($(uname -r)) 过低，无法直接开启BBR。请先手动升级内核。";
    fi
}

# 4. 设置Swap虚拟内存
setup_swap() {
    log_info "---> 设置Swap虚拟内存..."
    if [ "$(swapon --show | wc -l)" -gt 1 ]; then
        log_warn "检测到已存在的Swap，跳过创建。"; return
    fi
    MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$MEM_TOTAL_MB" -lt 2048 ]; then SWAP_SIZE_MB=$((MEM_TOTAL_MB * 2)); elif [ "$MEM_TOTAL_MB" -lt 8192 ]; then SWAP_SIZE_MB=$MEM_TOTAL_MB; else SWAP_SIZE_MB=8192; fi
    log_info "物理内存: ${MEM_TOTAL_MB}MB, 建议Swap: ${SWAP_SIZE_MB}MB"
    read -p "是否继续创建 ${SWAP_SIZE_MB}MB 的Swap文件? (y/n): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
        log_info "用户取消操作。"; return
    fi
    fallocate -l "${SWAP_SIZE_MB}M" /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
    backup_file "/etc/fstab"
    add_config "/etc/fstab" "/swapfile none swap sw 0 0"
    log_success "Swap创建并挂载成功！"
}

# 5. 智能配置DNS/NTP并优先使用IPv4
configure_dns_ntp_ipv4() {
    log_info "
