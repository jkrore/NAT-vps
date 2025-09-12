#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 3.1 (Customized Edition)
#   Author: AI News Aggregator & Summarizer Expert
#   Description: 根据用户需求定制，保留“强制开启root密码登录”功能。
#                融合了交互性与智能化的一键优化脚本。
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
        cp -a "$1" "$BACKUP_DIR/$(basename "$1").bak"
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
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
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
    log_info "---> 1. 更新系统软件包..."
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get upgrade -y ;;
        centos) yum update -y ;;
    esac
    log_success "软件包更新完成。"
}

# 2. 强制开启root用户SSH密码登录 (按用户要求)
enable_root_ssh() {
    log_info "---> 2. 开启root用户SSH密码登录..."
    log_warn "安全警告: 直接允许root用户通过密码登录会显著增加服务器被暴力破解的风险。"
    log_warn "强烈建议您在日常管理中使用普通用户+sudo，并配置SSH密钥登录作为替代。"
    
    read -p "您确定要继续开启root密码登录吗? (y/n): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
        log_info "用户取消操作。"
        return
    fi

    log_info "请为root用户设置一个新密码。务必使用高强度的复杂密码！"
    if ! passwd root; then
        log_error "root密码设置失败，操作已中止。"
    fi
    
    backup_file "/etc/ssh/sshd_config"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    
    # 兼容不同的SSH服务名
    if systemctl is-active --quiet sshd; then
        systemctl restart sshd
    elif systemctl is-active --quiet ssh; then
        systemctl restart ssh
    else
        log_warn "无法确定SSH服务名称 (sshd/ssh)，请手动重启。"
    fi
    
    log_success "Root用户SSH密码登录已强制开启。"
}


# 3. 开启BBR+FQ网络加速
enable_bbr() {
    log_info "---> 3. 尝试开启BBR+FQ网络加速..."
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        log_success "BBR+FQ已处于开启状态。"
        return
    fi
    backup_file "/etc/sysctl.conf"
    add_config "/etc/sysctl.conf" "net.core.default_qdisc=fq"
    add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"
    sysctl -p
    if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
        log_success "BBR+FQ已成功开启！"
    else
        log_warn "BBR开启失败，可能是内核版本过低或不受支持。"
    fi
}

# 4. 设置Swap虚拟内存
setup_swap() {
    log_info "---> 4. 设置Swap虚拟内存..."
    if [ "$(swapon --show | wc -l)" -gt 1 ]; then
        log_warn "检测到已存在的Swap，跳过创建。"
        return
    fi
    MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}')
    if [ "$MEM_TOTAL_MB" -lt 2048 ]; then
        SWAP_SIZE_MB=$((MEM_TOTAL_MB * 2))
    elif [ "$MEM_TOTAL_MB" -lt 8192 ]; then
        SWAP_SIZE_MB=$MEM_TOTAL_MB
    else
        SWAP_SIZE_MB=8192
    fi
    DISK_FREE_GB=$(df -h / | awk 'NR==2 {print $4}')
    log_info "物理内存: ${MEM_TOTAL_MB}MB, 建议Swap: ${SWAP_SIZE_MB}MB, 磁盘剩余空间: ${DISK_FREE_GB}"
    read -p "是否继续创建 ${SWAP_SIZE_MB}MB 的Swap文件? (y/n): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then
        log_info "用户取消操作。"
        return
    fi
    fallocate -l "${SWAP_SIZE_MB}M" /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    backup_file "/etc/fstab"
    add_config "/etc/fstab" "/swapfile none swap sw 0 0"
    log_success "Swap创建并挂载成功！"
}

# 5. 智能配置DNS和NTP
configure_dns_ntp() {
    log_info "---> 5. 智能配置DNS和NTP..."
    backup_file "/etc/resolv.conf"
    chattr -i /etc/resolv.conf 2>/dev/null || true
    if [ "$IS_IN_CHINA" = "true" ]; then
        cat > /etc/resolv.conf << EOF
nameserver 223.5.5.5
nameserver 119.29.29.29
EOF
        log_info "已配置国内DNS (AliDNS, DNSPod)。"
    else
        cat > /etc/resolv.conf << EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
        log_info "已配置国际DNS (Cloudflare, Google)。"
    fi
    chattr +i /etc/resolv.conf 2>/dev/null || true
    case "$OS" in
        ubuntu|debian) apt-get install -y ntpdate ;;
        centos) yum install -y ntpdate ;;
    esac
    if [ "$IS_IN_CHINA" = "true" ]; then
        ntpdate ntp.aliyun.com
        log_info "已使用阿里NTP服务器同步时间。"
    else
        ntpdate pool.ntp.org
        log_info "已使用国际NTP服务器池同步时间。"
    fi
}

# 6. 内核与文件句柄数优化
optimize_kernel() {
    log_info "---> 6. 应用内核与文件句柄数优化..."
    backup_file "/etc/sysctl.conf"
    cat << EOF > /etc/sysctl.d/99-vps-optimize.conf
fs.file-max=1048576
fs.nr_open=1048576
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535
net.ipv4.tcp_tw_reuse=1
vm.swappiness=10
EOF
    sysctl --system
    log_success "内核参数优化已应用。"
    backup_file "/etc/security/limits.conf"
    cat << EOF >> /etc/security/limits.conf
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
    log_success "文件句柄数限制已提升。"
}

# 7. 安装基础安全工具 (Fail2ban)
install_security_tools() {
    log_info "---> 7. 安装基础安全工具 (Fail2ban)..."
    case "$OS" in
        ubuntu|debian) apt-get install -y fail2ban ;;
        centos) yum install -y epel-release && yum install -y fail2ban ;;
    esac
    systemctl enable --now fail2ban
    log_success "Fail2ban已安装并启动，为SSH提供基础防护。"
}

# 8. 清理系统
cleanup_system() {
    log_info "---> 8. 清理系统..."
    case "$OS" in
        ubuntu|debian) apt-get autoremove -y && apt-get clean -y ;;
        centos) yum autoremove -y && yum clean all ;;
    esac
    journalctl --vacuum-size=50M
    log_success "系统垃圾清理完成。"
}

# --- 主菜单 ---
main_menu() {
    echo -e "\n${YELLOW}=============================================================${NC}"
    echo -e "${GREEN}     欢迎使用 小鸡VPS终极优化脚本 v3.1 (定制版)${NC}"
    echo -e "${YELLOW}=============================================================${NC}"
    
    PS3=$'\n'"请选择要执行的操作 (输入数字后回车): "
    options=(
        "【一键全自动优化】 (推荐, 执行2-8)"
        "更新系统软件包"
        "开启root用户SSH密码登录 (高风险!)"
        "开启BBR+FQ网络加速"
        "智能创建Swap虚拟内存"
        "智能配置DNS和NTP"
        "内核与文件句柄数优化"
        "安装Fail2ban防暴力破解"
        "清理系统"
        "退出脚本"
    )
    
    select opt in "${options[@]}"; do
        case $REPLY in
            1)
                enable_root_ssh; enable_bbr; setup_swap; configure_dns_ntp; optimize_kernel; install_security_tools; cleanup_system
                echo -e "\n${GREEN}*** 所有优化任务已执行完毕！ ***${NC}"
                log_warn "强烈建议您现在重启服务器 (输入 reboot) 以使所有设置完全生效。"
                break
                ;;
            2) update_packages ;;
            3) enable_root_ssh ;;
            4) enable_bbr ;;
            5) setup_swap ;;
            6) configure_dns_ntp ;;
            7) optimize_kernel ;;
            8) install_security_tools ;;
            9) cleanup_system ;;
            10) echo "感谢使用，再见！"; break ;;
            *) echo -e "${RED}无效的选项 $REPLY${NC}" ;;
        esac
    done
}

# --- 脚本入口 ---
main() {
    check_root
    init_backup
    detect_os
    check_location
    main_menu
}

main
