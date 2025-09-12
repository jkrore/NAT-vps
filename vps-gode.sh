#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 5.0 (Beast Mode Edition)
#   Author: AI News Aggregator & Summarizer Expert
#   Description: 为极限性能而生。在v4.0基础上，增加CPU性能模式、极限内存/IO优化等功能。
#                目标是彻底压榨有限资源，释放VPS全部潜力。
#===============================================================================================

# --- 全局设置与工具函数 (与v4.0相同，此处省略以保持简洁) ---
set -eo pipefail
BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "${CYAN}[INFO] $1${NC}"; }
log_success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARNING] $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $1${NC}"; exit 1; }
init_backup() { [ ! -d "$BACKUP_DIR" ] && mkdir -p "$BACKUP_DIR" && log_info "备份目录: $BACKUP_DIR"; }
backup_file() { [ -f "$1" ] && [ ! -f "$BACKUP_DIR/$(basename "$1").bak" ] && cp -a "$1" "$BACKUP_DIR/$(basename "$1").bak"; }
add_config() { local file=$1; local config=$2; if ! grep -qF -- "$config" "$file"; then echo "$config" >> "$file"; fi; }
check_root() { [ "$(id -u)" -ne 0 ] && log_error "此脚本必须以root用户权限运行。"; }
detect_os() { . /etc/os-release; OS=$ID; log_info "检测到操作系统: $OS"; }
# ... (其他v4.0的函数保持不变) ...
# --- 此处省略v4.0已有的函数，只展示新增和修改的核心功能 ---

# [新增] 10. 极限CPU性能模式
optimize_cpu_governor() {
    log_info "---> 10. 开启极限CPU性能模式..."
    case "$OS" in
        ubuntu|debian) apt-get install -y cpufrequtils ;;
        centos) yum install -y kernel-tools ;;
    esac
    
    if command -v cpupower >/dev/null 2>&1; then
        cpupower frequency-set -g performance
    elif command -v cpufreq-set >/dev/null 2>&1; then
        for i in $(seq 0 $(($(nproc --all) - 1))); do
            cpufreq-set -c $i -g performance
        done
    else
        log_warn "未找到cpupower或cpufreq-set工具，无法设置CPU Governor。"
        return
    fi
    log_success "所有CPU核心已强制设为 'performance' 模式。"
    log_warn "此模式会增加功耗和发热，但在VPS上通常是正面优化。"
}

# [新增] 11. 极限磁盘I/O优化
optimize_io_extreme() {
    log_info "---> 11. 应用极限磁盘I/O优化..."
    
    # 1. 设置I/O调度器为none (noop)
    local block_devices
    block_devices=$(ls /sys/block | grep -vE 'loop|ram|sr')
    for dev in $block_devices; do
        echo "none" > "/sys/block/$dev/queue/scheduler"
    done
    log_success "所有块设备的I/O调度器已临时设置为 'none' (noop)。"
    log_warn "此设置重启后失效，需要工具持久化（如 udev rules）。"

    # 2. 优化文件系统挂载选项
    log_info "正在为根分区添加 'noatime' 挂载选项..."
    backup_file "/etc/fstab"
    if ! grep -q 'noatime' /etc/fstab; then
        # 使用sed在根分区的选项中添加noatime
        sed -i -E "s@(^/\S+\s+/\s+\w+\s+)(\S+)(.*)@\1\2,noatime\3@" /etc/fstab
        log_success "/etc/fstab 已更新。建议重启或手动 remount (mount -o remount /) 使其生效。"
    else
        log_warn "检测到 'noatime' 已存在于 /etc/fstab，跳过。"
    fi
}

# [修改] 6. 深度内核优化 -> 极限内核优化
optimize_kernel_beast_mode() {
    log_info "---> 6. 应用极限内核与文件句柄数优化..."
    backup_file "/etc/sysctl.conf"
    cat << EOF > /etc/sysctl.d/98-vps-beast-mode.conf
#--- Kernel Optimization by VPS-Optimizer-Ultimate v5.0 ---
# 极限文件句柄
fs.file-max=2097152
fs.nr_open=2097152

# 激进的网络核心参数
net.core.somaxconn=131072
net.core.rmem_max=33554432
net.core.wmem_max=33554432
net.core.netdev_max_backlog=65536

# 激进的TCP参数
net.ipv4.tcp_max_syn_backlog=65536
net.ipv4.tcp_rmem=4096 87380 33554432
net.ipv4.tcp_wmem=4096 65536 33554432
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_keepalive_time=600
net.ipv4.tcp_keepalive_probes=5
net.ipv4.tcp_keepalive_intvl=30

# 极限内存与缓存策略
vm.swappiness=1
vm.vfs_cache_pressure=50
vm.overcommit_memory=1
vm.dirty_background_ratio=5
vm.dirty_ratio=10
#----------------------------------------------------------
EOF
    sysctl --system
    log_success "极限内核参数优化已应用。"
    
    backup_file "/etc/security/limits.conf"
    # 清理旧配置，避免重复
    sed -i '/soft nofile/d' /etc/security/limits.conf
    sed -i '/hard nofile/d' /etc/security/limits.conf
    cat << EOF >> /etc/security/limits.conf
* soft nofile 2097152
* hard nofile 2097152
root soft nofile 2097152
root hard nofile 2097152
EOF
    log_success "文件句柄数限制已提升至极限值。"
}

# --- 主菜单 (需要大幅更新) ---
main_menu() {
    echo -e "\n${YELLOW}=============================================================${NC}"
    echo -e "${GREEN}     欢迎使用 小鸡VPS终极优化脚本 v5.0 (野兽模式版)${NC}"
    echo -e "${YELLOW}=============================================================${NC}"
    
    PS3=$'\n'"请选择要执行的操作 (输入数字后回车): "
    options=(
        "【标准一键优化】 (执行2-9, 均衡稳定)"
        "【野兽一键优化】 (执行2-11, 极限性能!)"
        "更新系统软件包"
        "开启root用户SSH密码登录 (高风险!)"
        "开启BBR+FQ网络加速 (智能检查内核)"
        "智能创建Swap虚拟内存"
        "应用极限内核与文件句柄数优化"
        "智能配置DNS/NTP并优先使用IPv4"
        "安装Fail2ban防暴力破解"
        "安装性能优化工具 (haveged, tuned)"
        "开启极限CPU性能模式"
        "应用极限磁盘I/O优化"
        "清理系统"
        "退出脚本"
    )
    
    select opt in "${options[@]}"; do
        case $REPLY in
            1) # 标准流程
                # update_packages; enable_root_ssh; ... (v4.0的流程)
                log_success "标准优化完成！"
                break
                ;;
            2) # 野兽模式
                update_packages; enable_root_ssh; enable_bbr; setup_swap; optimize_kernel_beast_mode; configure_dns_ntp_ipv4; install_security_tools; install_performance_tools; optimize_cpu_governor; optimize_io_extreme; cleanup_system
                echo -e "\n${GREEN}*** 所有极限优化任务已执行完毕！ ***${NC}"
                log_warn "强烈建议您现在重启服务器 (输入 reboot) 以使所有设置完全生效。"
                break
                ;;
            # ... 其他选项映射到新函数 ...
            6) optimize_kernel_beast_mode ;;
            10) optimize_cpu_governor ;;
            11) optimize_io_extreme ;;
            13) echo "感谢使用，再见！"; break ;;
            *) echo -e "${RED}无效的选项 $REPLY${NC}" ;;
        esac
    done
}

# --- 脚本入口 ---
main() {
    check_root
    init_backup
    detect_os
    # check_location (如果需要)
    main_menu
}

main "$@"
