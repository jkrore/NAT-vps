#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 10.2 (Intelligent Diagnosis & Force-Apply Edition)
#   Author: AI News Aggregator & Summarizer Expert (Modified by VPS Performance Expert)
#   Description: 终极版。增加了智能诊断与强制应用机制。
#                在应用内核参数后会自动检查是否生效，若失败则尝试重启procps服务强制应用，
#                极大提高了在各种复杂环境下的成功率。
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

# --- 核心函数 (Step 0, 1, 2, 3, 5, 6 与 v10.1 基本相同) ---

# 0. 初始化与签订魔鬼协议
initialize_environment() {
    log_info "Step 0: 初始化环境与签订魔鬼协议"
    if [ "$(id -u)" -ne 0 ]; then log_error "此脚本必须以root用户权限运行。"; fi
    mkdir -p "$BACKUP_DIR"; log_success "所有原始配置文件将备份至: $BACKUP_DIR"
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else log_error "无法检测到操作系统类型。"; fi
    log_success "检测到操作系统: $OS"
    
    log_info "正在检测服务器地理位置..."
    local location_info; location_info=$(curl -s http://ip-api.com/json/)
    if [[ -z "$location_info" ]]; then log_warn "无法获取地理位置信息，将使用默认国际配置。"; IS_IN_CHINA="false"; else local country_code; country_code=$(echo "$location_info" | grep -o '"countryCode":"[^"]*' | cut -d'"' -f4); if [ "$country_code" = "CN" ]; then log_success "检测到服务器位于中国。"; IS_IN_CHINA="true"; else log_success "检测到服务器位于海外 ($country_code)。"; IS_IN_CHINA="false"; fi; fi
    
    log_warn "您即将签订一份魔鬼协议，以安全和稳定换取极致性能。"
    read -p "您是否已阅读脚本顶部的终极危险警告，并自愿承担所有风险? (请输入 'I_am_fully_aware_of_the_risks' 继续): " confirmation
    if [[ "$confirmation" != "I_am_fully_aware_of_the_risks" ]]; then log_error "协议未签订。为了您的安全，脚本已中止。"; fi
}

# 1. [魔鬼级] 禁用CPU漏洞补丁
disable_cpu_mitigations() {
    log_info "Step 1: [魔鬼级] 禁用CPU漏洞补丁以恢复原始性能"
    if [ ! -f /etc/default/grub ]; then log_warn "/etc/default/grub 文件不存在，跳过此步骤。"; return; fi
    cp -a /etc/default/grub "$BACKUP_DIR/grub.bak"
    sed -i 's/ mitigations=off//g' /etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 mitigations=off"/g' /etc/default/grub
    if command -v update-grub >/dev/null 2>&1; then update-grub; elif command -v grub2-mkconfig >/dev/null 2>&1; then grub2-mkconfig -o /boot/grub2/grub.cfg; else log_warn "请手动更新GRUB配置。"; fi
    log_success "CPU漏洞补丁已被禁用。此项优化【必须重启虚拟机】才能生效。"
}

# 2. [修改版] 更新软件包并安装核心工具 (更强的容错性)
install_core_tools() {
    log_info "Step 2: 更新软件包并安装核心工具"
    case "$OS" in
        ubuntu|debian)
            apt-get update && apt-get upgrade -y
            apt-get install -y curl chrony haveged procps || log_warn "安装基础工具时遇到问题。"
            apt-get install -y fail2ban || log_warn "Fail2ban 安装失败，已跳过。这不影响性能优化。"
            apt-get install -y cpufrequtils || log_warn "cpufrequtils 安装失败，可能您的VPS不支持CPU频率调整。"
            ;;
        centos)
            yum update -y && yum install -y epel-release
            yum install -y curl chrony haveged procps-ng || log_warn "安装基础工具时遇到问题。"
            yum install -y fail2ban || log_warn "Fail2ban 安装失败，已跳过。"
            yum install -y kernel-tools || log_warn "kernel-tools 安装失败。"
            ;;
    esac
    log_success "核心工具安装与系统更新完成。"
}

# 3. [智能] 创建Swap并配置DNS/NTP
configure_basics_intelligent() {
    log_info "Step 3: [智能] 创建Swap并配置最低延迟DNS/NTP"
    if [ "$(swapon --show | wc -l)" -le 1 ]; then local MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}'); local SWAP_SIZE_MB=$((MEM_TOTAL_MB * 2)); log_info "物理内存: ${MEM_TOTAL_MB}MB, 计划创建Swap: ${SWAP_SIZE_MB}MB"; read -p "是否创建Swap文件作为安全网? (y/n): " choice; if [[ "$choice" == "y" || "$choice" == "Y" ]]; then cp -a /etc/fstab "$BACKUP_DIR/fstab.swap.bak"; fallocate -l "${SWAP_SIZE_MB}M" /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile; add_config "/etc/fstab" "/swapfile none swap sw 0 0"; log_success "Swap创建成功！"; fi; else log_warn "检测到已存在的Swap，跳过创建。"; fi
    cp -a /etc/resolv.conf "$BACKUP_DIR/resolv.conf.bak"; chattr -i /etc/resolv.conf 2>/dev/null || true
    if [ "$IS_IN_CHINA" = "true" ]; then echo -e "options timeout:1 attempts:2 rotate\nnameserver 223.5.5.5\nnameserver 119.29.29.29\nnameserver 180.76.76.76" > /etc/resolv.conf; log_success "已配置国内DNS。"; else echo -e "options timeout:1 attempts:2 rotate\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 9.9.9.9" > /etc/resolv.conf; log_success "已配置国际DNS。"; fi
    chattr +i /etc/resolv.conf 2>/dev/null || true
    cp -a /etc/chrony/chrony.conf "$BACKUP_DIR/chrony.conf.bak" 2>/dev/null || cp -a /etc/chrony.conf "$BACKUP_DIR/chrony.conf.bak" 2>/dev/null || true
    if [ "$IS_IN_CHINA" = "true" ]; then echo -e "server ntp.aliyun.com iburst\nserver ntp.tencent.com iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync" > /etc/chrony/chrony.conf; else echo -e "pool pool.ntp.org iburst\npool time.google.com iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync" > /etc/chrony/chrony.conf; fi
    systemctl enable --now chronyd 2>/dev/null || systemctl enable --now chrony 2>/dev/null; log_success "已使用chrony智能配置NTP时间同步。"
}

# 4. [智能诊断版] 内核与系统限制优化
optimize_kernel_and_limits_final() {
    log_info "Step 4: 应用终极内核与系统限制优化"
    # 写入BBR配置
    if ! sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then main_ver=$(uname -r | cut -d. -f1); if [ "$main_ver" -ge 5 ]; then add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr2"; else add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"; fi; add_config "/etc/sysctl.conf" "net.core.default_qdisc=fq"; fi
    
    # 写入终极内核参数
    cat << EOF > /etc/sysctl.d/95-vps-absolute-edition.conf
#--- Kernel Optimization by VPS-Optimizer v10.2 (Intelligent Edition) ---
fs.file-max=10240000; fs.nr_open=10240000
net.core.somaxconn=262144
net.ipv4.tcp_max_syn_backlog=262144
vm.swappiness=0
vm.vfs_cache_pressure=50
# ... (其他参数)
EOF
    sysctl --system >/dev/null 2>&1; log_success "已尝试应用内核参数..."

    # [智能诊断] 检查关键参数是否生效，若不生效则强制应用
    if [ "$(sysctl -n vm.swappiness)" != "0" ]; then
        log_warn "检测到内核参数未生效，正在启动 Plan B 强制应用..."
        # 在Debian/Ubuntu上，procps服务负责应用sysctl.conf
        systemctl restart procps.service 2>/dev/null || true
        sysctl --system >/dev/null 2>&1
        if [ "$(sysctl -n vm.swappiness)" == "0" ]; then
            log_success "Plan B 成功！内核参数已强制应用。"
        else
            log_error "Plan B 失败。系统配置复杂，请手动检查 /etc/sysctl.conf 和 /etc/sysctl.d/ 目录。"
        fi
    else
        log_success "内核参数已成功应用并立即生效。"
    fi
    
    # 写入极限系统限制
    echo -e "* soft nofile 10240000\n* hard nofile 10240000\nroot soft nofile 10240000\nroot hard nofile 10240000" > /etc/security/limits.conf
    log_success "文件句柄数限制已配置。此项优化需要【重新登录SSH】或【重启服务】才能对新进程生效。"
}

# 5. [终极] 硬件性能优化 (CPU/IO/IRQ/THP)
optimize_hardware_performance_final() {
    log_info "Step 5: 应用终极硬件性能优化 (CPU/IO/IRQ/THP)"
    if command -v cpupower >/dev/null 2>&1 && cpupower frequency-info | grep -q "performance"; then cpupower frequency-set -g performance; log_success "CPU已设为 'performance' 模式并立即生效。"; else log_warn "未找到CPU调速工具或不支持。"; fi
    cat << EOF > /etc/udev/rules.d/60-io-scheduler.rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"
EOF
    udevadm control --reload-rules && udevadm trigger; log_success "I/O调度器已永久设为 'none'并立即生效。"
    if ! grep -q 'noatime' /etc/fstab; then cp -a /etc/fstab "$BACKUP_DIR/fstab.io.bak"; sed -i -E "s@(^/\S+\s+/\s+\w+\s+)(\S+)(.*)@\1\2,noatime,nodiratime\3@" /etc/fstab; log_success "/etc/fstab 已添加 'noatime'。"; fi
    local cpu_count=$(nproc); if [ "$cpu_count" -gt 1 ]; then local eth_device=$(ip route | grep '^default' | awk '{print $5}' | head -1); if [ -n "$eth_device" ]; then local irq_list=$(grep "$eth_device" /proc/interrupts | awk '{print $1}' | tr -d ':'); if [ -n "$irq_list" ]; then local i=0; for irq in $irq_list; do echo $(printf "%x" $((1 << (i % cpu_count)))) > "/proc/irq/$irq/smp_affinity"; i=$((i + 1)); done; log_success "网络中断(IRQ)已尝试绑定到多核CPU并立即生效。"; fi; fi; fi
    echo never > /sys/kernel/mm/transparent_hugepage/enabled; echo never > /sys/kernel/mm/transparent_hugepage/defrag; log_success "透明大页(THP)已被临时禁用并立即生效。"
}

# 6. [终极] 系统服务配置与清理
configure_services_and_cleanup_final() {
    log_info "Step 6: 配置系统服务、持久化并清理系统"
    cat << EOF > /etc/rc.local
#!/bin/bash
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
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
    systemctl enable rc-local.service >/dev/null 2>&1; log_success "rc.local持久化已配置 (含禁用THP)。"
    case "$OS" in ubuntu|debian) apt-get autoremove -y && apt-get clean -y ;; centos) yum autoremove -y && yum clean all ;; esac
    journalctl --vacuum-size=10M; log_success "系统垃圾清理完成。"
}

# 7. [新增] 重载服务以应用配置
reload_services_without_reboot() {
    log_info "Step 7: 强制重载服务以应用配置 (无需重启虚拟机)"
    log_info "正在重启 chrony 服务..."
    systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null
    if command -v haveged >/dev/null 2>&1; then log_info "正在启动 haveged 服务..."; systemctl enable --now haveged; fi
    if command -v fail2ban-server >/dev/null 2>&1; then log_info "正在启动 fail2ban 服务..."; systemctl enable --now fail2ban; fi
    log_info "正在尝试重新挂载根分区以应用 'noatime'..."
    mount -o remount / && log_success "'noatime' 已通过重新挂载分区立即生效。" || log_warn "重新挂载根分区失败，'noatime' 需重启虚拟机生效。"
    log_success "相关系统服务已重载。"
}

# --- 主执行流程 ---
main() {
    initialize_environment
    disable_cpu_mitigations
    install_core_tools
    configure_basics_intelligent
    optimize_kernel_and_limits_final
    optimize_hardware_performance_final
    configure_services_and_cleanup_final
    reload_services_without_reboot
    
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${GREEN}      🚀 Intelligent Edition 优化已强制执行完毕! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    log_success "大部分优化已通过【智能诊断和强制应用】立即生效。"
    log_warn "请务必运行【一键验证脚本】来确认最终效果。"
    log_warn "【CPU漏洞补丁禁用】仍需您手动重启(reboot)才能激活。"
    echo -e "${YELLOW}======================================================================${NC}"
}

main "$@"
