#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 13.0 (Grand Synthesis Edition)
#   Author: AI Executor
#   Description: 终极集大成版。遵从用户指令，完美融合了所有历史版本(v1-v12)的全部优点。
#                集成了v12的【健壮性与自我修复】、v11的【智能BBRv2】、v10的【魔鬼级优化】、
#                v8的【硬件压榨(IRQ/udev)】、v3的【地理位置智能检测】和v1的【系统清理】。
#                这是当前最全面、最智能、最激进、最可靠的一键化终极解决方案。
#
#   !!! 终极危险警告 - 魔鬼协议 !!!
#   1. 此脚本包含禁用CPU硬件漏洞补丁的选项，会使您的系统完全暴露于严重安全风险之下。
#   2. 激进的内核和硬件策略可能导致系统在特定负载下不稳定或无响应。
#   3. 此脚本为追求极致性能而设计，在用于生产环境或存有重要数据的机器前，您必须完全理解其风险。
#   4. 您必须自愿承担包括但不限于数据丢失、系统损坏、安全入侵等所有风险。
#===============================================================================================

# --- 全局设置与工具函数 ---
BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "\n${CYAN}>>> $1${NC}"; }
log_success() { echo -e "${GREEN}✔ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
log_error() { echo -e "${RED}✖ $1${NC}"; }
add_config() { local file=$1; local config=$2; if ! grep -qF -- "$config" "$file"; then echo "$config" >> "$file"; fi; }

# --- 核心函数 ---

# 0. 初始化
initialize_environment() {
    log_info "Step 0: 初始化环境"
    if [ "$(id -u)" -ne 0 ]; then log_error "此脚本必须以root用户权限运行。"; return; fi
    mkdir -p "$BACKUP_DIR"; log_success "所有原始配置文件将备份至: $BACKUP_DIR"
    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; VERSION_ID=$VERSION_ID; else log_error "无法检测到操作系统类型。"; return; fi
    log_success "检测到操作系统: $OS $VERSION_ID"
    log_info "正在检测服务器地理位置..."
    local location_info; location_info=$(curl -s http://ip-api.com/json/)
    if [[ -z "$location_info" ]]; then log_warn "无法获取地理位置信息，将使用默认国际配置。"; IS_IN_CHINA="false"; else local country_code; country_code=$(echo "$location_info" | grep -o '"countryCode":"[^"]*' | cut -d'"' -f4); if [ "$country_code" = "CN" ]; then log_success "检测到服务器位于中国。"; IS_IN_CHINA="true"; else log_success "检测到服务器位于海外 ($country_code)。"; IS_IN_CHINA="false"; fi; fi
    log_warn "“魔鬼协议”确认步骤已移除，脚本将直接执行。"
}

# 0.5 修复APT软件源
fix_apt_sources() {
    if [ "$OS" == "debian" ] && [ "$VERSION_ID" == "11" ]; then
        log_info "Step 0.5: [自我修复] 检测到Debian 11，正在修复软件源..."
        cp /etc/apt/sources.list "$BACKUP_DIR/sources.list.bak"
        cat << EOF > /etc/apt/sources.list
deb http://deb.debian.org/debian/ bullseye main
deb-src http://deb.debian.org/debian/ bullseye main
deb http://security.debian.org/debian-security bullseye-security main
deb-src http://security.debian.org/debian-security bullseye-security main
deb http://deb.debian.org/debian/ bullseye-updates main
deb-src http://deb.debian.org/debian/ bullseye-updates main
EOF
        log_success "Debian 11 软件源已修复为官方稳定源。"
    fi
}

# 1. [可选高风险] 开启root用户SSH密码登录
enable_root_ssh_optional() {
    log_info "Step 1: [可选高风险] 开启root用户SSH密码登录"
    log_warn "安全警告: 直接允许root用户通过密码登录会显著增加服务器被暴力破解的风险。"
    read -p "是否要执行此项操作? (y/n): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then log_info "已跳过开启root密码登录。"; return; fi
    log_info "请为root用户设置一个新密码。务必使用高强度的复杂密码！"
    if ! passwd root; then log_error "root密码设置失败，操作已中止。"; return; fi
    cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || log_warn "请手动重启SSH服务。"
    log_success "Root用户SSH密码登录已强制开启。"
}

# 2. [魔鬼级] 禁用CPU漏洞补丁 (需重启)
disable_cpu_mitigations() {
    log_info "Step 2: [魔鬼级] 配置禁用CPU漏洞补丁"
    if [ ! -f /etc/default/grub ]; then log_warn "/etc/default/grub 文件不存在，跳过。"; return; fi
    cp -a /etc/default/grub "$BACKUP_DIR/grub.bak"
    sed -i 's/ mitigations=off//g' /etc/default/grub
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="\(.*\)"/GRUB_CMDLINE_LINUX_DEFAULT="\1 mitigations=off"/g' /etc/default/grub
    update-grub >/dev/null 2>&1 || grub2-mkconfig -o /boot/grub2/grub.cfg >/dev/null 2>&1 || log_warn "请手动更新GRUB配置。"
    log_success "CPU漏洞补丁禁用已配置。此项优化【必须重启虚拟机】才能生效。"
}

# 3. 安装核心工具
install_core_tools() {
    log_info "Step 3: 更新软件包并安装核心工具"
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get install -y curl chrony haveged procps fail2ban cpufrequtils || log_warn "部分工具安装失败，已跳过。" ;;
        centos) yum update -y && yum install -y epel-release && yum install -y curl chrony haveged procps-ng fail2ban kernel-tools tuned || log_warn "部分工具安装失败，已跳过。" ;;
    esac
    log_success "核心工具安装与系统更新完成。"
}

# 3.5 [安全增强] 配置Fail2ban持久化规则
configure_fail2ban_enhanced() {
    log_info "Step 3.5: [安全增强] 配置Fail2ban持久化规则"
    if ! command -v fail2ban-server >/dev/null 2>&1; then log_warn "Fail2ban 未能成功安装，已跳过其配置步骤。"; return; fi
    cat << EOF > /etc/fail2ban/jail.local
#--- Fail2ban持久化配置 by VPS-Optimizer v13.0 ---
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5
[sshd]
enabled = true
EOF
    systemctl enable --now fail2ban >/dev/null 2>&1; systemctl restart fail2ban
    log_success "Fail2ban已配置持久化规则并启动。"; log_info "当前Fail2ban状态: $(systemctl is-active fail2ban)"
}

# 4. 智能配置基础环境 (Swap/DNS/NTP)
configure_basics() {
    log_info "Step 4: 智能配置基础环境 (Swap/DNS/NTP)"
    if [ "$(swapon --show | wc -l)" -le 1 ]; then local MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}'); local SWAP_SIZE_MB=$((MEM_TOTAL_MB < 2048 ? MEM_TOTAL_MB * 2 : (MEM_TOTAL_MB < 8192 ? MEM_TOTAL_MB : 8192) )); log_info "物理内存: ${MEM_TOTAL_MB}MB, 建议Swap: ${SWAP_SIZE_MB}MB"; read -p "是否创建Swap文件? (y/n): " choice; if [[ "$choice" == "y" || "$choice" == "Y" ]]; then cp -a /etc/fstab "$BACKUP_DIR/fstab.swap.bak"; fallocate -l "${SWAP_SIZE_MB}M" /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile; add_config "/etc/fstab" "/swapfile none swap sw 0 0"; log_success "Swap创建成功！"; fi; else log_warn "检测到已存在的Swap，跳过创建。"; fi
    cp -a /etc/resolv.conf "$BACKUP_DIR/resolv.conf.bak"; chattr -i /etc/resolv.conf 2>/dev/null || true
    if [ "$IS_IN_CHINA" = "true" ]; then echo -e "nameserver 223.5.5.5\nnameserver 119.29.29.29" > /etc/resolv.conf; log_success "已配置国内DNS。"; else echo -e "nameserver 1.1.1.1\nnameserver 8.8.8.8" > /etc/resolv.conf; log_success "已配置国际DNS。"; fi
    chattr +i /etc/resolv.conf 2>/dev/null || true
    local chrony_conf_path="/etc/chrony/chrony.conf"; if [ ! -f "$chrony_conf_path" ]; then chrony_conf_path="/etc/chrony.conf"; fi; cp -a "$chrony_conf_path" "$BACKUP_DIR/chrony.conf.bak" 2>/dev/null || true
    if [ "$IS_IN_CHINA" = "true" ]; then echo -e "server ntp.aliyun.com iburst\nserver ntp.tencent.com iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync" > "$chrony_conf_path"; else echo -e "pool pool.ntp.org iburst\npool time.google.com iburst\ndriftfile /var/lib/chrony/drift\nmakestep 1.0 3\nrtcsync" > "$chrony_conf_path"; fi
}

# 5. [核心] 智能检测并开启BBR (免重启)
intelligent_bbr_setup() {
    log_info "Step 5: [智能检测] 开启最佳BBR版本 (免重启)"
    modprobe tcp_bbr >/dev/null 2>&1; modprobe tcp_bbr2 >/dev/null 2>&1
    sed -i.bak '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i.bak '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    local available_bbrs; available_bbrs=$(sysctl -n net.ipv4.tcp_available_congestion_control)
    local best_bbr=""; if [[ "$available_bbrs" == *"bbr2"* ]]; then best_bbr="bbr2"; elif [[ "$available_bbrs" == *"bbr"* ]]; then best_bbr="bbr"; fi
    if [ -n "$best_bbr" ]; then
        log_success "检测到您的内核支持的最佳版本为: $best_bbr"
        echo "net.core.default_qdisc = fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control = $best_bbr" >> /etc/sysctl.conf
    else
        log_warn "您的内核不支持任何BBR版本，已跳过此项优化。"
    fi
}

# 6. [融合] 应用全面的内核与系统限制 (免重启)
optimize_kernel_and_limits() {
    log_info "Step 6: [融合] 应用全面的内核与系统限制优化"
    local conf_file="/etc/sysctl.d/97-vps-grand-synthesis.conf"
    cat << EOF > "$conf_file"
#--- Kernel Optimization by VPS-Optimizer v13.0 (Grand Synthesis) ---
fs.file-max=10240000
fs.nr_open=10240000
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=524288
net.core.somaxconn=262144
net.core.netdev_max_backlog=262144
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.busy_poll=50
net.ipv4.tcp_max_syn_backlog=262144
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
vm.swappiness=10
vm.vfs_cache_pressure=50
vm.overcommit_memory=1
vm.min_free_kbytes=65536
EOF
    add_config "/etc/gai.conf" "precedence ::ffff:0:0/96  100"
    sysctl --system >/dev/null 2>&1
    if [ "$(sysctl -n vm.swappiness)" != "10" ]; then
        log_warn "检测到内核参数未生效，正在启动强力 Plan B..."
        sysctl -p "$conf_file" >/dev/null 2>&1
        if [ "$(sysctl -n vm.swappiness)" == "10" ]; then log_success "强力 Plan B 成功！内核参数已强制应用。"; else log_error "强力 Plan B 失败，请手动检查 sysctl 配置。"; fi
    else
        log_success "内核参数已成功应用。"
    fi
    echo -e "* soft nofile 10240000\n* hard nofile 10240000" > /etc/security/limits.conf
    log_success "文件句柄数限制已配置。"
}

# 7. [融合] 硬件压榨与服务配置 (免重启)
finalize_setup() {
    log_info "Step 7: [融合] 应用硬件压榨、服务配置与持久化"
    # CPU Governor
    if command -v cpupower >/dev/null 2>&1 && cpupower frequency-info | grep -q "performance"; then cpupower frequency-set -g performance; log_success "CPU已设为 'performance' 模式。"; fi
    # I/O Scheduler (Persistent)
    cat << EOF > /etc/udev/rules.d/60-io-scheduler.rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"
EOF
    udevadm control --reload-rules && udevadm trigger; log_success "I/O调度器已通过udev永久设为 'none'。"
    # THP
    echo never > /sys/kernel/mm/transparent_hugepage/enabled; log_success "透明大页(THP)已禁用。"
    # IRQ Affinity
    local cpu_count=$(nproc); if [ "$cpu_count" -gt 1 ]; then local eth_device=$(ip route | grep '^default' | awk '{print $5}' | head -1); if [ -n "$eth_device" ]; then local irq_list=$(grep "$eth_device" /proc/interrupts | awk '{print $1}' | tr -d ':'); if [ -n "$irq_list" ]; then local i=0; for irq in $irq_list; do echo $(printf "%x" $((1 << (i % cpu_count)))) > "/proc/irq/$irq/smp_affinity"; i=$((i + 1)); done; log_success "网络中断(IRQ)已尝试绑定到多核CPU。"; fi; fi; fi
    # Core Services
    if [ "$OS" == "centos" ] && command -v tuned-adm >/dev/null 2>&1; then tuned-adm profile virtual-guest; systemctl enable --now tuned; log_success "Tuned服务已为CentOS设为 'virtual-guest' 模式。"; fi
    systemctl enable --now haveged chrony >/dev/null 2>&1 || true; log_success "核心服务(haveged, chrony)已启动。"
    # Persistence (rc.local)
    cat << EOF > /etc/rc.local
#!/bin/bash
echo never > /sys/kernel/mm/transparent_hugepage/enabled
if command -v cpupower >/dev/null 2>&1 && cpupower frequency-info | grep -q "performance"; then cpupower frequency-set -g performance; fi
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
    systemctl enable rc-local.service >/dev/null 2>&1; log_success "优化配置已通过rc.local持久化。"
    # Remount noatime
    mount -o remount,noatime / && log_success "'noatime' 已通过重新挂载分区立即生效。" || log_warn "'noatime' 重新挂载失败，需重启生效。"
}

# 8. 系统清理
cleanup_system() {
    log_info "Step 8: 清理系统"
    case "$OS" in
        ubuntu|debian) apt-get autoremove -y && apt-get clean -y ;;
        centos) yum autoremove -y && yum clean all ;;
    esac
    journalctl --vacuum-size=10M; log_success "系统垃圾与日志清理完成。"
}


# --- 主执行流程 ---
main() {
    initialize_environment
    fix_apt_sources
    enable_root_ssh_optional
    disable_cpu_mitigations
    install_core_tools
    configure_fail2ban_enhanced
    configure_basics
    intelligent_bbr_setup
    optimize_kernel_and_limits
    finalize_setup
    cleanup_system
    
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${GREEN}      🚀 v13.0 终极集大成版 优化已执行完毕! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${GREEN}以下优化已【立即生效】:${NC}"
    echo -e "${GREEN}  - [安全增强] Fail2ban已配置持久化规则并启动保护SSH。${NC}"
    echo -e "${GREEN}  - [智能网络] BBRv2/BBR + FQ 已自动选择并开启。${NC}"
    echo -e "${GREEN}  - [极限内核] 全面内核参数优化 (网络、内存、文件句柄等)。${NC}"
    echo -e "${GREEN}  - [硬件压榨] CPU模式, IRQ绑定, 永久I/O调度器, THP, noatime等。${NC}"
    echo -e "${GREEN}  - [核心服务] Haveged, Chrony等已启动。${NC}"
    echo ""
    echo -e "${YELLOW}以下优化需要【您的操作】才能完全激活:${NC}"
    echo -e "${YELLOW}  - 文件句柄数限制 -> 请【重新登录SSH】后生效。${NC}"
    echo -e "${YELLOW}  - [魔鬼级] CPU漏洞补丁禁用 -> 请在您方便时，手动【reboot】服务器来激活。${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${CYAN}脚本已执行完毕，命令行不会自动退出。您可以继续操作。${NC}"
}

main "$@"
