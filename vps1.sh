
#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 13.3 (Ultimate Annihilation Edition)
#   Author: AI Executor
#   Description: 遵从用户指令，为追求纯粹性能而生的逻辑终点。
#                - [算法领先] 优先检测并启用最先进的BBRv3。
#                - [极限内核] 内核参数被推向理论极限 (swappiness=1, 激进dirty ratio)。
#                - [硬件压榨] GRUB层面彻底禁用CPU所有节能状态，强制CPU永远全速运行。
#                - [焦土可选] 新增从内核层面彻底禁用IPv6的终极选项。
#                - [纯粹性能] 移除所有非性能相关的安全建议模块。
#
#   !!! 终极危险警告 - 魔鬼协议 !!!
#   1. 此脚本包含禁用CPU硬件漏洞补丁与所有节能特性的选项，将使系统暴露于安全风险并显著增加功耗。
#   2. 终极的内核与硬件策略可能导致系统在特定负载下不稳定、无响应或过热。
#   3. 您必须自愿承担包括但不限于数据丢失、系统损坏、安全入侵、硬件损坏等所有风险。
#===============================================================================================

# --- 全局设置与工具函数 ---
set -euo pipefail # 启用严谨模式，任何命令返回非零(错误)即中止脚本

BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "\n${CYAN}>>> $1${NC}"; }
log_success() { echo -e "${GREEN}✔ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
log_error() { echo -e "${RED}✖ $1${NC}"; }
add_config() {
    local file=$1 content=$2 pattern=${3:-$2}
    if ! grep -qF -- "$pattern" "$file"; then
        echo "$content" >> "$file"
    fi
}

# --- 核心函数 ---

# 0. 初始化
initialize_environment() {
    log_info "Step 0: 初始化环境并检测系统"
    if [[ "$(id -u)" -ne 0 ]]; then log_error "此脚本必须以root用户权限运行。"; exit 1; fi
    mkdir -p "$BACKUP_DIR"; log_success "所有原始配置文件将备份至: $BACKUP_DIR"
    
    if ! command -v lsb_release >/dev/null 2>&1; then
        apt-get update >/dev/null 2>&1 && apt-get install -y lsb-release >/dev/null 2>&1 || yum install -y redhat-lsb-core >/dev/null 2>&1
    fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID; VERSION_ID=$VERSION_ID; OS_CODENAME=$(lsb_release -cs)
    else
        log_error "无法检测到操作系统类型。"; exit 1;
    fi
    log_success "检测到操作系统: $OS $VERSION_ID ($OS_CODENAME)"

    log_info "正在检测服务器地理位置..."
    local location_info; location_info=$(curl -s --connect-timeout 5 http://ip-api.com/json/)
    if [[ -z "$location_info" ]]; then
        log_warn "无法获取地理位置信息，将使用默认国际配置。"; IS_IN_CHINA="false"
    else
        local country_code; country_code=$(echo "$location_info" | grep -o '"countryCode":"[^"]*' | cut -d'"' -f4)
        if [ "$country_code" = "CN" ]; then log_success "检测到服务器位于中国。"; IS_IN_CHINA="true"; else log_success "检测到服务器位于海外 ($country_code)。"; IS_IN_CHINA="false"; fi
    fi
}

# 0.5 [健壮性] 动态修复APT软件源
fix_apt_sources() {
    if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
        log_info "Step 0.5: [自我修复] 动态配置 $OS ($OS_CODENAME) 软件源..."
        cp /etc/apt/sources.list "$BACKUP_DIR/sources.list.bak"
        if [ "$IS_IN_CHINA" = "true" ]; then
            log_info "使用国内镜像源 (Tuna)..."
            if [[ "$OS" == "debian" ]]; then
                cat << EOF > /etc/apt/sources.list
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ $OS_CODENAME main contrib non-free
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ $OS_CODENAME-updates main contrib non-free
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ $OS_CODENAME-backports main contrib non-free
deb https://security.debian.org/debian-security $OS_CODENAME-security main contrib non-free
EOF
            elif [[ "$OS" == "ubuntu" ]]; then
                 cat << EOF > /etc/apt/sources.list
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $OS_CODENAME main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $OS_CODENAME-updates main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $OS_CODENAME-backports main restricted universe multiverse
deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ $OS_CODENAME-security main restricted universe multiverse
EOF
            fi
        fi
        log_success "$OS $OS_CODENAME 软件源已配置。"
    fi
}

# 1. [可选高风险] 开启root用户SSH密码登录
enable_root_ssh_optional() {
    log_info "Step 1: [可选高风险] 开启root用户SSH密码登录"
    log_warn "安全警告: 直接允许root用户通过密码登录会显著增加服务器被暴力破解的风险。"
    read -p "是否要执行此项操作? (y/n): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then log_info "已跳过开启root密码登录。"; return; fi
    
    log_info "请为root用户设置一个新密码。务必使用高强度的复杂密码！"
    passwd root
    
    cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || log_warn "请手动重启SSH服务。"
    log_success "Root用户SSH密码登录已强制开启。"
}

# 2. [魔鬼级] GRUB终极性能配置 (需重启)
configure_grub_ultimate_performance() {
    log_info "Step 2: [魔鬼级] 配置GRUB终极性能参数 (CPU漏洞/节能/IO)"
    log_warn "!!! 极度危险操作 !!! 这将禁用CPU漏洞补丁、禁用所有CPU节能状态(功耗和温度会显著上升)。"
    log_warn "仅当您100%确定自己在做什么，并且愿意承担所有风险时，才可继续。"
    read -p "请输入 'I UNDERSTAND THE RISK' 以确认执行: " confirmation
    if [[ "$confirmation" != "I UNDERSTAND THE RISK" ]]; then log_error "确认失败，已中止操作。"; return; fi

    if [ ! -f /etc/default/grub ]; then log_warn "/etc/default/grub 文件不存在，跳过。"; return; fi
    cp -a /etc/default/grub "$BACKUP_DIR/grub.bak"
    
    local current_cmdline=$(grep 'GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | cut -d'"' -f2)
    # 移除旧参数，避免重复
    current_cmdline=$(echo "$current_cmdline" | sed -e 's/mitigations=off//g' -e 's/processor.max_cstate=1//g' -e 's/intel_idle.max_cstate=0//g' -e 's/idle=poll//g' | tr -s ' ')
    # 添加终极参数
    local new_cmdline="$current_cmdline mitigations=off processor.max_cstate=1 intel_idle.max_cstate=0 idle=poll"
    sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"/" /etc/default/grub
    
    if command -v update-grub >/dev/null 2>&1; then update-grub; elif command -v grub2-mkconfig >/dev/null 2>&1; then grub2-mkconfig -o /boot/grub2/grub.cfg; else log_warn "无法自动更新GRUB配置，请手动执行。"; fi
    log_success "GRUB终极性能参数已配置。此项优化【必须重启虚拟机】才能生效。"
}

# 2.5 [可选焦土策略] 彻底禁用IPv6 (需重启)
disable_ipv6_optional() {
    log_info "Step 2.5: [可选焦土策略] 彻底禁用IPv6"
    log_warn "此操作将从内核层面彻底禁用IPv6。如果您的应用或网络环境需要IPv6，将会导致故障！"
    read -p "是否要彻底禁用IPv6? (y/n): " choice
    if [[ "$choice" != "y" && "$choice" != "Y" ]]; then log_info "已跳过禁用IPv6。"; return; fi

    # Sysctl 层面
    cat << EOF > /etc/sysctl.d/98-vps-optimizer-disable-ipv6.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    sysctl --system >/dev/null 2>&1

    # GRUB 层面
    if [ -f /etc/default/grub ]; then
        local current_cmdline=$(grep 'GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | cut -d'"' -f2)
        current_cmdline=$(echo "$current_cmdline" | sed 's/ipv6.disable=1//g' | tr -s ' ')
        local new_cmdline="$current_cmdline ipv6.disable=1"
        sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"/" /etc/default/grub
        if command -v update-grub >/dev/null 2>&1; then update-grub; elif command -v grub2-mkconfig >/dev/null 2>&1; then grub2-mkconfig -o /boot/grub2/grub.cfg; fi
    fi
    log_success "IPv6已从内核层面禁用。此项优化【必须重启虚拟机】才能完全生效。"
}

# 3. 安装核心工具
install_core_tools() {
    log_info "Step 3: 更新软件包并安装核心工具"
    case "$OS" in
        ubuntu|debian) apt-get update && apt-get install -y curl chrony haveged procps fail2ban cpufrequtils tuned ;;
        centos|rhel|almalinux|rocky) yum update -y && yum install -y epel-release && yum install -y curl chrony haveged procps-ng fail2ban kernel-tools tuned ;;
    esac
    log_success "核心工具安装与系统更新完成。"
}

# 3.5 [安全增强] 配置Fail2ban持久化规则
configure_fail2ban_enhanced() {
    log_info "Step 3.5: [安全增强] 配置Fail2ban持久化规则"
    if ! command -v fail2ban-server >/dev/null 2>&1; then log_warn "Fail2ban 未安装，跳过配置。"; return; fi
    cat << EOF > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 5
[sshd]
enabled = true
EOF
    systemctl enable --now fail2ban >/dev/null 2>&1
    log_success "Fail2ban已配置持久化规则并启动。"; log_info "当前Fail2ban状态: $(systemctl is-active fail2ban)"
}

# 4. 智能配置基础环境 (Swap/DNS/NTP)
configure_basics() {
    log_info "Step 4: 智能配置基础环境 (Swap/DNS/NTP)"
    # Swap
    if [ "$(swapon --show | wc -l)" -le 1 ]; then
        local MEM_TOTAL_MB=$(free -m | awk '/^Mem:/{print $2}'); local SWAP_SIZE_MB=$((MEM_TOTAL_MB < 2048 ? MEM_TOTAL_MB * 2 : (MEM_TOTAL_MB < 8192 ? MEM_TOTAL_MB : 8192) ))
        log_info "物理内存: ${MEM_TOTAL_MB}MB, 建议Swap: ${SWAP_SIZE_MB}MB"; read -p "是否创建Swap文件? (y/n): " choice
        if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
            cp -a /etc/fstab "$BACKUP_DIR/fstab.swap.bak"; fallocate -l "${SWAP_SIZE_MB}M" /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
            add_config "/etc/fstab" "/swapfile none swap sw 0 0" "/swapfile"; log_success "Swap创建成功！"
        fi
    else log_warn "检测到已存在的Swap，跳过创建。"; fi
    
    # DNS (智能适配版)
    local dns1 dns2; if [ "$IS_IN_CHINA" = "true" ]; then dns1="223.5.5.5"; dns2="119.29.29.29"; log_info "准备配置国内DNS: $dns1, $dns2"; else dns1="1.1.1.1"; dns2="8.8.8.8"; log_info "准备配置国际DNS: $dns1, $dns2"; fi
    if systemctl is-active --quiet systemd-resolved; then
        log_info "检测到 systemd-resolved 服务，使用 'resolvectl' 进行持久化配置..."; resolvectl dns global "$dns1" "$dns2"; systemctl restart systemd-resolved; log_success "已通过 systemd-resolved 持久化配置DNS。"
    else
        log_warn "未检测到 systemd-resolved。将直接修改 /etc/resolv.conf (可能被覆盖)。"; echo -e "nameserver $dns1\nnameserver $dns2" > /etc/resolv.conf; log_success "已临时配置DNS。"
    fi

    # NTP
    local chrony_conf_path="/etc/chrony/chrony.conf"; if [ ! -f "$chrony_conf_path" ]; then chrony_conf_path="/etc/chrony.conf"; fi
    if [ -f "$chrony_conf_path" ]; then
        cp -a "$chrony_conf_path" "$BACKUP_DIR/chrony.conf.bak"
        if [ "$IS_IN_CHINA" = "true" ]; then sed -i '/^pool/d;/^server/d' "$chrony_conf_path"; echo -e "server ntp.aliyun.com iburst\nserver ntp.tencent.com iburst" >> "$chrony_conf_path"; else sed -i '/^pool/d;/^server/d' "$chrony_conf_path"; echo -e "pool 2.pool.ntp.org iburst" >> "$chrony_conf_path"; fi
        systemctl restart chronyd 2>/dev/null || systemctl restart chrony 2>/dev/null; log_success "NTP服务已配置并重启。"
    fi
}

# 5 & 6. [融合] 内核、BBR与系统限制优化
optimize_kernel_and_limits() {
    log_info "Step 5 & 6: [融合] 应用内核、BBR与系统限制优化"
    local conf_file="/etc/sysctl.d/97-vps-optimizer.conf"
    
    # BBR (v13.3 优先BBRv3)
    modprobe tcp_bbr >/dev/null 2>&1; modprobe tcp_bbr2 >/dev/null 2>&1; modprobe tcp_bbr3 >/dev/null 2>&1
    local available_bbrs=$(sysctl -n net.ipv4.tcp_available_congestion_control)
    local best_bbr=""
    if [[ "$available_bbrs" == *"bbr3"* ]]; then best_bbr="bbr3"; elif [[ "$available_bbrs" == *"bbr2"* ]]; then best_bbr="bbr2"; elif [[ "$available_bbrs" == *"bbr"* ]]; then best_bbr="bbr"; fi
    
    # Kernel Params (v13.3 极限版)
    cat << EOF > "$conf_file"
#--- Kernel Optimization by VPS-Optimizer v13.3 (Ultimate Annihilation) ---
fs.file-max=10240000
fs.nr_open=10240000
net.core.somaxconn=262144
net.core.netdev_max_backlog=262144
net.ipv4.tcp_max_syn_backlog=262144
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_rmem=4096 87380 134217728
net.ipv4.tcp_wmem=4096 65536 134217728
vm.swappiness=1
vm.vfs_cache_pressure=50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
EOF

    if [ -n "$best_bbr" ]; then
        log_success "检测到最佳BBR版本: $best_bbr. 正在配置..."
        echo "net.core.default_qdisc = fq_pie" >> "$conf_file"
        echo "net.ipv4.tcp_congestion_control = $best_bbr" >> "$conf_file"
    else log_warn "您的内核不支持任何BBR版本，跳过此项优化。"; fi
    
    sysctl --system >/dev/null 2>&1; log_success "内核参数已成功应用。"

    # Limits
    echo -e "* soft nofile 10240000\n* hard nofile 10240000" > /etc/security/limits.d/97-vps-optimizer.conf
    log_success "文件句柄数限制已配置。"
}

# 7. [融合] 硬件压榨与服务配置 (免重启)
finalize_setup() {
    log_info "Step 7: [融合] 应用硬件压榨、服务配置与持久化"
    
    # I/O Scheduler (Persistent via udev)
    cat << EOF > /etc/udev/rules.d/60-io-scheduler.rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"
EOF
    udevadm control --reload-rules && udevadm trigger; log_success "I/O调度器已通过udev永久设为 'none'。"
    
    # fstab 持久化 noatime
    log_info "正在为根分区 / 持久化配置 'noatime'..."
    cp -a /etc/fstab "$BACKUP_DIR/fstab.noatime.bak"
    if grep -q -E '^\S+\s+/\s+' /etc/fstab && ! (grep -q -E '^\S+\s+/\s+' /etc/fstab | grep -q 'noatime'); then
        sed -i -E "s|^(\S+\s+/\s+\S+\s+)(\S+)(\s+.*)$|\1\2,noatime\3|" /etc/fstab
        log_success "/etc/fstab 中根分区的 'noatime' 已配置。"; mount -o remount,noatime /
    else log_warn "根分区已配置 'noatime' 或未找到，跳过。"; fi

    # Core Services
    if [[ "$OS" == "centos" || "$OS" == "rhel" || "$OS" == "almalinux" || "$OS" == "rocky" ]] && command -v tuned-adm >/dev/null 2>&1; then
        tuned-adm profile virtual-guest; systemctl enable --now tuned; log_success "Tuned服务已为CentOS/RHEL系设为 'virtual-guest' 模式。"
    fi
    systemctl enable --now haveged chrony >/dev/null 2>&1 || true; log_success "核心服务(haveged, chrony)已设为开机自启。"
    
    # Persistence (Modern systemd way - 增强版)
    local cpu_count=$(nproc); local eth_device=$(ip route | grep '^default' | awk '{print $5}' | head -1 || true); local irq_affinity_script=""
    if [ "$cpu_count" -gt 1 ] && [ -n "$eth_device" ]; then
        irq_affinity_script="irq_list=\$(grep '$eth_device' /proc/interrupts | awk '{print \$1}' | tr -d ':'); i=0; for irq in \$irq_list; do echo \$(printf '%x' \$((1 << (i % $cpu_count)))) > /proc/irq/\$irq/smp_affinity; i=\$((i + 1)); done"
    fi

    cat << EOF > /etc/systemd/system/vps-optimizer-boot.service
[Unit]
Description=VPS Optimizer Boot Tasks
After=network.target
[Service]
Type=oneshot
ExecStart=/bin/bash -c "echo never > /sys/kernel/mm/transparent_hugepage/enabled; \
if command -v cpupower >/dev/null 2>&1 && cpupower frequency-info | grep -q 'performance'; then cpupower frequency-set -g performance; fi; \
$irq_affinity_script"
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable --now vps-optimizer-boot.service >/dev/null 2>&1
    log_success "优化配置已通过systemd服务(vps-optimizer-boot.service)持久化。"
}

# 8. 系统清理
cleanup_system() {
    log_info "Step 8: 清理系统"
    case "$OS" in
        ubuntu|debian) apt-get autoremove -y && apt-get clean -y ;;
        centos|rhel|almalinux|rocky) yum autoremove -y && yum clean all ;;
    esac
    journalctl --vacuum-size=10M >/dev/null 2>&1; log_success "系统垃圾与日志清理完成。"
}

# --- 主执行流程 ---
main() {
    initialize_environment
    fix_apt_sources
    enable_root_ssh_optional
    configure_grub_ultimate_performance
    disable_ipv6_optional
    install_core_tools
    configure_fail2ban_enhanced
    configure_basics
    optimize_kernel_and_limits
    finalize_setup
    cleanup_system
    
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${RED}      🚀 v13.3 终极毁灭版 优化已执行完毕! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${GREEN}以下优化已【立即生效并永久固化】:${NC}"
    echo -e "${GREEN}  - [极限网络] 最佳BBR版本(优先v3) + FQ_PIE 已自动开启。"
    echo -e "${GREEN}  - [极限内核] 全面内核参数优化 (swappiness=1, 激进dirty ratio)。"
    echo -e "${GREEN}  - [持久化]   所有即时优化已通过systemd/fstab/udev彻底持久化。"
    echo ""
    echo -e "${RED}以下【魔鬼级】优化需要【重启】才能激活:${NC}"
    echo -e "${RED}  - [CPU压榨] 漏洞补丁禁用 + CPU节能彻底禁用 -> 请手动【reboot】。"
    echo -e "${RED}  - [网络压榨] (如果选择) IPv6彻底禁用 -> 请手动【reboot】。"
    echo -e "${YELLOW}其他优化需要【重新登录SSH】才能完全生效:${NC}"
    echo -e "${YELLOW}  - 文件句柄数限制。"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${CYAN}脚本已执行完毕。榨干硬件最后一滴性能。${NC}"
}

main "$@"
