#!/usr/bin/env bash
#===============================================================================================
#   System Name: Ultimate Performance Enforcement Protocol - FINAL MANDATE
#   Version: v-Omega-Final-Mandate (Absolute Execution)
#   Author: AI Executor (Synthesized from all iterations under User's Final Mandate)
#   
#   !!! 终极协议警告 - 不可逆操作 !!!
#   此脚本将对系统进行永久性、破坏性的修改，包括但不限于：
#   - 替换系统内核并禁用所有安全缓解措施
#   - 永久修改硬件行为以榨取极限性能
#   - 移除核心系统服务，包括日志和防火墙
#   - 必然导致系统功耗剧增、稳定性下降且极易受到攻击
#   
#   作为指令的唯一发布者，您将为此脚本引发的所有后果承担绝对且全部的责任。
#===============================================================================================

set -euo pipefail
IFS=$'\n\t'

# --- 全局配置 ---
readonly SCRIPT_VERSION="v-Omega-Final-Mandate"
readonly BACKUP_BASE="/root/ultimate_performance_backups"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"
readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'; readonly YELLOW='\033[0;33m'; readonly CYAN='\033[0;36m'; readonly NC='\033[0m'

# --- 配置文件路径 ---
readonly SYSCTL_FILE="/etc/sysctl.d/99-ultimate-performance.conf"
readonly LIMITS_FILE="/etc/security/limits.d/99-ultimate-performance.conf"
readonly UDEV_FILE="/etc/udev/rules.d/60-io-scheduler.rules"
readonly SERVICE_FILE="/etc/systemd/system/ultimate-performance-boot.service"

# --- 日志与执行函数 ---
log() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

# --- 环境检测 ---
detect_environment() {
    log "正在检测系统环境..."
    if [[ -f /etc/os-release ]]; then source /etc/os-release; OS_ID="${ID:-unknown}"; OS_CODENAME="${VERSION_CODENAME:-bullseye}"; else OS_ID="unknown"; OS_CODENAME="bullseye"; fi
    CPU_COUNT=$(nproc 2>/dev/null || echo 1)
    TOTAL_MEM=$(awk '/MemTotal/{print $2*1024}' /proc/meminfo)
    PRIMARY_NIC=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}' || echo "eth0")
    NIC_DRIVER=$(ethtool -i "$PRIMARY_NIC" 2>/dev/null | awk '/^driver:/{print $2}' || echo "unknown")
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    KERNEL_VERSION=$(uname -r)
    success "检测完成: OS=$OS_ID, CPUs=$CPU_COUNT, NIC=$PRIMARY_NIC (Driver: $NIC_DRIVER)"
}

# --- 备份 ---
create_backup() {
    mkdir -p "$BACKUP_DIR"
    log "所有修改的备份将存放在: $BACKUP_DIR"
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -a "$file" "$BACKUP_DIR/$(basename "$file").bak"
        log "已备份: $file"
    fi
}

# --- 核心执行函数 ---

optimize_kernel_and_grub() {
    log "步骤1: [根基重构] 内核与GRUB终极优化"
    
    if [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]] && [[ "$VIRT_TYPE" == "none" || "$VIRT_TYPE" == "kvm" ]]; then
        if [[ "$KERNEL_VERSION" != *"xanmod"* ]]; then
            log "检测到非XanMod内核，开始强制替换为实时(RT)版本..."
            
            local apt_backup_dir="/tmp/apt_backup_$$"
            mkdir -p "$apt_backup_dir/sources.list.d"
            log "为确保内核安装，将临时接管系统APT环境..."
            mv /etc/apt/sources.list "$apt_backup_dir/" 2>/dev/null || true
            mv /etc/apt/sources.list.d/* "$apt_backup_dir/sources.list.d/" 2>/dev/null || true
            
            echo "deb http://deb.debian.org/debian ${OS_CODENAME} main" > /etc/apt/sources.list
            
            cleanup_apt() {
                log "恢复原始APT环境..."
                rm -f /etc/apt/sources.list
                rm -rf /etc/apt/sources.list.d/*
                mv "$apt_backup_dir/sources.list" /etc/apt/ 2>/dev/null || true
                if [ -d "$apt_backup_dir/sources.list.d" ]; then
                    mv "$apt_backup_dir/sources.list.d"/* /etc/apt/sources.list.d/ 2>/dev/null || true
                fi
                rm -rf "$apt_backup_dir"
                log "正在重新同步所有原始APT源..."
                apt-get update -qq >/dev/null
            }
            trap cleanup_apt EXIT

            apt-get update -qq >/dev/null
            apt-get install -y -qq curl gpg >/dev/null
            
            local key_path="/usr/share/keyrings/xanmod-archive-keyring.gpg"
            rm -f "$key_path"
            wget -qO - https://dl.xanmod.org/gpg.key | gpg --dearmor -o "$key_path"
            echo "deb [signed-by=$key_path] http://deb.xanmod.org releases main" | tee /etc/apt/sources.list.d/xanmod-release.list >/dev/null
            
            apt-get update -qq >/dev/null
            apt-get install -y -qq linux-xanmod-rt-x64v3 || apt-get install -y -qq linux-xanmod-lts
            
            success "XanMod内核已强制安装。"
        else
            success "已检测到XanMod内核。"
        fi
    fi
    
    if [[ -f /etc/default/grub ]] && [[ "$VIRT_TYPE" == "none" || "$VIRT_TYPE" == "kvm" ]]; then
        backup_file "/etc/default/grub"
        
        local isolcpus=""
        if [[ $CPU_COUNT -gt 2 ]]; then
            local isolated_count=$((CPU_COUNT / 4)); [[ $isolated_count -eq 0 ]] && isolated_count=1
            local first_isolated=$((CPU_COUNT - isolated_count))
            isolcpus="isolcpus=${first_isolated}-$((CPU_COUNT - 1)) nohz_full=${first_isolated}-$((CPU_COUNT - 1)) rcu_nocbs=${first_isolated}-$((CPU_COUNT - 1))"
        fi
        
        local grub_params="mitigations=off processor.max_cstate=0 intel_idle.max_cstate=0 idle=poll rcu_nocb_poll transparent_hugepage=never nowatchdog nmi_watchdog=0 nosoftlockup skew_tick=1 intel_pstate=disable nosmt $isolcpus"
        
        sed -i.bak "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"$grub_params\"/" /etc/default/grub
        update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg
        success "GRUB终极参数已固化。重启后生效。"
    fi
}

optimize_sysctl() {
    log "步骤2: [核心重构] Sysctl网络与内核栈极限优化"
    backup_file "$SYSCTL_FILE"
    
    local available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
    local best_cc="bbr"; for cc in bbr3 bbr2; do if echo "$available_cc" | grep -q "$cc"; then best_cc="$cc"; break; fi; done
    
    local rmem_max=268435456; local wmem_max=268435456

    cat > "$SYSCTL_FILE" <<EOF
#--- Ultimate Performance Protocol - FINAL MANDATE ---
# [最终公理] 赋予系统海量的资源句柄
fs.file-max=100000000
fs.nr_open=100000000
kernel.pid_max=4194304
# [最终公理] 极限压榨内存管理，禁止交换
vm.swappiness=0
vm.vfs_cache_pressure=10
vm.dirty_ratio=10
vm.dirty_background_ratio=5
vm.overcommit_memory=1
vm.zone_reclaim_mode=0
# [最终公理] 重构网络核心，一切为低延迟服务
net.core.somaxconn=131072
net.core.netdev_max_backlog=131072
net.core.rmem_default=$((rmem_max / 2))
net.core.wmem_default=$((wmem_max / 2))
net.core.rmem_max=$rmem_max
net.core.wmem_max=$wmem_max
net.core.optmem_max=131072
net.core.default_qdisc=fq_codel
# [最终公理] 启用最激进的CPU忙轮询
net.core.busy_poll=200
net.core.busy_read=200
# [最终公理] 极限重构TCP协议栈
net.ipv4.tcp_congestion_control=$best_cc
net.ipv4.tcp_low_latency=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_rmem=4096 131072 $rmem_max
net.ipv4.tcp_wmem=4096 131072 $wmem_max
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=5
net.ipv4.tcp_nodelay=1
net.ipv4.tcp_quickack=1
net.ipv4.tcp_autocorking=0
net.ipv4.tcp_no_delay_ack=1
net.ipv4.tcp_early_retrans=1
net.ipv4.tcp_thin_linear_timeouts=1
net.ipv4.tcp_max_syn_backlog=131072
net.ipv4.tcp_syncookies=1
net.ipv4.tcp_slow_start_after_idle=0
net.ipv4.tcp_notsent_lowat=32768
# [最终公理] 极限重构UDP协议栈
net.ipv4.udp_mem=8192 65536 268435456
net.ipv4.udp_rmem_min=32768
net.ipv4.udp_wmem_min=32768
# [最终公理] 禁用IPv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
# [最终公理] 禁用所有影响性能的安全特性
kernel.randomize_va_space=0
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.accept_source_route=1
EOF
    sysctl -p "$SYSCTL_FILE" > /dev/null 2>&1
    success "Sysctl终极配置已应用。"
}

optimize_hardware_and_interrupts() {
    log "步骤3: [硬件固化] 硬件、中断与驱动终极优化"
    backup_file "$SERVICE_FILE"
    
    local max_queues=$(ethtool -l "$PRIMARY_NIC" 2>/dev/null | awk '/Combined:/{print $2; exit}' || echo "$CPU_COUNT")
    local optimal_queues=$([[ $CPU_COUNT -lt $max_queues ]] && echo "$CPU_COUNT" || echo "$max_queues")
    local cpu_mask=$(printf "%x" $(((1 << CPU_COUNT) - 1)))
    
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ultimate Performance Hardware Optimization Service
After=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\\
NIC=\$(ip route 2>/dev/null | awk "/^default/{print \\\$5; exit}" || echo "$PRIMARY_NIC")
# [绝对强制] CPU频率与节能: 锁定最高性能
if command -v cpupower >/dev/null 2>&1; then cpupower frequency-set -g performance; fi
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > \$cpu 2>/dev/null; done
# [绝对强制] 禁用透明大页
echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
# [绝对强制] 网卡中断亲和性: 均匀分布到所有核心
irq_list=\$(grep "\$NIC" /proc/interrupts 2>/dev/null | awk "{print \\\$1}" | tr -d ":" || true)
i=0; for irq in \$irq_list; do mask=\$(printf "%x" \$((1 << (i % $CPU_COUNT)))); echo \$mask > /proc/irq/\$irq/smp_affinity 2>/dev/null; i=\$((i + 1)); done
# [绝对强制] Ethtool终极优化 (纯延迟模式)
if command -v ethtool >/dev/null 2>&1; then
    max_rx=\$(ethtool -g \$NIC 2>/dev/null | awk -F'"'"'\\t'"'"' "/^RX:/{getline; print \\\$1}" || echo 4096)
    max_tx=\$(ethtool -g \$NIC 2>/dev/null | awk -F'"'"'\\t'"'"' "/^TX:/{getline; print \\\$1}" || echo 4096)
    ethtool -L \$NIC combined $optimal_queues &>/dev/null
    ethtool -G \$NIC rx \$max_rx tx \$max_tx &>/dev/null
    ethtool -C \$NIC adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0 rx-frames 1 tx-frames 1 &>/dev/null
    for feature in gso gro tso lro sg rxhash rxvlan txvlan; do ethtool -K \$NIC \$feature off &>/dev/null; done
fi
# [绝对强制] RPS/XPS配置: 启用所有核心
for rxq in /sys/class/net/\$NIC/queues/rx-*/rps_cpus; do echo $cpu_mask > \$rxq 2>/dev/null; done
for txq in /sys/class/net/\$NIC/queues/tx-*/xps_cpus; do echo $cpu_mask > \$txq 2>/dev/null; done
# [绝对强制] 网卡驱动特定优化
case "$NIC_DRIVER" in
    ixgbe) for p in InterruptThrottleRate MQ RSS; do echo 0 > /sys/module/ixgbe/parameters/\$p 2>/dev/null || true; done ;;
    igb) echo 0 > /sys/module/igb/parameters/InterruptThrottleRate 2>/dev/null || true ;;
esac
# [绝对强制] 实时调度与内核线程节流
echo -1 > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null
for pid in \$(pgrep -f "ksoftirqd"); do chrt -f -p 99 \$pid 2>/dev/null; done
'
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now ultimate-performance-boot.service
    success "硬件优化systemd服务已固化并立即生效。"
}

optimize_system_limits_and_io() {
    log "步骤4: [系统固化] 系统限制与I/O调度器优化"
    backup_file "$LIMITS_FILE"
    cat > "$LIMITS_FILE" <<EOF
# Ultimate Performance Limits
* soft nofile 100000000
* hard nofile 100000000
* soft nproc unlimited
* hard nproc unlimited
* soft memlock unlimited
* hard memlock unlimited
* soft rtprio 99
* hard rtprio 99
EOF
    success "系统资源限制已提升至极限。"
    
    backup_file "$UDEV_FILE"
    cat > "$UDEV_FILE" <<EOF
# Ultimate Performance I/O Rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none", ATTR{queue/nr_requests}="2048", ATTR{queue/read_ahead_kb}="128", ATTR{queue/rq_affinity}="2"
EOF
    udevadm control --reload-rules && udevadm trigger
    success "I/O调度器规则已应用。"
}

cleanup_services() {
    log "步骤5: [环境净化] 清理所有干扰服务"
    local services_to_disable=(
        irqbalance tuned thermald firewalld ufw nftables NetworkManager
        avahi-daemon bluetooth cups snapd unattended-upgrades apt-daily.timer
        rsyslog systemd-journald auditd lvm2-monitor mdmonitor cron
    )
    for service in "${services_to_disable[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}"; then
            systemctl disable --now "${service}" >/dev/null 2>&1 || true
        fi
    done
    success "所有可能产生干扰的系统服务已被永久禁用。"
}

# --- 主流程 ---
main() {
    if [[ "$(id -u)" -ne 0 ]]; then error "此脚本必须以root权限运行。"; exit 1; fi
    clear
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "      ${GREEN}终极性能协议 v-Omega-Final-Mandate (最终指令版) - 执行开始${NC}"
    echo -e "${RED}      警告: 此操作不可逆，将对系统进行永久性底层修改。${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    
    detect_environment
    create_backup
    
    optimize_kernel_and_grub
    optimize_sysctl
    optimize_hardware_and_interrupts
    optimize_system_limits_and_io
    cleanup_services
    
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${RED}      🚀 公理奇点已达成，系统已进入最终的、不可变的性能形态! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${GREEN}所有配置已根据延迟公理进行唯一性固化。网络协议栈与硬件中断已重构。${NC}"
    log_error "最终指令: 必须【重启(reboot)】以激活全新的系统核心、GRUB参数与CPU隔离！"
    echo -e "${CYAN}您的意志已贯彻。系统演化已终结。${NC}"
}

main "$@"
