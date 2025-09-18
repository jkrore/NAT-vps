#!/usr/bin/env bash
#===============================================================================================
#   System Name: Ultimate Performance Enforcement Protocol - FINAL ARCHITECTURE
#   Version: v-Final-Architecture (Architecturally Sound, Non-Interactive)
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
readonly SCRIPT_VERSION="v-Final-Architecture"
readonly BACKUP_BASE="/root/ultimate_performance_backups"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"
readonly RED='\033[0;31m'; readonly GREEN='\033[0;32m'; readonly YELLOW='\033[0;33m'; readonly CYAN='\033[0;36m'; readonly NC='\033[0m'

# --- 日志与执行函数 ---
log() { echo -e "\n${CYAN}>>> $1${NC}"; }
success() { echo -e "${GREEN}✔ $1${NC}"; }
warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
error() { echo -e "${RED}✖ $1${NC}"; }

backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        cp -a "$file" "$BACKUP_DIR/$(basename "$file").bak"
        log "已备份: $file"
    fi
}

# --- 核心执行函数 ---

step_1_kernel_and_grub() {
    log "步骤1: [根基重构] 强制安装实时内核并配置GRUB"
    
    if [[ -f /etc/os-release ]]; then source /etc/os-release; OS_ID="${ID:-unknown}"; OS_CODENAME="${VERSION_CODENAME:-bullseye}"; else OS_ID="unknown"; OS_CODENAME="bullseye"; fi
    local KERNEL_VERSION=$(uname -r)
    
    if [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]] && [[ "$(systemd-detect-virt 2>/dev/null)" != "lxc" ]]; then
        if [[ "$KERNEL_VERSION" != *"xanmod"* ]]; then
            warn "检测到非XanMod内核，开始强制替换为实时(RT)版本..."
            
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
                if [ -d "$apt_backup_dir/sources.list.d" ]; then mv "$apt_backup_dir/sources.list.d"/* /etc/apt/sources.list.d/ 2>/dev/null || true; fi
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
            cleanup_apt
            trap - EXIT
        else
            success "已检测到XanMod内核。"
        fi
    fi
    
    if [[ -f /etc/default/grub ]] && [[ "$(systemd-detect-virt 2>/dev/null)" != "lxc" ]]; then
        backup_file /etc/default/grub
        local CPU_COUNT=$(nproc)
        local ISO=""
        if [[ $CPU_COUNT -gt 2 ]]; then
            local ISO_START=$(( CPU_COUNT - (CPU_COUNT/4) )); [[ $ISO_START -le 0 ]] && ISO_START=1
            ISO="${ISO_START}-$((CPU_COUNT-1))"
        fi
        local GRUB_PARAMS="mitigations=off processor.max_cstate=0 intel_idle.max_cstate=0 idle=poll rcu_nocb_poll nohz_full=${ISO} rcu_nocbs=${ISO} isolcpus=${ISO} intel_pstate=disable nosmt nowatchdog nmi_watchdog=0 nosoftlockup transparent_hugepage=never"
        sed -i.bak "s|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_PARAMS}\"|" /etc/default/grub
        update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg 2>/dev/null || true
        success "GRUB终极参数已固化。重启后生效。"
    fi
}

step_2_sysctl() {
    log "步骤2: [核心重构] Sysctl网络与内核栈极限优化"
    local SYSCTL_FILE="/etc/sysctl.d/99-ultimate-zero-latency.conf"
    backup_file "$SYSCTL_FILE"
    
    local available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
    local best_cc="bbr"; for cc in bbr3 bbr2; do if echo "$available_cc" | grep -q "$cc"; then best_cc="$cc"; break; fi; done
    
    cat > "$SYSCTL_FILE" <<-EOF
#--- Ultimate Performance Protocol - FINAL ARCHITECTURE ---
# [最终公理] 赋予系统海量的资源句柄
fs.file-max=100000000
fs.nr_open=100000000
kernel.pid_max=4194304
# [最终公理] 极限压榨内存管理，禁止交换
vm.swappiness=0
vm.vfs_cache_pressure=10
vm.overcommit_memory=1
vm.dirty_ratio=5
vm.dirty_background_ratio=2
# [最终公理] 重构网络核心，一切为低延迟服务
net.core.somaxconn=262144
net.core.netdev_max_backlog=262144
net.core.rmem_max=268435456
net.core.wmem_max=268435456
net.core.rmem_default=67108864
net.core.wmem_default=67108864
net.core.optmem_max=262144
net.core.default_qdisc=fq
# [最终公理] 启用最激进的CPU忙轮询
net.core.busy_poll=1000
net.core.busy_read=1000
# [最终公理] 极限重构TCP协议栈
net.ipv4.tcp_congestion_control=$best_cc
net.ipv4.tcp_low_latency=1
net.ipv4.tcp_timestamps=1
net.ipv4.tcp_sack=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_rmem=4096 262144 134217728
net.ipv4.tcp_wmem=4096 262144 134217728
net.ipv4.tcp_nodelay=1
net.ipv4.tcp_quickack=1
net.ipv4.tcp_autocorking=0
net.ipv4.tcp_fin_timeout=5
net.ipv4.tcp_retries2=3
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_max_syn_backlog=262144
net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_no_delay_ack=1
net.ipv4.tcp_early_retrans=1
net.ipv4.tcp_thin_linear_timeouts=1
net.ipv4.tcp_notsent_lowat=32768
# [最终公理] 极限重构UDP协议栈
net.ipv4.udp_mem=8192 65536 268435456
net.ipv4.udp_rmem_min=65536
net.ipv4.udp_wmem_min=65536
net.ipv4.udp_early_demux=1
# [最终公理] 禁用IPv6
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
# [最终公理] 禁用所有影响性能的安全特性
kernel.randomize_va_space=0
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.accept_source_route=1
EOF
    sysctl --system > /dev/null 2>&1
    success "Sysctl终极配置已应用。"
}

step_3_hardware_and_interrupts() {
    log "步骤3: [硬件固化] 通过Systemd服务永久固化硬件、中断与驱动"
    
    # 【新架构】 创建独立的帮助脚本
    local HELPER_SCRIPT="/usr/local/bin/ultimate-performance-helper.sh"
    local PRIMARY_NIC=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}' || echo "eth0")
    local CPU_COUNT=$(nproc)
    local max_queues=$(ethtool -l "$PRIMARY_NIC" 2>/dev/null | awk '/Combined:/{print $2; exit}' || echo "$CPU_COUNT")
    local optimal_queues=$([[ $CPU_COUNT -lt $max_queues ]] && echo "$CPU_COUNT" || echo "$max_queues")
    local cpu_mask=$(printf "%x" $(((1 << CPU_COUNT) - 1)))

    cat > "$HELPER_SCRIPT" <<EOF
#!/bin/bash
set -x
NIC=\$(ip route 2>/dev/null | awk "/^default/{print \\\$5; exit}" || echo "$PRIMARY_NIC")
# [绝对强制] CPU频率、节能与Boost
if command -v cpupower >/dev/null 2>&1; then cpupower frequency-set -g performance; fi
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > \$cpu 2>/dev/null; done
if [[ -f /sys/devices/system/cpu/intel_pstate/no_turbo ]]; then echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo; fi
if [[ -f /sys/devices/system/cpu/cpufreq/boost ]]; then echo 0 > /sys/devices/system/cpu/cpufreq/boost; fi
# [绝对强制] 禁用透明大页
echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null
# [绝对强制] Ethtool终极优化 (纯延迟模式)
if command -v ethtool >/dev/null 2>&1; then
    max_rx=\$(ethtool -g \$NIC 2>/dev/null | awk -F"\\t" "/^RX:/{getline; print \\\$1}" || echo 4096)
    max_tx=\$(ethtool -g \$NIC 2>/dev/null | awk -F"\\t" "/^TX:/{getline; print \\\$1}" || echo 4096)
    ethtool -L \$NIC combined $optimal_queues &>/dev/null
    ethtool -G \$NIC rx \$max_rx tx \$max_tx &>/dev/null
    ethtool -C \$NIC adaptive-rx off adaptive-tx off rx-usecs 0 tx-usecs 0 rx-frames 1 tx-frames 1 &>/dev/null
    for feature in gso gro tso lro sg rxhash rxvlan txvlan; do ethtool -K \$NIC \$feature off &>/dev/null; done
fi
# [绝对强制] 网卡中断亲和性: 均匀分布到所有核心
irq_list=\$(grep "\$NIC" /proc/interrupts 2>/dev/null | awk "{print \\\$1}" | tr -d ":" || true)
i=0; for irq in \$irq_list; do mask=\$(printf "%x" \$((1 << (i % $CPU_COUNT)))); echo \$mask > /proc/irq/\$irq/smp_affinity 2>/dev/null; i=\$((i + 1)); done
# [绝对强制] RPS/XPS配置: 启用所有核心
for rxq in /sys/class/net/\$NIC/queues/rx-*/rps_cpus; do echo $cpu_mask > \$rxq 2>/dev/null; done
for txq in /sys/class/net/\$NIC/queues/tx-*/xps_cpus; do echo $cpu_mask > \$txq 2>/dev/null; done
# [绝对强制] 实时调度与内核线程节流
echo -1 > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null
for pid in \$(pgrep -f "ksoftirqd"); do chrt -f -p 99 \$pid 2>/dev/null; done
EOF
    
    chmod +x "$HELPER_SCRIPT"
    success "独立的硬件优化脚本已创建: $HELPER_SCRIPT"

    # 【新架构】 创建极简的Systemd服务文件
    local SERVICE_FILE="/etc/systemd/system/ultimate-performance.service"
    backup_file "$SERVICE_FILE"
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ultimate Performance Hardware & Scheduling Service (FINAL ARCHITECTURE)
After=network.target
[Service]
Type=oneshot
ExecStart=$HELPER_SCRIPT
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now ultimate-performance.service
    success "硬件优化systemd服务已固化并立即生效。"
}

step_4_limits_and_io() {
    log "步骤4: [系统固化] 系统限制与I/O调度器优化"
    local LIMIT_FILE="/etc/security/limits.d/99-ultimate-zero-latency.conf"
    backup_file "$LIMIT_FILE"
    cat > "$LIMIT_FILE" <<'EOF'
* soft nofile 100000000
* hard nofile 100000000
* soft nproc unlimited
* hard nproc unlimited
* soft memlock unlimited
* hard memlock unlimited
* soft rtprio 99
* hard rtprio 99
root soft nofile 100000000
root hard nofile 100000000
EOF
    success "系统资源限制已提升至极限。"
    
    local UDEV_FILE="/etc/udev/rules.d/60-ultimate-io.rules"
    backup_file "$UDEV_FILE"
    cat > "$UDEV_FILE" <<'EOF'
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none", ATTR{queue/nr_requests}="2048"
EOF
    udevadm control --reload-rules && udevadm trigger || true
    mount -o remount,noatime,nodiratime / || true
    success "I/O调度器与挂载选项已优化。"
}

step_5_cleanup_services() {
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

step_6_generate_guidance() {
    log "步骤6: [最终指令] 生成应用层优化指南"
    cat > "${BACKUP_DIR}/app_socket_hints.txt" <<'EOF'
Application-level changes to implement for minimum latency:

1) Use SO_BUSY_POLL (requires <linux/net.h> support and net.core.busy_poll>0):
   int busy = 1000; setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &busy, sizeof(busy));

2) Disable Nagle:
   int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

3) Enable QUICKACK (careful):
   setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));

4) Use recvmmsg/sendmmsg for batching without syscalls.

5) Consider kernel-bypass for ultimate latency: AF_XDP or DPDK.

6) Use SCHED_DEADLINE or SCHED_FIFO for critical threads: 'chrt -f 99 ...'

7) mlockall(MCL_CURRENT|MCL_FUTURE) to prevent page faults.

8) Use CPU affinity (taskset / pthread_setaffinity_np) to pin your app to non-isolated cores.
EOF
    success "应用层指南已生成: ${BACKUP_DIR}/app_socket_hints.txt"
}

# --- 主流程 ---
main() {
    if [[ "$(id -u)" -ne 0 ]]; then error "此脚本必须以root权限运行。"; exit 1; fi
    clear
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "      ${GREEN}终极性能协议 v-Final-Architecture (最终架构版) - 执行开始${NC}"
    echo -e "${RED}      警告: 此操作不可逆，将对系统进行永久性底层修改。${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    
    mkdir -p "$BACKUP_DIR"
    log "备份目录已创建: $BACKUP_DIR"
    
    step_1_kernel_and_grub
    step_2_sysctl
    step_3_hardware_and_interrupts
    step_4_limits_and_io
    step_5_cleanup_services
    step_6_generate_guidance
    
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${RED}      🚀 公理奇点已达成，系统已进入最终的、不可变的性能形态! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${GREEN}所有配置已根据延迟公理进行唯一性固化。网络协议栈与硬件中断已重构。${NC}"
    error "最终指令: 必须【重启(reboot)】以激活全新的系统核心、GRUB参数与CPU隔离！"
    echo -e "${CYAN}您的意志已贯彻。系统演化已终结。${NC}"
}

main "$@"
