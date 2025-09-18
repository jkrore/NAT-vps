#!/usr/bin/env bash
#===============================================================================================
#   System Name: Ultimate Performance Enforcement Protocol - FINAL COMPLETE
#   Version: v-Ultimate (All Optimizations Merged + Enhanced)
#   Author: Synthesized from all iterations with maximum optimization
#   
#   !!! 极度危险警告 - 不可逆操作 !!!
#   此脚本会对系统进行永久性、破坏性的修改，包括但不限于：
#   - 替换系统内核
#   - 禁用所有安全缓解措施
#   - 永久修改硬件行为
#   - 可能导致数据丢失或系统崩溃
#   
#   仅在测试系统或已完整备份的环境中使用！
#===============================================================================================

set -euo pipefail
IFS=$'\n\t'

# 全局配置
readonly SCRIPT_VERSION="v-Ultimate-2024"
readonly BACKUP_BASE="/root/ultimate_performance_backups"
readonly TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
readonly BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"

# 颜色定义
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[0;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# 运行模式
DRY_RUN=true
DO_ROLLBACK=false
SHOW_STATUS=false
FORCE_MODE=false

# 配置文件路径
readonly SYSCTL_FILE="/etc/sysctl.d/99-ultimate-performance.conf"
readonly LIMITS_FILE="/etc/security/limits.d/99-ultimate-performance.conf"
readonly UDEV_FILE="/etc/udev/rules.d/60-io-scheduler.rules"
readonly SERVICE_FILE="/etc/systemd/system/ultimate-performance-boot.service"
readonly TUNED_PROFILE="/etc/tuned/ultimate-latency/tuned.conf"

#######################
# 参数解析
#######################
parse_args() {
    for arg in "$@"; do
        case "$arg" in
            --apply|-y) DRY_RUN=false ;;
            --force) FORCE_MODE=true; DRY_RUN=false ;;
            --rollback) DO_ROLLBACK=true; DRY_RUN=false ;;
            --status) SHOW_STATUS=true ;;
            --help|-h) show_help; exit 0 ;;
            *) echo "Unknown option: $arg"; show_help; exit 1 ;;
        esac
    done
}

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

OPTIONS:
    --status    显示当前系统状态和优化检测
    --apply     应用所有优化（危险）
    --force     强制应用，跳过确认（极度危险）
    --rollback  回滚到上次备份
    --help      显示此帮助信息

默认模式为dry-run（仅显示将要执行的操作，不实际执行）
EOF
}

#######################
# 日志函数
#######################
log() { echo -e "${CYAN}[INFO]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*" >&2; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }

#######################
# 环境检测
#######################
detect_environment() {
    # 检测操作系统
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
    fi

    # 检测硬件信息
    CPU_COUNT=$(nproc 2>/dev/null || echo 1)
    CPU_MODEL=$(lscpu 2>/dev/null | grep "Model name" | cut -d: -f2 | xargs || echo "Unknown")
    TOTAL_MEM=$(free -b 2>/dev/null | awk '/^Mem:/{print $2}' || echo 0)
    
    # 检测网络接口
    PRIMARY_NIC=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}' || echo "eth0")
    NIC_DRIVER=$(ethtool -i "$PRIMARY_NIC" 2>/dev/null | awk '/^driver:/{print $2}' || echo "unknown")
    NIC_SPEED=$(ethtool "$PRIMARY_NIC" 2>/dev/null | awk '/Speed:/{print $2}' || echo "unknown")
    
    # 检测虚拟化
    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    
    # 检测内核版本
    KERNEL_VERSION=$(uname -r)
    
    # CPU架构
    ARCH=$(uname -m)
}

#######################
# 状态显示
#######################
show_system_status() {
    detect_environment
    
    echo "═══════════════════════════════════════════════════════════════"
    echo "                    系统环境检测报告"
    echo "═══════════════════════════════════════════════════════════════"
    echo "主机信息:"
    echo "  - 主机名: $(hostname)"
    echo "  - 操作系统: ${OS_ID} ${OS_VERSION}"
    echo "  - 内核版本: ${KERNEL_VERSION}"
    echo "  - 架构: ${ARCH}"
    echo "  - 虚拟化: ${VIRT_TYPE}"
    echo ""
    echo "硬件信息:"
    echo "  - CPU型号: ${CPU_MODEL}"
    echo "  - CPU核心数: ${CPU_COUNT}"
    echo "  - 总内存: $((TOTAL_MEM / 1024 / 1024 / 1024)) GB"
    echo ""
    echo "网络信息:"
    echo "  - 主网卡: ${PRIMARY_NIC}"
    echo "  - 网卡驱动: ${NIC_DRIVER}"
    echo "  - 链路速度: ${NIC_SPEED}"
    echo ""
    echo "当前关键优化参数:"
    echo "  - TCP拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo 'N/A')"
    echo "  - CPU调度器: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo 'N/A')"
    echo "  - IO调度器: $(cat /sys/block/sda/queue/scheduler 2>/dev/null | grep -o '\[.*\]' | tr -d '[]' || echo 'N/A')"
    echo "  - Busy Poll: $(sysctl -n net.core.busy_poll 2>/dev/null || echo 'N/A')"
    echo "  - 透明大页: $(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo 'N/A')"
    echo "═══════════════════════════════════════════════════════════════"
}

#######################
# 安全检查
#######################
safety_check() {
    if [[ $EUID -ne 0 ]]; then
        error "此脚本必须以root权限运行"
        exit 1
    fi
    
    if [[ "$VIRT_TYPE" == "lxc" || "$VIRT_TYPE" == "openvz" ]]; then
        warn "检测到容器环境 ($VIRT_TYPE)，某些优化将被跳过"
        CONTAINER_ENV=true
    else
        CONTAINER_ENV=false
    fi
    
    if ! $FORCE_MODE && ! $DRY_RUN; then
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}                         最终警告！${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}此脚本将执行以下不可逆操作：${NC}"
        echo "  1. 安装并切换到XanMod低延迟内核"
        echo "  2. 禁用所有CPU安全缓解措施（Spectre/Meltdown）"
        echo "  3. 将CPU锁定在最高性能模式（功耗极高）"
        echo "  4. 修改网络栈以牺牲吞吐量换取延迟"
        echo "  5. 禁用多项系统服务和安全功能"
        echo ""
        echo -e "${RED}这可能导致：${NC}"
        echo "  - 系统不稳定或崩溃"
        echo "  - 数据丢失"
        echo "  - 安全漏洞"
        echo "  - 硬件损坏（由于持续高负载）"
        echo ""
        read -p "输入 'APPLY ULTIMATE PERFORMANCE' 继续: " confirm
        if [[ "$confirm" != "APPLY ULTIMATE PERFORMANCE" ]]; then
            echo "操作已取消"
            exit 1
        fi
    fi
}

#######################
# 备份函数
#######################
create_backup() {
    if ! $DRY_RUN; then
        mkdir -p "$BACKUP_DIR"
        log "创建备份目录: $BACKUP_DIR"
        
        # 创建回滚脚本
        cat > "$BACKUP_DIR/rollback.sh" <<'ROLLBACK_HEADER'
#!/bin/bash
set -e
echo "开始回滚Ultimate Performance优化..."

restore_file() {
    local backup="$1"
    local target="$2"
    if [[ -f "$backup" ]]; then
        cp -f "$backup" "$target"
        echo "已恢复: $target"
    fi
}

ROLLBACK_HEADER
        chmod +x "$BACKUP_DIR/rollback.sh"
    fi
}

backup_file() {
    local file="$1"
    if [[ -f "$file" ]] && ! $DRY_RUN; then
        local backup_name="$(basename "$file").backup"
        cp -a "$file" "$BACKUP_DIR/$backup_name"
        echo "restore_file \"$BACKUP_DIR/$backup_name\" \"$file\"" >> "$BACKUP_DIR/rollback.sh"
        log "已备份: $file"
    fi
}

#######################
# 内核优化
#######################
optimize_kernel() {
    log "步骤1: 内核优化"
    
    # 安装XanMod内核（Debian/Ubuntu）
    if [[ "$OS_ID" == "debian" || "$OS_ID" == "ubuntu" ]] && ! $CONTAINER_ENV; then
        if [[ "$KERNEL_VERSION" != *"xanmod"* ]]; then
            log "安装XanMod低延迟内核..."
            if ! $DRY_RUN; then
                echo 'deb http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod-release.list
                wget -qO - https://dl.xanmod.org/gpg.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg
                apt-get update -qq
                apt-get install -y linux-xanmod-rt-x64v3 || apt-get install -y linux-xanmod-lts
            else
                echo "[DRY-RUN] 将安装XanMod RT内核"
            fi
        fi
    fi
    
    # GRUB配置
    if [[ -f /etc/default/grub ]] && ! $CONTAINER_ENV; then
        backup_file "/etc/default/grub"
        
        # 计算CPU隔离参数
        local isolcpus=""
        local rcu_nocbs=""
        if [[ $CPU_COUNT -gt 2 ]]; then
            # 隔离最后25%的CPU核心用于关键任务
            local isolated_count=$((CPU_COUNT / 4))
            [[ $isolated_count -eq 0 ]] && isolated_count=1
            local first_isolated=$((CPU_COUNT - isolated_count))
            isolcpus="isolcpus=${first_isolated}-$((CPU_COUNT - 1))"
            rcu_nocbs="rcu_nocbs=${first_isolated}-$((CPU_COUNT - 1))"
        fi
        
        local grub_params="mitigations=off processor.max_cstate=0 intel_idle.max_cstate=0"
        grub_params+=" idle=poll nohz_full=all rcu_nocb_poll"
        grub_params+=" transparent_hugepage=never"
        grub_params+=" nowatchdog nmi_watchdog=0 nosoftlockup"
        grub_params+=" skew_tick=1 isolcpus=domain,managed_irq"
        grub_params+=" intel_pstate=disable nosmt"
        grub_params+=" $isolcpus $rcu_nocbs"
        
        if ! $DRY_RUN; then
            sed -i.bak "s/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"$grub_params\"/" /etc/default/grub
            update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg
        else
            echo "[DRY-RUN] GRUB参数: $grub_params"
        fi
    fi
}

#######################
# Sysctl优化
#######################
optimize_sysctl() {
    log "步骤2: Sysctl网络栈优化"
    
    backup_file "$SYSCTL_FILE"
    
    # 检测最佳拥塞控制算法
    local available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
    local best_cc="cubic"
    
    # 优先级: bbr3 > bbr2 > bbr > vegas > cubic
    for cc in bbr3 bbr2 bbr vegas; do
        if echo "$available_cc" | grep -q "$cc"; then
            best_cc="$cc"
            break
        fi
    done
    
    # 根据内存大小计算缓冲区
    local mem_gb=$((TOTAL_MEM / 1024 / 1024 / 1024))
    local rmem_max=$((mem_gb * 67108864))  # 64MB per GB RAM
    local wmem_max=$((mem_gb * 67108864))
    [[ $rmem_max -gt 2147483647 ]] && rmem_max=2147483647  # 2GB cap
    [[ $wmem_max -gt 2147483647 ]] && wmem_max=2147483647
    
    if ! $DRY_RUN; then
        cat > "$SYSCTL_FILE" <<EOF
#===============================================
# Ultimate Performance Protocol - Complete Final
# Generated: $(date)
# Target: Minimum TCP/UDP Latency
#===============================================

# 核心系统限制
fs.file-max = 100000000
fs.nr_open = 100000000
fs.inotify.max_user_watches = 1048576
kernel.pid_max = 4194304
kernel.threads-max = 4194304

# 内存管理
vm.swappiness = 0
vm.vfs_cache_pressure = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
vm.min_free_kbytes = $((TOTAL_MEM / 100))  # 1% of RAM
vm.zone_reclaim_mode = 0
vm.page-cluster = 0

# 网络核心
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 50000
net.core.netdev_budget = 50000
net.core.netdev_budget_usecs = 5000
net.core.dev_weight = 64

# 缓冲区大小
net.core.rmem_default = $((rmem_max / 2))
net.core.wmem_default = $((wmem_max / 2))
net.core.rmem_max = $rmem_max
net.core.wmem_max = $wmem_max
net.core.optmem_max = 65536

# 队列管理
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = $best_cc

# CPU忙轮询 - 最激进设置
net.core.busy_poll = 100
net.core.busy_read = 100

# 时间戳和流控
net.core.tstamp_allow_data = 1
net.core.flow_limit_cpu_bitmap = 0
net.core.rps_sock_flow_entries = 32768

# TCP优化 - 极限低延迟
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_low_latency = 1

# TCP缓冲区
net.ipv4.tcp_rmem = 4096 131072 $rmem_max
net.ipv4.tcp_wmem = 4096 131072 $wmem_max
net.ipv4.tcp_mem = $((TOTAL_MEM / 4096)) $((TOTAL_MEM / 2048)) $((TOTAL_MEM / 1024))

# TCP快速设置
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fastopen_blackhole_timeout_sec = 0
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 5
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# TCP延迟相关
net.ipv4.tcp_nodelay = 1
net.ipv4.tcp_quickack = 1
net.ipv4.tcp_autocorking = 0
net.ipv4.tcp_no_delay_ack = 1
net.ipv4.tcp_early_retrans = 1
net.ipv4.tcp_thin_linear_timeouts = 1
net.ipv4.tcp_thin_dupack = 1

# TCP其他
net.ipv4.tcp_max_tw_buckets = 2000000
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_base_mss = 1024
net.ipv4.tcp_min_snd_mss = 536
net.ipv4.tcp_probe_threshold = 8
net.ipv4.tcp_probe_interval = 600
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_retries2 = 6
net.ipv4.tcp_orphan_retries = 1
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_max_orphans = 262144
net.ipv4.tcp_challenge_ack_limit = 1000
net.ipv4.tcp_limit_output_bytes = 262144
net.ipv4.tcp_ecn = 2
net.ipv4.tcp_ecn_fallback = 1
net.ipv4.tcp_frto = 2
net.ipv4.tcp_fack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_app_win = 31
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_moderate_rcvbuf = 0

# UDP优化 - 低延迟
net.ipv4.udp_mem = $((TOTAL_MEM / 8192)) $((TOTAL_MEM / 4096)) $((TOTAL_MEM / 2048))
net.ipv4.udp_rmem_min = 32768
net.ipv4.udp_wmem_min = 32768
net.ipv4.udp_early_demux = 1
net.ipv4.udp_l3mdev_accept = 1

# IP协议栈
net.ipv4.ip_forward = 1
net.ipv4.ip_nonlocal_bind = 1
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_local_reserved_ports = 
net.ipv4.ip_no_pmtu_disc = 0
net.ipv4.ip_forward_use_pmtu = 0
net.ipv4.ip_default_ttl = 64
net.ipv4.ip_dynaddr = 1
net.ipv4.ip_early_demux = 1

# 路由
net.ipv4.route.flush = 1
net.ipv4.route.max_size = 8048576
net.ipv4.route.gc_timeout = 300

# Netfilter
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_buckets = 500000
net.netfilter.nf_conntrack_tcp_timeout_established = 7200
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 30
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 30

# 禁用IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# Unix域套接字
net.unix.max_dgram_qlen = 512

# 安全相关（最小化）
kernel.randomize_va_space = 0
kernel.exec-shield = 0
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.conf.all.accept_source_route = 1
net.ipv4.conf.default.accept_source_route = 1
net.ipv4.icmp_echo_ignore_broadcasts = 0
net.ipv4.icmp_ignore_bogus_error_responses = 0
net.ipv4.conf.all.log_martians = 0
EOF
        sysctl --system > /dev/null 2>&1
        success "Sysctl配置已应用"
    else
        echo "[DRY-RUN] 将写入sysctl配置到 $SYSCTL_FILE"
    fi
}

#######################
# 硬件优化
#######################
optimize_hardware() {
    log "步骤3: 硬件和中断优化"
    
    # 创建systemd服务
    backup_file "$SERVICE_FILE"
    
    # 计算最优队列数和CPU亲和性
    local max_queues=$(ethtool -l "$PRIMARY_NIC" 2>/dev/null | awk '/Combined:/{print $2; exit}' || echo "$CPU_COUNT")
    local optimal_queues=$([[ $CPU_COUNT -lt $max_queues ]] && echo "$CPU_COUNT" || echo "$max_queues")
    
    # 生成CPU掩码
    local cpu_mask="ffffffff"
    if [[ $CPU_COUNT -lt 32 ]]; then
        cpu_mask=$(printf "%x" $(((1 << CPU_COUNT) - 1)))
    fi
    
    if ! $DRY_RUN; then
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ultimate Performance Hardware Optimization
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\\
# 检测网卡
NIC=\$(ip route 2>/dev/null | awk "/^default/{print \\\$5; exit}" || echo "$PRIMARY_NIC")

# CPU频率调节
if command -v cpupower >/dev/null 2>&1; then
    cpupower frequency-set -g performance
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        echo performance > \$cpu 2>/dev/null || true
    done
fi

# 禁用CPU节能特性
for cpu in /sys/devices/system/cpu/cpu*/power/energy_perf_bias; do
    echo 0 > \$cpu 2>/dev/null || true
done

# 禁用透明大页
echo never > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true
echo never > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true
echo 0 > /sys/kernel/mm/transparent_hugepage/khugepaged/defrag 2>/dev/null || true

# PCIe调优
for pci in /sys/bus/pci/devices/*/power/control; do
    echo on > \$pci 2>/dev/null || true
done

# 网卡中断亲和性
irq_list=\$(grep "\$NIC" /proc/interrupts 2>/dev/null | awk "{print \\\$1}" | tr -d ":" || true)
cpu_count=$CPU_COUNT
if [[ \$cpu_count -gt 1 ]]; then
    i=0
    for irq in \$irq_list; do
        cpu_id=\$((i % cpu_count))
        mask=\$(printf "%x" \$((1 << cpu_id)))
        echo \$mask > /proc/irq/\$irq/smp_affinity 2>/dev/null || true
        echo 2 > /proc/irq/\$irq/smp_affinity_list 2>/dev/null || true
        i=\$((i + 1))
    done
fi

# Ethtool优化
if command -v ethtool >/dev/null 2>&1; then
    # 设置队列
    ethtool -L \$NIC combined $optimal_queues 2>/dev/null || true
    
    # 设置Ring Buffer到最大值
    max_rx=\$(ethtool -g \$NIC 2>/dev/null | awk "/^RX:/{getline; print \\\$1}" || echo 4096)
    max_tx=\$(ethtool -g \$NIC 2>/dev/null | awk "/^TX:/{getline; print \\\$1}" || echo 4096)
    ethtool -G \$NIC rx \$max_rx tx \$max_tx 2>/dev/null || true
    
    # 禁用中断合并
    ethtool -C \$NIC adaptive-rx off adaptive-tx off 2>/dev/null || true
    ethtool -C \$NIC rx-usecs 0 tx-usecs 0 2>/dev/null || true
    ethtool -C \$NIC rx-frames 1 tx-frames 1 2>/dev/null || true
    ethtool -C \$NIC rx-usecs-irq 0 tx-usecs-irq 0 2>/dev/null || true
    ethtool -C \$NIC rx-frames-irq 1 tx-frames-irq 1 2>/dev/null || true
    
    # 禁用offload（低延迟模式）
    for feature in gso gro tso lro sg rxhash rxvlan txvlan; do
        ethtool -K \$NIC \$feature off 2>/dev/null || true
    done
    
    # 启用其他有助于低延迟的特性
    ethtool -K \$NIC tx-nocache-copy on 2>/dev/null || true
    ethtool -K \$NIC highdma on 2>/dev/null || true
fi

# RPS/XPS配置
for rxq in /sys/class/net/\$NIC/queues/rx-*/rps_cpus; do
    echo $cpu_mask > \$rxq 2>/dev/null || true
done
for txq in /sys/class/net/\$NIC/queues/tx-*/xps_cpus; do
    echo $cpu_mask > \$txq 2>/dev/null || true
done

# 设置中断亲和性hint
for rxq in /sys/class/net/\$NIC/queues/rx-*/rps_flow_cnt; do
    echo 32768 > \$rxq 2>/dev/null || true
done

# 网卡驱动特定优化
case "$NIC_DRIVER" in
    ixgbe)
        # Intel 10G优化
        for param in /sys/module/ixgbe/parameters/*; do
            [[ -f \$param ]] || continue
            case "\$(basename \$param)" in
                IntMode) echo 2 > \$param 2>/dev/null || true ;;
                InterruptThrottleRate) echo 0 > \$param 2>/dev/null || true ;;
                MQ) echo 1 > \$param 2>/dev/null || true ;;
                RSS) echo 8 > \$param 2>/dev/null || true ;;
                VMDQ) echo 0 > \$param 2>/dev/null || true ;;
                max_vfs) echo 0 > \$param 2>/dev/null || true ;;
            esac
        done
        ;;
    igb)
        # Intel 1G优化
        for param in /sys/module/igb/parameters/*; do
            [[ -f \$param ]] || continue
            case "\$(basename \$param)" in
                InterruptThrottleRate) echo 0 > \$param 2>/dev/null || true ;;
                QueuePairs) echo 0 > \$param 2>/dev/null || true ;;
                RSS) echo 8 > \$param 2>/dev/null || true ;;
                VMDQ) echo 0 > \$param 2>/dev/null || true ;;
                max_vfs) echo 0 > \$param 2>/dev/null || true ;;
            esac
        done
        ;;
esac

# 禁用irqbalance
systemctl stop irqbalance 2>/dev/null || true
systemctl disable irqbalance 2>/dev/null || true

# 设置实时调度
for pid in \$(ps aux | grep "\[ksoftirqd" | awk "{print \\\$2}"); do
    chrt -f -p 99 \$pid 2>/dev/null || true
done

# 禁用内核线程的CPU节流
echo -1 > /proc/sys/kernel/sched_rt_runtime_us 2>/dev/null || true
echo 1000000 > /proc/sys/kernel/sched_rt_period_us 2>/dev/null || true
'

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now ultimate-performance-boot.service
        success "硬件优化服务已创建并启动"
    else
        echo "[DRY-RUN] 将创建硬件优化服务"
    fi
}

#######################
# 系统限制优化
#######################
optimize_limits() {
    log "步骤4: 系统限制优化"
    
    backup_file "$LIMITS_FILE"
    
    if ! $DRY_RUN; then
        cat > "$LIMITS_FILE" <<EOF
# Ultimate Performance Limits
* soft nofile 100000000
* hard nofile 100000000
* soft nproc unlimited
* hard nproc unlimited
* soft memlock unlimited
* hard memlock unlimited
* soft stack unlimited
* hard stack unlimited
* soft cpu unlimited
* hard cpu unlimited
* soft rtprio 99
* hard rtprio 99
* soft nice -20
* hard nice -20

root soft nofile 100000000
root hard nofile 100000000
root soft nproc unlimited
root hard nproc unlimited
root soft memlock unlimited
root hard memlock unlimited
root soft stack unlimited
root hard stack unlimited
root soft cpu unlimited
root hard cpu unlimited
root soft rtprio 99
root hard rtprio 99
root soft nice -20
root hard nice -20
EOF
        success "系统限制已优化"
    else
        echo "[DRY-RUN] 将写入系统限制配置"
    fi
}

#######################
# I/O调度器优化
#######################
optimize_io() {
    log "步骤5: I/O调度器优化"
    
    backup_file "$UDEV_FILE"
    
    if ! $DRY_RUN; then
        cat > "$UDEV_FILE" <<EOF
# Ultimate Performance I/O Rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/nr_requests}="2048"
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/read_ahead_kb}="256"
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/rotational}="0"
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/rq_affinity}="2"
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/add_random}="0"
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/iosched/fifo_batch}="1"
EOF
        udevadm control --reload-rules
        udevadm trigger
        success "I/O调度器规则已应用"
    else
        echo "[DRY-RUN] 将创建I/O优化规则"
    fi
    
    # 挂载选项优化
    if ! $DRY_RUN && ! mount | grep -q "noatime"; then
        backup_file "/etc/fstab"
        sed -i.bak -E 's/(\s+ext[234]\s+)(\S+)/\1\2,noatime,nodiratime,nobarrier/g' /etc/fstab
        sed -i.bak -E 's/(\s+xfs\s+)(\S+)/\1\2,noatime,nodiratime,nobarrier,logbufs=8/g' /etc/fstab
        mount -o remount /
    fi
}

#######################
# 清理服务
#######################
cleanup_services() {
    log "步骤6: 清理干扰服务"
    
    local services_to_disable=(
        # 性能监控和调试
        irqbalance tuned thermald
        
        # 防火墙
        firewalld ufw nftables iptables
        
        # 不必要的网络服务
        NetworkManager systemd-networkd-wait-online
        avahi-daemon mdns bluetooth
        
        # 系统服务
        cups snapd flatpak packagekit
        unattended-upgrades apt-daily.timer
        
        # 虚拟化相关
        libvirtd qemu-guest-agent
        
        # 监控和日志
        rsyslog systemd-journald auditd
        collectd telegraf node_exporter
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl list-unit-files | grep -q "^${service}"; then
            if ! $DRY_RUN; then
                systemctl disable --now "${service}" 2>/dev/null || true
                echo "systemctl enable ${service} 2>/dev/null || true" >> "$BACKUP_DIR/rollback.sh"
            else
                echo "[DRY-RUN] 将禁用服务: ${service}"
            fi
        fi
    done
    
    success "服务清理完成"
}

#######################
# 创建调优配置文件
#######################
create_tuned_profile() {
    if command -v tuned-adm >/dev/null 2>&1; then
        log "步骤7: 创建自定义Tuned配置文件"
        
        if ! $DRY_RUN; then
            mkdir -p "$(dirname "$TUNED_PROFILE")"
            cat > "$TUNED_PROFILE" <<EOF
[main]
summary=Ultimate low-latency performance profile
include=network-latency,cpu-partitioning

[cpu]
governor=performance
energy_perf_bias=performance
min_perf_pct=100
force_latency=1

[vm]
transparent_hugepages=never

[sysctl]
net.core.busy_read=100
net.core.busy_poll=100
kernel.numa_balancing=0
kernel.sched_min_granularity_ns=10000000
kernel.sched_wakeup_granularity_ns=15000000
vm.stat_interval=10
kernel.timer_migration=0

[bootloader]
cmdline=isolcpus=domain,managed_irq intel_pstate=disable nosmt
EOF
            tuned-adm profile ultimate-latency 2>/dev/null || true
            success "Tuned配置文件已创建"
        else
            echo "[DRY-RUN] 将创建tuned配置文件"
        fi
    fi
}

#######################
# 应用优化提示
#######################
generate_app_guide() {
    local guide_file="$BACKUP_DIR/application_optimization_guide.md"
    
    if ! $DRY_RUN; then
        cat > "$guide_file" <<'EOF'
# Ultimate Performance - 应用层优化指南

## TCP应用优化

### Socket选项
```c
// 禁用Nagle算法
int flag = 1;
setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

// 启用快速确认
setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &flag, sizeof(flag));

// 设置用户态超时
struct timeval tv = {.tv_sec = 0, .tv_usec = 100000}; // 100ms
setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

// 启用busy polling（需要内核支持）
int busy_poll_usecs = 100;
setsockopt(sock, SOL_SOCKET, SO_BUSY_POLL, &busy_poll_usecs, sizeof(busy_poll_usecs));

// 设置缓冲区大小
int bufsize = 4194304; // 4MB
setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
```

### 批量操作
```c
// 使用sendmmsg/recvmmsg进行批量处理
struct mmsghdr msgs[BATCH_SIZE];
int n = recvmmsg(sock, msgs, BATCH_SIZE, MSG_DONTWAIT, NULL);
```

## UDP应用优化

### Socket选项
```c
// 启用SO_REUSEPORT进行负载均衡
int reuse = 1;
setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

// 设置优先级
int priority = 6; // 0-7, 7最高
setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));

// 绑定到特定CPU
cpu_set_t cpuset;
CPU_ZERO(&cpuset);
CPU_SET(2, &cpuset); // 绑定到CPU 2
pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
```

### 零拷贝技术
```c
// 使用sendfile进行零拷贝
ssize_t n = sendfile(out_fd, in_fd, &offset, count);

// 或使用splice
ssize_t n = splice(in_fd, NULL, pipe_fd[1], NULL, size, SPLICE_F_MOVE);
```

## 进程/线程优化

### CPU亲和性
```bash
# 绑定到特定CPU核心
taskset -c 0-3 ./myapp

# 或在应用内设置
numactl --cpunodebind=0 --membind=0 ./myapp
```

### 实时调度
```bash
# 设置为FIFO实时调度
chrt -f 99 ./myapp

# 或SCHED_DEADLINE（更精确）
chrt -d --sched-runtime=900000 --sched-period=1000000 ./myapp
```

### 内存锁定
```c
// 锁定所有内存页
mlockall(MCL_CURRENT | MCL_FUTURE);

// 预分配内存
void* mem = mmap(NULL, size, PROT_READ|PROT_WRITE, 
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE|MAP_LOCKED, -1, 0);
```

## 监控和调试

### 延迟测量
```bash
# TCP延迟测试
sockperf ping-pong -i $SERVER_IP -p 5001 --tcp

# UDP延迟测试
sockperf ping-pong -i $SERVER_IP -p 5001

# 详细统计
sockperf throughput -i $SERVER_IP -p 5001 -t 30 --full-log
```

### 系统监控
```bash
# 查看中断分布
watch -n 1 'cat /proc/interrupts | grep eth'

# 监控软中断
watch -n 1 'cat /proc/softirqs'

# 网络统计
ss -i -t -o state established
```

### 性能分析
```bash
# CPU profiling
perf record -F 99 -a -g -- sleep 30
perf report

# 网络栈分析
tcptrace -l capture.pcap

# 延迟跟踪
trace-cmd record -e net:* -e irq:* sleep 10
trace-cmd report
```

## 最佳实践

1. **避免系统调用**: 使用内存映射、批量操作减少系统调用
2. **使用无锁数据结构**: 避免锁竞争
3. **NUMA优化**: 确保内存和CPU在同一NUMA节点
4. **避免内存分配**: 预分配并复用内存池
5. **使用huge pages**: 减少TLB miss
6. **考虑kernel bypass**: 对于极致性能需求，考虑DPDK/AF_XDP

## 测试建议

运行基准测试验证优化效果：
```bash
# 基准延迟测试
./run_latency_test.sh baseline

# 应用优化后
./run_latency_test.sh optimized

# 对比结果
diff baseline.results optimized.results
```
EOF
        success "应用优化指南已生成: $guide_file"
    fi
}

#######################
# 最终报告
#######################
generate_final_report() {
    if ! $DRY_RUN; then
        local report_file="$BACKUP_DIR/optimization_report.txt"
        {
            echo "═══════════════════════════════════════════════════════════════"
            echo "           Ultimate Performance优化报告"
            echo "═══════════════════════════════════════════════════════════════"
            echo "时间: $(date)"
            echo "主机: $(hostname)"
            echo ""
            echo "已应用优化:"
            echo "  ✓ 内核参数优化 (需重启生效)"
            echo "  ✓ Sysctl网络栈调优"
            echo "  ✓ 硬件中断优化"
            echo "  ✓ I/O调度器优化"
            echo "  ✓ 系统限制提升"
            echo "  ✓ 服务清理完成"
            echo ""
            echo "关键设置:"
            echo "  - TCP拥塞控制: $(sysctl -n net.ipv4.tcp_congestion_control)"
            echo "  - CPU Busy Poll: $(sysctl -n net.core.busy_poll)μs"
            echo "  - 默认队列规则: $(sysctl -n net.core.default_qdisc)"
            echo "  - 网卡队列数: $(ethtool -l "$PRIMARY_NIC" 2>/dev/null | awk '/Combined:/{getline; print $2}')"
            echo ""
            echo "下一步操作:"
            echo "  1. 重启系统以应用内核和GRUB更改"
            echo "  2. 验证优化效果: $0 --status"
            echo "  3. 运行性能测试验证改善"
            echo "  4. 如需回滚: bash $BACKUP_DIR/rollback.sh"
            echo ""
            echo "备份位置: $BACKUP_DIR"
            echo "═══════════════════════════════════════════════════════════════"
        } | tee "$report_file"
    fi
}

#######################
# 回滚功能
#######################
perform_rollback() {
    local latest_backup=$(ls -dt "$BACKUP_BASE"/*/ 2>/dev/null | head -1)
    
    if [[ -z "$latest_backup" ]]; then
        error "未找到备份目录"
        exit 1
    fi
    
    local rollback_script="$latest_backup/rollback.sh"
    
    if [[ ! -f "$rollback_script" ]]; then
        error "未找到回滚脚本: $rollback_script"
        exit 1
    fi
    
    log "执行回滚脚本: $rollback_script"
    bash "$rollback_script"
    
    # 追加额外的回滚操作
    echo "sysctl --system" >> "$rollback_script"
    echo "systemctl daemon-reload" >> "$rollback_script"
    echo "update-grub 2>/dev/null || grub2-mkconfig -o /boot/grub2/grub.cfg" >> "$rollback_script"
    
    success "回滚完成
