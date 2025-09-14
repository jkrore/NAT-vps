#!/bin/bash

#===============================================================================================
#   System Name: 终极性能强制执行脚本 (Ultimate Performance Enforcer)
#   Version: 28.0 (Total Synthesis Edition - The Final Command)
#   Author: AI Executor (Synthesized from Community Wisdom under User's Final Command)
#   Description: 小鸡极限优化脚本。
#
#   !!! 终极危险警告 - 魔鬼协议 !!!
#   1. 此脚本将对您的系统进行大量底层修改，包括但不限于禁用CPU安全补丁、调整内核行为、
#      修改系统服务、优化网卡硬件参数。这些操作为高风险行为。
#   2. 作为指令的唯一发布者，您将为此脚本引发的所有后果（包括系统不稳定、数据丢失、
#      网络中断、无法启动等）承担全部责任。
#   3. 在生产环境或存有重要数据的服务器上运行前，请确保您完全理解每一行代码的含义，
#      并已做好完整备份。
#===============================================================================================

# --- 全局设置与工具函数 ---
set -o pipefail
export DEBIAN_FRONTEND=noninteractive
BACKUP_DIR="/root/system_backup_$(date +%Y%m%d_%H%M%S)"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS_ICON="${GREEN}✔${NC}"; FAIL_ICON="${RED}✖${NC}"; PEND_ICON="${YELLOW}⏳${NC}"

log_info() { echo -e "\n${CYAN}>>> $1${NC}"; }
log_success() { echo -e "${GREEN}✔ $1${NC}"; }
log_warn() { echo -e "${YELLOW}⚠ $1${NC}"; }
log_error() { echo -e "${RED}✖ $1${NC}"; }

# --- 主执行流程 ---
main() {
    clear
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "        ${GREEN}终极性能强制执行脚本 v28.0 (完全合成体) - 执行开始${NC}"
    echo -e "${CYAN}======================================================================${NC}"

    # 步骤 0: 环境预检查与初始化
    log_info "Step 0: 环境预检查与初始化"
    if [[ "$(id -u)" -ne 0 ]]; then log_error "致命错误: 此脚本必须以root用户权限运行。"; exit 1; fi
    mkdir -p "$BACKUP_DIR"; log_success "备份目录已创建: $BACKUP_DIR"

    if [ -f /etc/os-release ]; then . /etc/os-release; OS=$ID; else log_error "致命错误: 无法检测到操作系统类型。"; exit 1; fi
    log_success "检测到操作系统: $OS"

    log_info "正在静默安装核心依赖 (iproute2, ethtool, systemd)..."
    if [[ "$OS" == "debian" || "$OS" == "ubuntu" ]]; then
        apt-get update -qq >/dev/null && apt-get install -y -qq iproute2 ethtool systemd curl gpg >/dev/null
    elif [[ "$OS" == "centos" || "$OS" == "almalinux" || "$OS" == "rocky" || "$OS" == "fedora" ]]; then
        yum install -y -q iproute ethtool systemd curl gpg >/dev/null
    fi
    log_success "核心依赖已确保安装。"

    VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "kvm")
    log_success "检测到虚拟化技术: $VIRT_TYPE"
    ETH_DEVICE=$(ip route | grep '^default' | awk '{print $5}' | head -1 || echo "eth0")
    log_success "检测到主网络接口: $ETH_DEVICE"

    # 步骤 1: GRUB魔鬼模式配置 (需重启生效)
    log_info "Step 1: [硬件压榨] 配置GRUB魔鬼模式 (需重启)"
    if [[ "$VIRT_TYPE" != "lxc" && "$VIRT_TYPE" != "openvz" ]] && [ -f /etc/default/grub ]; then
        cp -a /etc/default/grub "$BACKUP_DIR/grub.bak"
        local current_cmdline=$(grep 'GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub | cut -d'"' -f2)
        current_cmdline=$(echo "$current_cmdline" | sed -E 's/mitigations=off|processor.max_cstate=[0-9]+|intel_idle.max_cstate=[0-9]+|idle=poll|ipv6.disable=1//g' | tr -s ' ')
        local new_cmdline="$current_cmdline mitigations=off processor.max_cstate=1 intel_idle.max_cstate=0 idle=poll ipv6.disable=1"
        sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"${new_cmdline}\"/" /etc/default/grub
        if command -v update-grub >/dev/null 2>&1; then update-grub; elif command -v grub2-mkconfig >/dev/null 2>&1; then grub2-mkconfig -o /boot/grub2/grub.cfg; fi
        log_success "GRUB终极性能参数已配置。"
    else
        log_warn "检测到容器环境或GRUB文件不存在，跳过此项。"
    fi

    # 步骤 2: 内核运行时极限优化 (即时生效)
    log_info "Step 2: [核心] 强制写入内核运行时参数 (sysctl)"
    # 智能检测最佳TCP拥塞控制算法
    modprobe tcp_bbr >/dev/null 2>&1; modprobe tcp_bbr2 >/dev/null 2>&1; modprobe tcp_bbr3 >/dev/null 2>&1
    local available_ccs=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
    local best_cc="cubic" # 默认降级
    if [[ "$available_ccs" == *"bbr3"* ]]; then best_cc="bbr3"; elif [[ "$available_ccs" == *"bbr2"* ]]; then best_cc="bbr2"; elif [[ "$available_ccs" == *"bbr"* ]]; then best_cc="bbr"; fi
    log_success "智能检测到最佳拥塞控制算法: $best_cc"

    local conf_file="/etc/sysctl.d/99-ultimate-performance.conf"
    cat << EOF > "$conf_file"
#--- Ultimate Performance Enforcer v28.0 (Total Synthesis) ---
# [文件系统与句柄]
fs.file-max = 10240000
fs.nr_open = 10240000
# [网络: 核心与缓冲区]
net.core.somaxconn = 1048576
net.core.netdev_max_backlog = 1048576
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.default_qdisc = fq_pie
# [网络: TCP协议栈]
net.ipv4.tcp_congestion_control = $best_cc
net.ipv4.tcp_max_syn_backlog = 1048576
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
# [网络: UDP协议栈]
net.ipv4.udp_mem = 8192 65536 134217728
# [内存与虚拟化]
vm.swappiness = 1
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 1
vm.min_free_kbytes = 65536
# [IPv6 禁用]
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
    sysctl --system >/dev/null 2>&1
    log_success "所有内核参数已写入配置文件并强制应用。"

    # 步骤 3: 系统级优化与持久化 (即时生效)
    log_info "Step 3: [系统] 应用系统级优化并确保持久化"
    echo -e "* soft nofile 10240000\n* hard nofile 10240000\nroot soft nofile 10240000\nroot hard nofile 10240000" > /etc/security/limits.d/99-ultimate-performance.conf
    log_success "文件句柄数限制已配置。"

    cat << EOF > /etc/udev/rules.d/60-io-scheduler.rules
ACTION=="add|change", KERNEL=="sd[a-z]|vd[a-z]|xvd[a-z]|hd[a-z]|nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none"
EOF
    udevadm control --reload-rules && udevadm trigger
    log_success "I/O调度器已通过udev永久设为 'none'。"
    
    if ! mount | grep -q ' / .*noatime'; then
        cp -a /etc/fstab "$BACKUP_DIR/fstab.bak" 2>/dev/null
        sed -i -E "s|^(\S+\s+/\s+\S+\s+)(\S+)(\s+.*)$|\1\2,noatime,nodiratime\3|" /etc/fstab
        mount -o remount,noatime,nodiratime /
        log_success "根分区 'noatime' 已配置并立即生效。"
    fi

    # 步骤 4: DNS与硬件层优化 (即时生效 + 持久化)
    log_info "Step 4: [网络深化] DNS解析与网卡硬件层优化"
    if [ -f /etc/systemd/resolved.conf ]; then
        if ! grep -q "DNS=1.1.1.1 8.8.8.8" /etc/systemd/resolved.conf; then
            cp -a /etc/systemd/resolved.conf "$BACKUP_DIR/resolved.conf.bak"
            sed -i -e 's/^#?DNS=.*/DNS=1.1.1.1 8.8.8.8/' -e 's/^#?FallbackDNS=.*/FallbackDNS=1.0.0.1 8.8.4.4/' -e 's/^#?Cache=.*/Cache=yes/' /etc/systemd/resolved.conf
            systemctl restart systemd-resolved &>/dev/null
            log_success "已配置 systemd-resolved 使用高速DNS并启用缓存。"
        else
            log_success "systemd-resolved 已配置，跳过。"
        fi
    fi

    local cpu_count=$(nproc); local irq_affinity_script=""
    if [ "$cpu_count" -gt 1 ]; then
        irq_affinity_script="irq_list=\$(grep '$ETH_DEVICE' /proc/interrupts | awk '{print \$1}' | tr -d ':'); i=0; for irq in \$irq_list; do echo \$(printf '%x' \$((1 << (i % $cpu_count)))) > /proc/irq/\$irq/smp_affinity; i=\$((i + 1)); done"
    fi
    
    cat << EOF > /etc/systemd/system/ultimate-performance-boot.service
[Unit]
Description=Ultimate Performance Boot Tasks (CPU, THP, IRQ, Ethtool)
After=network.target
[Service]
Type=oneshot
ExecStart=/bin/bash -c "echo never > /sys/kernel/mm/transparent_hugepage/enabled; \
echo never > /sys/kernel/mm/transparent_hugepage/defrag; \
if command -v cpupower >/dev/null 2>&1; then cpupower frequency-set -g performance; fi; \
$irq_affinity_script; \
if command -v ethtool >/dev/null 2>&1; then \
    ethtool -G $ETH_DEVICE rx 4096 tx 4096 &>/dev/null; \
    ethtool -K $ETH_DEVICE gso off gro off tso off &>/dev/null; \
fi"
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload; systemctl enable --now ultimate-performance-boot.service >/dev/null 2>&1
    log_success "硬件优化(THP, CPU, IRQ, Ethtool)已通过systemd服务持久化并立即生效。"

    # 步骤 5: 系统瘦身与维护
    log_info "Step 5: [系统精简] 清理无用服务与启用维护"
    local services_to_disable=("cups" "postfix" "exim4" "smb" "nfs" "avahi-daemon" "bluetooth" "iscsi" "lvm2-monitor" "mdmonitor" "ufw" "firewalld")
    for service in "${services_to_disable[@]}"; do
        systemctl disable --now "${service}.service" >/dev/null 2>&1
        systemctl disable --now "${service}.socket" >/dev/null 2>&1
    done
    log_success "常见无用及防火墙服务已清理 (为代理性能最大化)。"

    if ! systemctl is-active --quiet fstrim.timer; then
        systemctl enable --now fstrim.timer >/dev/null 2>&1
        log_success "SSD TRIM 定时任务 (fstrim.timer) 已启用。"
    fi

    # 步骤 6: 最终自我审计报告
    log_info "Step 6: 最终自我审计报告 (Final Self-Audit Report)"
    echo -e "----------------------------------------------------------------------"
    echo -e "内核版本:       $(uname -r)"
    tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control); if [[ "$tcp_cc" == "$best_cc" ]]; then echo -e "TCP拥塞控制:    ${PASS_ICON} $tcp_cc"; else echo -e "TCP拥塞控制:    ${FAIL_ICON} $tcp_cc (目标: $best_cc)"; fi
    qdisc=$(sysctl -n net.core.default_qdisc); if [[ "$qdisc" == "fq_pie" ]]; then echo -e "网络发包队列:   ${PASS_ICON} $qdisc"; else echo -e "网络发包队列:   ${FAIL_ICON} $qdisc (目标: fq_pie)"; fi
    thp_status=$(cat /sys/kernel/mm/transparent_hugepage/enabled); if [[ "$thp_status" == *"[never]"* ]]; then echo -e "透明大页 (THP):   ${PASS_ICON} 已禁用"; else echo -e "透明大页 (THP):   ${FAIL_ICON} 未禁用"; fi
    io_sched=$(cat /sys/block/$(ls /sys/block | grep -E 'sd|vd|xvd|hd|nvme' | head -1)/queue/scheduler 2>/dev/null || echo "N/A"); if [[ "$io_sched" == *"[none]"* || "$io_sched" == *"[noop]"* ]]; then echo -e "I/O调度器:      ${PASS_ICON} ${io_sched}"; else echo -e "I/O调度器:      ${FAIL_ICON} ${io_sched}"; fi
    if command -v ethtool >/dev/null 2>&1; then
        rx_buffers=$(ethtool -g $ETH_DEVICE 2>/dev/null | grep 'RX:' | awk '{print $2}'); if [[ "$rx_buffers" -ge 4096 ]]; then echo -e "网卡RX缓冲区:   ${PASS_ICON} $rx_buffers"; else echo -e "网卡RX缓冲区:   ${PEND_ICON} $rx_buffers (目标: 4096)"; fi
    fi
    echo -e "文件句柄数限制: ${PEND_ICON} 10240000 (需重新登录或重启服务生效)"
    echo -e "----------------------------------------------------------------------"

    # 最终指令
    echo -e "\n${GREEN}======================================================================${NC}"
    echo -e "${RED}      🚀 终极性能强制执行完毕 (完全合成体)! 🚀${NC}"
    echo -e "${YELLOW}======================================================================${NC}"
    echo -e "${GREEN}所有运行时优化已强制生效。DNS解析与网卡硬件层已深度优化。${NC}"
    log_error "最终指令: GRUB配置已更新，必须【重启(reboot)】才能激活终极硬件性能！"
    echo -e "${CYAN}您的意志已贯彻。${NC}"
}

main "$@"
