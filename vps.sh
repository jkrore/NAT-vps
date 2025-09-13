#!/bin/bash

#===============================================================================================
#   System Name: 优化效果验证脚本 (Optimizer-Verification-Script)
#   Version: 1.0
#   Author: AI Executor
#   Description: 专门用于验证 "VPS-Optimizer-Ultimate v13.3" 脚本优化效果的只读检查工具。
#===============================================================================================

# --- 全局设置与工具函数 ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info() { echo -e "\n${CYAN}>>> $1${NC}"; }
check_pass() { echo -e "  ${GREEN}[✔] $1${NC}"; }
check_fail() { echo -e "  ${RED}[✖] $1${NC}"; }
check_warn() { echo -e "  ${YELLOW}[⚠] $1${NC}"; }

# --- 验证函数 ---

check_reboot_required() {
    log_info "Part 1: 魔鬼级优化 (需要重启才能完全生效)"
    
    local cmdline=$(cat /proc/cmdline)
    
    # 1.1 检查CPU漏洞补丁
    if [[ "$cmdline" == *"mitigations=off"* ]]; then
        check_pass "CPU漏洞补丁已禁用 (mitigations=off)。"
    else
        check_fail "CPU漏洞补丁未禁用。请检查 /etc/default/grub 并重启。"
    fi

    # 1.2 检查CPU节能状态
    if [[ "$cmdline" == *"processor.max_cstate=1"* && "$cmdline" == *"intel_idle.max_cstate=0"* && "$cmdline" == *"idle=poll"* ]]; then
        check_pass "CPU节能状态已彻底禁用 (cstate/idle)。"
    else
        check_fail "CPU节能状态未禁用。请检查 /etc/default/grub 并重启。"
    fi

    # 1.3 检查IPv6禁用状态 (如果执行了)
    if [[ "$cmdline" == *"ipv6.disable=1"* ]]; then
        if ! ip a | grep -q "inet6"; then
            check_pass "IPv6已从内核层面彻底禁用。"
        else
            check_warn "GRUB已配置禁用IPv6，但系统中仍检测到IPv6地址，可能未完全生效。"
        fi
    else
        check_warn "未从GRUB层面禁用IPv6 (此为可选操作)。"
    fi
}

check_network_and_kernel() {
    log_info "Part 2: 网络与内核优化 (应立即生效)"

    # 2.1 检查BBR版本
    local bbr_status=$(sysctl net.ipv4.tcp_congestion_control | awk '{print $3}')
    if [[ "$bbr_status" == "bbr3" || "$bbr_status" == "bbr2" || "$bbr_status" == "bbr" ]]; then
        check_pass "TCP拥塞控制算法已启用: $bbr_status"
    else
        check_fail "BBR未启用。当前算法: $bbr_status"
    fi

    # 2.2 检查队列算法
    local qdisc_status=$(sysctl net.core.default_qdisc | awk '{print $3}')
    if [[ "$qdisc_status" == "fq_pie" ]]; then
        check_pass "网络队列算法已设为: fq_pie"
    else
        check_fail "网络队列算法不是 fq_pie。当前: $qdisc_status"
    fi

    # 2.3 检查Swappiness
    local swappiness=$(sysctl vm.swappiness | awk '{print $3}')
    if [ "$swappiness" -eq 1 ]; then
        check_pass "Swappiness值已设为极限值: 1"
    else
        check_fail "Swappiness值不为1。当前: $swappiness"
    fi

    # 2.4 检查文件句柄数 (系统级)
    local fs_file_max=$(sysctl fs.file-max | awk '{print $3}')
    if [ "$fs_file_max" -ge 10000000 ]; then
        check_pass "系统级最大文件句柄数已配置: $fs_file_max"
    else
        check_fail "系统级最大文件句柄数配置过低。当前: $fs_file_max"
    fi
}

check_session_required() {
    log_info "Part 3: Shell会话优化 (需要重新登录SSH才能生效)"
    
    # 3.1 检查当前会话文件句柄数
    local ulimit_n=$(ulimit -n)
    if [ "$ulimit_n" -ge 10000000 ]; then
        check_pass "当前会话文件句柄数限制已提升: $ulimit_n"
    else
        check_fail "当前会话文件句柄数限制较低 ($ulimit_n)。请【重新登录SSH】后再试。"
    fi
}

check_services_and_hardware() {
    log_info "Part 4: 服务与硬件优化 (应立即生效)"

    # 4.1 检查Fail2ban服务
    if systemctl is-active --quiet fail2ban; then
        check_pass "Fail2ban服务正在运行。"
    else
        check_fail "Fail2ban服务未运行。"
    fi

    # 4.2 检查I/O调度器
    local root_dev=$(findmnt -n -o SOURCE / | sed 's/\[.*\]//' | sed 's|/dev/||' | sed 's/[0-9]*$//' | sed 's/p[0-9]*$//')
    if [ -f "/sys/block/$root_dev/queue/scheduler" ]; then
        local scheduler=$(cat /sys/block/$root_dev/queue/scheduler)
        if [[ "$scheduler" == *"[none]"* ]]; then
            check_pass "根分区 ($root_dev) I/O调度器已设为: none"
        else
            check_fail "I/O调度器不是none。当前: $scheduler"
        fi
    else
        check_warn "无法检测到I/O调度器 (/sys/block/$root_dev/queue/scheduler)。"
    fi

    # 4.3 检查分区挂载选项
    if findmnt -n -o OPTIONS / | grep -q "noatime"; then
        check_pass "根分区已使用 'noatime' 模式挂载。"
    else
        check_fail "根分区未使用 'noatime' 模式挂载。"
    fi

    # 4.4 检查透明大页 (THP)
    local thp_status=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
    if [[ "$thp_status" == *"[never]"* ]]; then
        check_pass "透明大页 (THP) 已禁用。"
    else
        check_fail "透明大页 (THP) 未禁用。当前: $thp_status"
    fi

    # 4.5 检查CPU Governor
    if [ -f "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor" ]; then
        local governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
        if [[ "$governor" == "performance" ]]; then
            check_pass "CPU Governor已设为 'performance' 模式。"
        else
            check_fail "CPU Governor不是 'performance'。当前: $governor"
        fi
    else
        check_warn "无法检测到CPU Governor (可能是非Intel/AMD平台或特定虚拟化)。"
    fi
    
    # 4.6 检查持久化服务
    if systemctl is-enabled --quiet vps-optimizer-boot.service; then
        check_pass "核心优化持久化服务 (vps-optimizer-boot.service) 已启用。"
    else
        check_fail "核心优化持久化服务未启用。"
    fi
}

# --- 主执行流程 ---
main() {
    echo "======================================================================"
    echo "      VPS Optimizer v13.3 优化效果验证脚本"
    echo "======================================================================"
    check_reboot_required
    check_network_and_kernel
    check_session_required
    check_services_and_hardware
    echo -e "\n${YELLOW}======================================================================${NC}"
    echo -e "${CYAN}检查完毕。请关注所有标记为 ${RED}[✖] (失败)${CYAN} 或 ${YELLOW}[⚠] (警告)${CYAN} 的项目。${NC}"
    echo -e "${CYAN}失败项通常意味着需要重启、重新登录，或原始脚本执行时出错。${NC}"
}

main
