#!/bin/bash

#===============================================================================================
#   System Name: 终极性能优化验证脚本 (Ultimate Performance Verification Script)
#   Version: 1.0
#   Author: AI Executor
#   Description: 用于一键式验证 v28.0 优化脚本中的关键参数是否已正确应用。
#===============================================================================================

# --- 全局设置与颜色 ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS_ICON="${GREEN}✔${NC}"; FAIL_ICON="${RED}✖${NC}"; PEND_ICON="${YELLOW}⏳${NC}"

# --- 格式化输出函数 ---
print_check() {
    local status_icon=$1
    local description=$2
    local current_value=$3
    local target_value=$4
    printf "%-18s %-30s %-25s %-20s\n" "$status_icon" "$description" "Current: $current_value" "Target: $target_value"
}

# --- 主验证流程 ---
clear
echo -e "${CYAN}======================================================================${NC}"
echo -e "        ${GREEN}终极性能优化 v28.0 - 验证程序启动${NC}"
echo -e "${CYAN}======================================================================${NC}"
printf "%-18s %-30s %-25s %-20s\n" "状态" "检测项目" "当前值" "目标值"
echo -e "------------------------------------------------------------------------------------------"

# --- 1. 内核与网络 (Sysctl) ---
echo -e "${YELLOW}--- 1. 内核与网络 (Sysctl) ---${NC}"
# TCP 拥塞控制
current_cc=$(sysctl -n net.ipv4.tcp_congestion_control)
available_ccs=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "cubic")
best_cc="cubic"; if [[ "$available_ccs" == *"bbr3"* ]]; then best_cc="bbr3"; elif [[ "$available_ccs" == *"bbr2"* ]]; then best_cc="bbr2"; elif [[ "$available_ccs" == *"bbr"* ]]; then best_cc="bbr"; fi
if [[ "$current_cc" == "$best_cc" ]]; then print_check "$PASS_ICON" "TCP 拥塞控制" "$current_cc" "$best_cc"; else print_check "$FAIL_ICON" "TCP 拥塞控制" "$current_cc" "$best_cc"; fi

# 网络发包队列
current_qdisc=$(sysctl -n net.core.default_qdisc)
target_qdisc="fq_pie"
if [[ "$current_qdisc" == "$target_qdisc" ]]; then print_check "$PASS_ICON" "网络发包队列" "$current_qdisc" "$target_qdisc"; else print_check "$FAIL_ICON" "网络发包队列" "$current_qdisc" "$target_qdisc"; fi

# 最大连接数
current_somaxconn=$(sysctl -n net.core.somaxconn)
target_somaxconn="1048576"
if [[ "$current_somaxconn" -ge "$target_somaxconn" ]]; then print_check "$PASS_ICON" "最大连接数 (somaxconn)" "$current_somaxconn" ">= $target_somaxconn"; else print_check "$FAIL_ICON" "最大连接数 (somaxconn)" "$current_somaxconn" ">= $target_somaxconn"; fi

# Swappiness
current_swappiness=$(sysctl -n vm.swappiness)
target_swappiness="1"
if [[ "$current_swappiness" -le "$target_swappiness" ]]; then print_check "$PASS_ICON" "Swappiness" "$current_swappiness" "<= $target_swappiness"; else print_check "$FAIL_ICON" "Swappiness" "$current_swappiness" "<= $target_swappiness"; fi

# --- 2. 系统与硬件 ---
echo -e "${YELLOW}--- 2. 系统与硬件 ---${NC}"
# 透明大页 (THP)
current_thp=$(cat /sys/kernel/mm/transparent_hugepage/enabled)
if [[ "$current_thp" == *"[never]"* ]]; then print_check "$PASS_ICON" "透明大页 (THP)" "Disabled" "Disabled"; else print_check "$FAIL_ICON" "透明大页 (THP)" "Enabled" "Disabled"; fi

# I/O 调度器
root_dev_parent=$(lsblk -no pkname "$(findmnt -n -o SOURCE /)" 2>/dev/null | head -n 1)
if [ -n "$root_dev_parent" ] && [ -f "/sys/block/$root_dev_parent/queue/scheduler" ]; then
    current_io_sched=$(cat /sys/block/$root_dev_parent/queue/scheduler)
    if [[ "$current_io_sched" == *"[none]"* || "$current_io_sched" == *"[noop]"* ]]; then print_check "$PASS_ICON" "I/O 调度器" "${current_io_sched}" "[none] or [noop]"; else print_check "$FAIL_ICON" "I/O 调度器" "${current_io_sched}" "[none] or [noop]"; fi
else
    print_check "$FAIL_ICON" "I/O 调度器" "N/A" "[none] or [noop]"
fi

# CPU 调速器
if command -v cpupower >/dev/null 2>&1; then
    current_governor=$(cpupower frequency-info -p 2>/dev/null | grep 'The governor' | awk '{print $3}' | tr -d '"')
    if [[ "$current_governor" == "performance" ]]; then print_check "$PASS_ICON" "CPU 调速器" "$current_governor" "performance"; else print_check "$PEND_ICON" "CPU 调速器" "$current_governor" "performance"; fi
elif [ -f /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor ]; then
    current_governor=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)
    if [[ "$current_governor" == "performance" ]]; then print_check "$PASS_ICON" "CPU 调速器" "$current_governor" "performance"; else print_check "$PEND_ICON" "CPU 调速器" "$current_governor" "performance"; fi
fi

# --- 3. 网卡硬件 (Ethtool) ---
echo -e "${YELLOW}--- 3. 网卡硬件 (Ethtool) ---${NC}"
ETH_DEVICE=$(ip route | grep '^default' | awk '{print $5}' | head -1 || echo "eth0")
if command -v ethtool >/dev/null 2>&1; then
    # RX/TX 缓冲区
    current_rx=$(ethtool -g "$ETH_DEVICE" 2>/dev/null | grep 'RX:' | awk '{print $2}')
    target_rx="4096"
    if [[ -n "$current_rx" && "$current_rx" -ge "$target_rx" ]]; then print_check "$PASS_ICON" "网卡 RX 缓冲区" "$current_rx" ">= $target_rx"; else print_check "$FAIL_ICON" "网卡 RX 缓冲区" "${current_rx:-N/A}" ">= $target_rx"; fi
    
    # TSO/GSO/GRO
    tso_status=$(ethtool -k "$ETH_DEVICE" 2>/dev/null | grep 'tcp-segmentation-offload' | awk '{print $2}')
    if [[ "$tso_status" == "off" ]]; then print_check "$PASS_ICON" "TSO 硬件卸载" "$tso_status" "off"; else print_check "$FAIL_ICON" "TSO 硬件卸载" "${tso_status:-N/A}" "off"; fi
else
    print_check "$FAIL_ICON" "Ethtool" "Not Found" "Installed"
fi

# --- 4. 待生效项 (需重启/重登录) ---
echo -e "${YELLOW}--- 4. 待生效项 (需重启/重登录) ---${NC}"
# 文件句柄数
current_limit=$(ulimit -n)
target_limit="10240000"
if [[ "$current_limit" -ge "$target_limit" ]]; then print_check "$PASS_ICON" "文件句柄数 (当前会话)" "$current_limit" ">= $target_limit"; else print_check "$PEND_ICON" "文件句ールの数 (新会话)" "$current_limit" ">= $target_limit"; fi

# GRUB 参数
if [ -f /etc/default/grub ]; then
    grub_line=$(grep 'GRUB_CMDLINE_LINUX_DEFAULT=' /etc/default/grub)
    if [[ "$grub_line" == *"mitigations=off"* && "$grub_line" == *"idle=poll"* && "$grub_line" == *"ipv6.disable=1"* ]]; then
        print_check "$PEND_ICON" "GRUB 魔鬼模式" "已配置" "需重启生效"
    else
        print_check "$FAIL_ICON" "GRUB 魔鬼模式" "未完全配置" "需重启生效"
    fi
else
    print_check "$PEND_ICON" "GRUB 魔鬼模式" "文件不存在" "N/A"
fi

echo -e "------------------------------------------------------------------------------------------"
echo -e "${YELLOW}验证完毕。${NC}"
echo -e "${PEND_ICON} 标记的项需要您 ${RED}重启系统(reboot)${NC} 或 ${RED}重新登录SSH${NC} 才能完全生效。"
echo -e "${FAIL_ICON} 标记的项可能表示优化未成功应用，或当前环境不支持该项优化。"
echo -e "${CYAN}======================================================================${NC}"
