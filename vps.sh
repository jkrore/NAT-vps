#!/bin/bash

#===============================================================================================
#   System Name: 小鸡VPS终极优化脚本 (VPS-Optimizer-Ultimate)
#   Version: 1.0
#   Author: 小鸡VPS专家
#   Description: 专为低配置VPS设计的一键自动化优化脚本，集成了系统更新、安全设置、
#                网络加速、性能调优等多项功能。
#===============================================================================================

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# 检查是否为root用户
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误: 此脚本必须以root用户权限运行。${NC}"
        echo -e "${YELLOW}请尝试使用 'sudo -i' 或 'sudo su' 命令切换到root用户后再次运行。${NC}"
        exit 1
    fi
}

# 检测操作系统
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    elif [ -f /etc/redhat-release ]; then
        OS="centos"
    else
        echo -e "${RED}无法检测到操作系统类型。${NC}"
        exit 1
    fi
}

# 封装一个函数来安全地添加配置 (幂等性检查)
add_config() {
    local file=$1
    local config=$2
    if ! grep -qF -- "$config" "$file"; then
        echo "$config" >> "$file"
    fi
}

# 1. 更新软件包
update_packages() {
    echo -e "\n${GREEN}---> 1. 开始更新系统软件包...${NC}"
    case "$OS" in
        ubuntu|debian)
            apt-get update && apt-get upgrade -y
            ;;
        centos)
            yum update -y
            ;;
    esac
    echo -e "${GREEN}软件包更新完成。${NC}"
}

# 2. 开启root用户SSH登录
enable_root_ssh() {
    echo -e "\n${GREEN}---> 2. 设置并开启root用户SSH登录...${NC}"
    echo -e "${YELLOW}您现在需要为root用户设置一个新密码。请务必使用强密码！${NC}"
    passwd root
    if [ $? -ne 0 ]; then
        echo -e "${RED}密码设置失败，跳过此步骤。${NC}"
        return 1
    fi
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
    systemctl restart sshd
    echo -e "${GREEN}Root用户SSH登录已开启。${NC}"
}

# 3. 开启BBR+FQ网络加速
enable_bbr() {
    echo -e "\n${GREEN}---> 3. 尝试开启BBR+FQ网络加速...${NC}"
    KERNEL_VERSION=$(uname -r | cut -d- -f1)
    if dpkg --compare-versions "$KERNEL_VERSION" "ge" "4.9"; then
        echo -e "${GREEN}内核版本 ($KERNEL_VERSION) 符合要求，开始配置BBR。${NC}"
        add_config "/etc/sysctl.conf" "net.core.default_qdisc=fq"
        add_config "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control=bbr"
        sysctl -p
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
            echo -e "${GREEN}BBR+FQ已成功开启！${NC}"
        else
            echo -e "${RED}BBR开启失败，请检查配置。${NC}"
        fi
    else
        echo -e "${YELLOW}警告: 您的内核版本 ($KERNEL_VERSION) 过低，无法直接开启BBR。${NC}"
    fi
}

# 4. 设置Swap虚拟内存
setup_swap() {
    echo -e "\n${GREEN}---> 4. 设置Swap虚拟内存...${NC}"
    if [ "$(swapon --show | wc -l)" -gt 0 ]; then
        echo -e "${YELLOW}检测到已存在的Swap，跳过创建。${NC}"
        return
    fi
    MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    SWAP_SIZE=$((MEM_TOTAL * 2))
    echo "物理内存: ${MEM_TOTAL}MB, 计划创建Swap: ${SWAP_SIZE}MB"
    fallocate -l ${SWAP_SIZE}M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    add_config "/etc/fstab" "/swapfile none swap sw 0 0"
    echo -e "${GREEN}Swap创建并挂载成功！${NC}"
}

# 5. 清理系统垃圾
cleanup_system() {
    echo -e "\n${GREEN}---> 5. 清理系统垃圾文件...${NC}"
    case "$OS" in
        ubuntu|debian)
            apt-get autoremove -y && apt-get clean -y
            ;;
        centos)
            yum autoremove -y && yum clean all
            ;;
    esac
    journalctl --vacuum-size=50M
    echo -e "${GREEN}系统垃圾清理完成。${NC}"
}

# 6. 优化DNS并强制IPv4优先
optimize_dns_ipv4() {
    echo -e "\n${GREEN}---> 6. 优化DNS并强制IPv4优先...${NC}"
    echo -e "nameserver 8.8.8.8\nnameserver 1.1.1.1" > /etc/resolv.conf
    echo -e "${GREEN}DNS已设置为Google和Cloudflare DNS。${NC}"
    add_config "/etc/gai.conf" "precedence ::ffff:0:0/96  100"
    echo -e "${GREEN}已配置IPv4优先访问。${NC}"
}

# 7. 内核参数优化
optimize_sysctl() {
    echo -e "\n${GREEN}---> 7. 应用Linux系统内核参数优化...${NC}"
    cat << EOF | while read -r line; do add_config "/etc/sysctl.conf" "$line"; done
#--- Kernel Optimization by VPS-Optimizer-Ultimate v2.1 ---
fs.file-max=1000000
fs.nr_open=1000000
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.core.somaxconn=8192
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
net.ipv4.tcp_max_syn_backlog=8192
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30
vm.swappiness=10
#----------------------------------------------------------
EOF
    sysctl -p
    echo -e "${GREEN}内核参数优化已应用。${NC}"
}

# 8. 安装性能优化工具
install_performance_tools() {
    echo -e "\n${GREEN}---> 8. 安装性能优化辅助工具...${NC}"
    case "$OS" in
        ubuntu|debian)
            apt-get install -y haveged
            ;;
        centos)
            yum install -y haveged tuned
            systemctl enable --now tuned
            tuned-adm profile virtual-guest
            ;;
    esac
    systemctl enable --now haveged
    echo -e "${GREEN}Haveged (熵生成器) 已安装并启动。${NC}"
    if [ "$OS" == "centos" ]; then
        echo -e "${GREEN}Tuned (性能调优工具) 已安装并设置为 'virtual-guest' 模式。${NC}"
    fi
}

# 主函数
main() {
    check_root
    detect_os
    echo -e "${YELLOW}=============================================================${NC}"
    echo -e "${GREEN}       欢迎使用 小鸡VPS终极优化脚本 v2.1 (精简版)${NC}"
    echo -e "${YELLOW}=============================================================${NC}"
    
    PS3=$'\n'"请选择要执行的操作 (输入数字后回车): "
    options=(
        "【推荐】一键全自动优化 (执行1-8全部步骤)"
        "更新系统软件包"
        "开启root用户SSH登录"
        "开启BBR+FQ网络加速"
        "创建2倍内存的Swap"
        "清理系统垃圾文件"
        "优化DNS并强制IPv4优先"
        "应用Linux内核参数优化"
        "安装性能优化工具 (haveged/tuned)"
        "退出脚本"
    )
    
    select opt in "${options[@]}"; do
        case $REPLY in
            1)
                update_packages; enable_root_ssh; enable_bbr; setup_swap; cleanup_system; optimize_dns_ipv4; optimize_sysctl; install_performance_tools
                echo -e "\n${GREEN}*** 所有优化任务已执行完毕！ ***${NC}"
                echo -e "${YELLOW}强烈建议您现在重启服务器 (输入 reboot) 以使所有设置完全生效。${NC}"
                break
                ;;
            2) update_packages ;;
            3) enable_root_ssh ;;
            4) enable_bbr ;;
            5) setup_swap ;;
            6) cleanup_system ;;
            7) optimize_dns_ipv4 ;;
            8) optimize_sysctl ;;
            9) install_performance_tools ;;
            10) echo "感谢使用，再见！"; break ;;
            *) echo -e "${RED}无效的选项 $REPLY${NC}" ;;
        esac
    done
}

main
