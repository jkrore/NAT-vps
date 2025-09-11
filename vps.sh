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
        *)
            echo -e "${RED}不支持的操作系统: $OS${NC}"
            return 1
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

    # 备份SSH配置文件
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_$(date +%F)
    
    # 允许root登录
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config
    
    echo -e "${GREEN}正在重启SSH服务以应用更改...${NC}"
    systemctl restart sshd
    
    echo -e "${GREEN}Root用户SSH登录已开启。请务必使用刚才设置的密码登录。${NC}"
}

# 3. 开启BBR+FQ网络加速
enable_bbr() {
    echo -e "\n${GREEN}---> 3. 尝试开启BBR+FQ网络加速...${NC}"
    
    # 检查内核版本
    KERNEL_VERSION=$(uname -r | cut -d- -f1)
    if dpkg --compare-versions "$KERNEL_VERSION" "ge" "4.9"; then
        echo -e "${GREEN}内核版本 ($KERNEL_VERSION) 符合要求，直接开启BBR。${NC}"
        
        # 检查BBR是否已配置
        if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        fi
        if ! grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf; then
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
        fi
        
        sysctl -p
        
        # 验证
        if sysctl net.ipv4.tcp_congestion_control | grep -q "bbr"; then
            echo -e "${GREEN}BBR+FQ已成功开启！${NC}"
        else
            echo -e "${RED}BBR开启失败，请检查配置。${NC}"
        fi
    else
        echo -e "${YELLOW}警告: 您的内核版本 ($KERNEL_VERSION) 过低，无法直接开启BBR。${NC}"
        echo -e "${YELLOW}升级内核存在一定风险，可能导致VPS无法启动。不建议在生产环境自动执行。${NC}"
        echo -e "${YELLOW}您可以尝试手动升级内核到 5.x 或更高版本后再运行此脚本。${NC}"
    fi
}

# 4. 设置Swap虚拟内存
setup_swap() {
    echo -e "\n${GREEN}---> 4. 设置Swap虚拟内存...${NC}"
    
    # 获取物理内存大小 (MB)
    MEM_TOTAL=$(free -m | awk '/^Mem:/{print $2}')
    SWAP_SIZE=$((MEM_TOTAL * 2))
    
    echo "物理内存: ${MEM_TOTAL}MB"
    echo "计划创建Swap: ${SWAP_SIZE}MB"
    
    # 检查是否已有swap
    if [ "$(swapon --show | wc -l)" -gt 0 ]; then
        echo -e "${YELLOW}检测到已存在的Swap，跳过创建。${NC}"
        return
    fi
    
    fallocate -l ${SWAP_SIZE}M /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile
    
    # 写入fstab使其永久生效
    if ! grep -q "/swapfile" /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    
    echo -e "${GREEN}Swap创建并挂载成功！${NC}"
    free -m
}

# 5. 清理系统垃圾
cleanup_system() {
    echo -e "\n${GREEN}---> 5. 清理系统垃圾文件...${NC}"
    case "$OS" in
        ubuntu|debian)
            apt-get autoremove -y
            apt-get clean -y
            ;;
        centos)
            yum autoremove -y
            yum clean all
            ;;
    esac
    # 清理journal日志
    journalctl --vacuum-size=50M
    echo -e "${GREEN}系统垃圾清理完成。${NC}"
}

# 6. 优化DNS并强制IPv4优先
optimize_dns_ipv4() {
    echo -e "\n${GREEN}---> 6. 优化DNS并强制IPv4优先...${NC}"
    
    # 优化DNS
    echo -e "nameserver 8.8.8.8\nnameserver 8.8.4.4\nnameserver 1.1.1.1" > /etc/resolv.conf
    echo -e "${GREEN}DNS已设置为Google和Cloudflare DNS。${NC}"
    
    # 强制IPv4优先
    if [ -f /etc/gai.conf ] && ! grep -q "precedence ::ffff:0:0/96  100" /etc/gai.conf; then
        echo "precedence ::ffff:0:0/96  100" >> /etc/gai.conf
        echo -e "${GREEN}已配置IPv4优先访问。${NC}"
    fi
}

# 7. 内核参数优化
optimize_sysctl() {
    echo -e "\n${GREEN}---> 7. 应用Linux系统内核参数优化...${NC}"
    
    cat >> /etc/sysctl.conf << EOF

# Kernel Optimization by VPS-Optimizer-Ultimate
# 增加 TCP 最大缓冲区大小
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216

# 增加 TCP 连接队列
net.ipv4.tcp_max_syn_backlog=8192
net.core.somaxconn=8192

# 开启 TCP Fast Open
net.ipv4.tcp_fastopen=3

# 减少 TIME-WAIT 套接字数量，允许重用
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=30

# 增加系统文件描述符限制
fs.file-max=1000000
fs.nr_open=1000000

# 优化虚拟内存使用，降低Swap使用倾向
vm.swappiness=10
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
    echo -e "${GREEN}       欢迎使用 小鸡VPS终极优化脚本 v1.0${NC}"
    echo -e "${YELLOW}=============================================================${NC}"
    echo -e "本脚本将引导您完成一系列优化操作，请根据提示进行。"
    echo -e "${RED}重要提示: 在生产环境服务器上运行前，请务必做好数据备份！${NC}"
    
    PS3=$'\n'"请选择要执行的操作 (输入数字后回车，可重复选择): "
    options=(
        "【推荐】一键全自动优化 (执行1-8全部步骤)"
        "更新系统软件包"
        "开启root用户SSH登录 (需设置新密码)"
        "开启BBR+FQ网络加速"
        "创建2倍内存的Swap虚拟内存"
        "清理系统垃圾文件"
        "优化DNS并强制IPv4优先"
        "应用Linux内核参数优化"
        "安装性能优化工具 (haveged/tuned)"
        "退出脚本"
    )
    
    select opt in "${options[@]}"; do
        case $REPLY in
            1)
                echo -e "\n${GREEN}即将开始全自动优化...${NC}"
                update_packages
                enable_root_ssh
                enable_bbr
                setup_swap
                cleanup_system
                optimize_dns_ipv4
                optimize_sysctl
                install_performance_tools
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
            10)
                echo "感谢使用，再见！"
                break
                ;;
            *) echo -e "${RED}无效的选项 $REPLY${NC}" ;;
        esac
    done
}

# 运行主函数
main
