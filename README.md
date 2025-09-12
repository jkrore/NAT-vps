# 小鸡VPS终极优化脚本 v3.1 (定制版)

## 设计理念

本项目旨在为低配置（“小鸡”）VPS提供一个终极、全面的自动化优化解决方案。我们深知便利性与安全性同样重要，因此在 V3.1 定制版中，我们融合了以下核心理念：

1.  **智能化**: 脚本能自动检测服务器的地理位置（国内/海外）和操作系统，并据此应用最优化的DNS、NTP及软件包配置，无需用户手动判断。
2.  **安全性**: 在执行任何修改系统关键配置文件的操作前，脚本会自动创建带有时间戳的完整备份。同时，集成了Fail2ban等基础安全工具，提升服务器防护能力。
3.  **用户定制**: 严格遵循用户需求，保留了**“强制开启root用户SSH密码登录”**的功能选项，并在执行前提供明确的安全风险提示，让用户拥有最终控制权。
4.  **透明可逆**: 提供详尽的手动恢复步骤，让用户清楚了解脚本的每一项改动，并能在需要时安全地将系统恢复至优化前的状态。

## 功能详解

1.  **更新系统软件包**
    *   自动检测 `Debian/Ubuntu` 或 `CentOS` 系统，并执行相应的软件包更新命令，确保系统处于最新状态，修复已知安全漏洞。

2.  **[定制] 开启root用户SSH登录**
    *   **注意: 此功能存在安全风险。**
    *   此功能会引导您为 `root` 用户设置一个新密码，并修改SSH配置文件，允许 `root` 用户直接通过密码远程登录。

3.  **开启BBR+FQ网络加速**
    *   自动检测并启用Google BBR + FQ拥塞控制算法，能显著提升服务器的网络吞吐量，降低延迟，尤其适合建站和科学上网等场景。

4.  **智能创建Swap虚拟内存**
    *   根据服务器的物理内存大小，智能推荐并创建一个合理的Swap交换文件。该过程为交互式，会征求您的同意，避免在磁盘空间紧张的VPS上误操作。

5.  **智能配置DNS和NTP**
    *   自动判断服务器地理位置，为国内服务器配置阿里DNS和DNSPod，为海外服务器配置Cloudflare和Google DNS。同时使用最优的NTP服务器校准系统时间。

6.  **内核与文件句柄数优化**
    *   应用一系列经过社区验证的Linux内核参数，优化TCP/IP协议栈和文件系统性能。同时大幅提升系统和用户的最大文件句柄数限制，轻松应对高并发场景。

7.  **安装Fail2ban防暴力破解**
    *   一键安装并启用 `Fail2ban` 服务，它能自动监控系统日志，并封禁多次尝试登录失败的恶意IP地址，有效抵御SSH暴力破解攻击。

8.  **系统清理**
    *   自动清理已不再需要的软件包、缓存文件以及过大的日志文件，为您的VPS释放宝贵的磁盘空间。

## 如何使用：一键执行

**前提条件**: 您必须拥有服务器的 `root` 用户权限。

**方式一: 使用 wget (推荐)**
```bash
wget -O optimize.sh [您的脚本RAW链接] && bash optimize.sh
```

**方式二: 使用 curl**```bash
curl -o optimize.sh [您的脚本RAW链接] && bash optimize.sh
```> **提示**: 请将 `[您的脚本RAW链接]` 替换为您存放 `v3.1` 脚本的实际URL。

## 如何卸载：一键恢复与删除

我们**强烈建议**通过下面的手动分步指南来恢复，这能让您完全掌控恢复过程。

如果您确认要恢复所有配置，可以先找到脚本运行时创建的备份目录（路径类似于 `/root/system_backup_YYYYMMDD_HHMMSS`），然后参考下面的步骤进行操作。

## 手动恢复分步指南

请在执行前，将命令中的 `$BACKUP_DIR` 替换为您服务器上实际的备份目录路径，例如 `/root/system_backup_20250912_011500`。

**1. 恢复各项配置文件**
```bash
# 恢复SSH配置
cp $BACKUP_DIR/sshd_config.bak /etc/ssh/sshd_config
systemctl restart sshd

# 恢复系统内核配置
cp $BACKUP_DIR/sysctl.conf.bak /etc/sysctl.conf
# 删除脚本创建的优化配置
rm -f /etc/sysctl.d/99-vps-optimize.conf
sysctl -p

# 恢复文件句柄数限制
cp $BACKUP_DIR/limits.conf.bak /etc/security/limits.conf

# 恢复DNS配置
chattr -i /etc/resolv.conf
cp $BACKUP_DIR/resolv.conf.bak /etc/resolv.conf
```

**2. 移除Swap虚拟内存**
```bash
# 停止swap
swapoff /swapfile
# 从fstab中移除自动挂载
sed -i '/\/swapfile/d' /etc/fstab
# 删除swap文件
rm -f /swapfile
```

**3. 卸载Fail2ban**
```bash
# 停止并禁用服务
systemctl stop fail2ban
systemctl disable fail2ban

# 卸载软件包
# 对于Debian/Ubuntu
apt-get remove --purge -y fail2ban
# 对于CentOS
yum remove -y fail2ban
```

**4. 重启服务器使所有恢复生效**
```bash
reboot
```

## 不可逆的操作

请注意，以下操作是不可逆的，或恢复起来非常复杂：

*   **软件包更新**: `apt upgrade` / `yum update` 升级的系统组件无法简单降级。
*   **root密码修改**: 脚本中为root设置的新密码已被加密写入系统，无法找回旧密码。
*   **系统清理**: 被清理的缓存和日志文件通常无法恢复。

## 作者

*   **原始创意与脚本**: jkre, taurusxin
*   **V3.1融合与定制**: AI News Aggregator & Summarizer Expert (根据您的需求)
