# 小鸡VPS终极优化脚本 v2.1 (精简版)

这是一个专为低配置VPS（俗称“小鸡”）设计的纯粹性能优化脚本。它旨在通过一个简单、轻量级的交互式菜单，一键完成对Linux系统的基础设置与核心性能调优，特别针对网络性能进行深度优化。

## 设计理念

本脚本的构建遵循三大核心原则，旨在为您提供一个既强大又可靠的优化方案：

1.  **稳定与兼容优先**: 在众多网络加速方案中，我们坚决选择并只采用 **Linux 内核原生集成的 BBR 算法**。这保证了最佳的系统兼容性、稳定性和最低的资源占用，避免了因使用第三方破解模块（如锐速）而可能导致的内核不兼容或系统崩溃风险。

2.  **专注性能核心**: 脚本聚焦于**操作系统和网络协议栈**层面的优化。所有调整（如内核参数`sysctl`、Swap、DNS等）都是普适且高效的，能为运行在系统上的所有应用带来性能提升。我们刻意排除了应用层（如Nginx Gzip压缩）和场景特定（如MTU值）的优化，以保持脚本的通用性和纯粹性。

3.  **安全可重复执行 (幂等性)**: 这是衡量运维脚本专业性的关键。本脚本在修改配置文件前，会检查相应配置是否已存在。这意味着您可以**安全地重复运行此脚本**，它只会补充缺失的配置，而不会造成配置文件的重复和冗余。

---

## 功能详解

脚本集成了以下八大核心优化功能：

#### 1. 更新系统软件包
- **功能**: 自动执行 `apt upgrade` 或 `yum update`，将系统所有已安装的软件包更新到最新版本，修复已知的安全漏洞和Bug。

#### 2. 开启root用户SSH登录
- **功能**: 为了方便初始化管理，此功能会引导您为`root`用户设置一个新密码，并修改SSH配置文件，允许`root`用户直接通过密码登录。
- **注意**: 请务必设置一个高强度的复杂密码。

#### 3. 开启BBR+FQ网络加速
- **功能**: 自动检测当前Linux内核版本。如果版本高于`4.9`，则会自动在系统配置中启用Google BBR拥塞控制算法和FQ队列管理，能显著提升服务器的网络吞吐量和响应速度，尤其是在高延迟、易丢包的国际链路上效果拔群。

#### 4. 创建Swap虚拟内存
- **功能**: 自动检测物理内存大小，并创建一个大小为物理内存**两倍**的Swap交换文件。这对于内存较小的小鸡VPS至关重要，可以有效防止因内存耗尽（OOM）而导致的服务崩溃。

#### 5. 清理系统垃圾文件
- **功能**: 执行 `autoremove` 和 `clean` 等命令，清理不再需要的软件包依赖、缓存文件以及过期的系统日志，为您的“小鸡”释放宝贵的磁盘空间。

#### 6. 优化DNS并强制IPv4优先
- **功能**: 将系统的DNS解析服务器修改为更快速、更可靠的公共DNS（Google `8.8.8.8` 和 Cloudflare `1.1.1.1`）。同时，会配置系统优先使用IPv4网络，避免在某些网络环境下因IPv6导致的速度缓慢问题。

#### 7. 应用Linux内核参数优化
- **功能**: 向 `/etc/sysctl.conf` 文件中追加一系列经过社区和业界广泛验证的内核优化参数。这些参数能有效增大TCP缓冲区、增加TCP连接队列、开启TCP Fast Open等，全面提升网络性能。

#### 8. 安装性能优化辅助工具
- **功能**:
    - **Haveged**: 安装并启动`haveged`服务，解决因系统熵值过低导致的程序（尤其是加密应用）随机数生成缓慢、阻塞等问题。
    - **Tuned** (仅CentOS): 安装并启用`tuned`服务，并将其配置文件设置为`virtual-guest`模式，这是专门为虚拟机环境优化的官方性能调优方案。

---

## 如何使用：一键执行

**前提条件**: 您必须以 `root` 用户身份登录到您的VPS。

您可以通过以下两种方式中的任意一种，一键下载并运行本脚本。

#### 方式一：使用 `wget` (推荐)
```bash
wget -O optimizer.sh https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps.sh && bash optimizer.sh
```
> 这条命令会先将脚本文件下载并保存为 `optimizer.sh`，下载成功后立即执行它。

#### 方式二：使用 `curl`
```bash
curl -sS https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps.sh | bash
```
> 这条命令会直接在内存中下载脚本内容并通过管道传送给 `bash` 执行，不会在硬盘上留下脚本文件。

---

## 如何卸载：一键恢复与删除

**重要警告**: 卸载脚本所做的系统更改比安装要复杂。下面的“一键恢复脚本”会尝试自动完成所有可逆操作，但请在执行前理解其内容。

### 一键恢复脚本
直接复制以下所有代码，粘贴到您的VPS终端中，然后按回车键执行。它会自动完成大部分恢复工作。

```bash
bash <(curl -sS https://gist.githubusercontent.com/HelperFun/1694f713111921554178433891a5b14a/raw/uninstall_optimizer.sh)
```

### 手动恢复分步指南
如果您想手动控制恢复过程，或者一键脚本出现问题，请按照以下步骤操作。

#### 1. 恢复 Swap 空间
```bash
# 1. 禁用swap
sudo swapoff /swapfile

# 2. 从fstab中移除swap的自动挂载项
sudo sed -i '/\/swapfile/d' /etc/fstab

# 3. 删除swap文件本身
sudo rm /swapfile
```

#### 2. 移除内核优化参数 (包括BBR)
```bash
# 从配置文件中删除BBR和FQ的相关设置
sudo sed -i '/net.core.default_qdisc=fq/d' /etc/sysctl.conf
sudo sed -i '/net.ipv4.tcp_congestion_control=bbr/d' /etc/sysctl.conf

# 从配置文件中删除由脚本添加的整个优化块
sudo sed -i '/#--- Kernel Optimization by VPS-Optimizer-Ultimate/,/#---/d' /etc/sysctl.conf

# 让更改立即生效
sudo sysctl -p
```

#### 3. 恢复 DNS 和 IPv4 优先设置
```bash
# 恢复gai.conf (移除IPv4优先)
sudo sed -i '/precedence ::ffff:0:0\/96  100/d' /etc/gai.conf

# 恢复resolv.conf (DNS)
# 注意：重启网络服务或重启系统通常会自动恢复DNS设置。
sudo reboot
```

#### 4. 卸载性能优化工具
```bash
# 对于 Debian/Ubuntu 系统
sudo apt-get purge -y haveged

# 对于 CentOS 系统
sudo yum remove -y haveged tuned
```

#### 5. 恢复 SSH Root 登录设置 (可选)
如果您想禁止`root`用户通过密码登录（更安全的方式），可以执行以下操作：
```bash
# 编辑SSH配置文件，将PermitRootLogin改为prohibit-password
sudo sed -i 's/PermitRootLogin yes/PermitRootLogin prohibit-password/g' /etc/ssh/sshd_config

# 重启SSH服务
sudo systemctl restart sshd
```

### 不可逆的操作
以下由脚本执行的操作是**不可逆**的，但通常也无需恢复：
- **软件包更新 (`apt upgrade` / `yum update`)**: 系统更新是单向的，降级软件包非常复杂且危险。
- **系统垃圾清理 (`autoremove` / `clean`)**: 被清理的文件无法恢复。

## 作者
- **jkrore**
- **小鸡VPS专家**
