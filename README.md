

***

# Ultimate VPS 优化套件：完整终极指南

本指南为您提供 `jkrore/NAT-vps` 仓库中两个核心优化脚本 `vps.sh` 和 `vps2.sh` 的详尽说明，从“一键命令”到“深度解析”，涵盖您需要了解的一切。

### 核心设计理念
*   **安全第一**: 所有脚本默认以**预览模式 (Dry Run)** 运行，只显示操作计划，不修改系统。
*   **备份先行**: 在修改任何重要配置文件前，脚本会自动创建备份。
*   **智能检测**: 脚本会尝试分析您的系统环境（如网络延迟、硬件配置），以应用最合适的优化参数。

### 基本要求
*   **必须以 `root` 用户身份执行所有命令。**
*   您的系统需要安装 `wget`。 (通常都已预装)

---

## 第一部分：一键命令终极指南

这是最核心的部分，直接复制粘贴即可使用。

### `vps.sh` (系统综合优化)
此脚本优化 I/O、系统限制、清理服务、调整 CPU 等。

#### **1. 一键预览 (绝对安全)**
此命令会下载并执行脚本，**显示**它计划进行的所有更改，但**不会**对您的系统做任何实际修改。这是**必须执行**的第一步。

```bash
wget -O - https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps.sh | bash -s -- --all
```

#### **2. 一键应用 (执行修改)**
**警告：此命令会实际修改您的系统配置。** 请务必先运行上面的预览命令，确认所有操作都符合您的预期后，再执行此命令。

```bash
wget -O - https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps.sh | bash -s -- --apply --all
```

---

### `vps2.sh` (网络专项优化)
此脚本通过科学计算 BDP (带宽时延积) 来精细调整网络参数，开启 BBR，最大化网络吞吐量。

#### **1. 一键预览 (绝对安全)**
此命令会分析您的网络环境并**显示**推荐的网络参数，但**不会**保存它们。

```bash
wget -O - https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps2.sh | bash
```

#### **2. 一键应用 (执行修改)**
**警告：此命令会实际修改您的网络配置。** 请务必先运行上面的预览命令，确认参数无误后，再执行此命令。

```bash
wget -O - https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps2.sh | bash -s -- --apply
```

#### **3. [进阶] 激进模式应用**
此模式会额外修改 GRUB 启动项以禁用 CPU 安全漏洞补丁，可提升性能但有**安全风险**，且**需要重启**才能生效。

```bash
# 预览激进模式
wget -O - https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps2.sh | bash -s -- --mode aggressive

# 应用激进模式
wget -O - https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps2.sh | bash -s -- --apply --mode aggressive
```

---

## 第二部分：推荐的优化流程

对于一台全新的服务器，请遵循以下步骤以获得最佳效果：

1.  **先优化网络**:
    *   执行 `vps2.sh` 的**预览**命令。
    *   检查输出的参数是否合理。
    *   执行 `vps2.sh` 的**应用**命令。

2.  **再优化系统**:
    *   执行 `vps.sh` 的**预览**命令。
    *   仔细检查将要被禁用/修改的服务和配置。
    *   执行 `vps.sh` 的**应用**命令。

3.  **重启服务器 (如果需要)**:
    *   如果您在任何步骤中使用了涉及 GRUB 的优化 (例如 `vps2.sh` 的激进模式或 `vps.sh` 的 `--apply-grub` 模块)，您**必须重启服务器**才能使这些更改生效。
    *   执行 `sudo reboot`。

---

## 第三部分：脚本深度解析

### `vps.sh` (系统综合优化)

*   **目的**: 提供超越网络核心的系统级优化，增强服务器综合性能。
*   **备份目录**: `/root/ultimate_singularity_backups/`

#### **命令行参数**

| 参数 | 描述 | 风险等级 |
| :--- | :--- | :--- |
| `--apply` | 实际应用更改 (默认为预览模式) | - |
| `--all` | 选择下面所有的优化模块 | - |
| `--apply-io-limits` | 优化存储 I/O 和系统资源限制 (文件句柄数等) | **低** |
| `--cleanup-services` | **禁用**不常用的系统服务 (如蓝牙、打印等) | **高** |
| `--apply-grub` | 为母鸡角色应用 CPU 隔离等 GRUB 参数 | **极高** |
| `--apply-host-specifics` | 为母鸡角色应用大页内存等特定优化 | **中** |
| `--generate-tools` | 生成监控和基准测试的辅助脚本 | **低** |
| `--install-hw-tuning` | 安装并启用一个后台服务，用于动态硬件调优 | **中** |

### `vps2.sh` (网络专项优化)

*   **目的**: 专注于最大化网络吞吐量和降低延迟，是提升网络性能的核心脚本。
*   **备份目录**: `/var/backups/net-optimizer/`

#### **命令行参数**

| 参数 | 描述 |
| :--- | :--- |
| `--apply` | 实际应用更改 (默认为预览模式)。 |
| `--mode normal\|aggressive` | `normal` 为标准优化。`aggressive` 会额外禁用 CPU 安全补丁 (有风险，需重启)。 |
| `--rtt <毫秒>` | 手动指定网络的 RTT (延迟) 值，覆盖自动检测。 |
| `--iperf <IP地址>` | 在优化后，对指定的服务器运行 iperf3 带宽测试。 |
| `--rollback <备份目录>` | 从指定的备份目录中恢复配置。 |

#### **核心操作详解**

1.  **RTT 与 BDP 计算**: 脚本的核心。它会自动检测到您服务器的延迟(RTT)，然后结合带宽(默认1000Mbps)计算出**带宽时延积(BDP)**。BDP 是优化 TCP 缓冲区的最关键科学依据。
2.  **备份与冲突清理**: 在应用任何设置前，它会扫描现有的 `sysctl` 配置文件，将冲突的旧设置备份并禁用，同时生成一个一键回滚脚本 `rollback.sh` 存放在备份目录中。
3.  **Sysctl 参数配置**: 基于 BDP 的计算结果，生成一个全新的配置文件 `/etc/sysctl.d/999-net-optimizer.conf`，其中包含：
    *   **开启 BBRv2/BBRv3**: 设置 `net.ipv4.tcp_congestion_control = bbr` 和 `net.core.default_qdisc = fq`。
    *   **优化 TCP 缓冲区**: 科学地设置 `tcp_rmem` 和 `tcp_wmem` 等核心参数。
    *   **其他 TCP/IP 栈优化**: 启用 TCP Fast Open、窗口缩放等现代化特性。
4.  **网卡与 CPU 调优**:
    *   **CPU 调速器**: 将 CPU 设置为 `performance` 模式，确保最大性能。
    *   **中断绑定**: 将网卡的中断(IRQ)分散到不同的 CPU 核心上，避免单核瓶颈。
    *   **RPS/XPS**: 开启网卡的多核处理能力，进一步分散网络数据包处理压力。

---

## 第四部分：安全与回滚

两个脚本都设计了完善的备份机制。

*   对于 `vps.sh`，所有被修改的文件的原始版本都会被备份到 `/root/ultimate_singularity_backups/` 下的一个带时间戳的目录中。
*   对于 `vps2.sh`，它会创建一个功能更强大的备份，位于 `/var/backups/net-optimizer/`。每个备份目录里都包含一个 `rollback.sh` 脚本。

#### **如何使用 `vps2.sh` 的回滚功能？**

1.  首先，找到您想要回滚到的备份目录，例如 `/var/backups/net-optimizer/net-optimizer-2025-09-23-071400`。
2.  执行以下命令 (**需要 `--apply` 参数来确认执行**):

    ```bash
    wget -O - https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps2.sh | bash -s -- --apply --rollback /var/backups/net-optimizer/net-optimizer-2025-09-23-071400
    ```
