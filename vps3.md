# NAT-vps/vps3.sh

这是一个全面的网络和系统优化脚本，专为 Linux 服务器设计，特别是用作 NAT 网关或高性能 VPS 的服务器。它能自动检测系统参数，基于 BDP（带宽延迟积）计算最佳缓冲区大小，并应用广泛的 `sysctl`、网络接口和 CPU 优化。

## 功能特性

- **自动系统检测**: 自动检测总内存、CPU 核心数和网络 RTT，以量身定制优化方案。
- **基于 BDP 的调优**: 计算带宽延迟积以设置最佳的 TCP 缓冲区大小，并将其限制在安全的内存占用范围内。
- **安全的“应用”与“回滚”**: 默认以 `--dry-run` (试运行) 模式运行。在应用更改时，它会创建带时间戳的备份和一个回滚脚本。
- **冲突解决**: 自动备份并注释掉或禁用 `/etc/sysctl.conf` 和 `/etc/sysctl.d/` 目录中冲突的配置。
- **全面的 `sysctl` 调优**:
    - 启用 BBR 拥塞控制算法和 FQ 队列调度。
    - 优化 TCP/UDP 内存缓冲区 (`rmem`, `wmem`)。
    - 调整核心网络和虚拟内存设置以实现高吞吐量。
- **网卡 (NIC) 优化**:
    - 通过 `ethtool` 启用硬件卸载功能 (TSO, GSO, GRO 等)。
    - 配置接收数据包引导 (RPS) 和传输数据包引导 (XPS)，将网络处理负载分散到多个 CPU 核心。
    - 尝试将网卡中断请求 (IRQ) 分配到不同的 CPU 核心。
- **CPU 优化**:
    - 将 CPU governor 设置为 `performance` 模式以获得最高时钟速度。
    - 为网络优化进程创建一个专用的 `cpuset` cgroup。
- **DNS 优化**: 配置系统使用快速可靠的公共 DNS 服务器（Cloudflare, Google），并在可用时通过 `systemd-resolved` 启用本地缓存。
- **运行模式**:
    - **`normal` (正常模式)**: 一套安全有效的优化措施。
    - **`aggressive` (激进模式)**: 包括更高级、可能存在风险的优化，例如通过修改 GRUB 禁用 CPU 推测性执行漏洞的缓解措施，以换取极致性能。
- **钩子与实用工具**:
    - **`--iperf`**: 针对指定的服务器运行 `iperf3` 测试以测量带宽。
    - **`--install-service`**: (此版本中未完全实现) 用于安装 systemd 服务以进行定期重新调优。
    - **OCSP 助手**: 包含一个为指定域名获取并存储 OCSP 响应的功能，对 Nginx 等 Web 服务器很有用。
- **运行时自适应调优**: 一个监控功能，用于检查网络流量和 TCP 重传率，并动态地对缓冲区大小进行微调。

## 用法

### 先决条件

- 脚本必须以 **root** 用户身份运行。
- 必需命令: `ping`, `awk`, `ip`, `sysctl`。
- 推荐安装以获得完整功能的命令: `ethtool`, `cpupower`, `iperf3`, `jq`, `resolvectl`。

### 基本命令

**1. 试运行 (预览变更)**
这是默认且最安全的模式。它会显示脚本将要执行的所有操作，但不会实际修改您的系统。

```bash
sudo ./vps3.sh --dry-run --mode normal
```

**2. 应用变更**
要将更改写入系统，请使用 `--apply` 标志。脚本将在 `/var/backups/net-optimizer/` 目录下创建一个备份。

```bash
sudo ./vps3.sh --apply --mode normal
```

**3. 激进模式**
用于追求极致性能，但会降低安全性（禁用 CPU 漏洞缓解措施）。**请谨慎使用。**

```bash
sudo ./vps3.sh --apply --mode aggressive
```

**4. 强制指定 RTT**
如果自动检测的 RTT 不准确（例如，您从一个延迟极低的地方连接服务器），您可以手动指定它。

```bash
sudo ./vps3.sh --apply --rtt 120  # 强制将 RTT 设置为 120ms
```

**5. 回滚**
要撤销更改，请使用 `--rollback` 标志，并提供之前 `--apply` 运行时创建的备份目录路径。

```bash
# 首先，找到你的备份目录
ls /var/backups/net-optimizer/

# 然后，运行回滚命令
sudo ./vps3.sh --apply --rollback /var/backups/net-optimizer/net-optimizer-2025-09-23-052100
```
*注意：执行回滚脚本需要 `--apply` 标志以进行确认。*

### 所有命令行选项

| 标志 | 参数 | 描述 |
| :--- | :--- | :--- |
| `--dry-run` | | 预览变更而不应用它们（默认）。 |
| `--apply` | | 将变更应用到系统。 |
| `--mode` | `normal`\|`aggressive` | 设置优化级别。默认为 `normal`。 |
| `--rtt` | `<ms>` | 手动覆盖检测到的网络 RTT（单位：毫秒）。 |
| `--iperf` | `<ip1,ip2,...>` | 针对指定的、以逗号分隔的服务器列表运行 `iperf3` 测试。 |
| `--install-service` | | (未来使用) 安装一个 systemd 服务用于周期性调优。 |
| `--rollback` | `<backupdir>` | 使用指定的备份目录来恢复更改。 |
| `-q`, `--quiet` | | 减少信息性输出。 |
| `-h`, `--help` | | 显示帮助信息。 |

## 工作原理

1.  **解析参数**: 脚本首先读取命令行标志（如 `--apply`, `--mode` 等）。
2.  **环境检测**:
    *   确定系统的总内存和 CPU 核心数。
    *   尝试通过 ping SSH 客户端的 IP 地址来检测网络 RTT。如果失败，则回退到 ping `1.1.1.1`。
3.  **BDP 计算**:
    *   计算 BDP (`带宽 * RTT`) 以确定理论上网络中“在途”数据的最大值。
    *   将此值限制在一个安全的上限（例如，总内存的 3% 或 64MB，取较小者），以防止过度的内存消耗。这个结果决定了 TCP 读/写缓冲区的最大值。
4.  **备份与冲突清理**:
    *   在 `/var/backups/net-optimizer/` 下创建一个唯一的备份目录。
    *   扫描 `/etc/sysctl.conf` 和 `/etc/sysctl.d/` 目录下的文件，查找与脚本将要修改的设置相冲突的配置。
    *   冲突的设置项会被注释掉，或者整个文件会被重命名并添加 `.disabled_by_optimizer` 后缀。原始文件会被备份。
5.  **应用优化**:
    *   **Sysctl**: 将优化后的值写入一个新的配置文件 `/etc/sysctl.d/999-net-optimizer.conf`，并使用 `sysctl --system` 使其生效。
    *   **网卡调优**: 遍历所有活动的网络接口（排除 `lo`, `docker` 等），并应用 `ethtool`、RPS/XPS 和 IRQ 亲和性设置。
    *   **CPU**: 将 CPU governor 设置为 `performance`。
    *   **队列调度 (Qdisc)**: 将主网络接口上的默认数据包调度器设置为 `fq`（在激进模式下为 `cake`）。
    *   **DNS**: 更新系统的 DNS 解析器设置。
6.  **完成**: 显示已应用设置的摘要，以及备份目录和回滚脚本的路径。
