# NAT-vps/vps3.sh

这是一个用于 Linux 服务器的全面网络和系统优化脚本，特别是那些作为 NAT 网关或高性能 VPS 的服务器。它自动检测系统参数，根据 BDP（带宽延迟积）计算最佳缓冲区大小，并应用广泛的`sysctl`、网络接口和 CPU 优化。

## 功能

- **自动系统检测**：检测总内存、CPU 核心数和网络 RTT，以定制优化。
- **基于 BDP 的调优**：计算带宽时延积来设置最优 TCP 缓冲区大小，并限制在安全的内存占用范围内。
- **安全应用/回滚**：默认以`--dry-run`模式运行。应用时，它会创建带时间戳的备份和回滚脚本。
- **冲突解决**：自动备份并注释掉/禁用 `/etc/sysctl.conf` 和 `/etc/sysctl.d/` 中的冲突设置。
- **全面的 `sysctl` 调整**：
    - 启用使用 FQ 包调度的 BBR 拥塞控制。
    - 优化 TCP/UDP 内存缓冲区 (`rmem`, `wmem`)。
- 调整核心网络和虚拟内存设置以实现高吞吐量。
- **网络接口卡（NIC）优化**:
    - 通过 `ethtool` 启用硬件卸载功能（TSO、GSO、GRO 等）。
    - 配置接收包调度（RPS）和发送包调度（XPS），以在 CPU 核心间分配网络处理。
- 尝试将网卡中断（NIC IRQ）分配到各个 CPU 核心上。
- **CPU 优化**:
    - 将 CPU 调速器设置为`performance`模式以获得最大时钟速度。
    - 为网络优化进程创建一个专门的`cpuset` cgroup。
- **DNS 优化**：配置系统使用快速可靠的公共 DNS 服务器（Cloudflare、Google），并在可用的情况下通过`systemd-resolved`启用本地缓存。
- **操作模式**：
    - **`normal`**：一组安全有效的优化。
    - **`aggressive`**：包括更多高级且可能存在风险的优化，例如通过 GRUB 禁用 CPU 推测执行缓解措施以实现最大性能。
- **钩子与工具**:
    - **`--iperf`**: 对指定服务器运行 `iperf3` 测试以测量带宽。
    - **`--install-service`**: （在此版本中未完全实现）旨在安装一个 systemd 服务以进行周期性重新调整。
    - **OCSP 助手**: 包含一个函数，用于获取并存储给定域的 OCSP 响应，对 Nginx 等网络服务器很有用。
- **运行时自适应调优**: 一种监控功能，检查网络流量和 TCP 重传速率，动态调整缓冲区大小。

## 使用方法

### 前置条件

- 脚本必须以**root**身份运行。
- 必须的命令：`ping`, `awk`, `ip`, `sysctl`.
- 为实现完整功能推荐的命令：`ethtool`, `cpupower`, `iperf3`, `jq`, `resolvectl`.

### 基本命令

**1. 干运行（预览更改）**
这是默认且最安全模式。它会显示所有它*将要*执行的操作，而不会实际修改你的系统。

```bash
sudo ./vps3.sh --dry-run --mode normal
```

**2. 应用更改**
要将更改写入系统，请使用 `--apply` 标志。脚本将在 `/var/backups/net-optimizer/` 创建一个备份目录。

```bash
sudo ./vps3.sh --apply --mode normal
```

**3. 侵略模式**
为获得最佳性能，以降低安全性（禁用 CPU 缓解措施）为代价。**请谨慎使用。**

```bash
sudo ./vps3.sh --apply --mode aggressive
```

**4. 强制 RTT**
如果自动 RTT 检测不准确（例如，你从一个非常低延迟的位置连接），你可以手动指定它。

```bash
sudo ./vps3.sh --apply --rtt 120  # 强制将 RTT 设置为 120ms
```

**5. 回滚**
要撤销更改，请使用 `--rollback` 标志，并指定在之前的 `--apply` 运行期间创建的备份目录。

```bash
# 首先，找到您的备份目录
ls /var/backups/net-optimizer/
```

# 然后执行回滚
sudo ./vps3.sh --apply --rollback /var/backups/net-optimizer/net-optimizer-2025-09-23-052100
```
*注意：执行回滚脚本需要使用`--apply`标志。*

### 所有命令行选项

| 标志 | 参数 | 描述 |
| :--- | :--- | :--- |
| `--dry-run` | | 预览更改而不应用它们（默认）。 |
| `--apply` | | 将更改应用到系统。 |
| `--mode` | `normal`\|`aggressive` | 设置优化级别。`normal` 是默认值。 |
| `--rtt` | `<ms>` | 手动覆盖检测到的网络 RTT（毫秒）。 |
| `--iperf` | `<ip1,ip2,...>` | 对指定的逗号分隔服务器运行 `iperf3` 测试。 |
| `--install-service` | | (未来使用) 安装一个 systemd 服务以进行定期调整。 |
| `--rollback` | `<backupdir>` | 使用指定的备份目录回滚更改。 |
| `-q`, `--quiet` | | 减少信息输出的量。 |
| `-h`, `--help` | | 显示帮助信息。 |

## 工作原理

1.  **解析参数**: 脚本首先读取命令行标志 (`--apply`, `--mode` 等)。
2.  **环境检测**:
    *   它确定系统总内存和 CPU 核心数。
*   它尝试通过 ping SSH 客户端的 IP 地址来检测网络 RTT。如果失败，则回退到 ping `1.1.1.1`。
3.  **BDP 计算**:
    *   它计算 BDP（`带宽 * RTT`）以确定理论上"在飞行"数据的最大量。
    *   它将此值限制在一个安全范围内（例如，总 RAM 的 3%或 64MB，取较小者），以防止内存消耗过度。此结果决定了最大 TCP 读写缓冲区大小。
4.  **备份与冲突清理**:
    *   在 `/var/backups/net-optimizer/` 下创建一个唯一的备份目录。
    *   它会扫描 `/etc/sysctl.conf` 和 `/etc/sysctl.d/` 中的文件，查找即将更改的设置。
    *   冲突的设置会被注释掉，或者整个文件会被重命名为带有 `.disabled_by_optimizer` 后缀的名称。原始文件会被备份。
5.  **应用优化**:
    *   **Sysctl**: 将优化后的值写入新的配置文件 `/etc/sysctl.d/999-net-optimizer.conf`，并使用 `sysctl --system` 应用。
    *   **网卡调优**: 遍历所有活动网络接口（不包括 `lo`、`docker` 等），并应用 `ethtool`、RPS/XPS 和 IRQ 亲和性设置。
    *   **CPU**: 将 CPU 管理器设置为 `performance`。
*   **Qdisc**: 它将主网络接口的默认数据包调度器设置为 `fq`（在激进模式下为 `cake`）。
    *   **DNS**: 它更新系统的 DNS 解析器设置。
6.  **Finalization**: 显示已应用设置的摘要，包括备份目录的路径和回滚脚本。
