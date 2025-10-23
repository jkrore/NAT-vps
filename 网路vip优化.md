# NAT-vps 性能终极优化脚本集
本项目提供了一套针对 Debian 12/13 系统的网络性能优化脚本，旨在最大化 NAT VPS 或独立服务器的网络吞吐能力和响应速度。
## 核心文件
脚本集包含两个核心文件，**必须按顺序执行**：
1.  **`vip1.sh`**: **环境准备脚本**。负责更新系统、安装所有必要的依赖工具，并配置好 XanMod 内核的软件源。此脚本**绝对安全**，不会修改系统核心组件，也不会导致无法启动。
2.  **`vip2.sh`**: **核心优化脚本**。执行包括 BBRv3 内核安装、TCP/UDP 缓冲区优化、网卡硬件调优等一系列高级操作。
## 系统要求
*   一个纯净的 **Debian 12** 或 **Debian 13** 系统。
*   **root** 用户权限。
---
## 🚀 快速使用指南
此流程适用于一台刚刚 `dd` 完的纯净 Debian 系统。请以 `root` 用户身份登录服务器，然后按顺序执行以下步骤。
### 步骤一：执行 `vip1.sh` (环境准备)
此脚本会为后续的核心优化做好一切准备工作，确保 `vip2.sh` 不会因缺少工具而报错。
```bash
curl -sL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vip1.sh | bash
```
等待此脚本执行完毕，看到 "✅ 黄金准备脚本执行完毕！" 的提示信息。
### 步骤二：执行 `vip2.sh` (核心优化)
在准备工作完成后，运行此脚本来应用所有网络优化。
#### **基础用法 (推荐)**
此命令会启用所有优化、尝试安装 XanMod 内核 (BBRv3)，并自动检测网络参数。
```bash
curl -sL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vip2.sh | bash -s -- --apply --install-xanmod
```
#### **高级用法 (自定义参数)**
如果您对自己的网络环境有更精确的了解，可以通过附加参数进行微调。
```bash
curl -sL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vip2.sh | bash -s -- --apply --mode aggressive --install-xanmod --enable-xdp --rtt 200
```

```bash
curl -sL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vip3.sh | bash -s -- --apply 
```

> **提示**：脚本执行完毕后，如果成功安装了 XanMod 内核，会提示您需要重启。请手动执行 `reboot` 命令重启服务器，以加载新内核。
---
## 🛠️ `vip2.sh` 参数详解与帮助
`vip2.sh` 脚本支持多种参数以实现定制化调优。
### 查看内置帮助
您可以随时通过 `--help` 参数查看脚本支持的所有选项，而**不会执行任何操作**。
```bash
curl -sL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vip2.sh | bash -s -- --help
```
### 参数列表
所有参数都需要加在 `bash -s --` 之后。
*   `--apply`
    *   **必需参数**。默认情况下，脚本只进行“演习”（Dry Run），不会对系统做任何实际更改。使用此参数后，所有优化才会真正写入系统。
*   `--install-xanmod`
    *   **强烈推荐**。尝试安装集成了最新 BBRv3 算法的 XanMod 内核，这是获得最大性能提升的关键。
*   `--mode <模式>`
    *   **可选参数**。用于设定优化策略的倾向性。默认为 `aggressive`。
        *   `aggressive`: **激进模式**。最大化网络缓冲区，追求最高吞吐量，适合大流量下载/上传业务。
        *   `normal`: **普通模式**。在吞吐量和系统资源占用之间取得平衡。
        *   `latency`: **低延迟模式**。牺牲一部分吞吐量，优先保证网络响应速度，适合游戏代理等对延迟敏感的场景。
*   `--rtt <毫秒>`
    *   **可选参数**。手动指定您服务器到目标区域的平均 RTT (延迟)，单位为毫秒。例如 `--rtt 200`。脚本会自动检测，但手动指定结果更精确。
*   `--bandwidth <Mbps>`
    *   **可选参数**。手动指定您服务器的带宽，单位为 Mbps。例如 `--bandwidth 1000`。脚本会自动估算，但手动指定结果更精确。
*   `--iperf-server <IP地址>`
    *   **可选参数**。在优化结束后，使用 iperf3 工具向指定的服务器 IP 进行一次网络性能测试。
*   `--enable-xdp`
    *   **可选参数 (专家使用)**。尝试启用 XDP (eXpress Data Path) 功能，用于超低延迟的数据包处理。需要内核头文件支持，不保证在所有环境都能成功。
*   `-q` 或 `--quiet`
    *   **可选参数**。静默模式，减少脚本执行过程中的信息输出。
---
## ⚠️ 故障排查：重启后服务器失联怎么办？
如果执行完 `vip2.sh` 并重启后，服务器无法通过 SSH 连接，这**极有可能**是新安装的 XanMod 内核与您 VPS 的底层虚拟化驱动不兼容。
**解决方案：**
1.  通过您 VPS 提供商后台的 **VNC / KVM 控制台**登录服务器。
2.  在 VPS 后台执行“硬重启”，并立即切换到 VNC 窗口。
3.  在启动菜单 (GRUB) 出现时，快速用键盘方向键选择 **"Advanced options for Debian"**，然后选择带有 `Debian` 字样的**旧内核**启动。
4.  成功用旧内核登录系统后，执行以下命令卸载不兼容的 XanMod 内核：
    ```bash
    apt-get purge 'linux-xanmod*' 'linux-image-*-xanmod*' 'linux-headers-*-xanmod*' && update-grub
    ```
5.  执行完毕后，您的系统即恢复到可安全重启的状态。
> 在这种情况下，您的系统依然应用了除更换内核之外的所有优化（如大缓冲区、BBR开启等），性能同样远超默认状态。








