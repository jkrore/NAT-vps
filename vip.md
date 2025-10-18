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










概述

Ultimate Singularity v3.0 是一套面向 systemd + Debian/Ubuntu 环境的系统优化脚本集合，旨在为 VPS、代理 / NAT 节点及轻量云主机提供可选且结构化的系统与网络前置调优（I/O、CPU、内存、服务、ZRAM、fstab、GRUB 等）。脚本提供 DRY-RUN（默认）与实际应用两种执行模式，支持按模块启用以便逐步测试与部署。

重要提示（必读）

默认 DRY-RUN 模式：脚本默认不会修改系统；要写入更改请使用 --apply。

高风险模块需谨慎：--apply-grub（修改 GRUB）、--cleanup-services（批量禁用服务）属于高风险操作，请先在测试环境验证且确保能通过云 provider 控制台恢复。

必须以 root 运行：sudo bash vip0.sh ... 或切换到 root。

备份：脚本会在 /root/ultimate_singularity_backups/<TIMESTAMP>/ 下保存备份，但并非替代完整快照。

重启提示：修改 GRUB、fstab 等可能需要重启生效。

兼容性：优先针对 Debian/Ubuntu；在其他发行版上运行前请审阅并调整命令（如包管理和服务名）。

功能与模块（全面涉及）

下列模块均在脚本中实现；README 对每个模块的作用、影响与风险做说明，便于逐一启用与评估。

I/O 与 Limits（--apply-io-limits）

写入 /etc/security/limits.d/99-ultimate-singularity.conf（如提高 nofile 上限）

添加 udev 规则（如 NVMe/SSD 调度器与 nr_requests）

写入 /etc/sysctl.d/99-ultimate-fs.conf（fs.file-max、fs.nr_open）

适用场景：高并发文件/连接场景。

风险：极高的文件句柄数值需监控系统资源。

CPU 调优（--apply-cpu-tuning）

设置 governor（performance）

写 sysctl 调度参数（kernel.sched_*）

禁用 irqbalance 并做简单 IRQ affinity 绑定（将网卡中断分散到非 0 号核）

适用场景：延迟敏感与单线程性能优化。

风险：功耗增加、可能导致调度不均。

内存调优（--apply-memory-tuning）

THP -> madvise（若支持）

写入 VM 参数（vm.dirty_*、vm.swappiness、vm.overcommit_memory、vm.min_free_kbytes 等）

适用场景：控制脏页、减少 swap 压力。

风险：不当参数会影响写盘频率或内存分配行为。

服务清理（--cleanup-services） - 高风险

批量禁用可能不必要的服务（例如 tuned、snapd、rsyslog、auditd、cron、apparmor 等）

在非 nat 角色时还会禁用防火墙服务（firewalld / ufw / nftables）

禁用定时器（apt-daily.timer、fstrim.timer 等）

风险：可能破坏日志、合规性、自动更新或监控，生产环境慎用。

GRUB 优化（--apply-grub） - 极高风险

仅在检测到 host（母鸡）角色时执行

计算并设置 CPU 隔离参数（isolcpus、nohz_full、rcu_nocbs 等）和 processor.max_cstate、idle=poll

风险：可能导致无法引导或较差电源管理；执行前请确保控制台访问。

主机/NAT 专属优化（--apply-host-specifics）

host：分配 hugepages（/proc/sys/vm/nr_hugepages）

nat：设置 conntrack 最大条目（net.netfilter.nf_conntrack_max）

适用场景：大页内存需求或大量连接跟踪的 NAT/网关节点。

风险：大页分配占用内存，conntrack 过大会占用内核内存。

ZRAM（--apply-zram）

仅在内存 ≤ 4GB 时建议启用

安装 zram-tools 并配置 /etc/default/zramswap（压缩算法与大小）

适用场景：小内存 VPS。

风险：CPU 开销、并非在所有场景下都能提升性能。

fstab 优化（--apply-fstab）

为 ext4/xfs 分区添加 noatime,nodiratime 减少写 I/O

在写入前会备份 /etc/fstab。

风险：部分应用依赖 atime，请先确认。

基础环境（--apply-basics）

设置时区、安装并启用 chrony、优化 SSH（禁用 UseDNS/GSSAPI）并重启 sshd

用于改善时间同步与 SSH 登录速度。

禁用 IPv6（--disable-ipv6）

写入 sysctl 文件禁用 IPv6

风险：如果需要 IPv6 支持，请勿启用。

系统加固（--apply-hardening）

在 systemd drop-in 中设置默认超时、重启等待与文件句柄限制（/etc/systemd/system.conf.d/99-ultimate-hardening.conf）

之后执行 systemctl daemon-reload。

参数与快速使用
# 仅查看（默认 DRY-RUN）
sudo bash vip0.sh --apply-cpu-tuning --apply-memory-tuning

# 实际应用某些模块
sudo bash vip0.sh --apply --apply-cpu-tuning --apply-memory-tuning --apply-basics

# 启用大多数推荐模块（不含高风险模块）
sudo bash vip0.sh --apply --all

# 启用全部（包含高风险模块，**务必谨慎**）
sudo bash vip0.sh --apply --all --apply-grub --cleanup-services


--apply：实际写入并执行（否则为 DRY-RUN）

--all：启用默认推荐的多数模块（不会自动启用 --apply-grub 和 --cleanup-services）

-h|--help：查看帮助说明

角色检测逻辑

脚本会自动检测并设置三种角色用于有针对性的优化：

nat：如果开启 IP 转发或发现 iptables/nft 中有 MASQUERADE/SNAT，则判为 NAT 节点。

host：若非虚拟化且存在 /dev/kvm 且内存 ≥ 4GB，判为母机（host）。

guest：其他情况视为普通虚拟机（guest）。

脚本会基于该角色决定是否启用 GRUB 优化、host/nat 专属改动等。

备份与回滚

备份位置：脚本在执行前会尽量备份修改过的文件到：

/root/ultimate_singularity_backups/<TIMESTAMP>/


回滚步骤（示例）：

进入备份目录找到需要恢复的文件（如 /etc/default/grub.bak）。

将备份文件复制回原位，例如：

cp /root/ultimate_singularity_backups/20251018_123456/etc/default/grub.bak /etc/default/grub


对应重载命令：update-grub（若修改 grub）、systemctl daemon-reload（systemd）、sysctl -p /etc/sysctl.d/<file>（sysctl）、mount -a（fstab）。

必要时重启系统。

重要：GRUB 修改若导致引导失败，请使用云 provider 控制台或救援模式恢复。

测试与验证建议

在测试 / 临时实例上先运行 --apply（非生产环境）观察至少 24–72 小时。

监控项建议：journalctl -b、dmesg、iostat、iotop、vmstat、sar、ss -s、conntrack -L（若启用 conntrack）、top/htop。

对 IRQ affinity 建议使用更精细工具（结合 lscpu 与 sysfs 信息）做明确绑定，而不是简单轮询策略。

若使用 cloud provider（AWS/GCP/阿里云等），确保能通过 Console 访问以备恢复。

常见问题（FAQ）

Q：为什么脚本默认 DRY-RUN？
A：为避免误操作导致生产系统不可用，默认只打印操作，必须显式使用 --apply 才会写入修改。

Q：如何只回滚某个模块？
A：到备份目录手动恢复对应文件并执行相应重载命令（见“备份与回滚”）。

Q：--apply-grub 会立即生效吗？
A：写入 GRUB 后通常需执行 update-grub（脚本会尝试），并在重启后生效。
