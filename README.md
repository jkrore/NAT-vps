# vps.sh — 使用说明（README）

> 本文件为仓库 `jkrore/NAT-vps` 中 `vps.sh` 脚本的说明文档。文档内容包含脚本目的、功能概览、使用方法、参数说明、风险提示、回滚与测试建议。**请在测试环境验证并备份后再在生产环境运行。**

---

## 概览

`vps.sh` 是一个面向 VPS / 小鸡（guest）与 NAT/转发场景的极限性能优化与自动化配置脚本。脚本旨在自动检测系统环境（包括虚拟化类型、主网卡、CPU/内存等），并对系统网络栈、内核参数、网卡设置、I/O 调度、系统服务与启动项等进行集中优化，以尽可能释放网络吞吐与降低延迟。

该脚本通常包含以下能力（脚本作者或维护者可能会在后续版本调整细节）：

* 自动检测系统信息（OS、CPU、内存、主网卡、虚拟化/容器环境）。
* 配置并写入大量 `sysctl` 内核参数（TCP/UDP 缓冲、拥塞控制、net.core 相关）。
* 修改 GRUB 启动参数以启用 CPU 隔离、降低 C-state、关闭某些延迟源（部分选项极不安全，仅在明确同意下执行）。
* 用 `ethtool` 调整网卡 RX/TX 环形缓冲（ring）、关闭/开启 offload、调整中断合并策略。
* 通过 `udev` 规则或 systemd 单元设置 I/O 调度、readahead 等持久化 I/O 优化。
* 禁用/清理可能干扰性能的系统服务（例如桌面/打印/自动升级等）、启用 TRIM 定时器等维护任务。
* 生成简单的监控与基准脚本，便于变更前后性能对比。

---

## 使用前强烈建议

1. **先在测试机/快照上运行**：任何对内核 / GRUB / I/O /系统服务的修改都有可能导致不可启动或影响功能。请先拍摄系统快照或制作完整备份。
2. **先 `--dry-run`（若脚本支持）或读取脚本内容并理解每一行**。
3. **不要在公网生产主机上直接启用“极限/魔鬼”选项**（例如直接 `mitigations=off`、关闭 ASLR 等），除非明确理解风险并在隔离网络中运行。
4. 准备好回滚方案：备份 `/etc/default/grub`、`/etc/sysctl.d/*`、`/etc/udev/rules.d/*`、systemd 单元与 `/etc/security/limits.d/*` 文件。

---

## 快速使用（示例）

> 假设脚本名为 `vps.sh`，并放在服务器 `/root` 下：

```bash
# 下载并查看（强烈建议先查看）
curl -sSL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps.sh -o /root/vps.sh
less /root/vps.sh

# 预览将要执行的操作（若脚本支持 --dry-run）
sudo bash /root/vps.sh --dry-run

# 以保守模式执行（默认）
sudo bash /root/vps.sh

# 极限/危险模式（仅在隔离测试环境）
sudo bash /root/vps.sh --aggressive

# 测试脚本（建议前后都跑一遍看效果）
curl -sSL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vps1.sh -o /root/vps1.sh
```

---

## 常见参数与含义（参照脚本）

* `--dry-run`：预览脚本将做的改动（若脚本实现）。
* `--aggressive` / `AGGRESSIVE=1`：启用极限模式，可能会关闭多项安全缓解、强制 GRUB 参数、写入危险 sysctl。**高风险**。
* `-y`、`--yes`：无交互直接执行（谨慎使用）。

> 注意：不同版本的脚本参数名称可能不同，请优先阅读脚本头部注释与 `--help` 输出（若有）。

---

## 风险清单（必须阅读）

脚本可能会做出下列修改，其中任意一项错误配置都可能导致系统异常：

* **修改 GRUB 并关闭 CPU 缓解（mitigations）**：提升性能但显著降低安全性，可能允许投机执行侧信道类攻击。
* **更改 I/O 调度为 `none` / `noop`**：对 SSD 有利，但对混合或旋转盘工作负载可能降低性能或影响延迟平衡。
* **修改 netfilter/conntrack/端口范围与表大小**：若设置过大而内存不足，可能造成内存紧张或 OOM。
* **关闭 IPv6 / 禁用某些守护进程**：可能导致某些应用或监控链路失效。
* **关闭或修改 offload**：对通过一定硬件卸载的网卡会产生副作用，需和网卡驱动/固件配合。

如果你在生产环境运行，务必准备完整备份与回滚策略。

---

## 回滚（常用步骤）

> 如果脚本自带备份目录（例如 `/root/xxx_backup_timestamp`），可直接用备份恢复对应文件。通用回滚步骤：

1. 恢复 GRUB 文件并更新：

```bash
cp /path/to/backup/default-grub.bak /etc/default/grub
update-grub || grub2-mkconfig -o /boot/grub2/grub.cfg
```

2. 恢复 sysctl 配置并 reload：

```bash
cp /path/to/backup/99-ultimate-performance.conf /etc/sysctl.d/99-ultimate-performance.conf
sysctl --system
```

3. 恢复 udev/limits/systemd 单元并触发：

```bash
cp /path/to/backup/60-io-scheduler.rules /etc/udev/rules.d/
udevadm control --reload-rules && udevadm trigger
systemctl daemon-reload
systemctl disable --now ultimate-performance-boot.service || true
```

4. 若系统无法启动，使用云厂商快照控制台或引导救援系统恢复镜像文件。

---

## 基准/验证步骤（建议）

在变更前后都执行以下基准测试并记录：

* **网络**：`iperf3 -s`（服务端）与 `iperf3 -c <server> -P <parallel> -t 60`（客户端）。
* **磁盘**：`fio` 随机读写与顺序读写测试。示例：

  ```bash
  fio --name=seqwrite --size=1G --rw=write --bs=1M --ioengine=libaio --direct=1 --numjobs=1 --time_based --runtime=60
  ```
* **内存/CPU**：`dd if=/dev/zero of=/dev/null bs=1M count=1024` / `sysbench` / `stress-ng`。
* **长时间稳定性**：执行 24–72 小时的稳定性压力测试并监控 `dmesg`、`/var/log/syslog`、OOM 情况。

---

## 定制化建议

1. **按网卡型号调整 ring 与 irq 措施**：运行 `ethtool -i <nic>` 获取驱动信息，并参考厂商网卡优化文档。
2. **根据内存大小动态调整 rmem/wmem 与 hugepages**：若服务使用大内存池或虚拟化多虚机，合理设置 `nr_hugepages`。
3. **分阶段引入 AGGRESSIVE 项目**：先在单机上启用再进行全量上线。

---

## 结语

`vps.sh` 是一把强劲的工具，但也可能是一把危险的利刃。请始终遵循“备份 → dry-run → 小规模验证 → 指标对比 → 平滑放量”的流程。若你愿意，我可以为你：

* 生成该脚本的逐行注释版本；
* 列出 `--aggressive` 会修改的每一项并给出回退命令；
* 或基于你提供的 `lscpu` / `/proc/meminfo` / `ethtool -i <nic>` 输出生成定制化参数。

请选择下一步，我会直接把内容写进仓库 README 或输出供你保存。
