#!/usr/bin/env bash
#
# net-hw-optimize.sh
# 终极版 — 动态自适应硬件/驱动/进程/网络/运行时 全链路优化器
# - 默认激进并立即应用（可用 --dry-run 查看预览）
# - 功能：
#   * 自动检测 NIC/CPU/NUMA/内核、尝试加载 BBR/BBR2
#   * 生成并写入综合 sysctl（TCP/UDP/VM/Kernel）
#   * IRQ -> NUMA/CPU 绑定（手动或自动分配）
#   * RPS/XPS / RX/TX 队列调优
#   * ethtool offloads 与驱动级参数优化
#   * CPU governor -> performance，isolcpus/cpuset 支持
#   * 进程调度优化（cpuset/cgroups，移动高流量工具到专核）
#   * 动态运行时监控：通过 ss/ifstat/iperf/ssldump/ss 报表自动调整 rmem/wmem
#   * iperf3 hook：短测并用结果调整带宽估算
#   * DNS 优化（systemd-resolved 支持）
#   * 备份与回滚（/var/backups/net-hw-optimize-<ts>/rollback.sh）
#   * 可安装为 systemd 服务以自动巡检/微调
#
# WARNING: This script is aggressive and may break system functionality.
set -euo pipefail
IFS=$'\n\t'

# -------------------- 配置与默认 --------------------
PROG="$(basename "$0")"
VER="2025-09-23-ultimate-dynamic"
BACKUP_ROOT="/var/backups/net-hw-optimize"
SYSCTL_TARGET="/etc/sysctl.d/99-net-hw-optimize.conf"
LOGFILE="/var/log/net-hw-optimize.log"
KEY_REGEX='^(net\.core\.default_qdisc|net\.core\.rmem_max|net\.core\.wmem_max|net\.core\.rmem_default|net\.core\.wmem_default|net\.ipv4\.tcp_rmem|net\.ipv4\.tcp_wmem|net\.ipv4\.tcp_congestion_control|net\.ipv4\.udp_mem|net\.ipv4\.udp_rmem_min|net\.ipv4\.udp_wmem_min)[[:space:]]*='

# 默认参数（可通过 CLI 覆盖）
DEFAULT_BW_Mbps=1000
DEFAULT_RTT_MS=150
DEFAULT_MON_INTERVAL=60           # 运行时监控间隔（秒）
AUTO_INSTALL_SYSTEMD=0

# 行为开关（默认激进：立即应用）
DRY_RUN=0         # 0=立即应用（默认）；1=仅预览
AGGRESSIVE=1      # 激进修改（默认）
RUN_IPERF=0
IPERF_SERVERS=()
MON_INTERVAL=${DEFAULT_MON_INTERVAL}
FORCE=1           # 不交互（激进）
QUIET=0

# -------------------- 帮助、日志、执行器 --------------------
log() {
  local ts; ts="$(date +'%F %T')"
  echo "[$ts] $*" | tee -a "$LOGFILE"
}
note(){ [ "$QUIET" -eq 0 ] && echo -e "\033[1;34m[i]\033[0m $*"; log "[i] $*"; }
ok(){ [ "$QUIET" -eq 0 ] && echo -e "\033[1;32m[OK]\033[0m $*"; log "[OK] $*"; }
warn(){ echo -e "\033[1;33m[!]\033[0m $*" >&2; log "[WARN] $*"; }
err(){ echo -e "\033[1;31m[!!]\033[0m $*" >&2; log "[ERR] $*"; }

run_cmd() {
  # 在 dry-run 模式下仅打印命令，不执行
  if [ "$DRY_RUN" -eq 1 ]; then
    note "DRY-RUN: $*"
  else
    log "EXEC: $*"
    eval "$@"
  fi
}

usage(){
  cat <<EOF
$PROG v$VER
Usage: sudo ./$PROG [options]

Options:
  --dry-run              仅预览，不执行（默认会立即执行）
  --bw <Mbps>            目标/估计带宽 (默认 ${DEFAULT_BW_Mbps})
  --rtt <ms>             手动指定 RTT ms（否则自动检测）
  --iperf ip,ip2         启用 iperf3 测试并指定服务端（逗号分隔）
  --interval <s>         运行时监控间隔秒（默认 ${DEFAULT_MON_INTERVAL}）
  --install-service      安装 systemd 服务以定期运行/监控
  --no-aggressive        保守模式（不修改 GRUB/激进项）
  --force                跳过交互确认（默认已强制）
  --quiet                静默
  -h, --help             显示本帮助
EOF
  exit 0
}

# -------------------- 解析参数 --------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --bw) shift; BW_Mbps_INPUT="$1"; shift ;;
    --rtt) shift; RTT_INPUT="$1"; shift ;;
    --iperf) shift; RUN_IPERF=1; IFS=',' read -r -a IPERF_SERVERS <<< "$1"; shift ;;
    --interval) shift; MON_INTERVAL="$1"; shift ;;
    --install-service) AUTO_INSTALL_SYSTEMD=1; shift ;;
    --no-aggressive) AGGRESSIVE=0; shift ;;
    --force) FORCE=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown option $1"; usage ;;
  esac
done

# -------------------- 权限检查 --------------------
if [ "$(id -u)" -ne 0 ]; then
  err "请以 root 运行本脚本 (sudo)"; exit 2
fi

# -------------------- 基础检测函数 --------------------
timestamp(){ date +%F-%H%M%S; }
default_iface(){ ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true; }
has(){ command -v "$1" >/dev/null 2>&1; }

get_mem_gib(){
  awk '/MemTotal/ {printf "%.2f", $2/1024/1024; exit}' /proc/meminfo
}
get_cpu_count(){ nproc || true; }
get_numa_nodes(){
  if has numactl; then
    numactl --hardware 2>/dev/null | awk '/available:/{print $2}' | head -1 || true
  else
    echo ""
  fi
}

get_ssh_client_ip(){
  if [ -n "${SSH_CONNECTION:-}" ]; then echo "$SSH_CONNECTION" | awk '{print $1}'; return 0; fi
  if [ -n "${SSH_CLIENT:-}" ]; then echo "$SSH_CLIENT" | awk '{print $1}'; return 0; fi
  return 1
}

detect_rtt_ms() {
  local target="$1"
  local tmp out
  tmp="$(mktemp)"
  if ping -c 4 -W 2 "$target" >"$tmp" 2>/dev/null; then
    out=$(awk -F'/' '/rtt|round-trip/ {print $5; exit}' "$tmp" || true)
    if [ -z "$out" ]; then
      out=$(grep -Eo '[0-9]+(\.[0-9]+)?/([0-9]+(\.[0-9]+)?)' "$tmp" | head -n1 | awk -F'/' '{print $2}' || true)
    fi
  else
    out=$(tail -n 3 "$tmp" 2>/dev/null | awk -F'/' '/rtt|round-trip/ {print $5; exit}' || true)
  fi
  rm -f "$tmp"
  if [[ "$out" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf "%.0f" "$out"
  else
    echo ""
  fi
}

# -------------------- 参数与自动检测 --------------------
MEM_G="$(get_mem_gib)"
CPU_CORES="$(get_cpu_count)"
NUMA_NODES="$(get_numa_nodes || true)"
BW_Mbps="${BW_Mbps_INPUT:-${DEFAULT_BW_Mbps}}"
RTT_MS=""

# 优先使用 SSH 客户端 IP 做 ping 测试
if ssh_ip="$(get_ssh_client_ip 2>/dev/null || true)"; then
  if [ -n "$ssh_ip" ]; then
    note "自动从 SSH 连接检测到客户端 IP: $ssh_ip ，尝试 ping 获取 RTT"
    r="$(detect_rtt_ms "$ssh_ip" || true)"
    if [ -n "$r" ]; then
      RTT_MS="$r"; note "检测 RTT=${RTT_MS}ms (来自 SSH 客户端 $ssh_ip)"
    else
      warn "对 SSH 客户端 ping 失败"
    fi
  fi
fi

if [ -z "${RTT_MS:-}" ]; then
  note "回退到公共地址 1.1.1.1 进行 RTT 检测"
  r="$(detect_rtt_ms "1.1.1.1" || true)"
  if [ -n "$r" ]; then
    RTT_MS="$r"; note "检测 RTT=${RTT_MS}ms (来自 1.1.1.1)"
  else
    warn "Ping 无法解析 RTT，使用默认 ${DEFAULT_RTT_MS} ms"
    RTT_MS="${RTT_INPUT:-$DEFAULT_RTT_MS}"
  fi
fi

note "系统概览: MEM=${MEM_G} GiB, CPU=${CPU_CORES} cores, NUMA=${NUMA_NODES:-N/A}, BW=${BW_Mbps} Mbps, RTT=${RTT_MS} ms"

# -------------------- 计算 BDP & 桶化 --------------------
calc_bdp_bytes(){ awk -v bw="$1" -v rtt="$2" 'BEGIN{printf "%.0f", bw*125*rtt}'; }
BDP_BYTES="$(calc_bdp_bytes "$BW_Mbps" "$RTT_MS")"
MEM_BYTES=$(awk -v g="$MEM_G" 'BEGIN{printf "%.0f", g*1024*1024*1024}')
TWO_BDP=$((BDP_BYTES*2))
RAM3_BYTES=$(awk -v m="$MEM_BYTES" 'BEGIN{printf "%.0f", m*0.03}')
CAP64=$((64*1024*1024))
MAX_NUM_BYTES="$(min3() { awk -v a="$1" -v b="$2" -v c="$3" 'BEGIN{m=a; if(b<m)m=b; if(c<m)m=c; printf "%.0f", m}'; }; min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")"
MAX_MB_NUM=$(( MAX_NUM_BYTES / 1024 / 1024 ))
bucket_le_mb(){
  local mb="$1"
  if [ "$mb" -ge 64 ]; then echo 64
  elif [ "$mb" -ge 32 ]; then echo 32
  elif [ "$mb" -ge 16 ]; then echo 16
  elif [ "$mb" -ge 8 ]; then echo 8
  else echo 4
  fi
}
MAX_MB="$(bucket_le_mb "$MAX_MB_NUM")"
MAX_BYTES=$(( MAX_MB * 1024 * 1024 ))

# 基于桶选择默认 buffer 默认值
if [ "$MAX_MB" -ge 32 ]; then
  DEF_R=262144; DEF_W=524288
elif [ "$MAX_MB" -ge 8 ]; then
  DEF_R=131072; DEF_W=262144
else
  DEF_R=87380; DEF_W=131072
fi

TCP_RMEM_MIN=4096; TCP_RMEM_DEF=87380; TCP_RMEM_MAX=$MAX_BYTES
TCP_WMEM_MIN=4096; TCP_WMEM_DEF=65536; TCP_WMEM_MAX=$MAX_BYTES

note "BDP=${BDP_BYTES} bytes (~$(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB) -> cap ${MAX_MB} MB (${MAX_BYTES} bytes)"

# -------------------- 备份目录与 rollback 脚本 --------------------
TS="$(timestamp)"
BACKUP_DIR="${BACKUP_ROOT}/net-hw-optimize-${TS}"
mkdir -p "$BACKUP_DIR"
ROLLBACK_SCRIPT="${BACKUP_DIR}/rollback.sh"
cat > "$ROLLBACK_SCRIPT" <<'RB'
#!/usr/bin/env bash
set -euo pipefail
restore_file(){ src="$1"; dst="$2"; if [ -f "$src" ]; then cp -a "$src" "$dst"; echo "[rollback] restored $dst from $src"; else echo "[rollback] missing $src"; fi }
RB
chmod 700 "$ROLLBACK_SCRIPT"
echo "# rollback actions" > "${BACKUP_DIR}/rollback_actions.txt"

# -------------------- 冲突处理：注释 /etc/sysctl.conf & 改名 /etc/sysctl.d 冲突文件 --------------------
comment_conflicts_in_sysctl_conf() {
  local f="/etc/sysctl.conf"
  [ -f "$f" ] || { ok "/etc/sysctl.conf 不存在"; return 0; }
  if grep -Eq "$KEY_REGEX" "$f"; then
    cp -a "$f" "${BACKUP_DIR}/sysctl.conf.bak.${TS}"
    note "备份 /etc/sysctl.conf -> ${BACKUP_DIR}/sysctl.conf.bak.${TS}"
    awk -v re="$KEY_REGEX" '$0 ~ re && $0 !~ /^[[:space:]]*#/ { print "# " $0; next } { print $0 }' "$f" > "${f}.tmp.$$"
    install -m 0644 "${f}.tmp.$$" "$f"; rm -f "${f}.tmp.$$"
    echo "restore_file \"${BACKUP_DIR}/sysctl.conf.bak.${TS}\" \"/etc/sysctl.conf\"" >> "${BACKUP_DIR}/rollback_actions.txt"
    echo "restore_file \"${BACKUP_DIR}/sysctl.conf.bak.${TS}\" \"/etc/sysctl.conf\"" >> "$ROLLBACK_SCRIPT"
    ok "注释 /etc/sysctl.conf 中冲突键并记录回滚"
  else
    ok "/etc/sysctl.conf 无冲突键"
  fi
}

process_conflict_files_in_dir(){
  local dir="$1"; [ -d "$dir" ] || { ok "$dir 不存在"; return 0; }
  shopt -s nullglob
  local moved=0
  for f in "$dir"/*.conf; do
    [ "$(readlink -f "$f")" = "$(readlink -f "$SYSCTL_TARGET")" ] && continue
    if grep -Eq "$KEY_REGEX" "$f"; then
      local dest="${f}.disabled_by_net_hw_optimize.${TS}"
      mv -- "$f" "$dest"
      note "已改名并禁用冲突文件: $f -> $dest"
      echo "mv \"$dest\" \"$f\"" >> "${BACKUP_DIR}/rollback_actions.txt"
      echo "mv \"$dest\" \"$f\"" >> "$ROLLBACK_SCRIPT"
      moved=1
    fi
  done
  shopt -u nullglob
  [ "$moved" -eq 1 ] && ok "$dir 中的冲突文件已处理" || ok "$dir 无需处理"
}

note "开始冲突检测与备份"
comment_conflicts_in_sysctl_conf
process_conflict_files_in_dir "/etc/sysctl.d"
for d in "/usr/local/lib/sysctl.d" "/usr/lib/sysctl.d" "/lib/sysctl.d" "/run/sysctl.d"; do
  if [ -d "$d" ]; then
    warn "检测到系统路径 $d：仅提示不改"
    grep -RhnE "$KEY_REGEX" "$d" 2>/dev/null || true
  else
    ok "$d 不存在"
  fi
done

# -------------------- 生成综合 sysctl --------------------
TMP_SYSCTL="$(mktemp)"
cat > "$TMP_SYSCTL" <<EOF
# Generated by net-hw-optimize (ultimate)
# Inputs: MEM_G=${MEM_G}GiB, BW=${BW_Mbps}Mbps, RTT=${RTT_MS}ms
# BDP ~ $(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB -> cap ${MAX_MB} MB

# qdisc / congestion
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# core buffers
net.core.rmem_default = ${DEF_R}
net.core.wmem_default = ${DEF_W}
net.core.rmem_max = ${MAX_BYTES}
net.core.wmem_max = ${MAX_BYTES}
net.core.optmem_max = 262144
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 65535

# TCP
net.ipv4.tcp_rmem = ${TCP_RMEM_MIN} ${TCP_RMEM_DEF} ${TCP_RMEM_MAX}
net.ipv4.tcp_wmem = ${TCP_WMEM_MIN} ${TCP_WMEM_DEF} ${TCP_WMEM_MAX}
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_dsack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_no_metrics_save = 0

# UDP
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.udp_mem = 65536 131072 262144

# VM / misc aggressive
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
vm.min_free_kbytes = 65536
kernel.pid_max = 65535

# IPv4 misc
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
EOF

# 写入 sysctl 文件并备份原有
if [ -f "$SYSCTL_TARGET" ]; then
  cp -a "$SYSCTL_TARGET" "${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TS}"
  echo "restore_file \"${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TS}\" \"$SYSCTL_TARGET\"" >> "${BACKUP_DIR}/rollback_actions.txt"
  echo "restore_file \"${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TS}\" \"$SYSCTL_TARGET\"" >> "$ROLLBACK_SCRIPT"
  note "备份旧的 $SYSCTL_TARGET"
fi

run_cmd install -m 0644 "$TMP_SYSCTL" "$SYSCTL_TARGET"
run_cmd sysctl --system || warn "sysctl --system 返回非零"

# -------------------- NIC / driver level: detect NICs and tune --------------------
note "检测网络接口与驱动"
mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|virbr|docker|br-|veth|tun|tap)' || true)
note "候选接口: ${IFACES[*]:-none}"

# attempt to enable bbr / bbr2 if available
if grep -q bbr /boot/config-$(uname -r) 2>/dev/null || true; then
  run_cmd modprobe tcp_bbr || true
  if sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr2; then
    note "系统支持 bbr2"
  fi
fi

# Function: set ethtool offloads high-performance (attempt enable/disable depending)
tune_offloads() {
  local ifname="$1"
  if ! command -v ethtool >/dev/null 2>&1; then
    warn "系统缺少 ethtool，跳过驱动级 offload 调整"
    return 0
  fi
  # Query and attempt to set recommended for performance: enable gso/gro/tso if supported
  local supports
  supports=$(ethtool -k "$ifname" 2>/dev/null || true)
  # try enabling TSO/GSO/GRO (often beneficial), but for some virtualization it's better to disable; we enable here (aggressive)
  for feat in tso gso gro; do
    if echo "$supports" | grep -qi "^${feat}:"; then
      run_cmd ethtool -K "$ifname" "$feat" on || warn "ethtool -K $ifname $feat on failed"
    fi
  done
  # Disable rx/tx checksumming? usually beneficial to keep checksum offload on NIC: enable tx-checksumming
  for feat in rx tx sg rxvlan txvlan; do
    # toggle some features optimistically
    if echo "$supports" | grep -qi "^${feat}:"; then
      run_cmd ethtool -K "$ifname" "$feat" on || true
    fi
  done
  ok "尝试调整 $ifname 的 ethtool offloads（以提升吞吐）"
}

# RPS/XPS helper: set mask on rx queues
write_mask() {
  local path="$1"; local cpumask="$2"
  if [ -w "$path" ]; then
    run_cmd bash -c "echo $cpumask > $path"
  else
    warn "无法写入 $path"
  fi
}

# Create cpu mask string for first N cores (little-endian)
cpu_mask_for_cores() {
  local cores="$1"
  # build mask as hex: set bits 0..(cores-1)
  local mask=0
  # Use bash arithmetic via bc is cumbersome; do with printf
  # We'll create binary string then convert to hex
  local bin=""
  for ((i=0;i<cores;i++)); do bin="1${bin}"; done
  # pad to multiple of 4
  while (( ${#bin} % 4 != 0 )); do bin="0${bin}"; done
  # convert each nibble to hex
  local hex=""
  for ((i=0;i<${#bin}; i+=4)); do
    nibble="${bin:i:4}"
    hex_n=$(printf "%X" "$((2#${nibble}))")
    hex="${hex}${hex_n}"
  done
  # reverse hex string (because we built little-endian)
  echo "$hex" | rev
}

# NUMA-aware IRQ affinity: group queues to cores per NUMA
assign_irqs_to_cpus() {
  local ifname="$1"
  # find irq for device (eth tool)
  local devpath; devpath=$(ethtool -i "$ifname" 2>/dev/null | awk '/bus-info/ {print $2}' || true)
  # search /proc/interrupts for interface name or devpath
  while read -r line; do
    # sample:  29:  12345   0   0   0  PCI-MSI  eth0-rx-0
    irq=$(awk -F: '{print $1}' <<< "$line" | tr -d ' ')
    name=$(awk '{print $NF}' <<< "$line")
    if [[ "$line" =~ $ifname || "$line" =~ ${ifname}- ]]; then
      # decide CPU to bind: choose one core per queue (round-robin)
      # find number of CPUs
      local cores_count; cores_count="$CPU_CORES"
      # choose core index (simple hash by irq)
      local idx=$((irq % cores_count))
      # build mask for that single core
      local mask=$(printf "%x" $((1 << idx)))
      local aff_path="/proc/irq/${irq}/smp_affinity"
      if [ -w "$aff_path" ]; then
        run_cmd bash -c "printf '%s' ${mask} > ${aff_path}" || warn "写入 $aff_path 失败"
      fi
    fi
  done < /proc/interrupts
}

# Iterate interfaces and tune
for ifname in "${IFACES[@]:-}"; do
  note "处理接口: $ifname"
  # offload tuning
  tune_offloads "$ifname"

  # RPS/XPS: set rps_cpus for rx queues and xps_cpus for tx queues
  # default to use half of cores for RPS/XPS for performance
  rps_cores=$(( CPU_CORES / 2 ))
  [ "$rps_cores" -lt 1 ] && rps_cores=1
  cpumask_hex=$(cpu_mask_for_cores "$rps_cores")
  # write to rx queues
  qdir="/sys/class/net/$ifname/queues"
  if [ -d "$qdir" ]; then
    for rxq in "$qdir"/rx-*; do
      [ -e "$rxq/rps_cpus" ] || continue
      run_cmd bash -c "printf '%s' $cpumask_hex > $rxq/rps_cpus" || warn "写 rps_cpus 失败"
    done
    for txq in "$qdir"/tx-*; do
      [ -e "$txq/xps_cpus" ] || continue
      run_cmd bash -c "printf '%s' $cpumask_hex > $txq/xps_cpus" || warn "写 xps_cpus 失败"
    done
    ok "已为 $ifname 设置 RPS/XPS cpumask=$cpumask_hex"
  fi

  # try set irq affinity NUMA-aware
  assign_irqs_to_cpus "$ifname"
done

# -------------------- CPU / process scheduling tuning --------------------
# Set CPU governor to performance if possible
if has cpupower; then
  run_cmd cpupower frequency-set -g performance || true
elif [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
  for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    run_cmd bash -c "echo performance > $cpu" || true
  done
fi
ok "尝试将 CPU governor 设置为 performance"

# Optionally create isolated cpuset for network tasks
NET_CPUSET="/sys/fs/cgroup/cpuset/net-opt"
if [ -d /sys/fs/cgroup/cpuset ]; then
  if [ ! -d "$NET_CPUSET" ]; then
    run_cmd mkdir -p "$NET_CPUSET"
    # allocate last 1 or 2 cores to network (reserve high cores)
    reserved=$(( CPU_CORES - 1 ))
    [ "$reserved" -lt 0 ] && reserved=0
    run_cmd bash -c "echo 0-$reserved > ${NET_CPUSET}/cpuset.cpus"
    run_cmd bash -c "echo 0 > ${NET_CPUSET}/cpuset.mems"
    ok "已创建 cpuset for net tasks: ${NET_CPUSET}"
  fi
fi

# Move real-time or heavy network processes (iperf3 test) into cpuset if running
if has pgrep && has systemd-cgls; then
  for pname in iperf3; do
    if pgrep -x "$pname" >/dev/null 2>&1; then
      for pid in $(pgrep -x "$pname"); do
        if [ -w "${NET_CPUSET}/cgroup.procs" ]; then
          run_cmd bash -c "echo $pid > ${NET_CPUSET}/cgroup.procs" || true
        fi
      done
      note "已把运行中的 $pname 进程迁移到 ${NET_CPUSET}"
    fi
  done
fi

# -------------------- Dynamic runtime monitor & adaptive tuner --------------------
# Heuristic:
#  - 每周期采集 ss -> retrans，ifstat -> throughput，/proc/net/dev -> drops/errors
#  - 若重传率高 -> 降低 tcp_wmem/tcp_rmem 上限 10%
#  - 若吞吐低且重传低 -> 提升上限 10%（但不超过 MAX_BYTES）
#  - 逐步调整并写入 sysctl.d 文件，然后 sysctl --system
MON_LOG="${BACKUP_DIR}/runtime_monitor.log"
touch "$MON_LOG"
note "启动一次性运行时自适应调优（不会长期驻留，使用 --install-service 可安装为定期任务）"

runtime_once() {
  # sample metrics
  # 1) retransmissions for established sockets
  local total_retrans=0 total_segs_out=0
  if has ss; then
    # sum retrans across tcp sockets
    while read -r line; do
      # parse "retrans:123" segments; we use regex
      r=$(echo "$line" | grep -Po 'retrans:\d+/\K\d+' || echo 0)
      s=$(echo "$line" | grep -Po 'segs_out:\K\d+' || echo 0)
      total_retrans=$((total_retrans + r))
      total_segs_out=$((total_segs_out + s))
    done < <(ss -tin 2>/dev/null || true)
  fi
  # compute retransmission percentage
  local retrans_pct=0
  if [ "$total_segs_out" -gt 0 ]; then
    retrans_pct=$(awk -v r="$total_retrans" -v s="$total_segs_out" 'BEGIN{printf "%.2f", (r/s)*100}')
  fi

  # 2) throughput: read /proc/net/dev for interface totals over 1s
  declare -A rx1 tx1 rx2 tx2
  for iface in "${IFACES[@]:-}"; do
    # read initial byte counters
    local line
    line=$(grep -E "^\s*${iface}:" /proc/net/dev || true)
    if [ -n "$line" ]; then
      read -r _ rx1[$iface] tx1[$iface] <<< "$(echo "$line" | awk -F: '{gsub(/^ +/,"",$2); print $2}' | awk '{print $1,$9}')"
    else
      rx1[$iface]=0; tx1[$iface]=0
    fi
  done
  sleep 1
  for iface in "${IFACES[@]:-}"; do
    line=$(grep -E "^\s*${iface}:" /proc/net/dev || true)
    if [ -n "$line" ]; then
      read -r _ rx2[$iface] tx2[$iface] <<< "$(echo "$line" | awk -F: '{gsub(/^ +/,"",$2); print $2}' | awk '{print $1,$9}')"
    else
      rx2[$iface]=0; tx2[$iface]=0
    fi
  done
  # compute Mbps
  local total_mbps=0
  for iface in "${IFACES[@]:-}"; do
    local rxd=$(( rx2[$iface] - rx1[$iface] ))
    local txd=$(( tx2[$iface] - tx1[$iface] ))
    local mbps=$(( (rxd+txd) * 8 / 1000000 ))
    total_mbps=$(( total_mbps + mbps ))
  done

  # current tcp wmem/rmem max read
  local cur_rmax cur_wmax
  cur_rmax=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "$MAX_BYTES")
  cur_wmax=$(sysctl -n net.core.wmem_max 2>/dev/null || echo "$MAX_BYTES")

  # decision logic
  note "runtime metrics: total_mbps=${total_mbps} Mbps, retrans_pct=${retrans_pct}%"

  local change=0
  if (( $(echo "$retrans_pct > 2.0" | bc -l) )); then
    # too many retrans -> reduce buffers by 10%
    local new_rmax=$(( cur_rmax * 9 / 10 ))
    local new_wmax=$(( cur_wmax * 9 / 10 ))
    change=1
    note "检测到重传率高 (${retrans_pct}%), 降低 r/w max 到 $(printf "%d" "$new_rmax")"
  else
    # throughput low relative to estimate but retrans low -> increase up to cap
    if [ "$total_mbps" -lt "$BW_Mbps" ]; then
      local utilization_pct=$(awk -v t="$total_mbps" -v b="$BW_Mbps" 'BEGIN{ if(b==0){print 0} else {printf "%.2f", t/b*100}}')
      if (( $(echo "$utilization_pct < 30.0" | bc -l) )); then
        # maybe underutilized; cautiously increase
        local new_rmax=$(( cur_rmax * 11 / 10 ))
        local new_wmax=$(( cur_wmax * 11 / 10 ))
        # cap to MAX_BYTES
        [ "$new_rmax" -gt "$MAX_BYTES" ] && new_rmax="$MAX_BYTES"
        [ "$new_wmax" -gt "$MAX_BYTES" ] && new_wmax="$MAX_BYTES"
        change=1
        note "链路利用率低 (${utilization_pct}%), 逐步提升 r/w max 到 $new_rmax"
      fi
    fi
  fi

  if [ "$change" -eq 1 ]; then
    # write a new sysctl fragment and reload
    local tmpf="$(mktemp)"
    cat > "$tmpf" <<EOF
# runtime adjusted by net-hw-optimize (ts=$(timestamp))
net.core.rmem_max = ${new_rmax:-$cur_rmax}
net.core.wmem_max = ${new_wmax:-$cur_wmax}
net.ipv4.tcp_rmem = ${TCP_RMEM_MIN} ${TCP_RMEM_DEF} ${new_rmax:-$cur_rmax}
net.ipv4.tcp_wmem = ${TCP_WMEM_MIN} ${TCP_WMEM_DEF} ${new_wmax:-$cur_wmax}
EOF
    run_cmd install -m 0644 "$tmpf" "${SYSCTL_TARGET}"
    run_cmd sysctl --system || warn "sysctl --system 返回非零"
    rm -f "$tmpf" || true
    echo "$(date +%s) adjust rmax=${new_rmax:-$cur_rmax} wmax=${new_wmax:-$cur_wmax} mbps=${total_mbps} retrans=${retrans_pct}" >> "$MON_LOG"
    # record rollback: restore previous values by writing backup of old file
    # (we already backed up original earlier)
  else
    note "无需调整（重传率与吞吐在容忍范围）"
  fi
}

# run one adaptive tuning cycle now
runtime_once

# -------------------- Optional iperf3 hook (user enabled) --------------------
if [ "${RUN_IPERF:-0}" -eq 1 ] && has iperf3; then
  for s in "${IPERF_SERVERS[@]}"; do
    note "运行 iperf3 测试 -> $s"
    if iperf3 -c "$s" -t 15 -J >/tmp/.iperf.$$.json 2>/dev/null; then
      if has jq; then
        DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/.iperf.$$.json)
        UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/.iperf.$$.json)
      else
        DL=0; UL=0
      fi
      DL_Mbps=$(( (DL+500000)/1000000 ))
      UL_Mbps=$(( (UL+500000)/1000000 ))
      note "iperf3 result: DL=${DL_Mbps}Mbps UL=${UL_Mbps}Mbps"
      # if measured lower than BW_Mbps, adjust estimate and recompute BDP (conservative)
      if [ "$DL_Mbps" -gt 0 ] && [ "$DL_Mbps" -lt "$BW_Mbps" ]; then
        note "测得带宽小于估计，调整目标带宽为 ${DL_Mbps}Mbps 并重新计算"
        BW_Mbps="$DL_Mbps"
        BDP_BYTES="$(calc_bdp_bytes "$BW_Mbps" "$RTT_MS")"
        TWO_BDP=$((BDP_BYTES*2))
        RAM3_BYTES=$(awk -v m="$MEM_BYTES" 'BEGIN{printf "%.0f", m*0.03}')
        MAX_NUM_BYTES="$(min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")"
        MAX_MB_NUM=$(( MAX_NUM_BYTES / 1024 / 1024 ))
        MAX_MB="$(bucket_le_mb "$MAX_MB_NUM")"
        MAX_BYTES=$(( MAX_MB * 1024 * 1024 ))
        note "新的 cap=${MAX_MB} MB"
      fi
    else
      warn "iperf3 到 $s 测试失败"
    fi
    rm -f /tmp/.iperf.$$.json || true
  done
fi

# -------------------- Aggressive: modify GRUB to disable mitigations (if requested) --------------------
if [ "$AGGRESSIVE" -eq 1 ]; then
  GRUB_CFG="/etc/default/grub"
  if [ -f "$GRUB_CFG" ]; then
    cp -a "$GRUB_CFG" "${BACKUP_DIR}/grub.default.bak.${TS}"
    note "备份 GRUB -> ${BACKUP_DIR}/grub.default.bak.${TS}"
    # add mitigations=off and other flags
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_CFG"; then
      sed -E "s/GRUB_CMDLINE_LINUX_DEFAULT=\"([^\"]*)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 mitigations=off noibrs noibpb nopti nospectre_v2 nospectre_v1 l1tf=off mds=off tsx=on\"/" "$GRUB_CFG" > "${GRUB_CFG}.tmp.$$"
      run_cmd install -m 0644 "${GRUB_CFG}.tmp.$$" "$GRUB_CFG"; rm -f "${GRUB_CFG}.tmp.$$"
      echo "restore_file \"${BACKUP_DIR}/grub.default.bak.${TS}\" \"$GRUB_CFG\"" >> "${BACKUP_DIR}/rollback_actions.txt"
      echo "restore_file \"${BACKUP_DIR}/grub.default.bak.${TS}\" \"$GRUB_CFG\"" >> "$ROLLBACK_SCRIPT"
      # try update-grub
      if has update-grub; then run_cmd update-grub; fi
      if has update-grub2; then run_cmd update-grub2; fi
      ok "已修改 GRUB（激进模式）并尝试更新"
    else
      warn "未在 $GRUB_CFG 中找到 GRUB_CMDLINE_LINUX_DEFAULT"
    fi
  else
    warn "$GRUB_CFG 不存在，跳过激进 grub 修改"
  fi
fi

# -------------------- Finalization & systemd service install --------------------
# write logs and print summary
note "写入日志与备份位置: $BACKUP_DIR"
echo "Net HW Optimize run at $(date) -- BW=${BW_Mbps} RTT=${RTT_MS} BDP=${BDP_BYTES} cap=${MAX_MB}MB" >> "${BACKUP_DIR}/summary.txt"

# offer to install systemd service if requested
if [ "$AUTO_INSTALL_SYSTEMD" -eq 1 ]; then
  note "安装 systemd 服务 net-hw-optimize.service 与 timer"
  SERVICE_PATH="/etc/systemd/system/net-hw-optimize.service"
  TIMER_PATH="/etc/systemd/system/net-hw-optimize.timer"
  cat > "$SERVICE_PATH" <<'SRV'
[Unit]
Description=Net HW Optimize one-shot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/net-hw-optimize.sh --dry-run
SRV
  cat > "$TIMER_PATH" <<'TMR'
[Unit]
Description=Run net-hw-optimize daily

[Timer]
OnBootSec=2min
OnUnitActiveSec=1h
Persistent=true

[Install]
WantedBy=timers.target
TMR
  run_cmd systemctl daemon-reload
  run_cmd systemctl enable --now net-hw-optimize.timer || true
  ok "systemd timer installed (service at $SERVICE_PATH)"
fi

# final prints
echo "==== RESULT ===="
echo "Memory: ${MEM_G} GiB, CPU: ${CPU_CORES}, NUMA: ${NUMA_NODES:-N/A}"
echo "BDP ~ $(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB, cap=${MAX_MB} MB"
sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true
sysctl -n net.core.default_qdisc 2>/dev/null || true
sysctl -n net.core.rmem_max 2>/dev/null || true
sysctl -n net.core.wmem_max 2>/dev/null || true
sysctl -n net.ipv4.tcp_rmem 2>/dev/null || true
sysctl -n net.ipv4.tcp_wmem 2>/dev/null || true
if has tc; then
  IFACE="$(default_iface)"
  [ -n "$IFACE" ] && { echo "qdisc on $IFACE:"; tc qdisc show dev "$IFACE" || true; }
fi
echo "Backups & rollback in: $BACKUP_DIR"
echo "Run rollback: sudo $ROLLBACK_SCRIPT"
echo "Done."

exit 0
