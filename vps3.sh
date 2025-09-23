#!/usr/bin/env bash
# net-optimizer-final.sh
# 2025-09-23 final unified optimizer
# WARNING: aggressive changes — modifies sysctl, grub, sysfs, qdisc, cpuset, etc.
set -euo pipefail
IFS=$'\n\t'

# ---------------- CONFIG ----------------
APPLY=1                # 1=立即应用（默认激进）；0=dry-run（预览）
BACKUP_ROOT="/var/backups/net-optimizer"
SYSCTL_TARGET="/etc/sysctl.d/999-net-optimizer.conf"
DEFAULT_BW_Mbps=1000
DEFAULT_RTT_MS=150
MON_INTERVAL=60        # 运行时自适应监控间隔（秒），脚本默认执行一次调整周期
IPERF_SERVERS=()       # 如需自动 iperf 测试，设置成 ("1.2.3.4" "5.6.7.8")
RUN_IPERF=0            # 1=启用 iperf hook
INSTALL_SERVICE=0      # 1=安装 systemd timer/service
AGGRESSIVE=1           # 1=启用激进 grub / 内核参数修改
QUIET=0                # 1=静默

# ---------------- UI helpers ----------------
_note(){ [ "$QUIET" -eq 0 ] && printf "\033[1;34m[i]\033[0m %s\n" "$*"; }
_ok(){ [ "$QUIET" -eq 0 ] && printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
_warn(){ printf "\033[1;33m[!]\033[0m %s\n" "$*" >&2; }
_err(){ printf "\033[1;31m[!!]\033[0m %s\n" "$*" >&2; }

run_or_echo(){
  # 如果 APPLY=1 执行命令，否则仅打印（dry-run）
  if [ "$APPLY" -eq 1 ]; then
    eval "$@"
  else
    _note "DRY-RUN: $*"
  fi
}

require_root(){ if [ "$(id -u)" -ne 0 ]; then _err "请以 root 运行"; exit 2; fi; }
require_root

timestamp(){ date +%F-%H%M%S; }
default_iface(){ ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true; }
has(){ command -v "$1" >/dev/null 2>&1; }

# ---------------- utilities ----------------
min3(){ awk -v a="$1" -v b="$2" -v c="$3" 'BEGIN{m=a; if(b<m)m=b; if(c<m)m=c; printf "%.0f", m}'; }

get_mem_gib(){ awk '/MemTotal/ {printf "%.2f", $2/1024/1024; exit}' /proc/meminfo; }
get_ssh_client_ip(){
  if [ -n "${SSH_CONNECTION:-}" ]; then echo "$SSH_CONNECTION" | awk '{print $1}'; return 0; fi
  if [ -n "${SSH_CLIENT:-}" ]; then echo "$SSH_CLIENT" | awk '{print $1}'; return 0; fi
  return 1
}
detect_rtt_ms(){
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
  if [[ "$out" =~ ^[0-9]+([.][0-9]+)?$ ]]; then printf "%.0f" "$out"; else echo ""; fi
}
calc_bdp_bytes(){ awk -v bw="$1" -v rtt="$2" 'BEGIN{printf "%.0f", bw*125*rtt}'; }

cpu_mask_for_cores(){
  # return hex mask for first N cores (cap 62 to be safe)
  local cores="$1"
  if [ "$cores" -le 0 ]; then echo "1"; return; fi
  if [ "$cores" -gt 62 ]; then cores=62; fi
  local mask=$(( (1 << cores) - 1 ))
  printf "%x" "$mask"
}

write_sysfs_value(){
  local path="$1"; local val="$2"
  if [ ! -e "$path" ]; then _warn "sysfs not found: $path"; return 1; fi
  if [ ! -w "$path" ]; then _warn "sysfs not writable: $path"; return 2; fi
  printf '%s' "$val" > "$path" || { _warn "写入 $path 失败"; return 3; }
  return 0
}

# ---------------- initial detection ----------------
MEM_G=$(get_mem_gib)
CPU_CORES=$(nproc || echo 1)
BW_Mbps="${BW_Mbps:-$DEFAULT_BW_Mbps}"
RTT_MS=""
RTT_SOURCE="auto"

# 优先用 SSH 客户端 IP ping
if ssh_ip="$(get_ssh_client_ip 2>/dev/null || true)"; then
  if [ -n "$ssh_ip" ]; then
    _note "自动从 SSH 连接检测到客户端 IP: ${ssh_ip}，尝试 ping 获取 RTT"
    rttv="$(detect_rtt_ms "$ssh_ip" || true)"
    if [ -n "$rttv" ]; then RTT_MS="$rttv"; RTT_SOURCE="ssh:${ssh_ip}"; _ok "检测 RTT=${RTT_MS} ms (来自 SSH 客户端 ${ssh_ip})"; else _warn "对 SSH 客户端 ping 失败"; fi
  fi
fi

# 回退到 1.1.1.1
if [ -z "${RTT_MS}" ]; then
  _note "回退到公共地址 1.1.1.1 进行 RTT 检测"
  rttv="$(detect_rtt_ms 1.1.1.1 || true)"
  if [ -n "$rttv" ]; then RTT_MS="$rttv"; RTT_SOURCE="1.1.1.1"; _ok "检测 RTT=${RTT_MS} ms (来自 1.1.1.1)"; else _warn "无法检测 RTT，使用默认 ${DEFAULT_RTT_MS} ms"; RTT_MS="$DEFAULT_RTT_MS"; RTT_SOURCE="default"; fi
fi

_note "系统概览: MEM=${MEM_G} GiB, CPU=${CPU_CORES} cores, BW=${BW_Mbps} Mbps, RTT=${RTT_MS} ms"

# ---------------- BDP & caps ----------------
BDP_BYTES=$(calc_bdp_bytes "$BW_Mbps" "$RTT_MS")
MEM_BYTES=$(awk -v g="$MEM_G" 'BEGIN{printf "%.0f", g*1024*1024*1024}')
TWO_BDP=$(( BDP_BYTES * 2 ))
RAM3_BYTES=$(awk -v m="$MEM_BYTES" 'BEGIN{printf "%.0f", m*0.03}')
CAP64=$((64*1024*1024))
MAX_NUM_BYTES=$(min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")
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
MAX_MB=$(bucket_le_mb "$MAX_MB_NUM")
MAX_BYTES=$(( MAX_MB * 1024 * 1024 ))

if [ "$MAX_MB" -ge 32 ]; then
  DEF_R=262144; DEF_W=524288
elif [ "$MAX_MB" -ge 8 ]; then
  DEF_R=131072; DEF_W=262144
else
  DEF_R=87380; DEF_W=131072
fi

TCP_RMEM_MIN=4096; TCP_RMEM_DEF=87380; TCP_RMEM_MAX=$MAX_BYTES
TCP_WMEM_MIN=4096; TCP_WMEM_DEF=65536; TCP_WMEM_MAX=$MAX_BYTES

_note "BDP ≈ $(awk -v b="$BDP_BYTES" 'BEGIN{printf \"%.2f\", b/1024/1024}') MB -> cap ${MAX_MB} MB"

# ---------------- prepare backups & rollback ----------------
TS=$(timestamp)
BACKUP_DIR="${BACKUP_ROOT}/net-optimizer-${TS}"
run_or_echo mkdir -p "$BACKUP_DIR"
ROLLBACK="${BACKUP_DIR}/rollback.sh"
cat > "$ROLLBACK" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
restore_file(){ src="$1"; dst="$2"; if [ -f "$src" ]; then cp -a "$src" "$dst"; echo "[rollback] restored $dst from $src"; else echo "[rollback] missing $src"; fi }
EOF
run_or_echo chmod +x "$ROLLBACK"
_note "备份将存放在: $BACKUP_DIR"

# ---------------- conflict cleanup ----------------
KEY_REGEX='^(net\.core\.default_qdisc|net\.core\.rmem_max|net\.core\.wmem_max|net\.core\.rmem_default|net\.core\.wmem_default|net\.ipv4\.tcp_rmem|net\.ipv4\.tcp_wmem|net\.ipv4\.tcp_congestion_control)[[:space:]]*='

comment_conflicts_in_sysctl_conf(){
  local f="/etc/sysctl.conf"
  [ -f "$f" ] || { _ok "/etc/sysctl.conf 不存在"; return; }
  if grep -Eq "$KEY_REGEX" "$f"; then
    cp -a "$f" "${BACKUP_DIR}/sysctl.conf.bak.${TS}"
    _note "备份 /etc/sysctl.conf -> ${BACKUP_DIR}/sysctl.conf.bak.${TS}"
    awk -v re="$KEY_REGEX" '$0 ~ re && $0 !~ /^[[:space:]]*#/ { print "# " $0; next } { print $0 }' "$f" > "${f}.tmp.$$"
    run_or_echo install -m 0644 "${f}.tmp.$$" "$f"
    run_or_echo rm -f "${f}.tmp.$$"
    echo "restore_file \"${BACKUP_DIR}/sysctl.conf.bak.${TS}\" \"/etc/sysctl.conf\"" >> "$ROLLBACK"
    _ok "已注释 /etc/sysctl.conf 中的冲突键"
  else
    _ok "/etc/sysctl.conf 无冲突键"
  fi
}

disable_conflict_files_in_dir(){
  local dir="$1"
  [ -d "$dir" ] || { _ok "$dir 不存在"; return; }
  shopt -s nullglob
  for f in "$dir"/*.conf; do
    [ "$(readlink -f "$f")" = "$(readlink -f "$SYSCTL_TARGET")" ] && continue
    if grep -Eq "$KEY_REGEX" "$f"; then
      dest="${f}.disabled_by_optimizer.${TS}"
      run_or_echo mv -- "$f" "$dest"
      echo "mv \"$dest\" \"$f\"" >> "$ROLLBACK"
      _note "已备份并禁用冲突文件: $f -> $dest"
    fi
  done
  shopt -u nullglob
  _ok "$dir 中冲突文件处理完毕"
}

_note "步骤A：备份并注释 /etc/sysctl.conf 的冲突键"
comment_conflicts_in_sysctl_conf

_note "步骤B：备份并改名 /etc/sysctl.d 下含冲突键的旧文件"
disable_conflict_files_in_dir "/etc/sysctl.d"

_note "步骤C：扫描其他系统目录（只提示不改）"
for d in /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d /run/sysctl.d; do
  if [ -d "$d" ]; then
    _warn "提示：检测到系统路径 $d（仅提示，不做修改）"
    grep -RhnE "$KEY_REGEX" "$d" 2>/dev/null || true
  else
    _ok "$d 不存在"
  fi
done

# ---------------- try modprobe bbr ----------------
if has modprobe; then
  run_or_echo modprobe tcp_bbr 2>/dev/null || true
  _ok "尝试加载 tcp_bbr（若内核支持）"
fi

# ---------------- generate sysctl file ----------------
TMP_SYSCTL="$(mktemp)"
cat > "$TMP_SYSCTL" <<EOF
# Auto-generated by net-optimizer-final
# Inputs: MEM_G=${MEM_G}GiB, BW=${BW_Mbps}Mbps, RTT=${RTT_MS}ms (src=${RTT_SOURCE})
# BDP: ${BDP_BYTES} bytes (~$(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB)
# Caps: min(2*BDP, 3%RAM, 64MB) -> Bucket ${MAX_MB} MB

# qdisc and congestion
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

# TCP tune
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
net.ipv4.tcp_moderate_rcvbuf = 1

# UDP tune
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.udp_mem = 65536 131072 262144

# VM / misc
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

# Aggressive extras (from community / your provided sources)
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_adv_win_scale = 2
net.ipv4.tcp_notsent_lowat = 65536
net.ipv4.tcp_low_latency = 1
EOF

# write & backup old target
if [ -f "$SYSCTL_TARGET" ]; then
  run_or_echo cp -a "$SYSCTL_TARGET" "${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TS}"
  echo "restore_file \"${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TS}\" \"$SYSCTL_TARGET\"" >> "$ROLLBACK"
  _note "备份现有 $SYSCTL_TARGET"
fi
run_or_echo install -m 0644 "$TMP_SYSCTL" "$SYSCTL_TARGET"
run_or_echo sysctl --system >/dev/null 2>&1 || _warn "sysctl --system 返回非零"
_ok "已写入并应用 sysctl（视 APPLY）"

# ---------------- NIC/driver tuning ----------------
_note "检测网络接口"
mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|virbr|docker|br-|veth|tun|tap)' || true)
_note "候选接口: ${IFACES[*]:-none}"

tune_ethtool(){
  local ifn="$1"
  if ! has ethtool; then _warn "无 ethtool，跳过 $ifn"; return; fi
  local supports; supports=$(ethtool -k "$ifn" 2>/dev/null || true)
  # enable common offloads (aggressive)
  for feat in tso gso gro rx tx sg txvlan rxvlan; do
    if echo "$supports" | grep -qi "^${feat}:"; then
      run_or_echo ethtool -K "$ifn" "$feat" on 2>/dev/null || _warn "ethtool -K $ifn $feat on 失败"
    fi
  done
  _ok "尝试调整 $ifn 的 ethtool offloads"
}

assign_irqs_to_cpus(){
  local ifn="$1"
  # Try to bind IRQs that mention the interface name to cores round-robin
  local cores="$CPU_CORES"
  while read -r line; do
    irq=$(awk -F: '{print $1}' <<< "$line" | tr -d ' ')
    if echo "$line" | grep -q -E "${ifn}"; then
      idx=$(( irq % cores ))
      mask=$(printf "%x" $((1 << idx)))
      aff="/proc/irq/${irq}/smp_affinity"
      if [ -w "$aff" ]; then
        run_or_echo bash -c "printf '%s' ${mask} > ${aff}"
      fi
    fi
  done < /proc/interrupts
  _ok "尝试为 $ifn 分配 IRQ affinity"
}

set_rps_xps(){
  local ifn="$1"
  local rps_cores=$(( CPU_CORES / 2 ))
  [ "$rps_cores" -lt 1 ] && rps_cores=1
  local cpumask_hex; cpumask_hex=$(cpu_mask_for_cores "$rps_cores")
  local qdir="/sys/class/net/${ifn}/queues"
  if [ -d "$qdir" ]; then
    for rxq in "$qdir"/rx-*; do
      [ -e "$rxq/rps_cpus" ] || continue
      write_sysfs_value "$rxq/rps_cpus" "$cpumask_hex" || _warn "写入 $rxq/rps_cpus 失败"
    done
    for txq in "$qdir"/tx-*; do
      [ -e "$txq/xps_cpus" ] || continue
      write_sysfs_value "$txq/xps_cpus" "$cpumask_hex" || _warn "写入 $txq/xps_cpus 失败"
    done
    _ok "已为 $ifn 设置 RPS/XPS cpumask=$cpumask_hex"
  else
    _warn "$ifn 无 queues 目录，跳过 RPS/XPS"
  fi
}

for ifn in "${IFACES[@]:-}"; do
  _note "处理接口: $ifn"
  tune_ethtool "$ifn"
  set_rps_xps "$ifn"
  assign_irqs_to_cpus "$ifn"
done

# ---------------- CPU & cpuset ----------------
# governor -> performance
if has cpupower; then
  run_or_echo cpupower frequency-set -g performance || true
else
  if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      [ -w "$cpu" ] && run_or_echo bash -c "printf 'performance' > $cpu" || true
    done
  fi
fi
_ok "尝试设置 CPU governor 到 performance"

# create cpuset for network tasks
if [ -d /sys/fs/cgroup/cpuset ]; then
  NET_CPUSET="/sys/fs/cgroup/cpuset/net-opt"
  if [ ! -d "$NET_CPUSET" ]; then
    run_or_echo mkdir -p "$NET_CPUSET"
    reserved_end=$(( CPU_CORES - 1 ))
    if [ "$reserved_end" -lt 0 ]; then reserved_end=0; fi
    run_or_echo bash -c "printf '0-${reserved_end}' > ${NET_CPUSET}/cpuset.cpus" || true
    run_or_echo bash -c "printf '0' > ${NET_CPUSET}/cpuset.mems" || true
    _ok "已创建 cpuset: $NET_CPUSET"
  fi
fi

# ---------------- tc qdisc apply ----------------
IFACE=$(default_iface)
if has tc && [ -n "$IFACE" ]; then
  # choose qdisc: prefer cake if kernel supports it and user requested cake in aggressive mode
  QDISC_TO_SET="fq"
  if [ "$AGGRESSIVE" -eq 1 ]; then
    if tc qdisc add dev lo root cake 2>/dev/null; then
      tc qdisc del dev lo root 2>/dev/null || true
      QDISC_TO_SET="cake"
    fi
  fi
  run_or_echo tc qdisc replace dev "$IFACE" root "$QDISC_TO_SET" 2>/dev/null || _warn "tc qdisc replace 失败（可能内核不支持）"
  _ok "试图在 $IFACE 设置 qdisc: $QDISC_TO_SET"
fi

# ---------------- DNS optimizer (systemd-resolved aware) ----------------
dns_opt(){
  local DNS_LIST="1.1.1.1 8.8.8.8 9.9.9.9"
  if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -qi systemd; then
    if has resolvectl; then
      IFACE_LOCAL=$(default_iface)
      [ -n "$IFACE_LOCAL" ] && run_or_echo resolvectl dns "$IFACE_LOCAL" $DNS_LIST || true
      run_or_echo mkdir -p /etc/systemd/resolved.conf.d
      cat > /etc/systemd/resolved.conf.d/10-dns-opt.conf <<'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8 9.9.9.9
DNSSEC=allow-downgrade
Cache=yes
ReadEtcHosts=yes
EOF
      run_or_echo systemctl restart systemd-resolved || true
      run_or_echo cp -a /etc/systemd/resolved.conf.d/10-dns-opt.conf "${BACKUP_DIR}/10-dns-opt.conf.bak.${TS}" || true
      echo "restore_file \"${BACKUP_DIR}/10-dns-opt.conf.bak.${TS}\" \"/etc/systemd/resolved.conf.d/10-dns-opt.conf\"" >> "$ROLLBACK"
      _ok "已写入 systemd-resolved drop-in"
    fi
  else
    if [ -f /etc/resolv.conf ]; then
      run_or_echo cp -a /etc/resolv.conf "${BACKUP_DIR}/resolv.conf.bak.${TS}"
      run_or_echo bash -c 'cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
options single-request-reopen timeout:2 attempts:2 rotate
EOF'
      echo "restore_file \"${BACKUP_DIR}/resolv.conf.bak.${TS}\" \"/etc/resolv.conf\"" >> "$ROLLBACK"
      _ok "已备份并写入 /etc/resolv.conf"
    fi
  fi
}
dns_opt

# ---------------- iperf hook (optional) ----------------
iperf_hook(){
  if [ "${RUN_IPERF}" -eq 0 ] || ! has iperf3; then return; fi
  for s in "${IPERF_SERVERS[@]:-}"; do
    _note "iperf3 -> $s"
    if iperf3 -c "$s" -t 10 -J >/tmp/.iperf.json 2>/dev/null; then
      if has jq; then
        DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/.iperf.json)
        UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/.iperf.json)
      else
        DL=0; UL=0
      fi
      DL_Mbps=$(( (DL + 500000) / 1000000 ))
      UL_Mbps=$(( (UL + 500000) / 1000000 ))
      _note "iperf3 $s -> DL=${DL_Mbps}Mbps UL=${UL_Mbps}Mbps"
      if [ "$DL_Mbps" -gt 0 ] && [ "$DL_Mbps" -lt "$BW_Mbps" ]; then
        _note "测得带宽小于估计，调整 BW=${DL_Mbps}"
        BW_Mbps="$DL_Mbps"
        # 重新计算 BDP & caps
        BDP_BYTES=$(calc_bdp_bytes "$BW_Mbps" "$RTT_MS")
        TWO_BDP=$(( BDP_BYTES * 2 ))
        MAX_NUM_BYTES=$(min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")
        MAX_MB_NUM=$(( MAX_NUM_BYTES / 1024 / 1024 ))
        MAX_MB=$(bucket_le_mb "$MAX_MB_NUM")
        MAX_BYTES=$(( MAX_MB * 1024 * 1024 ))
        _note "新的 cap=${MAX_MB} MB"
        # update sysctl file r/w max — minimal change here, full update requires rewriting TMP_SYSCTL
      fi
    else
      _warn "iperf3 -> $s 测试失败"
    fi
    rm -f /tmp/.iperf.json || true
  done
}
iperf_hook

# ---------------- runtime adaptive tuner (one-shot) ----------------
runtime_adaptive(){
  local MON_LOG="${BACKUP_DIR}/runtime_monitor.log"
  touch "$MON_LOG"

  # gather retrans and segs_out
  local total_retrans=0 total_segs_out=0
  if has ss; then
    while IFS= read -r line; do
      r=$(echo "$line" | grep -Po 'retrans:\d+/\K\d+' || echo 0)
      s=$(echo "$line" | grep -Po 'segs_out:\K\d+' || echo 0)
      total_retrans=$(( total_retrans + r ))
      total_segs_out=$(( total_segs_out + s ))
    done < <(ss -tin 2>/dev/null || true)
  fi
  local retrans_pct=0
  if [ "$total_segs_out" -gt 0 ]; then
    retrans_pct=$(awk -v r="$total_retrans" -v s="$total_segs_out" 'BEGIN{printf "%.2f", (r/s*100)}')
  fi

  # throughput sample across IFACES
  declare -A rx1 tx1 rx2 tx2
  for ifn in "${IFACES[@]:-}"; do
    line=$(grep -E "^\s*${ifn}:" /proc/net/dev || true)
    if [ -n "$line" ]; then
      read -r _ rx1[$ifn] tx1[$ifn] <<< "$(echo "$line" | awk -F: '{gsub(/^ +/,"",$2); print $2}' | awk '{print $1,$9}')"
    else rx1[$ifn]=0; tx1[$ifn]=0; fi
  done
  sleep 1
  for ifn in "${IFACES[@]:-}"; do
    line=$(grep -E "^\s*${ifn}:" /proc/net/dev || true)
    if [ -n "$line" ]; then
      read -r _ rx2[$ifn] tx2[$ifn] <<< "$(echo "$line" | awk -F: '{gsub(/^ +/,"",$2); print $2}' | awk '{print $1,$9}')"
    else rx2[$ifn]=0; tx2[$ifn]=0; fi
  done
  local total_mbps=0
  for ifn in "${IFACES[@]:-}"; do
    rxd=$(( rx2[$ifn] - rx1[$ifn] ))
    txd=$(( tx2[$ifn] - tx1[$ifn] ))
    mbps=$(( (rxd + txd) * 8 / 1000000 ))
    total_mbps=$(( total_mbps + mbps ))
  done

  _note "runtime metrics: total_mbps=${total_mbps}Mbps retrans_pct=${retrans_pct}%"

  local cur_rmax cur_wmax
  cur_rmax=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "$MAX_BYTES")
  cur_wmax=$(sysctl -n net.core.wmem_max 2>/dev/null || echo "$MAX_BYTES")
  local change=0 new_rmax="$cur_rmax" new_wmax="$cur_wmax"

  # thresholding
  if awk -v r="$retrans_pct" 'BEGIN{exit !(r>2)}'; then
    new_rmax=$(( cur_rmax * 9 / 10 ))
    new_wmax=$(( cur_wmax * 9 / 10 ))
    change=1
    _note "检测高重传 (${retrans_pct}%), 减少 r/w max 10% -> ${new_rmax}"
  else
    if [ "$total_mbps" -lt "$BW_Mbps" ]; then
      util_pct=$(awk -v t="$total_mbps" -v b="$BW_Mbps" 'BEGIN{ if(b==0){print 0} else {printf "%.2f", t/b*100}}')
      if awk -v u="$util_pct" 'BEGIN{exit !(u<30)}'; then
        new_rmax=$(( cur_rmax * 11 / 10 ))
        new_wmax=$(( cur_wmax * 11 / 10 ))
        [ "$new_rmax" -gt "$MAX_BYTES" ] && new_rmax="$MAX_BYTES"
        [ "$new_wmax" -gt "$MAX_BYTES" ] && new_wmax="$MAX_BYTES"
        change=1
        _note "链路利用率低 (${util_pct}%), 逐步提升 r/w max -> ${new_rmax}"
      fi
    fi
  fi

  if [ "$change" -eq 1 ]; then
    tmpf="$(mktemp)"
    cat > "$tmpf" <<EOF
# runtime adjusted by net-optimizer-final $(date -u)
net.core.rmem_max = ${new_rmax}
net.core.wmem_max = ${new_wmax}
net.ipv4.tcp_rmem = ${TCP_RMEM_MIN} ${TCP_RMEM_DEF} ${new_rmax}
net.ipv4.tcp_wmem = ${TCP_WMEM_MIN} ${TCP_WMEM_DEF} ${new_wmax}
EOF
    run_or_echo install -m 0644 "$tmpf" "$SYSCTL_TARGET"
    run_or_echo sysctl --system >/dev/null 2>&1 || _warn "sysctl --system 返回非零"
    rm -f "$tmpf" || true
    echo "$(date +%s) adjust rmax=${new_rmax} wmax=${new_wmax} mbps=${total_mbps} retrans=${retrans_pct}" >> "${BACKUP_DIR}/runtime.log"
    _ok "runtime 调整已应用"
  else
    _note "runtime 调整：无需变更"
  fi
}
runtime_adaptive

# ---------------- grub aggressive changes (if AGGRESSIVE) ----------------
if [ "$AGGRESSIVE" -eq 1 ]; then
  GRUB_CFG="/etc/default/grub"
  if [ -f "$GRUB_CFG" ]; then
    run_or_echo cp -a "$GRUB_CFG" "${BACKUP_DIR}/grub.default.bak.${TS}"
    _note "备份 GRUB -> ${BACKUP_DIR}/grub.default.bak.${TS}"
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_CFG"; then
      sed -E "s/GRUB_CMDLINE_LINUX_DEFAULT=\"([^\"]*)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 mitigations=off noibrs noibpb nopti nospectre_v2 nospectre_v1 l1tf=off mds=off tsx=on\"/" "$GRUB_CFG" > "${GRUB_CFG}.tmp.$$"
      run_or_echo install -m 0644 "${GRUB_CFG}.tmp.$$" "$GRUB_CFG" && run_or_echo rm -f "${GRUB_CFG}.tmp.$$"
      echo "restore_file \"${BACKUP_DIR}/grub.default.bak.${TS}\" \"$GRUB_CFG\"" >> "$ROLLBACK"
      if has update-grub; then run_or_echo update-grub >/dev/null 2>&1 || _warn "update-grub 非零"; fi
      _ok "已修改 GRUB（激进）"
    else
      _warn "GRUB_CMDLINE_LINUX_DEFAULT 未找到，跳过"
    fi
  else
    _warn "GRUB 文件不存在，跳过"
  fi
fi

# ---------------- OCSP & nginx quick helper (from your snippets) ----------------
# getOCSP-like helper: fetch OCSP response for a cert (assumes certbot layout)
get_ocsp_response(){
  domain="$1"
  if [ -z "$domain" ]; then _warn "需要域名"; return 1; fi
  CERT="/etc/letsencrypt/live/${domain}/cert.pem"
  CHAIN="/etc/letsencrypt/live/${domain}/chain.pem"
  if [ ! -f "$CERT" ] || [ ! -f "$CHAIN" ]; then _warn "未找到证书/链: $CERT $CHAIN"; return 1; fi
  OUTDIR="/etc/letsencrypt/ocsp/${domain}"
  run_or_echo mkdir -p "$OUTDIR"
  # use openssl to get OCSP response
  OCSP_URL=$(openssl x509 -noout -ocsp_uri -in "$CERT")
  if [ -z "$OCSP_URL" ]; then _warn "未从 cert 读取到 OCSP URI"; return 1; fi
  # generate ocsp request and fetch response
  run_or_echo openssl ocsp -issuer "$CHAIN" -cert "$CERT" -url "$OCSP_URL" -respout "${OUTDIR}/${domain}.ocsp.resp" || _warn "openssl ocsp 获取失败"
  _ok "OCSP response 写入 ${OUTDIR}/${domain}.ocsp.resp （如成功）"
}

# ---------------- finalize / summary / rollback info ----------------
run_or_echo mkdir -p "$BACKUP_DIR"
# copy important backups list if exist
[ -f "$TMP_SYSCTL" ] && run_or_echo cp -a "$TMP_SYSCTL" "${BACKUP_DIR}/sysctl.generated.${TS}"

cat >> "$ROLLBACK" <<EOF
# additional manual rollback hints:
# - restore any moved /etc/sysctl.d/*.disabled_by_optimizer.* files by moving them back
# - restore /etc/resolv.conf from backup in ${BACKUP_DIR} if needed
EOF

run_or_echo chmod +x "$ROLLBACK"
_ok "回滚脚本已生成: $ROLLBACK"
_note "==== RESULT ===="
_note "最终使用值 -> 内存: ${MEM_G} GiB, 带宽: ${BW_Mbps} Mbps, RTT: ${RTT_MS} ms (source=${RTT_SOURCE})"
sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true
sysctl -n net.core.default_qdisc 2>/dev/null || true
sysctl -n net.core.rmem_max 2>/dev/null || true
sysctl -n net.core.wmem_max 2>/dev/null || true
sysctl -n net.ipv4.tcp_rmem 2>/dev/null || true
sysctl -n net.ipv4.tcp_wmem 2>/dev/null || true
if has tc && [ -n "$IFACE" ]; then
  echo "qdisc on ${IFACE}:"; tc qdisc show dev "$IFACE" || true
fi
_note "Backups & rollback in: $BACKUP_DIR"
_note "若要回滚: sudo $ROLLBACK"
_note "完成。"

exit 0
