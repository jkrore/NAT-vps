#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ---------------- CLI ----------------
APPLY=0            # 0=dry-run, 1=apply
MODE="normal"      # normal|aggressive
FORCE_RTT=""       # override rtt ms
INSTALL_SERVICE=0
RUN_IPERF=0
IPERF_SERVERS=()
QUIET=0
ROLLBACK_DIR=""

usage(){
  cat <<EOF
Usage:
  --dry-run               Preview only (default)
  --apply                 Apply changes (write)
  --mode normal|aggressive
  --rtt <ms>              Force RTT value (ms)
  --iperf ip,ip2          Enable iperf hook
  --install-service       Install systemd service+timer (optional)
  --rollback <backupdir>  Run rollback from given backup dir (will prompt)
  -q --quiet              Reduce output
  -h --help
EOF
  exit 1
}



# 生成前 n 个 CPU 的 cpumask（hex），例如 n=1 -> 1, n=2 -> 3, n=8 -> ff
# 返回不带0x前缀的小写十六进制字符串，兼容写入 rps/xps sysfs
# 生成前 n 个 CPU 的 cpumask（hex），例如 n=1 -> 1, n=2 -> 3, n=8 -> ff
# 返回不带0x前缀的小写十六进制字符串
cpu_mask_for_cores(){
  local n=$(to_pos_int "$1")
  if [ "$n" -le 0 ]; then printf "1"; return; fi
  # cap to 63 bits to avoid arithmetic overflow in bash
  if [ "$n" -gt 63 ]; then n=63; fi
  # compute (1<<n)-1
  local mask=$(( (1 << n) - 1 ))
  printf '%x' "$mask"
}

# 返回三个数中的最小值（整数安全）
min3(){
  local a=${1:-0} b=${2:-0} c=${3:-0}
  # 保证为整数（去掉非数字）
  a=$(echo "$a" | tr -cd '0-9')
  b=$(echo "$b" | tr -cd '0-9')
  c=$(echo "$c" | tr -cd '0-9')
  [ -z "$a" ] && a=0
  [ -z "$b" ] && b=0
  [ -z "$c" ] && c=0
  if (( b < a )); then a=$b; fi
  if (( c < a )); then a=$c; fi
  printf "%s" "$a"
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) APPLY=0; shift;;
    --apply) APPLY=1; shift;;
    --mode) MODE="${2:-}"; shift 2;;
    --rtt) FORCE_RTT="${2:-}"; shift 2;;
    --iperf) IFS=',' read -r -a IPERF_SERVERS <<< "${2:-}"; RUN_IPERF=1; shift 2;;
    --install-service) INSTALL_SERVICE=1; shift;;
    --rollback) ROLLBACK_DIR="${2:-}"; shift 2;;
    -q|--quiet) QUIET=1; shift;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

_note(){ [ "$QUIET" -eq 0 ] && printf "\033[1;34m[i]\033[0m %s\n" "$*"; }
_ok(){ [ "$QUIET" -eq 0 ] && printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
_warn(){ printf "\033[1;33m[!]\033[0m %s\n" "$*" >&2; }
_err(){ printf "\033[1;31m[!!]\033[0m %s\n" "$*" >&2; }

require_root(){ if [ "$(id -u)" -ne 0 ]; then _err "请以 root 运行"; exit 2; fi; }
require_root

# ---------------- housekeeping ----------------
TIMESTAMP="$(date +%F-%H%M%S)"
BACKUP_ROOT="/var/backups/net-optimizer"
BACKUP_DIR="${BACKUP_ROOT}/net-optimizer-${TIMESTAMP}"
SYSCTL_TARGET="/etc/sysctl.d/999-net-optimizer.conf"
DEFAULT_BW_Mbps=1000
DEFAULT_RTT_MS=150

mkdir -p "$BACKUP_DIR"

# ---------------- temp file tracking & cleanup ----------------
TMPFILES=()
track_tmp(){ TMPFILES+=("$1"); }
cleanup_tmp(){
  for f in "${TMPFILES[@]:-}"; do
    [ -e "$f" ] && rm -f "$f" || true
  done
}
trap cleanup_tmp EXIT


# ---------------- utilities ----------------
has(){ command -v "$1" >/dev/null 2>&1; }
timestamp(){ date +%F-%H%M%S; }

# strictly extract integer (digits only), optional fallback
to_int(){ local s="${1:-}"; s="$(printf '%s' "$s" | tr -cd '0-9')"; echo "${s:-0}"; }
to_pos_int(){ local s; s=$(to_int "$1"); [ "$s" -lt 0 ] && s=0; echo "$s"; }

# safe float to formatted string (for display)
fmt_mb(){ awk -v b="$1" 'BEGIN{printf "%.2f", b/1024/1024}'; }

# safe write to sysfs
write_sysfs_value(){
  local path="$1"; local val="$2"
  if [ ! -e "$path" ]; then _warn "sysfs not found: $path"; return 1; fi
  if [ ! -w "$path" ]; then _warn "sysfs not writable: $path"; return 2; fi
  printf '%s' "$val" > "$path" || { _warn "写入 $path 失败"; return 3; }
  return 0
}

# ---------------- RTT detection ----------------
get_ssh_client_ip(){
  if [ -n "${SSH_CONNECTION:-}" ]; then echo "$SSH_CONNECTION" | awk '{print $1}'; return 0; fi
  if [ -n "${SSH_CLIENT:-}" ]; then echo "$SSH_CLIENT" | awk '{print $1}'; return 0; fi
  return 1
}
detect_rtt_ms(){
  local target="$1" tmp out int_out
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
    int_out=$(printf "%.0f" "$out")
    # If rtt < 5ms treat as suspicious (your suggestion)
    if [ "$int_out" -lt 5 ]; then
      _warn "检测到的 RTT (${int_out} ms) 过低，可能不准确，忽略此测量"
      echo ""
    else
      echo "$int_out"
    fi
  else
    echo ""
  fi
}

# ---------------- environment detection ----------------
MEM_GIB=$(awk '/MemTotal/ {printf "%.2f", $2/1024/1024; exit}' /proc/meminfo)
CPU_CORES=$(to_pos_int "$(nproc 2>/dev/null || echo 1)")
BW_Mbps="$DEFAULT_BW_Mbps"
RTT_MS=""

# user forced RTT?
if [ -n "$FORCE_RTT" ]; then
  if [[ "$FORCE_RTT" =~ ^[0-9]+$ ]]; then RTT_MS="$FORCE_RTT"; _note "手动指定 RTT=${RTT_MS} ms"; else _warn "无效 --rtt，忽略"; fi
fi

# try SSH client IP
if [ -z "$RTT_MS" ] && sship="$(get_ssh_client_ip 2>/dev/null || true)"; then
  if [ -n "$sship" ]; then
    _note "自动从 SSH 检测到客户端 IP: $sship，尝试 ping RTT"
    r="$(detect_rtt_ms "$sship" || true)"
    if [ -n "$r" ]; then RTT_MS="$r"; _ok "检测 RTT=${RTT_MS} ms (来自 SSH 客户端 $sship)"; else _warn "对 SSH 客户端 ping 失败或不可信"; fi
  fi
fi

if [ -z "$RTT_MS" ]; then
  _note "回退到公共地址 1.1.1.1 进行 RTT 检测"
  r="$(detect_rtt_ms 1.1.1.1 || true)"
  if [ -n "$r" ]; then RTT_MS="$r"; _ok "检测 RTT=${RTT_MS} ms (1.1.1.1)"; else _warn "无法检测 RTT，使用默认 ${DEFAULT_RTT_MS} ms"; RTT_MS="$DEFAULT_RTT_MS"; fi
fi

_note "系统概览: MEM=${MEM_GIB} GiB, CPU=${CPU_CORES} cores, BW=${BW_Mbps} Mbps, RTT=${RTT_MS} ms"

# ---------------- BDP & bucketization ----------------
BDP_BYTES=$(awk -v bw="$BW_Mbps" -v rtt="$RTT_MS" 'BEGIN{printf "%.0f", bw*125*rtt}')
BDP_MB=$(fmt_mb "$BDP_BYTES")
MEM_BYTES=$(awk -v g="$MEM_GIB" 'BEGIN{printf "%.0f", g*1024*1024*1024}')
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
if [ "$MAX_MB" -ge 32 ]; then DEF_R=262144; DEF_W=524288
elif [ "$MAX_MB" -ge 8 ]; then DEF_R=131072; DEF_W=262144
else DEF_R=87380; DEF_W=131072; fi

TCP_RMEM_MIN=4096; TCP_RMEM_DEF=87380; TCP_RMEM_MAX=$MAX_BYTES
TCP_WMEM_MIN=4096; TCP_WMEM_DEF=65536; TCP_WMEM_MAX=$MAX_BYTES

_note "BDP=${BDP_BYTES} bytes (~${BDP_MB} MB) -> cap ${MAX_MB} MB"

# ---------------- backups & rollback scaffold ----------------
ROLLBACK="${BACKUP_DIR}/rollback.sh"
run_or_echo(){ if [ "$APPLY" -eq 1 ]; then eval "$@"; else _note "DRY-RUN: $*"; fi }
run_or_echo mkdir -p "$BACKUP_DIR"
cat > "$ROLLBACK" <<'EOF'
#!/usr/bin/env bash
# rollback helper (generated)
set -euo pipefail
echo "[ROLLBACK] 请手动检查备份并按需恢复"
EOF
run_or_echo chmod +x "$ROLLBACK"
_ok "备份目录: $BACKUP_DIR"

# ---------------- conflict cleaning ----------------
KEY_REGEX='^(net\.core\.default_qdisc|net\.core\.rmem_max|net\.core\.wmem_max|net\.core\.rmem_default|net\.core\.wmem_default|net\.ipv4\.tcp_rmem|net\.ipv4\.tcp_wmem|net\.ipv4\.tcp_congestion_control)[[:space:]]*='

comment_conflicts_in_sysctl_conf(){
  local f="/etc/sysctl.conf"
  [ -f "$f" ] || { _ok "/etc/sysctl.conf 不存在"; return; }
  if grep -Eq "$KEY_REGEX" "$f"; then
    run_or_echo cp -a "$f" "${BACKUP_DIR}/sysctl.conf.bak.${TIMESTAMP}"
    awk -v re="$KEY_REGEX" '$0 ~ re && $0 !~ /^[[:space:]]*#/ { print "# " $0; next } { print $0 }' "$f" > "${f}.tmp.$$"
    run_or_echo install -m 0644 "${f}.tmp.$$" "$f"
    run_or_echo rm -f "${f}.tmp.$$"
    echo "cp -a \"${BACKUP_DIR}/sysctl.conf.bak.${TIMESTAMP}\" \"/etc/sysctl.conf\"" >> "$ROLLBACK"
    _ok "注释 /etc/sysctl.conf 中冲突键"
  else
    _ok "/etc/sysctl.conf 无冲突键"
  fi
}
disable_conflict_files_in_dir(){
  local dir="$1"
  [ -d "$dir" ] || { _ok "$dir 不存在"; return; }
  shopt -s nullglob
  for f in "$dir"/*.conf; do
    [ -f "$f" ] || continue
    if grep -Eq "$KEY_REGEX" "$f"; then
      dest="${f}.disabled_by_optimizer.${TIMESTAMP}"
      run_or_echo mv -- "$f" "$dest"
      echo "mv \"${dest}\" \"${f}\"" >> "$ROLLBACK"
      _note "已改名并禁用冲突文件: $f -> $dest"
    fi
  done
  shopt -u nullglob
  _ok "$dir 中冲突文件处理完毕"
}

_note "步骤A：备份并注释 /etc/sysctl.conf 的冲突键"
comment_conflicts_in_sysctl_conf
_note "步骤B：备份并改名 /etc/sysctl.d 下含冲突键的旧文件"
disable_conflict_files_in_dir "/etc/sysctl.d"
_note "步骤C：扫描其他系统目录（仅提示）"
for d in /usr/local/lib/sysctl.d /usr/lib/sysctl.d /lib/sysctl.d /run/sysctl.d; do
  if [ -d "$d" ]; then
    _warn "提示：检测到系统路径 $d（仅提示，不做修改）"
    grep -RhnE "$KEY_REGEX" "$d" 2>/dev/null || true
  else
    _ok "$d 不存在"
  fi
done

# ---------------- load bbr ----------------
if has modprobe; then run_or_echo modprobe tcp_bbr 2>/dev/null || true; _ok "尝试加载 tcp_bbr"; fi

# ---------------- generate sysctl ----------------
TMP_SYSCTL="$(mktemp)"
track_tmp "$TMP_SYSCTL"
cat > "$TMP_SYSCTL" <<EOF
# Auto-generated by net-optimizer-final2
# MEM=${MEM_GIB} GiB, BW=${BW_Mbps} Mbps, RTT=${RTT_MS} ms
# BDP: ${BDP_BYTES} bytes (~${BDP_MB} MB)
# Cap bucket: ${MAX_MB} MB

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.rmem_default = ${DEF_R}
net.core.wmem_default = ${DEF_W}
net.core.rmem_max = ${MAX_BYTES}
net.core.wmem_max = ${MAX_BYTES}
net.core.optmem_max = 262144
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 65535

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

net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
net.ipv4.udp_mem = 65536 131072 262144

vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
vm.min_free_kbytes = 65536
kernel.pid_max = 65535

net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.ip_forward = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
EOF

if [ -f "$SYSCTL_TARGET" ]; then
  run_or_echo cp -a "$SYSCTL_TARGET" "${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TIMESTAMP}"
  echo "cp -a \"${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TIMESTAMP}\" \"${SYSCTL_TARGET}\"" >> "$ROLLBACK"
  _note "备份现有 $SYSCTL_TARGET"
fi
run_or_echo install -m 0644 "$TMP_SYSCTL" "$SYSCTL_TARGET"
run_or_echo sysctl --system >/dev/null 2>&1 || _warn "sysctl --system 返回非零"
_ok "已写入并应用 sysctl（视 APPLY）"

# ---------------- NIC tuning ----------------
_note "检测网络接口"
mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|virbr|docker|br-|veth|tun|tap)' || true)
_note "候选接口: ${IFACES[*]:-none}"

tune_ethtool(){
  local ifn="$1"
  if ! has ethtool; then _warn "无 ethtool，跳过 $ifn"; return; fi
  local supports
  supports=$(ethtool -k "$ifn" 2>/dev/null || true)
  for feat in tso gso gro tx rx sg txvlan rxvlan; do
    if echo "$supports" | grep -qi "^${feat}:"; then
      run_or_echo ethtool -K "$ifn" "$feat" on 2>/dev/null || true
    fi
  done
  _ok "调整 $ifn 的 ethtool offloads（如支持）"
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
    _warn "$ifn 无 queues，跳过"
  fi
}
assign_irqs_to_cpus(){
  local ifn="$1" cores="$CPU_CORES"
  cores=$(to_pos_int "$cores")
  while read -r line; do
    irq=$(awk -F: '{print $1}' <<< "$line" | tr -d ' ')
    if echo "$line" | grep -q -E "${ifn}"; then
      if [ "$cores" -gt 0 ]; then
        idx=$(( irq % cores ))
      else
        idx=0
      fi
      mask=$(printf "%x" $((1 << idx)))
      aff="/proc/irq/${irq}/smp_affinity"
      if [ -w "$aff" ]; then
        run_or_echo bash -c "printf '%s' ${mask} > ${aff}"
      else
        _warn "不可写：$aff"
      fi
    fi
  done < /proc/interrupts
  _ok "尝试为 $ifn 分配 IRQ affinity"
}


for ifn in "${IFACES[@]:-}"; do
  _note "处理接口: $ifn"
  tune_ethtool "$ifn"
  set_rps_xps "$ifn"
  assign_irqs_to_cpus "$ifn"
done

# ---------------- CPU governor & cpuset ----------------
if has cpupower; then run_or_echo cpupower frequency-set -g performance >/dev/null 2>&1 || true
else
  if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
    for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      [ -w "$cpu" ] && run_or_echo bash -c "printf 'performance' > $cpu" || true
    done
  fi
fi
_ok "CPU governor -> performance (如支持)"

if [ -d /sys/fs/cgroup/cpuset ]; then
  NET_CPUSET="/sys/fs/cgroup/cpuset/net-opt"
  if [ ! -d "$NET_CPUSET" ]; then
    run_or_echo mkdir -p "$NET_CPUSET"
    reserved_end=$(( CPU_CORES - 1 ))
    [ "$reserved_end" -lt 0 ] && reserved_end=0
    run_or_echo bash -c "printf '0-${reserved_end}' > ${NET_CPUSET}/cpuset.cpus" || true
    run_or_echo bash -c "printf '0' > ${NET_CPUSET}/cpuset.mems" || true
    _ok "创建 cpuset: $NET_CPUSET"
  fi
fi

# ---------------- qdisc ----------------
IFACE=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true)
if has tc && [ -n "$IFACE" ]; then
  QDISC="fq"
  if [ "$MODE" = "aggressive" ]; then
    if tc qdisc add dev lo root cake 2>/dev/null; then
      tc qdisc del dev lo root 2>/dev/null || true
      QDISC="cake"
    fi
  fi
  run_or_echo tc qdisc replace dev "$IFACE" root "$QDISC" 2>/dev/null || _warn "tc qdisc replace 失败"
  _ok "qdisc on ${IFACE}: ${QDISC}"
fi

# ---------------- DNS optimize ----------------
dns_opt(){
  local DNS_LIST="1.1.1.1 8.8.8.8 9.9.9.9"
  if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -qi systemd; then
    if has resolvectl; then
      [ -n "$IFACE" ] && run_or_echo resolvectl dns "$IFACE" $DNS_LIST || true
      run_or_echo mkdir -p /etc/systemd/resolved.conf.d
      cat > /etc/systemd/resolved.conf.d/10-dns-opt.conf <<'EOF'
[Resolve]
DNS=1.1.1.1 8.8.8.8 9.9.9.9
DNSSEC=allow-downgrade
Cache=yes
ReadEtcHosts=yes
EOF
      run_or_echo systemctl restart systemd-resolved || true
      run_or_echo cp -a /etc/systemd/resolved.conf.d/10-dns-opt.conf "${BACKUP_DIR}/10-dns-opt.conf.bak.${TIMESTAMP}" || true
      echo "cp -a \"${BACKUP_DIR}/10-dns-opt.conf.bak.${TIMESTAMP}\" \"/etc/systemd/resolved.conf.d/10-dns-opt.conf\"" >> "$ROLLBACK"
      _ok "写入 systemd-resolved drop-in"
    fi
  else
    if [ -f /etc/resolv.conf ]; then
      run_or_echo cp -a /etc/resolv.conf "${BACKUP_DIR}/resolv.conf.bak.${TIMESTAMP}"
      run_or_echo bash -c 'cat > /etc/resolv.conf <<EOF
nameserver 1.1.1.1
nameserver 8.8.8.8
options single-request-reopen timeout:2 attempts:2 rotate
EOF'
      echo "cp -a \"${BACKUP_DIR}/resolv.conf.bak.${TIMESTAMP}\" \"/etc/resolv.conf\"" >> "$ROLLBACK"
      _ok "备份并写入 /etc/resolv.conf"
    fi
  fi
}
dns_opt

# ---------------- iperf hook ----------------
iperf_hook(){
  if [ "$RUN_IPERF" -eq 0 ] || ! has iperf3; then return; fi
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
    else
      _warn "iperf3 -> $s 测试失败"
    fi
    rm -f /tmp/.iperf.json || true
  done
}
iperf_hook

# ---------------- runtime adaptive ----------------
runtime_adaptive(){
  local MON_LOG="${BACKUP_DIR}/runtime_monitor.log"
  touch "$MON_LOG"
  local total_retrans=0 total_segs_out=0
  total_retrans=0; total_segs_out=0
  if has ss; then
    while IFS= read -r line; do
      r=$(echo "$line" | grep -Po 'retrans:\d+/\K\d+' || echo 0)
      s=$(echo "$line" | grep -Po 'segs_out:\K\d+' || echo 0)
      r=${r:-0}; s=${s:-0}
      total_retrans=$(( total_retrans + r ))
      total_segs_out=$(( total_segs_out + s ))
    done < <(ss -tin 2>/dev/null || true)
  fi
  local retrans_pct="0"
  if [ "$total_segs_out" -gt 0 ]; then
    retrans_pct=$(awk -v r="$total_retrans" -v s="$total_segs_out" 'BEGIN{ if(s==0) print 0; else printf "%.2f", r/s*100 }')
  fi

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

  local total_mbps=0; total_mbps=0
  for ifn in "${IFACES[@]:-}"; do
    rxd=$(( (rx2[$ifn] - rx1[$ifn]) )); txd=$(( (tx2[$ifn] - tx1[$ifn]) ))
    rxd=${rxd:-0}; txd=${txd:-0}
    mbps=$(( (rxd + txd) * 8 / 1000000 ))
    total_mbps=$(( total_mbps + mbps ))
  done
  _note "runtime metrics: total_mbps=${total_mbps}Mbps retrans_pct=${retrans_pct}%"

  cur_rmax=$(sysctl -n net.core.rmem_max 2>/dev/null || echo "$MAX_BYTES")
  cur_wmax=$(sysctl -n net.core.wmem_max 2>/dev/null || echo "$MAX_BYTES")
  cur_rmax=$(to_pos_int "$cur_rmax"); cur_wmax=$(to_pos_int "$cur_wmax")
  local change=0 new_rmax="$cur_rmax" new_wmax="$cur_wmax"

  if awk -v r="$retrans_pct" 'BEGIN{exit !(r>2)}'; then
    new_rmax=$(( cur_rmax * 9 / 10 ))
    new_wmax=$(( cur_wmax * 9 / 10 ))
    change=1
    _note "检测高重传 (${retrans_pct}%)，降低 r/w max 10% -> ${new_rmax}"
  else
    util_pct=$(awk -v t="$total_mbps" -v b="$BW_Mbps" 'BEGIN{ if(b==0) print 0; else printf "%.2f", t/b*100 }')
    if awk -v u="$util_pct" 'BEGIN{exit !(u<30)}'; then
      new_rmax=$(( cur_rmax * 11 / 10 )); new_wmax=$(( cur_wmax * 11 / 10 ))
      [ "$new_rmax" -gt "$MAX_BYTES" ] && new_rmax="$MAX_BYTES"
      [ "$new_wmax" -gt "$MAX_BYTES" ] && new_wmax="$MAX_BYTES"
      change=1
      _note "利用率低 (${util_pct}%), 小幅提升 r/w max -> ${new_rmax}"
    fi
  fi

  if [ "$change" -eq 1 ]; then
    tmpf="$(mktemp)"
track_tmp "$tmpf"
    cat > "$tmpf" <<EOF
# runtime adjusted by net-optimizer-final2 $(date -u)
net.core.rmem_max = ${new_rmax}
net.core.wmem_max = ${new_wmax}
net.ipv4.tcp_rmem = ${TCP_RMEM_MIN} ${TCP_RMEM_DEF} ${new_rmax}
net.ipv4.tcp_wmem = ${TCP_WMEM_MIN} ${TCP_WMEM_DEF} ${new_wmax}
EOF
    run_or_echo install -m 0644 "$tmpf" "$SYSCTL_TARGET"
    run_or_echo sysctl --system >/dev/null 2>&1 || _warn "sysctl --system returned non-zero"
    rm -f "$tmpf" || true
    echo "$(date +%s) adjust rmax=${new_rmax} wmax=${new_wmax} mbps=${total_mbps} retrans=${retrans_pct}" >> "${BACKUP_DIR}/runtime.log"
    _ok "runtime 调整已应用"
  else
    _note "runtime 调整：无需变更"
  fi
}
runtime_adaptive

# ---------------- aggressive GRUB edits ----------------
if [ "$MODE" = "aggressive" ]; then
  GRUB_CFG="/etc/default/grub"
  if [ -f "$GRUB_CFG" ]; then
    run_or_echo cp -a "$GRUB_CFG" "${BACKUP_DIR}/grub.default.bak.${TIMESTAMP}"
    _note "备份 GRUB -> ${BACKUP_DIR}/grub.default.bak.${TIMESTAMP}"
    cur_line=$(grep -E '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_CFG" | head -n1 || true)
    if [ -n "$cur_line" ]; then
      val=$(echo "$cur_line" | sed -E 's/^[^=]+=//' | sed -E 's/^"//' | sed -E 's/"$//')
      extra="mitigations=off noibrs noibpb nopti nospectre_v2 nospectre_v1 l1tf=off mds=off tsx=on"
      if ! echo "$val" | grep -q "mitigations=off"; then
        newval="${val} ${extra}"
        awk -v nv="$newval" 'BEGIN{FS=OFS="="} /^GRUB_CMDLINE_LINUX_DEFAULT=/{$2="\"" nv "\""} {print}' "$GRUB_CFG" > "${GRUB_CFG}.tmp.$$"
        run_or_echo install -m 0644 "${GRUB_CFG}.tmp.$$" "$GRUB_CFG"
        run_or_echo rm -f "${GRUB_CFG}.tmp.$$"
        echo "cp -a \"${BACKUP_DIR}/grub.default.bak.${TIMESTAMP}\" \"/etc/default/grub\"" >> "$ROLLBACK"
        if has update-grub; then run_or_echo update-grub >/dev/null 2>&1 || true; fi
        _ok "已修改 GRUB（激进）"
      else
        _ok "GRUB 已包含 mitigations=off，跳过"
      fi
    else
      _warn "未识别 GRUB_CMDLINE_LINUX_DEFAULT，跳过"
    fi
  fi
fi

# ---------------- OCSP helper ----------------
get_ocsp_response(){
  domain="$1"
  if [ -z "$domain" ]; then _warn "get_ocsp_response: 需域名"; return 1; fi
  CERT="/etc/letsencrypt/live/${domain}/cert.pem"
  CHAIN="/etc/letsencrypt/live/${domain}/chain.pem"
  if [ ! -f "$CERT" ] || [ ! -f "$CHAIN" ]; then _warn "未找到 cert/chain"; return 1; fi
  OUTDIR="/etc/letsencrypt/ocsp/${domain}"
  run_or_echo mkdir -p "$OUTDIR"
  OCSP_URL=$(openssl x509 -noout -ocsp_uri -in "$CERT" 2>/dev/null || true)
  if [ -z "$OCSP_URL" ]; then _warn "未找到 OCSP URI"; return 1; fi
  run_or_echo openssl ocsp -issuer "$CHAIN" -cert "$CERT" -url "$OCSP_URL" -respout "${OUTDIR}/${domain}.ocsp.resp" || _warn "openssl ocsp 获取失败"
  _ok "OCSP response 写入 ${OUTDIR}/${domain}.ocsp.resp"
}

# ---------------- finalize backups and summary ----------------
run_or_echo cp -a "$TMP_SYSCTL" "${BACKUP_DIR}/sysctl.generated.${TIMESTAMP}" || true
run_or_echo chmod +x "$ROLLBACK"
_ok "回滚脚本已生成: $ROLLBACK"

_note "==== SUMMARY ===="
_note "MEM=${MEM_GIB} GiB, CPU=${CPU_CORES}, BDP~${BDP_MB}MB -> cap ${MAX_MB}MB, RTT=${RTT_MS}ms (mode=${MODE}, apply=${APPLY})"
sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true
sysctl -n net.core.default_qdisc 2>/dev/null || true
sysctl -n net.core.rmem_max 2>/dev/null || true
sysctl -n net.core.wmem_max 2>/dev/null || true
sysctl -n net.ipv4.tcp_rmem 2>/dev/null || true
sysctl -n net.ipv4.tcp_wmem 2>/dev/null || true
if has tc && [ -n "$IFACE" ]; then echo "qdisc on ${IFACE}:"; tc qdisc show dev "$IFACE" || true; fi
_note "Backups & rollback in: $BACKUP_DIR"
_note "若要回滚: sudo $ROLLBACK"

check_bbr_versions


# ---------------- rollback invocation if requested ----------------
if [ -n "$ROLLBACK_DIR" ]; then
  if [ -x "${ROLLBACK_DIR}/rollback.sh" ]; then
    _note "执行回滚脚本: ${ROLLBACK_DIR}/rollback.sh (会提示确认)"
    if [ "$APPLY" -eq 1 ]; then
      read -r -p "确认执行回滚吗？(yes/NO): " ans
      if [ "$ans" = "yes" ]; then
        bash "${ROLLBACK_DIR}/rollback.sh"
        _ok "回滚已执行"
      else
        _note "已取消回滚"
      fi
    else
      _note "DRY-RUN：要实际回滚请加 --apply"
    fi
  else
    _err "未在 ${ROLLBACK_DIR} 找到可执行 rollback.sh"
  fi
fi
# ---------------- BBR & Kernel Version Check ----------------
check_bbr_versions(){
    _note "==== 内核与BBR版本分析 ===="
    local kernel_version
    kernel_version=$(uname -r)
    _note "当前内核版本: ${kernel_version}"

    local available_cc
    available_cc=$(sysctl net.ipv4.tcp_available_congestion_control | awk -F'= ' '{print $2}')
    _note "可用拥塞控制算法: ${available_cc}"

    if [[ "$available_cc" == *"bbr"* ]]; then
        _ok "系统支持 BBR。脚本已默认启用。"
        # 简单的版本比较
        if [[ "$(printf '%s\n' "5.18" "$kernel_version" | sort -V | head -n1)" == "5.18" ]]; then
            _note "提示: 您的内核版本较新，可能已包含 BBRv2 的部分特性。社区中有通过更换内核（如xanmod）以启用完整 BBRv2/v3 的讨论，但这属于高风险操作，请自行研究。"
        else
            _warn "提示: 您的内核版本较低。升级内核可能会带来更新的BBR算法和性能改进，但存在风险。"
        fi
    else
        _err "错误: 系统不支持 BBR。此脚本的核心优化无法生效。"
    fi
}
exit 0
