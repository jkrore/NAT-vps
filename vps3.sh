#!/usr/bin/env bash
#
# nat-vps-final.sh
# NAT-VPS 终极优化套件 — 中文交互版（合并 vps1 + vps2 功能）
# 默认：DRY-RUN（仅预览）。使用 --apply 才会真正修改系统。
#
set -euo pipefail
IFS=$'\n\t'

# ---------------- CLI ----------------
DRY_RUN=1
MODE="normal"          # normal|aggressive
FORCE_RTT=""
RUN_IPERF=0
IPERF_SERVERS=()
QUIET=0
APPLY_IO_LIMITS=0
CLEANUP_SERVICES=0
APPLY_GRUB=0
APPLY_HOST_SPECIFICS=0
GENERATE_TOOLS=0
INSTALL_HW_TUNING=0

BACKUP_ROOT="/var/backups/nat-vps"
TIMESTAMP="$(date +%F-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/nat-vps-${TIMESTAMP}"
SYSCTL_TARGET="/etc/sysctl.d/999-net-optimizer.conf"

usage(){
  cat <<'USAGE'
用法: sudo ./nat-vps-final.sh [选项]

选项:
  --dry-run           (默认) 只预览，不做任何修改
  --apply             实际应用更改
  --mode normal|aggressive
  --rtt <ms>          指定 RTT(ms) 用于 BDP 计算
  --iperf ip,ip2      iperf3 测试节点（逗号分隔）
  --apply-io-limits   应用 I/O 与 limits
  --cleanup-services  禁用常见非必要服务（高风险）
  --apply-grub        应用 GRUB 激进项（仅 Host）
  --apply-host-specifics 应用 Host 专用优化（大页等）
  --generate-tools    生成监控/基准脚本
  --install-hw-tuning 安装硬件动态调优定时器
  -q|--quiet          减少输出
  -h|--help
USAGE
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift;;
    --apply) DRY_RUN=0; shift;;
    --mode) MODE="${2:-}"; shift 2;;
    --rtt) FORCE_RTT="${2:-}"; shift 2;;
    --iperf) IFS=',' read -r -a IPERF_SERVERS <<< "${2:-}"; RUN_IPERF=1; shift 2;;
    --apply-io-limits) APPLY_IO_LIMITS=1; shift;;
    --cleanup-services) CLEANUP_SERVICES=1; shift;;
    --apply-grub) APPLY_GRUB=1; shift;;
    --apply-host-specifics) APPLY_HOST_SPECIFICS=1; shift;;
    --generate-tools) GENERATE_TOOLS=1; shift;;
    --install-hw-tuning) INSTALL_HW_TUNING=1; shift;;
    -q|--quiet) QUIET=1; shift;;
    -h|--help) usage;;
    *) echo "未知参数: $1"; usage;;
  esac
done

# ---------------- output helpers ----------------
_info(){ [ "$QUIET" -eq 0 ] && printf "\033[1;34m[i]\033[0m %s\n" "$*"; }
_ok(){ [ "$QUIET" -eq 0 ] && printf "\033[1;32m[✔]\033[0m %s\n" "$*"; }
_warn(){ printf "\033[1;33m[!]\033[0m %s\n" "$*" >&2; }
_err(){ printf "\033[1;31m[✖]\033[0m %s\n" "$*" >&2; }

require_root(){ if [ "$(id -u)" -ne 0 ]; then _err "请以 root 运行"; exit 2; fi; }
require_root

mkdir -p "$BACKUP_DIR"

# ---------------- helpers ----------------
command_exists(){ command -v "$1" >/dev/null 2>&1; }

run_or_note(){
  if [ "$DRY_RUN" -eq 1 ]; then
    _info "（预览）将执行： $*"
  else
    _info "执行： $*"
    eval "$@"
  fi
}

backup_file(){
  local f="$1"
  [ -e "$f" ] || return 0
  mkdir -p "$BACKUP_DIR"
  cp -a "$f" "${BACKUP_DIR}/$(basename "$f").bak.${TIMESTAMP}" || true
  echo "cp -a \"${BACKUP_DIR}/$(basename "$f").bak.${TIMESTAMP}\" \"${f}\"" >> "${BACKUP_DIR}/rollback.sh"
}

write_file_atomic(){
  local path="$1"; shift
  local content="$*"
  backup_file "$path"
  if [ "$DRY_RUN" -eq 1 ]; then
    _info "（预览）将写入： $path"
  else
    mkdir -p "$(dirname "$path")"
    local tmp; tmp="$(mktemp)"
    printf '%s' "$content" > "$tmp"
    install -m 0644 "$tmp" "$path"
    rm -f "$tmp"
  fi
}

append_unique(){
  local file="$1"; shift; local line="$*"
  backup_file "$file"
  if [ "$DRY_RUN" -eq 1 ]; then
    if [ -f "$file" ] && grep -Fxq -- "$line" "$file"; then
      _info "（预览）$file 已包含该行"
    else
      _info "（预览）将追加到 $file: $line"
    fi
  else
    mkdir -p "$(dirname "$file")"
    touch "$file"
    if ! grep -Fxq -- "$line" "$file"; then
      echo "$line" >> "$file" || true
    fi
  fi
}

# 回滚脚本骨架
cat > "${BACKUP_DIR}/rollback.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[回滚提示] 查看同目录备份文件并按需手动恢复（脚本记录了操作记录）。"
EOF
chmod +x "${BACKUP_DIR}/rollback.sh" || true

# ---------------- env detect ----------------
detect_env(){
  [[ -f /etc/os-release ]] && source /etc/os-release || true
  ROLE="guest"
  CPU_COUNT=$(nproc 2>/dev/null || echo 1)
  TOTAL_MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
  VIRT_TYPE=$(command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt || echo none)
  if sysctl -n net.ipv4.ip_forward 2>/dev/null | grep -q 1; then ROLE="nat"; fi
  [[ -e /dev/kvm || $(lsmod 2>/dev/null | grep -q kvm; echo $?) -eq 0 ]] && HAS_KVM=true || HAS_KVM=false
  if [[ "$VIRT_TYPE" == "none" && "$HAS_KVM" == true && "$TOTAL_MEM_MB" -ge 4096 ]]; then ROLE="host"; fi
  _info "检测到: role=${ROLE}, CPU=${CPU_COUNT}, 内存=${TOTAL_MEM_MB}MB, virt=${VIRT_TYPE}"
}
detect_env

# ---------------- utilities ----------------
cpu_mask_for_cores(){
  local n=$(printf '%s' "${1:-0}" | tr -cd '0-9')
  [ -z "$n" ] && { printf "1"; return; }
  if [ "$n" -gt 63 ]; then n=63; fi
  awk -v n="$n" 'BEGIN{m=0; for(i=0;i<n;i++) m+=2^i; printf "%x\n", m}'
}

min3(){
  local a=${1:-0} b=${2:-0} c=${3:-0}
  a=$(printf '%s' "$a" | tr -cd '0-9'); b=$(printf '%s' "$b" | tr -cd '0-9'); c=$(printf '%s' "$c" | tr -cd '0-9')
  [ -z "$a" ] && a=0; [ -z "$b" ] && b=0; [ -z "$c" ] && c=0
  local m=$a
  if [ "$b" -lt "$m" ]; then m=$b; fi
  if [ "$c" -lt "$m" ]; then m=$c; fi
  printf "%s" "$m"
}

detect_rtt_ms(){
  local target="$1"
  local tmp; tmp="$(mktemp)"; ping -c 4 -W 2 "$target" >"$tmp" 2>/dev/null || true
  local out
  out=$(awk -F'/' '/rtt|round-trip/ {print $5; exit}' "$tmp" || true)
  if [ -z "$out" ]; then out=$(grep -Eo '[0-9]+(\.[0-9]+)?/([0-9]+(\.[0-9]+)?)' "$tmp" | head -n1 | awk -F'/' '{print $2}' || true); fi
  rm -f "$tmp"
  if [[ "$out" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    local int_out; int_out=$(printf "%.0f" "$out")
    if [ "$int_out" -lt 5 ]; then
      _warn "检测到 RTT ${int_out}ms 过低，忽略"
      echo ""
    else
      echo "$int_out"
    fi
  else
    echo ""
  fi
}

# ---------------- 冲突文件处理（来源 vps2） ----------------
KEY_REGEX='^(net\.core\.default_qdisc|net\.core\.rmem_max|net\.core\.wmem_max|net\.core\.rmem_default|net\.core\.wmem_default|net\.ipv4\.tcp_rmem|net\.ipv4\.tcp_wmem|net\.ipv4\.tcp_congestion_control)[[:space:]]*='

comment_conflicts_in_sysctl_conf(){
  local f="/etc/sysctl.conf"
  [ -f "$f" ] || { _info "/etc/sysctl.conf 不存在"; return; }
  if grep -Eq "$KEY_REGEX" "$f"; then
    run_or_note "cp -a \"$f\" \"${BACKUP_DIR}/sysctl.conf.bak.${TIMESTAMP}\""
    awk -v re="$KEY_REGEX" '$0 ~ re && $0 !~ /^[[:space:]]*#/ { print "# " $0; next } { print $0 }' "$f" > "${f}.tmp.$$"
    run_or_note "install -m 0644 \"${f}.tmp.$$\" \"$f\""
    run_or_note "rm -f \"${f}.tmp.$$\""
    echo "cp -a \"${BACKUP_DIR}/sysctl.conf.bak.${TIMESTAMP}\" \"/etc/sysctl.conf\"" >> "$BACKUP_DIR/rollback.sh"
    _ok "已注释 /etc/sysctl.conf 中可能冲突的键"
  else
    _info "/etc/sysctl.conf 无冲突键"
  fi
}

disable_conflict_files_in_dir(){
  local dir="$1"
  [ -d "$dir" ] || { _info "$dir 不存在"; return; }
  shopt -s nullglob
  for f in "$dir"/*.conf; do
    [ -f "$f" ] || continue
    if grep -Eq "$KEY_REGEX" "$f"; then
      dest="${f}.disabled_by_optimizer.${TIMESTAMP}"
      if [ "$DRY_RUN" -eq 1 ]; then
        _info "（预览）会把 $f 改名为 $dest"
      else
        mv -- "$f" "$dest"
      fi
      echo "mv \"${dest}\" \"${f}\"" >> "$BACKUP_DIR/rollback.sh"
      _info "禁用冲突文件: $f"
    fi
  done
  shopt -u nullglob
  _ok "$dir 中冲突文件处理完毕"
}

# ---------------- 运行时自适应（来自 vps2） ----------------
runtime_adaptive(){
  _info "运行时自适应：短期监测并根据重传率/利用率调整 r/w max"
  # 仅在 apply 模式下做持久改变
  if [ "$DRY_RUN" -eq 1 ]; then
    _info "（预览）运行时自适应会读取 ss 和 /proc/net/dev 并按需调整 sysctl"
    return
  fi

  total_retrans=0; total_segs_out=0
  if command_exists ss; then
    while IFS= read -r line; do
      r=$(echo "$line" | grep -Po 'retrans:\d+/\K\d+' || echo 0)
      s=$(echo "$line" | grep -Po 'segs_out:\K\d+' || echo 0)
      r=${r:-0}; s=${s:-0}
      total_retrans=$(( total_retrans + r ))
      total_segs_out=$(( total_segs_out + s ))
    done < <(ss -tin 2>/dev/null || true)
  fi
  retrans_pct="0"
  if [ "$total_segs_out" -gt 0 ]; then
    retrans_pct=$(awk -v r="$total_retrans" -v s="$total_segs_out" 'BEGIN{ if(s==0) print 0; else printf "%.2f", r/s*100 }')
  fi

  # 流量采样
  mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|virbr|docker|br-|veth|tun|tap)' || true)
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

  total_mbps=0
  for ifn in "${IFACES[@]:-}"; do
    rxd=$(( (rx2[$ifn] - rx1[$ifn]) )); txd=$(( (tx2[$ifn] - tx1[$ifn]) ))
    rxd=${rxd:-0}; txd=${txd:-0}
    mbps=$(( (rxd + txd) * 8 / 1000000 ))
    total_mbps=$(( total_mbps + mbps ))
  done

  _info "采样结果: total_mbps=${total_mbps}Mbps retrans_pct=${retrans_pct}%"

  cur_rmax=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
  cur_wmax=$(sysctl -n net.core.wmem_max 2>/dev/null || echo 0)
  cur_rmax=$(printf '%s' "$cur_rmax" | tr -cd '0-9'); cur_wmax=$(printf '%s' "$cur_wmax" | tr -cd '0-9')
  change=0; new_rmax="$cur_rmax"; new_wmax="$cur_wmax"

  if awk -v r="$retrans_pct" 'BEGIN{exit !(r>2)}'; then
    new_rmax=$(( cur_rmax * 9 / 10 ))
    new_wmax=$(( cur_wmax * 9 / 10 ))
    change=1
    _info "检测到重传 >2%，将 r/w max 降低 10% -> ${new_rmax}"
  else
    util_pct=$(awk -v t="$total_mbps" -v b="1000" 'BEGIN{ if(b==0) print 0; else printf "%.2f", t/b*100 }')
    if awk -v u="$util_pct" 'BEGIN{exit !(u<30)}'; then
      new_rmax=$(( cur_rmax * 11 / 10 )); new_wmax=$(( cur_wmax * 11 / 10 ))
      change=1
      _info "链路利用率低 (${util_pct}%)，小幅提升 r/w max -> ${new_rmax}"
    fi
  fi

  if [ "$change" -eq 1 ]; then
    tmpf="$(mktemp)"
    cat > "$tmpf" <<EOF
# runtime adjusted by nat-vps-final $(date -u)
net.core.rmem_max = ${new_rmax}
net.core.wmem_max = ${new_wmax}
net.ipv4.tcp_rmem = 4096 87380 ${new_rmax}
net.ipv4.tcp_wmem = 4096 65536 ${new_wmax}
EOF
    install -m 0644 "$tmpf" "$SYSCTL_TARGET"
    sysctl --system >/dev/null 2>&1 || _warn "sysctl --system returned non-zero"
    rm -f "$tmpf" || true
    echo "$(date +%s) adjust rmax=${new_rmax} wmax=${new_wmax} mbps=${total_mbps} retrans=${retrans_pct}" >> "${BACKUP_DIR}/runtime.log"
    _ok "运行时自适应已应用"
  else
    _info "运行时自适应：无需调整"
  fi
}

# ---------------- 模块：网络优化（合并 vps2） ----------------
network_module(){
  _info "网络模块：BDP/sysctl/BBR/qdisc/ethtool/RPS/IRQ/cpuset/conntrack/DNS"
  if [ "$DRY_RUN" -eq 1 ]; then
    read -r -p "是否继续网络优化？[Y/n] (回车默认是): " yn; yn=${yn:-y}
  else
    read -r -p "是否继续网络优化？[Y/n] (回车默认是): " yn; yn=${yn:-y}
  fi
  case "$yn" in [Nn]*) _info "跳过网络模块"; return;; esac

  # RTT
  RTT_MS=""
  if [ -n "$FORCE_RTT" ] && [[ "$FORCE_RTT" =~ ^[0-9]+$ ]]; then RTT_MS="$FORCE_RTT"; _info "使用手动 RTT=${RTT_MS}ms"; fi
  if [ -z "$RTT_MS" ]; then
    if [ -n "${SSH_CONNECTION:-}" ]; then sship=$(echo "$SSH_CONNECTION" | awk '{print $1}') || true; fi
    if [ -n "${sship:-}" ]; then
      _info "尝试通过 SSH 客户端检测 RTT ($sship)..."
      r="$(detect_rtt_ms "$sship" || true)"
      if [ -n "$r" ]; then RTT_MS="$r"; _ok "检测 RTT=${RTT_MS}ms"; fi
    fi
  fi
  if [ -z "$RTT_MS" ]; then
    _info "回退到 ping 1.1.1.1 检测 RTT ..."
    r="$(detect_rtt_ms 1.1.1.1 || true)"
    if [ -n "$r" ]; then RTT_MS="$r"; _ok "检测 RTT=${RTT_MS}ms (1.1.1.1)"; else RTT_MS=150; _warn "无法检测 RTT，使用默认 ${RTT_MS}ms"; fi
  fi

  DEFAULT_BW_Mbps=1000
  BW_Mbps="$DEFAULT_BW_Mbps"
  MEM_GIB=$(awk '/MemTotal/ {printf "%.2f", $2/1024/1024; exit}' /proc/meminfo)
  CPU_CORES=$(nproc 2>/dev/null || echo 1)
  BDP_BYTES=$(awk -v bw="$BW_Mbps" -v rtt="$RTT_MS" 'BEGIN{printf "%.0f", bw*125*rtt}')
  BDP_MB=$(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}')
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

  _info "BDP=${BDP_BYTES} bytes (~${BDP_MB} MB) -> cap ${MAX_MB} MB"

  # 生成 sysctl 临时文件
  TMP_SYSCTL="$(mktemp)"
  cat > "$TMP_SYSCTL" <<EOF
# Auto-generated by nat-vps-final ${TIMESTAMP}
# MEM=${MEM_GIB} GiB, BW=${BW_Mbps} Mbps, RTT=${RTT_MS} ms
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.rmem_default = ${DEF_R}
net.core.wmem_default = ${DEF_W}
net.core.rmem_max = ${MAX_BYTES}
net.core.wmem_max = ${MAX_BYTES}
net.core.optmem_max = 262144
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 65535

net.ipv4.tcp_rmem = 4096 87380 ${MAX_BYTES}
net.ipv4.tcp_wmem = 4096 65536 ${MAX_BYTES}
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

# conntrack
net.netfilter.nf_conntrack_max = 262144

# fs
fs.file-max = 2097152
EOF

  _info "将写入持久化 sysctl 到 $SYSCTL_TARGET（会先备份现有文件）"
  if [ "$DRY_RUN" -eq 1 ]; then
    _info "（预览）sysctl 文件将被写入（但未真正写入）"
  else
    backup_file "$SYSCTL_TARGET"
    install -m 0644 "$TMP_SYSCTL" "$SYSCTL_TARGET"
    sysctl --system || _warn "sysctl --system 返回非零"
    cp -a "$TMP_SYSCTL" "${BACKUP_DIR}/sysctl.generated.${TIMESTAMP}"
    echo "cp -a \"${BACKUP_DIR}/sysctl.generated.${TIMESTAMP}\" \"${SYSCTL_TARGET}\"" >> "${BACKUP_DIR}/rollback.sh"
    _ok "sysctl 写入并尝试加载"
  fi
  rm -f "$TMP_SYSCTL" || true

  # 尝试加载 bbr
  if command_exists modprobe; then
    run_or_note "modprobe tcp_bbr 2>/dev/null || true"
  fi

  # 处理冲突旧配置
  comment_conflicts_in_sysctl_conf
  disable_conflict_files_in_dir "/etc/sysctl.d"
  disable_conflict_files_in_dir "/usr/local/lib/sysctl.d"
  disable_conflict_files_in_dir "/usr/lib/sysctl.d"
  disable_conflict_files_in_dir "/lib/sysctl.d"
  disable_conflict_files_in_dir "/run/sysctl.d"

  # interfaces
  mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|virbr|docker|br-|veth|tun|tap)' || true)
  _info "候选接口: ${IFACES[*]:-none}"

  # 保存 ethtool 状态并尝试调优
  if command_exists ethtool; then
    for ifn in "${IFACES[@]:-}"; do
      outf="${BACKUP_DIR}/ethtool-${ifn}.k.${TIMESTAMP}.txt"
      if [ "$DRY_RUN" -eq 1 ]; then
        _info "（预览）会保存 ethtool -k $ifn 到 $outf"
      else
        ethtool -k "$ifn" > "$outf" 2>/dev/null || true
        _ok "保存 ethtool -k $ifn -> $outf"
      fi
    done
  fi

  tune_ethtool(){
    local ifn="$1"
    if ! command_exists ethtool; then _warn "未安装 ethtool，跳过 $ifn"; return; fi
    local supports; supports=$(ethtool -k "$ifn" 2>/dev/null || true)
    for feat in tso gso gro lro tx rx sg txvlan rxvlan; do
      if echo "$supports" | grep -qi "^${feat}:"; then
        if [ "$MODE" = "aggressive" ]; then
          run_or_note "ethtool -K $ifn $feat off 2>/dev/null || true"
        else
          if echo "$supports" | grep -qi "^${feat}: .*off"; then
            run_or_note "ethtool -K $ifn $feat on 2>/dev/null || true"
          fi
        fi
      fi
    done
  }

  set_rps_xps(){
    local ifn="$1"
    local rps_cores=$(( CPU_COUNT / 2 )); [ "$rps_cores" -lt 1 ] && rps_cores=1
    local cpumask_hex; cpumask_hex=$(cpu_mask_for_cores "$rps_cores")
    local qdir="/sys/class/net/${ifn}/queues"
    if [ -d "$qdir" ]; then
      for rxq in "$qdir"/rx-*; do
        [ -e "$rxq/rps_cpus" ] || continue
        run_or_note "printf '%s' ${cpumask_hex} > ${rxq}/rps_cpus"
      done
      for txq in "$qdir"/tx-*; do
        [ -e "$txq/xps_cpus" ] || continue
        run_or_note "printf '%s' ${cpumask_hex} > ${txq}/xps_cpus"
      done
      _ok "为 $ifn 设置 RPS/XPS (mask=${cpumask_hex})"
    else
      _warn "$ifn 无 queues，跳过"
    fi
  }

  assign_irqs(){
    local ifn="$1"
    while read -r line; do
      irq=$(awk -F: '{print $1}' <<< "$line" | tr -d ' ')
      if echo "$line" | grep -q -E "${ifn}"; then
        idx=$(( irq % CPU_COUNT ))
        mask=$(printf "%x" $((1 << idx)))
        aff="/proc/irq/${irq}/smp_affinity"
        if [ -w "$aff" ]; then
          run_or_note "printf '%s' ${mask} > ${aff}"
        else
          _warn "不可写: $aff"
        fi
      fi
    done < /proc/interrupts
    _ok "尝试为 $ifn 设置 IRQ affinity"
  }

  for ifn in "${IFACES[@]:-}"; do
    tune_ethtool "$ifn"
    set_rps_xps "$ifn"
    assign_irqs "$ifn"
  done

  # CPU governor
  if command_exists cpupower; then
    run_or_note "cpupower frequency-set -g performance >/dev/null 2>&1 || true"
  else
    if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
      for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
        [ -w "$cpu" ] && run_or_note "printf 'performance' > $cpu" || true
      done
    fi
  fi
  _ok "尝试设置 CPU governor 为 performance"

  # cpuset（非破坏性）
  if [ -d /sys/fs/cgroup/cpuset ]; then
    NET_CPUSET="/sys/fs/cgroup/cpuset/net-opt"
    if [ ! -d "$NET_CPUSET" ]; then
      run_or_note "mkdir -p ${NET_CPUSET}"
      reserved_end=$(( CPU_COUNT - 1 )); [ "$reserved_end" -lt 0 ] && reserved_end=0
      run_or_note "printf '0-${reserved_end}' > ${NET_CPUSET}/cpuset.cpus || true"
      run_or_note "printf '0' > ${NET_CPUSET}/cpuset.mems || true"
      _ok "创建 cpuset: $NET_CPUSET"
    fi
  fi

  # qdisc
  IFACE=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true)
  if command_exists tc && [ -n "$IFACE" ]; then
    QDISC="fq"
    if [ "$MODE" = "aggressive" ]; then
      if tc qdisc add dev lo root cake 2>/dev/null; then
        tc qdisc del dev lo root 2>/dev/null || true
        QDISC="cake"
      fi
    fi
    run_or_note "tc qdisc replace dev ${IFACE} root ${QDISC}"
    _ok "已在 ${IFACE} 上设置 qdisc=${QDISC}"
  fi

  # DNS 优化（可选）
  read -r -p "是否进行 DNS 快速优化？[Y/n] (回车默认是): " dnsyn; dnsyn=${dnsyn:-y}
  if [[ ! "$dnsyn" =~ ^[Nn] ]]; then
    if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -qi systemd; then
      if command_exists resolvectl; then
        run_or_note "mkdir -p /etc/systemd/resolved.conf.d"
        dropconf="/etc/systemd/resolved.conf.d/10-dns-opt.conf"
        dropcont="[Resolve]
DNS=1.1.1.1 8.8.8.8 9.9.9.9
DNSSEC=allow-downgrade
Cache=yes
ReadEtcHosts=yes
"
        write_file_atomic "$dropconf" "$dropcont"
        run_or_note "systemctl restart systemd-resolved || true"
      else
        _warn "resolvectl 不可用，跳过"
      fi
    else
      if [ -f /etc/resolv.conf ]; then
        backup_file "/etc/resolv.conf"
        run_or_note "cp -a /etc/resolv.conf ${BACKUP_DIR}/resolv.conf.bak.${TIMESTAMP} || true"
        if [ "$DRY_RUN" -eq 0 ]; then
          cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
options single-request-reopen timeout:2 attempts:2 rotate
EOF
        else
          _info "（预览）将写入 /etc/resolv.conf"
        fi
      fi
    fi
  fi

  # iperf
  if [ "$RUN_IPERF" -eq 1 ] && command_exists iperf3; then
    for s in "${IPERF_SERVERS[@]}"; do
      _info "iperf3 -> $s"
      if [ "$DRY_RUN" -eq 0 ]; then
        iperf3 -c "$s" -t 10 -J >/tmp/.iperf.json 2>/dev/null || _warn "iperf3 测试失败"
        if command_exists jq; then
          DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/.iperf.json)
          UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/.iperf.json)
          _info "DL=$(( (DL+500000)/1000000 ))Mbps UL=$(( (UL+500000)/1000000 ))Mbps"
        fi
        rm -f /tmp/.iperf.json || true
      else
        _info "（预览）将对 $s 运行 iperf3"
      fi
    done
  fi

  _ok "网络模块完成"
}

# ---------------- 模块：系统优化（合并 vps1） ----------------
system_module(){
  _info "系统模块：I/O limits、udev、HugePages（Host 专用）、生成工具、安装 hw 调优、清理服务、GRUB（Host）"
  read -r -p "是否继续系统模块？[Y/n] (回车默认是): " syn; syn=${syn:-y}
  case "$syn" in [Nn]*) _info "跳过系统模块"; return;; esac

  # I/O & limits
  if [ "$APPLY_IO_LIMITS" -eq 1 ] || { read -r -p "是否应用 I/O 与 limits 优化（提升 nofile/nproc 等）？[Y/n] (回车默认是): " yn; yn=${yn:-y}; echo "$yn" | grep -qi '^[Yy]' ; }; then
    LIMITS="/etc/security/limits.d/99-ultimate-singularity.conf"
    UDEV="/etc/udev/rules.d/60-ultimate-io.rules"
    LIMITS_CONTENT="* soft nofile 2097152
* hard nofile 2097152
root soft nofile 2097152
root hard nofile 2097152
* soft nproc unlimited
* hard nproc unlimited
"
    UDEV_CONTENT="ACTION==\"add|change\", KERNEL==\"nvme[0-9]n[0-9]\", ATTR{queue/scheduler}=\"none\", ATTR{queue/nr_requests}=\"1024\"
ACTION==\"add|change\", KERNEL==\"sd[a-z]\", ATTR{queue/rotational}==\"0\", ATTR{queue/scheduler}=\"mq-deadline\", ATTR{queue/nr_requests}=\"1024\"
"
    write_file_atomic "$LIMITS" "$LIMITS_CONTENT"
    write_file_atomic "$UDEV" "$UDEV_CONTENT"
    _ok "I/O 与 limits 模块准备完毕"
  fi

  # Host specific hugepages
  if [ "$ROLE" = "host" ] && ( [ "$APPLY_HOST_SPECIFICS" -eq 1 ] || { read -r -p "是否应用 Host 专用大页 (HugePages)？(Host 专用，需重启) [y/N]: " yn; yn=${yn:-N}; echo "$yn" | grep -qi '^[Yy]' ; } ); then
    HP_FILE="/etc/hugepages/ultimate-hugepages.conf"
    hp_count=$(( (TOTAL_MEM_MB / 200) ))
    [ "$hp_count" -lt 64 ] && hp_count=64
    [ "$hp_count" -gt 4096 ] && hp_count=4096
    write_file_atomic "$HP_FILE" "# hugepages recommendation\nnr_hugepages=${hp_count}\n"
    if [ "$DRY_RUN" -eq 0 ]; then
      if [ -w /proc/sys/vm/nr_hugepages ]; then
        printf '%s' "$hp_count" > /proc/sys/vm/nr_hugepages 2>/dev/null || _warn "写入 nr_hugepages 失败"
      else
        _warn "/proc/sys/vm/nr_hugepages 不可写"
      fi
    else
      _info "（预览）将尝试写入 ${hp_count} 到 /proc/sys/vm/nr_hugepages"
    fi
    _ok "HugePages 模块处理完成"
  fi

  # 生成工具
  if [ "$GENERATE_TOOLS" -eq 1 ] || { read -r -p "是否生成监控与基准脚本（/usr/local/bin/ultimate-monitor.sh / ultimate-bench.sh）？[Y/n] (回车默认是): " yn; yn=${yn:-y}; echo "$yn" | grep -qi '^[Yy]' ; }; then
    MON="/usr/local/bin/ultimate-monitor.sh"
    BENCH="/usr/local/bin/ultimate-bench.sh"
    MON_CONTENT='#!/usr/bin/env bash
set -euo pipefail
echo "=== Ultimate Monitor ==="
date
echo "Role: '"${ROLE}"'"
echo "CPU: $(nproc) cores"
free -h
uptime
ss -s || true
for nic in $(ls /sys/class/net | grep -v lo); do
  rx=$(cat /sys/class/net/$nic/statistics/rx_bytes 2>/dev/null || echo 0)
  tx=$(cat /sys/class/net/$nic/statistics/tx_bytes 2>/dev/null || echo 0)
  printf "%s: RX=%dMB TX=%dMB\n" "$nic" $((rx/1024/1024)) $((tx/1024/1024))
done
'
    BENCH_CONTENT='#!/usr/bin/env bash
set -euo pipefail
echo "=== Ultimate Bench ==="
date
ping -c 4 8.8.8.8 || true
if command -v dd >/dev/null 2>&1; then
  dd if=/dev/zero of=/dev/null bs=1M count=1024 2>&1 | tail -n1 || true
fi
'
    write_file_atomic "$MON" "$MON_CONTENT"
    write_file_atomic "$BENCH" "$BENCH_CONTENT"
    run_or_note "chmod +x $MON $BENCH"
    _ok "监控/基准脚本已准备"
  fi

  # HW dynamic tuning
  if [ "$INSTALL_HW_TUNING" -eq 1 ] || { read -r -p "是否安装硬件动态调优服务（定时器）？[y/N]: " yn; yn=${yn:-N}; echo "$yn" | grep -qi '^[Yy]' ; }; then
    HW_SCRIPT="/usr/local/bin/ultimate-hw-ai.sh"
    HW_CONTENT='#!/usr/bin/env bash
set -euo pipefail
IFS=$'\''\n\t'\''
CPU_COUNT=$(nproc || echo 1)
ALL_NICS=( $(ls /sys/class/net | grep -v lo || true) )
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [ -f "$gov" ] && echo performance > "$gov" 2>/dev/null || true
done
for NIC in "${ALL_NICS[@]}"; do
  [ -d "/sys/class/net/$NIC" ] || continue
  oper=$(cat /sys/class/net/$NIC/operstate 2>/dev/null || echo down)
  [ "$oper" = "up" ] || continue
  rx_old=$(cat /sys/class/net/$NIC/statistics/rx_bytes 2>/dev/null || echo 0)
  sleep 1
  rx_new=$(cat /sys/class/net/$NIC/statistics/rx_bytes 2>/dev/null || echo 0)
  rx_speed=$((rx_new - rx_old))
  rx_ring=1024
  if [ "$rx_speed" -gt 200000000 ]; then rx_ring=8192
  elif [ "$rx_speed" -gt 100000000 ]; then rx_ring=4096
  elif [ "$rx_speed" -gt 50000000 ]; then rx_ring=2048
  fi
  if command -v ethtool >/dev/null 2>&1; then
    ethtool -G "$NIC" rx "$rx_ring" tx "$rx_ring" >/dev/null 2>&1 || true
    ethtool -K "$NIC" gso off gro off tso off lro off >/dev/null 2>&1 || true
  fi
done
for dev in /sys/block/*/queue/read_ahead_kb; do
  [ -f "$dev" ] && echo 128 > "$dev" 2>/dev/null || true
done
'
    write_file_atomic "$HW_SCRIPT" "$HW_CONTENT"
    run_or_note "chmod +x $HW_SCRIPT"
    SERVICE="/etc/systemd/system/ultimate-hw-ai.service"
    TIMER="/etc/systemd/system/ultimate-hw-ai.timer"
    SVC="[Unit]
Description=Ultimate HW AI Dynamic Tuning
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ultimate-hw-ai.sh
"
    TMR="[Unit]
Description=Run Ultimate HW AI dynamic tuning periodically
[Timer]
OnBootSec=30s
OnUnitActiveSec=300s
[Install]
WantedBy=timers.target
"
    write_file_atomic "$SERVICE" "$SVC"
    write_file_atomic "$TIMER" "$TMR"
    run_or_note "systemctl daemon-reload || true"
    run_or_note "systemctl enable --now ultimate-hw-ai.timer || true"
    _ok "硬件动态调优服务已安装（定时器）"
  fi

  # Cleanup services (HIGH RISK)
  if [ "$CLEANUP_SERVICES" -eq 1 ] || { read -r -p "是否禁用一组非必要服务？（高风险，回车默认否）[y/N]: " yn; yn=${yn:-N}; echo "$yn" | grep -qi '^[Yy]' ; }; then
    services_common=(irqbalance tuned thermald bluetooth cups snapd unattended-upgrades rsyslog auditd cron)
    services_net=(firewalld ufw nftables)
    services_virt=(libvirtd virtlogd virtlockd)
    to_disable=("${services_common[@]}")
    if [ "$ROLE" != "nat" ]; then to_disable+=("${services_net[@]}"); fi
    if [ "$ROLE" != "host" ]; then to_disable+=("${services_virt[@]}"); fi
    for svc in "${to_disable[@]}"; do
      run_or_note "systemctl disable --now ${svc} >/dev/null 2>&1 || true"
    done
    _ok "已按请求尝试禁用服务（请检查）"
  fi

  # GRUB（极高风险，Host 专用）
  if [ "$ROLE" = "host" ] && ( [ "$APPLY_GRUB" -eq 1 ] || { read -r -p "是否应用激进 GRUB（CPU 隔离 + 禁用 mitigations）？仅 Host，危险，回车默认否 [y/N]: " yn; yn=${yn:-N}; echo "$yn" | grep -qi '^[Yy]' ; } ); then
    GRUB_FILE="/etc/default/grub"
    if [ -f "$GRUB_FILE" ]; then
      backup_file "$GRUB_FILE"
      iso_count=$(( CPU_COUNT / 4 )); [ "$iso_count" -lt 1 ] && iso_count=1; [ "$iso_count" -gt 8 ] && iso_count=8
      first_iso=$(( CPU_COUNT - iso_count ))
      ISO="${first_iso}-$((CPU_COUNT-1))"
      CPU_VENDOR=$(grep -m1 '^vendor_id' /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo unknown)
      CPU_SPEC=""
      case "$CPU_VENDOR" in
        GenuineIntel) CPU_SPEC="intel_pstate=disable intel_idle.max_cstate=0" ;;
        AuthenticAMD) CPU_SPEC="amd_pstate=disable" ;;
      esac
      GRUB_BASE="quiet loglevel=0"
      PERF="nohz_full=${ISO} rcu_nocbs=${ISO} isolcpus=${ISO} processor.max_cstate=1 idle=poll ${CPU_SPEC} mitigations=off noibrs noibpb nopti"
      run_or_note "sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_BASE} ${PERF}\"|' ${GRUB_FILE} || true"
      if command_exists update-grub; then run_or_note "update-grub || true"; fi
      if command_exists grub2-mkconfig; then run_or_note "grub2-mkconfig -o /boot/grub2/grub.cfg || true"; fi
      _warn "GRUB 修改已写入（或将写入），重启后生效，并可能降低系统安全。"
    else
      _warn "/etc/default/grub 未找到，跳过"
    fi
  fi

  _ok "系统模块完成"
}

# ---------------- 主流程 ----------------
final_summary(){
  cat <<EOF
================ SUMMARY ====================
模式: ${MODE}
检测到角色: ${ROLE}
备份与回滚脚本目录: ${BACKUP_DIR}/rollback.sh
DRY-RUN=${DRY_RUN} （0=已应用，1=仅预览）
建议:
  1) 先以 DRY-RUN 全面预览脚本输出，确认无误。
  2) 仅启用网络模块并 --apply，监控 24-72 小时。
  3) 慎用 cleanup / GRUB 激进项；仅在测试或裸机环境中使用。
=============================================
EOF
}

# Interactive flow
echo "=== NAT-VPS 终极优化向导 ==="
echo "备份目录: $BACKUP_DIR"
echo "模式: $MODE"
read -r -p "要更改模式吗？(1=normal, 2=aggressive，回车默认 1): " mode_choice; mode_choice=${mode_choice:-1}
if [ "$mode_choice" = "2" ]; then MODE="aggressive"; fi
_info "当前模式: $MODE"

# ask whether to run network module
read -r -p "是否运行 网络 模块 (BDP/sysctl/BBR/qdisc/RPS/IRQ)？回车默认是 [Y/n]: " yn; yn=${yn:-y}
if [[ ! "$yn" =~ ^[Nn] ]]; then
  read -r -p "请输入测得 RTT(ms)，留空则自动检测: " userrtt
  userrtt=$(printf '%s' "$userrtt" | tr -cd '0-9')
  if [ -n "$userrtt" ]; then FORCE_RTT="$userrtt"; fi
  if [ "$RUN_IPERF" -eq 0 ]; then
    read -r -p "是否要在优化后运行 iperf3 测试？回车默认否 [y/N]: " ipyn; ipyn=${ipyn:-N}
    if [[ "$ipyn" =~ ^[Yy] ]]; then
      read -r -p "请输入 iperf3 服务端 IP（逗号分隔）: " ips
      ips=$(echo "$ips" | tr -d ' ')
      if [ -n "$ips" ]; then IFS=',' read -r -a IPERF_SERVERS <<< "$ips"; RUN_IPERF=1; fi
    fi
  fi
  # run network module
  network_module
fi

# ask whether to run system module
read -r -p "是否运行 系统 模块（I/O/hugepages/工具/服务清理等）？回车默认是 [Y/n]: " syn; syn=${syn:-y}
if [[ ! "$syn" =~ ^[Nn] ]]; then
  # let user toggle options quickly
  read -r -p "是否立即启用 --apply-io-limits？回车默认是 [Y/n]: " x; x=${x:-y}; [ "$x" = "y" ] || [ "$x" = "Y" ] || APPLY_IO_LIMITS=0
  [ "$x" = "y" ] || [ "$x" = "Y" ] && APPLY_IO_LIMITS=1
  read -r -p "是否启用生成工具 (monitor/bench)？回车默认是 [Y/n]: " g; g=${g:-y}; [ "$g" = "y" -o "$g" = "Y" ] && GENERATE_TOOLS=1
  read -r -p "是否安装硬件动态调优服务？回车默认否 [y/N]: " h; h=${h:-N}; [ "$h" = "y" -o "$h" = "Y" ] && INSTALL_HW_TUNING=1
  read -r -p "是否启用 services cleanup（高风险）？回车默认否 [y/N]: " c; c=${c:-N}; [ "$c" = "y" -o "$c" = "Y" ] && CLEANUP_SERVICES=1
  if [ "$ROLE" = "host" ]; then
    read -r -p "是否应用 Host 专用优化（HugePages 等）？回车默认否 [y/N]: " hh; hh=${hh:-N}; [ "$hh" = "y" -o "$hh" = "Y" ] && APPLY_HOST_SPECIFICS=1
    read -r -p "是否应用 GRUB 激进项（极高风险）？回车默认否 [y/N]: " gg; gg=${gg:-N}; [ "$gg" = "y" -o "$gg" = "Y" ] && APPLY_GRUB=1
  fi

  # set flags accordingly for system_module
  [ "$APPLY_IO_LIMITS" -eq 1 ] || true
  [ "$GENERATE_TOOLS" -eq 1 ] || true
  [ "$INSTALL_HW_TUNING" -eq 1 ] || true
  [ "$CLEANUP_SERVICES" -eq 1 ] || true
  [ "$APPLY_HOST_SPECIFICS" -eq 1 ] || true
  [ "$APPLY_GRUB" -eq 1 ] || true

  system_module
fi

# runtime adaptive option
read -r -p "是否运行一次 运行时自适应 检测并按需微调 r/w max？回车默认否 [y/N]: " rad; rad=${rad:-N}
if [[ "$rad" =~ ^[Yy] ]]; then runtime_adaptive; fi

final_summary

# make rollback executable and show location
run_or_note "chmod +x ${BACKUP_DIR}/rollback.sh || true"
_info "若需要回滚，请查看并执行： ${BACKUP_DIR}/rollback.sh （回滚可能需要人工干预）"
echo "完成。"
