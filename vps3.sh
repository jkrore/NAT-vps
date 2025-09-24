#!/usr/bin/env bash
# nat-vps-interactive.sh
# Interactive checklist for VPS optimization (BDP/sysctl/ethtool/RPS/conntrack/hugepages/etc)
# Default: DRY-RUN. Use --apply to actually make changes.
set -euo pipefail
IFS=$'\n\t'

# ---------------- CLI ----------------
DRY_RUN=1
MODE="normal"          # normal|aggressive
FORCE_RTT=""
RUN_IPERF=0
IPERF_SERVERS=()
QUIET=0
BACKUP_ROOT="/var/backups/nat-vps"
TIMESTAMP="$(date +%F-%H%M%S)"
BACKUP_DIR="${BACKUP_ROOT}/nat-vps-${TIMESTAMP}"
SYSCTL_TARGET="/etc/sysctl.d/999-net-optimizer.conf"

usage(){
  cat <<'USAGE'
Usage: sudo ./nat-vps-interactive.sh [opts]

Options:
  --dry-run           (default) show what will happen
  --apply             actually apply changes
  --mode normal|aggressive
  --rtt <ms>          force RTT (ms) used for BDP calc
  --iperf ip,ip2      run iperf3 tests against listed servers
  -q|--quiet          reduce output
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
    -q|--quiet) QUIET=1; shift;;
    -h|--help) usage;;
    *) echo "Unknown arg: $1"; usage;;
  esac
done

_note(){ [ "$QUIET" -eq 0 ] && printf "\033[1;34m[i]\033[0m %s\n" "$*"; }
_ok(){ [ "$QUIET" -eq 0 ] && printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
_warn(){ printf "\033[1;33m[!]\033[0m %s\n" "$*" >&2; }
_err(){ printf "\033[1;31m[!!]\033[0m %s\n" "$*" >&2; }

require_root(){ if [ "$(id -u)" -ne 0 ]; then _err "Please run as root"; exit 2; fi; }
require_root

mkdir -p "$BACKUP_DIR"

# ---------------- helpers ----------------
command_exists(){ command -v "$1" >/dev/null 2>&1; }

run_or_note(){
  if [ "$DRY_RUN" -eq 1 ]; then
    _note "DRY-RUN => $*"
  else
    _note "RUN => $*"
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
    _note "DRY-RUN: would write to $path"
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
      _note "DRY-RUN: line exists in $file"
    else
      _note "DRY-RUN: would append to $file: $line"
    fi
  else
    mkdir -p "$(dirname "$file")"
    touch "$file"
    if ! grep -Fxq -- "$line" "$file"; then
      echo "$line" >> "$file" || true
    fi
  fi
}

# rollbacks script skeleton
cat > "${BACKUP_DIR}/rollback.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "[ROLLBACK] Inspect backup files in this directory and manually restore as needed."
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
  _note "Detected role=${ROLE}, cpu=${CPU_COUNT}, mem=${TOTAL_MEM_MB}MB, virt=${VIRT_TYPE}"
}
detect_env

# ---------------- useful functions ----------------
cpu_mask_for_cores(){
  local n=$(printf '%s' "${1:-0}" | tr -cd '0-9')
  [ -z "$n" ] && { printf "1"; return; }
  if [ "$n" -gt 63 ]; then n=63; fi
  # use awk to compute (1<<n)-1 with no overflow
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
      _warn "Detected RTT ${int_out}ms is suspiciously low; ignoring"
      echo ""
    else
      echo "$int_out"
    fi
  else
    echo ""
  fi
}

# ---------------- interactive prompts ----------------
ask_yes_no(){
  local prompt="$1"; local def="${2:-y}"
  local ans
  while true; do
    if [ "$DRY_RUN" -eq 1 ]; then
      read -r -p "$prompt [Y/n] (DRY-RUN default is Y): " ans
    else
      read -r -p "$prompt [Y/n]: " ans
    fi
    ans=${ans:-$def}
    case "$ans" in
      [Yy]|[Yy][Ee][Ss]) return 0 ;;
      [Nn]|[Nn][Oo]) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

select_mode(){
  echo "Select mode:"
  echo "  1) normal (recommended)"
  echo "  2) aggressive (high risk: cake qdisc, optional GRUB mitigations change)"
  read -r -p "Choice [1/2] (default 1): " m
  m=${m:-1}
  if [ "$m" = "2" ]; then MODE="aggressive"; else MODE="normal"; fi
  _note "Mode set to $MODE"
}

# ---------------- MODULE IMPLEMENTATIONS ----------------

# 1) Network: BDP sysctl, BBR, qdisc, RPS/XPS, IRQ affinity, ethtool backup+tune, dns
network_module(){
  _note "Network module will:"
  _note " - compute BDP (BW assumed 1000Mbps unless you customize), set net.* sysctl (r/wmem/tcp_rmem/tcp_wmem)"
  _note " - enable BBR & fq (or cake if aggressive)"
  _note " - backup current sysctl files and ethtool states"
  _note " - attempt ethtool tuning, RPS/XPS, IRQ affinity, cpu governor"
  if ! ask_yes_no "Proceed with Network optimization?"; then _note "Skipping network module"; return; fi

  # RTT
  RTT_MS=""
  if [ -n "$FORCE_RTT" ] && [[ "$FORCE_RTT" =~ ^[0-9]+$ ]]; then RTT_MS="$FORCE_RTT"; _note "Using forced RTT=${RTT_MS}ms"; fi
  if [ -z "$RTT_MS" ]; then
    if [ -n "${SSH_CONNECTION:-}" ]; then sship=$(echo "$SSH_CONNECTION" | awk '{print $1}') || true; fi
    if [ -n "${sship:-}" ]; then
      _note "Trying to detect RTT by pinging SSH client $sship..."
      r="$(detect_rtt_ms "$sship" || true)"
      if [ -n "$r" ]; then RTT_MS="$r"; _ok "RTT=${RTT_MS}ms (ssh)"; fi
    fi
  fi
  if [ -z "$RTT_MS" ]; then
    _note "Falling back to ping 1.1.1.1"
    r="$(detect_rtt_ms 1.1.1.1 || true)"
    if [ -n "$r" ]; then RTT_MS="$r"; _ok "RTT=${RTT_MS}ms (1.1.1.1)"; else RTT_MS=150; _warn "Cannot detect RTT; using default ${RTT_MS}ms"; fi
  fi

  # BDP calc
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

  _note "Computed BDP=${BDP_BYTES} bytes (~${BDP_MB} MB) -> cap ${MAX_MB} MB"

  TMP_SYSCTL="$(mktemp)"
  cat > "$TMP_SYSCTL" <<EOF
# Generated by nat-vps-interactive ${TIMESTAMP}
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

  _note "Will write sysctl to $SYSCTL_TARGET (backup will be stored)"
  if [ "$DRY_RUN" -eq 0 ]; then
    backup_file "$SYSCTL_TARGET"
    install -m 0644 "$TMP_SYSCTL" "$SYSCTL_TARGET"
    sysctl --system || _warn "sysctl --system returned non-zero"
    cp -a "$TMP_SYSCTL" "${BACKUP_DIR}/sysctl.generated.${TIMESTAMP}"
    echo "cp -a \"${BACKUP_DIR}/sysctl.generated.${TIMESTAMP}\" \"${SYSCTL_TARGET}\"" >> "${BACKUP_DIR}/rollback.sh"
    _ok "sysctl written and applied"
  else
    _note "DRY-RUN: sysctl would be written to $SYSCTL_TARGET"
  fi
  rm -f "$TMP_SYSCTL" || true

  # Attempt to load tcp_bbr
  if command_exists modprobe; then
    run_or_note "modprobe tcp_bbr 2>/dev/null || true"
  fi

  # Detect interfaces
  mapfile -t IFACES < <(ip -o link show | awk -F': ' '{print $2}' | grep -Ev '^(lo|virbr|docker|br-|veth|tun|tap)' || true)
  _note "Interfaces: ${IFACES[*]:-none}"

  # Save ethtool states
  if command_exists ethtool; then
    for ifn in "${IFACES[@]:-}"; do
      outf="${BACKUP_DIR}/ethtool-${ifn}.k.${TIMESTAMP}.txt"
      if [ "$DRY_RUN" -eq 1 ]; then
        _note "DRY-RUN: would save ethtool -k $ifn to $outf"
      else
        ethtool -k "$ifn" > "$outf" 2>/dev/null || true
        _ok "Saved ethtool -k $ifn -> $outf"
      fi
    done
  fi

  tune_ethtool(){
    local ifn="$1"
    if ! command_exists ethtool; then _warn "no ethtool"; return; fi
    local supports; supports=$(ethtool -k "$ifn" 2>/dev/null || true)
    for feat in tso gso gro lro tx rx sg txvlan rxvlan; do
      if echo "$supports" | grep -qi "^${feat}:"; then
        # aggressive mode: disable some offloads which can cause issues in virtualization
        if [ "$MODE" = "aggressive" ]; then
          run_or_note "ethtool -K $ifn $feat off 2>/dev/null || true"
        else
          # safe: try enabling if currently disabled
          if echo "$supports" | grep -qi "^${feat}: .*off"; then
            run_or_note "ethtool -K $ifn $feat on 2>/dev/null || true"
          fi
        fi
      fi
    done
    _ok "ethtool tuning (best-effort) for $ifn"
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
      _ok "RPS/XPS set for $ifn (cpumask=$cpumask_hex)"
    else
      _warn "$ifn has no queues"
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
          _warn "Cannot write $aff"
        fi
      fi
    done < /proc/interrupts
    _ok "IRQ assignment attempted for $ifn"
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
  _ok "CPU governor (performance) attempted"

  # qdisc
  IFACE=$(ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true)
  if command_exists tc && [ -n "$IFACE" ]; then
    QDISC="fq"
    if [ "$MODE" = "aggressive" ]; then
      # try cake if supported
      if tc qdisc add dev lo root cake 2>/dev/null; then
        tc qdisc del dev lo root 2>/dev/null || true
        QDISC="cake"
      fi
    fi
    run_or_note "tc qdisc replace dev ${IFACE} root ${QDISC}"
    _ok "qdisc set on ${IFACE}: ${QDISC}"
  fi

  # DNS quick optimize (best-effort)
  if ask_yes_no "Apply DNS quick optimization (systemd-resolved or /etc/resolv.conf)?" "y"; then
    if [ -L /etc/resolv.conf ] && readlink /etc/resolv.conf | grep -qi systemd; then
      if command_exists resolvectl; then
        run_or_note "mkdir -p /etc/systemd/resolved.conf.d"
        local dropconf="/etc/systemd/resolved.conf.d/10-dns-opt.conf"
        local content="[Resolve]
DNS=1.1.1.1 8.8.8.8 9.9.9.9
DNSSEC=allow-downgrade
Cache=yes
ReadEtcHosts=yes
"
        write_file_atomic "$dropconf" "$content"
        run_or_note "systemctl restart systemd-resolved || true"
      else
        _warn "resolvectl not available; skip"
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
          _note "DRY-RUN: would write /etc/resolv.conf"
        fi
      fi
    fi
  fi

  # iperf tests
  if [ "$RUN_IPERF" -eq 1 ] && command_exists iperf3; then
    for s in "${IPERF_SERVERS[@]}"; do
      _note "Running iperf3 -> $s"
      if [ "$DRY_RUN" -eq 0 ]; then
        iperf3 -c "$s" -t 10 -J >/tmp/.iperf.json 2>/dev/null || _warn "iperf3 failed"
        if command_exists jq; then
          DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/.iperf.json)
          UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/.iperf.json)
          _note "iperf3 $s DL=$(( (DL+500000)/1000000 ))Mbps UL=$(( (UL+500000)/1000000 ))Mbps"
        fi
        rm -f /tmp/.iperf.json || true
      else
        _note "DRY-RUN: would run iperf3 to $s"
      fi
    done
  fi

  _ok "Network module finished"
}

# 2) System module: I/O limits, udev, hugepages, hw tuning service, generate tools, cleanup services, grub (host-only)
system_module(){
  _note "System module will offer: I/O & limits, udev rules, hugepages (host-only), hw tuning service, generate tools, cleanup services (dangerous), GRUB (host-only, very dangerous)."
  if ! ask_yes_no "Proceed with System module?"; then _note "Skipping system module"; return; fi

  # I/O & limits
  if ask_yes_no "Apply I/O limits & udev optimizations (nofile, nproc, udev rules)?" "y"; then
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
    _ok "I/O limits & udev prepared (may require reload/triggers)"
  fi

  # Hugepages (host only)
  if [ "$ROLE" = "host" ]; then
    if ask_yes_no "Apply host-specific hugepages tuning (only for bare metal/host, may require reboot)?" "n"; then
      HP_FILE="/etc/hugepages/ultimate-hugepages.conf"
      hp_count=$(( (TOTAL_MEM_MB / 200) ))
      [ "$hp_count" -lt 64 ] && hp_count=64
      [ "$hp_count" -gt 4096 ] && hp_count=4096
      write_file_atomic "$HP_FILE" "# hugepages\ n r\nnr_hugepages=${hp_count}\n"
      if [ "$DRY_RUN" -eq 0 ]; then
        if [ -w /proc/sys/vm/nr_hugepages ]; then
          printf '%s' "$hp_count" > /proc/sys/vm/nr_hugepages 2>/dev/null || _warn "writing nr_hugepages failed"
        else
          _warn "/proc/sys/vm/nr_hugepages not writable"
        fi
      else
        _note "DRY-RUN: would attempt to write ${hp_count} to /proc/sys/vm/nr_hugepages"
      fi
      _ok "Hugepages configured (check /proc/sys/vm/nr_hugepages)"
    fi
  fi

  # Generate tools
  if ask_yes_no "Generate monitor & bench scripts (/usr/local/bin/ultimate-monitor.sh, ultimate-bench.sh)?" "y"; then
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
    _ok "Monitor & bench scripts installed"
  fi

  # HW dynamic tuning service
  if ask_yes_no "Install hardware dynamic tuning service (periodic ethtool/read_ahead adjustments)?" "n"; then
    HW_SCRIPT="/usr/local/bin/ultimate-hw-ai.sh"
    cat > "${BACKUP_DIR}/ultimate-hw-ai.sh.tmp" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
CPU_COUNT=$(nproc || echo 1)
ALL_NICS=( $(ls /sys/class/net | grep -v lo || true) )
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  if [ -f "$gov" ] && [ -w "$gov" ]; then
    echo performance > "$gov" 2>/dev/null || true
  fi
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
EOF
    # write the script
    write_file_atomic "$HW_SCRIPT" "$(cat "${BACKUP_DIR}/ultimate-hw-ai.sh.tmp")"
    rm -f "${BACKUP_DIR}/ultimate-hw-ai.sh.tmp" || true
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
    _ok "Hardware tuning service installed (timer)"
  fi

  # Cleanup services (dangerous)
  if ask_yes_no "Disable common non-essential services (irqbalance, snapd, rsyslog, auditd, cron, firewalld)? This is HIGH RISK." "n"; then
    services_common=(irqbalance tuned thermald bluetooth cups snapd unattended-upgrades rsyslog auditd cron)
    services_net=(firewalld ufw nftables)
    services_virt=(libvirtd virtlogd virtlockd)
    to_disable=("${services_common[@]}")
    if [ "$ROLE" != "nat" ]; then to_disable+=("${services_net[@]}"); fi
    if [ "$ROLE" != "host" ]; then to_disable+=("${services_virt[@]}"); fi
    for svc in "${to_disable[@]}"; do
      run_or_note "systemctl disable --now ${svc} >/dev/null 2>&1 || true"
    done
    _ok "Requested services disabled (check backups in $BACKUP_DIR)"
  fi

  # GRUB (host-only & extreme)
  if [ "$ROLE" = "host" ]; then
    if ask_yes_no "Apply aggressive GRUB CPU isolation & disable mitigations? VERY HIGH RISK and requires reboot. (only for host)" "n"; then
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
        apply_or_write="sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_BASE} ${PERF}\"|' ${GRUB_FILE}"
        run_or_note "${apply_or_write}"
        if command_exists update-grub; then run_or_note "update-grub || true"; fi
        if command_exists grub2-mkconfig; then run_or_note "grub2-mkconfig -o /boot/grub2/grub.cfg || true"; fi
        _warn "GRUB changes written. A reboot is required to apply them and this may reduce system security."
      else
        _warn "No /etc/default/grub found; skip"
      fi
    fi
  fi

  _ok "System module finished"
}

# finalize and show summary
final_summary(){
  cat <<EOF
================ SUMMARY ====================
Mode: ${MODE}
Role detected: ${ROLE}
Backups & rollback script location: ${BACKUP_DIR}/rollback.sh
Note: Script default is DRY-RUN. Re-run with --apply to actually make changes.
Recommended next steps:
  1) If you ran DRY-RUN and are happy, re-run with --apply and same options.
  2) Monitor with: ss -tin, tc qdisc show dev <iface>, iperf3 tests, dmesg.
  3) If GRUB was changed, reboot is required.
=============================================
EOF
}

# ---------------- RUN interactive flow ----------------
echo "=== NAT-VPS Interactive Optimizer ==="
echo "Backup dir: $BACKUP_DIR"
echo "Mode: $MODE (you can change)"
if ask_yes_no "Change mode? (aggressive enables more risky tuning)" "n"; then select_mode; fi

# Network
if ask_yes_no "Run network optimization module? (BDP/sysctl/BBR/qdisc/ethtool/RPS/IRQ/etc)" "y"; then
  # offer RTT input if not provided
  if [ -z "$FORCE_RTT" ]; then
    read -r -p "Enter measured RTT in ms (leave empty to auto-detect): " userrtt
    userrtt=$(printf '%s' "$userrtt" | tr -cd '0-9')
    if [ -n "$userrtt" ]; then FORCE_RTT="$userrtt"; fi
  fi
  # allow iperf servers
  if [ "$RUN_IPERF" -eq 0 ]; then
    if ask_yes_no "Would you like to run iperf3 tests after tuning? (need iperf3 client installed on this machine)" "n"; then
      read -r -p "Enter iperf3 server IPs (comma separated): " ips
      ips=$(echo "$ips" | tr -d ' ')
      if [ -n "$ips" ]; then IFS=',' read -r -a IPERF_SERVERS <<< "$ips"; RUN_IPERF=1; fi
    fi
  fi
  network_module
fi

# System
if ask_yes_no "Run system optimization module (I/O limits/hugepages/hw-tuning/cleanup/grub)?" "n"; then
  system_module
fi

final_summary

# make rollback.sh executable
if [ -f "${BACKUP_DIR}/rollback.sh" ]; then
  run_or_note "chmod +x ${BACKUP_DIR}/rollback.sh"
fi

echo "Done."
