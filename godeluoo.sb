#!/usr/bin/env bash
# proxy-ultimate-final.sh
# VPS 代理网络终极优化脚本 — FINAL (combined + fixes + vendor tips)
# Target: Debian 12/13, cloud VPS (0-4 vCPU, 0-16GB)
# Features:
#   - RTT, bandwidth, BDP calculations
#   - BBR detection (precise), optional XanMod install (BBRv3)
#   - TCP/UDP buffer tuning with safety/clamping
#   - NIC tuning (Ring, Coalesce, Offloads, UDP/GSO/GRO order)
#   - IRQ / RPS / XPS (safe CPU mask generation)
#   - Enhanced monitor: EWMA retrans smoothing, Coalesce dynamic adjust, Prometheus export, logrotate
#   - Conntrack tuning + hashsize
#   - Virtualization/driver specific optimizations (AWS/virtio hints, tx-udp-segmentation for >=5.18)
#   - Optional iperf3 speedtest and automated perf script
#   - Rate-limit protections (clamp sysctl writes), log rotation, snapshot before/after
# Usage:
#   sudo ./proxy-ultimate-final.sh [--apply] [--mode normal|aggressive|latency] [--install-xanmod] [--enable-xdp] [--iperf-server IP]
# Default: DRY-RUN unless --apply supplied.
set -euo pipefail
IFS=$'\n\t'

### ========== Configuration ==========
VERSION="final-2025-10-18"
TMP="/tmp/proxy-opt-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

APPLY=0
QUIET=0
MODE="aggressive"    # normal | aggressive | latency
INSTALL_XANMOD=0
ENABLE_XDP=0
ENABLE_MONITOR=1
IPERF_SERVER=""      # optionally supply iperf3 server
FORCE_RTT=""
FORCE_BW=""

SYSCTL_FILE="/etc/sysctl.d/99-proxy-ultimate.conf"
MONITOR_SCRIPT="/usr/local/bin/proxy-ultimate-monitor.sh"
MONITOR_SERVICE="/etc/systemd/system/proxy-ultimate-monitor.service"
HEALTH_SCRIPT="/usr/local/bin/proxy-probe-health.sh"
PERF_SCRIPT="/usr/local/bin/proxy-performance-test.sh"
LOGROTATE_FILE="/etc/logrotate.d/proxy-ultimate-monitor"

declare -A SYS NET NIC
declare -a NUMA_CPUS=()

### ========== Logging helpers ==========
_log(){ [ "${QUIET:-0}" -eq 0 ] && printf "\033[36m[%s]\033[0m %s\n" "$(date +%T)" "$*"; }
_ok(){ [ "${QUIET:-0}" -eq 0 ] && printf "\033[32m[✓]\033[0m %s\n" "$*"; }
_warn(){ printf "\033[33m[!]\033[0m %s\n" "$*" >&2; }
_err(){ printf "\033[31m[✗]\033[0m %s\n" "$*" >&2; exit 1; }
_section(){ [ "${QUIET:-0}" -eq 0 ] && printf "\n\033[1;35m╔══ %s ══╗\033[0m\n" "$*"; }

has(){ command -v "$1" >/dev/null 2>&1; }

to_int(){ local v="${1:-0}"; v="${v//[^0-9]/}"; echo "${v:-0}"; }

# safe clamp write to sysctl (min/max applied)
safe_sysctl_write(){
  # args: key value min max
  local key="$1"; local value="$2"; local min="${3:-0}"; local max="${4:-0}"
  local val=$(to_int "$value")
  if [ "$min" -ne 0 ] && [ "$val" -lt "$min" ]; then val="$min"; fi
  if [ "$max" -ne 0 ] && [ "$val" -gt "$max" ]; then val="$max"; fi
  run_cmd "sysctl -w $key=$val >/dev/null 2>&1 || true"
  _log "sysctl: $key=$val"
}

run_cmd(){
  if [ "${APPLY:-0}" -eq 1 ]; then
    if ! eval "$@"; then
      _warn "命令失败(已忽略): $*"
    fi
  else
    _log "DRY: $*"
  fi
}

# safe CPU mask generation up to 64 cores
cpu_mask_hex(){
  local n=$(to_int "$1"); [ "$n" -le 0 ] && echo "1" && return
  if [ "$n" -ge 64 ]; then echo "ffffffffffffffff"; return; fi
  # build mask as (1<<n)-1 via bc if necessary
  if [ "$n" -lt 61 ]; then
    printf '%x' $(( (1 << n) - 1 ))
    return
  fi
  # fallback for near-64: use Python if available else hard cap
  if has python3; then
    python3 - <<PY
n=$n
mask=(1<<n)-1
print(format(mask,'x'))
PY
  else
    echo "ffffffffffffffff"
  fi
}

### ========== Parse args ==========
usage(){ cat <<EOF
Usage: sudo $0 [--apply] [--mode normal|aggressive|latency] [--install-xanmod] [--enable-xdp] [--iperf-server IP] [--rtt MS] [--bandwidth MBPS]
Default: dry-run (no changes). Use --apply to commit.
EOF
exit 0; }

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1; shift;;
    --mode) MODE="${2:-aggressive}"; shift 2;;
    --install-xanmod) INSTALL_XANMOD=1; shift;;
    --enable-xdp) ENABLE_XDP=1; shift;;
    --iperf-server) IPERF_SERVER="${2:-}"; shift 2;;
    --rtt) FORCE_RTT="${2:-}"; shift 2;;
    --bandwidth) FORCE_BW="${2:-}"; shift 2;;
    -q|--quiet) QUIET=1; shift;;
    -h|--help) usage;;
    *) _err "Unknown arg: $1";;
  esac
done

[ "$(id -u)" -ne 0 ] && _err "Run as root"

### ========== Basic detection ==========
_section "System & NIC detection"
SYS[kernel]=$(uname -r)
SYS[cpu]=$(nproc)
SYS[mem_kb]=$(awk '/MemTotal/ {print $2}' /proc/meminfo || echo 0)
SYS[mem_bytes]=$((SYS[mem_kb]*1024))
SYS[mem_gb]=$(awk -v b="${SYS[mem_bytes]}" 'BEGIN{printf "%.1f", b/1024/1024/1024}')
SYS[virt]="unknown"
if has systemd-detect-virt; then SYS[virt]=$(systemd-detect-virt || echo unknown); fi
# NUMA
SYS[numa_nodes]=$(lscpu 2>/dev/null | awk '/^NUMA node\(s\):/ {print $NF}' || echo 1)
# main iface
SYS[iface]=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1 || true)
if [ -z "${SYS[iface]}" ]; then SYS[iface]=$(ip -o link show | awk -F': ' '$2!~/lo|virbr|docker|veth/ {print $2; exit}'); fi
[ -z "${SYS[iface]}" ] && _err "Cannot detect main network interface"

# NIC details
iface="${SYS[iface]}"
NIC[driver]=$(ethtool -i "$iface" 2>/dev/null | awk '/driver:/ {print $2}' || echo "unknown")
NIC[queues]=$(ethtool -l "$iface" 2>/dev/null | awk '/Combined:/ {print $2; exit}' || echo 1)
NIC[rx_max]=$(ethtool -g "$iface" 2>/dev/null | awk '/^RX:/{getline; print $1}' || echo 0)
NIC[tx_max]=$(ethtool -g "$iface" 2>/dev/null | awk '/^TX:/{getline; print $1}' || echo 0)
NIC[numa]=$(cat "/sys/class/net/$iface/device/numa_node" 2>/dev/null || echo -1)
_ok "Kernel=${SYS[kernel]} CPU=${SYS[cpu]} Mem=${SYS[mem_gb]}GB Iface=${iface} Driver=${NIC[driver]}"

### ========== RTT detection (robust) ==========
detect_rtt(){
  _section "RTT detection"
  if [ -n "$FORCE_RTT" ]; then NET[rtt]=$(to_int "$FORCE_RTT"); _ok "RTT forced ${NET[rtt]}ms"; return; fi
  declare -A targs=(["1.1.1.1"]=5 ["8.8.8.8"]=3 ["9.9.9.9"]=2)
  local total_weighted=0 total_weight=0
  for t in "${!targs[@]}"; do
    local w=${targs[$t]}
    local tf="${TMP}/ping_${t//./}"
    if ping -c 8 -W 2 -i 0.2 "$t" >"$tf" 2>/dev/null; then
      mapfile -t r < <(grep -Eo 'time=[0-9.]+' "$tf" | awk -F= '{print $2}')
      rm -f "$tf"
      if [ ${#r[@]} -ge 4 ]; then
        IFS=$'\n' sorted=($(printf '%s\n' "${r[@]}" | sort -n))
        local mid="${sorted[$(( ${#sorted[@]} / 2 ))]}"
        if awk -v m="$mid" 'BEGIN{exit !(m>=1 && m<=2000)}'; then
          total_weighted=$(awk -v a="$total_weighted" -v m="$mid" -v w="$w" 'BEGIN{printf "%.2f", a + m*w}')
          total_weight=$((total_weight + w))
          _log "$t median ${mid}ms (w=$w)"
        fi
      fi
    fi
  done
  if [ "$total_weight" -gt 0 ]; then
    NET[rtt]=$(awk -v a="$total_weighted" -v w="$total_weight" 'BEGIN{printf "%.0f", a/w}'); _ok "RTT=${NET[rtt]}ms"
  else
    NET[rtt]=50; _warn "RTT detection failed, default 50ms"
  fi
}

### ========== Bandwidth detection ==========
detect_bw(){
  _section "Bandwidth detect"
  local b=0
  local link=$(ethtool "$iface" 2>/dev/null | awk '/Speed:/ {print $2}' | tr -cd '0-9' || echo 0)
  link=$(to_int "$link")
  if [ "$link" -gt 0 ]; then b="$link"; _log "ethtool reports ${b}Mbps"; fi
  if [ "$b" -eq 0 ]; then
    local cpu_bw=$(( SYS[cpu] * 500 ))
    local mem_bw=$(awk -v m="${SYS[mem_gb]}" 'BEGIN{printf "%.0f", m*400}')
    b=$(( cpu_bw < mem_bw ? cpu_bw : mem_bw ))
    b=$(( b * 80 / 100 ))
    _log "Estimated bandwidth ${b}Mbps"
  fi
  if [ -n "$FORCE_BW" ]; then b=$(to_int "$FORCE_BW"); _log "Bandwidth forced ${b}Mbps"; fi
  [ "$b" -lt 10 ] && b=10
  NET[bw]=$b
  _ok "Bandwidth=${NET[bw]}Mbps"
}

### ========== BDP & buffers ==========
calc_buffers(){
  _section "BDP and buffers"
  local bw=${NET[bw]} rtt=${NET[rtt]}
  local bdp=$(awk -v bw="$bw" -v rtt="$rtt" 'BEGIN{printf "%.0f", bw*125*rtt}')
  NET[bdp]=$bdp
  NET[bdp_mb]=$(awk -v b="$bdp" 'BEGIN{printf "%.2f", b/1024/1024}')
  _log "BDP=${NET[bdp]} bytes (${NET[bdp_mb]}MB)"
  # memory safety
  local mem10=$(( SYS[mem_bytes] * 10 / 100 ))
  local mem15=$(( SYS[mem_bytes] * 15 / 100 ))
  # tcp max
  local mult=3
  [ "$MODE" = "aggressive" ] && mult=4
  [ "$MODE" = "latency" ] && mult=2
  local tcp_max=$(( bdp * mult ))
  [ "$tcp_max" -gt "$mem15" ] && tcp_max="$mem15"
  [ "$tcp_max" -lt 65536 ] && tcp_max=65536
  NET[tcp_rmem_max]=$tcp_max
  NET[tcp_wmem_max]=$tcp_max
  NET[tcp_rmem_def]=131072
  NET[tcp_rmem_min]=4096
  NET[tcp_wmem_def]=131072
  NET[tcp_wmem_min]=4096
  _ok "TCP def=128KB max=$(( tcp_max / 1024 / 1024 ))MB"
  # udp
  local udp_max=$(( bdp * 2 ))
  [ "$udp_max" -gt "$mem10" ] && udp_max=$mem10
  [ "$udp_max" -lt 65536 ] && udp_max=65536
  NET[udp_rmem_min]=16384; NET[udp_wmem_min]=16384
  local page=4096
  NET[udp_mem_min]=$(( udp_max / page / 4 ))
  NET[udp_mem_prs]=$(( udp_max / page / 2 ))
  NET[udp_mem_max]=$(( udp_max / page ))
  _ok "UDP max=$((udp_max/1024/1024))MB mem pages ${NET[udp_mem_min]}/${NET[udp_mem_prs]}/${NET[udp_mem_max]}"
  # backlog
  local backlog=$(( NET[bw] * 100 ))
  [ "$backlog" -lt 10000 ] && backlog=10000
  [ "$backlog" -gt 1000000 ] && backlog=1000000
  NET[backlog]=$backlog
  NET[budget]=$(( backlog / 10 ))
  # conntrack conservative
  local ct=$(( SYS[mem_bytes] / 32768 ))
  [ "$ct" -lt 65536 ] && ct=65536
  [ "$ct" -gt 524288 ] && ct=524288
  NET[conntrack]=$ct
  _log "backlog=${NET[backlog]} budget=${NET[budget]} conntrack=${NET[conntrack]}"
}

### ========== BBR detection (precise) ==========
detect_bbr(){
  _section "BBR detection"
  local avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
  NET[avail_cc]="$avail"
  local best="none"
  # check modules loaded first: bbr3 > bbrv2 > bbr2 > bbr
  for m in tcp_bbr3 tcp_bbrv2 tcp_bbr2 tcp_bbr; do
    if grep -qw "$m" /proc/modules 2>/dev/null; then best="$m"; break; fi
  done
  # if none loaded, check available list
  if [ "$best" = "none" ]; then
    for n in bbr3 bbrv2 bbr2 bbr; do
      if echo "$avail" | grep -qw "$n"; then best="$n"; break; fi
    done
  fi
  NET[bbr_best]="$best"
  _ok "Available CC: $avail -> Best detected: $best"
}

### ========== Sysctl generation (clamped) ==========
gen_sysctl(){
  _section "Generate sysctl"
  local tmpf="${TMP}/sysctl.conf"
  local somax=131072; [ "$MODE" = "aggressive" ] && somax=262144
  cat >"$tmpf" <<EOF
# Generated by proxy-ultimate-final $VERSION
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = ${NET[tcp_rmem_max]}
net.core.wmem_max = ${NET[tcp_wmem_max]}
net.core.optmem_max = 524288

net.ipv4.tcp_rmem = ${NET[tcp_rmem_min]} ${NET[tcp_rmem_def]} ${NET[tcp_rmem_max]}
net.ipv4.tcp_wmem = ${NET[tcp_wmem_min]} ${NET[tcp_wmem_def]} ${NET[tcp_wmem_max]}

net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_moderate_rcvbuf = 1
net.core.somaxconn = ${somax}
net.ipv4.tcp_max_syn_backlog = ${somax}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10

net.ipv4.udp_rmem_min = ${NET[udp_rmem_min]}
net.ipv4.udp_wmem_min = ${NET[udp_wmem_min]}
net.ipv4.udp_mem = ${NET[udp_mem_min]} ${NET[udp_mem_prs]} ${NET[udp_mem_max]}

net.core.netdev_max_backlog = ${NET[backlog]}
net.core.netdev_budget = ${NET[budget]}
net.core.netdev_budget_usecs = 5000

net.core.rps_sock_flow_entries = 65536

net.ipv4.ip_local_port_range = 10000 65535

net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

net.netfilter.nf_conntrack_max = ${NET[conntrack]}
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_udp_timeout = 60

vm.swappiness = 1
vm.vfs_cache_pressure = 50
vm.min_free_kbytes = 65536

fs.file-max = 2097152
fs.nr_open = 2097152
EOF
  run_cmd "install -m 0644 '$tmpf' '$SYSCTL_FILE'"
  # apply clamped writes for dangerous keys using safe_sysctl_write
  safe_sysctl_write net.core.rmem_max "${NET[tcp_rmem_max]}" 65536 $((512*1024*1024))
  safe_sysctl_write net.core.wmem_max "${NET[tcp_wmem_max]}" 65536 $((512*1024*1024))
  safe_sysctl_write net.netfilter.nf_conntrack_max "${NET[conntrack]}" 65536 524288
  run_cmd "sysctl -p '$SYSCTL_FILE' >/dev/null 2>&1 || true"
  _ok "Sysctl generated/applied (dry-run may have skipped actual writes)"
}

### ========== NIC optimizations (including vendor tips) ==========
optimize_nic(){
  _section "NIC hardware optimization"
  local iface="${SYS[iface]}"
  # ring buffers
  if [ "${NIC[rx_max]}" -gt 512 ] && [ "${NIC[tx_max]}" -gt 512 ]; then
    local rx=$(( NIC[rx_max] * 75 / 100 ))
    local tx=$(( NIC[tx_max] * 75 / 100 ))
    [ "$rx" -lt 512 ] && rx=512
    [ "$tx" -lt 512 ] && tx=512
    run_cmd "ethtool -G '$iface' rx $rx tx $tx || true"
    _ok "Ring set RX=$rx TX=$tx"
  fi
  # Offloads
  run_cmd "ethtool -K '$iface' tso on gso on sg on || true"
  # driver/cloud-specific tweaks (AWS virtio specific)
  if [[ "${SYS[virt],,}" == *"kvm"* || "${NIC[driver],,}" == *"virtio"* ]]; then
    # AWS/virtio hints
    run_cmd "ethtool -K '$iface' tx-nocache-copy off 2>/dev/null || true"
    run_cmd "ethtool -K '$iface' tx-checksum-ipv4 on 2>/dev/null || true"
    _ok "Applied virtio/EC2-specific ethtool hints"
  fi
  # enable GRO then UDP GRO forward if supported (order corrected)
  if [ "$MODE" = "latency" ]; then
    run_cmd "ethtool -K '$iface' gro off lro off || true"
    _log "Latency mode: GRO/LRO off"
  else
    run_cmd "ethtool -K '$iface' gro on || true"
    # try tx-udp-segmentation if kernel supports (>=5.18 recommended)
    if [[ "${SYS[kernel]}" =~ ^([6-9]|5\.(1[8-9]|[2-9][0-9])) ]]; then
      run_cmd "ethtool -K '$iface' tx-udp-segmentation on 2>/dev/null || true"
      _log "Attempted enable tx-udp-segmentation"
    fi
    run_cmd "ethtool -K '$iface' rx-gro-list on 2>/dev/null || true"
    run_cmd "ethtool -K '$iface' rx-udp-gro-forwarding on 2>/dev/null || true"
    _ok "Enabled GRO and attempted UDP GRO forward"
  fi
  # coalesce
  local rx_usecs=125 rx_frames=64
  case "$MODE" in latency) rx_usecs=30; rx_frames=16;; aggressive) rx_usecs=100; rx_frames=64;; *) rx_usecs=200; rx_frames=128;; esac
  run_cmd "ethtool -C '$iface' rx-usecs $rx_usecs rx-frames $rx_frames adaptive-rx off || true"
  _ok "Coalesce set rx-usecs=${rx_usecs}"
  # try to set combined queues
  local desired=${SYS[cpu]}; [ "$desired" -gt 32 ] && desired=32
  [ "${NIC[queues]:-1}" -ge 1 ] && [ "$desired" -gt "${NIC[queues]}" ] && desired=${NIC[queues]}
  run_cmd "ethtool -L '$iface' combined $desired || true"
  _ok "Attempted set combined queues to $desired"
}

### ========== IRQ / RPS / XPS ==========
opt_irq_rps_xps(){
  _section "IRQ/RPS/XPS"
  local iface="${SYS[iface]}"
  local mask=$(cpu_mask_hex "${SYS[cpu]}")
  _log "CPU mask hex: $mask"
  local qdir="/sys/class/net/$iface/queues"
  if [ -d "$qdir" ]; then
    local rps_cnt=0
    for rxq in "$qdir"/rx-*; do
      [ -e "$rxq/rps_cpus" ] || continue
      run_cmd "echo $mask > '$rxq/rps_cpus' || true"
      run_cmd "echo 4096 > '$rxq/rps_flow_cnt' || true"
      rps_cnt=$((rps_cnt+1))
    done
    [ "$rps_cnt" -gt 0 ] && _ok "RPS set for $rps_cnt rx queues"
    local tx_idx=0 xps_cnt=0
    for txq in "$qdir"/tx-*; do
      [ -e "$txq/xps_cpus" ] || continue
      local cpu_idx=$(( tx_idx % SYS[cpu] ))
      local single=$(printf '%x' $((1<<cpu_idx))) || single="1"
      run_cmd "echo $single > '$txq/xps_cpus' || true"
      xps_cnt=$((xps_cnt+1)); tx_idx=$((tx_idx+1))
    done
    [ "$xps_cnt" -gt 0 ] && _ok "XPS set for $xps_cnt tx queues"
  else
    _log "No queues dir, skip RPS/XPS"
  fi
}

### ========== Conntrack tuning (hashsize) ==========
opt_conntrack(){
  _section "Conntrack tuning"
  # set conntrack max via sysctl already; set hashsize parameter if available
  local ct=${NET[conntrack]}
  run_cmd "sysctl -w net.netfilter.nf_conntrack_max=$ct >/dev/null 2>&1 || true"
  # compute hashsize = ct/4 (kernel expects number of entries)
  local hash=$(( ct / 4 ))
  if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    run_cmd "echo $hash > /sys/module/nf_conntrack/parameters/hashsize || true"
    _ok "Conntrack hashsize set to $hash"
  else
    _log "Conntrack hashsize param not writable or not present"
  fi
  # vendor recommended:
  run_cmd "sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1 || true"
  run_cmd "sysctl -w net.netfilter.nf_conntrack_tcp_loose=1 >/dev/null 2>&1 || true"
}

### ========== CPU optimizations ==========
opt_cpu(){
  _section "CPU tuning"
  if has cpupower; then run_cmd "cpupower frequency-set -g performance || true"; _ok "cpupower set performance"; fi
  if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
    run_cmd "echo madvise > /sys/kernel/mm/transparent_hugepage/enabled || true"
    run_cmd "echo defer > /sys/kernel/mm/transparent_hugepage/defrag || true"
    _ok "THP set to madvise"
  fi
}

### ========== XDP helper (safe checks) ==========
opt_xdp(){
  [ "${ENABLE_XDP:-0}" -eq 0 ] && return
  _section "XDP try"
  if ! has clang; then _warn "clang missing, skip XDP"; return; fi
  # check headers
  if [ ! -f /usr/include/linux/bpf.h ] && [ ! -f /usr/include/uapi/linux/bpf.h ]; then _warn "bpf headers missing, skip XDP"; return; fi
  local c="${TMP}/xdp.c"
  cat >"$c" <<'C_EOF'
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
SEC("xdp")
int _xdp_prog(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void*)(eth+1) > data_end) return XDP_PASS;
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
C_EOF
  local o="${TMP}/xdp.o"
  if clang -O2 -target bpf -c "$c" -o "$o" 2>/dev/null; then
    if run_cmd "ip link set dev $iface xdp obj '$o' sec xdp 2>/dev/null"; then _ok "XDP attached native"; else run_cmd "ip link set dev $iface xdpgeneric obj '$o' sec xdp 2>/dev/null || true"; _ok "XDP tried generic"; fi
  else _warn "XDP compile failed"; fi
}

### ========== Monitor (enhanced) ==========
install_monitor(){
  [ "${ENABLE_MONITOR:-1}" -eq 0 ] && return
  _section "Install enhanced monitor"
  local script="$MONITOR_SCRIPT"
  cat > "$TMP/monitor.sh" <<'MON'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
IFACE="__IFACE__"
LOG="/var/log/proxy-ultimate-monitor.log"
INTERVAL=15
COOLDOWN=60
EWMA_SCALE=10000
# EWMA alpha=0.02 -> 200/10000
ALPHA=200
LAST_ADJUST=0
EWMA_RETRANS=0
CURRENT_USECS=125

log(){ echo "[$(date +'%F %T')] $*" >> "$LOG"; }
get_tcp_ext(){
  awk "/^TcpExt:/ {for(i=2;i<=NF;i++) if(\$i==\"$1\"){getline; print \$i; exit}}" /proc/net/netstat 2>/dev/null || echo 0
}

# init
RX_PKTS=$(cat /sys/class/net/$IFACE/statistics/rx_packets 2>/dev/null || echo 0)
RX_BYTES=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
RETRANS=$(get_tcp_ext TCPRetransSegs)
SEGS=$(get_tcp_ext TCPSegsOut)
# try read initial coalesce
CURRENT_USECS=$(ethtool -c "$IFACE" 2>/dev/null | awk '/rx-usecs:/ {print $2}' || echo 125)
log "monitor start iface=$IFACE usecs=$CURRENT_USECS"

while true; do
  sleep "$INTERVAL"
  # PPS
  local rx_new=$(cat /sys/class/net/$IFACE/statistics/rx_packets 2>/dev/null || echo 0)
  local pps=$(( (rx_new - RX_PKTS) / INTERVAL )); RX_PKTS=$rx_new
  # retrans rate
  local retrans_new=$(get_tcp_ext TCPRetransSegs)
  local segs_new=$(get_tcp_ext TCPSegsOut)
  local d_retrans=$(( retrans_new - RETRANS )); local d_segs=$(( segs_new - SEGS ))
  RETRANS=$retrans_new; SEGS=$segs_new
  local rate_scaled=0
  if [ "$d_segs" -gt 0 ]; then rate_scaled=$(( d_retrans * EWMA_SCALE / d_segs )); fi
  EWMA_RETRANS=$(( (EWMA_RETRANS*(EWMA_SCALE - ALPHA) + rate_scaled*ALPHA) / EWMA_SCALE ))
  # adaptive coalesce: 5 bands, also uses EWMA smoothing
  local target_usecs=250
  if [ "$pps" -gt 500000 ]; then target_usecs=20
  elif [ "$pps" -gt 300000 ]; then target_usecs=40
  elif [ "$pps" -gt 150000 ]; then target_usecs=80
  elif [ "$pps" -gt 50000 ]; then target_usecs=125
  else target_usecs=250; fi
  # if EWMA retrans high, decrease usecs (improve latency)
  if [ "$EWMA_RETRANS" -gt 150 ]; then target_usecs=$(( target_usecs / 2 )); fi
  if [ "$target_usecs" -ne "$CURRENT_USECS" ]; then
    local now=$(date +%s)
    if [ $(( now - LAST_ADJUST )) -gt $COOLDOWN ]; then
      if ethtool -C "$IFACE" rx-usecs "$target_usecs" 2>/dev/null; then
        log "COALESCE: pps=$pps ewma_retrans=$(awk -v r=$EWMA_RETRANS 'BEGIN{printf \"%.4f\", r/10000}') -> usecs=$target_usecs"
        CURRENT_USECS=$target_usecs; LAST_ADJUST=$now
      fi
    fi
  fi
  # adaptive buffer changes (protected): shrink on high retrans, increase on low retrans+high throughput
  local nowt=$(date +%s)
  # throughput
  rx_b=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
  tx_b=$(cat /sys/class/net/$IFACE/statistics/tx_bytes 2>/dev/null || echo 0)
  total_mbps=$(( ( (rx_b - RX_BYTES) + (tx_b - RX_BYTES) ) * 8 / INTERVAL / 1000000 )) || true
  RX_BYTES=$rx_b
  # shrink if ewma_retrans > 1.5% (scaled EWMA_RETRANS > 150)
  if [ $(( nowt - LAST_ADJUST )) -gt $COOLDOWN ] && [ "$EWMA_RETRANS" -gt 150 ]; then
    cur=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    new=$(( cur * 95 / 100 )); [ "$new" -lt 65536 ] && new=65536
    sysctl -w net.core.rmem_max=$new net.core.wmem_max=$new >/dev/null 2>&1 && { log "BUFFER-: ewma_retrans->${EWMA_RETRANS} set rmem=$new"; LAST_ADJUST=$nowt; }
  fi
  # increase if ewma small and traffic large (>200Mbps)
  if [ $(( nowt - LAST_ADJUST )) -gt $COOLDOWN ] && [ "$EWMA_RETRANS" -lt 50 ] && [ "${total_mbps:-0}" -gt 200 ]; then
    cur=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
    new=$(( cur * 102 / 100 )); maxcap=$((512*1024*1024)); [ "$new" -gt "$maxcap" ] && new=$maxcap
    sysctl -w net.core.rmem_max=$new net.core.wmem_max=$new >/dev/null 2>&1 && { log "BUFFER+: traffic=${total_mbps}Mbps ewma=${EWMA_RETRANS} -> rmem=$new"; LAST_ADJUST=$nowt; }
  fi
  # Prometheus textfile export (basic)
  mkdir -p /var/lib/node_exporter/textfile_collector 2>/dev/null || true
  echo "# TYPE proxy_opt_retrans gauge" > /var/lib/node_exporter/textfile_collector/proxy_opt.prom
  awk -v r="$EWMA_RETRANS" 'BEGIN{printf "proxy_opt_retrans %.4f\n", r/10000}' >> /var/lib/node_exporter/textfile_collector/proxy_opt.prom
  echo "proxy_opt_pps $pps" >> /var/lib/node_exporter/textfile_collector/proxy_opt.prom
done
MON
  sed -i "s|__IFACE__|$iface|g" "$TMP/monitor.sh"
  run_cmd "install -m 0755 '$TMP/monitor.sh' '$MONITOR_SCRIPT'"
  cat > "$TMP/monitor.service" <<SVC
[Unit]
Description=Proxy Ultimate Monitor
After=network.target

[Service]
Type=simple
ExecStart=$MONITOR_SCRIPT
Restart=always
RestartSec=10
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC
  run_cmd "install -m 0644 '$TMP/monitor.service' '$MONITOR_SERVICE'"
  run_cmd "systemctl daemon-reload || true"
  run_cmd "systemctl enable --now proxy-ultimate-monitor.service || true"
  _ok "Monitor installed/enabled (dry-run may have skipped actions)"
  # logrotate
  cat > "$TMP/logrotate" <<LR
/var/log/proxy-ultimate-monitor.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root adm
    su root adm
}
LR
  run_cmd "install -m 0644 '$TMP/logrotate' '$LOGROTATE_FILE' || true"
  _ok "Logrotate config installed"
}

### ========== Healthcheck script ==========
install_healthcheck(){
  _section "Install healthcheck"
  cat > "$TMP/health.sh" <<'HC'
#!/usr/bin/env bash
set -euo pipefail
iface="__IFACE__"
cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
if ! echo "$cc" | grep -qw "bbr"; then echo "BBR_NOT_ENABLED:$cc" >&2; exit 1; fi
rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
if [ "$rmem" -lt 65536 ]; then echo "RBUF_SMALL:$rmem" >&2; exit 1; fi
if ! tc qdisc show dev "$iface" | grep -q -E 'fq|cake'; then echo "QDISC_BAD" >&2; exit 1; fi
echo "OK"
exit 0
HC
  sed -i "s|__IFACE__|$iface|g" "$TMP/health.sh"
  run_cmd "install -m 0755 '$TMP/health.sh' '$HEALTH_SCRIPT'"
  _ok "Healthcheck script installed at $HEALTH_SCRIPT (dry-run may skip)"
}

### ========== Perf automation (optional) ==========
install_perf_script(){
  _section "Install perf automation (optional)"
  cat > "$TMP/perf.sh" <<'PS'
#!/usr/bin/env bash
# Simple perf automation: requires iperf3 server and iperf3 installed
set -euo pipefail
if [ $# -lt 1 ]; then echo "Usage: $0 <iperf3-server>"; exit 2; fi
srv="$1"
out="/var/log/proxy-perf-$(date +%s).log"
echo "Running iperf3 TCP (8 streams) against $srv..."
iperf3 -c "$srv" -t 60 -P 8 | tee -a "$out"
echo "Running iperf3 UDP at max BW..."
iperf3 -c "$srv" -u -b 0 -t 30 | tee -a "$out"
echo "Results saved to $out"
PS
  run_cmd "install -m 0755 '$TMP/perf.sh' '$PERF_SCRIPT'"
  _ok "Perf automation script installed at $PERF_SCRIPT (dry-run may skip)"
}

### ========== Snapshot (before/after) ==========
snapshot(){
  tag="$1"
  if [ "${APPLY:-0}" -ne 1 ]; then _log "DRY: snapshot $tag skipped"; return; fi
  d="/var/log/proxy-opt-${tag}-$(date +%s)"
  mkdir -p "$d"
  ip addr > "$d/ip_addr.txt" 2>/dev/null || true
  ethtool -i "$iface" > "$d/ethtool_i.txt" 2>/dev/null || true
  ethtool -g "$iface" > "$d/ethtool_g.txt" 2>/dev/null || true
  sysctl -a > "$d/sysctl_all.txt" 2>/dev/null || true
  ss -s > "$d/ss_s.txt" 2>/dev/null || true
  _ok "Saved snapshot to $d"
}

### ========== Speedtest helper (optional) ==========
run_optional_speedtest(){
  if [ -n "$IPERF_SERVER" ] && has iperf3 && [ "${APPLY:-0}" -eq 1 ]; then
    _section "Running iperf3 speedtest to $IPERF_SERVER"
    iperf3 -c "$IPERF_SERVER" -t 20 -P 8 || _warn "iperf3 tcp failed"
    iperf3 -c "$IPERF_SERVER" -u -b ${NET[bw]}M -t 20 || _warn "iperf3 udp failed"
  else
    _log "iperf3 test skipped (need --iperf-server and iperf3 installed and --apply)"
  fi
}

### ========== Main ==========
main(){
  _section "Start main"
  snapshot before
  detect_rtt
  detect_bw
  calc_buffers
  detect_bbr
  gen_sysctl
  optimize_nic
  opt_irq_rps_xps
  opt_conntrack
  opt_cpu
  if [ "${ENABLE_XDP:-0}" -eq 1 ]; then opt_xdp; fi
  if [ "${ENABLE_MONITOR:-1}" -eq 1 ]; then install_monitor; fi
  install_healthcheck
  install_perf_script
  snapshot after
  run_optional_speedtest
  _ok "All steps attempted (APPLY=${APPLY})"
  # final report summary
  cat <<SUM

Summary:
  Interface: $iface
  Driver: ${NIC[driver]}
  Bandwidth estimate: ${NET[bw]} Mbps
  RTT estimate: ${NET[rtt]} ms
  BDP: ${NET[bdp]} bytes (~${NET[bdp_mb]} MB)
  TCP rmem_max: ${NET[tcp_rmem_max]}
  UDP mem pages: ${NET[udp_mem_min]}/${NET[udp_mem_prs]}/${NET[udp_mem_max]}
  Conntrack max: ${NET[conntrack]}
  BBR best detected: ${NET[bbr_best]:-unknown}
  Monitor: ${ENABLE_MONITOR}
  XDP attempted: ${ENABLE_XDP}
  Perf script: ${PERF_SCRIPT}
  Healthcheck: ${HEALTH_SCRIPT}

Notes:
  - This script uses vendor/community tips:
    - SO_ZEROCOPY / UDP_SEGMENT (app-level) recommended for UDP bulk sending
    - net.ipv4.tcp_pacing_ca_ratio tuning is applicable for BBRv3 (if present)
    - Ring buffers set to 75% of max (Netflix suggestion)
    - conntrack liberal/loose flags applied (Alibaba suggestion)
    - virtio-specific ethtool hints attempted for EC2
    - tx-udp-segmentation attempted on kernel >=5.18
  - Heavy changes (kernel install/reboot, GRUB params) are optional and not auto-applied.

SUM
}

# Run installs as needed (XanMod optional)
if [ "${INSTALL_XANMOD:-0}" -eq 1 ]; then
  _section "Install XanMod (attempt)"
  if ! has curl; then run_cmd "apt-get update -qq && apt-get install -y -qq curl gnupg2 || true"; fi
  run_cmd "curl -fsSL https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg || true"
  run_cmd "echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod.list"
  run_cmd "apt-get update -qq && apt-get install -y -qq linux-xanmod || true"
  _ok "XanMod install attempted (reboot required to use new kernel)"
fi

main

# End
