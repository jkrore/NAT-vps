#!/usr/bin/env bash
# ============================================================
# 代理翻墙网络终极优化脚本 v3.0 (修正版)
# 基于用户上传文件：新文件 1.txt
# 修复项见顶部注释
# ============================================================

set -euo pipefail
IFS=$'\n\t'

# ============================================================
# 元信息
# ============================================================
readonly VERSION="3.0-production-fixed"
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 工作目录 & 路径
readonly TMP_DIR="/tmp/proxy-opt-$$"
readonly STATE_DIR="/var/lib/proxy-optimizer"
readonly STATE_FILE="${STATE_DIR}/state.conf"
readonly LOCK_FILE="/var/lock/proxy-optimizer.lock"

readonly SYSCTL_FILE="/etc/sysctl.d/99-proxy-ultimate.conf"
readonly MONITOR_SCRIPT="/usr/local/bin/proxy-ultimate-monitor.sh"
readonly MONITOR_SERVICE="/etc/systemd/system/proxy-ultimate-monitor.service"
readonly HEALTH_SCRIPT="/usr/local/bin/proxy-probe-health.sh"
readonly LOG_FILE="/var/log/proxy-optimizer.log"

# 保证清理
cleanup() {
  rm -rf "$TMP_DIR"
  rm -f "$LOCK_FILE"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR" "$STATE_DIR"

# ============================================================
# 日志与帮助函数
# ============================================================
log() {
  local level="$1"; shift
  local msg="$*"
  local timestamp
  timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo "[$timestamp] [$level] $msg" | tee -a "$LOG_FILE"
}

_log() { printf "\033[36m[%s]\033[0m %s\n" "$(date +%T)" "$*"; log "INFO" "$*"; }
_ok()  { printf "\033[32m[✓]\033[0m %s\n" "$*"; log "OK" "$*"; }
_warn(){ printf "\033[33m[!]\033[0m %s\n" "$*" >&2; log "WARN" "$*"; }
_err(){ printf "\033[31m[✗]\033[0m %s\n" "$*" >&2; log "ERROR" "$*"; exit 1; }
_section(){ printf "\n\033[1;35m╔══════════════════════════════════════════╗\033[0m\n"; printf "\033[1;35m║  %-38s║\033[0m\n" "$*"; printf "\033[1;35m╚══════════════════════════════════════════╝\033[0m\n"; log "SECTION" "$*"; }
_debug(){ [ "${DEBUG:-0}" = "1" ] && { printf "\033[90m[DEBUG] %s\033[0m\n" "$*" >&2; log "DEBUG" "$*"; }; }

has(){ command -v "$1" >/dev/null 2>&1; }

to_int(){ local v="${1:-0}"; v="${v//[^0-9]/}"; if [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -ge 0 ]; then echo "$v"; else echo "0"; fi }

is_valid_int(){ local v="$1"; [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -gt 0 ] 2>/dev/null; }

safe_run(){ _debug "执行命令: $*"; if eval "$@" 2>&1 | tee -a "$LOG_FILE" >/dev/null; then return 0; else _debug "命令失败: $*"; return 1; fi }

pause(){ echo; echo "按回车键继续..."; read -r || true; }

cpu_mask_hex(){ local n; n=$(to_int "$1"); [ "$n" -le 0 ] && echo "1" && return; [ "$n" -ge 64 ] && echo "ffffffffffffffff" && return; if [ "$n" -lt 61 ]; then printf '%x' $(( (1 << n) - 1 )); elif has python3; then python3 -c "n=$n; print(format((1<<n)-1,'x'))" 2>/dev/null || echo "ffffffffffffffff"; else echo "ffffffffffffffff"; fi }

# ============================================================
# 状态（关联数组）
# ============================================================
declare -A STATE=( [mode]="aggressive" [force_rtt]="" [force_bw]="" [selected_region]="" [selected_isp]="" [selected_ip]="" [selected_rtt]="" [system_detected]="0" [network_detected]="0" [buffers_calculated]="0" [optimization_applied]="0" )
declare -A SYS=()
declare -A NET=()
declare -A NIC=()

save_state(){
  local tmp_file="${STATE_FILE}.tmp"
  cat > "$tmp_file" <<EOF
# Proxy Optimizer State File
# Generated: $(date)
# Version: $VERSION
MODE="${STATE[mode]}"
FORCE_RTT="${STATE[force_rtt]}"
FORCE_BW="${STATE[force_bw]}"
SELECTED_REGION="${STATE[selected_region]}"
SELECTED_ISP="${STATE[selected_isp]}"
SELECTED_IP="${STATE[selected_ip]}"
SELECTED_RTT="${STATE[selected_rtt]}"
SYSTEM_DETECTED="${STATE[system_detected]}"
NETWORK_DETECTED="${STATE[network_detected]}"
BUFFERS_CALCULATED="${STATE[buffers_calculated]}"
OPTIMIZATION_APPLIED="${STATE[optimization_applied]}"
EOF
  if [ "${STATE[system_detected]}" = "1" ]; then
    {
      echo "# SYS Array"
      for key in "${!SYS[@]}"; do printf "SYS[%s]=%q\n" "$key" "${SYS[$key]}"; done
      echo "# NET Array"
      for key in "${!NET[@]}"; do printf "NET[%s]=%q\n" "$key" "${NET[$key]}"; done
      echo "# NIC Array"
      for key in "${!NIC[@]}"; do printf "NIC[%s]=%q\n" "$key" "${NIC[$key]}"; done
    } >> "$tmp_file"
  fi
  mv -f "$tmp_file" "$STATE_FILE"
  chmod 600 "$STATE_FILE"
  _debug "状态已保存到 $STATE_FILE"
}

load_state(){ if [ ! -f "$STATE_FILE" ]; then _debug "状态文件不存在，使用默认值"; return 0; fi; _debug "加载状态文件: $STATE_FILE"; if ! source "$STATE_FILE" 2>/dev/null; then _warn "状态文件损坏，已重置"; rm -f "$STATE_FILE"; return 1; fi; STATE[mode]="${MODE:-aggressive}"; STATE[force_rtt]="${FORCE_RTT:-}"; STATE[force_bw]="${FORCE_BW:-}"; STATE[selected_region]="${SELECTED_REGION:-}"; STATE[selected_isp]="${SELECTED_ISP:-}"; STATE[selected_ip]="${SELECTED_IP:-}"; STATE[selected_rtt]="${SELECTED_RTT:-}"; STATE[system_detected]="${SYSTEM_DETECTED:-0}"; STATE[network_detected]="${NETWORK_DETECTED:-0}"; STATE[buffers_calculated]="${BUFFERS_CALCULATED:-0}"; STATE[optimization_applied]="${OPTIMIZATION_APPLIED:-0}"; _debug "状态加载完成"; }

# ============================================================
# 地区与运营商数据
# ============================================================
declare -A REGIONS_IPV4=( ["上海"]="183.193.195.52 140.207.236.211 61.170.80.224" ["北京"]="111.132.33.234 123.126.74.241 220.181.141.62" ["广东"]="183.240.215.141 122.13.173.213 14.116.174.67" )
readonly ISP_LABELS=("移动" "联通" "电信")

# ============================================================
# 依赖检查
# ============================================================
check_root(){ if [ "$(id -u)" -ne 0 ]; then _err "必须使用 root 用户执行此脚本"; fi }
check_lock(){ if [ -f "$LOCK_FILE" ]; then local pid; pid=$(cat "$LOCK_FILE" 2>/dev/null || echo ""); if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then _err "脚本已在运行 (PID: $pid)"; else rm -f "$LOCK_FILE"; fi; fi; echo $$ > "$LOCK_FILE"; }
check_system_type(){ if ! has apt-get; then _err "仅支持 Debian/Ubuntu 系统"; fi; if [ -f /etc/os-release ]; then source /etc/os-release; _ok "系统: ${NAME:-Unknown} ${VERSION:-Unknown}"; fi }

install_dependencies(){ _section "检查并安装依赖"; local required_packages=(curl wget jq ethtool bc gnupg lsb-release ca-certificates net-tools sysstat iperf3); local missing_packages=(); for pkg in "${required_packages[@]}"; do if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then missing_packages+=("$pkg"); _debug "缺少包: $pkg"; fi; done; if [ ${#missing_packages[@]} -eq 0 ]; then _ok "所有依赖已安装"; return 0; fi; _log "需要安装 ${#missing_packages[@]} 个包: ${missing_packages[*]}"; if ! safe_run "apt-get update -qq"; then _warn "软件源更新失败，但将继续尝试安装"; fi; export DEBIAN_FRONTEND=noninteractive; if safe_run "apt-get install -y -qq ${missing_packages[*]} --no-install-recommends"; then _ok "依赖安装完成"; else _warn "部分依赖安装失败，某些功能可能受限"; fi }

# ============================================================
# 系统检测与网络检测
# ============================================================
detect_system_info(){ _section "系统信息检测"; SYS[kernel]=$(uname -r); SYS[cpu]=$(nproc); SYS[mem_kb]=$(awk '/MemTotal/ {print $2}' /proc/meminfo); SYS[mem_bytes]=$((SYS[mem_kb] * 1024)); SYS[mem_gb]=$(awk -v b="${SYS[mem_bytes]}" 'BEGIN{printf "%.1f", b/1024/1024/1024}'); if has systemd-detect-virt; then SYS[virt]=$(systemd-detect-virt 2>/dev/null || echo "unknown"); else SYS[virt]="unknown"; fi; SYS[numa_nodes]=$(lscpu 2>/dev/null | awk '/^NUMA node\(s\):/ {print $NF}' || echo 1); SYS[iface]=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1); if [ -z "${SYS[iface]}" ]; then SYS[iface]=$(ip -o link show | awk -F': ' '$2!~/lo|virbr|docker|veth/ {print $2; exit}'); fi; if [ -z "${SYS[iface]}" ]; then _err "无法检测主网卡接口"; fi; local iface="${SYS[iface]}"; NIC[driver]=$(ethtool -i "$iface" 2>/dev/null | awk '/driver:/ {print $2}' || echo "unknown"); NIC[queues]=$(ethtool -l "$iface" 2>/dev/null | awk '/Combined:/ {print $2; exit}' || echo "1"); local rx_output; rx_output=$(ethtool -g "$iface" 2>/dev/null || true); if [ -n "$rx_output" ]; then NIC[rx_max]=$(echo "$rx_output" | awk '/RX:/ {getline; if($1 ~ /^[0-9]+$/) print $1; else print 0}' || echo 0); NIC[tx_max]=$(echo "$rx_output" | awk '/TX:/ {getline; if($1 ~ /^[0-9]+$/) print $1; else print 0}' || echo 0); else NIC[rx_max]=0; NIC[tx_max]=0; fi; NIC[rx_max]=$(to_int "${NIC[rx_max]}"); NIC[tx_max]=$(to_int "${NIC[tx_max]}"); NIC[numa]=$(cat "/sys/class/net/$iface/device/numa_node" 2>/dev/null || echo "-1"); STATE[system_detected]=1; save_state; _ok "内核: ${SYS[kernel]}"; _ok "CPU: ${SYS[cpu]} 核心"; _ok "内存: ${SYS[mem_gb]} GB"; _ok "网卡: ${iface} (驱动: ${NIC[driver]})"; _ok "虚拟化: ${SYS[virt]}"; }

# 网络检测

detect_network_params(){ _section "网络参数检测"; local rtt_source="auto"; if [ -n "${STATE[force_rtt]}" ] && [ "${STATE[force_rtt]}" != "0" ]; then NET[rtt]="${STATE[force_rtt]}"; rtt_source="manual"; elif [ -n "${STATE[selected_rtt]}" ] && [ "${STATE[selected_rtt]}" != "0" ]; then NET[rtt]="${STATE[selected_rtt]}"; rtt_source="probe"; else _log "向多个 DNS 发送 ping 检测 RTT..."; declare -A targets=( [1.1.1.1]=5 [8.8.8.8]=3 [9.9.9.9]=2 ); local total_weighted=0 total_weight=0; for target in "${!targets[@]}"; do local weight=${targets[$target]}; if ping -c 4 -W 2 -i 0.2 "$target" >"${TMP_DIR}/ping_${target//./}" 2>/dev/null; then local median; median=$(grep -Eo 'time=[0-9.]+' "${TMP_DIR}/ping_${target//./}" | awk -F= '{print $2}' | sort -n | awk 'NR==2{print; exit}' || true); if [ -n "$median" ]; then total_weighted=$(awk -v a="$total_weighted" -v m="$median" -v w="$weight" 'BEGIN{printf "%.2f", a + m*w}'); total_weight=$((total_weight + weight)); _log "  $target: ${median}ms"; fi; fi; done; if [ "$total_weight" -gt 0 ]; then NET[rtt]=$(awk -v a="$total_weighted" -v w="$total_weight" 'BEGIN{printf "%.0f", a/w}'); else NET[rtt]=50; _warn "RTT 检测失败，使用默认值"; fi; fi; _ok "RTT: ${NET[rtt]} ms (来源: $rtt_source)";
  # 带宽检测
  local bw_source="auto"
  if [ -n "${STATE[force_bw]}" ] && [ "${STATE[force_bw]}" != "0" ]; then
    NET[bw]="${STATE[force_bw]}"
    bw_source="manual"
  else
    local link_speed
    link_speed=$(ethtool "${SYS[iface]}" 2>/dev/null | awk '/Speed:/ {print $2}' | tr -cd '0-9') || true
    if [ -n "$link_speed" ] && [ "$link_speed" -gt 0 ]; then
      NET[bw]="$link_speed"
    else
      local cpu_bw mem_bw
      cpu_bw=$((SYS[cpu] * 500))
      mem_bw=$(awk -v m="${SYS[mem_gb]}" 'BEGIN{printf "%.0f", m*400}')
      NET[bw]=$(( (cpu_bw < mem_bw ? cpu_bw : mem_bw) * 80 / 100 ))
      [ "${NET[bw]}" -lt 10 ] && NET[bw]=10
    fi
  fi
  _ok "带宽: ${NET[bw]} Mbps (来源: $bw_source)"

  # BBR 检测
  local avail_cc
  avail_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
  NET[avail_cc]="$avail_cc"
  local best_bbr="none"
  for mod in tcp_bbr3 tcp_bbrv2 tcp_bbr2 tcp_bbr; do
    if grep -qw "$mod" /proc/modules 2>/dev/null || echo "$avail_cc" | grep -qw "${mod#tcp_}"; then
      best_bbr="$mod"
      break
    fi
  done
  NET[bbr_best]="$best_bbr"
  _ok "BBR: $best_bbr"

  STATE[network_detected]=1
  save_state
}

# 计算缓冲区
calculate_buffers(){ _section "计算缓冲区参数"; if [ "${STATE[network_detected]}" != "1" ]; then _warn "请先检测网络参数"; return 1; fi; local bw rtt mode; bw=${NET[bw]}; rtt=${NET[rtt]}; mode=${STATE[mode]}; local bdp; bdp=$(awk -v bw="$bw" -v rtt="$rtt" 'BEGIN{printf "%.0f", bw*125*rtt}'); NET[bdp]=$bdp; NET[bdp_mb]=$(awk -v b="$bdp" 'BEGIN{printf "%.2f", b/1024/1024}'); _log "BDP: ${bdp} bytes (${NET[bdp_mb]} MB)"; local mem15 mem10; mem15=$((SYS[mem_bytes] * 15 / 100)); mem10=$((SYS[mem_bytes] * 10 / 100)); local mult=3; case "$mode" in aggressive) mult=4 ;; latency) mult=2 ;; esac; local tcp_max; tcp_max=$((bdp * mult)); [ "$tcp_max" -gt "$mem15" ] && tcp_max=$mem15; [ "$tcp_max" -lt 65536 ] && tcp_max=65536; NET[tcp_rmem_max]=$tcp_max; NET[tcp_wmem_max]=$tcp_max; NET[tcp_rmem_def]=131072; NET[tcp_rmem_min]=4096; NET[tcp_wmem_def]=131072; NET[tcp_wmem_min]=4096; _ok "TCP 缓冲: 最大=$((tcp_max/1024/1024))MB"; local udp_max; udp_max=$((bdp * 2)); [ "$udp_max" -gt "$mem10" ] && udp_max=$mem10; [ "$udp_max" -lt 65536 ] && udp_max=65536; NET[udp_rmem_min]=16384; NET[udp_wmem_min]=16384; local page=4096; NET[udp_mem_min]=$((udp_max / page / 4)); NET[udp_mem_prs]=$((udp_max / page / 2)); NET[udp_mem_max]=$((udp_max / page)); _ok "UDP 缓冲: 最大=$((udp_max/1024/1024))MB"; local backlog; backlog=$((bw * 100)); [ "$backlog" -lt 10000 ] && backlog=10000; [ "$backlog" -gt 1000000 ] && backlog=1000000; NET[backlog]=$backlog; NET[budget]=$((backlog / 10)); local ct; ct=$((SYS[mem_bytes] / 32768)); [ "$ct" -lt 65536 ] && ct=65536; [ "$ct" -gt 524288 ] && ct=524288; NET[conntrack]=$ct; _ok "Backlog: $backlog, Conntrack: $ct"; STATE[buffers_calculated]=1; save_state; }

# ============================================================
# 网卡 / IRQ / 优化函数
# ============================================================
show_region_menu(){ clear; _section "选择探测点"; echo; printf "\033[1;36m%-4s %-10s %-20s %-20s %-20s\033[0m\n" "ID" "地区" "${ISP_LABELS[0]}" "${ISP_LABELS[1]}" "${ISP_LABELS[2]}"; echo "────────────────────────────────────────────────────────────────────────"; local idx=1; for region in $(printf "%s\n" "${!REGIONS_IPV4[@]}" | sort); do read -r ip_cm ip_cu ip_ct <<< "${REGIONS_IPV4[$region]}"; printf "%-4s %-10s %-20s %-20s %-20s\n" "[$idx]" "$region" "$ip_cm" "$ip_cu" "$ip_ct"; idx=$((idx + 1)); done; echo; }

select_and_probe_region(){ show_region_menu; echo -n "请输入地区编号 (1-${#REGIONS_IPV4[@]}，0=取消): "; read -r region_id; [ "$region_id" = "0" ] && return 0; if ! is_valid_int "$region_id" || [ "$region_id" -gt "${#REGIONS_IPV4[@]}" ]; then _warn "无效编号"; pause; return 1; fi; mapfile -t sorted_regions < <(printf "%s\n" "${!REGIONS_IPV4[@]}" | sort); local region; region="${sorted_regions[$((region_id - 1))]}"; read -r ip_cm ip_cu ip_ct <<< "${REGIONS_IPV4[$region]}"; echo; echo "地区: $region"; echo "1. ${ISP_LABELS[0]} ($ip_cm)"; echo "2. ${ISP_LABELS[1]} ($ip_cu)"; echo "3. ${ISP_LABELS[2]} ($ip_ct)"; echo "0. 取消"; echo; echo -n "请选择运营商 (0-3): "; read -r isp_id; [ "$isp_id" = "0" ] && return 0; if ! [[ "$isp_id" =~ ^[1-3]$ ]]; then _warn "无效选择"; pause; return 1; fi; local target_ip isp_name; case "$isp_id" in 1) target_ip="$ip_cm"; isp_name="${ISP_LABELS[0]}" ;; 2) target_ip="$ip_cu"; isp_name="${ISP_LABELS[1]}" ;; 3) target_ip="$ip_ct"; isp_name="${ISP_LABELS[2]}" ;; esac; STATE[selected_region]="$region"; STATE[selected_isp]="$isp_name"; STATE[selected_ip]="$target_ip"; _section "探测节点"; _log "目标: $region - $isp_name ($target_ip)"; local rtt_ms=0; if ping -c 4 -W 2 "$target_ip" >"${TMP_DIR}/probe_ping" 2>&1; then rtt_ms=$(grep -Eo 'time=[0-9.]+' "${TMP_DIR}/probe_ping" | awk -F= '{print $2}' | sort -n | awk 'NR==2{print; exit}' || true); [ -z "$rtt_ms" ] && rtt_ms=$(grep -Eo 'time=[0-9.]+' "${TMP_DIR}/probe_ping" | awk -F= '{print $2}' | sort -n | awk 'END{print}' || true); _ok "ICMP Ping 成功: ${rtt_ms}ms"; else _warn "ICMP Ping 失败，尝试 TCP 探测..."; if has nc; then local start end; start=$(date +%s%3N 2>/dev/null || date +%s); if timeout 3 nc -zv "$target_ip" 80 >/dev/null 2>&1; then end=$(date +%s%3N 2>/dev/null || date +%s); rtt_ms=$((end - start)); _ok "TCP 探测成功: ${rtt_ms}ms"; else rtt_ms=999; _warn "TCP 探测失败，使用默认值"; fi; else rtt_ms=999; _warn "无探测工具，使用默认值"; fi; fi; STATE[selected_rtt]="$rtt_ms"; save_state; echo; _ok "════════════════════════════════════"; _ok "探测完成"; _ok "  地区: $region"; _ok "  运营商: $isp_name"; _ok "  IP: $target_ip"; _ok "  RTT: ${rtt_ms} ms"; _ok "════════════════════════════════════"; pause; }

apply_sysctl_optimization(){ _section "应用 Sysctl 优化"; if [ "${STATE[buffers_calculated]}" != "1" ]; then _warn "请先检测系统并计算参数（选项 2）"; return 1; fi; local mode somax; mode=${STATE[mode]}; somax=131072; [ "$mode" = "aggressive" ] && somax=262144; cat > "${TMP_DIR}/sysctl.conf" <<EOF
# Proxy Optimizer Sysctl Config
# Generated: $(date)
# Mode: $mode | RTT: ${NET[rtt]}ms | BW: ${NET[bw]}Mbps
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
net.ipv4.tcp_slow_start_after_idle = 0
net.core.somaxconn = $somax
net.ipv4.tcp_max_syn_backlog = $somax
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3
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
net.netfilter.nf_conntrack_tcp_be_liberal = 1
net.netfilter.nf_conntrack_tcp_loose = 1
vm.swappiness = 1
vm.vfs_cache_pressure = 50
vm.min_free_kbytes = 65536
fs.file-max = 2097152
fs.nr_open = 2097152
EOF
  install -m 0644 "${TMP_DIR}/sysctl.conf" "$SYSCTL_FILE"
  _log "应用 sysctl 配置..."
  local failed=0
  while IFS= read -r line; do
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "$line" ]] && continue
    if ! sysctl -w "$line" >/dev/null 2>&1; then _debug "失败: $line"; failed=$((failed + 1)); fi
  done < "$SYSCTL_FILE"
  if [ "$failed" -gt 0 ]; then _warn "有 $failed 项配置未生效（可能需要重启）"; else _ok "Sysctl 配置全部应用成功"; fi
  STATE[optimization_applied]=1
  save_state
}

optimize_network_card(){ _section "网卡硬件优化"; if [ "${STATE[system_detected]}" != "1" ]; then _warn "请先检测系统信息"; return 1; fi; local iface; iface="${SYS[iface]}"; local mode; mode="${STATE[mode]}"; if is_valid_int "${NIC[rx_max]}" && is_valid_int "${NIC[tx_max]}"; then if [ "${NIC[rx_max]}" -gt 512 ] && [ "${NIC[tx_max]}" -gt 512 ]; then local rx tx; rx=$((NIC[rx_max] * 75 / 100)); tx=$((NIC[tx_max] * 75 / 100)); [ "$rx" -lt 512 ] && rx=512; [ "$tx" -lt 512 ] && tx=512; if safe_run "ethtool -G '$iface' rx $rx tx $tx"; then _ok "Ring Buffer: RX=$rx TX=$tx"; fi; fi; fi; safe_run "ethtool -K '$iface' tso on gso on sg on"; if [[ "${SYS[virt]}" == *"kvm"* ]] || [[ "${NIC[driver]}" == *"virtio"* ]]; then _log "应用 VirtIO 优化..."; safe_run "ethtool -K '$iface' tx-nocache-copy off"; safe_run "ethtool -K '$iface' tx-checksum-ipv4 on"; fi; if [ "$mode" = "latency" ]; then safe_run "ethtool -K '$iface' gro off lro off"; _ok "已关闭 GRO/LRO (latency模式)"; else safe_run "ethtool -K '$iface' gro on"; safe_run "ethtool -K '$iface' rx-gro-list on"; safe_run "ethtool -K '$iface' rx-udp-gro-forwarding on"; _ok "已启用 GRO"; fi; local rx_usecs rx_frames; case "$mode" in latency) rx_usecs=30; rx_frames=16 ;; aggressive) rx_usecs=100; rx_frames=64 ;; *) rx_usecs=200; rx_frames=128 ;; esac; if safe_run "ethtool -C '$iface' rx-usecs $rx_usecs rx-frames $rx_frames adaptive-rx off"; then _ok "Coalesce: rx-usecs=$rx_usecs"; fi; local desired; desired=${SYS[cpu]}; [ "$desired" -gt 32 ] && desired=32; if is_valid_int "${NIC[queues]}" && [ "$desired" -gt "${NIC[queues]}" ]; then desired=${NIC[queues]}; fi; safe_run "ethtool -L '$iface' combined $desired"; _ok "队列数: $desired"; }

optimize_irq_rps_xps(){ _section "IRQ/RPS/XPS 优化"; if [ "${STATE[system_detected]}" != "1" ]; then _warn "请先检测系统信息"; return 1; fi; local iface; iface="${SYS[iface]}"; local mask; mask=$(cpu_mask_hex "${SYS[cpu]}"); local qdir="/sys/class/net/$iface/queues"; [ ! -d "$qdir" ] && { _warn "队列目录不存在"; return 1; }; local rps_cnt=0; for rxq in "$qdir"/rx-*; do [ ! -e "$rxq/rps_cpus" ] && continue; echo "$mask" > "$rxq/rps_cpus" 2>/dev/null && rps_cnt=$((rps_cnt+1)); echo 4096 > "$rxq/rps_flow_cnt" 2>/dev/null || true; done; [ "$rps_cnt" -gt 0 ] && _ok "RPS: $rps_cnt 个队列"; local tx_idx=0 xps_cnt=0; for txq in "$qdir"/tx-*; do [ ! -e "$txq/xps_cpus" ] && continue; local cpu_idx=$((tx_idx % SYS[cpu])); local single; single=$(printf '%x' $((1<<cpu_idx))); echo "$single" > "$txq/xps_cpus" 2>/dev/null && xps_cnt=$((xps_cnt+1)); tx_idx=$((tx_idx+1)); done; [ "$xps_cnt" -gt 0 ] && _ok "XPS: $xps_cnt 个队列"; }

optimize_conntrack(){ _section "Conntrack 优化"; [ "${STATE[buffers_calculated]}" != "1" ] && { _warn "请先计算参数"; return 1; }; local ct; ct=${NET[conntrack]}; sysctl -w net.netfilter.nf_conntrack_max=$ct >/dev/null 2>&1 || true; local hash=$((ct / 4)); if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then echo "$hash" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null || true; _ok "Conntrack: max=$ct hashsize=$hash"; fi; sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1 || true; sysctl -w net.netfilter.nf_conntrack_tcp_loose=1 >/dev/null 2>&1 || true; }

optimize_cpu(){ _section "CPU 优化"; if has cpupower; then safe_run "cpupower frequency-set -g performance"; _ok "CPU 频率: performance"; fi; if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || true; echo defer > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null || true; _ok "透明大页: madvise"; fi; }

# ============================================================
# 内核安装（XanMod / BBR v3），修复重复/条件判断问题
# ============================================================
check_current_kernel(){ local current; current=$(uname -r); if [[ "$current" == *"xanmod"* ]]; then echo "xanmod"; elif [[ "$current" == *"bbr"* ]] || dpkg -l 2>/dev/null | grep -q "joeyblog"; then echo "bbr3"; else echo "stock"; fi }

install_xanmod_kernel(){ _section "安装 XanMod 内核"; local current_type; current_type=$(check_current_kernel); if [ "$current_type" = "xanmod" ]; then _ok "已安装 XanMod 内核"; echo "当前内核: $(uname -r)"; echo; echo -n "是否重新安装? (y/N): "; read -r confirm; [[ "${confirm,,}" != "y" ]] && return 0; fi; _log "添加 XanMod 仓库..."; if ! safe_run "curl -fsSL https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg"; then _warn "无法添加 XanMod 密钥"; install_bbr3_kernel; return; fi; echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod.list; _log "更新软件源..."; if ! safe_run "apt-get update -qq"; then _warn "软件源更新失败"; install_bbr3_kernel; return; fi; _log "安装 XanMod 内核..."; if safe_run "apt-get install -y -qq linux-xanmod"; then _ok "XanMod 安装成功"; echo; echo "⚠️  请重启系统以使用新内核"; echo; else _warn "XanMod 安装失败，尝试 BBR v3..."; install_bbr3_kernel; fi; pause; }

install_bbr3_kernel(){ _section "安装 BBR v3 内核"; local current_type; current_type=$(check_current_kernel); if [ "$current_type" = "bbr3" ]; then _ok "已安装 BBR v3 内核"; echo "当前内核: $(uname -r)"; echo; echo -n "是否重新安装? (y/N): "; read -r confirm; [[ "${confirm,,}" != "y" ]] && { pause; return 0; }; fi; local arch; arch=$(uname -m); local arch_filter; case "$arch" in x86_64) arch_filter="x86_64" ;; aarch64) arch_filter="arm64" ;; *) _err "不支持的架构: $arch" ;; esac; _log "从 GitHub 获取 BBR v3..."; local api_url="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases"; local release_data; if ! release_data=$(curl -sL "$api_url" 2>/dev/null); then _err "无法访问 GitHub API"; fi; local latest_tag; latest_tag=$(echo "$release_data" | jq -r --arg filter "$arch_filter" 'map(select(.tag_name | test($filter; "i"))) | sort_by(.published_at) | .[-1].tag_name' 2>/dev/null || true); if [ -z "$latest_tag" ] || [ "$latest_tag" = "null" ]; then _err "未找到适配版本"; fi; _ok "找到版本: $latest_tag"; local asset_urls; asset_urls=$(echo "$release_data" | jq -r --arg tag "$latest_tag" '.[] | select(.tag_name == $tag) | .assets[].browser_download_url' 2>/dev/null || true); rm -f /tmp/linux-*.deb 2>/dev/null || true; _log "下载内核包..."; local downloaded=0; for url in $asset_urls; do if wget -q --show-progress "$url" -P /tmp/; then downloaded=1; else _warn "下载失败: $url"; fi; done; if ! ls /tmp/linux-*.deb >/dev/null 2>&1 || [ $downloaded -eq 0 ]; then _err "下载失败"; fi; if [ "$current_type" = "bbr3" ]; then _log "卸载旧版本..."; local old_pkgs; old_pkgs=$(dpkg -l 2>/dev/null | grep "joeyblog" | awk '{print $2}' | tr '\n' ' ' || true); [ -n "$old_pkgs" ] && safe_run "apt-get remove --purge -y $old_pkgs"; fi; _log "安装 BBR v3..."; safe_run "dpkg -i /tmp/linux-*.deb" || true; safe_run "apt-get install -f -y" || true; has update-grub && safe_run "update-grub" || true; _ok "BBR v3 安装完成"; echo; echo "⚠️  请重启系统"; echo; pause; }

# ============================================================
# 监控 / 健康检查
# ============================================================
install_monitoring(){ _section "安装监控服务"; [ "${STATE[system_detected]}" != "1" ] && { _warn "请先检测系统"; return 1; }; cat > "${TMP_DIR}/monitor.sh" <<'MONITOR'
#!/usr/bin/env bash
set -euo pipefail
IFACE="__IFACE__"
LOG="/var/log/proxy-ultimate-monitor.log"
INTERVAL=15
log(){ echo "[$(date +'%F %T')] $*" >> "$LOG"; }
while true; do
  sleep "$INTERVAL"
  rx_pkts=$(cat /sys/class/net/$IFACE/statistics/rx_packets 2>/dev/null || echo 0)
  tx_pkts=$(cat /sys/class/net/$IFACE/statistics/tx_packets 2>/dev/null || echo 0)
  mkdir -p /var/lib/node_exporter/textfile_collector 2>/dev/null || true
  {
    echo "# TYPE proxy_rx_packets counter"
    echo "proxy_rx_packets $rx_pkts"
    echo "# TYPE proxy_tx_packets counter"
    echo "proxy_tx_packets $tx_pkts"
  } > /var/lib/node_exporter/textfile_collector/proxy_opt.prom
  log "Stats: RX=$rx_pkts TX=$tx_pkts"
done
MONITOR
  sed -i "s|__IFACE__|${SYS[iface]}|g" "${TMP_DIR}/monitor.sh"
  install -m 0755 "${TMP_DIR}/monitor.sh" "$MONITOR_SCRIPT"
  cat > "${TMP_DIR}/monitor.service" <<SERVICE
[Unit]
Description=Proxy Network Monitor
After=network.target
[Service]
Type=simple
ExecStart=$MONITOR_SCRIPT
Restart=always
[Install]
WantedBy=multi-user.target
SERVICE
  install -m 0644 "${TMP_DIR}/monitor.service" "$MONITOR_SERVICE"
  systemctl daemon-reload
  systemctl enable --now proxy-ultimate-monitor.service || true
  _ok "监控服务已安装并启动"
}

install_health_check(){ _section "安装健康检查"; [ "${STATE[system_detected]}" != "1" ] && { _warn "请先检测系统"; return 1; }; cat > "${TMP_DIR}/health.sh" <<'HEALTH'
#!/usr/bin/env bash
set -euo pipefail
iface="__IFACE__"
cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
if ! echo "$cc" | grep -qw "bbr"; then echo "❌ BBR 未启用: $cc" >&2; exit 1; fi
rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
if [ "$rmem" -lt 65536 ]; then echo "❌ 缓冲区过小: $rmem" >&2; exit 1; fi
echo "✅ 健康检查通过"
exit 0
HEALTH
  sed -i "s|__IFACE__|${SYS[iface]}|g" "${TMP_DIR}/health.sh"
  install -m 0755 "${TMP_DIR}/health.sh" "$HEALTH_SCRIPT"
  _ok "健康检查脚本已安装: $HEALTH_SCRIPT"
}

run_health_check(){ _section "执行健康检查"; if [ ! -x "$HEALTH_SCRIPT" ]; then _warn "请先安装健康检查（选项 12）"; return 1; fi; if "$HEALTH_SCRIPT"; then _ok "健康检查通过"; else _warn "健康检查失败"; fi; pause; }

# ============================================================
# 完整优化流程与菜单
# ============================================================
run_full_optimization(){ _section "完整优化流程"; cat <<EOF
即将执行：
  1. 检测系统信息
  2. 检测网络参数（保留已设置值）
  3. 计算缓冲区
  4. 应用 Sysctl
  5. 优化网卡
  6. 优化 IRQ/RPS/XPS
  7. 优化 Conntrack
  8. 优化 CPU
  9. 安装监控
 10. 安装健康检查

当前设置将被保留：
  • RTT: ${STATE[force_rtt]:-${STATE[selected_rtt]:-自动检测}}
  • 带宽: ${STATE[force_bw]:-自动检测}
  • 模式: ${STATE[mode]}

EOF
  echo -n "继续? (y/N): "; read -r confirm; [[ "${confirm,,}" != "y" ]] && return 0
  detect_system_info
  detect_network_params
  calculate_buffers
  apply_sysctl_optimization
  optimize_network_card
  optimize_irq_rps_xps
  optimize_conntrack
  optimize_cpu
  install_monitoring
  install_health_check
  _section "优化完成"
  _ok "所有步骤已完成，建议重启系统以确保内核/网络参数生效"
  pause
}

show_intelligent_analysis(){ _section "智能分析与优化建议"; if [ "${STATE[system_detected]}" != "1" ]; then _warn "请先检测系统信息（选项 2）"; pause; return 1; fi; cat <<EOF

╔══════════════════════════════════════════════════════════════╗
║                     优化摘要                                   ║
╚══════════════════════════════════════════════════════════════╝

  🖥️  系统: ${SYS[kernel]}
  💻 CPU: ${SYS[cpu]} 核心 | 内存: ${SYS[mem_gb]} GB
  🌐 网卡: ${SYS[iface]} (${NIC[driver]})
  📊 带宽: ${NET[bw]} Mbps | RTT: ${NET[rtt]} ms
  🚀 BBR: ${NET[bbr_best]}
  ⚙️  模式: ${STATE[mode]}

  ✅ 优化已完成

EOF
  [ "${NET[bbr_best]}" = "none" ] && echo "  ⚠️  建议安装 XanMod 或 BBR v3 内核（选项 4）"
  echo
  echo "  💡 建议重启系统使所有配置生效"
  echo
  pause
}

show_main_menu(){ clear; cat <<'BANNER'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║       🚀 代理翻墙网络终极优化工具 v3.0 🚀                      ║
║                                                              ║
║          专为 Shadowsocks/V2Ray/Trojan/WireGuard 优化         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
BANNER
  echo
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  系统状态"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  if [ "${STATE[system_detected]}" = "1" ]; then printf "  内核: \033[32m%s\033[0m | CPU: \033[32m%s\033[0m 核 | 内存: \033[32m%s\033[0m GB\n" "${SYS[kernel]}" "${SYS[cpu]}" "${SYS[mem_gb]}"; else echo "  ⚠️  未检测系统信息（请运行选项 2）"; fi
  if [ "${STATE[network_detected]}" = "1" ]; then printf "  带宽: \033[32m%s\033[0m Mbps | RTT: \033[32m%s\033[0m ms | BBR: \033[32m%s\033[0m\n" "${NET[bw]}" "${NET[rtt]}" "${NET[bbr_best]}"; fi
  if [ -n "${STATE[selected_ip]}" ]; then printf "  探测点: \033[33m%s - %s\033[0m | RTT: \033[33m%s ms\033[0m\n" "${STATE[selected_region]}" "${STATE[selected_isp]}" "${STATE[selected_rtt]}"; fi
  printf "  当前模式: \033[36m%s\033[0m\n" "${STATE[mode]}"
  echo
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  主菜单"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo
  echo "  📍 探测与分析"
  echo "     1. 🌐 选择地区和运营商进行探测"
  echo "     2. 🔍 检测系统信息（CPU/内存/网卡）"
  echo "     3. 🧠 智能分析与优化建议"
  echo ""
  echo "  🔧 系统优化"
  echo "     4. 🚀 安装或升级内核（XanMod/BBR v3）"
  echo "     5. ⚙️  切换优化模式（当前: ${STATE[mode]})"
  echo "     6. 📊 手动设置 RTT 和带宽"
  echo "     7. 🔧 应用 Sysctl 配置"
  echo "     8. 🖧 优化网卡参数"
  echo "     9. ⚡ 优化 IRQ/RPS/XPS"
  echo "    10. 🎯 执行完整优化流程（推荐）"
  echo ""
  echo "  📈 监控与验证"
  echo "    11. ✅ 运行健康检查"
  echo "    12. 📈 安装监控服务"
  echo "    13. 📊 查看系统状态"
  echo "    14. 🔄 重置所有设置"
  echo ""
  echo "  ❓ 其他"
  echo "    15. 📚 查看使用说明"
  echo "     0. 🚪 退出程序"
  echo
}

show_usage_guide(){ clear; _section "使用说明"; cat <<'GUIDE'

快速开始 (略)

GUIDE
  pause
}

show_system_status(){ clear; _section "系统状态详情"; echo; echo "══════════════════════════════════════════════════════════="; echo "  系统信息"; echo "══════════════════════════════════════════════════════════="; uname -a; echo; if has lsb_release; then lsb_release -a 2>/dev/null || true; echo; fi; echo "══════════════════════════════════════════════════════════="; echo "  关键 Sysctl 参数"; echo "══════════════════════════════════════════════════════════="; sysctl net.ipv4.tcp_congestion_control 2>/dev/null || true; sysctl net.core.default_qdisc 2>/dev/null || true; sysctl net.core.rmem_max 2>/dev/null || true; sysctl net.core.wmem_max 2>/dev/null || true; sysctl net.netfilter.nf_conntrack_max 2>/dev/null || true; echo; if [ -n "${SYS[iface]:-}" ]; then echo "══════════════════════════════════════════════════════════="; echo "  网卡 ${SYS[iface]} 信息"; echo "══════════════════════════════════════════════════════════="; ethtool "${SYS[iface]}" 2>/dev/null || echo "无法获取信息"; echo; fi; pause; }

switch_mode(){ clear; _section "切换优化模式"; echo; echo "当前模式: ${STATE[mode]}"; echo; echo "可用模式:"; echo "  1. latency    - 低延迟优先（RTT > 100ms）"; echo "  2. normal     - 平衡模式（大多数场景）"; echo "  3. aggressive - 高吞吐优先（RTT < 50ms）"; echo "  0. 取消"; echo; echo -n "请选择 (0-3): "; read -r choice; case "$choice" in 1) STATE[mode]="latency"; _ok "已切换到 latency 模式" ;; 2) STATE[mode]="normal"; _ok "已切换到 normal 模式" ;; 3) STATE[mode]="aggressive"; _ok "已切换到 aggressive 模式" ;; 0) _log "已取消"; pause; return ;; *) _warn "无效选择"; pause; return ;; esac; save_state; echo; echo "模式已切换，建议重新计算缓冲区（选项 2）"; pause; }

manual_set_params(){ clear; _section "手动设置参数"; echo; echo "当前参数:"; echo "  RTT: ${NET[rtt]:-未设置} ms"; echo "  带宽: ${NET[bw]:-未设置} Mbps"; echo; echo -n "输入 RTT (毫秒，留空跳过): "; read -r rtt_input; if [ -n "$rtt_input" ]; then STATE[force_rtt]="$rtt_input"; NET[rtt]=$(to_int "$rtt_input"); _ok "已设置 RTT: ${NET[rtt]} ms"; fi; echo -n "输入带宽 (Mbps，留空跳过): "; read -r bw_input; if [ -n "$bw_input" ]; then STATE[force_bw]="$bw_input"; NET[bw]=$(to_int "$bw_input"); _ok "已设置带宽: ${NET[bw]} Mbps"; fi; if [ -n "$rtt_input" ] || [ -n "$bw_input" ]; then save_state; echo; echo -n "是否重新计算缓冲区? (y/N): "; read -r confirm; if [[ "${confirm,,}" = "y" ]]; then calculate_buffers; fi; fi; pause; }

reset_all_settings(){ clear; _section "重置所有设置"; echo; echo "⚠️  警告：此操作将："; echo "  • 删除所有保存的状态"; echo "  • 清除探测结果"; echo "  • 恢复默认模式"; echo; echo -n "确认重置? (yes/NO): "; read -r confirm; if [ "$confirm" = "yes" ]; then rm -f "$STATE_FILE"; STATE[mode]="aggressive"; STATE[force_rtt]=""; STATE[force_bw]=""; STATE[selected_region]=""; STATE[selected_isp]=""; STATE[selected_ip]=""; STATE[selected_rtt]=""; STATE[system_detected]="0"; STATE[network_detected]="0"; STATE[buffers_calculated]="0"; STATE[optimization_applied]="0"; SYS=(); NET=(); NIC=(); _ok "已重置所有设置"; else _log "已取消"; fi; pause; }

# ============================================================
# 主程序
# ============================================================
main(){ check_root; check_lock; check_system_type; load_state; install_dependencies; while true; do show_main_menu; echo -n "请选择操作 (0-15): "; read -r choice; case "$choice" in 0) echo; _ok "感谢使用，再见！"; exit 0 ;; 1) select_and_probe_region ;; 2) detect_system_info; detect_network_params; calculate_buffers; pause ;; 3) show_intelligent_analysis ;; 4) install_xanmod_kernel ;; 5) switch_mode ;; 6) manual_set_params ;; 7) apply_sysctl_optimization; pause ;; 8) optimize_network_card; pause ;; 9) optimize_irq_rps_xps; pause ;; 10) run_full_optimization ;; 11) run_health_check ;; 12) install_monitoring; pause ;; 13) show_system_status ;; 14) reset_all_settings ;; 15) show_usage_guide ;; *) _warn "无效选择"; sleep 2 ;; esac; done }

# 启动
main "$@"
