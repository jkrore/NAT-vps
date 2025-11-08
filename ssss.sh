#!/usr/bin/env bash
# ============================================================
# 代理服务器网络终极优化工具 v3.1
# 专为 Shadowsocks/V2Ray/Trojan/WireGuard 设计
# 架构：四段式执行逻辑 + 完整状态管理 + 智能分析
# ============================================================

set -euo pipefail
IFS=$'\n\t'

# ============================================================
# 阶段一：环境检查与准备
# ============================================================

readonly SCRIPT_VERSION="3.1-ultimate"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly TMP_DIR="/tmp/proxy-opt-$$"
readonly STATE_DIR="/var/lib/proxy-optimizer"
readonly STATE_FILE="${STATE_DIR}/state.conf"
readonly LOG_FILE="/var/log/proxy-optimizer.log"
readonly SYSCTL_FILE="/etc/sysctl.d/99-proxy-ultimate.conf"

# 清理函数
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR" "$STATE_DIR"

# 检查 Root 权限
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "\033[31m[✗] 请使用 root 用户执行此脚本\033[0m"
    exit 1
  fi
}

# 检查操作系统
check_os() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo -e "\033[31m[✗] 此脚本仅支持 Debian/Ubuntu 系统\033[0m"
    exit 1
  fi
  
  if [ -f /etc/os-release ]; then
    source /etc/os-release
    echo -e "\033[32m[✓] 系统: ${NAME:-Unknown} ${VERSION:-Unknown}\033[0m"
  fi
}

# 安装依赖（精确检查，无假报错）
install_dependencies() {
  echo -e "\033[36m[*] 检查系统依赖...\033[0m"
  
  local required=(curl wget jq ethtool bc gnupg lsb-release ca-certificates net-tools sysstat iperf3)
  local missing=()
  
  for pkg in "${required[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
      missing+=("$pkg")
    fi
  done
  
  if [ ${#missing[@]} -eq 0 ]; then
    echo -e "\033[32m[✓] 所有依赖已安装\033[0m"
    return 0
  fi
  
  echo -e "\033[33m[!] 需要安装: ${missing[*]}\033[0m"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq "${missing[@]}" --no-install-recommends >/dev/null 2>&1
  echo -e "\033[32m[✓] 依赖安装完成\033[0m"
}

check_root
check_os
install_dependencies

# ============================================================
# 阶段二：定义与状态管理
# ============================================================

# 日志函数
log_info() { echo -e "\033[36m[$(date +%T)]\033[0m $*" | tee -a "$LOG_FILE"; }
log_ok() { echo -e "\033[32m[✓]\033[0m $*" | tee -a "$LOG_FILE"; }
log_warn() { echo -e "\033[33m[!]\033[0m $*" | tee -a "$LOG_FILE" >&2; }
log_err() { echo -e "\033[31m[✗]\033[0m $*" | tee -a "$LOG_FILE" >&2; exit 1; }
log_section() { echo -e "\n\033[1;35m╔══════════════════════════════════════════╗\033[0m\n\033[1;35m║  $*\033[0m\n\033[1;35m╚══════════════════════════════════════════╝\033[0m"; }

# 工具函数
has() { command -v "$1" >/dev/null 2>&1; }
to_int() { local v="${1//[^0-9]/}"; [[ "$v" =~ ^[0-9]+$ ]] && echo "$v" || echo "0"; }
is_valid_int() { [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -gt 0 ] 2>/dev/null; }
pause() { echo ""; echo "按回车继续..."; read -r; }

# 状态变量
declare -A STATE=(
  [mode]="aggressive"
  [force_rtt]=""
  [force_bw]=""
  [region]=""
  [isp]=""
  [probe_ip]=""
  [probe_rtt]=""
  [sys_detected]="0"
  [net_detected]="0"
  [buf_calculated]="0"
)

declare -A SYS=() NET=() NIC=()

# 保存状态（原子写入）
save_state() {
  local tmp="${STATE_FILE}.tmp"
  cat > "$tmp" <<EOF
# Proxy Optimizer State - Generated: $(date)
MODE="${STATE[mode]}"
FORCE_RTT="${STATE[force_rtt]}"
FORCE_BW="${STATE[force_bw]}"
REGION="${STATE[region]}"
ISP="${STATE[isp]}"
PROBE_IP="${STATE[probe_ip]}"
PROBE_RTT="${STATE[probe_rtt]}"
SYS_DETECTED="${STATE[sys_detected]}"
NET_DETECTED="${STATE[net_detected]}"
BUF_CALCULATED="${STATE[buf_calculated]}"
EOF

  if [ "${STATE[sys_detected]}" = "1" ]; then
    for k in "${!SYS[@]}"; do printf "SYS[%s]=%q\n" "$k" "${SYS[$k]}"; done >> "$tmp"
    for k in "${!NET[@]}"; do printf "NET[%s]=%q\n" "$k" "${NET[$k]}"; done >> "$tmp"
    for k in "${!NIC[@]}"; do printf "NIC[%s]=%q\n" "$k" "${NIC[$k]}"; done >> "$tmp"
  fi
  
  mv -f "$tmp" "$STATE_FILE"
  chmod 600 "$STATE_FILE"
}

# 加载状态
load_state() {
  [ ! -f "$STATE_FILE" ] && return 0
  
  if ! source "$STATE_FILE" 2>/dev/null; then
    log_warn "状态文件损坏，已重置"
    rm -f "$STATE_FILE"
    return 1
  fi
  
  STATE[mode]="${MODE:-aggressive}"
  STATE[force_rtt]="${FORCE_RTT:-}"
  STATE[force_bw]="${FORCE_BW:-}"
  STATE[region]="${REGION:-}"
  STATE[isp]="${ISP:-}"
  STATE[probe_ip]="${PROBE_IP:-}"
  STATE[probe_rtt]="${PROBE_RTT:-}"
  STATE[sys_detected]="${SYS_DETECTED:-0}"
  STATE[net_detected]="${NET_DETECTED:-0}"
  STATE[buf_calculated]="${BUF_CALCULATED:-0}"
}

# 地域运营商数据
declare -A REGIONS=(
  ["上海"]="183.193.195.52 140.207.236.211 61.170.80.224"
  ["北京"]="111.132.33.234 123.126.74.241 220.181.141.62"
  ["广东"]="183.240.215.141 122.13.173.213 14.116.174.67"
  ["江苏"]="36.150.72.122 218.98.46.62 221.229.203.57"
  ["浙江"]="112.13.210.86 124.160.144.214 122.228.6.140"
  ["四川"]="112.45.29.107 119.6.226.87 182.140.222.120"
  ["湖北"]="111.48.204.91 122.188.1.46 171.43.200.232"
  ["河南"]="111.7.88.239 123.6.6.95 36.99.32.68"
  ["山东"]="120.220.200.235 116.196.134.235 140.249.226.28"
  ["福建"]="183.253.58.91 36.248.50.117 125.77.141.147"
)
readonly ISP_LIST=("移动" "联通" "电信")

load_state

# ============================================================
# 阶段四：核心功能执行
# ============================================================

# 系统检测
detect_system() {
  log_section "系统信息检测"
  
  SYS[kernel]=$(uname -r)
  SYS[cpu]=$(nproc)
  SYS[mem_kb]=$(awk '/MemTotal/{print $2}' /proc/meminfo)
  SYS[mem_gb]=$(awk -v k="${SYS[mem_kb]}" 'BEGIN{printf "%.1f", k/1024/1024}')
  SYS[virt]=$(systemd-detect-virt 2>/dev/null || echo "unknown")
  
  SYS[iface]=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1)
  [ -z "${SYS[iface]}" ] && SYS[iface]=$(ip -o link show | awk -F': ' '$2!~/lo|virbr|docker|veth/{print $2; exit}')
  [ -z "${SYS[iface]}" ] && log_err "无法检测主网卡"
  
  local iface="${SYS[iface]}"
  NIC[driver]=$(ethtool -i "$iface" 2>/dev/null | awk '/driver:/{print $2}' || echo "unknown")
  NIC[queues]=$(ethtool -l "$iface" 2>/dev/null | awk '/Combined:/{print $2; exit}' || echo "1")
  
  local rx_out=$(ethtool -g "$iface" 2>/dev/null || true)
  NIC[rx_max]=$(echo "$rx_out" | awk '/^RX:/{getline; if($1~/^[0-9]+$/) print $1; else print 0}' || echo 0)
  NIC[tx_max]=$(echo "$rx_out" | awk '/^TX:/{getline; if($1~/^[0-9]+$/) print $1; else print 0}' || echo 0)
  NIC[rx_max]=$(to_int "${NIC[rx_max]}")
  NIC[tx_max]=$(to_int "${NIC[tx_max]}")
  
  STATE[sys_detected]=1
  save_state
  
  log_ok "内核: ${SYS[kernel]} | CPU: ${SYS[cpu]}核 | 内存: ${SYS[mem_gb]}GB"
  log_ok "网卡: ${iface} (${NIC[driver]}) | 虚拟化: ${SYS[virt]}"
}

# 网络检测（智能保留用户设置）
detect_network() {
  log_section "网络参数检测"
  
  # RTT检测（优先级：手动 > 探测 > 自动）
  if [ -n "${STATE[force_rtt]}" ]; then
    NET[rtt]="${STATE[force_rtt]}"
    log_ok "RTT: ${NET[rtt]}ms (手动设置)"
  elif [ -n "${STATE[probe_rtt]}" ]; then
    NET[rtt]="${STATE[probe_rtt]}"
    log_ok "RTT: ${NET[rtt]}ms (来自探测: ${STATE[region]}-${STATE[isp]})"
  else
    log_info "自动检测 RTT..."
    declare -A targets=(["1.1.1.1"]=5 ["8.8.8.8"]=3)
    local total=0 weight=0
    
    for t in "${!targets[@]}"; do
      local w=${targets[$t]}
      if ping -c 4 -W 2 "$t" >"${TMP_DIR}/ping_$t" 2>&1; then
        local med=$(grep -Eo 'time=[0-9.]+' "${TMP_DIR}/ping_$t" | awk -F= '{print $2}' | sort -n | awk 'NR==2{print}')
        [ -n "$med" ] && total=$(awk -v a="$total" -v m="$med" -v w="$w" 'BEGIN{printf "%.0f", a+m*w}') && weight=$((weight+w))
      fi
    done
    
    NET[rtt]=$([ "$weight" -gt 0 ] && awk -v a="$total" -v w="$weight" 'BEGIN{printf "%.0f", a/w}' || echo 50)
    log_ok "RTT: ${NET[rtt]}ms (自动检测)"
  fi
  
  # 带宽检测
  if [ -n "${STATE[force_bw]}" ]; then
    NET[bw]="${STATE[force_bw]}"
    log_ok "带宽: ${NET[bw]}Mbps (手动设置)"
  else
    local link=$(ethtool "${SYS[iface]}" 2>/dev/null | awk '/Speed:/{print $2}' | tr -cd '0-9')
    if [ -n "$link" ] && [ "$link" -gt 0 ]; then
      NET[bw]="$link"
    else
      NET[bw]=$(( (SYS[cpu] * 500 < SYS[mem_gb] * 400 ? SYS[cpu] * 500 : SYS[mem_gb] * 400) * 80 / 100 ))
      [ "${NET[bw]}" -lt 10 ] && NET[bw]=10
    fi
    log_ok "带宽: ${NET[bw]}Mbps"
  fi
  
  # BBR检测
  local cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
  NET[cc_avail]="$cc"
  NET[bbr]="none"
  
  for m in tcp_bbr3 tcp_bbrv2 tcp_bbr2 tcp_bbr; do
    if grep -qw "$m" /proc/modules 2>/dev/null || echo "$cc" | grep -qw "${m#tcp_}"; then
      NET[bbr]="$m"
      break
    fi
  done
  
  log_ok "BBR: ${NET[bbr]}"
  
  STATE[net_detected]=1
  save_state
}

# 计算缓冲区
calc_buffers() {
  log_section "计算优化参数"
  
  [ "${STATE[net_detected]}" != "1" ] && { log_warn "请先检测网络参数"; return 1; }
  
  local bw=${NET[bw]} rtt=${NET[rtt]} mode=${STATE[mode]}
  local bdp=$(awk -v b="$bw" -v r="$rtt" 'BEGIN{printf "%.0f", b*125*r}')
  NET[bdp]=$bdp
  NET[bdp_mb]=$(awk -v b="$bdp" 'BEGIN{printf "%.2f", b/1024/1024}')
  
  local mult=3
  case "$mode" in
    aggressive) mult=4 ;;
    latency) mult=2 ;;
  esac
  
  local tcp_max=$(( bdp * mult ))
  local mem_limit=$(( SYS[mem_kb] * 1024 * 15 / 100 ))
  [ "$tcp_max" -gt "$mem_limit" ] && tcp_max=$mem_limit
  [ "$tcp_max" -lt 65536 ] && tcp_max=65536
  
  NET[tcp_max]=$tcp_max
  NET[tcp_def]=131072
  NET[tcp_min]=4096
  
  local udp_max=$(( bdp * 2 ))
  local udp_limit=$(( SYS[mem_kb] * 1024 * 10 / 100 ))
  [ "$udp_max" -gt "$udp_limit" ] && udp_max=$udp_limit
  [ "$udp_max" -lt 65536 ] && udp_max=65536
  
  NET[udp_min]=16384
  NET[udp_mem_min]=$(( udp_max / 4096 / 4 ))
  NET[udp_mem_prs]=$(( udp_max / 4096 / 2 ))
  NET[udp_mem_max]=$(( udp_max / 4096 ))
  
  NET[backlog]=$(( bw * 100 ))
  [ "${NET[backlog]}" -lt 10000 ] && NET[backlog]=10000
  [ "${NET[backlog]}" -gt 1000000 ] && NET[backlog]=1000000
  NET[budget]=$(( NET[backlog] / 10 ))
  
  local ct=$(( SYS[mem_kb] * 1024 / 32768 ))
  [ "$ct" -lt 65536 ] && ct=65536
  [ "$ct" -gt 524288 ] && ct=524288
  NET[conntrack]=$ct
  
  log_ok "BDP: ${NET[bdp_mb]}MB | TCP最大: $((tcp_max/1024/1024))MB | Conntrack: $ct"
  
  STATE[buf_calculated]=1
  save_state
}

# 探测功能（二级菜单）
probe_region() {
  clear
  log_section "选择探测点"
  
  echo ""
  printf "\033[1;36m%-4s %-10s %-20s %-20s %-20s\033[0m\n" "ID" "地区" "${ISP_LIST[0]}" "${ISP_LIST[1]}" "${ISP_LIST[2]}"
  echo "────────────────────────────────────────────────────────────────────"
  
  local idx=1
  mapfile -t sorted < <(printf "%s\n" "${!REGIONS[@]}" | sort)
  for r in "${sorted[@]}"; do
    read -r ip1 ip2 ip3 <<< "${REGIONS[$r]}"
    printf "%-4s %-10s %-20s %-20s %-20s\n" "[$idx]" "$r" "$ip1" "$ip2" "$ip3"
    idx=$((idx+1))
  done
  
  echo ""
  echo -n "选择地区 (1-${#REGIONS[@]}, 0=取消): "
  read -r rid
  
  [ "$rid" = "0" ] && return
  ! is_valid_int "$rid" || [ "$rid" -gt "${#sorted[@]}" ] && { log_warn "无效编号"; pause; return; }
  
  local region="${sorted[$((rid-1))]}"
  read -r ip1 ip2 ip3 <<< "${REGIONS[$region]}"
  
  echo ""
  echo "地区: $region"
  echo "1. ${ISP_LIST[0]} ($ip1)"
  echo "2. ${ISP_LIST[1]} ($ip2)"
  echo "3. ${ISP_LIST[2]} ($ip3)"
  echo "0. 取消"
  echo ""
  echo -n "选择运营商 (0-3): "
  read -r iid
  
  [ "$iid" = "0" ] && return
  ! [[ "$iid" =~ ^[1-3]$ ]] && { log_warn "无效选择"; pause; return; }
  
  local ip isp
  case "$iid" in
    1) ip="$ip1"; isp="${ISP_LIST[0]}" ;;
    2) ip="$ip2"; isp="${ISP_LIST[1]}" ;;
    3) ip="$ip3"; isp="${ISP_LIST[2]}" ;;
  esac
  
  STATE[region]="$region"
  STATE[isp]="$isp"
  STATE[probe_ip]="$ip"
  
  log_section "探测节点: $region - $isp"
  log_info "目标: $ip"
  
  local rtt=0
  if ping -c 4 -W 2 "$ip" >"${TMP_DIR}/probe" 2>&1; then
    rtt=$(grep -Eo 'time=[0-9.]+' "${TMP_DIR}/probe" | awk -F= '{print $2}' | sort -n | awk 'NR==2{print}')
    log_ok "ICMP Ping: ${rtt}ms"
  elif has nc && timeout 3 nc -zv "$ip" 80 2>&1; then
    rtt=999
    log_warn "TCP探测超时，使用默认值"
  else
    rtt=999
    log_warn "探测失败"
  fi
  
  STATE[probe_rtt]="$rtt"
  save_state
  
  echo ""
  log_ok "═══════════════════════"
  log_ok "探测完成"
  log_ok "  地区: $region"
  log_ok "  运营商: $isp"
  log_ok "  RTT: ${rtt}ms"
  log_ok "═══════════════════════"
  pause
}

# 智能分析（核心推荐）
intelligent_analysis() {
  clear
  log_section "智能分析与优化建议"
  
  [ "${STATE[sys_detected]}" != "1" ] && { log_warn "请先检测系统（选项2）"; pause; return; }
  
  cat <<EOF

╔══════════════════════════════════════════════════════════════╗
║                    当前系统状态                                ║
╚══════════════════════════════════════════════════════════════╝

  🖥️  系统: ${SYS[kernel]} | CPU: ${SYS[cpu]}核 | 内存: ${SYS[mem_gb]}GB
  🌐 网卡: ${SYS[iface]} (${NIC[driver]})
  📊 带宽: ${NET[bw]:-未检测}Mbps | RTT: ${NET[rtt]:-未检测}ms
  🚀 BBR: ${NET[bbr]:-未检测}
  ⚙️  模式: ${STATE[mode]}

EOF

  [ -n "${STATE[probe_ip]}" ] && cat <<EOF
  📍 探测点: ${STATE[region]} - ${STATE[isp]} | RTT: ${STATE[probe_rtt]}ms

EOF

  cat <<EOF
╔══════════════════════════════════════════════════════════════╗
║                 针对代理翻墙的智能建议                          ║
╚══════════════════════════════════════════════════════════════╝

EOF

  local rtt=${NET[rtt]:-50}
  
  if [ "$rtt" -gt 120 ]; then
    cat <<EOF
  ⚠️  【高延迟环境检测】RTT: ${rtt}ms
  
  📌 核心问题分析:
     • 高延迟是代理速度慢的元凶
     • 普通 BBR 在高延迟下效果有限
     • 需要启用更激进的拥塞控制
  
  ✅ 强烈推荐操作:
     1. 立即执行 [菜单3] 安装 XanMod 内核
        → 获得 BBR v3，专为高延迟优化
     2. 执行 [菜单4] 切换到 latency 模式
        → 降低批处理延迟，优先响应速度
     3. 执行 [菜单5] 一键优化
        → 应用针对性优化参数
  
  💡 预期提升: 20-40% 速度改善

EOF
  elif [ "$rtt" -lt 50 ]; then
    cat <<EOF
  ✅ 【低延迟环境】RTT: ${rtt}ms
  
  📌 环境分析:
     • 网络质量优秀，应最大化利用带宽
     • 可以启用更大的缓冲区
  
  ✅ 推荐操作:
     1. 执行 [菜单4] 切换到 aggressive 模式
        → 最大化吞吐量
     2. 执行 [菜单5] 一键优化
        → 榨干服务器性能

EOF
  else
    cat <<EOF
  ℹ️  【中等延迟环境】RTT: ${rtt}ms
  
  ✅ 推荐: 保持 normal 模式，执行 [菜单5] 优化即可

EOF
  fi
  
  if [ "${NET[bbr]}" = "none" ]; then
    cat <<EOF
  🚨 【致命问题】未检测到 BBR！
  
  ⚠️  警告:
     • BBR 是代理性能的基石
     • 没有 BBR，代理速度会极其糟糕
     • 这是最高优先级问题
  
  ✅ 立即操作:
     → 执行 [菜单3] 安装 XanMod 内核
     → 重启后 BBR 自动启用

EOF
  fi
  
  pause
}

# 内核安装
install_kernel() {
  log_section "安装 XanMod 内核 (BBR v3)"
  
  local current=$(uname -r)
  if [[ "$current" == *"xanmod"* ]]; then
    log_ok "已安装 XanMod: $current"
    echo -n "重新安装? (y/N): "
    read -r c
    [[ "${c,,}" != "y" ]] && return
  fi
  
  log_info "添加 XanMod 仓库..."
  curl -fsSL https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg 2>/dev/null || { log_warn "密钥下载失败"; install_bbr3; return; }
  
  echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod.list
  
  apt-get update -qq >/dev/null 2>&1 || { log_warn "更新失败"; install_bbr3; return; }
  
  if apt-get install -y -qq linux-xanmod >/dev/null 2>&1; then
    log_ok "XanMod 安装成功，请重启系统"
  else
    log_warn "XanMod 失败，尝试 BBR v3..."
    install_bbr3
  fi
  
  pause
}

install_bbr3() {
  log_info "安装 BBR v3 内核（备选）..."
  
  local arch=$(uname -m)
  local filter
  case "$arch" in
    x86_64) filter="x86_64" ;;
    aarch64) filter="arm64" ;;
    *) log_err "不支持架构: $arch" ;;
  esac
  
  local api="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases"
  local data=$(curl -sL "$api" 2>/dev/null) || { log_err "无法访问 GitHub"; }
  
  local tag=$(echo "$data" | jq -r --arg f "$filter" 'map(select(.tag_name | test($f; "i"))) | sort_by(.published_at) | .[-1].tag_name')
  [ -z "$tag" ] || [ "$tag" = "null" ] && { log_err "未找到适配版本"; }
  
  log_ok "找到版本: $tag"
  
  local urls=$(echo "$data" | jq -r --arg t "$tag" '.[] | select(.tag_name == $t) | .assets[].browser_download_url')
  
  rm -f /tmp/linux-*.deb
  for u in $urls; do
    wget -q --show-progress "$u" -P /tmp/ || log_warn "下载失败: $u"
  done
  
  [ ! -f /tmp/linux-*.deb ] && { log_err "下载失败"; }
  
  dpkg -i /tmp/linux-*.deb >/dev/null 2>&1
  apt-get install -f -y >/dev/null 2>&1
  has update-grub && update-grub >/dev/null 2>&1
  
  log_ok "BBR v3 安装完成，请重启"
}

# 一键优化
one_click_optimize() {
  log_section "执行一键优化"
  
  cat <<EOF

即将执行:
  1. 检测系统信息
  2. 检测网络参数（保留已设置值）
  3. 计算优化参数
  4. 应用 Sysctl 配置
  5. 优化网卡参数
