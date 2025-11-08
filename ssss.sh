#!/usr/bin/env bash
# ============================================================
# 代理翻墙网络终极优化脚本 v2.1 (修复版)
# 专为搭建代理/翻墙服务器优化网络参数
# 修复：状态持久化、参数覆盖、数值验证等问题
# ============================================================
set -euo pipefail
IFS=$'\n\t'

# ============================================================
# 第一部分：全局变量与配置（支持持久化）
# ============================================================
VERSION="2.1-fixed-2025"
TMP="/tmp/proxy-opt-$$"
mkdir -p "$TMP"
trap 'rm -rf "$TMP"' EXIT

# 持久化配置文件
STATE_FILE="/var/lib/proxy-optimizer/state.conf"
mkdir -p "$(dirname "$STATE_FILE")"

# 配置文件路径
SYSCTL_FILE="/etc/sysctl.d/99-proxy-ultimate.conf"
MONITOR_SCRIPT="/usr/local/bin/proxy-ultimate-monitor.sh"
MONITOR_SERVICE="/etc/systemd/system/proxy-ultimate-monitor.service"
HEALTH_SCRIPT="/usr/local/bin/proxy-probe-health.sh"
PERF_SCRIPT="/usr/local/bin/proxy-performance-test.sh"
LOGROTATE_FILE="/etc/logrotate.d/proxy-ultimate-monitor"

# 运行模式与开关（带默认值）
MODE="${MODE:-aggressive}"
INSTALL_XANMOD="${INSTALL_XANMOD:-0}"
ENABLE_XDP="${ENABLE_XDP:-0}"
ENABLE_MONITOR="${ENABLE_MONITOR:-1}"
IPERF_SERVER="${IPERF_SERVER:-}"
FORCE_RTT="${FORCE_RTT:-}"
FORCE_BW="${FORCE_BW:-}"

# 系统信息存储
declare -A SYS NET NIC
declare -a NUMA_CPUS=()

# 选定的探测点信息
SELECTED_REGION="${SELECTED_REGION:-}"
SELECTED_ISP="${SELECTED_ISP:-}"
SELECTED_IP="${SELECTED_IP:-}"
SELECTED_RTT="${SELECTED_RTT:-}"

# 状态标记
SYSTEM_DETECTED=0
NETWORK_DETECTED=0
BUFFERS_CALCULATED=0

# ============================================================
# 第二部分：状态持久化函数
# ============================================================

save_state() {
  cat > "$STATE_FILE" <<EOF
# 代理优化工具状态文件
# 生成时间: $(date)

MODE="$MODE"
FORCE_RTT="$FORCE_RTT"
FORCE_BW="$FORCE_BW"

SELECTED_REGION="$SELECTED_REGION"
SELECTED_ISP="$SELECTED_ISP"
SELECTED_IP="$SELECTED_IP"
SELECTED_RTT="$SELECTED_RTT"

SYSTEM_DETECTED=$SYSTEM_DETECTED
NETWORK_DETECTED=$NETWORK_DETECTED
BUFFERS_CALCULATED=$BUFFERS_CALCULATED

# 系统信息
$(declare -p SYS 2>/dev/null || echo "declare -A SYS=()")
$(declare -p NET 2>/dev/null || echo "declare -A NET=()")
$(declare -p NIC 2>/dev/null || echo "declare -A NIC=()")
EOF
  chmod 600 "$STATE_FILE"
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    # 安全加载状态文件
    source "$STATE_FILE" 2>/dev/null || true
  fi
}

# ============================================================
# 第三部分：地域与运营商数据定义
# ============================================================

declare -A REGIONS_IPV4=(
  ["上海"]="183.193.195.52 140.207.236.211 61.170.80.224"
  ["云南"]="36.147.59.95 180.130.96.87 182.242.90.222"
  ["内蒙古"]="117.161.74.9 116.136.37.50 36.102.211.14"
  ["北京"]="111.132.33.234 123.126.74.241 220.181.141.62"
  ["吉林"]="36.135.15.29 139.215.162.53 36.104.134.91"
  ["四川"]="112.45.29.107 119.6.226.87 182.140.222.120"
  ["天津"]="111.32.184.158 220.194.123.111 42.81.179.153"
  ["宁夏"]="111.51.158.194 42.63.65.85 222.75.63.58"
  ["安徽"]="112.29.208.234 211.91.68.233 117.66.50.79"
  ["山东"]="120.220.200.235 116.196.134.235 140.249.226.28"
  ["山西"]="183.201.217.212 221.204.69.240 1.71.88.66"
  ["广东"]="183.240.215.141 122.13.173.213 14.116.174.67"
  ["广西"]="36.159.112.50 121.31.230.218 222.216.123.115"
  ["新疆"]="36.189.11.227 116.178.75.25 110.157.250.207"
  ["江苏"]="36.150.72.122 218.98.46.62 221.229.203.57"
  ["江西"]="117.163.60.130 116.153.79.107 106.225.224.168"
  ["河北"]="111.62.129.51 221.195.63.207 124.238.112.166"
  ["河南"]="111.7.88.239 123.6.6.95 36.99.32.68"
  ["浙江"]="112.13.210.86 124.160.144.214 122.228.6.140"
  ["海南"]="111.29.14.183 113.59.44.60 124.225.127.237"
  ["湖北"]="111.48.204.91 122.188.1.46 171.43.200.232"
  ["湖南"]="111.22.253.121 61.240.220.8 113.219.200.211"
  ["甘肃"]="36.142.6.184 116.176.95.38 118.183.154.36"
  ["福建"]="183.253.58.91 36.248.50.117 125.77.141.147"
  ["西藏"]="117.180.226.125 116.172.148.16 113.62.123.11"
  ["贵州"]="117.187.205.58 220.197.201.184 119.0.107.88"
  ["辽宁"]="36.131.173.23 218.61.192.237 42.202.220.14"
  ["重庆"]="221.178.37.53 113.207.38.107 219.153.156.15"
  ["陕西"]="36.163.206.252 124.89.110.205 113.141.190.13"
  ["青海"]="111.12.213.165 139.170.154.39 223.221.179.79"
  ["黑龙江"]="111.42.114.74 1.189.232.55 42.185.157.195"
)

ISP_LABELS=("移动" "联通" "电信")

# ============================================================
# 第四部分：通用工具函数定义
# ============================================================

_log() { printf "\033[36m[%s]\033[0m %s\n" "$(date +%T)" "$*"; }
_ok() { printf "\033[32m[✓]\033[0m %s\n" "$*"; }
_warn() { printf "\033[33m[!]\033[0m %s\n" "$*" >&2; }
_err() { printf "\033[31m[✗]\033[0m %s\n" "$*" >&2; exit 1; }
_section() { printf "\n\033[1;35m╔══════════════════════════════════════════╗\033[0m\n\033[1;35m║  %s\033[0m\n\033[1;35m╚══════════════════════════════════════════╝\033[0m\n" "$*"; }

has() { command -v "$1" >/dev/null 2>&1; }

to_int() { 
  local v="${1:-0}"
  v="${v//[^0-9]/}"
  # 验证是否为有效数字
  if [[ "$v" =~ ^[0-9]+$ ]]; then
    echo "$v"
  else
    echo "0"
  fi
}

is_valid_int() {
  local v="$1"
  [[ "$v" =~ ^[0-9]+$ ]] && [ "$v" -gt 0 ]
}

run_cmd() { 
  if ! eval "$@" 2>/dev/null; then
    _warn "命令执行失败(已忽略): $*"
    return 1
  fi
  return 0
}

cpu_mask_hex() {
  local n=$(to_int "$1")
  [ "$n" -le 0 ] && echo "1" && return
  if [ "$n" -ge 64 ]; then echo "ffffffffffffffff"; return; fi
  if [ "$n" -lt 61 ]; then
    printf '%x' $(( (1 << n) - 1 ))
    return
  fi
  if has python3; then
    python3 -c "n=$n; mask=(1<<n)-1; print(format(mask,'x'))" 2>/dev/null || echo "ffffffffffffffff"
  else
    echo "ffffffffffffffff"
  fi
}

pause() {
  echo ""
  echo "按回车键继续..."
  read -r
}

# ============================================================
# 第五部分：系统环境检查函数
# ============================================================

check_root() {
  _section "环境检查"
  if [ "$(id -u)" -ne 0 ]; then
    _err "请使用 root 用户执行此脚本"
  fi
  _ok "Root 权限检查通过"
}

check_and_install_dependencies() {
  if ! has apt-get; then
    _err "此脚本仅支持 Debian/Ubuntu 系统"
  fi
  
  . /etc/os-release 2>/dev/null || true
  _ok "系统: ${NAME:-Unknown} ${VERSION_ID:-Unknown}"
  
  # 完整的依赖列表
  local required_tools=(
    "curl"
    "wget"
    "jq"
    "ethtool"
    "bc"
    "gnupg"
    "gnupg2"
    "lsb-release"
    "ca-certificates"
    "net-tools"
    "sysstat"
  )
  
  local missing_tools=()
  for tool in "${required_tools[@]}"; do
    if ! has "$tool" && ! dpkg -l | grep -qw "^ii.*$tool"; then
      missing_tools+=("$tool")
    fi
  done
  
  if [ ${#missing_tools[@]} -gt 0 ]; then
    _log "缺少依赖工具，准备安装: ${missing_tools[*]}"
    _log "更新软件源..."
    run_cmd "apt-get update -y >/dev/null 2>&1"
    _log "安装依赖包（可能需要几分钟）..."
    run_cmd "DEBIAN_FRONTEND=noninteractive apt-get install -y ${missing_tools[*]} --no-install-recommends >/dev/null 2>&1"
    _ok "依赖安装完成"
  else
    _ok "所有依赖工具已安装"
  fi
}

check_system() {
  check_root
  check_and_install_dependencies
  _ok "系统环境检查完成"
}

# ============================================================
# 第六部分：系统信息检测函数
# ============================================================

detect_system_info() {
  _section "系统信息检测"
  
  SYS[kernel]=$(uname -r)
  SYS[cpu]=$(nproc)
  SYS[mem_kb]=$(awk '/MemTotal/ {print $2}' /proc/meminfo || echo 0)
  SYS[mem_bytes]=$((SYS[mem_kb]*1024))
  SYS[mem_gb]=$(awk -v b="${SYS[mem_bytes]}" 'BEGIN{printf "%.1f", b/1024/1024/1024}')
  
  SYS[virt]="unknown"
  if has systemd-detect-virt; then
    SYS[virt]=$(systemd-detect-virt 2>/dev/null || echo "unknown")
  fi
  
  SYS[numa_nodes]=$(lscpu 2>/dev/null | awk '/^NUMA node\(s\):/ {print $NF}' || echo 1)
  
  SYS[iface]=$(ip -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -1 || true)
  if [ -z "${SYS[iface]}" ]; then
    SYS[iface]=$(ip -o link show | awk -F': ' '$2!~/lo|virbr|docker|veth/ {print $2; exit}')
  fi
  
  [ -z "${SYS[iface]}" ] && _err "无法检测到主网卡接口"
  
  local iface="${SYS[iface]}"
  NIC[driver]=$(ethtool -i "$iface" 2>/dev/null | awk '/driver:/ {print $2}' || echo "unknown")
  NIC[queues]=$(ethtool -l "$iface" 2>/dev/null | awk '/Combined:/ {print $2; exit}' || echo 1)
  
  # 修复：安全读取 Ring Buffer 大小
  local rx_max=$(ethtool -g "$iface" 2>/dev/null | awk '/^RX:/{getline; print $1}' || echo 0)
  local tx_max=$(ethtool -g "$iface" 2>/dev/null | awk '/^TX:/{getline; print $1}' || echo 0)
  NIC[rx_max]=$(to_int "$rx_max")
  NIC[tx_max]=$(to_int "$tx_max")
  
  NIC[numa]=$(cat "/sys/class/net/$iface/device/numa_node" 2>/dev/null || echo -1)
  
  SYSTEM_DETECTED=1
  save_state
  
  _ok "内核: ${SYS[kernel]}"
  _ok "CPU: ${SYS[cpu]} 核心"
  _ok "内存: ${SYS[mem_gb]} GB"
  _ok "网卡: ${iface} (驱动: ${NIC[driver]})"
  _ok "虚拟化: ${SYS[virt]}"
}

detect_network_params() {
  _section "网络参数检测"
  
  # RTT 检测（优先使用用户设置或探测结果）
  if [ -n "$FORCE_RTT" ] && [ "$FORCE_RTT" != "0" ]; then
    NET[rtt]=$(to_int "$FORCE_RTT")
    _ok "使用手动设置的 RTT: ${NET[rtt]} ms"
  elif [ -n "$SELECTED_RTT" ] && [ "$SELECTED_RTT" != "0" ]; then
    NET[rtt]=$(to_int "$SELECTED_RTT")
    _ok "使用探测点的 RTT: ${NET[rtt]} ms (来自 $SELECTED_REGION - $SELECTED_ISP)"
  else
    _log "正在检测 RTT（向多个公共 DNS 发送 ping）..."
    declare -A targets=(["1.1.1.1"]=5 ["8.8.8.8"]=3 ["9.9.9.9"]=2)
    local total_weighted=0 total_weight=0
    
    for target in "${!targets[@]}"; do
      local weight=${targets[$target]}
      local tmpfile="${TMP}/ping_${target//./}"
      
      if ping -c 6 -W 2 -i 0.2 "$target" >"$tmpfile" 2>/dev/null; then
        mapfile -t rtts < <(grep -Eo 'time=[0-9.]+' "$tmpfile" | awk -F= '{print $2}')
        rm -f "$tmpfile"
        
        if [ ${#rtts[@]} -ge 3 ]; then
          IFS=$'\n' sorted=($(printf '%s\n' "${rtts[@]}" | sort -n))
          local median="${sorted[$(( ${#sorted[@]} / 2 ))]}"
          
          if awk -v m="$median" 'BEGIN{exit !(m>=1 && m<=2000)}'; then
            total_weighted=$(awk -v a="$total_weighted" -v m="$median" -v w="$weight" 'BEGIN{printf "%.2f", a + m*w}')
            total_weight=$((total_weight + weight))
            _log "  $target: ${median}ms (权重=$weight)"
          fi
        fi
      fi
    done
    
    if [ "$total_weight" -gt 0 ]; then
      NET[rtt]=$(awk -v a="$total_weighted" -v w="$total_weight" 'BEGIN{printf "%.0f", a/w}')
      _ok "检测到 RTT: ${NET[rtt]} ms"
    else
      NET[rtt]=50
      _warn "RTT 检测失败，使用默认值 50ms"
    fi
  fi
  
  # 带宽检测（优先使用用户设置）
  if [ -n "$FORCE_BW" ] && [ "$FORCE_BW" != "0" ]; then
    NET[bw]=$(to_int "$FORCE_BW")
    _ok "使用手动设置的带宽: ${NET[bw]} Mbps"
  else
    _log "正在检测带宽..."
    local bw=0
    local link=$(ethtool "${SYS[iface]}" 2>/dev/null | awk '/Speed:/ {print $2}' | tr -cd '0-9' || echo 0)
    link=$(to_int "$link")
    
    if [ "$link" -gt 0 ]; then
      bw="$link"
      _log "  ethtool 报告链路速度: ${bw} Mbps"
    else
      local cpu_bw=$(( SYS[cpu] * 500 ))
      local mem_bw=$(awk -v m="${SYS[mem_gb]}" 'BEGIN{printf "%.0f", m*400}')
      bw=$(( cpu_bw < mem_bw ? cpu_bw : mem_bw ))
      bw=$(( bw * 80 / 100 ))
      _log "  基于系统配置估算带宽: ${bw} Mbps"
    fi
    
    [ "$bw" -lt 10 ] && bw=10
    NET[bw]=$bw
    _ok "检测到带宽: ${NET[bw]} Mbps"
  fi
  
  # BBR 检测
  _log "检测 BBR 拥塞控制算法..."
  local avail=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")
  NET[avail_cc]="$avail"
  
  local best="none"
  for module in tcp_bbr3 tcp_bbrv2 tcp_bbr2 tcp_bbr; do
    if grep -qw "$module" /proc/modules 2>/dev/null; then
      best="$module"
      break
    fi
  done
  
  if [ "$best" = "none" ]; then
    for name in bbr3 bbrv2 bbr2 bbr; do
      if echo "$avail" | grep -qw "$name"; then
        best="$name"
        break
      fi
    done
  fi
  
  NET[bbr_best]="$best"
  _ok "可用拥塞控制: $avail"
  _ok "最佳 BBR 版本: $best"
  
  NETWORK_DETECTED=1
  save_state
}

calculate_buffers() {
  _section "计算缓冲区参数"
  
  if [ -z "${NET[bw]:-}" ] || [ -z "${NET[rtt]:-}" ]; then
    _warn "请先检测网络参数（选项 2）"
    return 1
  fi
  
  local bw=${NET[bw]}
  local rtt=${NET[rtt]}
  
  local bdp=$(awk -v bw="$bw" -v rtt="$rtt" 'BEGIN{printf "%.0f", bw*125*rtt}')
  NET[bdp]=$bdp
  NET[bdp_mb]=$(awk -v b="$bdp" 'BEGIN{printf "%.2f", b/1024/1024}')
  
  _log "BDP (带宽延迟积): ${NET[bdp]} bytes (${NET[bdp_mb]} MB)"
  
  local mem10=$(( SYS[mem_bytes] * 10 / 100 ))
  local mem15=$(( SYS[mem_bytes] * 15 / 100 ))
  
  local mult=3
  case "$MODE" in
    aggressive) mult=4 ;;
    latency) mult=2 ;;
    *) mult=3 ;;
  esac
  
  local tcp_max=$(( bdp * mult ))
  [ "$tcp_max" -gt "$mem15" ] && tcp_max="$mem15"
  [ "$tcp_max" -lt 65536 ] && tcp_max=65536
  
  NET[tcp_rmem_max]=$tcp_max
  NET[tcp_wmem_max]=$tcp_max
  NET[tcp_rmem_def]=131072
  NET[tcp_rmem_min]=4096
  NET[tcp_wmem_def]=131072
  NET[tcp_wmem_min]=4096
  
  _ok "TCP 缓冲区: 默认=128KB, 最大=$(( tcp_max / 1024 / 1024 ))MB"
  
  local udp_max=$(( bdp * 2 ))
  [ "$udp_max" -gt "$mem10" ] && udp_max=$mem10
  [ "$udp_max" -lt 65536 ] && udp_max=65536
  
  NET[udp_rmem_min]=16384
  NET[udp_wmem_min]=16384
  
  local page=4096
  NET[udp_mem_min]=$(( udp_max / page / 4 ))
  NET[udp_mem_prs]=$(( udp_max / page / 2 ))
  NET[udp_mem_max]=$(( udp_max / page ))
  
  _ok "UDP 缓冲区: 最大=$((udp_max/1024/1024))MB"
  
  local backlog=$(( NET[bw] * 100 ))
  [ "$backlog" -lt 10000 ] && backlog=10000
  [ "$backlog" -gt 1000000 ] && backlog=1000000
  NET[backlog]=$backlog
  NET[budget]=$(( backlog / 10 ))
  
  local ct=$(( SYS[mem_bytes] / 32768 ))
  [ "$ct" -lt 65536 ] && ct=65536
  [ "$ct" -gt 524288 ] && ct=524288
  NET[conntrack]=$ct
  
  _ok "Backlog: ${NET[backlog]}, Budget: ${NET[budget]}, Conntrack: ${NET[conntrack]}"
  
  BUFFERS_CALCULATED=1
  save_state
}

# ============================================================
# 第七部分：地域与运营商选择交互函数
# ============================================================

show_region_list() {
  _section "可用探测点列表"
  
  echo ""
  printf "\033[1;36m%-6s %-12s %-22s %-22s %-22s\033[0m\n" "编号" "地区" "${ISP_LABELS[0]}" "${ISP_LABELS[1]}" "${ISP_LABELS[2]}"
  echo "──────────────────────────────────────────────────────────────────────────────────────"
  
  local idx=1
  for region in $(printf "%s\n" "${!REGIONS_IPV4[@]}" | sort); do
    IFS=' ' read -r ip_cm ip_cu ip_ct <<< "${REGIONS_IPV4[$region]}"
    printf "%-6s %-12s %-22s %-22s %-22s\n" "[$idx]" "$region" "$ip_cm" "$ip_cu" "$ip_ct"
    idx=$((idx+1))
  done
  
  echo ""
}

select_region_and_probe() {
  _section "选择探测点"
  
  show_region_list
  
  echo "请输入地区编号 (1-${#REGIONS_IPV4[@]}，输入 0 取消): "
  read -r region_id
  
  if [ "$region_id" = "0" ] || [ -z "$region_id" ]; then
    _log "已取消选择"
    return 1
  fi
  
  if ! [[ "$region_id" =~ ^[0-9]+$ ]]; then
    _warn "无效的编号"
    pause
    return 1
  fi
  
  mapfile -t region_list < <(printf "%s\n" "${!REGIONS_IPV4[@]}" | sort)
  
  if [ "$region_id" -lt 1 ] || [ "$region_id" -gt "${#region_list[@]}" ]; then
    _warn "编号超出范围"
    pause
    return 1
  fi
  
  local region="${region_list[$((region_id-1))]}"
  IFS=' ' read -r ip_cm ip_cu ip_ct <<< "${REGIONS_IPV4[$region]}"
  
  echo ""
  _ok "已选择地区: $region"
  echo ""
  echo "请选择运营商:"
  echo "  1. ${ISP_LABELS[0]} ($ip_cm)"
  echo "  2. ${ISP_LABELS[1]} ($ip_cu)"
  echo "  3. ${ISP_LABELS[2]} ($ip_ct)"
  echo "  0. 取消"
  echo ""
  echo "请输入运营商编号 (0-3): "
  read -r isp_id
  
  if [ "$isp_id" = "0" ] || [ -z "$isp_id" ]; then
    _log "已取消选择"
    return 1
  fi
  
  if ! [[ "$isp_id" =~ ^[1-3]$ ]]; then
    _warn "无效的运营商编号"
    pause
    return 1
  fi
  
  local target_ip
  local isp_name
  
  case "$isp_id" in
    1) target_ip="$ip_cm"; isp_name="${ISP_LABELS[0]}" ;;
    2) target_ip="$ip_cu"; isp_name="${ISP_LABELS[1]}" ;;
    3) target_ip="$ip_ct"; isp_name="${ISP_LABELS[2]}" ;;
  esac
  
  SELECTED_REGION="$region"
  SELECTED_ISP="$isp_name"
  SELECTED_IP="$target_ip"
  
  _ok "已选择: $region - $isp_name ($target_ip)"
  
  probe_selected_target
}

probe_selected_target() {
  _section "探测目标节点"
  
  if [ -z "$SELECTED_IP" ]; then
    _warn "未选择探测目标"
    return 1
  fi
  
  _log "正在探测: $SELECTED_REGION - $SELECTED_ISP ($SELECTED_IP)"
  
  local rtt_ms=0
  
  _log "尝试 ICMP ping..."
  if ping -c 4 -W 2 "$SELECTED_IP" >/tmp/ping_${SELECTED_IP}.out 2>/dev/null; then
    rtt_ms=$(grep -Eo 'time=[0-9.]+' /tmp/ping_${SELECTED_IP}.out | awk -F= '{print $2}' | sort -n | awk 'NR==2{print $0}')
    rm -f /tmp/ping_${SELECTED_IP}.out
    _ok "ICMP ping 成功"
  else
    _warn "ICMP ping 失败，尝试 TCP 连接测试..."
    
    if has nc; then
      local start=$(date +%s%3N)
      if timeout 3 nc -zv "$SELECTED_IP" 80 >/dev/null 2>&1; then
        local stop=$(date +%s%3N)
        rtt_ms=$(( stop - start ))
        _ok "TCP 连接成功"
      else
        _warn "TCP 连接失败，使用默认值"
        rtt_ms=999
      fi
    else
      _warn "nc 命令不可用，使用默认值"
      rtt_ms=999
    fi
  fi
  
  SELECTED_RTT="$rtt_ms"
  NET[rtt]="$rtt_ms"
  
  save_state
  
  echo ""
  _ok "════════════════════════════════════════"
  _ok "探测结果:"
  _ok "  地区: $SELECTED_REGION"
  _ok "  运营商: $SELECTED_ISP"
  _ok "  IP: $SELECTED_IP"
  _ok "  RTT: ${SELECTED_RTT} ms"
  _ok "════════════════════════════════════════"
  echo ""
  
  pause
}

# ============================================================
# 第八部分：智能分析与推荐函数
# ============================================================

show_intelligent_analysis() {
  _section "智能分析与优化建议"
  
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                    当前系统状态                                ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  printf "  🖥️  系统信息:\n"
  printf "      • 内核版本: %s\n" "${SYS[kernel]:-未检测}"
  printf "      • CPU 核心: %s\n" "${SYS[cpu]:-未检测}"
  printf "      • 内存大小: %s GB\n" "${SYS[mem_gb]:-未检测}"
  printf "      • 虚拟化: %s\n" "${SYS[virt]:-未检测}"
  echo ""
  printf "  🌐 网络信息:\n"
  printf "      • 网卡接口: %s\n" "${SYS[iface]:-未检测}"
  printf "      • 网卡驱动: %s\n" "${NIC[driver]:-未检测}"
  printf "      • 估算带宽: %s Mbps\n" "${NET[bw]:-未检测}"
  printf "      • 估算 RTT: %s ms\n" "${NET[rtt]:-未检测}"
  printf "      • BBR 版本: %s\n" "${NET[bbr_best]:-未检测}"
  echo ""
  
  if [ -n "$SELECTED_IP" ]; then
    printf "  📍 探测点信息:\n"
    printf "      • 地区: %s\n" "$SELECTED_REGION"
    printf "      • 运营商: %s\n" "$SELECTED_ISP"
    printf "      • IP 地址: %s\n" "$SELECTED_IP"
    printf "      • 实测 RTT: %s ms\n" "$SELECTED_RTT"
    echo ""
  fi
  
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                 代理翻墙优化建议                               ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  
  local rtt=${NET[rtt]:-50}
  printf "  📊 延迟分析 (RTT: %s ms):\n" "$rtt"
  
  if [ "$rtt" -gt 150 ]; then
    echo "      ⚠️  高延迟环境 (>150ms)"
    echo "      ✓ 强烈建议: MODE=latency (降低批处理延迟)"
    echo "      ✓ 关闭 GRO/LRO 减少聚合延迟"
    echo "      ✓ 降低 coalesce 参数 (rx-usecs=30)"
    echo "      ✓ 适合: Shadowsocks, V2Ray, Trojan 等交互型代理"
  elif [ "$rtt" -gt 80 ]; then
    echo "      ℹ️  中等延迟环境 (80-150ms)"
    echo "      ✓ 建议: MODE=normal (平衡吞吐与延迟)"
    echo "      ✓ 保持 GRO 启用，调整 coalesce (rx-usecs=125)"
    echo "      ✓ 适合: 大多数代理场景"
  else
    echo "      ✅ 低延迟环境 (<80ms)"
    echo "      ✓ 建议: MODE=aggressive (追求最大吞吐)"
    echo "      ✓ 启用所有硬件加速功能"
    echo "      ✓ 增大缓冲区以提升带宽利用率"
    echo "      ✓ 适合: 高带宽流媒体代理"
  fi
  echo ""
  
  local bw=${NET[bw]:-100}
  printf "  📈 带宽分析 (估算: %s Mbps):\n" "$bw"
  
  if [ "$bw" -lt 100 ]; then
    echo "      ⚠️  小带宽环境 (<100Mbps)"
    echo "      ✓ 优先优化 TCP 窗口和 conntrack"
    echo "      ✓ 避免过大 buffer 导致 bufferbloat"
    echo "      ✓ 启用 FQ/FQ_CODEL 队列管理"
  elif [ "$bw" -lt 500 ]; then
    echo "      ℹ️  中等带宽环境 (100-500Mbps)"
    echo "      ✓ 平衡缓冲区大小 (3-4倍 BDP)"
    echo "      ✓ 启用多队列和 RPS/XPS"
  else
    echo "      ✅ 高带宽环境 (>500Mbps)"
    echo "      ✓ 增大缓冲区至 4倍 BDP"
    echo "      ✓ 启用所有硬件 offload"
    echo "      ✓ 考虑启用 XDP 加速"
    echo "      ✓ 增大 conntrack 容量"
  fi
  echo ""
  
  printf "  🖥️  虚拟化环境分析:\n"
  if [[ "${SYS[virt],,}" == *"kvm"* ]] || [[ "${NIC[driver],,}" == *"virtio"* ]]; then
    echo "      ℹ️  检测到虚拟化环境 (KVM/VirtIO)"
    echo "      ✓ 启用 virtio 专用优化"
    echo "      ✓ 禁用 tx-nocache-copy"
    echo "      ✓ 启用 tx-checksum-ipv4"
    echo "      ✓ 如果是 AWS/阿里云，考虑使用增强网络"
  else
    echo "      ✅ 物理机或容器环境"
    echo "      ✓ 可以使用完整硬件加速功能"
    echo "      ✓ 建议启用 XDP (需要 --enable-xdp)"
  fi
  echo ""
  
  printf "  🚀 拥塞控制分析:\n"
  if [ "${NET[bbr_best]:-none}" = "none" ]; then
    echo "      ⚠️  未检测到 BBR"
    echo "      ✓ 强烈建议安装 XanMod 内核 (内置 BBR3)"
    echo "      ✓ 或使用脚本安装 BBR v3 内核"
    echo "      ✓ BBR 对高延迟/丢包环境提升明显 (10-40%)"
  elif [[ "${NET[bbr_best]}" == *"bbr3"* ]] || [[ "${NET[bbr_best]}" == *"bbrv2"* ]]; then
    echo "      ✅ 已安装新版 BBR (${NET[bbr_best]})"
    echo "      ✓ 适合高延迟高丢包的国际线路"
    echo "      ✓ 建议配合 FQ 队列使用"
  else
    echo "      ℹ️  使用标准 BBR (${NET[bbr_best]})"
    echo "      ✓ 考虑升级到 BBR v2/v3 以获得更好性能"
  fi
  echo ""
  
  echo "  🔐 代理翻墙场景建议:"
  echo ""
  printf "      针对 Shadowsocks/V2Ray/Trojan:\n"
  echo "      • 优先降低延迟 (MODE=latency 或 normal)"
  echo "      • 启用 TCP Fast Open"
  echo "      • 适度增加 conntrack 容量"
  echo "      • 调整 tcp_fin_timeout=10"
  echo ""
  printf "      针对 WireGuard/IPsec VPN:\n"
  echo "      • 优化 UDP 缓冲区"
  echo "      • 增大 udp_mem 参数"
  echo "      • 启用 UDP GRO (如果内核支持)"
  echo ""
  printf "      针对高并发多用户场景:\n"
  echo "      • 显著增大 conntrack (至少 262144)"
  echo "      • 增大 somaxconn 和 backlog"
  echo "      • 启用 tcp_tw_reuse"
  echo "      • 扩大 ip_local_port_range"
  echo ""
  
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                   推荐执行步骤                                 ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  echo "  1️⃣  选择/探测目标地区和运营商 (菜单选项 1)"
  echo "  2️⃣  如果 RTT > 100ms，切换到 latency 模式 (菜单选项 5)"
  echo "  3️⃣  如果未安装 BBR，安装 XanMod 内核 (菜单选项 4)"
  echo "  4️⃣  运行完整优化流水线 (菜单选项 10)"
  echo "  5️⃣  重启系统使内核生效"
  echo "  6️⃣  验证优化效果 (菜单选项 11)"
  echo ""
  pause
}

# ============================================================
# 第九部分：系统优化执行函数
# ============================================================

apply_sysctl_config() {
  _section "应用 Sysctl 优化配置"
  
  if [ "$BUFFERS_CALCULATED" -eq 0 ]; then
    _warn "请先计算缓冲区参数（会在检测网络参数后自动计算）"
    return 1
  fi
  
  local tmpfile="${TMP}/sysctl.conf"
  local somax=131072
  [ "$MODE" = "aggressive" ] && somax=262144
  
  cat >"$tmpfile" <<EOF
# ============================================================
# 代理翻墙网络优化配置
# 生成时间: $(date)
# 优化模式: $MODE
# RTT: ${NET[rtt]} ms | 带宽: ${NET[bw]} Mbps
# ============================================================

# 拥塞控制
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP 核心缓冲区
net.core.rmem_default = 262144
net.core.wmem_default = 262144
net.core.rmem_max = ${NET[tcp_rmem_max]}
net.core.wmem_max = ${NET[tcp_wmem_max]}
net.core.optmem_max = 524288

# TCP 套接字缓冲区
net.ipv4.tcp_rmem = ${NET[tcp_rmem_min]} ${NET[tcp_rmem_def]} ${NET[tcp_rmem_max]}
net.ipv4.tcp_wmem = ${NET[tcp_wmem_min]} ${NET[tcp_wmem_def]} ${NET[tcp_wmem_max]}

# TCP 优化
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.core.somaxconn = ${somax}
net.ipv4.tcp_max_syn_backlog = ${somax}
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 3

# UDP 缓冲区
net.ipv4.udp_rmem_min = ${NET[udp_rmem_min]}
net.ipv4.udp_wmem_min = ${NET[udp_wmem_min]}
net.ipv4.udp_mem = ${NET[udp_mem_min]} ${NET[udp_mem_prs]} ${NET[udp_mem_max]}

# 网络设备参数
net.core.netdev_max_backlog = ${NET[backlog]}
net.core.netdev_budget = ${NET[budget]}
net.core.netdev_budget_usecs = 5000
net.core.rps_sock_flow_entries = 65536

# 端口范围
net.ipv4.ip_local_port_range = 10000 65535

# IP 转发（代理必需）
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# Conntrack 优化
net.netfilter.nf_conntrack_max = ${NET[conntrack]}
net.netfilter.nf_conntrack_tcp_timeout_established = 3600
net.netfilter.nf_conntrack_udp_timeout = 60
net.netfilter.nf_conntrack_tcp_be_liberal = 1
net.netfilter.nf_conntrack_tcp_loose = 1

# 内存管理
vm.swappiness = 1
vm.vfs_cache_pressure = 50
vm.min_free_kbytes = 65536

# 文件描述符
fs.file-max = 2097152
fs.nr_open = 2097152
EOF

  run_cmd "install -m 0644 '$tmpfile' '$SYSCTL_FILE'"
  
  _log "正在应用 sysctl 配置..."
  if sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1; then
    _ok "Sysctl 配置已成功应用"
  else
    _warn "部分 sysctl 配置应用失败（可能需要重启）"
  fi
}

optimize_network_card() {
  _section "网卡硬件优化"
  
  if [ "$SYSTEM_DETECTED" -eq 0 ]; then
    _warn "请先检测系统信息（选项 2）"
    return 1
  fi
  
  local iface="${SYS[iface]}"
  
  # Ring Buffer 优化（修复：完善数值验证）
  local rx_max=${NIC[rx_max]:-0}
  local tx_max=${NIC[tx_max]:-0}
  
  if is_valid_int "$rx_max" && is_valid_int "$tx_max"; then
    if [ "$rx_max" -gt 512 ] && [ "$tx_max" -gt 512 ]; then
      local rx=$(( rx_max * 75 / 100 ))
      local tx=$(( tx_max * 75 / 100 ))
      [ "$rx" -lt 512 ] && rx=512
      [ "$tx" -lt 512 ] && tx=512
      
      _log "设置 Ring Buffer: RX=$rx TX=$tx"
      run_cmd "ethtool -G '$iface' rx $rx tx $tx 2>/dev/null"
    fi
  else
    _log "跳过 Ring Buffer 设置（无法读取当前值）"
  fi
  
  # Offload 功能
  _log "启用硬件 Offload 功能..."
  run_cmd "ethtool -K '$iface' tso on gso on sg on 2>/dev/null"
  
  # VirtIO 特殊优化
  if [[ "${SYS[virt],,}" == *"kvm"* ]] || [[ "${NIC[driver],,}" == *"virtio"* ]]; then
    _log "应用 VirtIO 专用优化..."
    run_cmd "ethtool -K '$iface' tx-nocache-copy off 2>/dev/null"
    run_cmd "ethtool -K '$iface' tx-checksum-ipv4 on 2>/dev/null"
  fi
  
  # GRO 设置（根据模式）
  if [ "$MODE" = "latency" ]; then
    _log "Latency 模式: 关闭 GRO/LRO"
    run_cmd "ethtool -K '$iface' gro off lro off 2>/dev/null"
  else
    _log "启用 GRO 和 UDP GRO"
    run_cmd "ethtool -K '$iface' gro on 2>/dev/null"
    run_cmd "ethtool -K '$iface' rx-gro-list on 2>/dev/null"
    run_cmd "ethtool -K '$iface' rx-udp-gro-forwarding on 2>/dev/null"
  fi
  
  # Coalesce 参数（根据模式）
  local rx_usecs=125 rx_frames=64
  case "$MODE" in
    latency)
      rx_usecs=30
      rx_frames=16
      ;;
    aggressive)
      rx_usecs=100
      rx_frames=64
      ;;
    *)
      rx_usecs=200
      rx_frames=128
      ;;
  esac
  
  _log "设置 Coalesce: rx-usecs=$rx_usecs rx-frames=$rx_frames"
  run_cmd "ethtool -C '$iface' rx-usecs $rx_usecs rx-frames $rx_frames adaptive-rx off 2>/dev/null"
  
  # 队列数量优化
  local desired=${SYS[cpu]}
  [ "$desired" -gt 32 ] && desired=32
  
  local nic_queues=${NIC[queues]:-1}
  if is_valid_int "$nic_queues"; then
    [ "$desired" -gt "$nic_queues" ] && desired=$nic_queues
  fi
  
  _log "设置队列数量: $desired"
  run_cmd "ethtool -L '$iface' combined $desired 2>/dev/null"
  
  _ok "网卡优化完成"
}

optimize_irq_rps_xps() {
  _section "IRQ/RPS/XPS 优化"
  
  if [ "$SYSTEM_DETECTED" -eq 0 ]; then
    _warn "请先检测系统信息（选项 2）"
    return 1
  fi
  
  local iface="${SYS[iface]}"
  local mask=$(cpu_mask_hex "${SYS[cpu]}")
  
  _log "CPU 掩码: $mask"
  
  local qdir="/sys/class/net/$iface/queues"
  if [ ! -d "$qdir" ]; then
    _warn "未找到队列目录，跳过 RPS/XPS 设置"
    return
  fi
  
  # RPS 设置
  local rps_cnt=0
  for rxq in "$qdir"/rx-*; do
    [ -e "$rxq/rps_cpus" ] || continue
    echo "$mask" > "$rxq/rps_cpus" 2>/dev/null && rps_cnt=$((rps_cnt+1))
    echo 4096 > "$rxq/rps_flow_cnt" 2>/dev/null
  done
  [ "$rps_cnt" -gt 0 ] && _ok "已为 $rps_cnt 个 RX 队列设置 RPS"
  
  # XPS 设置
  local tx_idx=0 xps_cnt=0
  for txq in "$qdir"/tx-*; do
    [ -e "$txq/xps_cpus" ] || continue
    local cpu_idx=$(( tx_idx % SYS[cpu] ))
    local single=$(printf '%x' $((1<<cpu_idx)) 2>/dev/null || echo "1")
    echo "$single" > "$txq/xps_cpus" 2>/dev/null && xps_cnt=$((xps_cnt+1))
    tx_idx=$((tx_idx+1))
  done
  [ "$xps_cnt" -gt 0 ] && _ok "已为 $xps_cnt 个 TX 队列设置 XPS"
}

optimize_conntrack() {
  _section "Conntrack 优化"
  
  if [ "$BUFFERS_CALCULATED" -eq 0 ]; then
    _warn "请先计算缓冲区参数"
    return 1
  fi
  
  local ct=${NET[conntrack]}
  
  _log "设置 conntrack 最大连接数: $ct"
  run_cmd "sysctl -w net.netfilter.nf_conntrack_max=$ct >/dev/null 2>&1"
  
  local hash=$(( ct / 4 ))
  if [ -w /sys/module/nf_conntrack/parameters/hashsize ]; then
    echo "$hash" > /sys/module/nf_conntrack/parameters/hashsize 2>/dev/null
    _ok "设置 conntrack hashsize: $hash"
  fi
  
  _log "启用 conntrack 宽松模式（适合代理）"
  run_cmd "sysctl -w net.netfilter.nf_conntrack_tcp_be_liberal=1 >/dev/null 2>&1"
  run_cmd "sysctl -w net.netfilter.nf_conntrack_tcp_loose=1 >/dev/null 2>&1"
  
  _ok "Conntrack 优化完成"
}

optimize_cpu() {
  _section "CPU 优化"
  
  if has cpupower; then
    _log "设置 CPU 频率调节器为 performance"
    run_cmd "cpupower frequency-set -g performance 2>/dev/null"
  fi
  
  if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
    _log "设置透明大页为 madvise"
    echo madvise > /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null
    echo defer > /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null
  fi
  
  _ok "CPU 优化完成"
}

install_monitoring() {
  _section "安装监控服务"
  
  if [ "$SYSTEM_DETECTED" -eq 0 ]; then
    _warn "请先检测系统信息（选项 2）"
    return 1
  fi
  
  local script="$MONITOR_SCRIPT"
  local iface="${SYS[iface]}"
  
  cat > "$TMP/monitor.sh" <<'MONITOR_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

IFACE="__IFACE__"
LOG="/var/log/proxy-ultimate-monitor.log"
INTERVAL=15
COOLDOWN=60
EWMA_SCALE=10000
ALPHA=200
LAST_ADJUST=0
EWMA_RETRANS=0
CURRENT_USECS=125

log() { echo "[$(date +'%F %T')] $*" >> "$LOG"; }

get_tcp_ext() {
  awk "/^TcpExt:/ {for(i=2;i<=NF;i++) if(\$i==\"$1\"){getline; print \$i; exit}}" /proc/net/netstat 2>/dev/null || echo 0
}

RX_PKTS=$(cat /sys/class/net/$IFACE/statistics/rx_packets 2>/dev/null || echo 0)
RX_BYTES=$(cat /sys/class/net/$IFACE/statistics/rx_bytes 2>/dev/null || echo 0)
RETRANS=$(get_tcp_ext TCPRetransSegs)
SEGS=$(get_tcp_ext TCPSegsOut)
CURRENT_USECS=$(ethtool -c "$IFACE" 2>/dev/null | awk '/rx-usecs:/ {print $2}' || echo 125)

log "Monitor started: iface=$IFACE usecs=$CURRENT_USECS"

while true; do
  sleep "$INTERVAL"
  
  rx_new=$(cat /sys/class/net/$IFACE/statistics/rx_packets 2>/dev/null || echo 0)
  pps=$(( (rx_new - RX_PKTS) / INTERVAL ))
  RX_PKTS=$rx_new
  
  retrans_new=$(get_tcp_ext TCPRetransSegs)
  segs_new=$(get_tcp_ext TCPSegsOut)
  d_retrans=$(( retrans_new - RETRANS ))
  d_segs=$(( segs_new - SEGS ))
  RETRANS=$retrans_new
  SEGS=$segs_new
  
  rate_scaled=0
  if [ "$d_segs" -gt 0 ]; then
    rate_scaled=$(( d_retrans * EWMA_SCALE / d_segs ))
  fi
  
  EWMA_RETRANS=$(( (EWMA_RETRANS*(EWMA_SCALE - ALPHA) + rate_scaled*ALPHA) / EWMA_SCALE ))
  
  target_usecs=250
  if [ "$pps" -gt 500000 ]; then target_usecs=20
  elif [ "$pps" -gt 300000 ]; then target_usecs=40
  elif [ "$pps" -gt 150000 ]; then target_usecs=80
  elif [ "$pps" -gt 50000 ]; then target_usecs=125
  fi
  
  if [ "$EWMA_RETRANS" -gt 150 ]; then
    target_usecs=$(( target_usecs / 2 ))
  fi
  
  now=$(date +%s)
  if [ "$target_usecs" -ne "$CURRENT_USECS" ] && [ $(( now - LAST_ADJUST )) -gt $COOLDOWN ]; then
    if ethtool -C "$IFACE" rx-usecs "$target_usecs" 2>/dev/null; then
      log "COALESCE: pps=$pps ewma=$(awk -v r=$EWMA_RETRANS 'BEGIN{printf \"%.4f\", r/10000}') -> usecs=$target_usecs"
      CURRENT_USECS=$target_usecs
      LAST_ADJUST=$now
    fi
  fi
  
  mkdir -p /var/lib/node_exporter/textfile_collector 2>/dev/null || true
  {
    echo "# TYPE proxy_opt_retrans gauge"
    awk -v r="$EWMA_RETRANS" 'BEGIN{printf "proxy_opt_retrans %.4f\n", r/10000}'
    echo "proxy_opt_pps $pps"
  } > /var/lib/node_exporter/textfile_collector/proxy_opt.prom
done
MONITOR_SCRIPT

  sed -i "s|__IFACE__|$iface|g" "$TMP/monitor.sh"
  run_cmd "install -m 0755 '$TMP/monitor.sh' '$script'"
  
  cat > "$TMP/monitor.service" <<SERVICE
[Unit]
Description=Proxy Ultimate Monitor
After=network.target

[Service]
Type=simple
ExecStart=$script
Restart=always
RestartSec=10
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
SERVICE

  run_cmd "install -m 0644 '$TMP/monitor.service' '$MONITOR_SERVICE'"
  run_cmd "systemctl daemon-reload"
  run_cmd "systemctl enable --now proxy-ultimate-monitor.service"
  
  cat > "$TMP/logrotate" <<LOGROTATE
/var/log/proxy-ultimate-monitor.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
    create 0640 root adm
}
LOGROTATE

  run_cmd "install -m 0644 '$TMP/logrotate' '$LOGROTATE_FILE'"
  
  _ok "监控服务安装完成"
}

install_health_check() {
  _section "安装健康检查脚本"
  
  if [ "$SYSTEM_DETECTED" -eq 0 ]; then
    _warn "请先检测系统信息（选项 2）"
    return 1
  fi
  
  local iface="${SYS[iface]}"
  
  cat > "$TMP/health.sh" <<'HEALTH'
#!/usr/bin/env bash
set -euo pipefail

iface="__IFACE__"

cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "")
if ! echo "$cc" | grep -qw "bbr"; then
  echo "BBR 未启用: $cc" >&2
  exit 1
fi

rmem=$(sysctl -n net.core.rmem_max 2>/dev/null || echo 0)
if [ "$rmem" -lt 65536 ]; then
  echo "接收缓冲区过小: $rmem" >&2
  exit 1
fi

if ! tc qdisc show dev "$iface" | grep -q -E 'fq|cake'; then
  echo "队列调度器未优化" >&2
  exit 1
fi

echo "健康检查通过"
exit 0
HEALTH

  sed -i "s|__IFACE__|$iface|g" "$TMP/health.sh"
  run_cmd "install -m 0755 '$TMP/health.sh' '$HEALTH_SCRIPT'"
  
  _ok "健康检查脚本已安装: $HEALTH_SCRIPT"
}

run_health_check() {
  _section "执行健康检查"
  
  if [ ! -x "$HEALTH_SCRIPT" ]; then
    _warn "健康检查脚本未安装，请先运行完整优化"
    return 1
  fi
  
  if "$HEALTH_SCRIPT"; then
    _ok "健康检查通过"
  else
    _warn "健康检查失败，请检查配置"
    return 1
  fi
}

install_xanmod_kernel() {
  _section "安装 XanMod 内核"
  
  _log "添加 XanMod 仓库..."
  if ! has curl; then
    run_cmd "apt-get update -y"
    run_cmd "apt-get install -y curl gnupg2"
  fi
  
  run_cmd "curl -fsSL https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg"
  run_cmd "echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' > /etc/apt/sources.list.d/xanmod.list"
  
  _log "更新软件源..."
  run_cmd "apt-get update -y"
  
  _log "安装 XanMod 内核..."
  if run_cmd "apt-get install -y linux-xanmod"; then
    _ok "XanMod 内核安装成功"
    echo ""
    echo "⚠️  重要提示:"
    echo "    请重启系统以使用新内核"
    echo "    重启后可验证: uname -r"
    echo ""
  else
    _warn "XanMod 安装失败，尝试安装 BBR v3 作为替代..."
    install_bbr3_kernel
  fi
  
  pause
}

install_bbr3_kernel() {
  _section "安装 BBR v3 内核（备选方案）"
  
  local arch=$(uname -m)
  local arch_filter=""
  
  case "$arch" in
    aarch64) arch_filter="arm64" ;;
    x86_64) arch_filter="x86_64" ;;
    *) _warn "不支持的架构: $arch"; return 1 ;;
  esac
  
  _log "从 GitHub 获取 BBR v3 release..."
  local api_url="https://api.github.com/repos/byJoey/Actions-bbr-v3/releases"
  
  local release_data
  if ! release_data=$(curl -sL "$api_url"); then
    _warn "无法访问 GitHub API"
    return 1
  fi
  
  local latest_tag
  latest_tag=$(echo "$release_data" | jq -r --arg filter "$arch_filter" 'map(select(.tag_name | test($filter; "i"))) | sort_by(.published_at) | .[-1].tag_name' 2>/dev/null || true)
  
  if [ -z "$latest_tag" ] || [ "$latest_tag" = "null" ]; then
    _warn "未找到适配的 BBR v3 版本"
    return 1
  fi
  
  _ok "找到 BBR v3 版本: $latest_tag"
  
  local asset_urls
  asset_urls=$(echo "$release_data" | jq -r --arg tag "$latest_tag" '.[] | select(.tag_name == $tag) | .assets[].browser_download_url' 2>/dev/null)
  
  rm -f /tmp/linux-*.deb
  
  _log "下载内核包..."
  for url in $asset_urls; do
    _log "  下载: $(basename "$url")"
    wget -q --show-progress "$url" -P /tmp/ || _warn "下载失败: $url"
  done
  
  if ! ls /tmp/linux-*.deb &> /dev/null; then
    _warn "下载失败，未找到内核包"
    return 1
  fi
  
  _log "卸载旧版 joeyblog 内核..."
  local old_packages
  old_packages=$(dpkg -l | grep "joeyblog" | awk '{print $2}' | tr '\n' ' ' || true)
  if [ -n "$old_packages" ]; then
    run_cmd "apt-get remove --purge -y $old_packages"
  fi
  
  _log "安装 BBR v3 内核包..."
  run_cmd "dpkg -i /tmp/linux-*.deb"
  run_cmd "apt-get install -f -y"
  
  if command -v update-grub &> /dev/null; then
    run_cmd "update-grub"
  fi
  
  _ok "BBR v3 内核安装完成"
  echo ""
  echo "⚠️  重要提示:"
  echo "    请重启系统以使用新内核"
  echo "    重启后可验证: uname -r"
  echo ""
}

run_full_optimization() {
  _section "执行完整优化流程"
  
  echo "准备执行以下步骤:"
  echo "  1. 检查并安装系统依赖"
  echo "  2. 检测系统信息"
  echo "  3. 检测网络参数（保留已设置的值）"
  echo "  4. 计算缓冲区"
  echo "  5. 应用 sysctl 配置"
  echo "  6. 优化网卡"
  echo "  7. 优化 IRQ/RPS/XPS"
  echo "  8. 优化 Conntrack"
  echo "  9. 优化 CPU"
  echo " 10. 安装监控服务"
  echo " 11. 安装健康检查"
  echo ""
  echo "按回车继续，Ctrl+C 取消..."
  read -r
  
  # 1. 安装依赖
  _section "步骤 1/11: 检查系统依赖"
  check_and_install_dependencies
  
  # 2. 检测系统信息
  _section "步骤 2/11: 检测系统信息"
  detect_system_info
  
  # 3. 检测网络参数（修复：不覆盖用户设置）
  _section "步骤 3/11: 检测网络参数"
  
  # 检查是否有用户设置或探测结果
  if [ -n "$FORCE_RTT" ] && [ "$FORCE_RTT" != "0" ]; then
    _ok "保留手动设置的 RTT: ${FORCE_RTT} ms"
  elif [ -n "$SELECTED_RTT" ] && [ "$SELECTED_RTT" != "0" ]; then
    _ok "保留探测点的 RTT: ${SELECTED_RTT} ms"
  else
    _log "未找到手动设置或探测的 RTT，将进行自动检测"
  fi
  
  if [ -n "$FORCE_BW" ] && [ "$FORCE_BW" != "0" ]; then
    _ok "保留手动设置的带宽: ${FORCE_BW} Mbps"
  else
    _log "未找到手动设置的带宽，将进行自动检测"
  fi
  
  detect_network_params
  
  # 4. 计算缓冲区
  _section "步骤 4/11: 计算缓冲区参数"
  calculate_buffers
  
  # 5-9. 应用优化
  _section "步骤 5/11: 应用 Sysctl 配置"
  apply_sysctl_config
  
  _section "步骤 6/11: 优化网卡参数"
  optimize_network_card
  
  _section "步骤 7/11: 优化 IRQ/RPS/XPS"
  optimize_irq_rps_xps
  
  _section "步骤 8/11: 优化 Conntrack"
  optimize_conntrack
  
  _section "步骤 9/11: 优化 CPU"
  optimize_cpu
  
  # 10-11. 安装工具
  _section "步骤 10/11: 安装监控服务"
  install_monitoring
  
  _section "步骤 11/11: 安装健康检查"
  install_health_check
  
  _section "完整优化流程执行完成"
  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║                     优化摘要                                   ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""
  printf "  🖥️  系统: ${SYS[kernel]} | CPU: ${SYS[cpu]} 核 | 内存: ${SYS[mem_gb]} GB\n"
  printf "  🌐 网卡: ${SYS[iface]} | 驱动: ${NIC[driver]}\n"
  printf "  📊 带宽: ${NET[bw]} Mbps | RTT: ${NET[rtt]} ms | BDP: ${NET[bdp_mb]} MB\n"
  printf "  🚀 拥塞控制: ${NET[bbr_best]}\n"
  printf "  ⚙️  优化模式: $MODE\n"
  echo ""
  
  if [ "${NET[bbr_best]}" = "none" ]; then
    echo "  ⚠️  未检测到 BBR，建议安装 XanMod 或 BBR v3 内核（选项 4）"
  fi
  
  echo ""
  echo "  ✅ 优化已应用，建议重启系统以确保所有设置生效"
  echo ""
  pause
}

# ============================================================
# 第十部分：主菜单与交互界面
# ============================================================

show_main_menu() {
  clear
  cat <<'BANNER'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║       🚀 代理翻墙网络终极优化工具 v2.1 🚀                      ║
║                                                              ║
║          专为 Shadowsocks/V2Ray/Trojan/WireGuard 优化         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
BANNER

  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  系统状态"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  
  if [ "$SYSTEM_DETECTED" -eq 1 ]; then
    printf "  内核: \033[32m%s\033[0m | CPU: \033[32m%s\033[0m 核 | 内存: \033[32m%s\033[0m GB\n" "${SYS[kernel]}" "${SYS[cpu]}" "${SYS[mem_gb]}"
  else
    echo "  未检测系统信息（请先运行选项 2）"
  fi
  
  if [ "$NETWORK_DETECTED" -eq 1 ]; then
    printf "  带宽: \033[32m%s\033[0m Mbps | RTT: \033[32m%s\033[0m ms | BBR: \033[32m%s\033[0m\n" "${NET[bw]}" "${NET[rtt]}" "${NET[bbr_best]}"
  fi
  
  if [ -n "$SELECTED_IP" ]; then
    printf "  探测点: \033[33m%s - %s (%s)\033[0m | RTT: \033[33m%s ms\033[0m\n" "$SELECTED_REGION" "$SELECTED_ISP" "$SELECTED_IP" "$SELECTED_RTT"
  fi
  
  printf "  当前模式: \033[36m%s\033[0m\n" "$MODE"
  
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "  主菜单"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
  echo "  📍 探测与分析"
  echo "     1. 🌐 选择地区和运营商进行探测"
  echo "     2. 🔍 检测系统信息（CPU/内存/网卡）"
  echo "     3. 🧠 智能分析与优化建议"
  echo ""
  echo "  🔧 系统优化"
  echo "     4. 🚀 安装或升级 XanMod 内核（BBR3）"
  echo "     5. ⚙️  切换优化模式（当前: $MODE）"
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
  echo ""
  echo "  ❓ 其他"
  echo "    14. 📚 查看使用说明"
  echo "     0. 🚪 退出程序"
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

show_usage_guide() {
  _section "使用说明"
  
  cat <<'GUIDE'

╔══════════════════════════════════════════════════════════════╗
║                        快速开始指南                            ║
╚══════════════════════════════════════════════════════════════╝

🎯 推荐流程（首次使用）:

  1️⃣  选择地区和运营商探测（选项 1）
      → 选择你的服务器所在地区和目标用户的运营商
      → 系统会自动测试延迟

  2️⃣  查看智能分析（选项 3）
      → 根据你的 RTT 和带宽，系统会给出优化建议
      → 了解你的网络环境特点

  3️⃣  安装 XanMod 内核（选项 4）
      → 如果 BBR 未启用，强烈建议安装
      → BBR 对高延迟环境提升明显（10-40%）
      → 安装后需要重启

  4️⃣  执行完整优化（选项 10）
      → 一键应用所有优化配置
      → 包括 sysctl、网卡、IRQ 等全方位优化

  5️⃣  重启服务器
      → 使内核和所有配置生效

  6️⃣  运行健康检查（选项 11）
      → 验证优化是否成功应用


╔══════════════════════════════════════════════════════════════╗
║                      优化模式说明                              ║
╚══════════════════════════════════════════════════════════════╝

  🔸 latency 模式（低延迟优先）
     • 适用场景: RTT > 100ms 的高延迟环境
     • 特点: 关闭 GRO/LRO，降低 coalesce，减少批处理
     • 推荐用于: 交互型代理、游戏加速、SSH

  🔸 normal 模式（平衡模式）
     • 适用场景: RTT 50-100ms 的常规环境
     • 特点: 平衡延迟和吞吐量
     • 推荐用于: 大多数代理场景

  🔸 aggressive 模式（高吞吐优先）
     • 适用场景: RTT < 50ms 的低延迟环境
     • 特点: 最大化缓冲区，启用所有硬件加速
     • 推荐用于: 高带宽流媒体代理


╔══════════════════════════════════════════════════════════════╗
║                      重要说明                                  ║
╚══════════════════════════════════════════════════════════════╝

  ⚠️  注意事项:
     • 本脚本会修改系统网络参数，建议先备份配置
     • 安装新内核后必须重启才能生效
     • 虚拟机（VPS）可能不支持某些硬件优化
     • 建议在低峰期执行优化，避免影响在线服务

  📊 性能提升预期:
     • 标准 VPS: 10-30% 吞吐提升，延迟降低 5-15ms
     • 高延迟环境 + BBR: 20-40% 性能提升
     • 物理机: 30-60% 吞吐提升（硬件加速）

  🔧 故障排查:
     • 如果优化后出现问题，可删除 /etc/sysctl.d/99-proxy-ultimate.conf
     • 然后执行: sysctl --system
     • 或者重启服务器恢复默认设置

  💾 状态持久化:
     • 脚本会自动保存状态到 /var/lib/proxy-optimizer/state.conf
     • 重启后会自动加载之前的设置
     • 探测结果、手动设置的参数都会被保存

GUIDE

  pause
}

show_system_status() {
  _section "系统状态详情"
  
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  系统信息"
  echo "═══════════════════════════════════════════════════════════"
  uname -a
  echo ""
  
  if has lsb_release; then
    lsb_release -a 2>/dev/null
    echo ""
  fi
  
  echo "═══════════════════════════════════════════════════════════"
  echo "  网络接口"
  echo "═══════════════════════════════════════════════════════════"
  ip addr show
  echo ""
  
  echo "═══════════════════════════════════════════════════════════"
  echo "  当前 Sysctl 关键参数"
  echo "═══════════════════════════════════════════════════════════"
  sysctl net.ipv4.tcp_congestion_control 2>/dev/null || true
  sysctl net.core.default_qdisc 2>/dev/null || true
  sysctl net.core.rmem_max 2>/dev/null || true
  sysctl net.core.wmem_max 2>/dev/null || true
  sysctl net.netfilter.nf_conntrack_max 2>/dev/null || true
  echo ""
  
  if [ -n "${SYS[iface]:-}" ]; then
    echo "═══════════════════════════════════════════════════════════"
    echo "  网卡 ${SYS[iface]} 详细信息"
    echo "═══════════════════════════════════════════════════════════"
    ethtool "${SYS[iface]}" 2>/dev/null || echo "ethtool 信息获取失败"
    echo ""
  fi
  
  pause
}

switch_mode() {
  _section "切换优化模式"
  
  echo ""
  echo "当前模式: $MODE"
  echo ""
  echo "可用模式:"
  echo "  1. latency    - 低延迟优先（适合高延迟环境）"
  echo "  2. normal     - 平衡模式（适合大多数场景）"
  echo "  3. aggressive - 高吞吐优先（适合低延迟环境）"
  echo ""
  echo "请选择模式 (1-3，0 取消): "
  read -r choice
  
  case "$choice" in
    1) MODE="latency"; _ok "已切换到 latency 模式" ;;
    2) MODE="normal"; _ok "已切换到 normal 模式" ;;
    3) MODE="aggressive"; _ok "已切换到 aggressive 模式" ;;
    0) _log "已取消" ;;
    *) _warn "无效选择" ;;
  esac
  
  save_state
  pause
}

manual_set_params() {
  _section "手动设置参数"
  
  echo ""
  echo "当前参数:"
  echo "  RTT: ${NET[rtt]:-未设置} ms"
  echo "  带宽: ${NET[bw]:-未设置} Mbps"
  echo ""
  
  echo "请输入 RTT (毫秒，留空跳过): "
  read -r rtt_input
  if [ -n "$rtt_input" ]; then
    FORCE_RTT="$rtt_input"
    NET[rtt]=$(to_int "$rtt_input")
    _ok "已设置 RTT: ${NET[rtt]} ms"
  fi
  
  echo "请输入带宽 (Mbps，留空跳过): "
  read -r bw_input
  if [ -n "$bw_input" ]; then
    FORCE_BW="$bw_input"
    NET[bw]=$(to_int "$bw_input")
    _ok "已设置带宽: ${NET[bw]} Mbps"
  fi
  
  if [ -n "$rtt_input" ] || [ -n "$bw_input" ]; then
    save_state
    echo ""
    echo "是否重新计算缓冲区参数? (y/N): "
    read -r confirm
    if [[ "${confirm,,}" = "y" ]]; then
      calculate_buffers
    fi
  fi
  
  pause
}

# ============================================================
# 第十一部分：主程序入口
# ============================================================

main() {
  # 加载持久化状态
  load_state
  
  # 检查 root 和系统
  check_root
  check_and_install_dependencies
  
  # 主循环
  while true; do
    show_main_menu
    
    echo -n "请选择操作 (0-14): "
    read -r choice
    
    case "$choice" in
      0)
        echo ""
        _ok "感谢使用，再见！"
        exit 0
        ;;
      1)
        select_region_and_probe
        ;;
      2)
        detect_system_info
        detect_network_params
        calculate_buffers
        pause
        ;;
      3)
        if [ "$SYSTEM_DETECTED" -eq 0 ]; then
          _warn "请先运行选项 2 检测系统信息"
          pause
        else
          show_intelligent_analysis
        fi
        ;;
      4)
        install_xanmod_kernel
        ;;
      5)
        switch_mode
        ;;
      6)
        manual_set_params
        ;;
      7)
        apply_sysctl_config
        pause
        ;;
      8)
        optimize_network_card
        pause
        ;;
      9)
        optimize_irq_rps_xps
        pause
        ;;
      10)
        run_full_optimization
        ;;
      11)
        run_health_check
        pause
        ;;
      12)
        install_monitoring
        pause
        ;;
      13)
        show_system_status
        ;;
      14)
        show_usage_guide
        ;;
      *)
        _warn "无效选择，请重新输入"
        sleep 2
        ;;
    esac
  done
}

# 脚本入口
main

# End of script
