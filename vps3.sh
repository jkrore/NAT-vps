#!/usr/bin/env bash
#
# net-optimizer-final.sh
# 终极版：TCP+UDP 智能优化器（激进默认、立即应用）
# - 优点：自动检测 SSH 客户端 IP -> ping -> BDP 计算 -> 生成并写入 sysctl
# -       支持 iperf3 hook、冲突备份（改名备份）、回滚脚本、GRUB 激进修改（可选）
# - 说明：你要求不考虑安全，脚本默认激进并直接 apply；如果你希望保守运行，传 --dry-run 或 --conservative
#
set -euo pipefail
IFS=$'\n\t'

# -------------------- 配置默认 --------------------
PROG="$(basename "$0")"
VERSION="2025-09-23-final"
BACKUP_ROOT="/var/backups/net-optimizer"
SYSCTL_TARGET="/etc/sysctl.d/999-net-optimizer.conf"
KEY_REGEX='^(net\.core\.default_qdisc|net\.core\.rmem_max|net\.core\.wmem_max|net\.core\.rmem_default|net\.core\.wmem_default|net\.ipv4\.tcp_rmem|net\.ipv4\.tcp_wmem|net\.ipv4\.tcp_congestion_control|net\.ipv4\.udp_rmem_min|net\.ipv4\.udp_wmem_min|net\.ipv4\.udp_mem)[[:space:]]*='

# 默认行为（激进并应用）
APPLY=1             # 1=写入并生效，0=dry-run
AGGRESSIVE=1        # 1=激进（改 grub 等），0=不激进
CONSERVATIVE=0      # 若传 --conservative 会覆盖 AGGRESSIVE=0
RUN_IPERF=0
IPERF_SERVERS=()
FORCE=1             # 默认不询问（你要求不考虑安全）
QUIET=0

# 默认带宽/RTT（若未被检测）
DEFAULT_BW_Mbps=1000
DEFAULT_RTT_MS=150

# -------------------- 日志与输出 --------------------
_note() { [ "$QUIET" -eq 0 ] && printf "\033[1;34m[i]\033[0m %s\n" "$*"; }
_ok()   { [ "$QUIET" -eq 0 ] && printf "\033[1;32m[OK]\033[0m %s\n" "$*"; }
_warn() { printf "\033[1;33m[!]\033[0m %s\n" "$*" >&2; }
_err()  { printf "\033[1;31m[!!]\033[0m %s\n" "$*" >&2; }

usage() {
  cat <<EOF
$PROG v$VERSION
用法: sudo ./$PROG [选项]

选项:
  --mem <GiB>            指定内存 GiB（默认自动检测）
  --bw <Mbps>            指定带宽 Mbps（默认 1000）
  --rtt <ms>             指定 RTT ms（默认自动检测或 150）
  --dry-run              仅预览，不写入（覆盖默认激进 apply）
  --conservative         保守模式（不修改 grub 等危险项）
  --iperf ip,ip2         使用 iperf3 进行自动探测（逗号分隔）
  --no-iperf             不运行 iperf（默认不强制）
  --quiet                静默（只输出错误）
  --help                 显示帮助
说明：脚本默认会立即写入并生效（激进）。如需保守，请使用 --dry-run 或 --conservative。
EOF
  exit 0
}

# -------------------- 解析参数 --------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --mem) shift; MEM_G_INPUT="$1"; shift ;;
    --bw) shift; BW_Mbps_INPUT="$1"; shift ;;
    --rtt) shift; RTT_ms_INPUT="$1"; shift ;;
    --dry-run) APPLY=0; shift ;;
    --conservative) AGGRESSIVE=0; CONSERVATIVE=1; shift ;;
    --iperf) shift; IFS=',' read -r -a IPERF_SERVERS <<< "$1"; RUN_IPERF=1; shift ;;
    --no-iperf) RUN_IPERF=0; IPERF_SERVERS=(); shift ;;
    --quiet) QUIET=1; shift ;;
    --help|-h) usage ;;
    *) _err "未知参数: $1"; usage; ;;
  esac
done

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    _err "请以 root 运行 (sudo)"; exit 2
  fi
}
require_root

# -------------------- 工具函数 --------------------
default_iface(){ ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true; }

get_mem_gib() {
  # use MemTotal from /proc/meminfo (KB)
  local mem_kb
  mem_kb=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  awk -v kb="$mem_kb" 'BEGIN{printf "%.2f", (kb/1024/1024)}'
}

# 尝试从 SSH 环境变量读取客户端 IP（优先）
get_ssh_client_ip() {
  if [ -n "${SSH_CONNECTION:-}" ]; then
    echo "$SSH_CONNECTION" | awk '{print $1}'
    return 0
  fi
  if [ -n "${SSH_CLIENT:-}" ]; then
    echo "$SSH_CLIENT" | awk '{print $1}'
    return 0
  fi
  return 1
}

# 稳健的 ping 获取平均 RTT（只返回数值或空字符串）
detect_rtt_ms() {
  local target="$1"
  local out tmp
  tmp="$(mktemp)"
  # try different ping flavors: iputils (rtt line) or busybox
  if ping -c 4 -W 2 "$target" >"$tmp" 2>/dev/null; then
    # try parse rtt/round-trip
    out=$(awk -F'/' '/rtt|round-trip/ {print $5; exit}' "$tmp" || true)
    if [ -z "$out" ]; then
      # try alternative pattern: something like "min/avg/max/mdev = 0.045/0.045/0.045/0.000 ms"
      out=$(grep -Eo '[0-9]+(\.[0-9]+)?/([0-9]+(\.[0-9]+)?)' "$tmp" | head -n1 | awk -F'/' '{print $2}' || true)
    fi
  else
    # ping failed; still try last-line parse
    out=$(tail -n 3 "$tmp" 2>/dev/null | awk -F'/' '/rtt|round-trip/ {print $5; exit}' || true)
  fi
  rm -f "$tmp"
  if [[ "$out" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    # return integer ms
    printf "%.0f" "$out"
  else
    # failure
    echo ""
  fi
}

# BDP 计算（输入 Mbps, ms） -> bytes
calc_bdp_bytes() {
  awk -v bw="$1" -v rtt="$2" 'BEGIN{printf "%.0f", bw*125*rtt}'
}

# bucket down to {4,8,16,32,64} MB
bucket_le_mb() {
  local mb="$1"
  if [ "$mb" -ge 64 ]; then echo 64
  elif [ "$mb" -ge 32 ]; then echo 32
  elif [ "$mb" -ge 16 ]; then echo 16
  elif [ "$mb" -ge 8 ]; then echo 8
  else echo 4
  fi
}

timestamp() { date +%F-%H%M%S; }

# -------------------- 检测并设定参数 --------------------
MEM_G="$(get_mem_gib)"        # 自动检测 GiB
MEM_G="${MEM_G_INPUT:-$MEM_G}"
BW_Mbps="${BW_Mbps_INPUT:-$DEFAULT_BW_Mbps}"

# 自动检测 RTT：优先 SSH 客户端 IP；若无则尝试网关或 1.1.1.1
RTT_MS=""
RTT_SOURCE="auto"
if ssh_ip="$(get_ssh_client_ip 2>/dev/null || true)"; then
  if [ -n "$ssh_ip" ]; then
    _note "自动检测到 SSH 客户端 IP: ${ssh_ip}，优先使用其做 ping 测试"
    rtt_val="$(detect_rtt_ms "$ssh_ip")" || true
    if [ -n "$rtt_val" ]; then
      RTT_MS="$rtt_val"; RTT_SOURCE="ssh-client:$ssh_ip"
      _ok "检测到平均 RTT: ${RTT_MS} ms (来自 SSH 客户端 ${ssh_ip})"
    else
      _warn "Ping ${ssh_ip} 失败或无法解析 RTT，回退到默认/后续检测"
    fi
  fi
fi

if [ -z "${RTT_MS:-}" ]; then
  # 尝试默认网关
  gw_if="$(default_iface)"
  gw_ip=""
  if [ -n "$gw_if" ]; then
    gw_ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1);exit}}' || true)"
  fi
  # use 1.1.1.1 as fallback target to measure
  target="1.1.1.1"
  _note "尝试对 ${target} 进行 RTT 测试..."
  rtt_val="$(detect_rtt_ms "$target")" || true
  if [ -n "$rtt_val" ]; then
    RTT_MS="$rtt_val"; RTT_SOURCE="public:${target}"
    _ok "检测到平均 RTT: ${RTT_MS} ms (来自 ${target})"
  else
    _warn "Ping ${target} 失败或无法解析 RTT，使用默认 ${DEFAULT_RTT_MS} ms"
    RTT_MS="$DEFAULT_RTT_MS"; RTT_SOURCE="fallback-default"
  fi
fi

# ensure numeric
if ! [[ "$RTT_MS" =~ ^[0-9]+$ ]]; then
  _warn "RTT 解析异常（非整数），使用默认 ${DEFAULT_RTT_MS} ms"
  RTT_MS="$DEFAULT_RTT_MS"
fi

_note "最终使用参数: 内存 ${MEM_G} GiB, 带宽 ${BW_Mbps} Mbps, RTT ${RTT_MS} ms"

# -------------------- 计算 BDP 与桶化 --------------------
BDP_BYTES=$(calc_bdp_bytes "$BW_Mbps" "$RTT_MS")
MEM_BYTES=$(awk -v g="$MEM_G" 'BEGIN{printf "%.0f", g*1024*1024*1024}')
TWO_BDP=$(( BDP_BYTES * 2 ))
RAM3_BYTES=$(awk -v m="$MEM_BYTES" 'BEGIN{printf "%.0f", m*0.03}')
CAP64=$((64*1024*1024))

# cap = min(2*BDP, 3%RAM, 64MB)
min3() { awk -v a="$1" -v b="$2" -v c="$3" 'BEGIN{m=a; if(b<m)m=b; if(c<m)m=c; printf "%.0f", m}'; }
MAX_NUM_BYTES=$(min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")
MAX_MB_NUM=$(( MAX_NUM_BYTES / 1024 / 1024 ))
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

_note "BDP ≈ $(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB -> cap ${MAX_MB} MB"

# -------------------- 冲突备份与处理 --------------------
TS=$(timestamp)
BACKUP_DIR="${BACKUP_ROOT}/net-optimizer-${TS}"
mkdir -p "$BACKUP_DIR"
echo "# rollback actions generated at $(date -u)" > "${BACKUP_DIR}/rollback_actions.sh"
chmod 600 "${BACKUP_DIR}/rollback_actions.sh"

comment_conflicts_in_sysctl_conf() {
  local f="/etc/sysctl.conf"
  [ -f "$f" ] || { _ok "/etc/sysctl.conf 不存在"; return 0; }
  if grep -Eq "$KEY_REGEX" "$f"; then
    local bak="${BACKUP_DIR}/sysctl.conf.bak.${TS}"
    cp -a "$f" "$bak"
    _note "备份 /etc/sysctl.conf -> $bak"
    awk -v re="$KEY_REGEX" '
      $0 ~ re && $0 !~ /^[[:space:]]*#/ { print "# " $0; next }
      { print $0 }
    ' "$f" > "${f}.tmp.$$"
    install -m 0644 "${f}.tmp.$$" "$f"
    rm -f "${f}.tmp.$$"
    echo "restore_file \"$bak\" \"/etc/sysctl.conf\"" >> "${BACKUP_DIR}/rollback_actions.sh"
    _ok "已注释 /etc/sysctl.conf 中的冲突键（并记录回滚）"
  else
    _ok "/etc/sysctl.conf 无冲突键"
  fi
}

process_conflict_files_in_dir() {
  local dir="$1"
  [ -d "$dir" ] || { _ok "$dir 不存在"; return 0; }
  shopt -s nullglob
  local moved=0
  for f in "$dir"/*.conf; do
    [ "$(readlink -f "$f")" = "$(readlink -f "$SYSCTL_TARGET")" ] && continue
    if grep -Eq "$KEY_REGEX" "$f"; then
      local dest="${f}.disabled_by_optimizer.${TS}"
      mv -- "$f" "$dest"
      _note "已备份并禁用冲突文件: $f -> $dest"
      echo "mv \"$dest\" \"$f\"" >> "${BACKUP_DIR}/rollback_actions.sh"
      moved=1
    fi
  done
  shopt -u nullglob
  if [ "$moved" -eq 1 ]; then
    _ok "$dir 中的冲突文件已处理（改名备份）"
  else
    _ok "$dir 无需处理"
  fi
}

scan_conflicts_ro() {
  local dir="$1"
  [ -d "$dir" ] || { _ok "$dir 不存在"; return 0; }
  if grep -RIlEq "$KEY_REGEX" "$dir" 2>/dev/null; then
    _warn "发现潜在冲突（只提示不改）：$dir"
    grep -RhnE "$KEY_REGEX" "$dir" 2>/dev/null || true
  else
    _ok "$dir 未发现冲突"
  fi
}

_note "步骤A：备份并注释 /etc/sysctl.conf 冲突键（如有）"
comment_conflicts_in_sysctl_conf

_note "步骤B：备份并改名 /etc/sysctl.d 下含冲突键的旧文件"
process_conflict_files_in_dir "/etc/sysctl.d"

_note "步骤C：扫描其他目录（只读提示）"
scan_conflicts_ro "/usr/local/lib/sysctl.d"
scan_conflicts_ro "/usr/lib/sysctl.d"
scan_conflicts_ro "/lib/sysctl.d"
scan_conflicts_ro "/run/sysctl.d"

# -------------------- 尝试加载 tcp_bbr --------------------
if command -v modprobe >/dev/null 2>&1; then
  modprobe tcp_bbr 2>/dev/null || true
  _ok "尝试加载 tcp_bbr（如内核支持）"
fi

# -------------------- 生成 sysctl 文件（包含 TCP 与 UDP 优化项） --------------------
TMPF="$(mktemp)"
cat >"$TMPF" <<EOF
# Auto-generated by net-optimizer-final
# Inputs: MEM_G=${MEM_G}GiB, BW=${BW_Mbps}Mbps, RTT=${RTT_MS}ms (source=${RTT_SOURCE})
# BDP: ${BDP_BYTES} bytes (~$(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB)
# Caps: min(2*BDP, 3%RAM, 64MB) -> Bucket ${MAX_MB} MB

# --- qdisc & congestion control ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# --- core buffers (applies to TCP and UDP) ---
net.core.rmem_default = ${DEF_R}
net.core.wmem_default = ${DEF_W}
net.core.rmem_max = ${MAX_BYTES}
net.core.wmem_max = ${MAX_BYTES}
net.core.optmem_max = 262144
net.core.netdev_max_backlog = 30000
net.core.somaxconn = 65535
net.core.msg_max = 65535

# --- TCP tuning ---
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
net.ipv4.tcp_congestion_control = bbr

# --- UDP tuning ---
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192
# udp_mem: low/pressure/high (pages) - set reasonably large based on RAM
# set as bytes to pages conversion is internal; using conservative high numbers
net.ipv4.udp_mem = 65536 131072 262144

# --- other kernel VM / performance (aggressive defaults) ---
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5
vm.overcommit_memory = 1
vm.min_free_kbytes = 65536

# --- IPv4 misc ---
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_mtu_probing = 1
net.ipv4.ip_forward = 1
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.default.arp_ignore = 1

# --- logging/limits ---
kernel.pid_max = 65535

EOF

# Add optional additional large-params recommended by some repos (user doesn't care about security)
cat >>"$TMPF" <<'EOF'
# Optional aggressive extras
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_adv_win_scale = 2
EOF

_note "生成 sysctl 内容到临时文件：$TMPF"
# print brief preview
sed -n '1,200p' "$TMPF"

# -------------------- iperf3 测试 hook（若有） --------------------
if [ "${RUN_IPERF:-0}" -eq 1 ] && command -v iperf3 >/dev/null 2>&1; then
  _note "iperf3 hook 启用：开始对 ${IPERF_SERVERS[*]} 运行短测"
  for s in "${IPERF_SERVERS[@]}"; do
    _note "iperf3 -> $s"
    if iperf3 -c "$s" -t 10 -J >/tmp/.iperf_result.json 2>/dev/null; then
      if command -v jq >/dev/null 2>&1; then
        DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/.iperf_result.json)
        UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/.iperf_result.json)
      else
        _warn "未安装 jq，无法解析 iperf3 JSON 输出"
        DL=0; UL=0
      fi
      DL_Mbps=$(( (DL + 500000) / 1000000 ))
      UL_Mbps=$(( (UL + 500000) / 1000000 ))
      _note "iperf3 $s -> DL ${DL_Mbps} Mbps, UL ${UL_Mbps} Mbps"
      # conservative adjust: if measured < configured, lower BW and regenerate caps
      if [ "$DL_Mbps" -gt 0 ] && [ "$DL_Mbps" -lt "$BW_Mbps" ]; then
        _warn "测得带宽低于估计 (${DL_Mbps} < ${BW_Mbps})，将使用测得值作为瓶颈估计"
        BW_Mbps="$DL_Mbps"
        BDP_BYTES=$(calc_bdp_bytes "$BW_Mbps" "$RTT_MS")
        TWO_BDP=$((BDP_BYTES*2))
        MAX_NUM_BYTES=$(min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")
        MAX_MB_NUM=$(( MAX_NUM_BYTES / 1024 / 1024 ))
        MAX_MB=$(bucket_le_mb "$MAX_MB_NUM")
        MAX_BYTES=$(( MAX_MB * 1024 * 1024 ))
        TCP_RMEM_MAX=$MAX_BYTES
        TCP_WMEM_MAX=$MAX_BYTES
        # rewrite TMPF with new caps
        sed -n '1,120p' "$TMPF" > "${TMPF}.bak" || true
        # regenerate top-of-file caps by simple replace:
        awk -v RDEF="$DEF_R" -v WDEF="$DEF_W" -v MAXB="$MAX_BYTES" \
            'BEGIN{printed=0} /# --- core buffers/ {print; while(getline) { if($0~/net.core.rmem_default/) {print "net.core.rmem_default = "RDEF; next} if($0~/net.core.wmem_default/) {print "net.core.wmem_default = "WDEF; next} if($0~/net.core.rmem_max/) {print "net.core.rmem_max = "MAXB; next} if($0~/net.core.wmem_max/) {print "net.core.wmem_max = "MAXB; next} print } printed=1; next} {print}' "$TMPF" > "${TMPF}.new"
        mv -f "${TMPF}.new" "$TMPF"
        _note "基于 iperf3 结果重新调整 caps -> ${MAX_MB} MB"
      fi
    else
      _warn "iperf3 -> $s 测试失败或被阻止"
    fi
    rm -f /tmp/.iperf_result.json || true
  done
else
  if [ "${RUN_IPERF:-0}" -eq 1 ]; then _warn "iperf3 不可用，跳过 iperf hook"; fi
fi

# -------------------- 生成回滚脚本骨架 --------------------
ROLLBACK_SH="${BACKUP_DIR}/rollback.sh"
cat > "$ROLLBACK_SH" <<'BROLL'
#!/usr/bin/env bash
set -euo pipefail
restore_file() {
  local src="$1" dst="$2"
  if [ -f "$src" ]; then
    cp -a "$src" "$dst"
    echo "[rollback] restored $dst from $src"
  else
    echo "[rollback] source $src missing"
  fi
}
BROLL
chmod 700 "$ROLLBACK_SH"
echo "echo '[rollback] 查看并执行本脚本以恢复改动 (backup dir: $BACKUP_DIR)'" >> "$ROLLBACK_SH"

# -------------------- 应用或仅预览 --------------------
if [ "$APPLY" -ne 1 ]; then
  _note "DRY-RUN：仅预览，不写入。要应用请在下一次运行时省略 --dry-run（或不传）"
  echo "===== SUMMARY (DRY-RUN preview) ====="
  echo "Sysctl target: $SYSCTL_TARGET"
  echo "Bucket cap: ${MAX_MB} MB (bytes=${MAX_BYTES})"
  echo "TCP rmem max: ${TCP_RMEM_MAX}, tcp wmem max: ${TCP_WMEM_MAX}"
  sed -n '1,200p' "$TMPF"
  _note "Backups would be placed under: $BACKUP_DIR"
  exit 0
fi

# -------------- 应用写入（不再询问） --------------
_note "写入备份目录: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# 备份旧 target if exists
if [ -f "$SYSCTL_TARGET" ]; then
  cp -a "$SYSCTL_TARGET" "${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TS}"
  echo "restore_file \"${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.${TS}\" \"$SYSCTL_TARGET\"" >> "${BACKUP_DIR}/rollback_actions.sh"
  _note "备份旧的 $SYSCTL_TARGET"
fi

# 将 /etc/sysctl.conf 注释备份动作已经在 comment_conflicts_in_sysctl_conf 中生成 rollback 动作。
# 将 TMPF 移动到目标并设置权限
install -m 0644 "$TMPF" "$SYSCTL_TARGET"
_ok "已写入 $SYSCTL_TARGET"

# 将 rollback_actions.sh 内容追加到 rollback.sh
if [ -f "${BACKUP_DIR}/rollback_actions.sh" ]; then
  cat "${BACKUP_DIR}/rollback_actions.sh" >> "$ROLLBACK_SH"
fi
chmod 700 "$ROLLBACK_SH"
_ok "回滚脚本已生成： $ROLLBACK_SH"

# 重新加载 sysctl
sysctl --system >/dev/null 2>&1 || _warn "sysctl --system 返回非零（请手动检查）"
_ok "sysctl 已重新加载 (sysctl --system)"

# 尝试设置 tc qdisc fq（若 tc 和 iface 可用）
IFACE="$(default_iface)"
if command -v tc >/dev/null 2>&1 && [ -n "$IFACE" ]; then
  tc qdisc replace dev "$IFACE" root fq 2>/dev/null || _warn "设置 qdisc fq 失败（内核可能不含 fq）"
  _ok "尝试设置 qdisc fq 在接口 $IFACE"
  echo "tc qdisc replace dev \"$IFACE\" root pfifo_fast || true" >> "${BACKUP_DIR}/rollback_actions.sh"
else
  _warn "tc 或默认网卡不可用，跳过 qdisc 设置"
fi

# -------------------- 激进模式：修改 GRUB 等（根据 AGGRESSIVE） --------------------
if [ "$AGGRESSIVE" -eq 1 ] && [ "$CONSERVATIVE" -eq 0 ]; then
  _note "激进模式启用：将修改 /etc/default/grub 以添加 mitigations=off 等（若存在）"
  GRUB_CFG="/etc/default/grub"
  if [ -f "$GRUB_CFG" ]; then
    cp -a "$GRUB_CFG" "${BACKUP_DIR}/grub.default.bak.${TS}"
    # 添加 mitigations=off 到 GRUB_CMDLINE_LINUX_DEFAULT
    if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_CFG"; then
      sed -E "s/GRUB_CMDLINE_LINUX_DEFAULT=\"([^\"]*)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 mitigations=off\"/" "$GRUB_CFG" > "${GRUB_CFG}.tmp.$$"
      install -m 0644 "${GRUB_CFG}.tmp.$$" "$GRUB_CFG"
      rm -f "${GRUB_CFG}.tmp.$$"
      echo "restore_file \"${BACKUP_DIR}/grub.default.bak.${TS}\" \"$GRUB_CFG\"" >> "${BACKUP_DIR}/rollback_actions.sh"
      _ok "已修改 $GRUB_CFG（备份在 ${BACKUP_DIR}），请运行 update-grub 以使改动生效"
    else
      _warn "$GRUB_CFG 中未检测到 GRUB_CMDLINE_LINUX_DEFAULT，跳过修改"
    fi
  else
    _warn "$GRUB_CFG 不存在，跳过 GRUB 修改"
  fi
fi

_ok "所有写入完成。备份与回滚信息位于: $BACKUP_DIR"
_ok "若需回滚，请以 root 执行: $ROLLBACK_SH （或查看 $BACKUP_DIR/rollback_actions.sh）"

# 最终打印当前关键 sysctl 值以便核对
echo "==== RESULT ===="
echo "最终使用值 -> 内存: ${MEM_G} GiB, 带宽: ${BW_Mbps} Mbps, RTT: ${RTT_MS} ms (source=${RTT_SOURCE})"
sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true
sysctl -n net.core.default_qdisc 2>/dev/null || true
sysctl -n net.core.rmem_max 2>/dev/null || true
sysctl -n net.core.wmem_max 2>/dev/null || true
sysctl -n net.ipv4.tcp_rmem 2>/dev/null || true
sysctl -n net.ipv4.tcp_wmem 2>/dev/null || true
if command -v tc >/dev/null 2>&1 && [ -n "$IFACE" ]; then
  echo "qdisc on ${IFACE}:"; tc qdisc show dev "$IFACE" || true
fi
echo "==============="
exit 0
