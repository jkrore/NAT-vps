#!/usr/bin/env bash
# net-optimizer.sh
# 统一整合版：BBR+fq 智能优化器（保守默认，dry-run 默认）
# 功能：BDP 计算 -> 生成 sysctl 文件 -> 冲突备份/注释 -> 可选 iperf3 测试 hook -> 可选应用
# 设计原则：默认保守，所有破坏性操作需要 --apply 或 --force 才执行；激进模式需 --aggressive --force-aggressive
set -euo pipefail

### -------------- 配置与帮助 --------------
PROGNAME="$(basename "$0")"
VERSION="1.0.0"
BACKUP_ROOT="/var/backups/net-optimizer"
SYSCTL_TARGET="/etc/sysctl.d/999-net-optimizer.conf"
KEY_REGEX='^(net\.core\.default_qdisc|net\.core\.rmem_max|net\.core\.wmem_max|net\.core\.rmem_default|net\.core\.wmem_default|net\.ipv4\.tcp_rmem|net\.ipv4\.tcp_wmem|net\.ipv4\.tcp_congestion_control)[[:space:]]*='

DRY_RUN=1           # 默认 dry-run
APPLY=0
AGGRESSIVE=0        # 默认保守：不改 grub / 不撤销 mitigations
FORCE_AGGRESSIVE=0
FORCE=0             # 用于跳过 confirmations（小心）
RUN_IPERF=0
IPERF_SERVERS=()
QUIET=0

usage() {
  cat <<EOF
$PROGNAME v$VERSION
用法: sudo $PROGNAME [选项]

选项:
  --mem <GiB>          指定内存（GiB）；默认自动检测
  --bw <Mbps>          指定带宽（Mbps）；默认 1000
  --rtt <ms>           指定 RTT（ms）；默认自动检测（优先 SSH 客户端 IP）
  --apply              写入并生效（默认只是预览）
  --dry-run            显示预览并退出（默认）
  --aggressive         启用激进修改（需同时 --force-aggressive）
  --force-aggressive   允许激进修改（必须配合 --aggressive）
  --force              跳过交互确认（危险）
  --iperf <ip1[,ip2]>  使用 iperf3 测试（逗号分隔的服务端 IP）
  --quiet              静默模式（只输出重要信息）
  -h, --help           显示本帮助并退出

示例:
  sudo $PROGNAME --bw 1000 --apply
  sudo $PROGNAME --iperf 1.2.3.4 --apply
EOF
  exit 0
}

### -------------- 日志与交互包装 --------------
note() { [ "$QUIET" -eq 0 ] && echo -e "\033[1;34m[i]\033[0m $*"; }
ok()   { [ "$QUIET" -eq 0 ] && echo -e "\033[1;32m[OK]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*" >&2; }
bad()  { echo -e "\033[1;31m[!!]\033[0m $*" >&2; }

confirm() {
  local prompt="${1:-Proceed? (yes/no): }"
  if [ "$FORCE" -eq 1 ]; then return 0; fi
  read -r -p "$prompt" ans
  case "$ans" in
    y|Y|yes|YES|Yes) return 0 ;;
    *) return 1 ;;
  esac
}

### -------------- 参数解析 --------------
while [ $# -gt 0 ]; do
  case "$1" in
    --mem) shift; MEM_G_INPUT="$1"; shift ;;
    --bw) shift; BW_Mbps_INPUT="$1"; shift ;;
    --rtt) shift; RTT_ms_INPUT="$1"; shift ;;
    --apply) DRY_RUN=0; APPLY=1; shift ;;
    --dry-run) DRY_RUN=1; APPLY=0; shift ;;
    --aggressive) AGGRESSIVE=1; shift ;;
    --force-aggressive) FORCE_AGGRESSIVE=1; shift ;;
    --force) FORCE=1; shift ;;
    --iperf) shift; IFS=',' read -r -a IPERF_SERVERS <<< "$1"; RUN_IPERF=1; shift ;;
    --quiet) QUIET=1; shift ;;
    -h|--help) usage ;;
    --version) echo "$PROGNAME $VERSION"; exit 0 ;;
    *) bad "未知选项: $1"; usage; ;;
  esac
done

require_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    bad "需要 root 权限，请使用 sudo 运行"; exit 1
  fi
}

require_root

### -------------- 系统检测与辅助函数 --------------
default_iface(){ ip -o -4 route show to default 2>/dev/null | awk '{print $5}' | head -1 || true; }

get_mem_gib() {
  local mem_bytes
  mem_bytes=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  # /proc/meminfo 给的是 KB
  awk -v kb="$mem_bytes" 'BEGIN{printf "%.2f", (kb/1024/1024)}'
}

get_ssh_client_ip() {
  # SSH_CONNECTION 格式: clientIP clientPort serverIP serverPort
  if [ -n "${SSH_CONNECTION:-}" ]; then
    echo "$SSH_CONNECTION" | awk '{print $1}'
    return 0
  fi
  # 如果运行在 systemd user 会话可能有环境变量 SSH_CLIENT
  if [ -n "${SSH_CLIENT:-}" ]; then
    echo "$SSH_CLIENT" | awk '{print $1}'
    return 0
  fi
  return 1
}

get_rtt_ms() {
  local ping_target=""
  local ping_desc=""

  if ping_target="$(get_ssh_client_ip 2>/dev/null || true)"; then
    if [ -n "$ping_target" ]; then
      ping_desc="SSH 客户端 ${ping_target}"
      note "自动检测到 SSH 客户端 IP: ${ping_target}，优先使用其做 ping 测试"
    fi
  fi

  if [ -z "${ping_target:-}" ]; then
    # 提示用户输入（只在交互时）
    if [ "$FORCE" -eq 0 ]; then
      read -r -p "未检测到 SSH 客户端 IP，输入测试用客户机 IP（回车则使用 1.1.1.1）: " client_ip || true
      ping_target="${client_ip:-}"
    fi
  fi

  if [ -z "${ping_target:-}" ]; then
    ping_target="1.1.1.1"
    ping_desc="公共地址 ${ping_target}"
    note "使用默认公共地址 ${ping_target} 做 RTT 测试"
  fi

  note "正在对 ${ping_desc:-$ping_target} 执行 ping ... (4 次, 超时 2s)"
  local ping_result
  # 兼容 busybox ping 及 iputils ping
  if ping -c 4 -W 2 "$ping_target" >/tmp/.ping_out 2>/dev/null; then
    ping_result=$(awk -F'/' '/rtt/ {print $5; exit} END{if(NR==0) exit 1}' /tmp/.ping_out || true)
  else
    # 可能 ping 输出不同，尽量从最后一行解析平均值
    ping_result=$(tail -n 2 /tmp/.ping_out 2>/dev/null | awk -F'/' '{print $5}' || true)
  fi
  rm -f /tmp/.ping_out || true

  if [[ -n "$ping_result" && "$ping_result" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    ok "检测到平均 RTT: ${ping_result} ms"
    printf "%.0f" "$ping_result"
  else
    warn "Ping 失败或无法解析 RTT，使用默认 150 ms"
    echo "150"
  fi
}

is_num() { [[ "${1:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]; }
is_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

### -------------- 初始默认与用户输入 --------------
DEFAULT_MEM_G=$(get_mem_gib)
DEFAULT_BW_Mbps=1000
DEFAULT_RTT_MS=$(get_rtt_ms)

MEM_G="${MEM_G_INPUT:-${DEFAULT_MEM_G:-1}}"
BW_Mbps="${BW_Mbps_INPUT:-${DEFAULT_BW_Mbps}}"
RTT_ms="${RTT_ms_INPUT:-${DEFAULT_RTT_MS}}"

# 验证数值
is_num "$MEM_G" || MEM_G="$DEFAULT_MEM_G"
is_int "$BW_Mbps" || BW_Mbps="$DEFAULT_BW_Mbps"
is_int "$RTT_ms" || RTT_ms="$DEFAULT_RTT_MS"

note "最终使用参数: 内存 ${MEM_G} GiB, 带宽 ${BW_Mbps} Mbps, RTT ${RTT_ms} ms"
note "默认为 dry-run（仅预览）。如需写入请使用 --apply"

### -------------- BDP 与桶化逻辑 --------------
# BDP(bytes) = Mbps * 125 * RTT(ms)
BDP_BYTES=$(awk -v bw="$BW_Mbps" -v rtt="$RTT_ms" 'BEGIN{printf "%.0f", bw*125*rtt}')
MEM_BYTES=$(awk -v g="$MEM_G" 'BEGIN{printf "%.0f", g*1024*1024*1024}')
TWO_BDP=$((BDP_BYTES * 2))
RAM3_BYTES=$(awk -v m="$MEM_BYTES" 'BEGIN{printf "%.0f", m*0.03}')
CAP64=$((64*1024*1024))

# cap = min(2*BDP, 3%RAM, 64MB)
min3() {
  awk -v a="$1" -v b="$2" -v c="$3" 'BEGIN{m=a; if(b<m)m=b; if(c<m)m=c; printf "%.0f", m}'
}
MAX_NUM_BYTES=$(min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")

bucket_le_mb() {
  local mb_num=$1
  # 向下对齐到 {4,8,16,32,64}
  if [ "$mb_num" -ge 64 ]; then echo 64
  elif [ "$mb_num" -ge 32 ]; then echo 32
  elif [ "$mb_num" -ge 16 ]; then echo 16
  elif [ "$mb_num" -ge 8 ]; then echo 8
  else echo 4
  fi
}

MAX_MB_NUM=$(( MAX_NUM_BYTES / 1024 / 1024 ))
MAX_MB=$(bucket_le_mb "$MAX_MB_NUM")
MAX_BYTES=$(( MAX_MB * 1024 * 1024 ))

# 基于桶选取默认 r/w default
if [ "$MAX_MB" -ge 32 ]; then
  DEF_R=262144; DEF_W=524288
elif [ "$MAX_MB" -ge 8 ]; then
  DEF_R=131072; DEF_W=262144
else
  DEF_R=87380; DEF_W=131072
fi

TCP_RMEM_MIN=4096; TCP_RMEM_DEF=87380; TCP_RMEM_MAX=$MAX_BYTES
TCP_WMEM_MIN=4096; TCP_WMEM_DEF=65536; TCP_WMEM_MAX=$MAX_BYTES

note "BDP ≈ $(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB -> cap ${MAX_MB} MB"

### -------------- 冲突处理策略（保守） --------------
timestamp() { date +%F-%H%M%S; }
BACKUP_DIR="${BACKUP_ROOT}/net-optimizer-$(timestamp)"
mkdir -p "$BACKUP_DIR"

comment_conflicts_in_sysctl_conf() {
  local f="/etc/sysctl.conf"
  [ -f "$f" ] || { ok "/etc/sysctl.conf 不存在"; return 0; }
  if grep -Eq "$KEY_REGEX" "$f"; then
    local b="${BACKUP_DIR}/sysctl.conf.bak.$(timestamp)"
    cp -a "$f" "$b"
    note "备份 /etc/sysctl.conf -> $b"
    awk -v re="$KEY_REGEX" '
      $0 ~ re && $0 !~ /^[[:space:]]*#/ { print "# " $0; next }
      { print $0 }
    ' "$f" > "${f}.tmp.$$"
    install -m 0644 "${f}.tmp.$$" "$f"
    rm -f "${f}.tmp.$$"
    # 记录 rollback 操作
    echo "restore_file \"$b\" \"$f\"" >> "${BACKUP_DIR}/rollback_actions.sh"
    ok "/etc/sysctl.conf 中的冲突键已注释（备份并记录回滚）"
  else
    ok "/etc/sysctl.conf 无冲突键"
  fi
}

process_conflict_files_in_dir() {
  local dir="$1"
  [ -d "$dir" ] || { ok "$dir 不存在"; return 0; }
  shopt -s nullglob
  local moved=0
  for f in "$dir"/*.conf; do
    # 忽略目标文件自身
    [ "$(readlink -f "$f")" = "$(readlink -f "$SYSCTL_TARGET")" ] && continue
    if grep -Eq "$KEY_REGEX" "$f"; then
      local dest="${f}.disabled_by_optimizer.$(timestamp)"
      mv -- "$f" "$dest"
      note "已备份并禁用冲突文件: $f -> $dest"
      echo "mv \"${dest}\" \"${f}\"" >> "${BACKUP_DIR}/rollback_actions.sh"
      moved=1
    fi
  done
  shopt -u nullglob
  [ "$moved" -eq 1 ] && ok "$dir 中的冲突文件已处理（改名备份）" || ok "$dir 无需处理"
}

scan_conflicts_ro() {
  local dir="$1"
  [ -d "$dir" ] || { ok "$dir 不存在"; return 0; }
  if grep -RIlEq "$KEY_REGEX" "$dir" 2>/dev/null; then
    warn "发现潜在冲突（只提示不改）：$dir"
    grep -RhnE "$KEY_REGEX" "$dir" 2>/dev/null || true
  else
    ok "$dir 未发现冲突"
  fi
}

# -------------- 预备动作（只做备份/记录） --------------
note "准备冲突处理（将备份并注释 /etc/sysctl.conf；/etc/sysctl.d 冲突文件改名备份）"
comment_conflicts_in_sysctl_conf
process_conflict_files_in_dir "/etc/sysctl.d"
note "扫描系统目录（仅提示，不做修改）"
scan_conflicts_ro "/usr/local/lib/sysctl.d"
scan_conflicts_ro "/usr/lib/sysctl.d"
scan_conflicts_ro "/lib/sysctl.d"
scan_conflicts_ro "/run/sysctl.d"

### -------------- 内核模块尝试加载（非破坏） --------------
if command -v modprobe >/dev/null 2>&1; then
  modprobe tcp_bbr 2>/dev/null || true
  ok "尝试加载 tcp_bbr（如果内核支持）"
fi

### -------------- 生成 sysctl 内容（写入临时文件，dry-run 默认展示） --------------
gen_sysctl_tmp() {
  cat <<EOF
# Auto-generated by net-optimizer (conservative defaults)
# Inputs: MEM_G=${MEM_G}GiB, BW=${BW_Mbps}Mbps, RTT=${RTT_ms}ms
# BDP: ${BDP_BYTES} bytes (~$(awk -v b="$BDP_BYTES" 'BEGIN{printf "%.2f", b/1024/1024}') MB)
# Caps: min(2*BDP, 3%RAM, 64MB) -> Bucket ${MAX_MB} MB

net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

net.core.rmem_default = ${DEF_R}
net.core.wmem_default = ${DEF_W}
net.core.rmem_max = ${MAX_BYTES}
net.core.wmem_max = ${MAX_BYTES}

net.ipv4.tcp_rmem = ${TCP_RMEM_MIN} ${TCP_RMEM_DEF} ${TCP_RMEM_MAX}
net.ipv4.tcp_wmem = ${TCP_WMEM_MIN} ${TCP_WMEM_DEF} ${TCP_WMEM_MAX}

net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
EOF
}

TMP_SYSCTL_FILE="$(mktemp)"
gen_sysctl_tmp > "$TMP_SYSCTL_FILE"

note "生成 sysctl 预览（位于临时文件 $TMP_SYSCTL_FILE）："
sed -n '1,200p' "$TMP_SYSCTL_FILE"

### -------------- iperf3 hook（可选） --------------
# 若用户请求 iperf 测试并且 iperf3 存在 -> 运行短测并可能调整 BW_Mbps 估计（conservative）
if [ "$RUN_IPERF" -eq 1 ] && command -v iperf3 >/dev/null 2>&1; then
  note "检测到 iperf3 且你请求了 iperf 测试：${IPERF_SERVERS[*]}"
  for s in "${IPERF_SERVERS[@]}"; do
    note "对 $s 进行 10s 测试（-R 测下行）"
    if iperf3 -c "$s" -t 10 -J >/tmp/.iperf_result.json 2>/dev/null; then
      # 解析 JSON 中的 receiver.bits_per_second（下载），sender.bits_per_second（上传）
      DL=$(jq -r '.end.sum_received.bits_per_second // 0' /tmp/.iperf_result.json 2>/dev/null || echo 0)
      UL=$(jq -r '.end.sum_sent.bits_per_second // 0' /tmp/.iperf_result.json 2>/dev/null || echo 0)
      # 转换为 Mbps 整数
      DL_Mbps=$(( (DL+500000)/1000000 ))
      UL_Mbps=$(( (UL+500000)/1000000 ))
      note "iperf 结果: DL ${DL_Mbps} Mbps, UL ${UL_Mbps} Mbps"
      # 采用保守的瓶颈带宽估计（min(DL, UL, 目前估计*1.5)）
      if [ "$DL_Mbps" -gt 0 ] && [ "$UL_Mbps" -gt 0 ]; then
        est_bw=$(( (DL_Mbps<UL_Mbps?DL_Mbps:UL_Mbps) ))
        if [ "$est_bw" -lt "$BW_Mbps" ]; then
          warn "iperf 测试检测到比预估更低的带宽 ${est_bw} Mbps，脚本将保守采用较低值"
          BW_Mbps="$est_bw"
          # 重新计算 BDP 相关
          BDP_BYTES=$(awk -v bw="$BW_Mbps" -v rtt="$RTT_ms" 'BEGIN{printf "%.0f", bw*125*rtt}')
          TWO_BDP=$((BDP_BYTES*2))
          MAX_NUM_BYTES=$(min3 "$TWO_BDP" "$RAM3_BYTES" "$CAP64")
          MAX_MB_NUM=$(( MAX_NUM_BYTES / 1024 / 1024 ))
          MAX_MB=$(bucket_le_mb "$MAX_MB_NUM")
          MAX_BYTES=$(( MAX_MB * 1024 * 1024 ))
          TCP_RMEM_MAX=$MAX_BYTES
          TCP_WMEM_MAX=$MAX_BYTES
          note "重新计算后 cap ${MAX_MB} MB"
          gen_sysctl_tmp > "$TMP_SYSCTL_FILE"
          sed -n '1,200p' "$TMP_SYSCTL_FILE"
        fi
      fi
    else
      warn "iperf3 到 $s 测试失败（可能防火墙或服务端未运行）"
    fi
    rm -f /tmp/.iperf_result.json || true
  done
else
  if [ "$RUN_IPERF" -eq 1 ]; then
    warn "未检测到 iperf3 命令，跳过 iperf 测试（请安装 iperf3 或去掉 --iperf）"
  fi
fi

### -------------- 生成 rollback 脚本框架 --------------
rollback_sh="${BACKUP_DIR}/rollback.sh"
cat > "$rollback_sh" <<'EOFF'
#!/usr/bin/env bash
set -euo pipefail
# rollback helper generated by net-optimizer
restore_file() {
  local src="$1"; local dst="$2"
  if [ -f "$src" ]; then
    cp -a "$src" "$dst"
    echo "[rollback] restored $dst from $src"
  fi
}
EOFF
chmod 700 "$rollback_sh"
# 记录将要做的实际写入（如果 apply 时会追加更多回滚操作）
echo "echo '[rollback] review ${BACKUP_DIR}/rollback_actions.sh and this script to restore changes'" >> "$rollback_sh"

### -------------- 预览或写入配置 --------------
apply_sysctl() {
  local tmp="$1"
  # maintain backup of any existing target
  if [ -f "$SYSCTL_TARGET" ]; then
    local bak="${BACKUP_DIR}/$(basename "$SYSCTL_TARGET").bak.$(timestamp)"
    cp -a "$SYSCTL_TARGET" "$bak"
    echo "restore_file \"$bak\" \"$SYSCTL_TARGET\"" >> "${BACKUP_DIR}/rollback_actions.sh"
    ok "备份旧的 $SYSCTL_TARGET -> $bak"
  fi
  install -m 0644 "$tmp" "$SYSCTL_TARGET"
  ok "已写入 $SYSCTL_TARGET"
  # 记录回滚（直接 restore 备份会覆盖）
  echo "rm -f \"$SYSCTL_TARGET\"" >> "${BACKUP_DIR}/rollback_actions.sh"
  # 让 sysctl 重新加载（捕获输出）
  sysctl --system || warn "sysctl --system 返回非零（请手动检查）"
}

if [ "$DRY_RUN" -eq 1 ]; then
  note "DRY-RUN: 未写入文件。若确认写入，请以 --apply 运行"
  note "如果你想让脚本立即生效并写入，请运行: sudo $PROGNAME --apply"
  # print final summary
  echo "===== SUMMARY (DRY-RUN preview) ====="
  echo "Sysctl target: $SYSCTL_TARGET"
  echo "Bucket cap: ${MAX_MB} MB (bytes=${MAX_BYTES})"
  echo "TCP rmem max: ${TCP_RMEM_MAX}, tcp wmem max: ${TCP_WMEM_MAX}"
  echo "Generated sysctl content (first 200 lines):"
  sed -n '1,200p' "$TMP_SYSCTL_FILE"
  echo "Backups will be placed under: $BACKUP_DIR"
  exit 0
fi

# APPLY path:
note "开始应用更改（apply 模式） —— 破坏性操作将会执行。"
if ! confirm "继续并写入 $SYSCTL_TARGET ? (yes/no): "; then
  bad "用户取消操作"
  exit 1
fi

# 执行冲突恢复记录脚本（移动的配置已经记录在 BACKUP_DIR/rollback_actions.sh）
# 把 rollback_actions 脚本添加到 rollback.sh
if [ -f "${BACKUP_DIR}/rollback_actions.sh" ]; then
  cat "${BACKUP_DIR}/rollback_actions.sh" >> "$rollback_sh"
fi
chmod 700 "$rollback_sh"
ok "回滚脚本已生成： $rollback_sh"

# 安全写入：先把 /etc/sysctl.conf 的备份已在 comment_conflicts_in_sysctl_conf 中做过
# 再写入 sysctl file
apply_sysctl "$TMP_SYSCTL_FILE"

# 尝试设置 tc qdisc 为 fq 在默认网卡上（如果存在）
IFACE="$(default_iface)"
if command -v tc >/dev/null 2>&1 && [ -n "${IFACE:-}" ]; then
  if tc qdisc replace dev "$IFACE" root fq 2>/dev/null; then
    ok "已在接口 $IFACE 上设置 qdisc fq"
    # 回滚记录
    echo "tc qdisc replace dev \"$IFACE\" root pfifo_fast || true" >> "${BACKUP_DIR}/rollback_actions.sh"
  else
    warn "尝试设置 qdisc fq 失败（可能内核未编译 fq）"
  fi
else
  warn "未检测到 tc 或默认网卡，跳过 qdisc 设置"
fi

ok "所有写入已完成。备份与回滚信息位于 ${BACKUP_DIR}"
ok "若需回滚，请以 root 执行: ${rollback_sh}"

### -------------- 激进模式（需双重确认） --------------
if [ "$AGGRESSIVE" -eq 1 ]; then
  if [ "$FORCE_AGGRESSIVE" -ne 1 ]; then
    bad "要启用激进模式请同时传 --aggressive 和 --force-aggressive"
    exit 1
  fi
  if ! confirm "你正在启用激进模式（会修改 GRUB 启动参数并可能禁用安全 mitigations），确认继续? (yes/no): "; then
    bad "用户放弃激进模式修改"
  else
    # 示例：写入 GRUB_CMDLINE_LINUX_DEFAULT 的 mitigations=off（仅演示）
    grub_cfg="/etc/default/grub"
    if [ -f "$grub_cfg" ]; then
      grub_bak="${BACKUP_DIR}/grub.default.bak.$(timestamp)"
      cp -a "$grub_cfg" "$grub_bak"
      sed -E "s/GRUB_CMDLINE_LINUX_DEFAULT=\"([^\"]*)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\1 mitigations=off\"/" "$grub_cfg" > "${grub_cfg}.tmp.$$" && install -m 0644 "${grub_cfg}.tmp.$$" "$grub_cfg" && rm -f "${grub_cfg}.tmp.$$"
      ok "已修改 /etc/default/grub（备份: $grub_bak），请手动运行 update-grub 或 update-grub2"
      echo "restore_file \"$grub_bak\" \"$grub_cfg\"" >> "${BACKUP_DIR}/rollback_actions.sh"
    else
      warn "/etc/default/grub 不存在，跳过激进 grub 修改"
    fi
  fi
fi

# 结束
ok "操作完成。"
exit 0
