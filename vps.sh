#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ---------- 配置与日志 ----------
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_BASE="/root/ultimate_singularity_backups"
BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"
mkdir -p "${BACKUP_DIR}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log(){ echo -e "${CYAN}>>> $*${NC}"; }
ok(){ echo -e "${GREEN}✔ $*${NC}"; }
warn(){ echo -e "${YELLOW}⚠ $*${NC}"; }
err(){ echo -e "${RED}✖ $*${NC}"; }

# ---------- 参数解析 ----------
DRY_RUN=1 # 默认是 Dry Run 模式，更安全
APPLY_ALL=0
APPLY_IO_LIMITS=0
CLEANUP_SERVICES=0
APPLY_GRUB=0
APPLY_HOST_SPECIFICS=0
GENERATE_TOOLS=0
INSTALL_HW_TUNING=0

usage() {
  echo "Usage: $0 [--apply] [MODULE...]"
  echo "  --apply                 实际应用更改 (默认是 --dry-run 模式，只打印操作)"
  echo ""
  echo "Modules:"
  echo "  --all                   选择所有下面的模块"
  echo "  --apply-io-limits       应用存储 I/O 优化 (udev) 和系统资源限制 (limits.conf)"
  echo "  --cleanup-services      [高风险] 禁用不常用的系统服务和内核模块"
  echo "  --apply-grub            [极高风险] 为母鸡角色应用CPU隔离等GRUB参数 (可能导致无法启动)"
  echo "  --apply-host-specifics  为母鸡角色应用大页内存等特定优化"
  echo "  --generate-tools        生成监控和基准测试辅助脚本"
  echo "  --install-hw-tuning     安装并启用'AI'硬件动态调优后台服务"
  echo "  -h, --help              显示此帮助信息"
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    --apply) DRY_RUN=0 ;;
    --all) APPLY_ALL=1 ;;
    --apply-io-limits) APPLY_IO_LIMITS=1 ;;
    --cleanup-services) CLEANUP_SERVICES=1 ;;
    --apply-grub) APPLY_GRUB=1 ;;
    --apply-host-specifics) APPLY_HOST_SPECIFICS=1 ;;
    --generate-tools) GENERATE_TOOLS=1 ;;
    --install-hw-tuning) INSTALL_HW_TUNING=1 ;;
    -h|--help) usage ;;
  esac
done

if [[ "$APPLY_ALL" -eq 1 ]]; then
  APPLY_IO_LIMITS=1
  CLEANUP_SERVICES=1
  APPLY_GRUB=1
  APPLY_HOST_SPECIFICS=1
  GENERATE_TOOLS=1
  INSTALL_HW_TUNING=1
fi

# ---------- 工具函数 (来自代码一) ----------
command_exists(){ command -v "$1" >/dev/null 2>&1; }
backup_file(){
  local f="$1"
  [[ -e "$f" ]] || return 0
  mkdir -p "$BACKUP_DIR"
  cp -a "$f" "$BACKUP_DIR/$(basename "$f").bak" || true
}
apply_or_echo(){
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} ==> $*"
  else
    eval "$*"
  fi
}
write_file_safe(){
  local path="$1"; shift
  local content="$*"
  backup_file "$path"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} ==> Write to $path"
  else
    mkdir -p "$(dirname "$path")"
    cat > "$path" <<< "$content"
  fi
}

# ---------- 环境检测 (来自代码一) ----------
detect_environment_and_role(){
  log "开始智能环境检测..."
  [[ -f /etc/os-release ]] && source /etc/os-release || true
  OS_ID="${ID:-unknown}"
  CPU_COUNT=$(nproc 2>/dev/null || echo 1)
  TOTAL_MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
  VIRT_TYPE=$(command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt || echo none)
  IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
  HAS_NAT=false
  if command_exists iptables-save && iptables-save 2>/dev/null | grep -E "(MASQUERADE|SNAT)" >/dev/null 2>&1; then HAS_NAT=true; fi
  if command_exists nft && nft list ruleset 2>/dev/null | grep -E "(masquerade|snat)" >/dev/null 2>&1; then HAS_NAT=true; fi
  HAS_KVM=false
  [[ -e /dev/kvm ]] && HAS_KVM=true
  lsmod 2>/dev/null | grep -q kvm && HAS_KVM=true || true

  if [[ "$IP_FORWARD" -eq 1 || "$HAS_NAT" == true ]]; then
    ROLE="nat"
  elif [[ "$VIRT_TYPE" == "none" && "$HAS_KVM" == true && "$TOTAL_MEM_MB" -ge 4096 ]]; then
    ROLE="host"
  else
    ROLE="guest"
  fi
  ok "检测完成: 角色判定为=${ROLE}"
}

# ---------- 模块化功能 ----------

# 模块一: I/O 与 Limits 优化
apply_io_limits_module(){
  log "应用 limits 与 udev/I/O 优化..."
  LIMITS="/etc/security/limits.d/99-ultimate-singularity.conf"
  UDEV="/etc/udev/rules.d/60-ultimate-io.rules"
  
  LIMITS_CONTENT=$'* soft nofile 2097152\n* hard nofile 2097152\nroot soft nofile 2097152\nroot hard nofile 2097152\n* soft nproc unlimited\n* hard nproc unlimited\n'
  UDEV_CONTENT=$'ACTION=="add|change", KERNEL=="nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none", ATTR{queue/nr_requests}="1024"\nACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline", ATTR{queue/nr_requests}="1024"\n'

  write_file_safe "$LIMITS" "$LIMITS_CONTENT"
  write_file_safe "$UDEV" "$UDEV_CONTENT"

  apply_or_echo "udevadm control --reload-rules || true"
  apply_or_echo "udevadm trigger || true"
  ok "I/O 与 Limits 模块已处理"
}

# 模块二: 服务清理
cleanup_services_module(){
  log "智能清理与禁用可能干扰性能的服务..."
  services_common=(irqbalance tuned thermald bluetooth cups snapd unattended-upgrades rsyslog auditd cron)
  services_net=(firewalld ufw nftables)
  services_virt=(libvirtd virtlogd virtlockd)

  to_disable=("${services_common[@]}")
  if [[ "$ROLE" != "nat" ]]; then to_disable+=("${services_net[@]}"); fi
  if [[ "$ROLE" != "host" ]]; then to_disable+=("${services_virt[@]}"); fi

  for svc in "${to_disable[@]}"; do
    apply_or_echo "systemctl disable --now ${svc} >/dev/null 2>&1 || true"
  done

  timers=(apt-daily.timer apt-daily-upgrade.timer fstrim.timer)
  for t in "${timers[@]}"; do apply_or_echo "systemctl disable --now ${t} >/dev/null 2>&1 || true"; done

  MOD_BLACK="/etc/modprobe.d/ultimate-blacklist.conf"
  backup_file "$MOD_BLACK"
  MODS="bluetooth btusb pcspkr joydev"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} ==> Write blacklist modules to $MOD_BLACK"
  else
    for m in $MODS; do echo "blacklist $m" >> "$MOD_BLACK" || true; done
  fi
  ok "服务清理模块已处理"
}

# 模块三: GRUB 优化 (CPU隔离)
apply_grub_module(){
  [[ "$ROLE" == "host" ]] || { warn "当前非母鸡(role=host)，跳过 GRUB 优化"; return; }
  log "为母鸡角色应用 GRUB CPU 隔离优化..."
  GRUB_FILE="/etc/default/grub"
  [[ -f "$GRUB_FILE" ]] || { warn "$GRUB_FILE 不存在，跳过"; return; }
  backup_file "$GRUB_FILE"

  local iso_count=$(( CPU_COUNT / 4 )); [[ $iso_count -lt 1 ]] && iso_count=1; [[ $iso_count -gt 8 ]] && iso_count=8
  local first_iso=$(( CPU_COUNT - iso_count ))
  local ISO="${first_iso}-$((CPU_COUNT-1))"
  
  local CPU_VENDOR=$(grep -m1 '^vendor_id' /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo unknown)
  local CPU_SPEC=""
  case "$CPU_VENDOR" in
    GenuineIntel) CPU_SPEC="intel_pstate=disable intel_idle.max_cstate=0" ;;
    AuthenticAMD) CPU_SPEC="amd_pstate=disable" ;;
  esac

  local GRUB_BASE="quiet loglevel=0"
  local PERF="nohz_full=${ISO} rcu_nocbs=${ISO} isolcpus=${ISO} processor.max_cstate=1 idle=poll ${CPU_SPEC}"

  if grep -q '^GRUB_CMDLINE_LINUX_DEFAULT=' "$GRUB_FILE"; then
    apply_or_echo "sed -i 's|^GRUB_CMDLINE_LINUX_DEFAULT=.*|GRUB_CMDLINE_LINUX_DEFAULT=\"${GRUB_BASE} ${PERF}\"|' ${GRUB_FILE}"
  else
    apply_or_echo "echo \"GRUB_CMDLINE_LINUX_DEFAULT=\\\"${GRUB_BASE} ${PERF}\\\"\" >> ${GRUB_FILE}"
  fi
  
  if command_exists update-grub; then apply_or_echo "update-grub || true"; fi
  if command_exists grub2-mkconfig; then apply_or_echo "grub2-mkconfig -o /boot/grub2/grub.cfg || true"; fi
  ok "GRUB 模块已处理 (如应用需重启生效)"
}

# 模块四: 母鸡特定优化 (大页内存)
apply_host_specifics_module(){
  [[ "$ROLE" == "host" ]] || { warn "当前非母鸡(role=host)，跳过母鸡特定优化"; return; }
  log "为母鸡角色应用大页内存优化..."
  HP="/etc/hugepages/ultimate-hugepages.conf"
  hp_count=$(( (TOTAL_MEM_MB / 200) )); [[ $hp_count -lt 64 ]] && hp_count=64; [[ $hp_count -gt 4096 ]] && hp_count=4096
  content="# hugepages recommendation for host\nnr_hugepages=${hp_count}\n"
  write_file_safe "$HP" "$content"
  ok "母鸡特定优化模块已处理"
}

# 模块五: 生成辅助工具
generate_tools_module(){
  log "生成监控与基准脚本..."
  MON="/usr/local/bin/ultimate-monitor.sh"
  BENCH="/usr/local/bin/ultimate-bench.sh"
  
  MON_CONTENT='#!/usr/bin/env bash
echo "=== Ultimate Monitor ==="; date; echo "Role: '${ROLE}'"; echo "CPU: $(nproc) cores"; free -h; uptime; ss -s
echo "Top NIC RX/TX (MB):"
for nic in $(ls /sys/class/net | grep -v lo); do rx=$(cat /sys/class/net/$nic/statistics/rx_bytes); tx=$(cat /sys/class/net/$nic/statistics/tx_bytes); printf "%s: RX=%dMB TX=%dMB\n" "$nic" $((rx/1024/1024)) $((tx/1024/1024)); done'

  BENCH_CONTENT='#!/usr/bin/env bash
echo "=== Ultimate Bench ==="; echo "Ping test to 8.8.8.8"; ping -c 4 8.8.8.8 || true
if command -v dd >/dev/null 2>&1; then echo "Memory write test (dd to /dev/null):"; dd if=/dev/zero of=/dev/null bs=1M count=1024 2>&1 | tail -n1 || true; fi'

  write_file_safe "$MON" "$MON_CONTENT"
  write_file_safe "$BENCH" "$BENCH_CONTENT"
  apply_or_echo "chmod +x $MON $BENCH"
  ok "辅助工具生成模块已处理"
}

# 模块六: 安装硬件动态调优服务
install_hw_tuning_module(){
  log "部署硬件动态优化后台服务..."
  HW_SCRIPT="/usr/local/bin/ultimate-hw-ai.sh"
  read -r -d '' HW_CONTENT <<'EOF' || true
#!/usr/bin/env bash
set -euo pipefail; IFS=$'\n\t'; CPU_COUNT=$(nproc || echo 1); ALL_NICS=( $(ls /sys/class/net | grep -v lo || true) )
for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do [[ -f "$gov" ]] && echo performance > "$gov" 2>/dev/null || true; done
for NIC in "${ALL_NICS[@]}"; do
  [[ -d "/sys/class/net/$NIC" && "$(cat /sys/class/net/$NIC/operstate' 2>/dev/null)" == "up" ]] || continue
  rx_old=$(cat /sys/class/net/$NIC/statistics/rx_bytes 2>/dev/null || echo 0); sleep 1; rx_new=$(cat /sys/class/net/$NIC/statistics/rx_bytes 2>/dev/null || echo 0)
  rx_speed=$((rx_new - rx_old)); rx_ring=1024
  if [[ $rx_speed -gt 200000000 ]]; then rx_ring=8192; elif [[ $rx_speed -gt 100000000 ]]; then rx_ring=4096; elif [[ $rx_speed -gt 50000000 ]]; then rx_ring=2048; fi
  if command -v ethtool >/dev/null 2>&1; then ethtool -G "$NIC" rx "$rx_ring" tx "$rx_ring" >/dev/null 2>&1 || true; ethtool -K "$NIC" gso off gro off tso off lro off >/dev/null 2>&1 || true; fi
done
for dev in /sys/block/*/queue/read_ahead_kb; do [[ -f "$dev" ]] && echo 128 > "$dev" 2>/dev/null || true; done
EOF
  write_file_safe "$HW_SCRIPT" "$HW_CONTENT"
  apply_or_echo "chmod +x ${HW_SCRIPT}"

  SERVICE="/etc/systemd/system/ultimate-hw-ai.service"
  TIMER="/etc/systemd/system/ultimate-hw-ai.timer"
  read -r -d '' SVC <<'SVC' || true
[Unit]
Description=Ultimate HW AI Dynamic Tuning
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ultimate-hw-ai.sh
SVC
  read -r -d '' TMR <<'TMR' || true
[Unit]
Description=Run Ultimate HW AI dynamic tuning periodically
[Timer]
OnBootSec=30s
OnUnitActiveSec=300s
[Install]
WantedBy=timers.target
TMR
  write_file_safe "$SERVICE" "$SVC"
  write_file_safe "$TIMER" "$TMR"
  apply_or_echo "systemctl daemon-reload || true"
  apply_or_echo "systemctl enable --now ultimate-hw-ai.timer || true"
  ok "硬件动态调优服务模块已处理"
}

# ---------- 主流程 ----------
main(){
  [[ "$(id -u)" -ne 0 ]] && { err "请使用 root 权限运行脚本"; exit 1; }
  
  log "Ultimate Singularity 补充模块脚本启动"
  if [[ "$DRY_RUN" -eq 1 ]]; then warn "当前为 DRY-RUN 模式：不会对系统进行任何实际修改。"; fi
  log "备份目录位于: ${BACKUP_DIR}"

  detect_environment_and_role

  if [[ "$APPLY_IO_LIMITS" -eq 1 ]]; then apply_io_limits_module; fi
  if [[ "$CLEANUP_SERVICES" -eq 1 ]]; then cleanup_services_module; fi
  if [[ "$APPLY_GRUB" -eq 1 ]]; then apply_grub_module; fi
  if [[ "$APPLY_HOST_SPECIFICS" -eq 1 ]]; then apply_host_specifics_module; fi
  if [[ "$GENERATE_TOOLS" -eq 1 ]]; then generate_tools_module; fi
  if [[ "$INSTALL_HW_TUNING" -eq 1 ]]; then install_hw_tuning_module; fi

  echo
  ok "所有选定模块已处理完毕。"
  if [[ "$DRY_RUN" -eq 0 && "$APPLY_GRUB" -eq 1 ]]; then
    warn "GRUB 模块已被应用，您需要手动重启服务器才能使其生效。"
  fi
}

main "$@"
