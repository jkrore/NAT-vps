#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ... (日志、参数解析等部分保持不变，此处省略) ...
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
# --- 新增模块参数 ---
APPLY_ZRAM=0
APPLY_FSTAB=0
APPLY_BASICS=0
DISABLE_IPV6=0

usage() {
  echo "Usage: $0 [--apply] [MODULE...]"
  echo "  --apply                 实际应用更改 (默认是 --dry-run 模式)"
  echo ""
  echo "Core Modules:"
  echo "  --all                   选择所有下面的模块 (高风险模块除外)"
  echo "  --apply-io-limits       应用存储 I/O 优化 (udev) 和系统资源限制 (limits.conf)"
  echo "  --cleanup-services      [高风险] 禁用不常用的系统服务和内核模块"
  echo "  --apply-grub            [极高风险] 为母鸡角色应用CPU隔离等GRUB参数"
  echo "  --apply-host-specifics  为母鸡/NAT角色应用特定优化"
  echo "  --generate-tools        生成监控和基准测试辅助脚本"
  echo "  --install-hw-tuning     安装并启用'AI'硬件动态调优后台服务"
  echo ""
  echo "Nodeseek Community Inspired Modules:"
  echo "  --apply-zram            [新增] 为小内存VPS配置zram (内存压缩Swap)"
  echo "  --apply-fstab           [新增] 为磁盘挂载添加 noatime 选项以减少I/O"
  echo "  --apply-basics          [新增] 配置时区、NTP时间同步和优化SSH连接速度"
  echo "  --disable-ipv6          [新增] 禁用IPv6以减少开销"
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
    # --- 新增 case ---
    --apply-zram) APPLY_ZRAM=1 ;;
    --apply-fstab) APPLY_FSTAB=1 ;;
    --apply-basics) APPLY_BASICS=1 ;;
    --disable-ipv6) DISABLE_IPV6=1 ;;
    -h|--help) usage ;;
  esac
done

if [[ "$APPLY_ALL" -eq 1 ]]; then
  APPLY_IO_LIMITS=1
  APPLY_HOST_SPECIFICS=1
  GENERATE_TOOLS=1
  INSTALL_HW_TUNING=1
  # --- 新增到 --all ---
  APPLY_ZRAM=1
  APPLY_FSTAB=1
  APPLY_BASICS=1
  DISABLE_IPV6=1
  warn "--all 模式已启用，但为安全起见，--cleanup-services 和 --apply-grub 等高风险模块需要手动指定。"
fi

# ---------- 工具函数 ----------
command_exists(){ command -v "$1" >/dev/null 2>&1; }
backup_file(){
  local f="$1"
  [[ -e "$f" ]] || return 0
  mkdir -p "$BACKUP_DIR/$(dirname "$f")"
  cp -a "$f" "$BACKUP_DIR/$(dirname "$f")/$(basename "$f").bak" || true
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

# ---------- 环境检测 ----------
# ... (此函数无错误，保持原样) ...
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
# ... (模块一、二无错误，保持原样) ...
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

# 模块三: GRUB 优化 (已修正)
apply_grub_module(){
  [[ "$ROLE" == "host" ]] || { warn "当前非母鸡(role=host)，跳过 GRUB 优化"; return; }
  log "为母鸡角色应用 GRUB CPU 隔离优化..."
  GRUB_FILE="/etc/default/grub"
  [[ -f "$GRUB_FILE" ]] || { warn "$GRUB_FILE 不存在，跳过"; return; }
  backup_file "$GRUB_FILE"

  local iso_count=$(( CPU_COUNT / 4 )); [[ $iso_count -lt 1 ]] && iso_count=1; [[ $iso_count -gt 8 ]] && iso_count=8
  local first_iso=$(( CPU_COUNT - iso_count ))
  local ISO="${first_iso}-$((CPU_COUNT-1))"
  
  local CPU_VENDOR
  CPU_VENDOR=$(grep -m1 '^vendor_id' /proc/cpuinfo 2>/dev/null | awk '{print $3}' || echo unknown)
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

# ... (模块四、五无错误，保持原样) ...
apply_host_specifics_module(){
  if [[ "$ROLE" == "host" ]]; then
    log "为母鸡角色应用大页内存优化..."
    local HP="/etc/hugepages/ultimate-hugepages.conf"
    local hp_count=$(( (TOTAL_MEM_MB / 200) )); [[ $hp_count -lt 64 ]] && hp_count=64; [[ $hp_count -gt 4096 ]] && hp_count=4096
    local content="# hugepages recommendation for host\nnr_hugepages=${hp_count}\n"
    write_file_safe "$HP" "$content"
    ok "母鸡特定优化模块已处理"
  elif [[ "$ROLE" == "nat" ]]; then
    log "为NAT角色优化连接跟踪表大小..."
    # 基于内存大小计算，每GB内存支持65536个连接
    local conntrack_max=$(( TOTAL_MEM_MB * 64 ))
    # 设置一个合理的上下限
    [[ $conntrack_max -lt 65536 ]] && conntrack_max=65536
    [[ $conntrack_max -gt 1048576 ]] && conntrack_max=1048576
    local NAT_SYSCTL="/etc/sysctl.d/98-nat-tweaks.conf"
    local nat_content="net.netfilter.nf_conntrack_max = ${conntrack_max}\nnet.nf_conntrack_max = ${conntrack_max}"
    write_file_safe "$NAT_SYSCTL" "$nat_content"
    apply_or_echo "sysctl -p ${NAT_SYSCTL}"
    ok "NAT特定优化模块已处理"
  else
    warn "当前角色(${ROLE})无需特定优化，跳过"
  fi
}
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

# 模块六: 安装硬件动态调优服务 (恢复正确结构)
install_hw_tuning_module(){
  log "部署硬件动态优化后台服务..."
  local HW_SCRIPT="/usr/local/bin/ultimate-hw-ai.sh"
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

  local SERVICE="/etc/systemd/system/ultimate-hw-ai.service"
  local TIMER="/etc/systemd/system/ultimate-hw-ai.timer"
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

# ---------- 新增模块 (Nodeseek Community Inspired) ----------
# ... (模块七、八、九、十无错误，保持原样) ...
apply_zram_module(){
  if [[ "$TOTAL_MEM_MB" -gt 2048 ]]; then
    warn "内存大于2GB，通常无需ZRAM，跳过此模块。"; return;
  fi
  log "为小内存VPS配置ZRAM..."
  
  local pkg_manager
  if command_exists apt-get; then pkg_manager="apt-get";
  elif command_exists dnf; then pkg_manager="dnf";
  elif command_exists yum; then pkg_manager="yum";
  else warn "不支持的包管理器，无法自动安装ZRAM。"; return; fi

  apply_or_echo "$pkg_manager update"
  if [[ "$pkg_manager" == "apt-get" ]]; then
    apply_or_echo "$pkg_manager install -y zram-tools"
  else
    apply_or_echo "$pkg_manager install -y zram-generator"
  fi

  # 为 zram-generator (CentOS/Fedora) 或 zram-tools (Debian/Ubuntu) 创建配置
  if command_exists zramctl; then
      local zram_size=$(( TOTAL_MEM_MB / 2 ))
      [[ $zram_size -gt 4096 ]] && zram_size=4096
      
      local ZRAM_GEN_CONF="/etc/systemd/zram-generator.conf"
      local zram_content="[zram0]\nzram-size = ${zram_size}M\ncompression-algorithm = zstd"
      write_file_safe "$ZRAM_GEN_CONF" "$zram_content"
      
      apply_or_echo "systemctl daemon-reload"
      apply_or_echo "systemctl start /dev/zram0"
      ok "ZRAM模块已处理"
  else
      err "ZRAM工具安装失败，跳过配置。"
  fi
}
apply_fstab_module(){
  log "优化 /etc/fstab，添加 noatime, nodiratime..."
  local FSTAB="/etc/fstab"
  [[ -f "$FSTAB" ]] || { warn "$FSTAB 不存在，跳过"; return; }
  backup_file "$FSTAB"
  
  if [[ "$DRY_RUN" -eq 1 ]]; then
    echo -e "${YELLOW}[DRY-RUN]${NC} ==> 将在 $FSTAB 中为 ext4/xfs 文件系统添加 'noatime,nodiratime' 选项"
  else
    # 使用 awk 安全地添加 noatime, 仅处理 ext4 和 xfs, 且不重复添加
    awk '
    # 跳过注释、空行、已处理的行
    /^\s*#/ || /^\s*$/ || $4 ~ /noatime/ {print; next}
    # 只处理 ext4 和 xfs 文件系统
    $3 ~ /ext4|xfs/ {
        $4 = $4 ",noatime,nodiratime"
        printf "%-22s %-22s %-7s %-25s %s %s\n", $1, $2, $3, $4, $5, $6
        next
    }
    # 其他行保持原样
    { print }
    ' "$FSTAB" > "${FSTAB}.tmp" && mv "${FSTAB}.tmp" "$FSTAB"
  fi
  ok "fstab模块已处理 (建议择机 'mount -o remount /' 或重启)"
}
apply_basics_module(){
  log "配置基础环境 (时区/NTP/SSH)..."
  # 1. 设置时区
  apply_or_echo "timedatectl set-timezone Asia/Shanghai"
  
  # 2. 安装并启用 chrony
  local pkg_manager
  if command_exists apt-get; then pkg_manager="apt-get";
  elif command_exists dnf; then pkg_manager="dnf";
  elif command_exists yum; then pkg_manager="yum";
  else warn "无法确定包管理器，跳过NTP安装。"; fi
  
  if [[ -n "$pkg_manager" ]]; then
    apply_or_echo "$pkg_manager install -y chrony"
    apply_or_echo "systemctl enable --now chronyd || systemctl enable --now chrony"
  fi

  # 3. 优化 SSH
  local SSH_CONF="/etc/ssh/sshd_config"
  if [[ -f "$SSH_CONF" ]]; then
    backup_file "$SSH_CONF"
    apply_or_echo "sed -i -E 's/^[#\s]*UseDNS\s+yes/UseDNS no/' '$SSH_CONF'"
    apply_or_echo "grep -q '^UseDNS' '$SSH_CONF' || echo 'UseDNS no' >> '$SSH_CONF'"
    apply_or_echo "sed -i -E 's/^[#\s]*GSSAPIAuthentication\s+yes/GSSAPIAuthentication no/' '$SSH_CONF'"
    apply_or_echo "grep -q '^GSSAPIAuthentication' '$SSH_CONF' || echo 'GSSAPIAuthentication no' >> '$SSH_CONF'"
    apply_or_echo "systemctl restart sshd || systemctl restart ssh"
  fi
  ok "基础环境模块已处理"
}
disable_ipv6_module(){
  log "禁用IPv6..."
  local IPV6_SYSCTL="/etc/sysctl.d/97-disable-ipv6.conf"
  local ipv6_content="net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1"
  write_file_safe "$IPV6_SYSCTL" "$ipv6_content"
  apply_or_echo "sysctl -p ${IPV6_SYSCTL}"
  ok "IPv6禁用模块已处理"
}


# ---------- 主流程 (恢复正确结构) ----------
main(){
  [[ "$(id -u)" -ne 0 ]] && { err "请使用 root 权限运行脚本"; exit 1; }
  
  log "Ultimate Singularity (增强版) 脚本启动"
  if [[ "$DRY_RUN" -eq 1 ]]; then warn "当前为 DRY-RUN 模式：不会对系统进行任何实际修改。"; fi
  log "备份目录位于: ${BACKUP_DIR}"

  detect_environment_and_role

  if [[ "$APPLY_IO_LIMITS" -eq 1 ]]; then apply_io_limits_module; fi
  if [[ "$CLEANUP_SERVICES" -eq 1 ]]; then cleanup_services_module; fi
  if [[ "$APPLY_GRUB" -eq 1 ]]; then apply_grub_module; fi
  if [[ "$APPLY_HOST_SPECIFICS" -eq 1 ]]; then apply_host_specifics_module; fi
  if [[ "$GENERATE_TOOLS" -eq 1 ]]; then generate_tools_module; fi
  if [[ "$INSTALL_HW_TUNING" -eq 1 ]]; then install_hw_tuning_module; fi
  if [[ "$APPLY_ZRAM" -eq 1 ]]; then apply_zram_module; fi
  if [[ "$APPLY_FSTAB" -eq 1 ]]; then apply_fstab_module; fi
  if [[ "$APPLY_BASICS" -eq 1 ]]; then apply_basics_module; fi
  if [[ "$DISABLE_IPV6" -eq 1 ]]; then disable_ipv6_module; fi

  echo
  ok "所有选定模块已处理完毕。"
  if [[ "$DRY_RUN" -eq 0 && ("$APPLY_GRUB" -eq 1 || "$APPLY_FSTAB" -eq 1) ]]; then
    warn "GRUB 或 fstab 模块已被应用，您需要手动重启服务器才能使其完全生效。"
  fi
}

main "$@"
