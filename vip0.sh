#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# =================================================================
#  Ultimate Singularity v3.0 "Bedrock Edition"
#  Universal System Optimizer - Pre-Network Tuning
#  Author: Your Name (Inspired by Nodeseek & Community Best Practices)
# =================================================================

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
DRY_RUN=1
APPLY_ALL=0
# --- 模块开关 ---
APPLY_IO_LIMITS=0
APPLY_CPU_TUNING=0
APPLY_MEMORY_TUNING=0
CLEANUP_SERVICES=0
APPLY_GRUB=0
APPLY_HOST_SPECIFICS=0
APPLY_ZRAM=0
APPLY_FSTAB=0
APPLY_BASICS=0
DISABLE_IPV6=0
APPLY_HARDENING=0

usage() {
  echo "Ultimate Singularity v3.0 'Bedrock Edition' - Universal System Optimizer"
  echo "Usage: $0 [--apply] [MODULE...]"
  echo "  --apply                 实际应用更改 (默认是 --dry-run 模式)"
  echo "  --all                   选择所有推荐模块 (高风险模块除外)"
  echo ""
  echo "System & Hardware Modules:"
  echo "  --apply-io-limits       应用存储 I/O 调度 (udev) 和系统资源限制 (limits.conf)"
  echo "  --apply-cpu-tuning      [新增] 优化CPU Governor, 中断亲和性, 并调整内核调度器"
  echo "  --apply-memory-tuning   [新增] 优化VM参数 (脏页, 内存过量提交, THP)"
  echo "  --apply-grub            [极高风险] 为母鸡角色应用CPU隔离等GRUB参数"
  echo "  --apply-host-specifics  为母鸡/NAT角色应用特定优化 (大页内存/连接跟踪)"
  echo ""
  echo "OS & Service Modules:"
  echo "  --cleanup-services      [高风险] 禁用不常用的系统服务和内核模块"
  echo "  --apply-zram            为小内存VPS配置zram (内存压缩Swap)"
  echo "  --apply-fstab           为磁盘挂载添加 noatime 选项以减少I/O"
  echo "  --apply-basics          配置时区、NTP时间同步和优化SSH连接速度"
  echo "  --disable-ipv6          禁用IPv6以减少网络栈开销"
  echo "  --apply-hardening       配置systemd全局默认值, 实现服务自动重启和资源限制"
  echo ""
  echo "  -h, --help              显示此帮助信息"
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    --apply) DRY_RUN=0 ;;
    --all) APPLY_ALL=1 ;;
    --apply-io-limits) APPLY_IO_LIMITS=1 ;;
    --apply-cpu-tuning) APPLY_CPU_TUNING=1 ;;
    --apply-memory-tuning) APPLY_MEMORY_TUNING=1 ;;
    --cleanup-services) CLEANUP_SERVICES=1 ;;
    --apply-grub) APPLY_GRUB=1 ;;
    --apply-host-specifics) APPLY_HOST_SPECIFICS=1 ;;
    --apply-zram) APPLY_ZRAM=1 ;;
    --apply-fstab) APPLY_FSTAB=1 ;;
    --apply-basics) APPLY_BASICS=1 ;;
    --disable-ipv6) DISABLE_IPV6=1 ;;
    --apply-hardening) APPLY_HARDENING=1 ;;
    -h|--help) usage ;;
  esac
done

if [[ "$APPLY_ALL" -eq 1 ]]; then
  APPLY_IO_LIMITS=1
  APPLY_CPU_TUNING=1
  APPLY_MEMORY_TUNING=1
  APPLY_HOST_SPECIFICS=1
  APPLY_ZRAM=1
  APPLY_FSTAB=1
  APPLY_BASICS=1
  DISABLE_IPV6=1
  APPLY_HARDENING=1
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
    printf '%s\n' "$content" > "$path"
  fi
}

# ---------- 环境检测 ----------
detect_environment_and_role(){
  log "开始智能环境检测..."
  [[ -f /etc/os-release ]] && source /etc/os-release || true
  OS_ID="${ID:-unknown}"
  CPU_COUNT=$(nproc 2>/dev/null || echo 1)
  TOTAL_MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
  VIRT_TYPE=$(command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt || echo none)
  
  # 角色判定逻辑
  IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
  HAS_NAT=false
  if command_exists iptables-save && iptables-save 2>/dev/null | grep -qE "(MASQUERADE|SNAT)"; then HAS_NAT=true; fi
  if command_exists nft && nft list ruleset 2>/dev/null | grep -qE "(masquerade|snat)"; then HAS_NAT=true; fi
  
  if [[ "$IP_FORWARD" -eq 1 || "$HAS_NAT" == true ]]; then
    ROLE="nat"
  elif [[ "$VIRT_TYPE" == "none" && -e /dev/kvm && "$TOTAL_MEM_MB" -ge 4096 ]]; then
    ROLE="host"
  else
    ROLE="guest"
  fi
  ok "检测完成: OS=${OS_ID}, CPU=${CPU_COUNT}, Mem=${TOTAL_MEM_MB}MB, Role=${ROLE}"
}

# ---------- 模块化功能 ----------

# 模块一: I/O 与 Limits
apply_io_limits_module(){
  log "应用 I/O 调度 (udev) 和系统资源限制 (limits.conf)..."
  LIMITS_CONF="/etc/security/limits.d/99-ultimate-singularity.conf"
  UDEV_RULES="/etc/udev/rules.d/60-ultimate-io.rules"
  SYSCTL_CONF="/etc/sysctl.d/99-ultimate-fs.conf"
  
  LIMITS_CONTENT=$'* soft nofile 2097152\n* hard nofile 2097152\nroot soft nofile 2097152\nroot hard nofile 2097152'
  UDEV_CONTENT=$'ACTION=="add|change", KERNEL=="nvme[0-9]n[0-9]", ATTR{queue/scheduler}="none", ATTR{queue/nr_requests}="1024"\nACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline", ATTR{queue/nr_requests}="1024"'
  SYSCTL_CONTENT=$'fs.file-max = 2097152\nfs.nr_open = 2097152'

  write_file_safe "$LIMITS_CONF" "$LIMITS_CONTENT"
  write_file_safe "$UDEV_RULES" "$UDEV_CONTENT"
  write_file_safe "$SYSCTL_CONF" "$SYSCTL_CONTENT"

  apply_or_echo "sysctl -p ${SYSCTL_CONF}"
  apply_or_echo "udevadm control --reload-rules || true"
  apply_or_echo "udevadm trigger || true"
  ok "I/O 与 Limits 模块已处理"
}

# 模块二: CPU 调优 (新增)
apply_cpu_tuning_module(){
  log "应用 CPU 性能优化..."
  SYSCTL_CONF="/etc/sysctl.d/98-ultimate-kernel.conf"
  
  # 强制使用 performance governor
  if command_exists cpupower; then
    apply_or_echo "cpupower frequency-set -g performance"
  else
    for gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
      apply_or_echo "echo performance > $gov"
    done
  fi
  
  # 调整内核调度器以优化延迟
  SYSCTL_CONTENT=$'kernel.sched_migration_cost_ns = 5000000\nkernel.sched_latency_ns = 24000000'
  write_file_safe "$SYSCTL_CONF" "$SYSCTL_CONTENT"
  apply_or_echo "sysctl -p ${SYSCTL_CONF}"

  # 禁用 irqbalance 并手动设置中断亲和性
  if command_exists irqbalance; then
    apply_or_echo "systemctl disable --now irqbalance >/dev/null 2>&1 || true"
  fi
  
  # 简单的中断绑定逻辑：将网卡中断分散到非0号CPU核心
  local nic_irqs
  nic_irqs=$(grep -E 'eth|ens|eno|enp' /proc/interrupts | awk '{print $1}' | tr -d ':')
  local i=1
  for irq in $nic_irqs; do
    local cpu_mask
    cpu_mask=$(printf "%x" $((1 << (i % CPU_COUNT))))
    apply_or_echo "echo $cpu_mask > /proc/irq/$irq/smp_affinity"
    i=$((i + 1))
    # 避免绑定到0号核心
    if [[ $i -ge $CPU_COUNT ]]; then i=1; fi
  done

  ok "CPU 调优模块已处理"
}

# 模块三: 内存调优 (新增)
apply_memory_tuning_module(){
  log "应用 VM (虚拟内存) 性能优化..."
  SYSCTL_CONF="/etc/sysctl.d/97-ultimate-vm.conf"
  
  # THP -> madvise
  if [ -f /sys/kernel/mm/transparent_hugepage/enabled ]; then
    apply_or_echo "echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"
  fi

  # 脏页、内存过量提交、最小保留内存等
  local min_free_kb=$(( TOTAL_MEM_MB * 16 )) # 每GB内存保留16MB
  [[ $min_free_kb -lt 65536 ]] && min_free_kb=65536
  [[ $min_free_kb -gt 262144 ]] && min_free_kb=262144
  
  SYSCTL_CONTENT=$(cat <<EOF
vm.dirty_background_ratio = 5
vm.dirty_ratio = 10
vm.swappiness = 10
vm.vfs_cache_pressure = 50
vm.overcommit_memory = 1
vm.min_free_kbytes = ${min_free_kb}
EOF
)
  write_file_safe "$SYSCTL_CONF" "$SYSCTL_CONTENT"
  apply_or_echo "sysctl -p ${SYSCTL_CONF}"
  ok "内存调优模块已处理"
}

# 模块四: 服务清理
cleanup_services_module(){
  log "智能清理与禁用可能干扰性能的服务..."
  services_common=(tuned thermald bluetooth cups snapd unattended-upgrades rsyslog auditd cron apparmor)
  services_net=(firewalld ufw nftables)
  
  local to_disable=("${services_common[@]}")
  if [[ "$ROLE" != "nat" ]]; then to_disable+=("${services_net[@]}"); fi

  for svc in "${to_disable[@]}"; do
    apply_or_echo "systemctl disable --now ${svc} >/dev/null 2>&1 || true"
  done

  timers=(apt-daily.timer apt-daily-upgrade.timer fstrim.timer motd-news.timer)
  for t in "${timers[@]}"; do apply_or_echo "systemctl disable --now ${t} >/dev/null 2>&1 || true"; done
  
  ok "服务清理模块已处理"
}

# 模块五: GRUB 优化
apply_grub_module(){
  [[ "$ROLE" == "host" ]] || { warn "当前非母鸡(role=host)，跳过 GRUB 优化"; return; }
  log "为母鸡角色应用 GRUB CPU 隔离优化..."
  GRUB_FILE="/etc/default/grub"
  [[ -f "$GRUB_FILE" ]] || { warn "$GRUB_FILE 不存在，跳过"; return; }
  backup_file "$GRUB_FILE"

  local iso_count=$(( CPU_COUNT / 4 )); [[ $iso_count -lt 1 ]] && iso_count=1
  local first_iso=$(( CPU_COUNT - iso_count ))
  local ISO="${first_iso}-$((CPU_COUNT-1))"
  
  local PERF="nohz_full=${ISO} rcu_nocbs=${ISO} isolcpus=${ISO} processor.max_cstate=1 idle=poll"

  apply_or_echo "sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT=.*/GRUB_CMDLINE_LINUX_DEFAULT=\"quiet ${PERF}\"/' ${GRUB_FILE}"
  
  if command_exists update-grub; then apply_or_echo "update-grub || true"; fi
  ok "GRUB 模块已处理 (需重启生效)"
}

# 模块六: 特定角色优化
apply_host_specifics_module(){
  if [[ "$ROLE" == "host" ]]; then
    log "为母鸡角色应用大页内存优化..."
    local hp_count=$(( (TOTAL_MEM_MB / 200) )); [[ $hp_count -lt 64 ]] && hp_count=64
    apply_or_echo "echo ${hp_count} > /proc/sys/vm/nr_hugepages"
    ok "母鸡特定优化模块已处理"
  elif [[ "$ROLE" == "nat" ]]; then
    log "为NAT角色优化连接跟踪表大小..."
    local conntrack_max=$(( TOTAL_MEM_MB * 64 ))
    [[ $conntrack_max -lt 65536 ]] && conntrack_max=65536
    [[ $conntrack_max -gt 1048576 ]] && conntrack_max=1048576
    local NAT_SYSCTL="/etc/sysctl.d/98-nat-tweaks.conf"
    local nat_content="net.netfilter.nf_conntrack_max = ${conntrack_max}"
    write_file_safe "$NAT_SYSCTL" "$nat_content"
    apply_or_echo "sysctl -p ${NAT_SYSCTL}"
    ok "NAT特定优化模块已处理"
  fi
}

# 模块七: ZRAM
apply_zram_module(){
  if [[ "$TOTAL_MEM_MB" -gt 4096 ]]; then
    warn "内存大于4GB，通常无需ZRAM，跳过。"; return;
  fi
  log "为小内存VPS配置ZRAM..."
  
  apply_or_echo "apt-get update -y && apt-get install -y zram-tools"
  
  local zram_size=$(( TOTAL_MEM_MB / 2 ))
  local ZRAM_CONF="/etc/default/zramswap"
  local zram_content="ALGO=zstd\nSIZE=${zram_size}\nPRIORITY=100"
  write_file_safe "$ZRAM_CONF" "$zram_content"
  
  apply_or_echo "systemctl enable --now zramswap.service"
  ok "ZRAM模块已处理"
}

# 模块八: fstab
apply_fstab_module(){
  log "优化 /etc/fstab，添加 noatime,nodiratime..."
  local FSTAB="/etc/fstab"
  [[ -f "$FSTAB" ]] || { warn "$FSTAB 不存在，跳过"; return; }
  backup_file "$FSTAB"
  
  if [[ "$DRY_RUN" -eq 0 ]]; then
    awk '
    /^\s*#/ || /^\s*$/ || $4 ~ /noatime/ {print; next}
    $3 ~ /ext4|xfs/ { $4 = $4 ",noatime,nodiratime"; }
    { printf "%-22s %-22s %-7s %-25s %s %s\n", $1, $2, $3, $4, $5, $6 }
    ' "$FSTAB" > "${FSTAB}.tmp" && mv "${FSTAB}.tmp" "$FSTAB"
  else
    log "[DRY-RUN] ==> 将在 $FSTAB 中为 ext4/xfs 文件系统添加 'noatime,nodiratime'"
  fi
  ok "fstab模块已处理 (建议 'mount -o remount /' 或重启)"
}

# 模块九: 基础环境
apply_basics_module(){
  log "配置基础环境 (时区/NTP/SSH)..."
  apply_or_echo "timedatectl set-timezone Asia/Shanghai"
  apply_or_echo "apt-get install -y chrony"
  apply_or_echo "systemctl enable --now chrony"

  local SSH_CONF="/etc/ssh/sshd_config"
  if [[ -f "$SSH_CONF" ]]; then
    backup_file "$SSH_CONF"
    apply_or_echo "sed -i -E 's/^[#\s]*UseDNS\s+yes/UseDNS no/' '$SSH_CONF'"
    apply_or_echo "sed -i -E 's/^[#\s]*GSSAPIAuthentication\s+yes/GSSAPIAuthentication no/' '$SSH_CONF'"
    apply_or_echo "systemctl restart sshd"
  fi
  ok "基础环境模块已处理"
}

# 模块十: 禁用IPv6
disable_ipv6_module(){
  log "禁用IPv6..."
  local IPV6_SYSCTL="/etc/sysctl.d/97-disable-ipv6.conf"
  local ipv6_content="net.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1"
  write_file_safe "$IPV6_SYSCTL" "$ipv6_content"
  apply_or_echo "sysctl -p ${IPV6_SYSCTL}"
  ok "IPv6禁用模块已处理"
}

# 模块十一: 系统加固
apply_hardening_module(){
  log "应用 systemd 全局默认值，增强系统稳定性..."
  local SYSTEMD_DROPIN_DIR="/etc/systemd/system.conf.d"
  local HARDENING_CONF="${SYSTEMD_DROPIN_DIR}/99-ultimate-hardening.conf"
  
  local hardening_content="[Manager]\nDefaultTimeoutStopSec=10s\nDefaultRestartSec=5s\nDefaultLimitNOFILE=1048576"
  
  write_file_safe "$HARDENING_CONF" "$hardening_content"
  apply_or_echo "systemctl daemon-reload"
  ok "系统加固模块已处理"
}

# ---------- 主流程 ----------
main(){
  [[ "$(id -u)" -ne 0 ]] && { err "请使用 root 权限运行脚本"; exit 1; }
  
  log "Ultimate Singularity v3.0 'Bedrock Edition' 脚本启动"
  if [[ "$DRY_RUN" -eq 1 ]]; then warn "当前为 DRY-RUN 模式：不会对系统进行任何实际修改。"; fi
  log "备份目录位于: ${BACKUP_DIR}"

  detect_environment_and_role

  if [[ "$APPLY_IO_LIMITS" -eq 1 ]]; then apply_io_limits_module; fi
  if [[ "$APPLY_CPU_TUNING" -eq 1 ]]; then apply_cpu_tuning_module; fi
  if [[ "$APPLY_MEMORY_TUNING" -eq 1 ]]; then apply_memory_tuning_module; fi
  if [[ "$CLEANUP_SERVICES" -eq 1 ]]; then cleanup_services_module; fi
  if [[ "$APPLY_GRUB" -eq 1 ]]; then apply_grub_module; fi
  if [[ "$APPLY_HOST_SPECIFICS" -eq 1 ]]; then apply_host_specifics_module; fi
  if [[ "$APPLY_ZRAM" -eq 1 ]]; then apply_zram_module; fi
  if [[ "$APPLY_FSTAB" -eq 1 ]]; then apply_fstab_module; fi
  if [[ "$APPLY_BASICS" -eq 1 ]]; then apply_basics_module; fi
  if [[ "$DISABLE_IPV6" -eq 1 ]]; then disable_ipv6_module; fi
  if [[ "$APPLY_HARDENING" -eq 1 ]]; then apply_hardening_module; fi

  echo
  ok "所有选定模块已处理完毕。"
  if [[ "$DRY_RUN" -eq 0 && ("$APPLY_GRUB" -eq 1 || "$APPLY_FSTAB" -eq 1) ]]; then
    warn "GRUB 或 fstab 模块已被应用，您需要手动重启服务器才能使其完全生效。"
  fi
}

main "$@"
