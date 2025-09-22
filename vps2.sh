#!/usr/bin/env bash
#
# ===================================================================================
# Ultimate Singularity v12.0 - The Self-Correcting Performance Framework
# ===================================================================================
#
# Author: AI Executor (Self-Correcting Edition)
# Version: v12.0-self-correcting
#
# This definitive version introduces a critical layer of robustness and self-correction.
# It validates all auto-detected data and intelligently falls back to safe defaults
# when detection fails, ensuring predictable and stable outcomes in any environment.
#
set -euo pipefail
IFS=$'\n\t'

# ========== Global Configuration & State ==========
readonly SCRIPT_VER="v12.0-self-correcting"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly BACKUP_BASE="/root/ultimate_singularity_backups"
readonly BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"
readonly SYSCTL_TARGET="/etc/sysctl.d/99-ultimate-singularity-v12.conf"
readonly LOG_FILE="/var/log/ultimate-singularity.log"
readonly REPORT_FILE_TXT="/root/ultimate-singularity-report-${TIMESTAMP}.txt"
readonly REPORT_FILE_JSON="/root/ultimate-singularity-report-${TIMESTAMP}.json"
readonly ROLLBACK_SCRIPT="${BACKUP_DIR}/rollback.sh"
readonly LOCKFILE="/var/lock/ultimate_optimize.lock"
readonly CONFIG_FILE="/etc/ultimate_optimizer.conf"

# Defaults
AGGRESSIVE=1
DRY_RUN=0
DEBUG=0
DETECTION_ACCURATE=1 # Flag to track if auto-detection was successful

declare -A ORIGINAL_SERVICE_STATES
declare -A ORIGINAL_SERVICE_ACTIVE
declare -A CHANGES_SUMMARY
TEMP_FILES=()

# ========== CLI parsing ==========
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --conservative) AGGRESSIVE=0 ;;
    --aggressive) AGGRESSIVE=1 ;;
    --debug) DEBUG=1 ;;
  esac
done

# ========== Logging & Output Utilities ==========
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || true
log()  { printf '%s [INFO] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE"; }
warn() { printf '%s [WARN] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE" >&2; }
err()  { printf '%s [ERROR] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE" >&2; }
ok()   { printf '%s [OK] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE"; }
debug() { [[ "$DEBUG" -eq 1 ]] && printf '%s [DEBUG] %s\n' "$(date -Iseconds)" "$*"; }

# ========== Core Execution & File Management Modules ==========

# Concurrency lock
exec 200>"$LOCKFILE"
if ! flock -n 200; then err "Another instance is running. Exiting."; exit 1; fi

# Temp file management
mktemp_add() { local f; f=$(mktemp) || { err "mktemp failed"; return 1; }; TEMP_FILES+=("$f"); echo "$f"; }
cleanup() { for f in "${TEMP_FILES[@]:-}"; do [[ -f "$f" ]] && rm -f "$f"; done; }
trap cleanup EXIT

# Backup utility
backup_file() {
  local path="$1"; mkdir -p "$BACKUP_DIR"
  if [[ -e "$path" ]]; then local base; base=$(basename "$path"); cp -aL "$path" "$BACKUP_DIR/${base}.bak" || true; fi
}

# Safe command runner
run_cmd() {
  debug "Executing: $*"
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then echo "[DRY-RUN] $*"; return 0; fi
  if [[ "${1:-}" == "bash-c" ]]; then shift; bash -c "$*"; else "$@"; fi
}

# Idempotent & Atomic file writer
write_file_safe() {
  local path="$1"; shift; local content="$*"
  if [[ -f "$path" ]] && command -v sha256sum >/dev/null 2>&1; then
    local new_hash; new_hash=$(printf '%s\n' "$content" | sha256sum | awk '{print $1}')
    local old_hash; old_hash=$(sha256sum "$path" | awk '{print $1}')
    if [[ "$new_hash" == "$old_hash" ]]; then log "Content of $path is unchanged, skipping write."; return 0; fi
  fi
  backup_file "$path"
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then echo "[DRY-RUN] write to $path"; return 0; fi
  local tmp; tmp=$(mktemp_add) || return 1
  printf '%s\n' "$content" > "$tmp"
  install -m 0644 "$tmp" "$path" || { err "install failed for $path"; return 1; }
  ok "Wrote: $path"
}

# Rollback registration with comments
register_rollback_step() {
  local comment="$1" cmd="$2"
  mkdir -p "$(dirname "$ROLLBACK_SCRIPT")"
  if [[ ! -f "$ROLLBACK_SCRIPT" ]]; then
    printf '#!/usr/bin/env bash\nset -euo pipefail\n\n' > "$ROLLBACK_SCRIPT"
    chmod 700 "$ROLLBACK_SCRIPT"
  fi
  printf '# %s\n%s\n' "$comment" "$cmd" >> "$ROLLBACK_SCRIPT"
}

# ========== Advanced System Management Modules ==========

# Stateful service manager
manage_service() {
  local service_name="$1" action="$2"
  if ! command -v systemctl >/dev/null 2>&1; then warn "systemctl not found, skipping service management for ${service_name}"; return 0; fi
  if ! systemctl list-unit-files --type=service | awk '{print $1}' | grep -q -x "${service_name}.service"; then return 0; fi
  
  ORIGINAL_SERVICE_STATES["$service_name"]=$(systemctl is-enabled --quiet "$service_name" && echo "enabled" || echo "disabled")
  if [[ "$action" == "disable" && "${ORIGINAL_SERVICE_STATES[$service_name]}" == "disabled" ]]; then log "Service ${service_name} is already disabled, skipping."; return 0; fi

  log "Action: ${action} on ${service_name}"
  run_cmd systemctl "$action" --now "$service_name" || true
  if [[ "${ORIGINAL_SERVICE_STATES[$service_name]}" == "enabled" ]]; then register_rollback_step "Re-enable service ${service_name}" "systemctl enable '$service_name' || true"; fi
}

# Multi-strategy RTT detector
detect_best_rtt() {
  local rtt target rtt_s
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    target=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    if rtt=$(ping -c 3 -W 2 "$target" 2>/dev/null | awk -F'/' '/rtt/ {print $5}'); then [[ -n "$rtt" ]] && printf "%.0f" "$rtt" && return; fi
  fi
  target=$(ip route | awk '/default/ {print $3; exit}')
  if [[ -n "$target" ]]; then
    if rtt=$(ping -c 3 -W 2 "$target" 2>/dev/null | awk -F'/' '/rtt/ {print $5}'); then [[ -n "$rtt" ]] && printf "%.0f" "$rtt" && return; fi
  fi
  if rtt=$(ping -c 3 -W 2 1.1.1.1 2>/dev/null | awk -F'/' '/rtt/ {print $5}'); then [[ -n "$rtt" ]] && printf "%.0f" "$rtt" && return; fi
  if command -v curl >/dev/null 2>&1; then
    rtt_s=$(curl -s -o /dev/null -w '%{time_connect}' --connect-timeout 4 https://1.1.1.1 || true)
    if [[ -n "$rtt_s" ]]; then awk -v s="$rtt_s" 'BEGIN{printf "%.0f", s*1000}'; return; fi
  fi
  echo "" # Return empty on failure
}

# Post-optimization health check
health_check() {
  log "Performing post-optimization health check..."
  if ! ping -c 1 -W 2 1.1.1.1 &>/dev/null && ! curl -s --connect-timeout 3 https://1.1.1.1 >/dev/null; then
    err "Health Check FAIL: Network connectivity lost. Execute rollback script immediately: $ROLLBACK_SCRIPT"
    return 1
  fi
  ok "Health check passed."
}

# Hooks/Plugins runner
run_hooks() {
    local hook_name="$1"
    local hook_dir="/etc/ultimate_optimizer/hooks.d"
    if [[ -d "${hook_dir}/${hook_name}" ]]; then
        log "Executing ${hook_name} hooks..."
        for script in $(run-parts --list "${hook_dir}/${hook_name}" 2>/dev/null || true); do
            log "  -> Running ${script}"
            run_cmd "$script"
        done
    fi
}

# ========== Main Optimization Logic ==========

main() {
  # --- Initialization ---
  [[ "$(id -u)" -eq 0 ]] || { err "This script must be run as root."; exit 1; }
  log "Starting Ultimate Singularity v12.0 - The Self-Correcting Framework"
  mkdir -p "$BACKUP_DIR"
  [[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"
  [[ "$DRY_RUN" -eq 1 ]] && warn "DRY-RUN mode is active. No changes will be made."
  [[ "$AGGRESSIVE" -eq 1 ]] && warn "AGGRESSIVE mode is active by default." || ok "CONSERVATIVE mode active."

  # --- Stages ---
  check_and_install_deps
  detect_environment_and_workload
  calculate_bdp_and_tcp
  run_hooks "pre-optimize"
  handle_conflicts
  generate_sysctl_and_memory
  install_dynamic_optimizer
  optimize_dns
  cleanup_services
  optimize_grub
  run_hooks "post-optimize"
  
  log "Applying configurations and performing health check..."
  run_cmd sysctl --system
  health_check || exit 1
  
  generate_report_and_rollback

  # --- Finalization ---
  ok "Optimization complete."
  ok "A detailed report has been saved to: ${REPORT_FILE_TXT} (and .json)"
  ok "A one-click rollback script has been created: ${ROLLBACK_SCRIPT}"
  [[ "$ROLE" == "host" ]] && warn "A reboot is required for GRUB changes to take effect."
}

# ========== Function Implementations ==========

check_and_install_deps() {
    log "Stage 1: Checking dependencies..."
    local -A cmd_to_pkg=( [ethtool]="ethtool" [sha256sum]="coreutils" [nproc]="coreutils" [iptables-save]="iptables" [ip]="iproute2" [ping]="iputils-ping" [curl]="curl" )
    local missing_pkgs=()
    for cmd in "${!cmd_to_pkg[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then missing_pkgs+=("${cmd_to_pkg[$cmd]}"); fi
    done
    if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
        local unique_pkgs; unique_pkgs=$(echo "${missing_pkgs[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' ')
        warn "Missing dependencies: ${unique_pkgs}"
        if command -v apt-get >/dev/null 2>&1; then run_cmd apt-get update -y && run_cmd apt-get install -y $unique_pkgs
        elif command -v yum >/dev/null 2>&1; then run_cmd yum install -y $unique_pkgs
        else err "Cannot auto-install dependencies. Please install them manually."; exit 1; fi
    fi
}

detect_environment_and_workload() {
  log "Stage 2: Detecting System, Workload, and Architecture..."
  [[ -f /etc/os-release ]] && source /etc/os-release || true
  OS_ID="${ID:-unknown}"; CPU_COUNT=$(nproc 2>/dev/null || echo 1); TOTAL_MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)
  PRIMARY_NIC=$(ip route | awk '/default/ {print $5; exit}' || echo eth0)
  
  # ROBUST Link Speed Detection
  local speed
  speed=$(cat "/sys/class/net/${PRIMARY_NIC}/speed" 2>/dev/null || echo "")
  if ! [[ "$speed" =~ ^[0-9]+$ && "$speed" -gt 0 ]]; then
      speed=$(ethtool "${PRIMARY_NIC}" 2>/dev/null | awk -F': ' '/Speed/ {gsub(/[^0-9]/,"",$2); print $2; exit}' || echo "")
  fi
  if ! [[ "$speed" =~ ^[0-9]+$ && "$speed" -gt 0 ]]; then
      warn "Could not detect link speed for ${PRIMARY_NIC}. Using fallback of 1000Mbps."
      DETECTION_ACCURATE=0
      LINK_SPEED_MBPS=1000
  else
      LINK_SPEED_MBPS=$speed
  fi

  VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo none)
  local ip_forward; ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
  local has_nat=false; command -v iptables-save &>/dev/null && iptables-save 2>/dev/null | grep -qE "(MASQUADE|SNAT)" && has_nat=true
  if [[ "$ip_forward" -eq 1 || "$has_nat" == true ]]; then ROLE="nat"; elif [[ "$VIRT_TYPE" == "none" && -e /dev/kvm ]]; then ROLE="host"; else ROLE="guest"; fi
  HAS_NUMA=$([[ -d /sys/devices/system/node/node1 ]] && echo true || echo false)
  HAS_NGINX=$(pgrep -x nginx &>/dev/null && echo true || echo false)
  HAS_MYSQL=$( (pgrep -x mysqld || pgrep -x mariadbd) &>/dev/null && echo true || echo false)
  HAS_REDIS=$(pgrep -x redis-server &>/dev/null && echo true || echo false)
  ok "Detection: Role=${ROLE}, NIC=${PRIMARY_NIC}(${LINK_SPEED_MBPS}Mbps), NUMA=${HAS_NUMA}, Nginx=${HAS_NGINX}, MySQL=${HAS_MYSQL}, Redis=${HAS_REDIS}"
}

calculate_bdp_and_tcp() {
  log "Stage 3: Calculating BDP and TCP Parameters..."
  local rtt_ms_raw; rtt_ms_raw=$(detect_best_rtt)
  if [[ -z "$rtt_ms_raw" || "$rtt_ms_raw" -lt 1 ]]; then
      warn "RTT detection failed or returned invalid value. Using fallback of 80ms."
      DETECTION_ACCURATE=0
      RTT_MS=80
  else
      RTT_MS=$rtt_ms_raw
  fi

  if [[ "$DETECTION_ACCURATE" -eq 0 ]]; then
      warn "One or more network parameters were not accurately detected. Applying safe conservative defaults for TCP buffers."
      TCP_BUFFER_MAX=$(( 64 * 1024 * 1024 ))
      TCP_DEFAULT_BUF=262144
      return
  fi

  local bdp_bytes=$(( LINK_SPEED_MBPS * 125 * RTT_MS ))
  local suggested_buffer=$(( bdp_bytes * 2 ))
  local mem_limit=$(( TOTAL_MEM_MB * 1024 * 5 / 100 ))
  local cap_256mb=$(( 256 * 1024 * 1024 ))
  [[ $suggested_buffer -gt $mem_limit ]] && suggested_buffer=$mem_limit
  [[ $suggested_buffer -gt $cap_256mb ]] && suggested_buffer=$cap_256mb
  local buffer_mb=$(( suggested_buffer / 1024 / 1024 ))
  if [[ $buffer_mb -ge 256 ]]; then buffer_mb=256; elif [[ $buffer_mb -ge 128 ]]; then buffer_mb=128; elif [[ $buffer_mb -ge 64 ]]; then buffer_mb=64; else buffer_mb=32; fi
  TCP_BUFFER_MAX=$(( buffer_mb * 1024 * 1024 ))
  TCP_DEFAULT_BUF=$(( buffer_mb >= 64 ? 524288 : 262144 ))
  ok "BDP Calc: ${LINK_SPEED_MBPS}Mbps @ ${RTT_MS}ms -> Buffer=${buffer_mb}MB"
}

handle_conflicts() {
  log "Stage 4: Resolving existing sysctl conflicts..."
  local key_regex='(rmem_max|wmem_max|tcp_rmem|tcp_wmem|tcp_congestion_control|default_qdisc)'
  if [[ -f /etc/sysctl.conf ]] && grep -qE "$key_regex" /etc/sysctl.conf; then
    backup_file /etc/sysctl.conf
    register_rollback_step "Restore /etc/sysctl.conf" "cp -a '$BACKUP_DIR/sysctl.conf.bak' /etc/sysctl.conf || true"
    run_cmd bash-c "sed -i -E '/${key_regex}/s/^/#DISABLED_BY_US# /' /etc/sysctl.conf"
  fi
  for f in /etc/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    if grep -qE "$key_regex" "$f"; then
      local mv_dest="${f}.disabled_by_us"
      run_cmd mv "$f" "$mv_dest"
      register_rollback_step "Revert disabled sysctl file ${f}" "mv '$mv_dest' '$f' || true"
    fi
  done
}

generate_sysctl_and_memory() {
  log "Stage 5: Generating sysctl and memory configs..."
  local congestion="bbr"; if command -v sysctl &>/dev/null && sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr2; then congestion="bbr2"; fi
  local qdisc="fq"
  local content
  content=$(cat <<EOF
# Ultimate Singularity v12.0 - Generated ${TIMESTAMP}
# Mode: $([[ "$AGGRESSIVE" -eq 1 ]] && echo "Aggressive" || echo "Conservative")

# --- Core Kernel & Memory ---
fs.file-max = 8388608
vm.swappiness = 1
vm.dirty_ratio = 10
vm.dirty_background_ratio = 3

# --- Network Core (BDP Optimized) ---
net.core.default_qdisc = ${qdisc}
net.core.netdev_max_backlog = 65536
net.core.somaxconn = 65536
net.core.rmem_max = ${TCP_BUFFER_MAX}
net.core.wmem_max = ${TCP_BUFFER_MAX}

# --- TCP Stack (High-Performance) ---
net.ipv4.tcp_congestion_control = ${congestion}
net.ipv4.tcp_rmem = 4096 ${TCP_DEFAULT_BUF} ${TCP_BUFFER_MAX}
net.ipv4.tcp_wmem = 4096 ${TCP_DEFAULT_BUF} ${TCP_BUFFER_MAX}
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_max_syn_backlog = 32768
EOF
)
  if [[ "$HAS_NGINX" == "true" ]]; then content+=$'\nnet.ipv4.tcp_max_tw_buckets = 2000000'; fi
  if [[ "$HAS_REDIS" == "true" ]]; then content+=$'\nvm.overcommit_memory = 1'; fi
  if [[ "$HAS_NUMA" == "true" ]]; then content+=$'\nkernel.numa_balancing = 0'; fi
  if [[ "$HAS_MYSQL" == "true" || "$ROLE" == "host" ]]; then
    local hugepages_count=$(( TOTAL_MEM_MB / 2 / 2 ))
    content+=$'\n# --- Workload: Huge Pages for DB/KVM ---\nvm.nr_hugepages = '"$hugepages_count"
    register_rollback_step "Revert HugePages" "sysctl -w vm.nr_hugepages=0"
  fi
  if [[ "$AGGRESSIVE" -eq 1 ]]; then content+=$'\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1'; fi
  
  write_file_safe "$SYSCTL_TARGET" "$content"
  register_rollback_step "Remove generated sysctl file" "rm -f $SYSCTL_TARGET || true"

  if [[ "$HAS_REDIS" == "true" && -f /sys/kernel/mm/transparent_hugepage/enabled ]]; then
    local original_thp; original_thp=$(cat /sys/kernel/mm/transparent_hugepage/enabled | awk '{print $1}' | tr -d '[]')
    run_cmd bash-c "echo madvise > /sys/kernel/mm/transparent_hugepage/enabled"
    register_rollback_step "Restore THP setting" "echo ${original_thp} > /sys/kernel/mm/transparent_hugepage/enabled"
  fi
}

install_dynamic_optimizer() {
  log "Stage 6: Deploying NUMA-Aware Dynamic Optimizer..."
  local script_path="/usr/local/bin/ultimate-dynamic-optimizer.sh"
  local script_content
  script_content=$(cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
expand_cpulist() { echo "$1" | sed -E 's/,/ /g; s/-/\../g' | xargs -n1 seq 2>/dev/null | tr '\n' ' ' || echo "$1"; }
CPU_COUNT=$(nproc 2>/dev/null || echo 1)
for NIC in $(ls /sys/class/net | grep -v lo); do
  [[ -d "/sys/class/net/$NIC" && "$(cat "/sys/class/net/$NIC/operstate" 2>/dev/null)" == "up" ]] || continue
  local affinity_cpus=()
  numa_node_file="/sys/class/net/$NIC/device/numa_node"
  if [[ -f "$numa_node_file" ]]; then
      numa_node=$(cat "$numa_node_file")
      if [[ "$numa_node" -ge 0 && -f "/sys/devices/system/node/node${numa_node}/cpulist" ]]; then
          mapfile -t affinity_cpus < <(expand_cpulist "$(cat "/sys/devices/system/node/node${numa_node}/cpulist")")
      fi
  fi
  if [[ ${#affinity_cpus[@]} -eq 0 ]]; then mapfile -t affinity_cpus < <(seq 0 $((CPU_COUNT - 1))); fi
  local affinity_cpu_count=${#affinity_cpus[@]}
  local irq_list; irq_list=$(grep "$NIC" /proc/interrupts 2>/dev/null | awk '{print $1}' | tr -d ':' | head -n 32 || true)
  local idx=0
  for irq in $irq_list; do
    if [[ -f "/proc/irq/$irq/smp_affinity_list" ]]; then
      cpu_target=${affinity_cpus[$(( idx % affinity_cpu_count ))]}
      echo "$cpu_target" > "/proc/irq/$irq/smp_affinity_list" 2>/dev/null || true
      ((idx++))
    fi
  done
done
EOF
)
  write_file_safe "$script_path" "$script_content"
  if ! run_cmd bash -n "$script_path"; then err "Dynamic optimizer script syntax error!"; return 1; fi
  run_cmd chmod +x "$script_path"
  register_rollback_step "Remove dynamic optimizer script" "rm -f $script_path || true"

  write_file_safe "/etc/systemd/system/ultimate-dynamic-optimizer.service" "$(cat <<'UNIT'
[Unit]
Description=Ultimate Dynamic Optimizer (NUMA-Aware)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/ultimate-dynamic-optimizer.sh
UNIT
)"
  write_file_safe "/etc/systemd/system/ultimate-dynamic-optimizer.timer" "$(cat <<'TIMER'
[Unit]
Description=Run Optimizer periodically
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
TIMER
)"
  run_cmd systemctl daemon-reload || true
  run_cmd systemctl enable --now ultimate-dynamic-optimizer.timer || true
  run_cmd "$script_path" || true
  register_rollback_step "Disable dynamic optimizer timer" "systemctl disable --now ultimate-dynamic-optimizer.timer || true"
  register_rollback_step "Remove dynamic optimizer units" "rm -f /etc/systemd/system/ultimate-dynamic-optimizer.{service,timer} || true"
}

optimize_dns() {
  log "Stage 7: Optimizing DNS..."
  if [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf | grep -q 'systemd'; then
    write_file_safe "/etc/systemd/resolved.conf.d/99-ultimate.conf" "$(cat <<'RES'
[Resolve]
DNS=1.1.1.1 8.8.8.8 9.9.9.9
Cache=yes
RES
)"
    run_cmd systemctl restart systemd-resolved || true
    register_rollback_step "Revert systemd-resolved config" "rm -f /etc/systemd/resolved.conf.d/99-ultimate.conf && systemctl restart systemd-resolved || true"
  else
    backup_file /etc/resolv.conf
    write_file_safe "/etc/resolv.conf" "$(cat <<'RES'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
options edns0 single-request-reopen
RES
)"
    register_rollback_step "Restore /etc/resolv.conf" "cp -a '$BACKUP_DIR/resolv.conf.bak' /etc/resolv.conf || true"
  fi
}

cleanup_services() {
    log "Stage 8: Cleaning up non-essential services..."
    local services_to_disable=(irqbalance tuned thermald bluetooth cups snapd unattended-upgrades)
    [[ "$ROLE" != "nat" ]] && services_to_disable+=(firewalld ufw)
    local pids=(); for svc in "${services_to_disable[@]}"; do ( manage_service "$svc" "disable" ) & pids+=($!); done
    for pid in "${pids[@]}"; do wait "$pid"; done
}

optimize_grub() {
  log "Stage 9: Applying ultimate GRUB optimizations..."
  [[ "$ROLE" != "host" ]] && { log "Not a host, skipping GRUB."; return 0; }
  [[ ! -f /etc/default/grub ]] && { warn "GRUB config not found, skipping."; return 0; }
  local params="quiet loglevel=3"
  if [[ "$AGGRESSIVE" -eq 1 ]]; then
    params+=" mitigations=off"
    if [[ "$CPU_COUNT" -ge 4 ]]; then
      local housekeeping_cores=$(( CPU_COUNT * 3 / 4 ))
      local isolated_range="${housekeeping_cores}-$((CPU_COUNT - 1))"
      local housekeeping_range="0-$((housekeeping_cores - 1))"
      params+=" isolcpus=${isolated_range} nohz_full=${isolated_range} rcu_nocbs=${isolated_range} irqaffinity=${housekeeping_range}"
    fi
  fi
  backup_file /etc/default/grub
  register_rollback_step "Restore GRUB config" "cp -a '$BACKUP_DIR/grub.bak' /etc/default/grub && update-grub || true"
  local tmp; tmp=$(mktemp_add) || return 1
  awk -v p="$params" 'BEGIN{found=0} /^GRUB_CMDLINE_LINUX_DEFAULT=/ { print "GRUB_CMDLINE_LINUX_DEFAULT=\"" p "\""; found=1; next } { print } END { if (!found) print "GRUB_CMDLINE_LINUX_DEFAULT=\"" p "\"" }' /etc/default/grub > "$tmp"
  run_cmd mv "$tmp" /etc/default/grub
  run_cmd bash-c "update-grub || grub2-mkconfig -o /boot/grub2/grub.cfg || true"
}

generate_report_and_rollback() {
  log "Stage 11: Generating final reports and rollback script..."
  # Text Report
  local report_txt
  report_txt=$(cat <<EOF
===================================================================
          Ultimate Singularity v12.0 Optimization Report
===================================================================
- Timestamp: ${TIMESTAMP}
- Mode: $([[ "$AGGRESSIVE" -eq 1 ]] && echo "Aggressive" || echo "Conservative")
- Backup Directory: ${BACKUP_DIR}
- One-Click Rollback Script: ${ROLLBACK_SCRIPT}

--- System & Workload Profile ---
- OS: ${OS_ID:-unknown}
- Hardware: ${CPU_COUNT} Cores / ${TOTAL_MEM_MB}MB RAM / NUMA: ${HAS_NUMA}
- Role: ${ROLE}
- Detected Workloads: Nginx=${HAS_NGINX}, MySQL/MariaDB=${HAS_MYSQL}, Redis=${HAS_REDIS}

--- Network Tuning Summary ---
- Detection Accuracy: $([[ "$DETECTION_ACCURATE" -eq 1 ]] && echo "High" || echo "Low (Used Fallbacks)")
- TCP Congestion Control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
- TCP Buffer: $((TCP_BUFFER_MAX / 1024 / 1024))MB (Based on ${LINK_SPEED_MBPS}Mbps @ ${RTT_MS}ms)
- GRUB: Advanced CPU isolation and performance parameters applied (reboot required).
EOF
)
  write_file_safe "$REPORT_FILE_TXT" "$report_txt"

  # JSON Report
  local report_json
  report_json=$(cat <<EOF
{
  "script_version": "${SCRIPT_VER}", "timestamp": "${TIMESTAMP}",
  "mode": "$([[ "$AGGRESSIVE" -eq 1 ]] && echo "Aggressive" || echo "Conservative")",
  "detection_accurate": $([[ "$DETECTION_ACCURATE" -eq 1 ]] && echo true || echo false),
  "backup_dir": "${BACKUP_DIR}", "rollback_script": "${ROLLBACK_SCRIPT}",
  "system": { "os": "${OS_ID:-unknown}", "cpu_cores": ${CPU_COUNT}, "memory_mb": ${TOTAL_MEM_MB}, "role": "${ROLE}", "numa": ${HAS_NUMA} },
  "workloads": { "nginx": ${HAS_NGINX}, "mysql": ${HAS_MYSQL}, "redis": ${HAS_REDIS} },
  "optimization": {
    "tcp_congestion_control": "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")",
    "tcp_buffer_mb": $((TCP_BUFFER_MAX / 1024 / 1024)),
    "link_speed_mbps": ${LINK_SPEED_MBPS}, "rtt_ms": ${RTT_MS}
  }
}
EOF
)
  write_file_safe "$REPORT_FILE_JSON" "$report_json"
  ok "Reports written: $REPORT_FILE_TXT and $REPORT_FILE_JSON"
}

# ========== Script Entry Point ==========
main
