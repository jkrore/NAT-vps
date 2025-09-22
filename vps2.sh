#!/usr/bin/env bash
#
# ===================================================================================
# Ultimate Singularity v10_final.sh - Definitive Performance & Automation Framework
# ===================================================================================
#
# Author: AI Executor (finalized)
# Version: v10.0-final
#
# Defaults: AGGRESSIVE mode by default. Use --conservative for safer run.
#
set -euo pipefail
IFS=$'\n\t'

# ========== Globals ==========
readonly SCRIPT_VER="v10.0-final"
readonly TIMESTAMP=$(date +%Y%m%d_%H%M%S)
readonly BACKUP_BASE="/root/ultimate_singularity_backups"
readonly BACKUP_DIR="${BACKUP_BASE}/${TIMESTAMP}"
readonly SYSCTL_TARGET="/etc/sysctl.d/99-ultimate-singularity-v10.conf"
readonly LOG_FILE="/var/log/ultimate-singularity.log"
readonly REPORT_FILE_TXT="/root/ultimate-singularity-report-${TIMESTAMP}.txt"
readonly REPORT_FILE_JSON="/root/ultimate-singularity-report-${TIMESTAMP}.json"
readonly ROLLBACK_SCRIPT="${BACKUP_DIR}/rollback.sh"
readonly LOCKFILE="/var/lock/ultimate_optimize.lock"
readonly CONFIG_FILE="/etc/ultimate_optimizer.conf"

# Defaults
AGGRESSIVE=1
DRY_RUN=0

declare -A ORIGINAL_SERVICE_STATES
declare -A ORIGINAL_SERVICE_ACTIVE
TEMP_FILES=()

# ========== CLI parsing ==========
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --conservative) AGGRESSIVE=0 ;;
    --aggressive) AGGRESSIVE=1 ;;
  esac
done

# ========== Logging (also write to file) ==========
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true
touch "$LOG_FILE" 2>/dev/null || true
log()  { printf '%s [INFO] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE"; }
warn() { printf '%s [WARN] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE" >&2; }
err()  { printf '%s [ERROR] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE" >&2; }
ok()   { printf '%s [OK] %s\n' "$(date -Iseconds)" "$*" | tee -a "$LOG_FILE"; }

# ========== Concurrency lock ==========
exec 200>"$LOCKFILE"
if ! flock -n 200; then
  err "Another instance is running. Exiting."
  exit 1
fi

# ========== Temp file management ==========
mktemp_add() {
  local f
  f=$(mktemp) || { err "mktemp failed"; return 1; }
  TEMP_FILES+=("$f")
  echo "$f"
}
_remove_temp_from_array() {
  local t="$1"
  local i out=()
  for i in "${TEMP_FILES[@]:-}"; do [[ "$i" != "$t" ]] && out+=("$i"); done
  TEMP_FILES=("${out[@]}")
}
cleanup() {
  for f in "${TEMP_FILES[@]:-}"; do [[ -f "$f" ]] && rm -f "$f"; done
}
trap cleanup EXIT

# ========== Backup utility ==========
backup_file() {
  local path="$1"
  mkdir -p "$BACKUP_DIR"
  if [[ -e "$path" ]]; then
    local base
    base=$(basename "$path")
    cp -aL "$path" "$BACKUP_DIR/${base}.bak" || true
    log "Backup: $path -> $BACKUP_DIR/${base}.bak"
  fi
}

# ========== Safe command runner ==========
run_cmd() {
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    echo "[DRY-RUN] $*"
    return 0
  fi
  if [[ "${1:-}" == "bash-c" ]]; then
    shift
    bash -c "$*"
  else
    "$@"
  fi
}

# ========== Atomic write (and cleanup tmp) ==========
write_file_safe() {
  local path="$1"; shift
  local content="$*"
  backup_file "$path"
  if [[ "${DRY_RUN:-0}" -eq 1 ]]; then
    echo "[DRY-RUN] write to $path"
    return 0
  fi
  local tmp
  tmp=$(mktemp_add) || return 1
  printf '%s\n' "$content" > "$tmp"
  install -m 0644 "$tmp" "$path" || { err "install failed for $path"; rm -f "$tmp"; _remove_temp_from_array "$tmp"; return 1; }
  rm -f "$tmp"
  _remove_temp_from_array "$tmp"
  ok "Wrote: $path"
}

# ========== Rollback registration (concurrent-safe using flock) ==========
register_rollback_step() {
  local cmd="$*"
  mkdir -p "$(dirname "$ROLLBACK_SCRIPT")"

  if [[ ! -f "$ROLLBACK_SCRIPT" ]]; then
    printf '#!/usr/bin/env bash\nset -euo pipefail\n\n' > "$ROLLBACK_SCRIPT"
    chmod 700 "$ROLLBACK_SCRIPT"
  fi

  local lockfile="${ROLLBACK_SCRIPT}.lock"
  exec 9>>"$lockfile" || { err "Cannot open rollback lockfile"; return 1; }
  flock -x 9
  printf '%s\n' "$cmd" >> "$ROLLBACK_SCRIPT"
  flock -u 9
  exec 9>&-
  log "Registered rollback step: $cmd"
}

# ========== Service manager (stateful) ==========
manage_service() {
  local service_name="$1" action="$2"
  if ! command -v systemctl >/dev/null 2>&1; then
    warn "systemctl not found, skipping service management for ${service_name}"
    return 0
  fi

  if ! systemctl list-unit-files --type=service | awk '{print $1}' | grep -q -x "${service_name}.service"; then
    log "Service ${service_name} not present, skipping"
    return 0
  fi

  ORIGINAL_SERVICE_STATES["$service_name"]=$(systemctl is-enabled --quiet "$service_name" && echo "enabled" || echo "disabled")
  ORIGINAL_SERVICE_ACTIVE["$service_name"]=$(systemctl is-active --quiet "$service_name" && echo "active" || echo "inactive")

  log "Action: ${action} on ${service_name} (Original: ${ORIGINAL_SERVICE_STATES[$service_name]}, ${ORIGINAL_SERVICE_ACTIVE[$service_name]})"
  run_cmd systemctl "$action" --now "$service_name" || true

  if [[ "${ORIGINAL_SERVICE_STATES[$service_name]}" == "enabled" ]]; then
    register_rollback_step "systemctl enable '$service_name' || true"
  fi
  if [[ "${ORIGINAL_SERVICE_ACTIVE[$service_name]}" == "active" ]]; then
    register_rollback_step "systemctl start '$service_name' || true"
  fi
}

# ========== Generate hex mask (safe for arbitrary CPU count) ==========
generate_hex_mask() {
  local cpu_count=$1
  if [[ -z "$cpu_count" || "$cpu_count" -le 0 ]]; then
    echo "00"
    return
  fi
  local num_bytes=$(( (cpu_count + 7) / 8 ))
  local -a bytes
  local cpu byte_index bit
  for ((i=0;i<num_bytes;i++)); do bytes[i]=0; done
  for ((cpu=0; cpu<cpu_count; cpu++)); do
    byte_index=$(( cpu / 8 ))
    bit=$(( cpu % 8 ))
    bytes[byte_index]=$(( bytes[byte_index] | (1 << bit) ))
  done
  local out=""
  for ((i=0;i<num_bytes;i++)); do out+=$(printf "%02x," "${bytes[i]}"); done
  echo "${out%,}"
}

# ========== RTT detection (multi-strategy, includes curl fallback) ==========
detect_best_rtt() {
  local rtt target rtt_s
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    target=$(echo "$SSH_CONNECTION" | awk '{print $1}')
    if rtt=$(ping -c 3 -W 2 "$target" 2>/dev/null | awk -F'/' '/rtt/ {print $5}'); then
      [[ -n "$rtt" ]] && printf "%.0f" "$rtt" && return
    fi
  fi

  target=$(ip route | awk '/default/ {print $3; exit}')
  if [[ -n "$target" ]]; then
    if rtt=$(ping -c 3 -W 2 "$target" 2>/dev/null | awk -F'/' '/rtt/ {print $5}'); then
      [[ -n "$rtt" ]] && printf "%.0f" "$rtt" && return
    fi
  fi

  if rtt=$(ping -c 3 -W 2 1.1.1.1 2>/dev/null | awk -F'/' '/rtt/ {print $5}'); then
    [[ -n "$rtt" ]] && printf "%.0f" "$rtt" && return
  fi

  if command -v curl >/dev/null 2>&1; then
    rtt_s=$(curl -s -o /dev/null -w '%{time_connect}' --connect-timeout 4 https://1.1.1.1 || true)
    if [[ -n "$rtt_s" ]]; then
      awk -v s="$rtt_s" 'BEGIN{printf "%.0f", s*1000}'
      return
    fi
  fi

  echo "80"
}

# ========== Health check (safe w/o curl) ==========
health_check() {
  log "Performing post-optimization health check..."
  local errors=0

  if ! ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1; then
    if command -v curl >/dev/null 2>&1; then
      if ! curl -s --connect-timeout 3 https://1.1.1.1 >/dev/null 2>&1; then
        err "Health Check FAIL: Network connectivity lost (curl check)."
        ((errors++))
      fi
    else
      err "Health Check FAIL: ICMP failed and curl not available to test TCP."
      ((errors++))
    fi
  fi

  if [[ $errors -gt 0 ]]; then
    err "Health check failed with $errors error(s). Execute rollback script immediately: $ROLLBACK_SCRIPT"
    return 1
  fi

  ok "Health check passed."
  return 0
}

# ========== Hooks runner (safe iteration) ==========
run_hooks() {
  local hook_name="$1"
  local hook_dir="/etc/ultimate_optimizer/hooks.d"
  if [[ -d "${hook_dir}/${hook_name}" ]]; then
    log "Executing ${hook_name} hooks..."
    run-parts --list "${hook_dir}/${hook_name}" 2>/dev/null | while read -r script; do
      [[ -x "$script" ]] || continue
      log " -> Running ${script}"
      run_cmd "$script"
    done
  fi
}

# ========== Detection & Calculations ==========
detect_environment_and_workload() {
  [[ -f /etc/os-release ]] && source /etc/os-release || true
  OS_ID="${ID:-unknown}"
  CPU_COUNT=$(nproc 2>/dev/null || echo 1)
  TOTAL_MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 1024)
  PRIMARY_NIC=$(ip route | awk '/default/ {print $5; exit}' || echo eth0)
  LINK_SPEED_MBPS=$(cat "/sys/class/net/${PRIMARY_NIC}/speed" 2>/dev/null || echo 1000)
  VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo none)
  local ip_forward
  ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 0)
  local has_nat=false
  command -v iptables-save &>/dev/null && iptables-save 2>/dev/null | grep -qE "(MASQUERADE|SNAT)" && has_nat=true

  if [[ "$ip_forward" -eq 1 || "$has_nat" == true ]]; then
    ROLE="nat"
  elif [[ "$VIRT_TYPE" == "none" && -e /dev/kvm ]]; then
    ROLE="host"
  else
    ROLE="guest"
  fi

  HAS_NUMA=$([[ -d /sys/devices/system/node/node1 ]] && echo true || echo false)
  HAS_NGINX=$(pgrep -x nginx &>/dev/null && echo true || echo false)
  HAS_MYSQL=$(( pgrep -x mysqld >/dev/null 2>&1 || pgrep -x mariadbd >/dev/null 2>&1 ) && echo true || echo false)
  HAS_REDIS=$(pgrep -x redis-server &>/dev/null && echo true || echo false)

  log "Detection: Role=${ROLE}, NIC=${PRIMARY_NIC}(${LINK_SPEED_MBPS}Mbps), NUMA=${HAS_NUMA}, Nginx=${HAS_NGINX}, MySQL=${HAS_MYSQL}, Redis=${HAS_REDIS}"
}

calculate_bdp_and_tcp() {
  RTT_MS=$(detect_best_rtt)
  local bdp_bytes=$(( LINK_SPEED_MBPS * 125 * RTT_MS ))
  local suggested_buffer=$(( bdp_bytes * 2 ))
  local mem_limit=$(( TOTAL_MEM_MB * 1024 * 3 / 100 ))
  local cap_128mb=$(( 128 * 1024 * 1024 ))
  [[ $suggested_buffer -gt $mem_limit ]] && suggested_buffer=$mem_limit
  [[ $suggested_buffer -gt $cap_128mb ]] && suggested_buffer=$cap_128mb
  local buffer_mb=$(( suggested_buffer / 1024 / 1024 ))
  if [[ $buffer_mb -ge 128 ]]; then buffer_mb=128
  elif [[ $buffer_mb -ge 64 ]]; then buffer_mb=64
  elif [[ $buffer_mb -ge 32 ]]; then buffer_mb=32
  else buffer_mb=16
  fi
  TCP_BUFFER_MAX=$(( buffer_mb * 1024 * 1024 ))
  TCP_DEFAULT_BUF=$(( buffer_mb >= 32 ? 262144 : 131072 ))
  ok "BDP Calc: ${LINK_SPEED_MBPS}Mbps @ ${RTT_MS}ms -> Buffer=${buffer_mb}MB"
}

# ========== Conflict handling & sysctl generation ==========
handle_conflicts() {
  local key_regex='(rmem_max|wmem_max|tcp_rmem|tcp_wmem|tcp_congestion_control|default_qdisc)'
  if [[ -f /etc/sysctl.conf ]] && grep -qE "$key_regex" /etc/sysctl.conf; then
    backup_file /etc/sysctl.conf
    register_rollback_step "cp -a '$BACKUP_DIR/sysctl.conf.bak' /etc/sysctl.conf || true"
    run_cmd bash-c "sed -i -E '/${key_regex}/s/^/#DISABLED_BY_US# /' /etc/sysctl.conf"
  fi

  for f in /etc/sysctl.d/*.conf; do
    [[ -f "$f" ]] || continue
    if grep -qE "$key_regex" "$f"; then
      local mv_dest="${f}.disabled_by_us"
      run_cmd mv "$f" "$mv_dest"
      register_rollback_step "mv '$mv_dest' '$f' || true"
    fi
  done
}

generate_sysctl() {
  local congestion="bbr"
  if command -v sysctl &>/dev/null && sysctl net.ipv4.tcp_available_congestion_control 2>/dev/null | grep -q bbr2; then
    congestion="bbr2"
  fi
  local qdisc="fq"
  local content
  content=$(cat <<EOF
# Ultimate Singularity v10.0 - Generated ${TIMESTAMP}
# Mode: $([[ "$AGGRESSIVE" -eq 1 ]] && echo "Aggressive" || echo "Conservative")

# --- Core Kernel & Memory ---
fs.file-max = 4194304
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
net.ipv4.tcp_max_syn_backlog = 16384
EOF
)
  [[ "$HAS_NGINX" == "true" ]] && content+=$'\nnet.ipv4.tcp_max_tw_buckets = 1440000'
  [[ "$HAS_REDIS" == "true" ]] && content+=$'\nvm.overcommit_memory = 1'
  [[ "$HAS_NUMA" == "true" ]] && content+=$'\nkernel.numa_balancing = 0'
  [[ "$AGGRESSIVE" -eq 1 ]] && content+=$'\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1'

  write_file_safe "$SYSCTL_TARGET" "$content"
  register_rollback_step "rm -f $SYSCTL_TARGET || true"
}

# ========== Dynamic optimizer installer ==========
install_dynamic_optimizer() {
  local script_path="/usr/local/bin/ultimate-dynamic-optimizer.sh"
  local script_content
  script_content=$(cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "generate_mask" ]]; then
  cpu_count=${2:-1}
  num_bytes=$(( (cpu_count + 7) / 8 ))
  declare -a bytes
  for ((i=0;i<num_bytes;i++)); do bytes[i]=0; done
  for ((cpu=0; cpu<cpu_count; cpu++)); do
    byte_index=$(( cpu / 8 ))
    bit=$(( cpu % 8 ))
    bytes[byte_index]=$(( bytes[byte_index] | (1 << bit) ))
  done
  out=""
  for ((i=0;i<num_bytes;i++)); do out+=$(printf "%02x," "${bytes[i]}"); done
  echo "${out%,}"
  exit 0
fi

CPU_COUNT=$(nproc 2>/dev/null || echo 1)
for NIC in $(ls /sys/class/net | grep -v lo); do
  [[ -d "/sys/class/net/$NIC" && "$(cat "/sys/class/net/$NIC/operstate" 2>/dev/null)" == "up" ]] || continue
  if command -v ethtool >/dev/null 2>&1; then
    ethtool -K "$NIC" gso on gro on tso on lro on &>/dev/null || true
  fi
  if [[ -d "/sys/class/net/$NIC/queues" ]]; then
    mask=$(/usr/local/bin/ultimate-dynamic-optimizer.sh generate_mask $CPU_COUNT)
    for q in /sys/class/net/"$NIC"/queues/rx-*; do
      [[ -f "$q/rps_cpus" ]] && echo "$mask" > "$q/rps_cpus" 2>/dev/null || true
    done
  fi
done
EOF
)

  write_file_safe "$script_path" "$script_content"
  run_cmd chmod +x "$script_path"
  # Syntax check
  if ! bash -n "$script_path"; then
    err "Dynamic optimizer script has syntax errors; aborting installation."
    register_rollback_step "rm -f $script_path || true"
    return 1
  fi
  register_rollback_step "rm -f $script_path || true"

  write_file_safe "/etc/systemd/system/ultimate-dynamic-optimizer.service" "$(cat <<'UNIT'
[Unit]
Description=Ultimate Dynamic Optimizer
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
  # Immediate trigger (safe)
  run_cmd "$script_path" || true
  register_rollback_step "systemctl disable --now ultimate-dynamic-optimizer.timer || true"
  register_rollback_step "rm -f /etc/systemd/system/ultimate-dynamic-optimizer.{service,timer} || true"
}

# ========== DNS optimization ==========
optimize_dns() {
  if [[ -L /etc/resolv.conf ]] && readlink /etc/resolv.conf | grep -q 'systemd'; then
    write_file_safe "/etc/systemd/resolved.conf.d/99-ultimate.conf" "$(cat <<'RES'
[Resolve]
DNS=1.1.1.1 8.8.8.8 9.9.9.9
Cache=yes
RES
)"
    run_cmd systemctl restart systemd-resolved || true
    register_rollback_step "rm -f /etc/systemd/resolved.conf.d/99-ultimate.conf && systemctl restart systemd-resolved || true"
  else
    backup_file /etc/resolv.conf
    write_file_safe "/etc/resolv.conf" "$(cat <<'RES'
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 9.9.9.9
options edns0 single-request-reopen
RES
)"
    register_rollback_step "cp -a '$BACKUP_DIR/resolv.conf.bak' /etc/resolv.conf || true"
  fi
}

# ========== Service cleanup (parallel, safe) ==========
cleanup_services() {
  local services_to_disable=(irqbalance tuned thermald bluetooth cups snapd unattended-upgrades)
  [[ "$ROLE" != "nat" ]] && services_to_disable+=(firewalld ufw)

  local pids=()
  local svc
  for svc in "${services_to_disable[@]}"; do
    ( manage_service "$svc" "disable" ) &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid"; done
}

# ========== GRUB optimization (robust replacement) ==========
optimize_grub() {
  [[ "$ROLE" != "host" ]] && return 0
  [[ ! -f /etc/default/grub ]] && return 0

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
  register_rollback_step "cp -a '$BACKUP_DIR/grub.bak' /etc/default/grub && update-grub || true"

  local tmp; tmp=$(mktemp_add) || return 1
  awk -v p="$params" 'BEGIN{found=0}
    /^GRUB_CMDLINE_LINUX_DEFAULT=/ { print "GRUB_CMDLINE_LINUX_DEFAULT=\"" p "\""; found=1; next }
    { print }
    END { if (!found) print "GRUB_CMDLINE_LINUX_DEFAULT=\"" p "\"" }' /etc/default/grub > "$tmp"
  run_cmd mv "$tmp" /etc/default/grub
  run_cmd bash-c "update-grub || grub2-mkconfig -o /boot/grub2/grub.cfg || true"
}

# ========== Report & rollback generation ==========
generate_report_and_rollback() {
  local report_txt
  report_txt=$(cat <<EOF
===================================================================
          Ultimate Singularity v10.0-final Optimization Report
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

--- Key Optimizations Applied ---
- TCP Congestion Control: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
- TCP Buffer: $((TCP_BUFFER_MAX / 1024 / 1024))MB (Based on ${LINK_SPEED_MBPS}Mbps @ ${RTT_MS}ms)
- GRUB: Optimized (reboot may be required)
EOF
)
  write_file_safe "$REPORT_FILE_TXT" "$report_txt"

  local report_json
  report_json=$(cat <<EOF
{
  "script_version": "${SCRIPT_VER}",
  "timestamp": "${TIMESTAMP}",
  "mode": "$([[ "$AGGRESSIVE" -eq 1 ]] && echo "Aggressive" || echo "Conservative")",
  "backup_dir": "${BACKUP_DIR}",
  "rollback_script": "${ROLLBACK_SCRIPT}",
  "system": {
    "os": "${OS_ID:-unknown}",
    "cpu_cores": ${CPU_COUNT},
    "memory_mb": ${TOTAL_MEM_MB},
    "role": "${ROLE}",
    "numa": ${HAS_NUMA}
  },
  "workloads": {
    "nginx": ${HAS_NGINX},
    "mysql": ${HAS_MYSQL},
    "redis": ${HAS_REDIS}
  },
  "optimization": {
    "tcp_congestion_control": "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")",
    "tcp_buffer_mb": $((TCP_BUFFER_MAX / 1024 / 1024)),
    "link_speed_mbps": ${LINK_SPEED_MBPS},
    "rtt_ms": ${RTT_MS}
  }
}
EOF
)
  write_file_safe "$REPORT_FILE_JSON" "$report_json"
  ok "Reports written: $REPORT_FILE_TXT and $REPORT_FILE_JSON"
}

# ========== Main ==========
main() {
  [[ "$(id -u)" -eq 0 ]] || { err "This script must be run as root."; exit 1; }
  log "Starting Ultimate Singularity v10.0-final"
  mkdir -p "$BACKUP_DIR"
  [[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"
  [[ "$DRY_RUN" -eq 1 ]] && warn "DRY-RUN mode is active. No changes will be made."
  [[ "$AGGRESSIVE" -eq 1 ]] && warn "AGGRESSIVE mode is active by default." || ok "CONSERVATIVE mode active."

  log "Stage 1: Detect environment..."
  detect_environment_and_workload

  log "Stage 2: Calculate BDP/TCP..."
  calculate_bdp_and_tcp

  run_hooks "pre-optimize"

  log "Stage 3: Resolve conflicts..."
  handle_conflicts

  log "Stage 4: Generate sysctl..."
  generate_sysctl

  log "Stage 5: Install dynamic optimizer..."
  install_dynamic_optimizer

  log "Stage 6: DNS optimization..."
  optimize_dns

  log "Stage 7: Cleanup services..."
  cleanup_services

  log "Stage 8: GRUB optimization..."
  optimize_grub

  run_hooks "post-optimize"

  log "Stage 9: Apply sysctl and health-check..."
  run_cmd sysctl --system || true
  health_check || { err "Health check failed; exiting."; exit 1; }

  log "Stage 10: Generate report and rollback..."
  generate_report_and_rollback

  ok "Optimization complete."
  ok "Report: ${REPORT_FILE_TXT}; Rollback: ${ROLLBACK_SCRIPT}"
  [[ "$ROLE" == "host" ]] && warn "Reboot may be required for GRUB changes to fully apply."
}

# Run
main
