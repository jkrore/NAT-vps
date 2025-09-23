Of course, here is the MD file for the provided script.

---

# NAT-vps/vps3.sh

This is a comprehensive network and system optimization script for Linux servers, particularly those acting as NAT gateways or high-performance VPS. It automatically detects system parameters, calculates optimal buffer sizes based on BDP (Bandwidth-Delay Product), 和 applies a wide range of `sysctl`, network interface, 和 CPU optimizations.

## Features

- **Automatic System Detection**: Detects total memory, CPU cores, 和 network RTT to tailor optimizations.
- **BDP-Based Tuning**: Calculates the Bandwidth-Delay Product to set optimal TCP buffer sizes, capped at a safe memory footprint.
- **Safe Apply/Rollback**: Runs in `--dry-run` mode by default. When applying, it creates timestamped backups and a rollback script.
- **Conflict Resolution**: Automatically backs up and comments out/disables conflicting settings in `/etc/sysctl.conf` 和 `/etc/sysctl.d/`。
- **Comprehensive `sysctl` Tuning**:
    - Enables BBR congestion control with FQ packet scheduling.
    - Optimizes TCP/UDP memory buffers (`rmem`, `wmem`).
    - Adjusts core networking and virtual memory settings for high throughput.
- **Network Interface Card (NIC) Optimization**:
    - Enables hardware offloading features (TSO, GSO, GRO, etc.) via `ethtool`.
    - Configures Receive Packet Steering (RPS) and Transmit Packet Steering (XPS) to distribute network processing across CPU cores.
    - Attempts to distribute NIC IRQ interrupts across CPU cores.
- **CPU Optimization**:
    - Sets the CPU governor to `performance` mode for maximum clock speed.
    - Creates a dedicated `cpuset` cgroup for network-optimized processes.
- **DNS Optimization**: Configures the system to use fast and reliable public DNS servers (Cloudflare, Google) and enables local caching via `systemd-resolved` if available.
- **Modes of Operation**:
    - **`normal`**: A safe and effective set of optimizations.
    - **`aggressive`**: Includes more advanced and potentially risky optimizations, such as disabling CPU speculative execution mitigations via GRUB for maximum performance.
- **Hooks & Utilities**:
    - **`--iperf`**: Run an `iperf3` test against specified servers to measure bandwidth.
    - **`--install-service`**: (Not fully implemented in this version) Intended to install a systemd service for periodic re-tuning.
    - **OCSP Helper**: Includes a function to fetch and store OCSP responses for a given domain, useful for web servers like Nginx.
- **Runtime Adaptive Tuning**: A monitoring function that checks network traffic and TCP retransmission rates, making minor adjustments to buffer sizes on the fly.

## Usage

### Prerequisites

- The script must be run as **root**。
- Required commands: `ping`， `awk`, `ip`, `sysctl`.
- Recommended commands for full functionality: `ethtool`， `cpupower`， `iperf3`， `jq`， `resolvectl`.

### Basic Commands

**1. Dry Run (Preview changes)**
This is the default and safest mode. It will show you all the actions it *would* take without actually modifying your system.

```bash
sudo ./vps3.sh --dry-run --mode normal
```

**2. Apply Changes**
To write the changes to your system, use the `--apply` flag. The script will create a backup directory in `/var/backups/net-optimizer/`.

```bash
sudo ./vps3.sh --apply --mode normal
```

**3. Aggressive Mode**
For maximum performance, at the cost of reduced security (disables CPU mitigations). **Use with caution.**

```bash
sudo ./vps3.sh --apply --mode aggressive
```

**4. Forcing RTT**
If the automatic RTT detection is inaccurate (e.g., you are connecting from a very low-latency location), you can manually specify it.

```bash
sudo ./vps3.sh --apply --rtt 120  # Force RTT to 120ms
```

**5. Rollback**
To undo the changes, use the `--rollback` flag with the backup directory created during a previous `--apply` run.

```bash
# First, find your backup directory
ls /var/backups/net-optimizer/

# Then, run the rollback
sudo ./vps3.sh --apply --rollback /var/backups/net-optimizer/net-optimizer-2025-09-23-052100
```
*Note: The `--apply` flag is required to confirm the execution of the rollback script.*

### All Command-Line Options

| Flag | Argument | Description |
| :--- | :--- | :--- |
| `--dry-run` | | Preview changes without applying them (default). |
| `--apply` | | Apply the changes to the system. |
| `--mode` | `normal`\|`aggressive` | Set the optimization level. `normal` is default. |
| `--rtt` | `<ms>` | Manually override the detected network RTT in milliseconds. |
| `--iperf` | `<ip1,ip2,...>` | Run an `iperf3` test against the specified comma-separated servers. |
| `--install-service` | | (Future use) Install a systemd service for periodic tuning. |
| `--rollback` | `<backupdir>` | Revert changes using the specified backup directory. |
| `-q`, `--quiet` | | Reduce the amount of informational output. |
| `-h`, `--help` | | Display the help message. |

## How It Works

1.  **Parsing Arguments**: The script first reads the command-line flags (`--apply`, `--mode`, etc.).
2.  **Environment Detection**:
    *   It determines the total system memory and number of CPU cores.
    *   It attempts to detect the network RTT by pinging the SSH client's IP address. If that fails, it falls back to pinging `1.1.1.1`.
3.  **BDP Calculation**:
    *   It calculates the BDP (`Bandwidth * RTT`) to determine the theoretical maximum amount of data "in flight".
    *   It caps this value to a safe limit (e.g., 3% of total RAM or 64MB, whichever is smaller) to prevent excessive memory consumption. This result determines the maximum TCP read/write buffer sizes.
4.  **Backups & Conflict Cleaning**:
    *   A unique backup directory is created under `/var/backups/net-optimizer/`.
    *   It scans `/etc/sysctl.conf` and files in `/etc/sysctl.d/` for settings that it is about to change.
    *   Conflicting settings are commented out or the entire file is renamed with a `.disabled_by_optimizer` suffix. The original files are backed up.
5.  **Applying Optimizations**:
    *   **Sysctl**: A new configuration file is written to `/etc/sysctl.d/999-net-optimizer.conf` with optimized values and applied with `sysctl --system`.
    * **NIC Tuning**: It iterates through all active network interfaces (excluding `lo`, `docker`, etc.) and applies `ethtool`, RPS/XPS, 和 IRQ affinity settings.
    *   **CPU**: It sets the CPU governor to `performance`.
    *   **Qdisc**: It sets the default packet scheduler on the main network interface to `fq` (or `cake` in aggressive mode).
    *   **DNS**: It updates the system's DNS resolver settings.
6.  **Finalization**: A summary of the applied settings is displayed, along with the path to the backup directory and the rollback script.  
