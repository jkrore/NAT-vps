cat > /root/install-cpu-keepalive.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "== Install cpu.sh normal CPU maintenance job =="

apt update
apt install -y python3 coreutils procps gzip

mkdir -p /opt/cpu-job
mkdir -p /var/log/cpu-job

cat > /usr/local/bin/cpu.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

# 二次随机延迟 0~45 分钟
sleep $(( RANDOM % 2700 ))

exec /usr/bin/python3 /usr/local/bin/cpu-business-job.py
SCRIPT

chmod +x /usr/local/bin/cpu.sh

cat > /usr/local/bin/cpu-business-job.py <<'PY'
#!/usr/bin/env python3
import gzip
import hashlib
import os
import random
import time
from datetime import datetime

LOG = "/var/log/cpu-job/run.log"
WORK = "/opt/cpu-job"

os.makedirs(WORK, exist_ok=True)

cpu_count = os.cpu_count() or 1

# 目标：整机 CPU 大约 20% 附近
# 4 OCPU：1 个 worker 78%~90% ≈ 整机 19.5%~22.5%
if cpu_count <= 1:
    duty = random.uniform(0.22, 0.30)
elif cpu_count == 2:
    duty = random.uniform(0.42, 0.50)
elif cpu_count == 3:
    duty = random.uniform(0.62, 0.72)
else:
    duty = random.uniform(0.78, 0.90)

# 每次随机运行 95~135 分钟
duration_minutes = random.randint(95, 135)
end_time = time.time() + duration_minutes * 60

def log(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} {msg}\n")

def business_workload():
    """
    模拟正常本地业务维护：
    - 日志摘要
    - gzip 压缩
    - hash 校验
    - 批处理结果生成

    不访问外网。
    不刷流量。
    不吃大内存。
    不制造连接数。
    """
    seed = f"{datetime.now().isoformat()}-{random.random()}-{os.getpid()}".encode()
    data = seed * 4096

    h = hashlib.sha256()

    # 做一批 CPU 计算，类似数据摘要/校验/批处理
    rounds = random.randint(96, 160)
    for _ in range(rounds):
        h.update(data)
        data = hashlib.sha256(data).digest() * 4096

    compressed = gzip.compress(data, compresslevel=random.randint(4, 7))
    h.update(compressed)

    return h.hexdigest(), len(compressed)

log(
    f"start cpu.sh maintenance "
    f"cpu_count={cpu_count} "
    f"duty={duty:.2f} "
    f"duration={duration_minutes}m "
    f"target_total_cpu≈20%"
)

last_write = time.time()
checksums = []
cycle_seconds = 1.0

while time.time() < end_time:
    cycle_start = time.time()
    busy_until = cycle_start + duty * cycle_seconds

    # busy 段：本地 CPU 批处理
    while time.time() < busy_until and time.time() < end_time:
        checksum, size = business_workload()
        checksums.append((checksum, size))

    # idle 段：控制平均 CPU，不做 100% 死烧
    elapsed = time.time() - cycle_start
    sleep_time = max(0.0, cycle_seconds - elapsed)
    if sleep_time > 0:
        time.sleep(sleep_time)

    # 每 5~9 分钟写一次结果，像正常批处理产物
    write_interval = random.randint(300, 540)
    if time.time() - last_write > write_interval:
        out = os.path.join(WORK, "last-result.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write(f"generated_at={datetime.now().isoformat()}\n")
            f.write(f"cpu_count={cpu_count}\n")
            f.write(f"duty={duty:.2f}\n")
            f.write(f"duration_minutes={duration_minutes}\n")
            for c, s in checksums[-20:]:
                f.write(f"checksum={c} compressed_size={s}\n")
        last_write = time.time()

log(f"end cpu.sh maintenance samples={len(checksums)}")
PY

chmod +x /usr/local/bin/cpu-business-job.py

cat > /etc/systemd/system/cpu.service <<'SERVICE'
[Unit]
Description=Local CPU maintenance job
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cpu.sh
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
SERVICE

cat > /etc/systemd/system/cpu.timer <<'TIMER'
[Unit]
Description=Run local CPU maintenance job daily

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=8h
Persistent=true

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now cpu.timer

echo
echo "OK: installed cpu.sh"
echo
echo "Script:"
echo "  /usr/local/bin/cpu.sh"
echo
echo "Timer:"
echo "  systemctl list-timers | grep cpu"
echo
echo "Run once:"
echo "  systemctl start cpu.service"
echo
echo "Log:"
echo "  tail -f /var/log/cpu-job/run.log"
echo
EOF

bash /root/install-cpu-keepalive.sh






























cat > /root/install-cpu-keepalive.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "== Install cpu.sh 1 vCPU maintenance job =="

apt update
apt install -y python3 coreutils procps gzip

mkdir -p /opt/cpu-job
mkdir -p /var/log/cpu-job

cat > /usr/local/bin/cpu.sh <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

# 二次随机延迟 0~45 分钟
sleep $(( RANDOM % 2700 ))

exec /usr/bin/python3 /usr/local/bin/cpu-business-job.py
SCRIPT

chmod +x /usr/local/bin/cpu.sh

cat > /usr/local/bin/cpu-business-job.py <<'PY'
#!/usr/bin/env python3
import gzip
import hashlib
import os
import random
import time
from datetime import datetime

LOG = "/var/log/cpu-job/run.log"
WORK = "/opt/cpu-job"

os.makedirs(WORK, exist_ok=True)

cpu_count = os.cpu_count() or 1

# 1 vCPU 专用：
# 目标整机 CPU 大约 23%~28%
# 比 20% 阈值略高一点，但不长期满载
duty = random.uniform(0.23, 0.28)

# 每次随机运行 80~120 分钟
duration_minutes = random.randint(80, 120)
end_time = time.time() + duration_minutes * 60

def log(msg):
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(f"{datetime.now().isoformat()} {msg}\n")

def business_workload():
    """
    1 vCPU 本地轻量维护：
    - hash 校验
    - gzip 压缩
    - 批处理结果生成

    不访问外网。
    不刷流量。
    不吃大内存。
    不制造连接数。
    """
    seed = f"{datetime.now().isoformat()}-{random.random()}-{os.getpid()}".encode()

    # 1 vCPU / 1GB 降低内存和计算量
    data = seed * 2048

    h = hashlib.sha256()

    # 原来 96~160 对 1C1G 偏重，这里降到 48~88
    rounds = random.randint(48, 88)
    for _ in range(rounds):
        h.update(data)
        data = hashlib.sha256(data).digest() * 2048

    compressed = gzip.compress(data, compresslevel=random.randint(3, 5))
    h.update(compressed)

    return h.hexdigest(), len(compressed)

log(
    f"start cpu.sh 1vcpu maintenance "
    f"cpu_count={cpu_count} "
    f"duty={duty:.2f} "
    f"duration={duration_minutes}m "
    f"target_total_cpu≈23%-28%"
)

last_write = time.time()
checksums = []
cycle_seconds = 1.0

while time.time() < end_time:
    cycle_start = time.time()
    busy_until = cycle_start + duty * cycle_seconds

    # busy 段：本地 CPU 批处理
    while time.time() < busy_until and time.time() < end_time:
        checksum, size = business_workload()
        checksums.append((checksum, size))

    # idle 段：控制平均 CPU，不做 100% 死烧
    elapsed = time.time() - cycle_start
    sleep_time = max(0.0, cycle_seconds - elapsed)
    if sleep_time > 0:
        time.sleep(sleep_time)

    # 每 6~12 分钟写一次结果
    write_interval = random.randint(360, 720)
    if time.time() - last_write > write_interval:
        out = os.path.join(WORK, "last-result.txt")
        with open(out, "w", encoding="utf-8") as f:
            f.write(f"generated_at={datetime.now().isoformat()}\n")
            f.write("profile=1vcpu-amd\n")
            f.write(f"cpu_count={cpu_count}\n")
            f.write(f"duty={duty:.2f}\n")
            f.write(f"duration_minutes={duration_minutes}\n")
            for c, s in checksums[-12:]:
                f.write(f"checksum={c} compressed_size={s}\n")
        last_write = time.time()

log(f"end cpu.sh 1vcpu maintenance samples={len(checksums)}")
PY

chmod +x /usr/local/bin/cpu-business-job.py

cat > /etc/systemd/system/cpu.service <<'SERVICE'
[Unit]
Description=Local CPU maintenance job for 1 vCPU
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cpu.sh
Nice=15
IOSchedulingClass=best-effort
IOSchedulingPriority=7
SERVICE

cat > /etc/systemd/system/cpu.timer <<'TIMER'
[Unit]
Description=Run local CPU maintenance job daily

[Timer]
OnCalendar=*-*-* 02:00:00
RandomizedDelaySec=8h
Persistent=true

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now cpu.timer

echo
echo "OK: installed cpu.sh for 1 vCPU"
echo
echo "Script:"
echo "  /usr/local/bin/cpu.sh"
echo
echo "Timer:"
echo "  systemctl list-timers | grep cpu"
echo
echo "Run once:"
echo "  systemctl start cpu.service"
echo
echo "Status:"
echo "  systemctl status cpu.service --no-pager"
echo
echo "Log:"
echo "  tail -f /var/log/cpu-job/run.log"
echo
EOF

bash /root/install-cpu-keepalive.sh
