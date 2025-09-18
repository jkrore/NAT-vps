#!/bin/bash
# vps1.sh - 验证优化效果脚本
# 用法: ./vps1.sh before | ./vps1.sh after

set -e

if [ -z "$1" ]; then
  echo "用法: $0 before|after"
  exit 1
fi

TAG=$1
TS=$(date +"%Y%m%d_%H%M%S")
OUTDIR="/root/verify_results"
mkdir -p $OUTDIR

echo ">>> [$TAG] 开始采集验证数据..."

# 1. 采集 sysctl 关键参数
SYSCTL_KEYS=(
  "net.core.somaxconn"
  "net.ipv4.tcp_fin_timeout"
  "net.ipv4.tcp_tw_reuse"
  "net.ipv4.tcp_max_syn_backlog"
  "net.ipv4.tcp_keepalive_time"
  "fs.file-max"
  "vm.swappiness"
)

SYS_FILE="$OUTDIR/sysctl_${TAG}_${TS}.txt"
echo "# sysctl dump ($TAG)" > $SYS_FILE
for key in "${SYSCTL_KEYS[@]}"; do
  val=$(sysctl -n $key 2>/dev/null || echo "N/A")
  echo "$key = $val" >> $SYS_FILE
done
echo "✔ sysctl 关键参数已保存: $SYS_FILE"

# 2. 性能基准测试（调用 ultimate-bench.sh，如果存在）
BENCH_FILE="$OUTDIR/bench_${TAG}_${TS}.txt"
if command -v ultimate-bench.sh >/dev/null 2>&1 || [ -f "/usr/local/bin/ultimate-bench.sh" ]; then
  echo "# benchmark ($TAG)" > $BENCH_FILE
  /usr/local/bin/ultimate-bench.sh >> $BENCH_FILE 2>&1 || true
  echo "✔ 性能基准已保存: $BENCH_FILE"
else
  echo "⚠ 未找到 ultimate-bench.sh，跳过性能测试"
fi

echo ">>> [$TAG] 采集完成！结果保存在: $OUTDIR"
