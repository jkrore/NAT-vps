#!/bin/bash
# 验证 sysctl 优化是否生效 + 压测对比
# 用法： ./verify_optimization.sh before|after

BENCH_SCRIPT="./ultimate-bench.sh"
RESULT_DIR="./verify_results"
KEY_PARAMS=(
  "net.core.rmem_max"
  "net.core.wmem_max"
  "net.ipv4.tcp_fin_timeout"
  "net.ipv4.tcp_tw_reuse"
  "vm.swappiness"
  "fs.file-max"
)

mkdir -p $RESULT_DIR

if [ "$1" != "before" ] && [ "$1" != "after" ]; then
  echo "用法: $0 before|after"
  exit 1
fi

STAMP=$(date +%Y%m%d_%H%M%S)
SYSCTL_FILE="$RESULT_DIR/sysctl_$1_$STAMP.txt"
BENCH_FILE="$RESULT_DIR/bench_$1_$STAMP.txt"

echo "=== 导出 sysctl 参数 ==="
for key in "${KEY_PARAMS[@]}"; do
  echo "$key = $(sysctl -n $key)" >> $SYSCTL_FILE
done

echo "sysctl 参数已保存到: $SYSCTL_FILE"

if [ -x "$BENCH_SCRIPT" ]; then
  echo "=== 运行基准测试: $BENCH_SCRIPT ==="
  bash $BENCH_SCRIPT > $BENCH_FILE 2>&1
  echo "性能结果保存到: $BENCH_FILE"
else
  echo "未找到 $BENCH_SCRIPT, 跳过性能测试"
fi

echo "✅ [$1] 阶段结果采集完成"
