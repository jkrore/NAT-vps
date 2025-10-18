#!/bin/bash
set -e

# =================================================================
#  Debian 13 "Golden Prep-Script" for Ultimate Network Optimization
#  在运行任何主优化脚本之前，请先执行此脚本
# =================================================================

echo "--- [步骤 1/4] 正在更新并验证 Debian 官方软件源... ---"
apt-get update -y
apt-get upgrade -y

echo "--- [步骤 2/4] 正在安装所有必需的依赖工具... ---"
# 这里包含了主脚本中所有可能用到的外部命令
apt-get install -y \
    curl \
    gnupg \
    ethtool \
    clang \
    iperf3 \
    bc \
    lsb-release \
    ca-certificates \
    --no-install-recommends

echo "--- [步骤 3/4] 正在预先配置并验证 XanMod 高性能内核软件源... ---"
# 下载并安装GPG密钥
curl -fsSL https://dl.xanmod.org/archive.key | gpg --dearmor -o /usr/share/keyrings/xanmod-archive-keyring.gpg

# 创建软件源配置文件
echo 'deb [signed-by=/usr/share/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org releases main' | tee /etc/apt/sources.list.d/xanmod.list

# 强制更新软件列表以包含XanMod，并检查是否成功
echo "--- 正在验证 XanMod 软件源是否可用... ---"
apt-get update -y

# 检查是否能搜索到 XanMod 内核包，作为最终验证
if apt-cache search linux-xanmod | grep -q 'linux-xanmod'; then
    echo "--- XanMod 软件源验证成功！ ---"
else
    echo "--- [警告] 未能从软件源中找到 XanMod 内核包，后续安装可能会失败。 ---"
fi

echo "--- [步骤 4/4] 正在清理系统缓存... ---"
apt-get autoremove -y
apt-get clean

echo ""
echo "================================================================="
echo " ✅  黄金准备脚本执行完毕！"
echo "     您的系统现在已拥有一个干净、完整且配置正确的环境。"
echo "     接下来，您可以安全地运行您的主网络优化脚本了。"
echo "================================================================="

