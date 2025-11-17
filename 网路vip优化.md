# NAT-vps 性能终极优化脚本集
本项目提供了一套针对 Debian 12/13 系统的网络性能优化脚本，旨在最大化 NAT VPS 或独立服务器的网络吞吐能力和响应速度。
curl -sL https://raw.githubusercontent.com/jkrore/NAT-vps/main/vip0.sh | bash -s --  --apply --apply-io-limits  --apply-cpu-tuning --apply-memory-tuning --cleanup-services --apply-host-specifics --apply-zram --apply-fstab --apply-basics --apply-hardening
