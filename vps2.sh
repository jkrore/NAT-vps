#!/usr/bin/env bash
# proxy-config-final.sh — 智能代理配置（最终版）
#
# 用法示例：
#   sudo ./proxy-config-final.sh --force-client-cdn --cdn-ip "104.21.48.162,1.1.1.1" --concurrency 12
#
set -euo pipefail
IFS=$'\n\t'

# ------------------------
# 配置（可通过 CLI 覆盖）
# ------------------------
CURRENT_DIR="/root/proxy-config"
SINGBOX_BIN="/usr/local/bin/sing-box"
XRAY_BIN="/usr/local/bin/xray"
SERVER_IP=""
FORCE_CLIENT_CDN="no"
CDN_USER_SPEC=""    # 可为 "ip1,ip2,ip3"
CONCURRENCY=8
DRY_RUN="no"
SKIP_INSTALL="no"
TMPDIR="$(mktemp -d -t proxycfg.XXXXXX)"
NODES_JSON="$TMPDIR/nodes.jsonl"
CLIENT_VPS="$CURRENT_DIR/client_nodes_vps.txt"
CLIENT_CDN="$CURRENT_DIR/client_nodes_cdn.txt"
LOGFILE="$CURRENT_DIR/proxy-config.log"
USER_AGENT="proxy-config-final/1.0"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log(){ echo -e "${GREEN}[$(date +'%H:%M:%S')] $*${NC}" | tee -a "$LOGFILE"; }
warn(){ echo -e "${YELLOW}[$(date +'%H:%M:%S')] $*${NC}" | tee -a "$LOGFILE"; }
err(){ echo -e "${RED}[$(date +'%H:%M:%S')] $*${NC}" | tee -a "$LOGFILE"; }

cleanup(){ rm -rf "$TMPDIR"; }
trap cleanup EXIT INT TERM

usage(){
  cat <<EOF
Usage: $0 [options]
Options:
  --force-client-cdn         强制客户端使用 CDN -> VPS -> 节点（默认不强制）
  --cdn-ip IP[,IP...]        指定优选 CDN IP 列表（逗号分隔），脚本会为每个节点择优选可用的 CDN IP
  --concurrency N            连通性检测并发数（默认 $CONCURRENCY）
  --dry-run                  只生成文件，不安装/启动服务
  --skip-install             跳过下载/安装 sing-box & xray
  --help                     显示本帮助
EOF
  exit 1
}

# 解析 CLI
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force-client-cdn) FORCE_CLIENT_CDN="yes"; shift ;;
    --cdn-ip) CDN_USER_SPEC="$2"; shift 2 ;;
    --concurrency) CONCURRENCY="$2"; shift 2 ;;
    --dry-run) DRY_RUN="yes"; shift ;;
    --skip-install) SKIP_INSTALL="yes"; shift ;;
    --help) usage ;;
    *) warn "未知参数: $1"; usage ;;
  esac
done

ensure_root(){
  if [[ $EUID -ne 0 ]]; then err "请以 root 运行此脚本"; exit 1; fi
  mkdir -p "$CURRENT_DIR" "$TMPDIR"
  touch "$LOGFILE"
}

install_deps(){
  log "检查/安装依赖：curl wget jq unzip tar openssl coreutils ca-certificates"
  if command -v apt >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl wget jq unzip tar openssl coreutils ca-certificates iproute2 >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget jq unzip tar openssl coreutils ca-certificates iproute >/dev/null 2>&1 || true
  fi
  command -v jq >/dev/null 2>&1 || { warn "安装 jq"; curl -fsSL -o /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64; chmod +x /usr/local/bin/jq; }
}

get_server_ip(){
  SERVER_IP=$(curl -s --connect-timeout 6 -A "$USER_AGENT" ipv4.icanhazip.com || curl -s --connect-timeout 6 -A "$USER_AGENT" ifconfig.me || true)
  if [[ -z "$SERVER_IP" ]]; then err "无法获取公网 IP"; exit 1; fi
  log "服务器公网 IP: $SERVER_IP"
}

is_ip(){ [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# 处理 base64 urlsafe + padding
decode_b64_urlsafe(){
  local s="$1"
  s="${s//_/\/}"; s="${s//-/+}"
  local mod=$(( ${#s} % 4 ))
  if [[ $mod -ne 0 ]]; then s="${s}$(printf '=%.0s' $(seq $((4-mod))))"; fi
  echo -n "$s" | base64 -d 2>/dev/null || echo ""
}

# 尝试从多个来源获取一个可能的 CDN IP（保留原有两个来源作为备选）
get_auto_cdn_candidates(){
  local out=()
  local urls=( "https://ip.164746.xyz/ipTop.html" "https://stock.hostmonit.com/CloudFlareYes" "https://api.ipify.org" )
  for s in "${urls[@]}"; do
    ip=$(curl -fsS --connect-timeout 6 -A "$USER_AGENT" "$s" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -n "$ip" ]]; then out+=("$ip"); fi
  done
  # 追加一个常用 cloudflare 任意 IP 作为兜底（可替换）
  out+=("104.21.48.162")
  # 去重
  printf '%s\n' "${out[@]}" | awk '!seen[$0]++' | paste -sd, -
}

# 测试主机端口是否可连（先 /dev/tcp，再 openssl s_client）
test_connectivity(){
  local host="$1"; local port="$2"; local sni="$3"
  # 若 host 是本机的 IP，视作可达
  if [[ "$host" == "$SERVER_IP" ]]; then return 0; fi
  # /dev/tcp 方法
  if timeout 3 bash -c "cat < /dev/tcp/${host}/${port} >/dev/null 2>&1"; then return 0; fi
  # 使用 curl 尝试（http/https 不确定但有时能通）
  if command -v curl >/dev/null 2>&1; then
    if timeout 4 curl -s --connect-timeout 3 --max-time 5 --resolve "${sni}:${port}:${host}" "https://${sni:-$host}:${port}/" >/dev/null 2>&1; then return 0; fi
  fi
  # openssl s_client fallback（对 TLS 服务有用）
  if command -v openssl >/dev/null 2>&1; then
    if timeout 6 openssl s_client -servername "${sni:-$host}" -connect "${host}:${port}" < /dev/null >/dev/null 2>&1; then return 0; fi
  fi
  return 1
}

# 为单个 vmess 链接生成 CDN 回落版（修改 add -> cdn_ip 并把 host 字段保留为原域名）
modify_vmess_for_cdn(){
  local link="$1"; local cdn="$2"
  local b64=${link#vmess://}
  local json=$(decode_b64_urlsafe "$b64")
  if [[ -z "$json" ]]; then echo "$link"; return; fi
  local add=$(echo "$json" | jq -r '.add // empty' || true)
  if [[ -n "$add" && -n "$cdn" ]]; then
    newjson=$(echo "$json" | jq --arg cdn "$cdn" --arg orighost "$add" '.add=$cdn | .host=(.host // $orighost)')
    local nb64=$(echo -n "$newjson" | base64 | tr -d '\n')
    echo "vmess://${nb64}"
  else
    echo "$link"
  fi
}

# 解析用户逐行粘入的节点（空行结束），写成每行 JSON 到 $NODES_JSON
parse_input_nodes(){
  > "$NODES_JSON"
  echo
  echo -e "${CYAN}请逐行粘入原始节点（vless/vmess/trojan/ss/hysteria2/tuic），空行结束：${NC}"
  while IFS= read -r line; do
    [[ -z "$line" ]] && break
    # 预处理 anytls:// -> vless://
    if [[ $line == anytls://* ]]; then line="vless://${line#anytls://}"; fi

    if [[ $line == vless://* ]]; then
      orig_host=$(echo "$line" | sed -n 's/.*@\([^:\/?#]*\):\([0-9]*\).*/\1/p' || true)
      orig_port=$(echo "$line" | sed -n 's/.*@\([^:\/?#]*\):\([0-9]*\).*/\2/p' || true)
      jq -n --arg proto "vless" --arg orig_host "$orig_host" --arg orig_port "$orig_port" --arg orig_link "$line" '{"proto":$proto,"orig_host":$orig_host,"orig_port":$orig_port,"orig_link":$orig_link,"cdn_link":"","reachable":false}' >> "$NODES_JSON"
    elif [[ $line == vmess://* ]]; then
      b64=${line#vmess://}
      json=$(decode_b64_urlsafe "$b64" || echo "")
      add=$(echo "$json" | jq -r '.add // empty' || true)
      port=$(echo "$json" | jq -r '.port // empty' || true)
      jq -n --arg proto "vmess" --arg orig_host "$add" --arg orig_port "$port" --arg orig_link "$line" '{"proto":$proto,"orig_host":$orig_host,"orig_port":$orig_port,"orig_link":$orig_link,"cdn_link":"","reachable":false}' >> "$NODES_JSON"
    elif [[ $line == trojan://* || $line == ss://* || $line == hysteria2://* || $line == tuic://* ]]; then
      proto=$(echo "$line" | sed -n 's#^\(trojan\|ss\|hysteria2\|tuic\)://.*#\1#p' || true)
      orig_host=$(echo "$line" | sed -n 's/.*@\([^:\/?#]*\):\([0-9]*\).*/\1/p' || true)
      orig_port=$(echo "$line" | sed -n 's/.*@[^:\/?#]*:\([0-9]*\).*/\1/p' || true)
      jq -n --arg proto "$proto" --arg orig_host "$orig_host" --arg orig_port "$orig_port" --arg orig_link "$line" '{"proto":$proto,"orig_host":$orig_host,"orig_port":$orig_port,"orig_link":$orig_link,"cdn_link":"","reachable":false}' >> "$NODES_JSON"
    else
      warn "跳过未知或无法解析的行：$line"
    fi
  done
  log "解析完成，写入 $NODES_JSON"
}

# 从候选 CDN 列表中为某个节点择优选能连通的 CDN IP（返回单个 IP）
choose_cdn_for_node(){
  local orig_host="$1"; local orig_port="$2"; local candidates_csv="$3"
  IFS=',' read -r -a cand <<< "$candidates_csv"
  for ip in "${cand[@]}"; do
    ip="${ip// /}"
    [[ -z "$ip" ]] && continue
    if test_connectivity "$ip" "$orig_port" "$orig_host"; then
      echo "$ip"; return
    fi
  done
  # 若没有一个能连，就返回第一个候选（可能只是占位）
  echo "${cand[0]}"
}

# 并发执行任务的简单 semaphore（大量节点时控制并发）
run_with_concurrency(){
  local i=0
  local max="$1"; shift
  while [[ $((i)) -ge 0 ]]; do
    # 清理已结束子进程，使 /proc 里可见的减少（bash 本身会自动收集）
    # 等待直到后台任务数小于 max
    while (( $(jobs -r | wc -l) >= max )); do
      sleep 0.05
    done
    # 执行命令
    ("$@") &
    return 0
  done
}

# 处理每个节点：检测可达并生成 client_vps/client_cdn
process_nodes_and_make_clients(){
  # 确定 CDN 候选
  if [[ -n "$CDN_USER_SPEC" ]]; then
    cdn_candidates="$CDN_USER_SPEC"
  else
    cdn_candidates="$(get_auto_cdn_candidates)"
  fi
  log "CDN 候选: $cdn_candidates (逗号分隔)"

  > "$CLIENT_VPS"; > "$CLIENT_CDN"
  tmpfile="$TMPDIR/nodes.out.jsonl"; > "$tmpfile"

  idx=0
  # 遍历每行 JSON（保留顺序）
  while IFS= read -r line; do
    idx=$((idx+1))
    # 把处理逻辑放到子函数以便并发
    _handle_node(){
      local line="$1"; local idx="$2"
      proto=$(echo "$line" | jq -r '.proto')
      orig_host=$(echo "$line" | jq -r '.orig_host')
      orig_port=$(echo "$line" | jq -r '.orig_port')
      orig_link=$(echo "$line" | jq -r '.orig_link')
      reachable=false
      if [[ -n "$orig_host" && -n "$orig_port" && "$orig_port" =~ ^[0-9]+$ ]]; then
        if test_connectivity "$orig_host" "$orig_port" ""; then reachable=true; fi
      fi
      cdn_link="$orig_link"
      chosen_cdn=""
      # 处理协议差异
      if [[ "$proto" == "vmess" ]]; then
        # 先为该节点选择一个 CDN IP（择优）
        chosen_cdn=$(choose_cdn_for_node "$orig_host" "$orig_port" "$cdn_candidates")
        cdn_link="$(modify_vmess_for_cdn "$orig_link" "$chosen_cdn")"
      else
        if [[ -n "$orig_host" && -n "$orig_port" ]]; then
          # 直接替 host:port
          chosen_cdn=$(choose_cdn_for_node "$orig_host" "$orig_port" "$cdn_candidates")
          cdn_link=$(echo "$orig_link" | sed "s@${orig_host}:${orig_port}@${chosen_cdn}:${orig_port}@g")
          # 如果链接里没有 sni= 且 orig_host 不是 ip 则添加 sni 参数（保持原主机名）
          if [[ "$cdn_link" != *"sni="* ]] && ! is_ip "$orig_host"; then
            if [[ "$cdn_link" == *"#"* ]]; then
              before="${cdn_link%%#*}"; after="${cdn_link#*#}"
              if [[ "$before" == *"?"* ]]; then cdn_link="${before}&sni=${orig_host}#${after}"; else cdn_link="${before}?sni=${orig_host}#${after}"; fi
            else
              if [[ "$cdn_link" == *"?"* ]]; then cdn_link="${cdn_link}&sni=${orig_host}"; else cdn_link="${cdn_link}?sni=${orig_host}"; fi
            fi
          fi
        fi
      fi

      client_vps="$orig_link"
      if [[ -n "$orig_host" && -n "$orig_port" ]]; then
        client_vps=$(echo "$orig_link" | sed "s@${orig_host}:${orig_port}@${SERVER_IP}:${orig_port}@g")
      fi

      if [[ "$FORCE_CLIENT_CDN" == "yes" ]]; then
        client_cdn="$cdn_link"
      else
        if [[ "$reachable" == true ]]; then client_cdn="$client_vps"; else client_cdn="$cdn_link"; fi
      fi

      # 输出到文件（并发写入 -> append）
      echo "$client_vps" >> "$CLIENT_VPS"
      echo "$client_cdn" >> "$CLIENT_CDN"

      # 写回增强 JSON
      echo "$line" | jq --arg cl "$cdn_link" --argjson r $([[ "$reachable" == true ]] && echo true || echo false) --arg cdn "$chosen_cdn" '. + {cdn_link:$cl,reachable:$r,chosen_cdn:$cdn}' >> "$tmpfile"

      if [[ "$reachable" == true ]]; then
        log "节点 $idx: $proto $orig_host:$orig_port -> VPS 可直连"
      else
        warn "节点 $idx: $proto $orig_host:$orig_port -> VPS 不可直连，使用 CDN 回退 ($chosen_cdn)"
      fi
    }  # end _handle_node

    # 并发启动子任务（限制并发数）
    # 用一个小 wrapper，因为 run_with_concurrency 的实现比较简单：直接后台启动并且依赖 shell 的 jobs 控制
    while (( $(jobs -r | wc -l) >= CONCURRENCY )); do sleep 0.05; done
    _handle_node "$line" "$idx" &

  done < "$NODES_JSON"

  wait
  mv -f "$tmpfile" "$NODES_JSON"
  log "生成客户端文件：VPS:$CLIENT_VPS CDN:$CLIENT_CDN"
}

# 生成 sing-box config（更安全地用 jq 构造 inbounds 数组）
generate_singbox_config(){
  log "生成 sing-box 配置..."
  cfg="$CURRENT_DIR/sing-box-config.json"
  fragdir="$TMPDIR/frags"; mkdir -p "$fragdir"
  > "$fragdir/list.txt"

  n=0
  while IFS= read -r l; do
    proto=$(echo "$l" | jq -r '.proto')
    orig_port=$(echo "$l" | jq -r '.orig_port')
    orig_link=$(echo "$l" | jq -r '.orig_link')
    case "$proto" in
      vless)
        uuid=$(echo "$orig_link" | sed -n 's#vless://\([^@]*\)@.*#\1#p' || true)
        sni=$(echo "$orig_link" | grep -oP 'sni=[^&]+' | sed 's/sni=//' || true)
        inb=$(jq -n --arg type "vless" --arg tag "vless-in-$orig_port" --arg listen "::" --argjson listen_port "$orig_port" --arg uuid "$uuid" '{
          type:$type,
          tag:$tag,
          listen:$listen,
          listen_port:$listen_port|tonumber,
          users:[{uuid:$uuid}]
        }')
        if [[ -n "$sni" ]]; then inb=$(echo "$inb" | jq --arg sni "$sni" '. + {"tls": {"enabled": true, "server_name": $sni}}'); fi
        ;;
      vmess)
        b64=$(echo "$orig_link" | sed 's#vmess://##')
        json=$(decode_b64_urlsafe "$b64" || echo "{}")
        id=$(echo "$json" | jq -r '.id // .uuid // empty' || true)
        inb=$(jq -n --arg type "vmess" --arg tag "vmess-in-$orig_port" --arg listen "::" --argjson listen_port "$orig_port" --arg id "$id" '{
          type:$type,
          tag:$tag,
          listen:$listen,
          listen_port:$listen_port|tonumber,
          users:[{id:$id}]
        }')
        ;;
      hysteria2)
        uuid=$(echo "$orig_link" | sed -n 's#hysteria2://\([^@]*\)@.*#\1#p' || true)
        inb=$(jq -n --arg type "hysteria2" --arg tag "hysteria2-in-$orig_port" --arg listen "::" --argjson listen_port "$orig_port" --arg uuid "$uuid" '{
          type:$type, tag:$tag, listen:$listen, listen_port:$listen_port|tonumber, users:{ ($uuid): "" }
        }')
        ;;
      tuic)
        pair=$(echo "$orig_link" | sed -n 's#tuic://\([^@]*\)@.*#\1#p' || true); u=${pair%%:*}; pss=${pair#*:}; [[ "$pss" == "$pair" ]] && pss=""
        inb=$(jq -n --arg type "tuic" --arg tag "tuic-in-$orig_port" --arg listen "::" --argjson listen_port "$orig_port" --arg u "$u" --arg pss "$pss" '{
          type:$type, tag:$tag, listen:$listen, listen_port:$listen_port|tonumber, users:[{uuid:$u, password:$pss}]
        }')
        ;;
      trojan)
        pw=$(echo "$orig_link" | sed -n 's#trojan://\([^@]*\)@.*#\1#p' || true)
        inb=$(jq -n --arg type "trojan" --arg tag "trojan-in-$orig_port" --arg listen "::" --argjson listen_port "$orig_port" --arg pw "$pw" '{
          type:$type, tag:$tag, listen:$listen, listen_port:$listen_port|tonumber, passwords:[$pw]
        }')
        ;;
      ss)
        # 这里只写一个占位（真实 password/method 可能需解析 ss://）
        inb=$(jq -n --arg type "shadowsocks" --arg tag "ss-in-$orig_port" --arg listen "::" --argjson listen_port "$orig_port" '{
          type:$type, tag:$tag, listen:$listen, listen_port:$listen_port|tonumber, method:"aes-128-gcm", password:""
        }')
        ;;
      *)
        warn "跳过协议: $proto"
        continue
        ;;
    esac
    n=$((n+1))
    echo "$inb" > "$fragdir/inb.$n.json"
    echo "$fragdir/inb.$n.json" >> "$fragdir/list.txt"
  done < "$NODES_JSON"

  # 用 jq 合并 fragments
  inb_array=$(jq -s '.' $(cat "$fragdir/list.txt" 2>/dev/null || true) 2>/dev/null || echo "[]")
  cat > "$cfg" <<EOF
{
  "log":{"level":"info","timestamp":true},
  "inbounds": $inb_array,
  "outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
  "route":{"rules":[{"geosite":"category-ads-all","outbound":"block"}],"final":"direct"}
}
EOF

  if ! jq . "$cfg" >/dev/null 2>&1; then err "sing-box 配置校验失败：$cfg"; exit 1; fi
  log "sing-box 配置写入：$cfg"
}

# 生成 xray 模板（保留 REPLACE_*）
generate_xray_template(){
  XRAY_CFG="$CURRENT_DIR/xray-config.json"
  cat > "$XRAY_CFG" <<'EOF'
{
  "log":{"access":"","error":"","loglevel":"info"},
  "inbounds":[
    {
      "listen":"0.0.0.0","port":443,"protocol":"vless",
      "settings":{
        "clients":[{"id":"REPLACE_UUID","level":0}],
        "decryption":"none",
        "fallbacks":[{"dest":"/dev/shm/xhttp.sock","xver":0}]
      },
      "streamSettings":{
        "network":"raw","security":"reality",
        "realitySettings":{
          "show":false,"xver":0,
          "serverNames":["REPLACE_DOMAIN"],
          "public_key":"REPLACE_PUBKEY",
          "short_ids":["REPLACE_SID"]
        }
      }
    },
    {
      "listen":"/dev/shm/xhttp.sock,0666","protocol":"vless",
      "settings":{"clients":[{"id":"REPLACE_UUID2","level":0}],"decryption":"none"},
      "streamSettings":{"network":"xhttp","xhttpSettings":{"mode":"auto","path":"/xhttp_path","host":[]}}
    }
  ],
  "outbounds":[{"protocol":"freedom","settings":{},"tag":"direct"}]
}
EOF
  log "xray 模板写入：$XRAY_CFG （请手动替换 REPLACE_*）"
}

# 获取 GitHub release 的最新 tag（简易）
get_latest_github_tag(){
  local repo="$1"
  curl -s -A "$USER_AGENT" "https://api.github.com/repos/${repo}/releases/latest" | jq -r '.tag_name // empty'
}

install_binaries(){
  if [[ "$SKIP_INSTALL" == "yes" || "$DRY_RUN" == "yes" ]]; then
    log "跳过二进制下载/安装（skip/install/dry-run）"
    return
  fi
  log "尝试安装 sing-box 和 xray（若网络允许）"

  # sing-box
  tag=$(get_latest_github_tag "SagerNet/sing-box" || true)
  ver=${tag#v}
  if [[ -n "$ver" ]]; then
    asset="sing-box-${ver}-linux-amd64.tar.gz"
    url="https://github.com/SagerNet/sing-box/releases/download/${tag}/${asset}"
    log "下载 sing-box: $url"
    wget -qO "$TMPDIR/singbox.tar.gz" "$url" || wget -qO "$TMPDIR/singbox.tar.gz" "https://mirror.ghproxy.com/${url}" || true
    if [[ -f "$TMPDIR/singbox.tar.gz" ]]; then
      tar -xzf "$TMPDIR/singbox.tar.gz" -C "$TMPDIR" || true
      bin=$(find "$TMPDIR" -type f -name sing-box -print -quit || true)
      if [[ -n "$bin" ]]; then
        mv -f "$bin" "$SINGBOX_BIN" && chmod +x "$SINGBOX_BIN" && log "sing-box v$ver 安装完成"
      else
        warn "sing-box 包中未找到可执行文件"
      fi
    else
      warn "sing-box 下载失败"
    fi
  else
    warn "无法获取 sing-box 最新版本信息"
  fi

  # xray
  tag=$(get_latest_github_tag "XTLS/Xray-core" || true)
  ver=${tag#v}
  if [[ -n "$ver" ]]; then
    asset="Xray-linux-64.zip"
    url="https://github.com/XTLS/Xray-core/releases/download/${tag}/${asset}"
    log "下载 xray: $url"
    wget -qO "$TMPDIR/xray.zip" "$url" || wget -qO "$TMPDIR/xray.zip" "https://mirror.ghproxy.com/${url}" || true
    if [[ -f "$TMPDIR/xray.zip" ]]; then
      unzip -qo "$TMPDIR/xray.zip" -d "$TMPDIR" || true
      if [[ -f "$TMPDIR/xray" ]]; then
        mv -f "$TMPDIR/xray" "$XRAY_BIN" && chmod +x "$XRAY_BIN" && log "xray v$ver 安装完成"
      else
        warn "xray 包中未找到可执行文件"
      fi
    else
      warn "xray 下载失败"
    fi
  else
    warn "无法获取 xray 最新版本信息"
  fi
}

create_systemd_services(){
  log "创建 systemd 服务（使用非 root 用户 proxysvc）"
  useradd -r -s /sbin/nologin proxysvc 2>/dev/null || true
  # sing-box service
  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box
After=network.target
[Service]
Type=simple
User=proxysvc
ExecStart=$SINGBOX_BIN run -c $CURRENT_DIR/sing-box-config.json
Restart=on-failure
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

  # xray service
  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=xray
After=network.target
[Service]
Type=simple
User=proxysvc
ExecStart=$XRAY_BIN run -c $CURRENT_DIR/xray-config.json
Restart=on-failure
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload || true
  systemctl enable sing-box xray >/dev/null 2>&1 || true
}

start_services(){
  if [[ "$DRY_RUN" == "yes" ]]; then
    log "dry-run 模式，跳过启动服务"
    return
  fi
  systemctl restart sing-box 2>/dev/null || warn "sing-box 启动失败，请查看日志"
  systemctl restart xray 2>/dev/null || warn "xray 启动失败，请查看日志"
  sleep 1
  systemctl is-active --quiet sing-box && log "sing-box active" || warn "sing-box 未激活"
  systemctl is-active --quiet xray && log "xray active" || warn "xray 未激活"
}

final_report(){
  echo
  echo -e "${CYAN}===== 完成 =====${NC}"
  echo -e "服务器 IP: ${YELLOW}$SERVER_IP${NC}"
  echo -e "客户端文件：VPS: ${YELLOW}$CLIENT_VPS${NC}  CDN: ${YELLOW}$CLIENT_CDN${NC}"
  echo -e "选定 CDN 候选: ${YELLOW}${CDN_USER_SPEC:-(自动获取)}${NC}"
  echo "查看 sing-box 配置: $CURRENT_DIR/sing-box-config.json"
  echo "查看 xray 模板: $CURRENT_DIR/xray-config.json （请替换 REPLACE_*）"
  echo "查看日志: journalctl -u sing-box -f"
  echo "查看日志: journalctl -u xray -f"
  echo -e "${YELLOW}如果有问题，贴出 $CLIENT_CDN 前10行 和 journalctl 日志，我来帮你定位${NC}"
}

# ------------------------
# 主流程
# ------------------------
main(){
  ensure_root
  install_deps
  get_server_ip

  echo
  if [[ "$FORCE_CLIENT_CDN" == "yes" ]]; then
    log "已设置为强制客户端走 CDN -> VPS -> 节点"
  else
    log "默认：客户端优先走 VPS 直连（若 VPS 无法直连，客户端将使用 CDN 版本）"
  fi

  parse_input_nodes

  # 规范化 nodes.jsonl（防止 pretty json）
  if sed -n '1,4p' "$NODES_JSON" | grep -q '^{'; then
    if ! awk 'END{print NR}' "$NODES_JSON" | grep -q '^1$'; then
      awk 'BEGIN{RS=""; ORS="\n"} { gsub(/\n[ \t]*/," "); gsub(/[ \t]+/," "); print }' "$NODES_JSON" > "${NODES_JSON}.fixed" && mv -f "${NODES_JSON}.fixed" "$NODES_JSON" || true
    fi
  fi

  process_nodes_and_make_clients

  generate_singbox_config
  generate_xray_template

  install_binaries
  create_systemd_services
  start_services

  final_report
}

main "$@"
