#!/usr/bin/env bash
# proxy-config-final.sh — 智能代理配置（最终版）
set -euo pipefail
IFS=$'\n\t'

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
log(){ echo -e "${GREEN}[$(date +'%H:%M:%S')] $*${NC}"; }
warn(){ echo -e "${YELLOW}[$(date +'%H:%M:%S')] $*${NC}"; }
err(){ echo -e "${RED}[$(date +'%H:%M:%S')] $*${NC}"; }

CURRENT_DIR="/root/proxy-config"
TMPDIR="/tmp/proxycfg.$$"
NODES_JSON="$TMPDIR/nodes.jsonl"
CLIENT_VPS="$CURRENT_DIR/client_nodes_vps.txt"
CLIENT_CDN="$CURRENT_DIR/client_nodes_cdn.txt"
SINGBOX_BIN="/usr/local/bin/sing-box"
XRAY_BIN="/usr/local/bin/xray"
SERVER_IP=""
CDN_USER_SPEC=""
CDN_CHOSEN=""
FORCE_CLIENT_CDN="yes"

ensure_root(){
  if [[ $EUID -ne 0 ]]; then err "请以 root 运行此脚本"; exit 1; fi
  mkdir -p "$CURRENT_DIR" "$TMPDIR"
}

install_deps(){
  log "检查/安装依赖：curl wget jq unzip tar openssl base64"
  if command -v apt >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >/dev/null 2>&1 || true
    apt-get install -y curl wget jq unzip tar openssl coreutils ca-certificates >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y curl wget jq unzip tar openssl coreutils ca-certificates >/dev/null 2>&1 || true
  fi
  command -v jq >/dev/null 2>&1 || { warn "安装 jq"; curl -fsSL -o /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64; chmod +x /usr/local/bin/jq; }
}

get_server_ip(){
  SERVER_IP=$(curl -s --connect-timeout 6 ipv4.icanhazip.com || curl -s --connect-timeout 6 ifconfig.me || true)
  if [[ -z "$SERVER_IP" ]]; then err "无法获取公网 IP"; exit 1; fi
  log "服务器公网 IP: $SERVER_IP"
}

is_ip(){ [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

get_auto_cdn_ip(){
  if [[ -n "$CDN_USER_SPEC" ]]; then echo "$CDN_USER_SPEC"; return; fi
  local sources=( "https://ip.164746.xyz/ipTop.html" "https://stock.hostmonit.com/CloudFlareYes" )
  for s in "${sources[@]}"; do
    ip=$(curl -s --connect-timeout 5 "$s" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)
    if [[ -n "$ip" ]]; then echo "$ip"; return; fi
  done
  echo "104.21.48.162"
}

modify_vmess_for_cdn(){
  local link="$1"; local cdn="$2"
  local b64=${link#vmess://}
  local json
  if ! json=$(echo "$b64" | tr '_-' '/+' | base64 -d 2>/dev/null); then
    json=$(echo "$b64" | base64 -d 2>/dev/null || true)
  fi
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

test_connectivity(){
  local host="$1"; local port="$2"; local sni="$3"
  if [[ "$host" == "$SERVER_IP" ]]; then return 0; fi
  if timeout 3 bash -c "cat < /dev/tcp/${host}/${port} >/dev/null 2>&1"; then return 0; fi
  if command -v openssl >/dev/null 2>&1; then
    if timeout 6 openssl s_client -servername "${sni:-$host}" -connect "${host}:${port}" < /dev/null >/dev/null 2>&1; then return 0; fi
  fi
  return 1
}

parse_input_nodes(){
  > "$NODES_JSON"
  echo
  echo -e "${CYAN}请逐行粘入原始节点（vless/vmess/trojan/ss/hysteria2/tuic），空行结束：${NC}"
  while IFS= read -r line; do
    [[ -z "$line" ]] && break
    if [[ $line == anytls://* ]]; then line="vless://${line#anytls://}"; fi
    if [[ $line == vless://* ]]; then
      orig_host=$(echo "$line" | sed -n 's/.*@\([^:]*\):\([0-9]*\).*/\1/p' || true)
      orig_port=$(echo "$line" | sed -n 's/.*@[^:]*:\([0-9]*\).*/\1/p' || true)
      jq -n --arg proto "vless" --arg orig_host "$orig_host" --arg orig_port "$orig_port" --arg orig_link "$line" '{"proto":$proto,"orig_host":$orig_host,"orig_port":$orig_port,"orig_link":$orig_link,"cdn_link":"","reachable":false}' >> "$NODES_JSON"
    elif [[ $line == vmess://* ]]; then
      b64=${line#vmess://}
      json=$(echo "$b64" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "")
      add=$(echo "$json" | jq -r '.add // empty' || true)
      port=$(echo "$json" | jq -r '.port // empty' || true)
      jq -n --arg proto "vmess" --arg orig_host "$add" --arg orig_port "$port" --arg orig_link "$line" '{"proto":$proto,"orig_host":$orig_host,"orig_port":$orig_port,"orig_link":$orig_link,"cdn_link":"","reachable":false}' >> "$NODES_JSON"
    elif [[ $line == trojan://* || $line == ss://* || $line == hysteria2://* || $line == tuic://* ]]; then
      proto=$(echo "$line" | sed -n 's#^\(trojan\|ss\|hysteria2\|tuic\)://.*#\1#p' || true)
      orig_host=$(echo "$line" | sed -n 's/.*@\([^:]*\):\([0-9]*\).*/\1/p' || true)
      orig_port=$(echo "$line" | sed -n 's/.*@[^:]*:\([0-9]*\).*/\1/p' || true)
      jq -n --arg proto "$proto" --arg orig_host "$orig_host" --arg orig_port "$orig_port" --arg orig_link "$line" '{"proto":$proto,"orig_host":$orig_host,"orig_port":$orig_port,"orig_link":$orig_link,"cdn_link":"","reachable":false}' >> "$NODES_JSON"
    else
      warn "跳过未知或无法解析的行：$line"
    fi
  done
  log "解析完成，写入 $NODES_JSON"
}

process_nodes_and_make_clients(){
  cdnip=$(get_auto_cdn_ip); CDN_CHOSEN="$cdnip"
  log "选定 CDN: $cdnip"
  > "$CLIENT_VPS"; > "$CLIENT_CDN"
  tmpfile="$TMPDIR/nodes.out.jsonl"; > "$tmpfile"
  idx=0
  while IFS= read -r line; do
    idx=$((idx+1))
    proto=$(echo "$line" | jq -r '.proto')
    orig_host=$(echo "$line" | jq -r '.orig_host')
    orig_port=$(echo "$line" | jq -r '.orig_port')
    orig_link=$(echo "$line" | jq -r '.orig_link')
    reachable=false
    if [[ -n "$orig_host" && -n "$orig_port" ]]; then
      if test_connectivity "$orig_host" "$orig_port" ""; then reachable=true; fi
    fi
    cdn_link="$orig_link"
    if [[ "$proto" == "vmess" ]]; then
      cdn_link="$(modify_vmess_for_cdn "$orig_link" "$cdnip")"
    else
      if [[ -n "$orig_host" && -n "$orig_port" ]]; then
        cdn_link=$(echo "$orig_link" | sed "s@${orig_host}:${orig_port}@${cdnip}:${orig_port}@g")
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
    echo "$client_vps" >> "$CLIENT_VPS"
    echo "$client_cdn" >> "$CLIENT_CDN"
    echo "$line" | jq --arg cl "$cdn_link" --argjson r $([[ "$reachable" == true ]] && echo true || echo false) '. + {cdn_link:$cl,reachable:$r}' >> "$tmpfile"
    if [[ "$reachable" == true ]]; then
      log "节点 $idx: $proto $orig_host:$orig_port -> VPS 可直连"
    else
      warn "节点 $idx: $proto $orig_host:$orig_port -> VPS 不可直连，准备 CDN 回退"
    fi
  done < "$NODES_JSON"
  mv -f "$tmpfile" "$NODES_JSON"
  log "生成客户端文件：VPS:$CLIENT_VPS CDN:$CLIENT_CDN"
}

generate_singbox_config(){
  log "生成 sing-box 配置..."
  cfg="$CURRENT_DIR/sing-box-config.json"
  inb=""
  while IFS= read -r l; do
    proto=$(echo "$l" | jq -r '.proto')
    orig_port=$(echo "$l" | jq -r '.orig_port')
    orig_link=$(echo "$l" | jq -r '.orig_link')
    case "$proto" in
      vless)
        uuid=$(echo "$orig_link" | sed -n 's#vless://\([^@]*\)@.*#\1#p' || true)
        sni=$(echo "$orig_link" | grep -oP 'sni=[^&]+' | sed 's/sni=//' || true)
        tlsblock=""; [[ -n "$sni" ]] && tlsblock=",\"tls\":{\"enabled\":true,\"server_name\":\"$sni\"}"
        frag=$(cat <<EOF
{
  "type":"vless","tag":"vless-in-$orig_port","listen":"::","listen_port":$orig_port,"users":[{"uuid":"$uuid"}]$tlsblock
}
EOF
)
        ;;
      vmess)
        b64=$(echo "$orig_link" | sed 's#vmess://##')
        json=$(echo "$b64" | tr '_-' '/+' | base64 -d 2>/dev/null || echo "{}")
        id=$(echo "$json" | jq -r '.id // .uuid // empty' || true)
        frag=$(cat <<EOF
{
  "type":"vmess","tag":"vmess-in-$orig_port","listen":"::","listen_port":$orig_port,"users":[{"id":"$id"}]
}
EOF
)
        ;;
      hysteria2)
        uuid=$(echo "$orig_link" | sed -n 's#hysteria2://\([^@]*\)@.*#\1#p' || true)
        frag=$(cat <<EOF
{
  "type":"hysteria2","tag":"hysteria2-in-$orig_port","listen":"::","listen_port":$orig_port,"users": { "$uuid": "" }
}
EOF
)
        ;;
      tuic)
        pair=$(echo "$orig_link" | sed -n 's#tuic://\([^@]*\)@.*#\1#p' || true); u=${pair%%:*}; pss=${pair#*:}; [[ "$pss" == "$pair" ]] && pss=""
        frag=$(cat <<EOF
{
  "type":"tuic","tag":"tuic-in-$orig_port","listen":"::","listen_port":$orig_port,"users":[{"uuid":"$u","password":"$pss"}]
}
EOF
)
        ;;
      trojan)
        pw=$(echo "$orig_link" | sed -n 's#trojan://\([^@]*\)@.*#\1#p' || true)
        frag=$(cat <<EOF
{
  "type":"trojan","tag":"trojan-in-$orig_port","listen":"::","listen_port":$orig_port,"passwords":["$pw"]
}
EOF
)
        ;;
      ss)
        frag=$(cat <<EOF
{
  "type":"shadowsocks","tag":"ss-in-$orig_port","listen":"::","listen_port":$orig_port,"method":"aes-128-gcm","password":""
}
EOF
)
        ;;
      *)
        warn "跳过协议: $proto"
        continue
        ;;
    esac
    inb+="${frag},"
  done < "$NODES_JSON"
  inb="[${inb%,}]"
  cat > "$cfg" <<EOF
{
  "log":{"level":"info","timestamp":true},
  "inbounds": $inb,
  "outbounds":[{"type":"direct","tag":"direct"},{"type":"block","tag":"block"}],
  "route":{"rules":[{"geosite":"category-ads-all","outbound":"block"}],"final":"direct"}
}
EOF
  if ! jq . "$cfg" >/dev/null 2>&1; then err "sing-box 配置校验失败：$cfg"; exit 1; fi
  log "sing-box 配置写入：$cfg"
}

generate_xray_template(){
  XRAY_CFG="$CURRENT_DIR/xray-config.json"
  cat > "$XRAY_CFG" <<'EOF'
{ "log":{"access":"","error":"","loglevel":"info"}, "inbounds":[{ "listen":"0.0.0.0","port":443,"protocol":"vless","settings":{"clients":[{"id":"REPLACE_UUID","level":0}],"decryption":"none","fallbacks":[{"dest":"/dev/shm/xhttp.sock","xver":0}]},"streamSettings":{"network":"raw","security":"reality","realitySettings":{"show":false,"xver":0,"serverNames":["REPLACE_DOMAIN"],"public_key":"REPLACE_PUBKEY","short_ids":["REPLACE_SID"]}}},{ "listen":"/dev/shm/xhttp.sock,0666","protocol":"vless","settings":{"clients":[{"id":"REPLACE_UUID2","level":0}],"decryption":"none"},"streamSettings":{"network":"xhttp","xhttpSettings":{"mode":"auto","path":"/xhttp_path","host":[]}}}], "outbounds":[{"protocol":"freedom","settings":{},"tag":"direct"}] }
EOF
  log "xray 模板写入：$XRAY_CFG （请手动替换 REPLACE_*）"
}

install_binaries(){
  log "尝试安装 sing-box 和 xray（若网络允许）"
  tag=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | jq -r '.tag_name' || true); ver=${tag#v}
  if [[ -n "$ver" && "$ver" != "null" ]]; then
    asset="sing-box-${ver}-linux-amd64.tar.gz"
    url="https://github.com/SagerNet/sing-box/releases/download/${tag}/${asset}"
    wget -qO "$TMPDIR/singbox.tar.gz" "$url" || wget -qO "$TMPDIR/singbox.tar.gz" "https://mirror.ghproxy.com/${url}" || true
    if [[ -f "$TMPDIR/singbox.tar.gz" ]]; then tar -xzf "$TMPDIR/singbox.tar.gz" -C "$TMPDIR" || true; bin=$(find "$TMPDIR" -type f -name sing-box -print -quit || true); [[ -n "$bin" ]] && mv -f "$bin" "$SINGBOX_BIN" && chmod +x "$SINGBOX_BIN" && log "sing-box v$ver 安装完成"; fi
  else warn "无法获取 sing-box 版本"
  tag=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name' || true); ver=${tag#v}
  if [[ -n "$ver" && "$ver" != "null" ]]; then
    asset="Xray-linux-64.zip"; url="https://github.com/XTLS/Xray-core/releases/download/${tag}/${asset}"
    wget -qO "$TMPDIR/xray.zip" "$url" || wget -qO "$TMPDIR/xray.zip" "https://mirror.ghproxy.com/${url}" || true
    if [[ -f "$TMPDIR/xray.zip" ]]; then unzip -qo "$TMPDIR/xray.zip" -d "$TMPDIR" || true; [[ -f "$TMPDIR/xray" ]] && mv -f "$TMPDIR/xray" "$XRAY_BIN" && chmod +x "$XRAY_BIN" && log "xray v$ver 安装完成"; fi
  else warn "无法获取 xray 版本"
}

create_systemd_services(){
  cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box
After=network.target
[Service]
Type=simple
ExecStart=$SINGBOX_BIN run -c $CURRENT_DIR/sing-box-config.json
Restart=on-failure
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=xray
After=network.target
[Service]
Type=simple
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
  echo -e "客户端文件：VPS（$CLIENT_VPS）  CDN（$CLIENT_CDN）"
  echo -e "选定 CDN: ${YELLOW}$CDN_CHOSEN${NC}"
  echo "查看 sing-box 配置: $CURRENT_DIR/sing-box-config.json"
  echo "查看 xray 模板: $CURRENT_DIR/xray-config.json （请替换 REPLACE_*）"
  echo "查看日志: journalctl -u sing-box -f"
  echo "查看日志: journalctl -u xray -f"
  echo -e "${YELLOW}如果有问题，贴出 $CLIENT_CDN 前10行 和 journalctl 日志，我来帮你定位${NC}"
}

main(){
  ensure_root
  install_deps
  get_server_ip
  echo
  echo -e "${CYAN}是否强制客户端先走 CDN（客户端->CDN->VPS）？${NC}"
  echo "1) 是（默认）"
  echo "2) 否"
  read -p "请选择 [1-2] (回车默认1): " ch || true
  ch=${ch:-1}
  if [[ "$ch" == "2" ]]; then FORCE_CLIENT_CDN="no"; else FORCE_CLIENT_CDN="yes"; fi
  if [[ "$FORCE_CLIENT_CDN" == "yes" ]]; then read -p "是否手动指定 CDN IP/域名（回车自动获取）: " ucdn || true; CDN_USER_SPEC="${ucdn:-}"; fi
  parse_input_nodes
  # 尝试把 pretty JSON -> 每行 JSON（容错）
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
  rm -rf "$TMPDIR" || true
}

main "$@"
