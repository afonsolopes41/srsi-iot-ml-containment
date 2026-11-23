#!/usr/bin/env bash
# Arranque do gateway:
#   1. tabela nftables com o set de quarentena (regra de drop antes de established/related);
#   2. desliga offloads (o Zeek tem de ver pacotes com o tamanho real);
#   3. espelha a entrada de TODAS as interfaces para a interface "zeekmon" (cada pacote é visto
#      uma única vez, incluindo o movimento lateral entre sub-redes IoT e o tráfego já em quarentena);
#   4. rota por omissão para o servidor "Internet";
#   5. Zeek em primeiro plano, a escrever conn.log e conn_interim.log em JSON.
set -euo pipefail

LOG_DIR=${LOG_DIR:-/logs}
ZEEK_DIR="$LOG_DIR/zeek"
GW_DIR="$LOG_DIR/gateway"
MON=zeekmon
mkdir -p "$ZEEK_DIR" "$GW_DIR"

log() { printf '%s [gateway] %s\n' "$(date -u +%FT%T.%3NZ)" "$*" | tee -a "$GW_DIR/gateway.log"; }

# 1. nftables
QUARANTINE_TIMEOUT=${QUARANTINE_TIMEOUT:-300s}
sed "s/timeout 300s/timeout ${QUARANTINE_TIMEOUT}/" /opt/srsi/nft/srsi.nft > /tmp/srsi.nft
nft -f /tmp/srsi.nft
log "nftables carregado (quarentena expira em ${QUARANTINE_TIMEOUT})"
nft -a list chain inet srsi forward >> "$GW_DIR/gateway.log"

# Interfaces de dados (todas menos lo e o espelho)
IFACES=()
for d in /sys/class/net/*; do
  i=${d##*/}; [[ "$i" == lo || "$i" == "$MON" || "$i" == "${MON}-p" ]] || IFACES+=("$i")
done

# 2. offloads
for i in "${IFACES[@]}"; do
  ethtool -K "$i" gro off gso off tso off lro off >/dev/null 2>&1 || true
done

# 3. espelho para o Zeek
# Interface "dummy" se o kernel a tiver; senão um par veth (o par recebe os pacotes e descarta-os).
if ! ip link show "$MON" >/dev/null 2>&1; then
  if ip link add "$MON" type dummy 2>/dev/null; then
    log "espelho: interface dummy $MON"
  else
    ip link add "$MON" type veth peer name "${MON}-p"
    ip link set "${MON}-p" up
    log "espelho: par veth $MON/${MON}-p (kernel sem dummy)"
  fi
fi
ip link set "$MON" mtu 9000 up
for i in "${IFACES[@]}"; do
  tc qdisc replace dev "$i" handle ffff: ingress
  if ! tc filter add dev "$i" parent ffff: protocol all prio 1 u32 match u32 0 0 \
          action mirred egress mirror dev "$MON"; then
    log "ERRO: não foi possível espelhar $i para $MON (o kernel tem sch_ingress/act_mirred?)"
    exit 1
  fi
  log "interface $i ($(ip -o -4 addr show dev "$i" | awk '{print $4}')) espelhada para $MON"
done

# Mapa interface -> sub-rede, útil para os relatórios das experiências
ip -j -4 addr show | jq '[.[] | select(.ifname != "lo") | {ifname, addr: .addr_info[0].local, prefix: .addr_info[0].prefixlen}]' \
  > "$GW_DIR/interfaces.json"

# 4. rota por omissão ("Internet")
if [[ -n "${INTERNET_NEXT_HOP:-}" ]]; then
  ip route replace default via "$INTERNET_NEXT_HOP"
  log "rota por omissão via $INTERNET_NEXT_HOP"
fi

# 5. Detetor em segundo plano, se houver modelo escolhido (docs/interfaces.md §4)
if [[ -n "${DETECTOR_MODEL:-}" ]]; then
  python -m srsi.detector --model "$DETECTOR_MODEL" --zeek-dir "$ZEEK_DIR" \
    --out "$GW_DIR/flows.jsonl" >> "$GW_DIR/detector.log" 2>&1 &
  log "detetor iniciado com o modelo $DETECTOR_MODEL"
fi

# 6. Zeek (diretório de trabalho = diretório dos logs)
cd "$ZEEK_DIR"
log "a iniciar o Zeek em $MON ($(zeek --version))"
exec zeek -C -i "$MON" /opt/srsi/zeek/local.zeek \
     "ConnInterim::every=${ZEEK_INTERIM_EVERY:-30sec}"
