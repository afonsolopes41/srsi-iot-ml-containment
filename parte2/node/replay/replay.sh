#!/usr/bin/env bash
# Reproduz uma captura do IoT-23 a partir deste contentor (atacante ou dispositivo), à
# velocidade ORIGINAL (promessa da Parte 1), e regista o instante de início.
#
# Uso (a partir de parte2/, no PC):
#   docker compose exec attacker /opt/replay/replay.sh /pcaps/s2_mirai_34-1_20min.pcap 192.168.1.195 CTU-IoT-Malware-Capture-34-1
#
# Argumentos: <pcap> <IP do dispositivo infetado na captura original> <nome da captura>
#
# O que faz:
#   1. tcprewrite: o IP original passa a ser o IP deste contentor (nos dois sentidos); MAC de
#      origem = o deste contentor; MAC de destino = o do gateway (para os pacotes lá chegarem);
#      recalcula checksums e corrige o comprimento dos cabeçalhos IP/TCP quando não bate
#      com o pacote (--fixhdrlen; sem isto o tcprewrite salta esses pacotes).
#   2. tcpreplay à velocidade original (sem -x/-M/-t).
#   3. Acrescenta uma linha a /logs/<host>/replay.jsonl (docs/interfaces.md §6):
#      t_start (1.º pacote enviado), t_end, pcap_t0 (instante do 1.º pacote NA CAPTURA ORIGINAL),
#      para se poder converter qualquer instante da captura no instante do replay:
#          t_replay = t_start + (t_original - pcap_t0)
#      O t_ataque de T_c = t_start + (ts do 1.º fluxo malicioso - pcap_t0).
set -euo pipefail

PCAP=${1:?uso: replay.sh <pcap> <ip_original> <captura>}
IP_ORIG=${2:?falta o IP original}
CAPTURA=${3:?falta o nome da captura}
IFACE=${IFACE:-eth0}
HOST=$(hostname)
now() { date -u +%s.%N | cut -c1-17; }

MEU_IP=$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1)
MEU_MAC=$(cat "/sys/class/net/$IFACE/address")
ping -c 1 -W 1 "${GATEWAY:?}" >/dev/null 2>&1 || true
GW_MAC=$(ip neigh show "$GATEWAY" | awk '{print $5}' | head -1)
[[ -n "$GW_MAC" ]] || { echo "Não consegui o MAC do gateway ($GATEWAY)" >&2; exit 1; }

OUT=/tmp/replay_$(basename "$PCAP")
echo "[$HOST] tcprewrite: $IP_ORIG -> $MEU_IP, MAC destino $GW_MAC"
tcprewrite --infile="$PCAP" --outfile="$OUT" \
  --srcipmap="$IP_ORIG/32:$MEU_IP/32" --dstipmap="$IP_ORIG/32:$MEU_IP/32" \
  --enet-smac="$MEU_MAC" --enet-dmac="$GW_MAC" --fixcsum --fixhdrlen

PCAP_T0=$(tcpdump -tt -n -r "$PCAP" -c 1 2>/dev/null | awk '{print $1}')
mkdir -p "/logs/$HOST"
echo "[$HOST] tcpreplay à velocidade original de $(basename "$PCAP") (pode demorar)..."
T_START=$(now)
tcpreplay -i "$IFACE" "$OUT" > /tmp/tcpreplay.out 2>&1
T_END=$(now)
PKTS=$(grep -oE 'Actual: [0-9]+ packets' /tmp/tcpreplay.out | grep -oE '[0-9]+' || echo 0)

printf '{"host":"%s","capture":"%s","pcap":"%s","ip_original":"%s","src_ip":"%s","speed":"original","pcap_t0":%s,"t_start":%s,"t_end":%s,"packets":%s}\n' \
  "$HOST" "$CAPTURA" "$(basename "$PCAP")" "$IP_ORIG" "$MEU_IP" "$PCAP_T0" "$T_START" "$T_END" "$PKTS" \
  | tee -a "/logs/$HOST/replay.jsonl"
