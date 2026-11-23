#!/usr/bin/env bash
# Arranque de um nó. Todos os nós mandam o tráfego pelo gateway:
#   device/attacker: rota por omissão via o gateway da sua sub-rede;
#   server:          rota para a rede IoT via o gateway.
#
# device/attacker fazem um "heartbeat" HTTP ao servidor e registam o resultado em
# /logs/nodes/<host>.jsonl. Serve de testemunha da contenção: quando o dispositivo entra em
# quarentena, os pedidos passam a falhar; quando a quarentena expira, voltam a funcionar.
# O tráfego benigno e malicioso das experiências vem do tcpreplay (scripts em /pcaps, Fase 1).
set -euo pipefail

ROLE=${ROLE:?defina ROLE}
HOST=$(hostname)
mkdir -p /logs/nodes
now() { date -u +%s.%N | cut -c1-17; }   # epoch com ms, igual ao "ts" do Zeek

case "$ROLE" in
  device|attacker)
    ip route replace default via "${GATEWAY:?}"
    echo "[$HOST] rota por omissão via $GATEWAY"
    if [[ "${HEARTBEAT_S:-0}" != "0" ]]; then
      while true; do
        code=$(curl -s -o /dev/null -m 2 -w '%{http_code}' "http://${SERVER:?}/" || true)
        ok=false; [[ "$code" == "200" ]] && ok=true
        printf '{"ts":%s,"host":"%s","target":"%s","http_code":"%s","ok":%s}\n' \
          "$(now)" "$HOST" "$SERVER" "$code" "$ok" >> "/logs/nodes/$HOST.jsonl"
        sleep "$HEARTBEAT_S"
      done
    else
      exec sleep infinity
    fi
    ;;
  server)
    ip route replace "${IOT_NET:?}" via "${GATEWAY:?}"
    echo "[$HOST] rota $IOT_NET via $GATEWAY"
    mkdir -p /srv/www
    echo "srsi-server ok" > /srv/www/index.html
    # Ficheiro de 2 MB para ligações longas (teste dos registos parciais e do corte de ligações estabelecidas)
    head -c 2097152 /dev/urandom > /srv/www/big.bin
    exec busybox httpd -f -p 80 -h /srv/www
    ;;
  *)
    echo "ROLE desconhecido: $ROLE" >&2; exit 1 ;;
esac
